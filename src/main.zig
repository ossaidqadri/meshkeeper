//! meshkeeper: a minimal EasyMesh (Multi-AP) controller for OpenWrt.
//!
//! Wiring only: OpenWrt config files, ubus for wireless status and hostapd, an AF_PACKET socket for IEEE 1905
//! frames, hostapd probe events for the auto-WPS gate, and a poll loop that
//! feeds the pure `Controller`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const cmdu = @import("cmdu.zig");
const wsc = @import("wsc.zig");
const uci = @import("uci.zig");
const controller = @import("controller.zig");
const Controller = controller.Controller;

pub const std_options: std.Options = .{
    .log_level = .info,
    .logFn = if (builtin.os.tag == .linux and !builtin.is_test) syslogLog else std.log.defaultLog,
};
const log = std.log.scoped(.main);

/// Logs to syslog with each message's own severity. procd files everything a
/// service writes to stderr under LOG_ERR, so stderr stays for panic traces only.
/// Speaks the /dev/log datagram protocol directly rather than linking libc for
/// syslog(3); a fresh socket per line keeps working across logd restarts.
fn syslogLog(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    const severity: u8 = switch (level) {
        .err => 3,
        .warn => 4,
        .info => 6,
        .debug => 7,
    };
    const facility_daemon = 3 << 3;
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    // Overlong messages are cut at the buffer end, like syslog(3) does.
    w.print("<{d}>meshkeeper[{d}]: {t}: ", .{ facility_daemon | severity, linux.getpid(), scope }) catch {};
    w.print(format, args) catch {};
    const msg = w.buffered();

    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) == .SUCCESS) {
        const fd: posix.fd_t = @intCast(rc);
        defer _ = linux.close(fd);
        var addr: linux.sockaddr.un = .{ .path = @splat(0) };
        @memcpy(addr.path[0.."/dev/log".len], "/dev/log");
        if (linux.errno(linux.sendto(fd, msg.ptr, msg.len, 0, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) == .SUCCESS) return;
    }
    std.log.defaultLog(level, scope, format, args);
}

const usage =
    \\usage: meshkeeper [--observe] [--config NAME]
    \\  --observe      decode and log, never send frames or open WPS
    \\  --config NAME  UCI config to read (default: meshkeeper)
    \\
;

const state_dir = "/etc/meshkeeper";
const state_path = state_dir ++ "/state";
/// RAM (tmpfs), read by the LuCI status page; rewritten often, so never flash.
const mesh_dir = "/var/run/meshkeeper";
const mesh_path = mesh_dir ++ "/mesh.json";
const mesh_every_ms = 5 * std.time.ms_per_s;
const local_every_ms = 5 * std.time.ms_per_s;
const resubscribe_after_ms = 5 * std.time.ms_per_s;
const packet_outgoing = 4; // linux/if_packet.h PACKET_OUTGOING

/// What the daemon needs from OpenWrt, resolved once at start and again after
/// hostapd objects disappear (a `wifi reload`).
const Settings = struct {
    interface: []const u8,
    fronthaul: [2]?wsc.Bss,
    auto_wps: bool,
    /// hostapd object that runs WPS push-button for the agents (5 GHz fronthaul).
    wps_object: ?[]const u8,
    /// Every hostapd object, for probe events and dropping stale stations.
    hostapd_objects: []const []const u8,
    steering: bool,
    /// The router's fronthaul BSSes and their hostapd objects, same order.
    local: []const controller.LocalBss,
    local_objects: []const []const u8,

    fn localIndex(s: Settings, ifname: []const u8) ?u8 {
        for (s.local_objects, 0..) |obj, i| {
            if (std.mem.eql(u8, obj["hostapd.".len..], ifname)) return @intCast(i);
        }
        return null;
    }
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var observe = false;
    var config_name: []const u8 = "meshkeeper";
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--observe")) {
            observe = true;
        } else if (std.mem.eql(u8, args[i], "--config") and i + 1 < args.len and std.mem.indexOfScalar(u8, args[i + 1], '/') == null) {
            i += 1;
            config_name = args[i];
        } else {
            std.debug.print(usage, .{});
            std.process.exit(2);
        }
    }

    // Settings live in their own arena, replaced whole on every reload, so a
    // long-running daemon doesn't grow with each Wi-Fi reload or retry.
    var settings_arena: std.heap.ArenaAllocator = .init(init.gpa);
    defer settings_arena.deinit();
    var settings = try loadSettings(settings_arena.allocator(), init.gpa, io, config_name);
    const sock = try PacketSocket.open(io, settings.interface);
    defer sock.close();

    var first_mid: u16 = undefined;
    io.random(std.mem.asBytes(&first_mid));
    var ctl: Controller = .init(.{
        .al_mac = sock.mac,
        .fronthaul = settings.fronthaul,
        .auto_wps = settings.auto_wps and !observe,
        .steering = settings.steering,
        .local = settings.local,
    }, first_mid);
    loadState(init.gpa, io, &ctl);

    log.info("controller {x} on {s}{s}, auto-WPS {s}, steering {s}", .{ sock.mac, settings.interface, if (observe) " (observe only)" else "", if (ctl.cfg.auto_wps) "on" else "off", if (ctl.cfg.steering) "on" else "off" });
    for (settings.fronthaul, [_][]const u8{ "2.4", "5" }) |bss, band| {
        if (bss) |b| log.info("  {s} GHz agent radios get \"{s}\"", .{ band, b.ssid });
    }

    var probes: ProbeFeed = .{};
    defer probes.stop(io);
    var resubscribe_at: i64 = 0;
    var mesh_at: i64 = 0;
    var local_at: i64 = 0;
    var mesh_failing = false; // log a failing write once, not every 5 s into logd's small ring

    var rx: [cmdu.max_frame]u8 = undefined;
    var tx: [cmdu.max_frame]u8 = undefined;
    while (true) {
        const now = Io.Clock.awake.now(io).toMilliseconds();

        if (probes.child == null and now >= resubscribe_at) {
            var fresh: std.heap.ArenaAllocator = .init(init.gpa);
            if (loadSettings(fresh.allocator(), init.gpa, io, config_name)) |s| {
                settings_arena.deinit();
                settings_arena = fresh;
                settings = s;
                ctl.cfg.fronthaul = settings.fronthaul;
                ctl.cfg.steering = settings.steering;
                ctl.setLocal(settings.local);
                if (settings.steering and !observe) enableBtm(init.gpa, io, settings);
            } else |err| {
                fresh.deinit();
                log.warn("reloading settings failed ({t}), keeping the old ones", .{err});
            }
            probes.start(init.gpa, io, settings.hostapd_objects) catch |err| {
                log.warn("hostapd subscription failed ({t})", .{err});
                resubscribe_at = now + resubscribe_after_ms;
            };
        }

        var fds = [_]posix.pollfd{
            .{ .fd = sock.fd, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = if (probes.child) |c| c.stdout.?.handle else -1, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = try posix.poll(&fds, 1000);

        if (fds[0].revents & posix.POLL.IN != 0) {
            while (sock.recv(&rx)) |frame| {
                const f = cmdu.Frame.parse(frame) catch continue;
                const secrets = try wsc.Secrets.random(io);
                const reply = ctl.onFrame(f, now, &tx, secrets) catch |err| {
                    log.warn("frame {t} from {x}: {t}", .{ f.msg_type, f.src, err });
                    continue;
                };
                if (reply) |r| send(sock, observe, r);
            }
        }

        if (fds[1].revents != 0) {
            if (!probes.drain(&ctl, settings, now)) {
                probes.stop(io);
                resubscribe_at = now + resubscribe_after_ms;
                log.info("hostapd subscription ended (Wi-Fi reload?), resubscribing", .{});
            }
        }

        const t = ctl.tick(now, &tx) catch |err| blk: {
            log.warn("tick: {t}", .{err});
            break :blk Controller.Tick{};
        };
        if (t.frame) |frame| send(sock, observe, frame);
        if (t.wps) |w| openWps(init.gpa, io, settings, w);
        if (t.btm) |b| suggestMove(init.gpa, io, settings, observe, b);

        if (settings.steering and now >= local_at) {
            local_at = now + local_every_ms;
            pollLocalClients(init.gpa, io, settings, &ctl, now);
        }

        if (ctl.dirty) {
            // Observe mode has no side effects, flash writes included.
            if (!observe) saveState(io, &ctl) catch |err| log.warn("saving {s} failed: {t}", .{ state_path, err });
            ctl.dirty = false;
        }

        if (now >= mesh_at) {
            mesh_at = now + mesh_every_ms;
            if (writeMesh(io, &ctl, now)) |_| {
                if (mesh_failing) log.info("writing {s} works again", .{mesh_path});
                mesh_failing = false;
            } else |err| {
                if (!mesh_failing) log.warn("writing {s} failed: {t}", .{ mesh_path, err });
                mesh_failing = true;
            }
        }
    }
}

fn writeMesh(io: Io, ctl: *const Controller, now: i64) !void {
    var buf: [32 * 1024]u8 = undefined; // full tables: 4 agents x 32 clients is ~19 KB
    var w: Io.Writer = .fixed(&buf);
    try ctl.writeMesh(&w, now);
    const cwd = Io.Dir.cwd();
    try cwd.createDirPath(io, mesh_dir);
    try cwd.writeFile(io, .{ .sub_path = mesh_path ++ ".tmp", .data = w.buffered() });
    try cwd.rename(mesh_path ++ ".tmp", cwd, mesh_path, io);
}

fn send(sock: PacketSocket, observe: bool, frame: []const u8) void {
    const f = cmdu.Frame.parse(frame) catch unreachable; // built by us
    if (observe) {
        log.info("observe: would send {t} to {x}", .{ f.msg_type, f.dst });
        return;
    }
    sock.send(frame) catch |err| log.warn("send {t} to {x}: {t}", .{ f.msg_type, f.dst, err });
}

/// Raw IEEE 1905 frames on one interface (normally the LAN bridge).
const PacketSocket = struct {
    fd: posix.fd_t,
    ifindex: i32,
    mac: cmdu.Mac,

    const proto_be = std.mem.nativeToBig(u16, cmdu.ethertype);

    fn open(io: Io, ifname: []const u8) !PacketSocket {
        var path_buf: [64]u8 = undefined;
        var buf: [32]u8 = undefined;
        const index_text = try Io.Dir.cwd().readFile(io, try std.fmt.bufPrint(&path_buf, "/sys/class/net/{s}/ifindex", .{ifname}), &buf);
        const ifindex = try std.fmt.parseInt(i32, std.mem.trim(u8, index_text, " \n"), 10);
        const mac_text = try Io.Dir.cwd().readFile(io, try std.fmt.bufPrint(&path_buf, "/sys/class/net/{s}/address", .{ifname}), &buf);
        var mac: cmdu.Mac = undefined;
        var hex: [12]u8 = undefined;
        var n: usize = 0;
        for (std.mem.trim(u8, mac_text, " \n")) |ch| if (ch != ':' and n < hex.len) {
            hex[n] = ch;
            n += 1;
        };
        _ = try std.fmt.hexToBytes(&mac, hex[0..n]);

        const rc = linux.socket(linux.AF.PACKET, linux.SOCK.RAW | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, proto_be);
        const fd: posix.fd_t = switch (linux.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .PERM, .ACCES => return error.NeedCapNetRaw,
            else => |e| return posix.unexpectedErrno(e),
        };
        errdefer _ = linux.close(fd);
        const addr: linux.sockaddr.ll = .{ .protocol = proto_be, .ifindex = ifindex, .hatype = 0, .pkttype = 0, .halen = 0, .addr = @splat(0) };
        switch (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.ll)))) {
            .SUCCESS => {},
            else => |e| return posix.unexpectedErrno(e),
        }
        return .{ .fd = fd, .ifindex = ifindex, .mac = mac };
    }

    fn close(s: PacketSocket) void {
        _ = linux.close(s.fd);
    }

    /// Next received frame, or null when none is pending. Skips our own transmissions.
    fn recv(s: PacketSocket, buf: []u8) ?[]const u8 {
        while (true) {
            var from: linux.sockaddr.ll = undefined;
            var from_len: linux.socklen_t = @sizeOf(linux.sockaddr.ll);
            const rc = linux.recvfrom(s.fd, buf.ptr, buf.len, 0, @ptrCast(&from), &from_len);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                .AGAIN => return null,
                else => |e| {
                    log.warn("recv: {t}", .{e});
                    return null;
                },
            }
            if (from.pkttype == packet_outgoing) continue;
            return buf[0..rc];
        }
    }

    fn send(s: PacketSocket, frame: []const u8) !void {
        var addr: linux.sockaddr.ll = .{ .protocol = proto_be, .ifindex = s.ifindex, .hatype = 0, .pkttype = 0, .halen = 6, .addr = @splat(0) };
        addr.addr[0..6].* = frame[0..6].*;
        const rc = linux.sendto(s.fd, frame.ptr, frame.len, 0, @ptrCast(&addr), @sizeOf(linux.sockaddr.ll));
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |e| return posix.unexpectedErrno(e),
        }
    }
};

/// `ubus subscribe` on the hostapd objects, read line by line for probe requests.
const ProbeFeed = struct {
    child: ?std.process.Child = null,
    line: [8192]u8 = undefined,
    len: usize = 0,

    fn start(feed: *ProbeFeed, gpa: Allocator, io: Io, objects: []const []const u8) !void {
        // hostapd only reports probes to subscribers once notify_response is set.
        for (objects) |obj| _ = ubus(gpa, io, &.{ "call", obj, "notify_response", "{\"notify_response\":0}" }) catch {};
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.appendSlice(gpa, &.{ "ubus", "-S", "subscribe" });
        try argv.appendSlice(gpa, objects);
        feed.child = try std.process.spawn(io, .{ .argv = argv.items, .stdin = .ignore, .stdout = .pipe, .stderr = .ignore });
        feed.len = 0;
        log.info("watching probe requests on {d} hostapd interface(s)", .{objects.len});
    }

    fn stop(feed: *ProbeFeed, io: Io) void {
        if (feed.child) |*c| {
            c.kill(io);
            feed.child = null;
        }
    }

    /// One read per poll wakeup (poll said it is readable, so it can't block).
    /// False once the subscription ended.
    fn drain(feed: *ProbeFeed, ctl: *Controller, settings: Settings, now: i64) bool {
        if (feed.len == feed.line.len) feed.len = 0; // oversized line: drop it
        const n = posix.read(feed.child.?.stdout.?.handle, feed.line[feed.len..]) catch return false;
        if (n == 0) return false;
        feed.len += n;
        while (std.mem.indexOfScalar(u8, feed.line[0..feed.len], '\n')) |nl| {
            handleEvent(feed.line[0..nl], ctl, settings, now);
            std.mem.copyForwards(u8, feed.line[0..], feed.line[nl + 1 .. feed.len]);
            feed.len -= nl + 1;
        }
        return true;
    }

    fn handleEvent(line: []const u8, ctl: *Controller, settings: Settings, now: i64) void {
        // Probes arrive often (every client scan); parse without touching the heap.
        var scratch: [4096]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&scratch);
        const Event = struct { probe: ?struct { address: []const u8, ifname: []const u8 = "", signal: ?i32 = null } = null };
        const ev = std.json.parseFromSliceLeaky(Event, fba.allocator(), line, .{ .ignore_unknown_fields = true }) catch return;
        const probe = ev.probe orelse return;
        const mac = parseMacText(probe.address) orelse return;
        const heard: ?controller.Heard = if (settings.localIndex(probe.ifname)) |bss| (if (probe.signal) |sig|
            .{ .bss = bss, .rssi = std.math.lossyCast(i8, sig), .at = now }
        else
            null) else null;
        ctl.onProbe(mac, now, heard);
    }
};

/// "aa:bb:cc:dd:ee:ff", either case.
fn parseMacText(text: []const u8) ?cmdu.Mac {
    if (text.len != 17) return null;
    var hex: [12]u8 = undefined;
    for (0..6) |k| hex[k * 2 ..][0..2].* = text[k * 3 ..][0..2].*;
    var mac: cmdu.Mac = undefined;
    _ = std.fmt.hexToBytes(&mac, &hex) catch return null;
    return mac;
}

/// Lets clients see the router supports 802.11v (runtime only; a Wi-Fi reload
/// undoes it and the next settings reload redoes it).
fn enableBtm(gpa: Allocator, io: Io, s: Settings) void {
    for (s.local_objects) |obj| {
        const r = ubus(gpa, io, &.{ "call", obj, "bss_mgmt_enable", "{\"bss_transition\":true}" }) catch |err| {
            log.warn("bss_mgmt_enable on {s} failed: {t}", .{ obj, err });
            continue;
        };
        gpa.free(r);
    }
}

fn suggestMove(gpa: Allocator, io: Io, s: Settings, observe: bool, b: controller.Btm) void {
    const obj = s.local_objects[b.bss];
    // Neighbor Report body: BSSID, BSSID info (reachable, secure, same keys), op class, channel, PHY type VHT.
    var nr: [13]u8 = undefined;
    nr[0..6].* = b.target.bssid;
    nr[6..10].* = .{ 0x0f, 0, 0, 0 };
    nr[10] = b.target.op_class;
    nr[11] = b.target.channel;
    nr[12] = 9;
    var arg_buf: [256]u8 = undefined;
    const arg = std.fmt.bufPrint(&arg_buf, "{{\"addr\":\"{s}\",\"disassociation_imminent\":false,\"abridged\":true,\"validity_period\":30,\"neighbors\":[\"{s}\"]}}", .{ &controller.macText(b.sta), &std.fmt.bytesToHex(nr, .lower) }) catch unreachable;
    if (observe) {
        log.info("observe: would call {s} bss_transition_request {s}", .{ obj, arg });
        return;
    }
    const r = ubus(gpa, io, &.{ "call", obj, "bss_transition_request", arg }) catch |err| {
        log.warn("bss_transition_request to {x} on {s} failed: {t}", .{ b.sta, obj, err });
        return;
    };
    gpa.free(r);
}

fn pollLocalClients(gpa: Allocator, io: Io, s: Settings, ctl: *Controller, now: i64) void {
    var list: [controller.max_clients]controller.LocalClient = undefined;
    var n: usize = 0;
    for (s.local_objects, 0..) |obj, bss| {
        const raw = ubus(gpa, io, &.{ "call", obj, "get_clients" }) catch continue;
        defer gpa.free(raw);
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const Clients = struct { clients: std.json.ArrayHashMap(struct { signal: ?i32 = null }) = .{} };
        const parsed = std.json.parseFromSliceLeaky(Clients, arena.allocator(), raw, .{ .ignore_unknown_fields = true }) catch continue;
        var it = parsed.clients.map.iterator();
        while (it.next()) |e| {
            if (n == list.len) break;
            const mac = parseMacText(e.key_ptr.*) orelse continue;
            const sig = e.value_ptr.signal orelse continue;
            list[n] = .{ .mac = mac, .bss = @intCast(bss), .rssi = std.math.lossyCast(i8, sig) };
            n += 1;
        }
    }
    ctl.setLocalClients(list[0..n], now);
}

fn openWps(gpa: Allocator, io: Io, s: Settings, w: controller.WpsAction) void {
    var arg_buf: [128]u8 = undefined;
    const del = std.fmt.bufPrint(&arg_buf, "{{\"addr\":\"{s}\",\"reason\":3,\"deauth\":true,\"ban_time\":0}}", .{&controller.macText(w.stale_station)}) catch unreachable;
    for (s.hostapd_objects) |obj| _ = ubus(gpa, io, &.{ "call", obj, "del_client", del }) catch {};
    const obj = s.wps_object orelse {
        log.warn("no WPS-enabled fronthaul found, cannot open a window", .{});
        return;
    };
    if (ubus(gpa, io, &.{ "call", obj, "wps_start" })) |_| {
        log.warn("opened WPS on {s} (window {d}); press WPS on the satellite", .{ obj, w.window });
    } else |err| log.warn("wps_start on {s} failed: {t}", .{ obj, err });
}

/// Runs `ubus` and returns its stdout (caller frees with `gpa`).
fn ubus(gpa: Allocator, io: Io, args: []const []const u8) ![]u8 {
    var argv_buf: [8][]const u8 = undefined;
    argv_buf[0] = "ubus";
    @memcpy(argv_buf[1..][0..args.len], args);
    const r = try std.process.run(gpa, io, .{ .argv = argv_buf[0 .. args.len + 1], .stdout_limit = .limited(1 << 20) });
    defer gpa.free(r.stderr);
    errdefer gpa.free(r.stdout);
    switch (r.term) {
        .exited => |code| if (code != 0) return error.UbusFailed,
        else => return error.UbusFailed,
    }
    return r.stdout;
}

fn loadSettings(arena: Allocator, gpa: Allocator, io: Io, config_name: []const u8) !Settings {
    const own = try readUci(arena, io, config_name);
    const main_section = own.section("main") orelse return error.MissingMainSection;
    const wifi = try readUci(arena, io, "wireless");
    const opts: std.json.ParseOptions = .{ .ignore_unknown_fields = true, .allocate = .alloc_always };

    const status_raw = try ubus(gpa, io, &.{ "call", "network.wireless", "status" });
    defer gpa.free(status_raw);
    const Status = std.json.ArrayHashMap(struct { interfaces: []const struct { section: []const u8, ifname: ?[]const u8 = null } = &.{} });
    const status = try std.json.parseFromSliceLeaky(Status, arena, status_raw, opts);

    const suffix = main_section.get("ssid_suffix") orelse "";
    var fronthaul: [2]?wsc.Bss = .{ null, null };
    var wps_object: ?[]const u8 = null;
    var local: std.ArrayList(controller.LocalBss) = .empty;
    var local_objects: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{ "fronthaul_2g", "fronthaul_5g" }, 0..) |key, band| {
        const section = main_section.get(key) orelse continue;
        const iface = wifi.section(section) orelse {
            log.warn("{s}: wireless section '{s}' not found", .{ key, section });
            continue;
        };
        const ssid = iface.get("ssid") orelse continue;
        const passphrase = iface.get("key") orelse continue;
        if (passphrase.len < 8 or passphrase.len > 63) {
            log.warn("{s}: key must be an 8-63 character passphrase", .{section});
            continue;
        }
        const full_ssid = try std.mem.concat(arena, u8, &.{ ssid, suffix });
        if (full_ssid.len > 32) return error.SsidTooLong;
        fronthaul[band] = .{ .ssid = full_ssid, .passphrase = passphrase };
        const obj = try hostapdObject(arena, status, section) orelse continue;
        if (band == 1) wps_object = obj;
        if (localBss(arena, gpa, io, obj)) |bss| {
            try local.append(arena, bss);
            try local_objects.append(arena, obj);
        } else |err| log.warn("{s} get_status: {t}", .{ obj, err });
    }

    var objects: std.ArrayList([]const u8) = .empty;
    for (status.map.values()) |radio| for (radio.interfaces) |iface| {
        const ifname = iface.ifname orelse continue;
        try objects.append(arena, try std.mem.concat(arena, u8, &.{ "hostapd.", ifname }));
    };

    return .{
        .interface = main_section.get("interface") orelse "br-lan",
        .fronthaul = fronthaul,
        .auto_wps = std.mem.eql(u8, main_section.get("auto_wps") orelse "0", "1"),
        .wps_object = wps_object,
        .hostapd_objects = objects.items,
        .steering = std.mem.eql(u8, main_section.get("steering") orelse "0", "1"),
        .local = local.items,
        .local_objects = local_objects.items,
    };
}

fn localBss(arena: Allocator, gpa: Allocator, io: Io, obj: []const u8) !controller.LocalBss {
    const raw = try ubus(gpa, io, &.{ "call", obj, "get_status" });
    defer gpa.free(raw);
    const Status = struct { bssid: []const u8, freq: u32, channel: u8, op_class: u8 };
    const st = try std.json.parseFromSliceLeaky(Status, arena, raw, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
    return .{
        .bssid = parseMacText(st.bssid) orelse return error.BadBssid,
        .band = .fromMhz(st.freq),
        .op_class = st.op_class,
        .channel = st.channel,
    };
}

fn hostapdObject(arena: Allocator, status: anytype, section: []const u8) !?[]const u8 {
    for (status.map.values()) |radio| for (radio.interfaces) |iface| {
        if (!std.mem.eql(u8, iface.section, section)) continue;
        const ifname = iface.ifname orelse return null;
        return try std.mem.concat(arena, u8, &.{ "hostapd.", ifname });
    };
    return null;
}

/// Reads /etc/config/<name> directly, as the service user: file permissions
/// then keep root-only configs (network, system, ...) out of reach, which
/// `ubus call uci get` would not.
fn readUci(arena: Allocator, io: Io, name: []const u8) !uci.Config {
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/etc/config/{s}", .{name});
    const text = try Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(uci.max_file));
    var diag: uci.Diagnostics = .{};
    return uci.parse(arena, text, &diag) catch |err| {
        log.warn("{s} line {d}: {t}", .{ path, diag.line, err });
        return err;
    };
}

fn loadState(gpa: Allocator, io: Io, ctl: *Controller) void {
    const text = Io.Dir.cwd().readFileAlloc(io, state_path, gpa, .limited(64 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return,
        else => {
            log.warn("reading {s}: {t}", .{ state_path, err });
            return;
        },
    };
    defer gpa.free(text);
    ctl.load(text);
    log.info("loaded {d} known agent(s) from {s}", .{ ctl.n_agents, state_path });
}

/// Written only when something new was learned; atomic via rename.
fn saveState(io: Io, ctl: *const Controller) !void {
    var buf: [4096]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try ctl.save(&w);
    const cwd = Io.Dir.cwd();
    try cwd.createDirPath(io, state_dir);
    try cwd.writeFile(io, .{ .sub_path = state_path ++ ".tmp", .data = w.buffered() });
    try cwd.rename(state_path ++ ".tmp", cwd, state_path, io);
}

test {
    _ = @import("cmdu.zig");
    _ = @import("wsc.zig");
    _ = @import("controller.zig");
    _ = @import("uci.zig");
}
