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
const ubus = @import("ubus.zig");
const controller = @import("controller.zig");
const Controller = controller.Controller;

const on_router = builtin.os.tag == .linux and !builtin.is_test;

// This module parses everything that comes from outside; build.zig may make
// std small, never this.
comptime {
    if (builtin.mode != .debug and builtin.mode != .safe) @compileError("daemon.zig must be built with safety checks");
}

pub const std_options: std.Options = .{
    .log_level = .info,
    .logFn = if (on_router) syslogLog else std.log.defaultLog,
    // Stripped release binaries have no stack traces to print, so the 256 KB
    // signal stack and the segfault handler that would print them are dead weight.
    .signal_stack_size = if (on_router) null else 1 << 18,
    .enable_segfault_handler = !on_router,
    .allow_stack_tracing = !on_router,
    // Sockets are raw linux calls; std's networking (DNS and all) is never used.
    .networking = false,
};

/// Safety checks stay on (ReleaseSafe); a failed one logs and exits, and
/// procd restarts the service.
pub const panic = if (on_router) std.debug.FullPanic(struct {
    fn panic(msg: []const u8, _: ?usize) noreturn {
        log.err("panic: {s}", .{msg});
        std.process.abort();
    }
}.panic) else std.debug.FullPanic(std.debug.defaultPanic);

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
    \\       meshkeeper [--config NAME] --steer AGENT CLIENT FROM TO
    \\       meshkeeper [--config NAME] --policy AGENT off|mandate|allow DBM RUID...
    \\       meshkeeper [--config NAME] --block AGENT BSSID CLIENT SECONDS
    \\  --observe      decode and log, never send frames or open WPS
    \\  --config NAME  UCI config to read (default: meshkeeper)
    \\  --steer        ask agent AGENT to move CLIENT from its BSS FROM to this
    \\                 router's BSS TO, once, then exit; the running daemon logs
    \\                 the answer (MACs as on the Mesh page)
    \\  --policy       set AGENT's own steering for the listed radios: off, or move
    \\                 clients weaker than DBM by itself (mandate) or when it likes (allow)
    \\  --block        keep CLIENT off AGENT's BSS for SECONDS (0 unblocks), so it
    \\                 reconnects elsewhere; disconnects the client
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
    steering: controller.Steering,
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
    var steer: ?[]const []const u8 = null;
    var policy: ?[]const []const u8 = null;
    var block: ?[]const []const u8 = null;
    var config_name: []const u8 = "meshkeeper";
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--observe")) {
            observe = true;
        } else if (std.mem.eql(u8, args[i], "--steer") and i + 4 < args.len) {
            steer = args[i + 1 .. i + 5];
            i += 4;
        } else if (std.mem.eql(u8, args[i], "--block") and i + 4 < args.len) {
            block = args[i + 1 .. i + 5];
            i += 4;
        } else if (std.mem.eql(u8, args[i], "--policy") and i + 4 < args.len) {
            policy = args[i + 1 ..]; // the RUIDs take the rest
            i = args.len;
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
    var bus: ubus.Conn = .{};
    defer bus.deinit(init.gpa);
    var settings_arena: std.heap.ArenaAllocator = .init(init.gpa);
    defer settings_arena.deinit();
    var settings = try loadSettings(settings_arena.allocator(), init.gpa, io, &bus, config_name);
    const sock = try PacketSocket.open(io, settings.interface);
    defer sock.close();
    if (steer) |s| return steerOnce(io, sock, settings, s);
    if (policy) |p| return policyOnce(io, sock, p);
    if (block) |b| return blockOnce(io, sock, b);

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

    log.info("controller {x} on {s}{s}, auto-WPS {s}, steering {s}", .{ sock.mac, settings.interface, if (observe) " (observe only)" else "", if (ctl.cfg.auto_wps) "on" else "off", @tagName(ctl.cfg.steering) });
    for (settings.fronthaul, [_][]const u8{ "2.4", "5" }) |bss, band| {
        if (bss) |b| log.info("  {s} GHz agent radios get \"{s}\"", .{ band, b.ssid });
    }

    var probes: ProbeFeed = .{};
    defer probes.sub.deinit(init.gpa);
    var resubscribe_at: i64 = 0;
    var mesh_at: i64 = 0;
    var local_at: i64 = 0;
    var mesh_failing = false; // log a failing write once, not every 5 s into logd's small ring

    var rx: [cmdu.max_frame]u8 = undefined;
    var tx: [cmdu.max_frame]u8 = undefined;
    while (true) {
        const now = Io.Clock.awake.now(io).toMilliseconds();

        if (!probes.sub.active() and now >= resubscribe_at) {
            var fresh: std.heap.ArenaAllocator = .init(init.gpa);
            if (loadSettings(fresh.allocator(), init.gpa, io, &bus, config_name)) |s| {
                settings_arena.deinit();
                settings_arena = fresh;
                settings = s;
                ctl.cfg.fronthaul = settings.fronthaul;
                ctl.cfg.steering = settings.steering;
                ctl.setLocal(settings.local);
                if (settings.steering == .on and !observe) enableBtm(init.gpa, &bus, settings);
            } else |err| {
                fresh.deinit();
                log.warn("reloading settings failed ({t}), keeping the old ones", .{err});
            }
            probes.start(init.gpa, &bus, settings.hostapd_objects) catch |err| {
                log.warn("hostapd subscription failed ({t})", .{err});
                resubscribe_at = now + resubscribe_after_ms;
            };
        }

        var fds = [_]posix.pollfd{
            .{ .fd = sock.fd, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = probes.sub.fd(), .events = posix.POLL.IN, .revents = 0 },
        };
        _ = try posix.poll(&fds, 1000);

        if (fds[0].revents & posix.POLL.IN != 0) {
            while (sock.recv(&rx)) |frame| {
                const f = cmdu.Frame.parse(frame) catch continue;
                const secrets = try wsc.Secrets.random(io);
                const reply = ctl.onFrame(f, now, &tx, secrets) catch |err| {
                    log.warn("frame {f} from {x}: {t}", .{ f.msg_type, f.src, err });
                    continue;
                };
                if (reply) |r| send(sock, observe, r);
            }
        }

        if (fds[1].revents != 0) {
            if (!probes.drain(init.gpa, &ctl, settings, now)) {
                probes.sub.stop();
                resubscribe_at = now + resubscribe_after_ms;
                log.info("hostapd subscription ended (Wi-Fi reload?), resubscribing", .{});
            }
        }

        const t = ctl.tick(now, &tx) catch |err| blk: {
            log.warn("tick: {t}", .{err});
            break :blk Controller.Tick{};
        };
        if (t.frame) |frame| send(sock, observe, frame);
        if (t.wps) |w| openWps(init.gpa, &bus, settings, w);
        if (t.btm) |b| suggestMove(init.gpa, &bus, settings, observe, b);

        if (settings.steering != .off and now >= local_at) {
            local_at = now + local_every_ms;
            pollLocalClients(init.gpa, &bus, settings, &ctl, now);
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

/// Streamed through a small buffer: full tables (4 agents x 32 clients) are
/// ~19 KB, which as one buffer would stay resident on the stack.
fn writeMesh(io: Io, ctl: *const Controller, now: i64) !void {
    var af = try Io.Dir.cwd().createFileAtomic(io, mesh_path, .{ .make_path = true, .replace = true });
    defer af.deinit(io);
    var buf: [1024]u8 = undefined;
    var fw = af.file.writer(io, &buf);
    try ctl.writeMesh(&fw.interface, now);
    try fw.interface.flush();
    try af.replace(io);
}

fn send(sock: PacketSocket, observe: bool, frame: []const u8) void {
    const f = cmdu.Frame.parse(frame) catch unreachable; // built by us
    if (observe) {
        log.info("observe: would send {f} to {x}", .{ f.msg_type, f.dst });
        return;
    }
    sock.send(frame) catch |err| log.warn("send {f} to {x}: {t}", .{ f.msg_type, f.dst, err });
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

/// hostapd notifications (probe requests, 802.11v answers) from a ubus subscription.
const ProbeFeed = struct {
    sub: ubus.Subscriber = .{},

    fn start(feed: *ProbeFeed, gpa: Allocator, bus: *ubus.Conn, objects: []const []const u8) !void {
        // hostapd only reports probes to subscribers once notify_response is set.
        for (objects) |obj| if (bus.call(gpa, obj, "notify_response", .{ .notify_response = 0 })) |r| gpa.free(r) else |_| {};
        try feed.sub.start(gpa, objects);
        log.info("watching probe requests on {d} hostapd interface(s)", .{objects.len});
    }

    /// One message per poll wakeup. False once the subscription ended.
    fn drain(feed: *ProbeFeed, gpa: Allocator, ctl: *Controller, settings: Settings, now: i64) bool {
        const n = feed.sub.next(gpa) catch return false;
        // A malformed or unknown event is dropped; the subscription goes on.
        const ev = parseEvent(n orelse return true) catch return true;
        switch (ev orelse return true) {
            .btm_answer => |a| ctl.onBtmAnswer(a.sta, a.status),
            .probe => |p| {
                const bss = settings.localIndex(p.ifname);
                const heard: ?controller.Heard = if (bss != null and p.signal != null)
                    .{ .bss = bss.?, .rssi = std.math.lossyCast(i8, p.signal.?), .at = now }
                else
                    null;
                ctl.onProbe(p.sta, now, heard);
            },
        }
        return true;
    }
};

const Event = union(enum) {
    probe: struct { sta: cmdu.Mac, ifname: []const u8, signal: ?i64 },
    btm_answer: struct { sta: cmdu.Mac, status: u8 },
};

fn parseEvent(n: ubus.Subscriber.Notification) !?Event {
    const sta = parseMacText(try n.data.string("address") orelse return null) orelse return null;
    if (std.mem.eql(u8, n.method, "probe")) return .{ .probe = .{
        .sta = sta,
        .ifname = try n.data.string("ifname") orelse "",
        .signal = try n.data.int("signal"),
    } };
    if (std.mem.eql(u8, n.method, "bss-transition-response")) return .{ .btm_answer = .{
        .sta = sta,
        .status = std.math.cast(u8, try n.data.int("status-code") orelse return null) orelse return null,
    } };
    return null;
}

/// `--steer`: one Client Steering Request, built as the controller builds it,
/// so the whole path (agent, client, report) can be tested without waiting
/// for a weak signal. prplMesh certifies steering the same way.
fn steerOnce(io: Io, sock: PacketSocket, s: Settings, args: []const []const u8) !void {
    var macs: [4]cmdu.Mac = undefined;
    for (args, &macs) |text, *m| m.* = macOrExit(text);
    const agent, const sta, const from, const to = macs;
    const local = for (s.local) |l| (if (std.mem.eql(u8, &l.bssid, &to)) break l) else {
        std.debug.print("{s} is not one of this router's BSSes\n", .{args[3]});
        std.process.exit(2);
    };
    var mid: u16 = undefined;
    io.random(std.mem.asBytes(&mid));
    const req = cmdu.steeringRequest(from, sta, local.target());
    var tx: [cmdu.max_frame]u8 = undefined;
    try sock.send(try cmdu.build(&tx, agent, sock.mac, .client_steering_request, mid, &.{
        .{ .type = .steering_request, .value = &req },
    }));
    log.info("asked agent {x} to move {x} to {x} (mid {d})", .{ agent, sta, to, mid });
}

/// `--policy`: one Multi-AP Policy Config Request, setting the agent's own
/// steering for the listed radios.
fn policyOnce(io: Io, sock: PacketSocket, args: []const []const u8) !void {
    const agent = macOrExit(args[0]);
    const policy: cmdu.SteeringPolicy = if (std.mem.eql(u8, args[1], "off"))
        .disallowed
    else if (std.mem.eql(u8, args[1], "mandate"))
        .mandated
    else if (std.mem.eql(u8, args[1], "allow"))
        .allowed
    else {
        std.debug.print("mode is off, mandate or allow, not {s}\n{s}", .{ args[1], usage });
        std.process.exit(2);
    };
    const dbm = std.fmt.parseInt(i8, args[2], 10) catch dbmOutOfRange(args[2]);
    if (dbm > 0 or dbm < -110) dbmOutOfRange(args[2]);
    const ruid_args = args[3..];
    if (ruid_args.len > controller.max_radios) {
        std.debug.print("at most {d} RUIDs\n{s}", .{ controller.max_radios, usage });
        std.process.exit(2);
    }
    var ruids: [controller.max_radios]cmdu.Mac = undefined;
    for (ruid_args, ruids[0..ruid_args.len]) |text, *m| m.* = macOrExit(text);
    var value: [3 + 9 * controller.max_radios]u8 = undefined;
    const tlv = cmdu.steeringPolicy(&value, ruids[0..ruid_args.len], policy, dbm);
    var mid: u16 = undefined;
    io.random(std.mem.asBytes(&mid));
    var tx: [cmdu.max_frame]u8 = undefined;
    try sock.send(try cmdu.build(&tx, agent, sock.mac, .multi_ap_policy_config_request, mid, &.{
        .{ .type = .steering_policy, .value = tlv },
    }));
    log.info("sent steering policy {s} at {d} dBm for {d} radio(s) to agent {x} (mid {d})", .{ args[1], dbm, ruid_args.len, agent, mid });
}

/// `--block`: one Client Association Control Request, keeping a client off a BSS.
fn blockOnce(io: Io, sock: PacketSocket, args: []const []const u8) !void {
    const agent = macOrExit(args[0]);
    const bssid = macOrExit(args[1]);
    const sta = macOrExit(args[2]);
    const seconds = std.fmt.parseInt(u16, args[3], 10) catch {
        std.debug.print("not seconds (0-65535): {s}\n{s}", .{ args[3], usage });
        std.process.exit(2);
    };
    const value = cmdu.associationControl(bssid, sta, seconds != 0, seconds);
    var mid: u16 = undefined;
    io.random(std.mem.asBytes(&mid));
    var tx: [cmdu.max_frame]u8 = undefined;
    try sock.send(try cmdu.build(&tx, agent, sock.mac, .client_association_control_request, mid, &.{
        .{ .type = .client_association_control_request, .value = &value },
    }));
    log.info("asked agent {x} to block {x} from {x} for {d} s, 0 = unblock (mid {d})", .{ agent, sta, bssid, seconds, mid });
}

fn macOrExit(text: []const u8) cmdu.Mac {
    return parseMacText(text) orelse {
        std.debug.print("not a MAC: {s}\n{s}", .{ text, usage });
        std.process.exit(2);
    };
}

fn dbmOutOfRange(text: []const u8) noreturn {
    std.debug.print("DBM is between -110 and 0, not {s}\n{s}", .{ text, usage });
    std.process.exit(2);
}

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
fn enableBtm(gpa: Allocator, bus: *ubus.Conn, s: Settings) void {
    for (s.local_objects) |obj| {
        const r = bus.call(gpa, obj, "bss_mgmt_enable", .{ .bss_transition = true }) catch |err| {
            log.warn("bss_mgmt_enable on {s} failed: {t}", .{ obj, err });
            continue;
        };
        gpa.free(r);
    }
}

fn suggestMove(gpa: Allocator, bus: *ubus.Conn, s: Settings, observe: bool, b: controller.Btm) void {
    const obj = s.local_objects[b.bss];
    // Neighbor Report body: BSSID, BSSID info (reachable, secure, same keys), op class, channel, PHY type VHT.
    var nr: [13]u8 = undefined;
    nr[0..6].* = b.target.bssid;
    nr[6..10].* = .{ 0x0f, 0, 0, 0 };
    nr[10] = b.target.op_class;
    nr[11] = b.target.channel;
    nr[12] = 9;
    const sta = controller.macText(b.sta);
    const neighbor = std.fmt.bytesToHex(nr, .lower);
    if (observe) {
        log.info("observe: would call {s} bss_transition_request for {s}, neighbor {s}", .{ obj, &sta, &neighbor });
        return;
    }
    const arg = .{ .addr = &sta, .disassociation_imminent = false, .abridged = true, .validity_period = 30, .neighbors = .{&neighbor} };
    const r = bus.call(gpa, obj, "bss_transition_request", arg) catch |err| {
        log.warn("bss_transition_request to {x} on {s} failed: {t}", .{ b.sta, obj, err });
        return;
    };
    gpa.free(r);
}

fn pollLocalClients(gpa: Allocator, bus: *ubus.Conn, s: Settings, ctl: *Controller, now: i64) void {
    var list: [controller.max_clients]controller.LocalClient = undefined;
    var n: usize = 0;
    for (s.local_objects, 0..) |obj, bss| {
        const raw = bus.call(gpa, obj, "get_clients", .{}) catch continue;
        defer gpa.free(raw);
        n += parseClients(.{ .rest = raw }, @intCast(bss), list[n..]) catch continue;
    }
    ctl.setLocalClients(list[0..n], now);
}

/// hostapd `get_clients` output into `out`; returns how many were filled.
fn parseClients(reply: ubus.List, bss: u8, out: []controller.LocalClient) !usize {
    var clients = try reply.list("clients") orelse return 0;
    var n: usize = 0;
    while (try clients.next()) |e| {
        if (n == out.len) break;
        const mac = parseMacText(e.name) orelse continue;
        const client = e.value.asList() orelse continue;
        const sig = try client.int("signal") orelse continue;
        // Extended Capabilities bit 19: BSS Transition (802.11v).
        var btm = false;
        if (try client.list("extended_capabilities")) |caps| {
            var it = caps;
            var k: usize = 0;
            while (try it.next()) |octet| : (k += 1) if (k == 2) {
                btm = (octet.value.asInt() orelse 0) & 0x08 != 0;
                break;
            };
        }
        out[n] = .{ .mac = mac, .bss = bss, .rssi = std.math.lossyCast(i8, sig), .btm = btm };
        n += 1;
    }
    return n;
}

test "hostapd output as captured on the C6" {
    const t = std.testing;
    const vectors = @import("testdata/blobmsg_vectors.zig");
    var bytes: [2048]u8 = undefined;
    var list: [4]controller.LocalClient = undefined;
    const n = try parseClients(.{ .rest = try std.fmt.hexToBytes(&bytes, vectors.cases[5].hex) }, 0, &list);
    try t.expectEqual(2, n);
    try t.expectEqual(-74, list[0].rssi);
    try t.expect(list[0].btm);
    try t.expect(!list[1].btm);

    const probe = (try parseEvent(.{ .method = "probe", .data = .{ .rest = try std.fmt.hexToBytes(&bytes, vectors.cases[6].hex) } })).?.probe;
    try t.expectEqual(-62, probe.signal.?);
    try t.expectEqualStrings("phy1-ap0", probe.ifname);
    try t.expectEqual(0xef, probe.sta[5]);

    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try ubus.putFields(&w, .{ .address = "02:00:00:00:c0:de", .@"dialog-token" = 1, .@"status-code" = 1, .@"bss-termination-delay" = 0 });
    const answer = (try parseEvent(.{ .method = "bss-transition-response", .data = .{ .rest = w.buffered() } })).?.btm_answer;
    try t.expectEqual(1, answer.status);
    try t.expectEqual(null, try parseEvent(.{ .method = "assoc", .data = .{ .rest = w.buffered() } }));
}

fn openWps(gpa: Allocator, bus: *ubus.Conn, s: Settings, w: controller.WpsAction) void {
    const sta = controller.macText(w.stale_station);
    const del = .{ .addr = &sta, .reason = 3, .deauth = true, .ban_time = 0 };
    for (s.hostapd_objects) |obj| if (bus.call(gpa, obj, "del_client", del)) |r| gpa.free(r) else |_| {};
    const obj = s.wps_object orelse {
        log.warn("no WPS-enabled fronthaul found, cannot open a window", .{});
        return;
    };
    if (bus.call(gpa, obj, "wps_start", .{})) |r| {
        gpa.free(r);
        log.warn("opened WPS on {s} (window {d}); press WPS on the satellite", .{ obj, w.window });
    } else |err| switch (err) {
        // wpad-basic builds hostapd without WPS, e.g. after a sysupgrade to a stock image.
        error.MethodNotFound => log.err("{s} has no WPS: install the full wpad (wpad-mbedtls) to re-pair satellites", .{obj}),
        else => log.warn("wps_start on {s} failed: {t}", .{ obj, err }),
    }
}

fn loadSettings(arena: Allocator, gpa: Allocator, io: Io, bus: *ubus.Conn, config_name: []const u8) !Settings {
    const own = try readUci(arena, io, config_name);
    const main_section = own.section("main") orelse return error.MissingMainSection;
    const wifi = try readUci(arena, io, "wireless");

    // Every wifi-iface that is up: its UCI section and its hostapd object.
    const status_raw = try bus.call(gpa, "network.wireless", "status", .{});
    defer gpa.free(status_raw);
    const Up = struct { section: []const u8, object: []const u8 };
    var up: std.ArrayList(Up) = .empty;
    var radios: ubus.List = .{ .rest = status_raw };
    while (try radios.next()) |radio| {
        var ifaces = try (radio.value.asList() orelse continue).list("interfaces") orelse continue;
        while (try ifaces.next()) |e| {
            const iface = e.value.asList() orelse continue;
            const ifname = try iface.string("ifname") orelse continue;
            try up.append(arena, .{
                .section = try iface.string("section") orelse continue,
                .object = try std.mem.concat(arena, u8, &.{ "hostapd.", ifname }),
            });
        }
    }

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
        const obj = for (up.items) |u| {
            if (std.mem.eql(u8, u.section, section)) break u.object;
        } else continue;
        if (band == 1) wps_object = obj;
        if (localBss(gpa, bus, obj)) |found| {
            var bss = found;
            bss.ssid = ssid; // no longer than full_ssid, so at most 32
            try local.append(arena, bss);
            try local_objects.append(arena, obj);
        } else |err| log.warn("{s} get_status: {t}", .{ obj, err });
    }

    const objects = try arena.alloc([]const u8, up.items.len);
    for (up.items, objects) |u, *o| o.* = u.object;

    return .{
        .interface = main_section.get("interface") orelse "br-lan",
        .fronthaul = fronthaul,
        .auto_wps = std.mem.eql(u8, main_section.get("auto_wps") orelse "0", "1"),
        .wps_object = wps_object,
        .hostapd_objects = objects,
        .steering = steering: {
            const v = main_section.get("steering") orelse "0";
            if (std.mem.eql(u8, v, "1")) break :steering .on;
            if (std.mem.eql(u8, v, "log")) break :steering .log;
            break :steering .off;
        },
        .local = local.items,
        .local_objects = local_objects.items,
    };
}

fn localBss(gpa: Allocator, bus: *ubus.Conn, obj: []const u8) !controller.LocalBss {
    const raw = try bus.call(gpa, obj, "get_status", .{});
    defer gpa.free(raw);
    const st: ubus.List = .{ .rest = raw };
    return .{
        .bssid = parseMacText(try st.string("bssid") orelse "") orelse return error.BadBssid,
        .band = .fromMhz(try uintField(u32, st, "freq")),
        .op_class = try uintField(u8, st, "op_class"),
        .channel = try uintField(u8, st, "channel"),
    };
}

fn uintField(comptime T: type, l: ubus.List, name: []const u8) !T {
    return std.math.cast(T, try l.int(name) orelse return error.MissingField) orelse error.OutOfRange;
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
    var af = try Io.Dir.cwd().createFileAtomic(io, state_path, .{ .make_path = true, .replace = true });
    defer af.deinit(io);
    var buf: [1024]u8 = undefined;
    var fw = af.file.writer(io, &buf);
    try ctl.save(&fw.interface);
    try fw.interface.flush();
    try af.replace(io);
}

test {
    _ = @import("cmdu.zig");
    _ = @import("wsc.zig");
    _ = @import("controller.zig");
    _ = @import("uci.zig");
    _ = @import("ubus.zig");
}
