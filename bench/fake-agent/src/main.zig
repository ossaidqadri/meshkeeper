//! A fake EasyMesh satellite, modelled on the TP-Link AX12 (docs/field-notes.md): it searches for a
//! controller, answers topology and capability queries, sends an M1 per radio, and checks that the
//! M2 it gets back decrypts to the controller's SSID and key. Frames travel as datagrams on a unix
//! socket, one Ethernet frame each, which is QEMU's `-netdev dgram` format.
//!
//! It only builds what src/ doesn't already have (the enrollee side of WSC: M1 builder, M2 verify).
//! Events go to stderr, one line each, for the tests to read; the exit status is 0 only when both
//! radios got a valid M2 and the controller's link-metrics query was answered.

const std = @import("std");
const cmdu = @import("cmdu");
const wsc = @import("wsc");
const crypto = std.crypto;
const mem = std.mem;
const Io = std.Io;
const linux = std.os.linux;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Aes128 = crypto.core.aes.Aes128;

// Made-up identifiers (the repo's test set), never real hardware addresses.
const al_mac: cmdu.Mac = .{ 0x02, 0x00, 0x00, 0xa0, 0xd9, 0x50 };
const bsta_mac: cmdu.Mac = .{ 0x06, 0x00, 0x00, 0xa0, 0xd9, 0x4f };
const client_mac: cmdu.Mac = .{ 0x02, 0x00, 0x00, 0x00, 0xc0, 0xde };

const Radio = struct {
    ruid: cmdu.Mac,
    rf_band: u8,
    freq_band: u8,
    factory_ssid: []const u8,
    /// What the M2 must carry; given on the command line.
    want_ssid: []const u8 = "",
    want_key: []const u8 = "",
    applied_ssid: ?[]const u8 = null,
    m1: [512]u8 = undefined,
    m1_len: usize = 0,
    dh_private: [wsc.dh_len]u8 = undefined,
    nonce: [16]u8 = undefined,
    verified: bool = false,
};

var radios = [2]Radio{
    .{ .ruid = .{ 0x02, 0x00, 0x00, 0xa0, 0xd9, 0x4e }, .rf_band = wsc.rf_band_24, .freq_band = cmdu.band_24, .factory_ssid = "TP-Link_D950_2G" },
    .{ .ruid = .{ 0x02, 0x00, 0x00, 0xa0, 0xd9, 0x4f }, .rf_band = wsc.rf_band_5, .freq_band = cmdu.band_5, .factory_ssid = "TP-Link_D950_5G" },
};

// ---- WSC, enrollee side ----------------------------------------------------------------------
// The shared parts (attribute ids, writers, DH, key derivation) come from src/wsc.zig.

const dh_len = wsc.dh_len;
const putAttr = wsc.putAttr;
const putInt = wsc.putAttrInt;

/// An M1 the way an AX12 radio sends it (WSC 2.0, EasyMesh enrollee).
fn buildM1(r: *Radio, io: Io) !void {
    io.random(&r.dh_private);
    io.random(&r.nonce);
    var uuid: [16]u8 = undefined;
    io.random(&uuid);
    const public = try wsc.dhPublic(&r.dh_private);
    var w: Io.Writer = .fixed(&r.m1);
    try putAttr(&w, .version, &.{0x10});
    try putAttr(&w, .msg_type, &.{wsc.msg_m1});
    try putAttr(&w, .uuid_e, &uuid);
    try putAttr(&w, .mac, &r.ruid);
    try putAttr(&w, .enrollee_nonce, &r.nonce);
    try putAttr(&w, .public_key, &public);
    try putInt(&w, .auth_type_flags, @as(u16, 0x0001 | wsc.auth_wpa2psk | wsc.auth_sae));
    try putInt(&w, .encr_type_flags, @as(u16, 0x0001 | 0x0008));
    try putAttr(&w, .conn_type_flags, &.{0x01});
    try putInt(&w, .config_methods, @as(u16, 0x0080));
    try putAttr(&w, .manufacturer, "Bench");
    try putAttr(&w, .model_name, "fake-agent");
    try putAttr(&w, .model_number, "1");
    try putAttr(&w, .serial_number, "1");
    try putAttr(&w, .primary_dev_type, &.{ 0x00, 0x06, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01 });
    try putAttr(&w, .dev_name, "fake-agent");
    try putAttr(&w, .rf_bands, &.{r.rf_band});
    try putInt(&w, .assoc_state, @as(u16, 0));
    try putInt(&w, .config_error, @as(u16, 0));
    try putInt(&w, .dev_password_id, @as(u16, 0));
    try putInt(&w, .os_version, @as(u32, 0x80000000));
    r.m1_len = w.buffered().len;
}

const M2Result = struct { ssid: []const u8, key: []const u8, mac: *const [6]u8 };
const M2Error = error{ NotM2, Truncated, MissingAttribute, WrongNonce, BadAuthenticator, BadKeyWrapAuth, BadPadding, BadPeerKey, BadLength };

const AttrView = struct { t: wsc.Attr, v: []const u8, start: usize };

fn nextAttr(r: *Io.Reader, base: []const u8) M2Error!?AttrView {
    if (r.bufferedLen() == 0) return null;
    const start = base.len - r.bufferedLen();
    const t = r.takeInt(u16, .big) catch return error.Truncated;
    const n = r.takeInt(u16, .big) catch return error.Truncated;
    const v = r.take(n) catch return error.Truncated;
    return .{ .t = @fromBackingInt(t), .v = v, .start = start };
}

/// Checks M2 against what this radio sent in M1: nonce echo, both authenticators, and returns the
/// decrypted settings. `plain` receives the decrypted settings, the result points into it.
fn verifyM2(r: *const Radio, m2: []const u8, plain: *[512]u8) M2Error!M2Result {
    var registrar_nonce: ?[]const u8 = null;
    var public_key: ?[]const u8 = null;
    var encrypted: ?[]const u8 = null;
    var authenticator: ?AttrView = null;
    var is_m2 = false;
    var rd: Io.Reader = .fixed(m2);
    while (try nextAttr(&rd, m2)) |a| switch (a.t) {
        .msg_type => is_m2 = a.v.len == 1 and a.v[0] == wsc.msg_m2,
        .enrollee_nonce => if (!mem.eql(u8, a.v, &r.nonce)) return error.WrongNonce,
        .registrar_nonce => registrar_nonce = a.v,
        .public_key => public_key = a.v,
        .encr_settings => encrypted = a.v,
        .authenticator => authenticator = a,
        else => {},
    };
    if (!is_m2) return error.NotM2;
    const rn = registrar_nonce orelse return error.MissingAttribute;
    const pk = public_key orelse return error.MissingAttribute;
    const enc = encrypted orelse return error.MissingAttribute;
    const auth = authenticator orelse return error.MissingAttribute;
    if (rn.len != 16 or pk.len != dh_len or enc.len < 32 or enc.len % 16 != 0 or enc.len - 16 > plain.len or auth.v.len != 8) return error.BadLength;

    const shared = wsc.dhShared(&r.dh_private, pk[0..dh_len]) catch return error.BadPeerKey;
    const keys = wsc.Keys.derive(&shared, &r.nonce, &r.ruid, rn[0..16]);

    var mac: [HmacSha256.mac_length]u8 = undefined;
    var h = HmacSha256.init(&keys.auth_key);
    h.update(r.m1[0..r.m1_len]);
    h.update(m2[0..auth.start]);
    h.final(&mac);
    if (!crypto.timing_safe.eql([8]u8, mac[0..8].*, auth.v[0..8].*)) return error.BadAuthenticator;

    // IV || AES-128-CBC(KeyWrapKey, settings || KeyWrapAuthenticator || PKCS#7 padding).
    const ct = enc[16..];
    const dec = Aes128.initDec(keys.key_wrap_key);
    var prev: [16]u8 = enc[0..16].*;
    var i: usize = 0;
    while (i < ct.len) : (i += 16) {
        const block: [16]u8 = ct[i..][0..16].*;
        dec.decrypt(plain[i..][0..16], &block);
        for (plain[i..][0..16], prev) |*p, x| p.* ^= x;
        prev = block;
    }
    const pad = plain[ct.len - 1];
    if (pad == 0 or pad > 16 or pad > ct.len) return error.BadPadding;
    for (plain[ct.len - pad .. ct.len]) |b| if (b != pad) return error.BadPadding;
    const inner = plain[0 .. ct.len - pad];

    var ssid: ?[]const u8 = null;
    var key: ?[]const u8 = null;
    var inner_mac: ?[]const u8 = null;
    var kwa: ?AttrView = null;
    var ir: Io.Reader = .fixed(inner);
    while (try nextAttr(&ir, inner)) |a| switch (a.t) {
        .ssid => ssid = a.v,
        .network_key => key = a.v,
        .mac => inner_mac = a.v,
        .key_wrap_auth => kwa = a,
        else => {},
    };
    const k = kwa orelse return error.MissingAttribute;
    var kmac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&kmac, inner[0..k.start], &keys.auth_key);
    if (k.v.len != 8 or !crypto.timing_safe.eql([8]u8, kmac[0..8].*, k.v[0..8].*)) return error.BadKeyWrapAuth;
    const im = inner_mac orelse return error.MissingAttribute;
    if (im.len != 6) return error.BadLength;
    return .{ .ssid = ssid orelse return error.MissingAttribute, .key = key orelse return error.MissingAttribute, .mac = im[0..6] };
}
// ---- transport ---------------------------------------------------------------------------------

const Sock = struct {
    fd: i32,
    peer: linux.sockaddr.un,

    fn open(own: []const u8, peer_path: []const u8) !Sock {
        const rc = linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
        const fd: i32 = @intCast(rc);
        var addr: linux.sockaddr.un = .{ .path = @splat(0) };
        @memcpy(addr.path[0..own.len], own);
        _ = linux.unlink(@ptrCast(&addr.path)); // a stale file from an earlier run
        if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS) return error.BindFailed;
        var peer: linux.sockaddr.un = .{ .path = @splat(0) };
        @memcpy(peer.path[0..peer_path.len], peer_path);
        return .{ .fd = fd, .peer = peer };
    }

    fn send(s: Sock, frame: []const u8) void {
        _ = linux.sendto(s.fd, frame.ptr, frame.len, 0, @ptrCast(&s.peer), @sizeOf(linux.sockaddr.un));
    }

    /// Next datagram within `timeout_ms`, or null.
    fn recv(s: Sock, buf: []u8, timeout_ms: i32) ?[]const u8 {
        var pfd = [_]linux.pollfd{.{ .fd = s.fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.errno(linux.poll(&pfd, 1, timeout_ms)) != .SUCCESS or pfd[0].revents & linux.POLL.IN == 0) return null;
        const rc = linux.recvfrom(s.fd, buf.ptr, buf.len, 0, null, null);
        if (linux.errno(rc) != .SUCCESS) return null;
        return buf[0..rc];
    }
};

fn say(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ "\n", args);
}

// ---- the agent ---------------------------------------------------------------------------------

const Agent = struct {
    sock: Sock,
    io: Io,
    controller: ?cmdu.Mac = null,
    mid: u16 = 0x4000,
    searched: bool = false,
    metrics_answered: bool = false,

    fn nextMid(a: *Agent) u16 {
        defer a.mid +%= 1;
        return a.mid;
    }

    fn sendFrame(a: *Agent, dst: cmdu.Mac, msg: cmdu.MsgType, mid: u16, tlvs: []const cmdu.TlvEntry) void {
        var out: [cmdu.max_frame]u8 = undefined;
        const frame = cmdu.build(&out, dst, al_mac, msg, mid, tlvs) catch return;
        a.sock.send(frame);
    }

    fn search(a: *Agent) void {
        for (radios) |r| {
            a.sendFrame(cmdu.multicast, .ap_autoconfig_search, a.nextMid(), &.{
                .{ .type = .al_mac, .value = &al_mac },
                .{ .type = .searched_role, .value = &.{cmdu.role_registrar} },
                .{ .type = .autoconfig_freq_band, .value = &.{r.freq_band} },
                .{ .type = .searched_service, .value = &.{ 1, cmdu.service_controller } },
                .{ .type = .supported_service, .value = &.{ 1, cmdu.service_agent } },
                .{ .type = .multi_ap_profile, .value = &.{cmdu.profile} },
            });
        }
        say("search sent", .{});
    }

    fn topology(a: *Agent, dst: cmdu.Mac, mid: u16) void {
        var info: [7 + 9]u8 = undefined;
        info[0..6].* = al_mac;
        info[6] = 1;
        info[7..13].* = bsta_mac;
        info[13..16].* = .{ 0x01, 0x08, 0 };
        var ops: [128]u8 = undefined;
        var w: Io.Writer = .fixed(&ops);
        w.writeByte(radios.len) catch return;
        for (radios) |r| {
            const ssid = r.applied_ssid orelse r.factory_ssid;
            w.writeAll(&r.ruid) catch return;
            w.writeByte(1) catch return;
            w.writeAll(&r.ruid) catch return; // the BSSID is the radio's own MAC
            w.writeByte(@intCast(ssid.len)) catch return;
            w.writeAll(ssid) catch return;
        }
        // One client on the 5 GHz BSS.
        var clients: [1 + 6 + 2 + 6 + 2]u8 = undefined;
        clients[0] = 1;
        clients[1..7].* = radios[1].ruid;
        mem.writeInt(u16, clients[7..9], 1, .big);
        clients[9..15].* = client_mac;
        mem.writeInt(u16, clients[15..17], 30, .big);
        a.sendFrame(dst, .topology_response, mid, &.{
            .{ .type = .device_info, .value = &info },
            .{ .type = .supported_service, .value = &.{ 1, cmdu.service_agent } },
            .{ .type = .ap_operational_bss, .value = w.buffered() },
            .{ .type = .associated_clients, .value = &clients },
            .{ .type = .multi_ap_profile, .value = &.{cmdu.profile} },
        });
        say("topology answered", .{});
    }

    fn sendM1(a: *Agent, r: *Radio, dst: cmdu.Mac) void {
        buildM1(r, a.io) catch |err| return say("M1 build failed: {t}", .{err});
        var caps: [8]u8 = @splat(0);
        caps[0..6].* = r.ruid;
        a.sendFrame(dst, .ap_autoconfig_wsc, a.nextMid(), &.{
            .{ .type = .ap_radio_basic_caps, .value = &caps },
            .{ .type = .wsc, .value = r.m1[0..r.m1_len] },
        });
        say("M1 sent radio={x} rf_band={d}", .{ r.ruid, r.rf_band });
    }

    fn onM2(a: *Agent, f: cmdu.Frame) void {
        _ = a;
        const ruid_v = f.find(.ap_radio_identifier) orelse return;
        const wsc_v = f.find(.wsc) orelse return;
        if (ruid_v.len != 6) return;
        for (&radios) |*r| {
            if (!mem.eql(u8, &r.ruid, ruid_v)) continue;
            if (r.m1_len == 0) return say("M2 for radio {x} before its M1", .{r.ruid});
            var plain: [512]u8 = undefined;
            const res = verifyM2(r, wsc_v, &plain) catch |err| return say("M2 BAD radio={x}: {t}", .{ r.ruid, err });
            const ssid_ok = mem.eql(u8, res.ssid, r.want_ssid);
            const key_ok = mem.eql(u8, res.key, r.want_key);
            say("M2 {s} radio={x} ssid=\"{s}\" key=\"{s}\" mac={x}", .{ if (ssid_ok and key_ok) "ok" else "WRONG", r.ruid, res.ssid, res.key, res.mac.* });
            if (ssid_ok and key_ok) {
                // Like the AX12, apply it: later topology reports show the new SSID.
                r.verified = true;
                r.applied_ssid = r.want_ssid;
            }
        }
    }

    fn onFrame(a: *Agent, f: cmdu.Frame) void {
        if (mem.eql(u8, &f.src, &al_mac)) return;
        switch (f.msg_type) {
            .ap_autoconfig_response => {
                if (a.controller == null) say("autoconfig response from {x}", .{f.src});
                a.controller = f.src;
            },
            .topology_query => {
                a.controller = f.src;
                a.topology(f.src, f.mid);
                // The controller won't answer an M1 before it has a topology report.
                for (&radios) |*r| if (!r.verified) a.sendM1(r, f.src);
            },
            .ap_autoconfig_wsc => a.onM2(f),
            .ap_capability_query => a.sendFrame(f.src, .ap_capability_report, f.mid, &.{.{ .type = .ap_capability, .value = &.{0xc0} }}),
            .assoc_sta_link_metrics_query => {
                const sta = f.find(.sta_mac_address) orelse return;
                if (sta.len != 6 or !mem.eql(u8, sta, &client_mac)) return;
                var v: [6 + 1 + 6 + 4 + 4 + 4 + 1]u8 = undefined;
                v[0..6].* = client_mac;
                v[6] = 1;
                v[7..13].* = radios[1].ruid;
                mem.writeInt(u32, v[13..17], 0, .big);
                mem.writeInt(u32, v[17..21], 600, .big); // downlink Mbit/s
                mem.writeInt(u32, v[21..25], 300, .big); // uplink Mbit/s
                v[25] = 100; // RCPI 100 = -60 dBm
                a.sendFrame(f.src, .assoc_sta_link_metrics_response, f.mid, &.{.{ .type = .associated_sta_link_metrics, .value = &v }});
                if (!a.metrics_answered) say("link metrics answered client={x} rssi=-60", .{client_mac});
                a.metrics_answered = true;
            },
            .client_steering_request => {
                say("steering request received", .{});
                a.sendFrame(f.src, .ack, f.mid, &.{});
            },
            else => {},
        }
    }

    fn done(a: Agent) bool {
        return radios[0].verified and radios[1].verified and a.metrics_answered;
    }
};

const usage = "usage: fake-agent --sock PATH --peer PATH --want-2g SSID:KEY --want-5g SSID:KEY [--timeout SECONDS]\n";

fn wantFrom(arg: []const u8, r: *Radio) !void {
    const i = mem.indexOfScalar(u8, arg, ':') orelse return error.BadArgument;
    r.want_ssid = arg[0..i];
    r.want_key = arg[i + 1 ..];
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var own: ?[]const u8 = null;
    var peer: ?[]const u8 = null;
    var timeout_s: i64 = 120;
    var i: usize = 1;
    while (i + 1 < args.len) : (i += 2) {
        const flag = args[i];
        const v = args[i + 1];
        if (mem.eql(u8, flag, "--sock")) {
            own = v;
        } else if (mem.eql(u8, flag, "--peer")) {
            peer = v;
        } else if (mem.eql(u8, flag, "--want-2g")) {
            try wantFrom(v, &radios[0]);
        } else if (mem.eql(u8, flag, "--want-5g")) {
            try wantFrom(v, &radios[1]);
        } else if (mem.eql(u8, flag, "--timeout")) {
            timeout_s = try std.fmt.parseInt(i64, v, 10);
        } else {
            std.debug.print(usage, .{});
            return 2;
        }
    }
    if (own == null or peer == null or radios[0].want_ssid.len == 0 or radios[1].want_ssid.len == 0) {
        std.debug.print(usage, .{});
        return 2;
    }

    var agent: Agent = .{ .sock = try .open(own.?, peer.?), .io = io };
    const start = Io.Clock.awake.now(io).toMilliseconds();
    var last_search: i64 = -1_000_000;
    var rx: [cmdu.max_frame]u8 = undefined;
    say("agent up al_mac={x}", .{al_mac});
    while (!agent.done()) {
        const now = Io.Clock.awake.now(io).toMilliseconds();
        if (now - start > timeout_s * std.time.ms_per_s) break;
        // Until a controller answered, keep searching, like the AX12 does.
        if (agent.controller == null and now - last_search > 5 * std.time.ms_per_s) {
            agent.search();
            last_search = now;
        }
        const raw = agent.sock.recv(&rx, 500) orelse continue;
        const f = cmdu.Frame.parse(raw) catch continue;
        // Unicast to us, or the 1905 multicast.
        if (!mem.eql(u8, &f.dst, &al_mac) and !mem.eql(u8, &f.dst, &cmdu.multicast)) continue;
        agent.onFrame(f);
    }
    if (agent.done()) {
        say("done: both radios configured, link metrics answered", .{});
        return 0;
    }
    say("timeout: 2g_verified={} 5g_verified={} metrics_answered={}", .{ radios[0].verified, radios[1].verified, agent.metrics_answered });
    return 1;
}
