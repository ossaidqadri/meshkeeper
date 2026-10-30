//! Controller state machine. Pure: no sockets, no clocks, no processes. Frames
//! and events go in, reply frames and WPS actions come out, so every decision
//! is testable on the host.
//!
//! Policy, learned from a TP-Link Archer AX12 satellite:
//! - Applying an M2 restarts the agent's Wi-Fi and, after an agent reboot, it
//!   needs a WPS press to rejoin. So M2 is only sent when the agent's reported
//!   SSIDs (AP Operational BSS) or the configured credentials actually differ.
//! - After an agent power loss it probes but never authenticates until WPS.
//!   With `auto_wps`, the controller opens the router's WPS window, behind a
//!   gate: the agent's 1905 traffic stopped, its own radio has been probing for
//!   a minute, and windows are rate limited per outage.

const std = @import("std");
const cmdu = @import("cmdu.zig");
const wsc = @import("wsc.zig");
const Mac = cmdu.Mac;
const Sha256 = std.crypto.hash.sha2.Sha256;

const log = std.log.scoped(.controller);

pub const max_agents = 4;
pub const max_ifaces = 8;
pub const max_radios = 4;
pub const max_ssids = 4;

/// Milliseconds on a monotonic clock.
pub const Ms = i64;

pub const timing = struct {
    pub const query_interval: Ms = 5 * std.time.ms_per_min;
    pub const query_retry: Ms = 30 * std.time.ms_per_s;
    pub const agent_silent_after: Ms = 60 * std.time.ms_per_s;
    pub const probe_recent: Ms = 30 * std.time.ms_per_s;
    pub const probe_before_wps: Ms = 60 * std.time.ms_per_s;
    pub const wps_spacing: Ms = 150 * std.time.ms_per_s;
    pub const max_wps_per_outage = 3;
    pub const renew_spacing: Ms = 10 * std.time.ms_per_min;
};

/// Credentials digest, so a password change is detected without storing it.
pub const Digest = [8]u8;

pub fn digestOf(bss: wsc.Bss) Digest {
    var h = Sha256.init(.{});
    h.update(bss.ssid);
    h.update(&.{0});
    h.update(bss.passphrase);
    var auth: [2]u8 = undefined;
    std.mem.writeInt(u16, &auth, bss.auth, .big);
    h.update(&auth);
    return h.finalResult()[0..8].*;
}

pub const Config = struct {
    al_mac: Mac,
    /// Fronthaul credentials per agent radio band: [0] 2.4 GHz, [1] 5 GHz.
    fronthaul: [2]?wsc.Bss,
    auto_wps: bool,
};

const Band = enum(u1) {
    @"2.4" = 0,
    @"5" = 1,

    fn fromRfBands(rf: u8) ?Band {
        return switch (rf) {
            wsc.rf_band_24 => .@"2.4",
            wsc.rf_band_5 => .@"5",
            else => null,
        };
    }
};

pub const Radio = struct {
    ruid: Mac,
    band: ?Band = null,
    /// Wyhash of each SSID the agent last reported on this radio.
    ssids: [max_ssids]u64 = undefined,
    n_ssids: u8 = 0,
    /// Credentials this controller pushed to (or adopted from) the radio.
    applied: ?Digest = null,
    last_push: ?Ms = null,

    fn broadcasts(r: Radio, ssid: []const u8) bool {
        const h = std.hash.Wyhash.hash(0, ssid);
        return std.mem.indexOfScalar(u64, r.ssids[0..r.n_ssids], h) != null;
    }
};

pub const Agent = struct {
    al_mac: Mac,
    ifaces: [max_ifaces]Mac = undefined,
    n_ifaces: u8 = 0,
    radios: [max_radios]Radio = undefined,
    n_radios: u8 = 0,
    last_heard: ?Ms = null,
    last_report: ?Ms = null,
    last_query: ?Ms = null,
    last_renew: ?Ms = null,
    last_probe: ?Ms = null,
    probing_iface: Mac = undefined,
    outage: Outage = .{},

    const Outage = struct {
        first_probe: ?Ms = null,
        windows: u8 = 0,
        last_window: ?Ms = null,
    };

    fn radio(a: *Agent, ruid: Mac) ?*Radio {
        for (a.radios[0..a.n_radios]) |*r| if (std.mem.eql(u8, &r.ruid, &ruid)) return r;
        if (a.n_radios == max_radios) return null;
        a.radios[a.n_radios] = .{ .ruid = ruid };
        a.n_radios += 1;
        return &a.radios[a.n_radios - 1];
    }

    fn ownsIface(a: Agent, mac: Mac) bool {
        for (a.ifaces[0..a.n_ifaces]) |m| if (std.mem.eql(u8, &m, &mac)) return true;
        return false;
    }

    fn silent(a: Agent, now: Ms) bool {
        const heard = a.last_heard orelse return true;
        return now - heard > timing.agent_silent_after;
    }
};

pub const WpsAction = struct {
    /// Backhaul station to drop first: the router may still hold the agent's
    /// pre-reboot association (ath10k kept one for 7+ minutes).
    stale_station: Mac,
    agent: Mac,
    window: u8,
};

pub const Controller = struct {
    cfg: Config,
    agents: [max_agents]Agent = undefined,
    n_agents: u8 = 0,
    next_mid: u16,
    /// Learned state changed; the caller should persist it.
    dirty: bool = false,

    pub fn init(cfg: Config, first_mid: u16) Controller {
        return .{ .cfg = cfg, .next_mid = first_mid };
    }

    fn mid(c: *Controller) u16 {
        defer c.next_mid +%= 1;
        return c.next_mid;
    }

    pub fn agent(c: *Controller, al_mac: Mac) ?*Agent {
        for (c.agents[0..c.n_agents]) |*a| if (std.mem.eql(u8, &a.al_mac, &al_mac)) return a;
        return null;
    }

    fn agentOrNew(c: *Controller, al_mac: Mac) ?*Agent {
        if (c.agent(al_mac)) |a| return a;
        if (c.n_agents == max_agents) {
            log.warn("agent table full, ignoring {x}", .{al_mac});
            return null;
        }
        c.agents[c.n_agents] = .{ .al_mac = al_mac };
        c.n_agents += 1;
        c.dirty = true;
        log.info("new agent {x}", .{al_mac});
        return &c.agents[c.n_agents - 1];
    }

    /// Handles one received 1905 frame; returns a reply frame in `out`, if any.
    pub fn onFrame(c: *Controller, f: cmdu.Frame, now: Ms, out: []u8, secrets: wsc.Secrets) !?[]const u8 {
        if (std.mem.eql(u8, &f.src, &c.cfg.al_mac)) return null;
        const al_mac: Mac = if (f.find(.al_mac)) |v| (if (v.len == 6) v[0..6].* else return null) else f.src;
        // Only messages an agent sends about itself may create one. A TP-Link
        // backhaul STA also emits zero-filled 0x893a frames that parse as empty
        // CMDUs; those must not turn its radio MAC into a phantom agent.
        const introduces = switch (f.msg_type) {
            .ap_autoconfig_search, .topology_query, .topology_response, .ap_autoconfig_wsc => true,
            else => false,
        };
        const a = (if (introduces and f.tlv_bytes.len > 0) c.agentOrNew(al_mac) else c.agent(al_mac)) orelse return null;
        if (a.outage.windows > 0 or a.outage.first_probe != null) log.info("agent {x} is back", .{al_mac});
        a.last_heard = now;
        a.outage = .{};

        switch (f.msg_type) {
            .ap_autoconfig_search => {
                const searched = f.find(.searched_service) orelse return null;
                if (std.mem.indexOfScalar(u8, searched[@min(1, searched.len)..], cmdu.service_controller) == null) return null;
                const band = f.find(.autoconfig_freq_band) orelse return null;
                if (band.len != 1) return null;
                return try cmdu.build(out, al_mac, c.cfg.al_mac, .ap_autoconfig_response, f.mid, &.{
                    .{ .type = .supported_role, .value = &.{cmdu.role_registrar} },
                    .{ .type = .supported_freq_band, .value = band },
                    .{ .type = .supported_service, .value = &.{ 1, cmdu.service_controller } },
                    .{ .type = .multi_ap_profile, .value = &.{cmdu.profile} },
                });
            },
            .topology_query => {
                const info = cmdu.deviceInfo(c.cfg.al_mac);
                return try cmdu.build(out, f.src, c.cfg.al_mac, .topology_response, f.mid, &.{
                    .{ .type = .device_info, .value = &info },
                    .{ .type = .supported_service, .value = &.{ 1, cmdu.service_controller } },
                    .{ .type = .multi_ap_profile, .value = &.{cmdu.profile} },
                });
            },
            .topology_response => {
                try c.learnTopology(a, f, now);
                return null;
            },
            .ap_autoconfig_wsc => return c.answerM1(a, f, now, out, secrets),
            else => return null,
        }
    }

    fn learnTopology(c: *Controller, a: *Agent, f: cmdu.Frame, now: Ms) !void {
        a.last_report = now;
        if (f.find(.device_info)) |v| learnIfaces(c, a, v);
        const ops = f.find(.ap_operational_bss) orelse return;
        var ob: cmdu.OperationalBss = try .init(ops);
        while (try ob.nextRadio()) |next| {
            var it = next;
            const r = a.radio(it.ruid);
            if (r) |rad| rad.n_ssids = 0;
            while (try it.nextBss()) |bss| {
                const rad = r orelse continue;
                if (rad.n_ssids == max_ssids) continue;
                rad.ssids[rad.n_ssids] = std.hash.Wyhash.hash(0, bss.ssid);
                rad.n_ssids += 1;
            }
        }
    }

    fn learnIfaces(c: *Controller, a: *Agent, v: []const u8) void {
        // Device Information: AL MAC(6), count(1), then MAC(6) media(2) len(1) info(len).
        if (v.len < 7) return;
        var r: std.Io.Reader = .fixed(v[7..]);
        for (0..v[6]) |_| {
            const mac = (r.takeArray(6) catch return).*;
            r.discardAll(2) catch return;
            const info_len = r.takeByte() catch return;
            r.discardAll(info_len) catch return;
            if (a.ownsIface(mac) or a.n_ifaces == max_ifaces) continue;
            a.ifaces[a.n_ifaces] = mac;
            a.n_ifaces += 1;
            c.dirty = true;
        }
    }

    fn answerM1(c: *Controller, a: *Agent, f: cmdu.Frame, now: Ms, out: []u8, secrets: wsc.Secrets) !?[]const u8 {
        const caps = f.find(.ap_radio_basic_caps) orelse return null;
        const m1_raw = f.find(.wsc) orelse return null;
        if (caps.len < 6) return null;
        const m1 = wsc.M1.parse(m1_raw) catch |err| {
            log.warn("agent {x}: bad M1 ({t})", .{ a.al_mac, err });
            return null;
        };
        const band = Band.fromRfBands(m1.rf_bands) orelse return null;
        const r = a.radio(caps[0..6].*) orelse return null;
        if (r.band != band) {
            r.band = band;
            c.dirty = true;
        }
        const want = c.cfg.fronthaul[@intFromEnum(band)] orelse return null;
        if (!c.needsConfig(a, r, want)) return null;
        if (r.last_push) |t| if (now - t < timing.renew_spacing) {
            log.warn("agent {x} radio {x}: settings pushed {d} s ago, not again yet", .{ a.al_mac, r.ruid, @divTrunc(now - t, std.time.ms_per_s) });
            return null;
        };

        var m2_buf: [1024]u8 = undefined;
        var uuid: [16]u8 = @splat(0);
        uuid[0..6].* = c.cfg.al_mac;
        const m2 = try wsc.buildM2(&m2_buf, m1, want, &uuid, secrets);
        r.applied = digestOf(want);
        r.last_push = now;
        c.dirty = true;
        log.warn("agent {x} radio {x} ({s} GHz): pushing SSID \"{s}\". It will restart its Wi-Fi; if it stays offline, press WPS on it", .{ a.al_mac, r.ruid, @tagName(band), want.ssid });
        return try cmdu.build(out, f.src, c.cfg.al_mac, .ap_autoconfig_wsc, c.mid(), &.{
            .{ .type = .ap_radio_identifier, .value = &r.ruid },
            .{ .type = .wsc, .value = m2 },
        });
    }

    /// Only push when the agent's reported SSIDs or our credentials changed.
    /// Without a report yet, do nothing: an M2 costs the owner a WPS press.
    fn needsConfig(c: *Controller, a: *Agent, r: *Radio, want: wsc.Bss) bool {
        if (a.last_report == null) return false;
        if (!r.broadcasts(want.ssid)) return true;
        const d = digestOf(want);
        if (r.applied) |applied| return !std.mem.eql(u8, &applied, &d);
        // Already broadcasting the wanted SSID and never pushed by us: adopt it.
        r.applied = d;
        c.dirty = true;
        return false;
    }

    /// A probe request reached a router AP; `sta` is the sender.
    pub fn onProbe(c: *Controller, sta: Mac, now: Ms) void {
        for (c.agents[0..c.n_agents]) |*a| if (a.ownsIface(sta)) {
            a.last_probe = now;
            a.probing_iface = sta;
        };
    }

    pub const Tick = struct { frame: ?[]const u8 = null, wps: ?WpsAction = null };

    /// Periodic work: topology queries, renew requests and the auto-WPS gate.
    pub fn tick(c: *Controller, now: Ms, out: []u8) !Tick {
        for (c.agents[0..c.n_agents]) |*a| {
            if (c.wpsGate(a, now)) |action| return .{ .wps = action };
            if (a.silent(now)) continue;
            const due = if (a.last_report) |t| now - t > timing.query_interval else true;
            const retry_ok = if (a.last_query) |t| now - t > timing.query_retry else true;
            if (due and retry_ok) {
                a.last_query = now;
                return .{ .frame = try cmdu.build(out, a.al_mac, c.cfg.al_mac, .topology_query, c.mid(), &.{
                    .{ .type = .multi_ap_profile, .value = &.{cmdu.profile} },
                }) };
            }
            if (c.renewBand(a, now)) |band| {
                a.last_renew = now;
                log.info("agent {x}: settings differ on {s} GHz, asking it to renew", .{ a.al_mac, @tagName(band) });
                const freq: u8 = switch (band) {
                    .@"2.4" => cmdu.band_24,
                    .@"5" => cmdu.band_5,
                };
                return .{ .frame = try cmdu.build(out, a.al_mac, c.cfg.al_mac, .ap_autoconfig_renew, c.mid(), &.{
                    .{ .type = .al_mac, .value = &c.cfg.al_mac },
                    .{ .type = .supported_role, .value = &.{cmdu.role_registrar} },
                    .{ .type = .supported_freq_band, .value = &.{freq} },
                }) };
            }
        }
        return .{};
    }

    fn renewBand(c: *Controller, a: *Agent, now: Ms) ?Band {
        if (a.last_report == null) return null;
        if (a.last_renew) |t| if (now - t < timing.renew_spacing) return null;
        for (a.radios[0..a.n_radios]) |*r| {
            const band = r.band orelse continue;
            const want = c.cfg.fronthaul[@intFromEnum(band)] orelse continue;
            if (c.needsConfig(a, r, want)) return band;
        }
        return null;
    }

    fn wpsGate(c: *Controller, a: *Agent, now: Ms) ?WpsAction {
        if (!c.cfg.auto_wps or !a.silent(now)) return null;
        const probe = a.last_probe orelse return null;
        if (now - probe > timing.probe_recent) return null;
        const first = a.outage.first_probe orelse {
            a.outage.first_probe = probe;
            log.info("agent {x} silent but probing from {x}", .{ a.al_mac, a.probing_iface });
            return null;
        };
        if (now - first < timing.probe_before_wps) return null;
        if (a.outage.windows >= timing.max_wps_per_outage) return null;
        if (a.outage.last_window) |t| if (now - t < timing.wps_spacing) return null;
        a.outage.windows += 1;
        a.outage.last_window = now;
        log.warn("agent {x}: opening WPS window {d}/{d} for {x}", .{ a.al_mac, a.outage.windows, timing.max_wps_per_outage, a.probing_iface });
        return .{ .stale_station = a.probing_iface, .agent = a.al_mac, .window = a.outage.windows };
    }

    /// Persists what was learned (agents, their interfaces, radio bands and
    /// applied credential digests) as one line per agent.
    pub fn save(c: *const Controller, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (c.agents[0..c.n_agents]) |a| {
            try w.print("agent {x}", .{a.al_mac});
            for (a.ifaces[0..a.n_ifaces]) |m| try w.print(" if={x}", .{m});
            for (a.radios[0..a.n_radios]) |r| {
                try w.print(" radio={x}", .{r.ruid});
                if (r.band) |b| try w.print(",band={s}", .{@tagName(b)});
                if (r.applied) |d| try w.print(",applied={x}", .{d});
            }
            try w.writeByte('\n');
        }
    }

    pub fn load(c: *Controller, text: []const u8) void {
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |line| loadAgent(c, line) catch |err| log.warn("state: skipping line ({t})", .{err});
        c.dirty = false;
    }

    fn loadAgent(c: *Controller, line: []const u8) !void {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        if (!std.mem.eql(u8, fields.next() orelse return error.Empty, "agent")) return error.NotAgent;
        const a = c.agentOrNew(try parseMac(fields.next() orelse return error.MissingMac)) orelse return error.TableFull;
        while (fields.next()) |field| {
            if (std.mem.startsWith(u8, field, "if=")) {
                if (a.n_ifaces < max_ifaces) {
                    a.ifaces[a.n_ifaces] = try parseMac(field[3..]);
                    a.n_ifaces += 1;
                }
            } else if (std.mem.startsWith(u8, field, "radio=")) {
                var parts = std.mem.tokenizeScalar(u8, field["radio=".len..], ',');
                const r = a.radio(try parseMac(parts.next() orelse return error.MissingMac)) orelse continue;
                while (parts.next()) |p| {
                    if (std.mem.eql(u8, p, "band=2.4")) r.band = .@"2.4";
                    if (std.mem.eql(u8, p, "band=5")) r.band = .@"5";
                    if (std.mem.startsWith(u8, p, "applied=")) {
                        var d: Digest = undefined;
                        _ = try std.fmt.hexToBytes(&d, p["applied=".len..]);
                        r.applied = d;
                    }
                }
            }
        }
    }
};

fn parseMac(hex: []const u8) !Mac {
    var m: Mac = undefined;
    if ((try std.fmt.hexToBytes(&m, hex)).len != 6) return error.BadMac;
    return m;
}

// ---------------------------------------------------------------------------
// Tests: a scripted AX12, using frames shaped like the ones captured on the C6.

const testing = std.testing;
const vectors = @import("testdata/wsc_vectors.zig");

const c6: Mac = .{ 0x02, 0x00, 0x00, 0xc6, 0x00, 0x41 };
const ax12: Mac = .{ 0x02, 0x00, 0x00, 0xa0, 0xd9, 0x50 };
const ax12_bsta: Mac = .{ 0x06, 0x00, 0x00, 0xa0, 0xd9, 0x4f };
const radio5: Mac = .{ 0x02, 0x00, 0x00, 0xa0, 0xd9, 0x4f };

const want5: wsc.Bss = .{ .ssid = "MK 5GHz Ext", .passphrase = "exactly8" };

fn testController(auto_wps: bool) Controller {
    return .init(.{ .al_mac = c6, .fronthaul = .{ .{ .ssid = "MK Ext", .passphrase = "exactly8" }, want5 }, .auto_wps = auto_wps }, 100);
}

fn testSecrets() wsc.Secrets {
    var s: wsc.Secrets = undefined;
    @memset(&s.dh_private, 0x42);
    @memset(&s.registrar_nonce, 0x17);
    @memset(&s.iv, 0x99);
    return s;
}

fn frameFrom(buf: []u8, msg: cmdu.MsgType, tlvs: []const cmdu.TlvEntry) !cmdu.Frame {
    return .parse(try cmdu.build(buf, c6, ax12, msg, 7, tlvs));
}

fn topologyWithSsid(buf: []u8, ssid: []const u8) !cmdu.Frame {
    var info: [7 + 9]u8 = undefined;
    info[0..6].* = ax12;
    info[6] = 1;
    info[7..13].* = ax12_bsta;
    info[13..16].* = .{ 0x01, 0x08, 0 };
    var ops_buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&ops_buf);
    try w.writeAll(&.{1});
    try w.writeAll(&radio5);
    try w.writeAll(&.{1});
    try w.writeAll(&radio5);
    try w.writeByte(@intCast(ssid.len));
    try w.writeAll(ssid);
    return frameFrom(buf, .topology_response, &.{
        .{ .type = .device_info, .value = &info },
        .{ .type = .ap_operational_bss, .value = w.buffered() },
    });
}

fn m1Frame(buf: []u8) !cmdu.Frame {
    var m1_buf: [512]u8 = undefined;
    const m1 = try std.fmt.hexToBytes(&m1_buf, vectors.cases[0].m1); // rf_bands 0x02
    var caps: [8]u8 = @splat(0);
    caps[0..6].* = radio5;
    return frameFrom(buf, .ap_autoconfig_wsc, &.{
        .{ .type = .ap_radio_basic_caps, .value = &caps },
        .{ .type = .wsc, .value = m1 },
    });
}

test "answers search and topology query as controller" {
    var c = testController(false);
    var in: [cmdu.max_frame]u8 = undefined;
    var out: [cmdu.max_frame]u8 = undefined;
    const search = try frameFrom(&in, .ap_autoconfig_search, &.{
        .{ .type = .al_mac, .value = &ax12 },
        .{ .type = .searched_service, .value = &.{ 1, cmdu.service_controller } },
        .{ .type = .autoconfig_freq_band, .value = &.{cmdu.band_5} },
    });
    const reply: cmdu.Frame = try .parse((try c.onFrame(search, 0, &out, testSecrets())).?);
    try testing.expectEqual(cmdu.MsgType.ap_autoconfig_response, reply.msg_type);
    try testing.expectEqual(search.mid, reply.mid);
    try testing.expectEqualSlices(u8, &ax12, &reply.dst);

    const query = try frameFrom(&in, .topology_query, &.{});
    const tr: cmdu.Frame = try .parse((try c.onFrame(query, 1, &out, testSecrets())).?);
    try testing.expectEqual(cmdu.MsgType.topology_response, tr.msg_type);
}

test "no M2 before a topology report, none when already broadcasting, one when it differs" {
    var c = testController(false);
    var in: [cmdu.max_frame]u8 = undefined;
    var out: [cmdu.max_frame]u8 = undefined;

    try testing.expectEqual(null, try c.onFrame(try m1Frame(&in), 0, &out, testSecrets()));

    _ = try c.onFrame(try topologyWithSsid(&in, "MK 5GHz Ext"), 1, &out, testSecrets());
    try testing.expectEqual(null, try c.onFrame(try m1Frame(&in), 2, &out, testSecrets()));
    try testing.expect(c.agent(ax12).?.radios[0].applied != null); // adopted

    _ = try c.onFrame(try topologyWithSsid(&in, "TP-Link_D950_5G"), 3, &out, testSecrets());
    const m2: cmdu.Frame = try .parse((try c.onFrame(try m1Frame(&in), 4, &out, testSecrets())).?);
    try testing.expectEqual(cmdu.MsgType.ap_autoconfig_wsc, m2.msg_type);
    try testing.expectEqualSlices(u8, &radio5, m2.find(.ap_radio_identifier).?);

    // A second M1 right after must not trigger another restart.
    try testing.expectEqual(null, try c.onFrame(try m1Frame(&in), 5, &out, testSecrets()));
}

test "password change on the router triggers renew, then M2" {
    var c = testController(false);
    var in: [cmdu.max_frame]u8 = undefined;
    var out: [cmdu.max_frame]u8 = undefined;
    _ = try c.onFrame(try topologyWithSsid(&in, "MK 5GHz Ext"), 0, &out, testSecrets());
    _ = try c.onFrame(try m1Frame(&in), 1, &out, testSecrets()); // adopts current creds, learns band
    c.cfg.fronthaul[1] = .{ .ssid = "MK 5GHz Ext", .passphrase = "a-new-longer-password" };
    const t = try c.tick(2, &out);
    const renew: cmdu.Frame = try .parse(t.frame.?);
    try testing.expectEqual(cmdu.MsgType.ap_autoconfig_renew, renew.msg_type);
    try testing.expect(try c.onFrame(try m1Frame(&in), 3, &out, testSecrets()) != null);
}

test "auto-WPS opens only after a minute of probing while silent, rate limited" {
    var c = testController(true);
    var in: [cmdu.max_frame]u8 = undefined;
    var out: [cmdu.max_frame]u8 = undefined;
    const s = std.time.ms_per_s;
    _ = try c.onFrame(try topologyWithSsid(&in, "MK 5GHz Ext"), 0, &out, testSecrets()); // learns bSTA mac

    // Power cut at ~0 s: no more 1905 frames. Probes start at 70 s.
    var now: Ms = 70 * s;
    var opened: u8 = 0;
    var first_open: ?Ms = null;
    while (now < 20 * std.time.ms_per_min) : (now += 5 * s) {
        c.onProbe(ax12_bsta, now);
        const t = try c.tick(now, &out);
        if (t.wps) |w| {
            try testing.expectEqualSlices(u8, &ax12_bsta, &w.stale_station);
            opened += 1;
            if (first_open == null) first_open = now;
        }
    }
    try testing.expect(first_open.? >= 130 * s);
    try testing.expectEqual(timing.max_wps_per_outage, opened);

    // The agent comes back: the outage resets.
    _ = try c.onFrame(try frameFrom(&in, .topology_query, &.{}), now, &out, testSecrets());
    try testing.expectEqual(0, c.agent(ax12).?.outage.windows);
}

test "auto-WPS stays shut when disabled, for unknown stations, and while the agent talks" {
    var c = testController(false);
    var in: [cmdu.max_frame]u8 = undefined;
    var out: [cmdu.max_frame]u8 = undefined;
    _ = try c.onFrame(try topologyWithSsid(&in, "MK 5GHz Ext"), 0, &out, testSecrets());
    var now: Ms = 0;
    while (now < 10 * std.time.ms_per_min) : (now += 5000) {
        c.onProbe(ax12_bsta, now);
        try testing.expectEqual(null, (try c.tick(now, &out)).wps);
    }

    c.cfg.auto_wps = true;
    const stranger: Mac = .{ 0x02, 0, 0, 0, 0, 1 };
    now = 0;
    c.agent(ax12).?.last_heard = 0;
    while (now < 10 * std.time.ms_per_min) : (now += 5000) {
        c.onProbe(stranger, now);
        try testing.expectEqual(null, (try c.tick(now, &out)).wps);
    }
}

test "zero-filled 0x893a frames from a backhaul STA create no agent" {
    var c = testController(false);
    var out: [cmdu.max_frame]u8 = undefined;
    // As captured on the C6: 9e:f1:..:4f -> radio MAC, ethertype 0x893a, all zeros.
    var frame: [60]u8 = @splat(0);
    frame[0..6].* = .{ 0x02, 0x00, 0x00, 0xc6, 0x00, 0x40 };
    frame[6..12].* = ax12_bsta;
    frame[12..14].* = .{ 0x89, 0x3a };
    const f: cmdu.Frame = try .parse(&frame);
    try testing.expectEqual(null, try c.onFrame(f, 0, &out, testSecrets()));
    try testing.expectEqual(0, c.n_agents);
}

test "unanswered topology queries back off" {
    var c = testController(false);
    var in: [cmdu.max_frame]u8 = undefined;
    var out: [cmdu.max_frame]u8 = undefined;
    _ = try c.onFrame(try frameFrom(&in, .topology_query, &.{.{ .type = .multi_ap_profile, .value = &.{2} }}), 0, &out, testSecrets());
    var sent: usize = 0;
    var now: Ms = 0;
    while (now < 55 * std.time.ms_per_s) : (now += std.time.ms_per_s) {
        c.agent(ax12).?.last_heard = now; // agent keeps talking, never answers
        if ((try c.tick(now, &out)).frame != null) sent += 1;
    }
    try testing.expectEqual(2, sent); // at 0 s and after the 30 s retry
}

test "state survives a save/load round trip" {
    var c = testController(false);
    var in: [cmdu.max_frame]u8 = undefined;
    var out: [cmdu.max_frame]u8 = undefined;
    _ = try c.onFrame(try topologyWithSsid(&in, "MK 5GHz Ext"), 0, &out, testSecrets());
    _ = try c.onFrame(try m1Frame(&in), 1, &out, testSecrets());

    var text: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&text);
    try c.save(&w);

    var d = testController(false);
    d.load(w.buffered());
    const a = d.agent(ax12).?;
    try testing.expect(a.ownsIface(ax12_bsta));
    try testing.expectEqual(Band.@"5", a.radios[0].band.?);
    try testing.expectEqualSlices(u8, &digestOf(want5), &a.radios[0].applied.?);
    try testing.expect(!d.dirty);
}

test "fuzz: random frames from a known agent never crash the controller" {
    var c = testController(true);
    var prng: std.Random.DefaultPrng = .init(0xc0de);
    const rand = prng.random();
    var in: [cmdu.max_frame]u8 = undefined;
    var out: [cmdu.max_frame]u8 = undefined;
    var tlv_buf: [300]u8 = undefined;
    const types = [_]cmdu.MsgType{ .ap_autoconfig_search, .topology_query, .topology_response, .ap_autoconfig_wsc, .vendor_specific };
    for (0..5000) |i| {
        const n = rand.uintAtMost(usize, tlv_buf.len);
        rand.bytes(tlv_buf[0..n]);
        const t: cmdu.Tlv = @enumFromInt(rand.int(u8));
        const f = frameFrom(&in, types[rand.uintLessThan(usize, types.len)], &.{.{ .type = t, .value = tlv_buf[0..n] }}) catch continue;
        _ = c.onFrame(f, @intCast(i), &out, testSecrets()) catch {};
        _ = c.tick(@intCast(i), &out) catch {};
    }
}
