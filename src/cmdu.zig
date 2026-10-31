//! IEEE 1905.1 CMDU framing and the EasyMesh TLVs a minimal controller needs.
//! Parsing never trusts a length field: every TLV is bounds-checked against the
//! frame, so malformed input becomes an error, not a crash.

const std = @import("std");
const mem = std.mem;
const Io = std.Io;

pub const ethertype: u16 = 0x893a;
pub const multicast = [6]u8{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x13 };
pub const eth_header_len = 14;
const cmdu_header_len = 8;
pub const max_frame = 1514;

pub const Mac = [6]u8;

pub const MsgType = enum(u16) {
    topology_discovery = 0x0000,
    topology_notification = 0x0001,
    topology_query = 0x0002,
    topology_response = 0x0003,
    vendor_specific = 0x0004,
    link_metric_query = 0x0005,
    ap_autoconfig_search = 0x0007,
    ap_autoconfig_response = 0x0008,
    ap_autoconfig_wsc = 0x0009,
    ap_autoconfig_renew = 0x000A,
    ack = 0x8000,
    ap_capability_query = 0x8001,
    ap_capability_report = 0x8002,
    assoc_sta_link_metrics_query = 0x800D,
    assoc_sta_link_metrics_response = 0x800E,
    beacon_metrics_query = 0x8011,
    beacon_metrics_response = 0x8012,
    client_steering_request = 0x8014,
    client_steering_btm_report = 0x8015,
    steering_completed = 0x8017,
    _,
};

pub const Tlv = enum(u8) {
    end = 0x00,
    al_mac = 0x01,
    device_info = 0x03,
    searched_role = 0x0D,
    autoconfig_freq_band = 0x0E,
    supported_role = 0x0F,
    supported_freq_band = 0x10,
    wsc = 0x11,
    supported_service = 0x80,
    searched_service = 0x81,
    ap_radio_identifier = 0x82,
    ap_operational_bss = 0x83,
    associated_clients = 0x84,
    ap_radio_basic_caps = 0x85,
    client_association_event = 0x92,
    sta_mac_address = 0x95,
    associated_sta_link_metrics = 0x96,
    beacon_metrics_query = 0x99,
    beacon_metrics_response = 0x9A,
    steering_request = 0x9B,
    steering_btm_report = 0x9C,
    ap_capability = 0xA1,
    error_code = 0xA3,
    multi_ap_profile = 0xB3,
    _,
};

pub const flag_last_fragment: u8 = 0x80;
pub const flag_relay: u8 = 0x40;

pub const role_registrar: u8 = 0x00;
pub const service_controller: u8 = 0x00;
pub const service_agent: u8 = 0x01;
pub const band_24: u8 = 0x00;
pub const band_5: u8 = 0x01;
const media_ieee_802_3ab: u16 = 0x0001;
/// Profile 1, like prplMesh: some certified agents fail to parse richer
/// responses, and profile 1 needs no 802.1Q TLVs in M2.
pub const profile: u8 = 1;

pub const ParseError = error{ TooShort, NotIeee1905, UnsupportedVersion, Truncated };

pub const Frame = struct {
    dst: Mac,
    src: Mac,
    msg_type: MsgType,
    mid: u16,
    fragment: u8,
    flags: u8,
    /// TLV area, already validated by `parse` to be well formed up to End of Message.
    tlv_bytes: []const u8,

    pub fn parse(frame: []const u8) ParseError!Frame {
        if (frame.len < eth_header_len + cmdu_header_len) return error.TooShort;
        if (mem.readInt(u16, frame[12..14], .big) != ethertype) return error.NotIeee1905;
        const h = frame[eth_header_len..][0..cmdu_header_len];
        if (h[0] != 0) return error.UnsupportedVersion;
        const body = frame[eth_header_len + cmdu_header_len ..];
        // Validate the whole TLV chain once so iteration can't fail later.
        var end: usize = 0;
        var it: TlvIterator = .{ .r = .fixed(body) };
        while (try it.next()) |_| end = body.len - it.r.bufferedLen();
        return .{
            .dst = frame[0..6].*,
            .src = frame[6..12].*,
            .msg_type = @fromBackingInt(mem.readInt(u16, h[2..4], .big)),
            .mid = mem.readInt(u16, h[4..6], .big),
            .fragment = h[6],
            .flags = h[7],
            .tlv_bytes = body[0..end],
        };
    }

    pub fn tlvs(f: Frame) TlvIterator {
        return .{ .r = .fixed(f.tlv_bytes) };
    }

    pub fn find(f: Frame, t: Tlv) ?[]const u8 {
        var it = f.tlvs();
        while (it.next() catch unreachable) |e| if (e.type == t) return e.value;
        return null;
    }
};

pub const TlvEntry = struct { type: Tlv, value: []const u8 };

pub const TlvIterator = struct {
    r: Io.Reader,

    /// Next TLV, null at End of Message or end of data (frames are padded to 60 bytes).
    pub fn next(it: *TlvIterator) ParseError!?TlvEntry {
        if (it.r.bufferedLen() < 3) return null;
        const t: Tlv = @fromBackingInt(it.r.takeByte() catch unreachable);
        const n = it.r.takeInt(u16, .big) catch unreachable;
        if (t == .end) return null;
        const v = it.r.take(n) catch return error.Truncated;
        return .{ .type = t, .value = v };
    }
};

/// Writes Ethernet + CMDU header, TLVs and End of Message, padded to the 60-byte
/// Ethernet minimum. Returns the frame slice of `out`.
pub fn build(out: []u8, dst: Mac, src: Mac, msg_type: MsgType, mid: u16, entries: []const TlvEntry) Io.Writer.Error![]u8 {
    var w: Io.Writer = .fixed(out);
    try w.writeAll(&dst);
    try w.writeAll(&src);
    try w.writeInt(u16, ethertype, .big);
    try w.writeAll(&.{ 0, 0 });
    try w.writeInt(u16, @backingInt(msg_type), .big);
    try w.writeInt(u16, mid, .big);
    try w.writeAll(&.{ 0, flag_last_fragment });
    for (entries) |e| {
        try w.writeByte(@backingInt(e.type));
        try w.writeInt(u16, @intCast(e.value.len), .big);
        try w.writeAll(e.value);
    }
    try w.writeAll(&.{ 0, 0, 0 });
    const min_frame = 60;
    if (w.buffered().len < min_frame) try w.splatByteAll(0, min_frame - w.buffered().len);
    return w.buffered();
}

/// Device Information TLV value for a controller with one wired interface.
pub fn deviceInfo(al_mac: Mac) [6 + 1 + 6 + 2 + 1]u8 {
    var v: [16]u8 = undefined;
    v[0..6].* = al_mac;
    v[6] = 1;
    v[7..13].* = al_mac;
    mem.writeInt(u16, v[13..15], media_ieee_802_3ab, .big);
    v[15] = 0;
    return v;
}

pub const BssEntry = struct { bssid: Mac, ssid: []const u8 };

/// Walks an AP Operational BSS TLV: per radio, its radio UID and BSSes.
pub const OperationalBss = struct {
    r: Io.Reader,
    radios_left: u8,

    pub fn init(value: []const u8) ParseError!OperationalBss {
        var r: Io.Reader = .fixed(value);
        const n = r.takeByte() catch return error.Truncated;
        return .{ .r = r, .radios_left = n };
    }

    pub const Radio = struct {
        ruid: Mac,
        bss_left: u8,
        parent: *OperationalBss,

        pub fn nextBss(radio: *Radio) ParseError!?BssEntry {
            if (radio.bss_left == 0) return null;
            radio.bss_left -= 1;
            const r = &radio.parent.r;
            const bssid = (r.takeArray(6) catch return error.Truncated).*;
            const len = r.takeByte() catch return error.Truncated;
            const ssid = r.take(len) catch return error.Truncated;
            return .{ .bssid = bssid, .ssid = ssid };
        }
    };

    /// The caller must drain each radio's BSSes before asking for the next radio.
    pub fn nextRadio(ob: *OperationalBss) ParseError!?Radio {
        if (ob.radios_left == 0) return null;
        ob.radios_left -= 1;
        const ruid = (ob.r.takeArray(6) catch return error.Truncated).*;
        const n = ob.r.takeByte() catch return error.Truncated;
        return .{ .ruid = ruid, .bss_left = n, .parent = ob };
    }
};

/// AP Capability TLV value (EasyMesh 17.2.6); bit 7 is the first flag.
pub const ApCapability = packed struct(u8) {
    _reserved: u5 = 0,
    agent_rssi_steering: bool,
    unassoc_metrics_off_channel: bool,
    unassoc_metrics_on_channel: bool,
};

pub const ClientEntry = struct { bssid: Mac, mac: Mac, secs_since_assoc: u16 };

/// Walks an Associated Clients TLV: per BSS its BSSID and clients, flattened.
pub const AssociatedClients = struct {
    r: Io.Reader,
    bss_left: u8,
    bssid: Mac = undefined,
    clients_left: u16 = 0,

    pub fn init(value: []const u8) ParseError!AssociatedClients {
        var r: Io.Reader = .fixed(value);
        const n = r.takeByte() catch return error.Truncated;
        return .{ .r = r, .bss_left = n };
    }

    pub fn next(it: *AssociatedClients) ParseError!?ClientEntry {
        while (it.clients_left == 0) {
            if (it.bss_left == 0) return null;
            it.bss_left -= 1;
            it.bssid = (it.r.takeArray(6) catch return error.Truncated).*;
            it.clients_left = it.r.takeInt(u16, .big) catch return error.Truncated;
        }
        it.clients_left -= 1;
        const mac = (it.r.takeArray(6) catch return error.Truncated).*;
        const secs = it.r.takeInt(u16, .big) catch return error.Truncated;
        return .{ .bssid = it.bssid, .mac = mac, .secs_since_assoc = secs };
    }
};

pub const LinkMetric = struct {
    bssid: Mac,
    age_ms: u32,
    downlink_mbps: u32,
    uplink_mbps: u32,
    /// Uplink signal as the agent measured it, dBm; null when unavailable.
    rssi: ?i8,
};

/// Associated STA Link Metrics TLV: the station, then one entry per BSS.
pub const StaLinkMetrics = struct {
    sta: Mac,
    r: Io.Reader,
    left: u8,

    pub fn init(value: []const u8) ParseError!StaLinkMetrics {
        var r: Io.Reader = .fixed(value);
        const sta = (r.takeArray(6) catch return error.Truncated).*;
        const n = r.takeByte() catch return error.Truncated;
        return .{ .sta = sta, .r = r, .left = n };
    }

    pub fn next(it: *StaLinkMetrics) ParseError!?LinkMetric {
        if (it.left == 0) return null;
        it.left -= 1;
        const bssid = (it.r.takeArray(6) catch return error.Truncated).*;
        const age = it.r.takeInt(u32, .big) catch return error.Truncated;
        const dl = it.r.takeInt(u32, .big) catch return error.Truncated;
        const ul = it.r.takeInt(u32, .big) catch return error.Truncated;
        const rcpi = it.r.takeByte() catch return error.Truncated;
        return .{ .bssid = bssid, .age_ms = age, .downlink_mbps = dl, .uplink_mbps = ul, .rssi = rcpiToDbm(rcpi) };
    }
};

/// IEEE 802.11 RCPI (0..220, half-dB steps from -110 dBm) to dBm.
pub fn rcpiToDbm(rcpi: u8) ?i8 {
    if (rcpi > 220) return null;
    return @intCast(@as(i16, rcpi / 2) - 110);
}

/// Client Association Event TLV: client, BSSID, and whether it joined or left.
pub const AssociationEvent = struct {
    mac: Mac,
    bssid: Mac,
    joined: bool,

    pub fn parse(value: []const u8) ParseError!AssociationEvent {
        if (value.len < 13) return error.Truncated;
        return .{ .mac = value[0..6].*, .bssid = value[6..12].*, .joined = value[12] & 0x80 != 0 };
    }
};

pub const SteerTarget = struct { bssid: Mac, op_class: u8, channel: u8 };

/// Steering Request TLV value (EasyMesh 17.2.29, layout as in prplMesh tlvf):
/// a steering mandate for one client of `serving`, towards one target BSS.
/// The agent sends the client an 802.11v BTM request; abridged, so the client
/// prefers the listed BSS, and no disassociation threat: the client may refuse.
pub fn steeringRequest(serving: Mac, sta: Mac, target: SteerTarget) [27]u8 {
    const mode_mandate = 0x80;
    const btm_abridged = 0x20;
    var v: [27]u8 = undefined;
    v[0..6].* = serving;
    v[6] = mode_mandate | btm_abridged;
    v[7..11].* = .{ 0, 0, 0, 0 }; // opportunity window, BTM disassociation timer
    v[11] = 1;
    v[12..18].* = sta;
    v[18] = 1;
    v[19..25].* = target.bssid;
    v[25] = target.op_class;
    v[26] = target.channel;
    return v;
}

/// Steering BTM Report TLV: the client's answer to a BTM request (0 = accept).
pub const BtmReport = struct {
    bssid: Mac,
    sta: Mac,
    status: u8,

    pub fn parse(value: []const u8) ParseError!BtmReport {
        if (value.len < 13) return error.Truncated;
        return .{ .bssid = value[0..6].*, .sta = value[6..12].*, .status = value[12] };
    }
};

/// Beacon Metrics Query TLV value (layout as in prplMesh tlvf): asks the agent
/// to have its client measure every BSS it hears on one channel (802.11k), with
/// wildcard BSSID and SSID, no reporting detail.
pub fn beaconQuery(sta: Mac, op_class: u8, channel: u8) [18]u8 {
    var v: [18]u8 = undefined;
    v[0..6].* = sta;
    v[6] = op_class;
    v[7] = channel;
    v[8..14].* = @splat(0xff);
    v[14..18].* = .{ 0, 0, 0, 0 }; // reporting detail, SSID length, AP channel reports, element IDs
    return v;
}

/// 802.11 global operating class of a 20 MHz channel, as 802.11k measurement
/// requests use; null for channels this controller doesn't know.
pub fn opClass20(channel: u8) ?u8 {
    return switch (channel) {
        1...13 => 81,
        36...48 => 115,
        52...64 => 118,
        100...144 => 121,
        149...165 => 125,
        else => null,
    };
}

pub const BeaconReport = struct { bssid: Mac, rssi: ?i8 };

/// Beacon Metrics Response TLV: the client, then raw 802.11 Measurement Report
/// elements; yields the beacon reports (type 5) among them.
pub const BeaconReports = struct {
    sta: Mac,
    r: Io.Reader,
    left: u8,

    pub fn init(value: []const u8) ParseError!BeaconReports {
        var r: Io.Reader = .fixed(value);
        const sta = (r.takeArray(6) catch return error.Truncated).*;
        r.discardAll(1) catch return error.Truncated;
        const n = r.takeByte() catch return error.Truncated;
        return .{ .sta = sta, .r = r, .left = n };
    }

    pub fn next(it: *BeaconReports) ParseError!?BeaconReport {
        const eid_measurement_report = 39;
        const type_beacon = 5;
        while (it.left > 0) {
            it.left -= 1;
            const eid = it.r.takeByte() catch return error.Truncated;
            const len = it.r.takeByte() catch return error.Truncated;
            const body = it.r.take(len) catch return error.Truncated;
            // token, mode, type, then op class(1) channel(1) start(8) duration(2)
            // frame info(1) RCPI(1) RSNI(1) BSSID(6) ...
            if (eid != eid_measurement_report or body.len < 3 + 21 or body[2] != type_beacon) continue;
            const b = body[3..];
            return .{ .bssid = b[15..21].*, .rssi = rcpiToDbm(b[13]) };
        }
        return null;
    }
};

const testing = std.testing;

test "beacon query and report" {
    const q = beaconQuery(.{ 2, 2, 2, 2, 2, 2 }, 125, 149);
    try testing.expectEqualSlices(u8, &([_]u8{ 2, 2, 2, 2, 2, 2, 125, 149, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 }), &q);
    try testing.expectEqual(@as(?u8, 125), opClass20(149));
    try testing.expectEqual(@as(?u8, null), opClass20(14));

    // Two beacon reports (RCPI 100 = -60 dBm, 80 = -70 dBm) and one other element.
    const head = [_]u8{ 2, 2, 2, 2, 2, 2, 0, 3 };
    const z11: [11]u8 = @splat(0); // start time, duration, frame info
    const z5: [5]u8 = @splat(0); // antenna, parent TSF
    const rep1 = [_]u8{ 39, 3 + 26, 1, 0, 5, 125, 149 } ++ z11 ++ [_]u8{ 100, 0, 3, 3, 3, 3, 3, 3 } ++ z5;
    const other = [_]u8{ 221, 2, 0, 0 };
    const rep2 = [_]u8{ 39, 3 + 26, 2, 0, 5, 125, 149 } ++ z11 ++ [_]u8{ 80, 0, 4, 4, 4, 4, 4, 4 } ++ z5;
    var it: BeaconReports = try .init(&(head ++ rep1 ++ other ++ rep2));
    const a = (try it.next()).?;
    try testing.expectEqualSlices(u8, &.{ 3, 3, 3, 3, 3, 3 }, &a.bssid);
    try testing.expectEqual(@as(?i8, -60), a.rssi);
    try testing.expectEqual(@as(?i8, -70), (try it.next()).?.rssi);
    try testing.expectEqual(null, try it.next());
}

test "steering request layout" {
    const v = steeringRequest(.{ 1, 1, 1, 1, 1, 1 }, .{ 2, 2, 2, 2, 2, 2 }, .{ .bssid = .{ 3, 3, 3, 3, 3, 3 }, .op_class = 128, .channel = 149 });
    try testing.expectEqualSlices(u8, &([_]u8{ 1, 1, 1, 1, 1, 1, 0xa0, 0, 0, 0, 0, 1, 2, 2, 2, 2, 2, 2, 1, 3, 3, 3, 3, 3, 3, 128, 149 }), &v);
}

test "associated clients and link metrics walks" {
    const ac = [_]u8{2} ++ [_]u8{ 1, 1, 1, 1, 1, 1, 0, 2 } ++ [_]u8{ 0xa, 0, 0, 0, 0, 1, 0, 5 } ++ [_]u8{ 0xa, 0, 0, 0, 0, 2, 0, 6 } ++
        [_]u8{ 2, 2, 2, 2, 2, 2, 0, 1 } ++ [_]u8{ 0xb, 0, 0, 0, 0, 3, 1, 0 };
    var it: AssociatedClients = try .init(&ac);
    try testing.expectEqual(5, (try it.next()).?.secs_since_assoc);
    try testing.expectEqual(6, (try it.next()).?.secs_since_assoc);
    const third = (try it.next()).?;
    try testing.expectEqualSlices(u8, &.{ 2, 2, 2, 2, 2, 2 }, &third.bssid);
    try testing.expectEqual(256, third.secs_since_assoc);
    try testing.expectEqual(null, try it.next());

    const lm = [_]u8{ 0xa, 0, 0, 0, 0, 1, 1 } ++ [_]u8{ 1, 1, 1, 1, 1, 1, 0, 0, 0, 10, 0, 0, 1, 0x90, 0, 0, 0, 0xc8, 100 };
    var m: StaLinkMetrics = try .init(&lm);
    const e = (try m.next()).?;
    try testing.expectEqual(400, e.downlink_mbps);
    try testing.expectEqual(200, e.uplink_mbps);
    try testing.expectEqual(-60, e.rssi.?);
    try testing.expectEqual(null, try m.next());
    try testing.expectEqual(null, rcpiToDbm(255));
    try testing.expectEqual(@as(?i8, -110), rcpiToDbm(0));
}

test "build then parse round-trips header and TLVs" {
    var buf: [max_frame]u8 = undefined;
    const al: Mac = .{ 0x02, 0x00, 0x00, 0xc6, 0x00, 0x41 };
    const agent: Mac = .{ 0x02, 0x00, 0x00, 0xa0, 0xd9, 0x50 };
    const frame = try build(&buf, agent, al, .ap_autoconfig_response, 0x6d23, &.{
        .{ .type = .supported_role, .value = &.{role_registrar} },
        .{ .type = .supported_service, .value = &.{ 1, service_controller } },
    });
    try testing.expectEqual(60, frame.len);
    const f: Frame = try .parse(frame);
    try testing.expectEqual(MsgType.ap_autoconfig_response, f.msg_type);
    try testing.expectEqual(0x6d23, f.mid);
    try testing.expectEqualSlices(u8, &.{ 1, service_controller }, f.find(.supported_service).?);
    try testing.expectEqual(null, f.find(.wsc));
}

test "parses the AX12's captured AP-Autoconfig Search" {
    // Captured on the C6 on 2026-10-30 (search for a controller on 5 GHz).
    var buf: [128]u8 = undefined;
    const frame = try std.fmt.hexToBytes(&buf, "0180c2000013020000a0d950893a000000076df700c0010006020000a0d9500d0001000e0001018000020101810002010" ++ "0b30001020000000000000000000000");
    const f: Frame = try .parse(frame);
    try testing.expectEqual(MsgType.ap_autoconfig_search, f.msg_type);
    try testing.expectEqualSlices(u8, &.{ 1, service_controller }, f.find(.searched_service).?);
    try testing.expectEqualSlices(u8, &.{band_5}, f.find(.autoconfig_freq_band).?);
}

test "operational BSS walk" {
    // 1 radio, 2 BSSes: hidden backhaul + "MK Ext".
    const v = [_]u8{ 1, 0x02, 0x00, 0x00, 0xa0, 0xd9, 0x4e, 2 } ++
        [_]u8{ 0xae, 0xf1, 0x7e, 0x87, 0xd9, 0x4e, 3 } ++ "abc".* ++
        [_]u8{ 0x02, 0x00, 0x00, 0xa0, 0xd9, 0x4e, 6 } ++ "MK Ext".*;
    var ob: OperationalBss = try .init(&v);
    var radio = (try ob.nextRadio()).?;
    try testing.expectEqualStrings("abc", (try radio.nextBss()).?.ssid);
    try testing.expectEqualStrings("MK Ext", (try radio.nextBss()).?.ssid);
    try testing.expectEqual(null, try radio.nextBss());
    try testing.expectEqual(null, try ob.nextRadio());
}

test "fuzz: random and truncated frames never crash the parsers" {
    var prng: std.Random.DefaultPrng = .init(0x1905);
    const rand = prng.random();
    var buf: [256]u8 = undefined;
    for (0..20_000) |_| {
        const len = rand.uintAtMost(usize, buf.len);
        rand.bytes(buf[0..len]);
        // Force a valid header half the time so the TLV walker gets exercised.
        if (len >= 22 and rand.boolean()) {
            mem.writeInt(u16, buf[12..14], ethertype, .big);
            buf[14] = 0;
        }
        const f = Frame.parse(buf[0..len]) catch continue;
        var it = f.tlvs();
        while (it.next() catch unreachable) |e| {
            switch (e.type) {
                .ap_operational_bss => {
                    var ob = OperationalBss.init(e.value) catch continue;
                    while (ob.nextRadio() catch null) |r| {
                        var radio = r;
                        while (radio.nextBss() catch null) |_| {}
                    }
                },
                .associated_clients => {
                    var ac = AssociatedClients.init(e.value) catch continue;
                    while (ac.next() catch null) |_| {}
                },
                .associated_sta_link_metrics => {
                    var m = StaLinkMetrics.init(e.value) catch continue;
                    while (m.next() catch null) |_| {}
                },
                .client_association_event => _ = AssociationEvent.parse(e.value) catch {},
                .steering_btm_report => _ = BtmReport.parse(e.value) catch {},
                .beacon_metrics_response => {
                    var br = BeaconReports.init(e.value) catch continue;
                    while (br.next() catch null) |_| {}
                },
                else => {},
            }
        }
    }
}
