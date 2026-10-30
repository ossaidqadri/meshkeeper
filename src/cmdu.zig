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
    ap_radio_basic_caps = 0x85,
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
            .msg_type = @enumFromInt(mem.readInt(u16, h[2..4], .big)),
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
        const t: Tlv = @enumFromInt(it.r.takeByte() catch unreachable);
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
    try w.writeInt(u16, @intFromEnum(msg_type), .big);
    try w.writeInt(u16, mid, .big);
    try w.writeAll(&.{ 0, flag_last_fragment });
    for (entries) |e| {
        try w.writeByte(@intFromEnum(e.type));
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

const testing = std.testing;

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
            if (e.type == .ap_operational_bss) {
                var ob = OperationalBss.init(e.value) catch continue;
                while (ob.nextRadio() catch null) |r| {
                    var radio = r;
                    while (radio.nextBss() catch null) |_| {}
                }
            }
        }
    }
}
