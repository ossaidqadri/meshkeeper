//! WSC (Wi-Fi Simple Configuration) registrar side: parse an enrollee's M1 and
//! build the M2 that carries one BSS configuration, as EasyMesh AP-Autoconfiguration
//! uses it. DH group 5, HMAC-SHA256 KDF, AES-128-CBC encrypted settings (WSC 2.0).

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Io = std.Io;
const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Aes128 = crypto.core.aes.Aes128;

pub const dh_len = 192;
const Dh = crypto.ff.Modulus(dh_len * 8);

/// RFC 3526 1536-bit MODP group, generator 2.
const dh_prime: [dh_len]u8 = hexArray(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" ++
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" ++
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" ++
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" ++
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" ++
        "9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
);

const Attr = enum(u16) {
    version = 0x104A,
    msg_type = 0x1022,
    uuid_e = 0x1047,
    uuid_r = 0x1048,
    mac = 0x1020,
    enrollee_nonce = 0x101A,
    registrar_nonce = 0x1039,
    public_key = 0x1032,
    auth_type_flags = 0x1004,
    encr_type_flags = 0x1010,
    conn_type_flags = 0x100D,
    config_methods = 0x1008,
    manufacturer = 0x1021,
    model_name = 0x1023,
    model_number = 0x1024,
    serial_number = 0x1042,
    primary_dev_type = 0x1054,
    dev_name = 0x1011,
    rf_bands = 0x103C,
    assoc_state = 0x1002,
    config_error = 0x1009,
    dev_password_id = 0x1012,
    os_version = 0x102D,
    vendor_ext = 0x1049,
    encr_settings = 0x1018,
    authenticator = 0x1005,
    ssid = 0x1045,
    auth_type = 0x1003,
    encr_type = 0x100F,
    network_key = 0x1027,
    key_wrap_auth = 0x101E,
    _,
};

const msg_m1 = 0x04;
const msg_m2 = 0x05;

pub const auth_wpa2psk = 0x0020;
pub const auth_sae = 0x0040;
const encr_aes = 0x0008;

pub const rf_band_24 = 0x01;
pub const rf_band_5 = 0x02;

const wfa_oui = [_]u8{ 0x00, 0x37, 0x2a };
const wfa_elem_version2 = 0x00;
const wfa_elem_multi_ap = 0x06;
pub const multi_ap_backhaul_bss = 0x40;
pub const multi_ap_fronthaul_bss = 0x20;

const kdf_label = "Wi-Fi Easy and Secure Key Derivation";

pub const ParseError = error{ NotM1, MissingAttribute, BadLength, Truncated };

pub const M1 = struct {
    raw: []const u8,
    mac: *const [6]u8,
    nonce: *const [16]u8,
    public_key: *const [dh_len]u8,
    rf_bands: u8,
    auth_flags: u16,
    encr_flags: u16,

    pub fn parse(raw: []const u8) ParseError!M1 {
        var mac: ?[]const u8 = null;
        var nonce: ?[]const u8 = null;
        var public_key: ?[]const u8 = null;
        var rf_bands: ?[]const u8 = null;
        var auth_flags: u16 = 0;
        var encr_flags: u16 = 0;
        var is_m1 = false;

        var r: Io.Reader = .fixed(raw);
        while (r.bufferedLen() >= 4) {
            const t: Attr = @enumFromInt(r.takeInt(u16, .big) catch unreachable);
            const n = r.takeInt(u16, .big) catch unreachable;
            const v = r.take(n) catch return error.Truncated;
            switch (t) {
                .msg_type => is_m1 = v.len == 1 and v[0] == msg_m1,
                .mac => mac = v,
                .enrollee_nonce => nonce = v,
                .public_key => public_key = v,
                .rf_bands => rf_bands = v,
                .auth_type_flags => if (v.len == 2) {
                    auth_flags = mem.readInt(u16, v[0..2], .big);
                },
                .encr_type_flags => if (v.len == 2) {
                    encr_flags = mem.readInt(u16, v[0..2], .big);
                },
                else => {},
            }
        }
        if (!is_m1) return error.NotM1;
        const m = mac orelse return error.MissingAttribute;
        const nc = nonce orelse return error.MissingAttribute;
        const pk = public_key orelse return error.MissingAttribute;
        const rf = rf_bands orelse return error.MissingAttribute;
        if (m.len != 6 or nc.len != 16 or pk.len != dh_len or rf.len != 1) return error.BadLength;
        return .{
            .raw = raw,
            .mac = m[0..6],
            .nonce = nc[0..16],
            .public_key = pk[0..dh_len],
            .rf_bands = rf[0],
            .auth_flags = auth_flags,
            .encr_flags = encr_flags,
        };
    }
};

pub const Keys = struct {
    auth_key: [32]u8,
    key_wrap_key: [16]u8,
    emsk: [32]u8,

    /// WSC 2.0 §7.4: KDK = HMAC(DHKey, N1 || EnrolleeMAC || N2), then a
    /// 640-bit KDF stream split into AuthKey, KeyWrapKey and EMSK.
    pub fn derive(dh_shared: *const [dh_len]u8, enrollee_nonce: *const [16]u8, enrollee_mac: *const [6]u8, registrar_nonce: *const [16]u8) Keys {
        var dhkey: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(dh_shared, &dhkey, .{});

        var kdk: [HmacSha256.mac_length]u8 = undefined;
        var h = HmacSha256.init(&dhkey);
        h.update(enrollee_nonce);
        h.update(enrollee_mac);
        h.update(registrar_nonce);
        h.final(&kdk);

        const total_bits = 640;
        var stream: [3 * HmacSha256.mac_length]u8 = undefined;
        for (0..3) |i| {
            var ctx = HmacSha256.init(&kdk);
            var be: [4]u8 = undefined;
            mem.writeInt(u32, &be, @intCast(i + 1), .big);
            ctx.update(&be);
            ctx.update(kdf_label);
            mem.writeInt(u32, &be, total_bits, .big);
            ctx.update(&be);
            ctx.final(stream[i * HmacSha256.mac_length ..][0..HmacSha256.mac_length]);
        }
        return .{
            .auth_key = stream[0..32].*,
            .key_wrap_key = stream[32..48].*,
            .emsk = stream[48..80].*,
        };
    }
};

pub const Bss = struct {
    ssid: []const u8,
    passphrase: []const u8,
    auth: u16 = auth_wpa2psk,
    multi_ap: u8 = multi_ap_fronthaul_bss,
};

/// Per-M2 randomness; fixed values only in tests.
pub const Secrets = struct {
    dh_private: [dh_len]u8,
    registrar_nonce: [16]u8,
    iv: [16]u8,

    pub fn random(io: Io) Io.RandomSecureError!Secrets {
        var s: Secrets = undefined;
        try io.randomSecure(mem.asBytes(&s));
        return s;
    }
};

pub const BuildError = error{ InvalidPeerKey, BufferTooSmall } || crypto.ff.NullExponentError;

/// Builds M2 for `m1` into `out` and returns the used slice.
pub fn buildM2(out: []u8, m1: M1, bss: Bss, registrar_uuid: *const [16]u8, secrets: Secrets) BuildError![]u8 {
    const dh = Dh.fromBytes(&dh_prime, .big) catch unreachable;
    const generator = Dh.Fe.fromPrimitive(u8, dh, 2) catch unreachable;
    const peer = Dh.Fe.fromBytes(dh, m1.public_key, .big) catch return error.InvalidPeerKey;
    // Reject 0, 1 and p-1, which would force a trivial shared secret.
    const p_minus_1 = dh.sub(dh.zero, dh.one());
    if (peer.isZero() or peer.eql(dh.one()) or peer.eql(p_minus_1)) return error.InvalidPeerKey;

    var public_key: [dh_len]u8 = undefined;
    var shared: [dh_len]u8 = undefined;
    (try dh.powWithEncodedExponent(generator, &secrets.dh_private, .big)).toBytes(&public_key, .big) catch unreachable;
    (try dh.powWithEncodedExponent(peer, &secrets.dh_private, .big)).toBytes(&shared, .big) catch unreachable;
    const keys = Keys.derive(&shared, m1.nonce, m1.mac, &secrets.registrar_nonce);

    var w: Io.Writer = .fixed(out);
    writeM2Body(&w, m1, bss, registrar_uuid, &public_key, keys, secrets) catch return error.BufferTooSmall;

    var authenticator: [HmacSha256.mac_length]u8 = undefined;
    var h = HmacSha256.init(&keys.auth_key);
    h.update(m1.raw);
    h.update(w.buffered());
    h.final(&authenticator);
    putAttr(&w, .authenticator, authenticator[0..8]) catch return error.BufferTooSmall;
    return w.buffered();
}

fn writeM2Body(w: *Io.Writer, m1: M1, bss: Bss, uuid: *const [16]u8, public_key: *const [dh_len]u8, keys: Keys, secrets: Secrets) Io.Writer.Error!void {
    try putAttr(w, .version, &.{0x10});
    try putAttr(w, .msg_type, &.{msg_m2});
    try putAttr(w, .enrollee_nonce, m1.nonce);
    try putAttr(w, .registrar_nonce, &secrets.registrar_nonce);
    try putAttr(w, .uuid_r, uuid);
    try putAttr(w, .public_key, public_key);
    try putAttrInt(w, .auth_type_flags, @as(u16, auth_wpa2psk | auth_sae));
    try putAttrInt(w, .encr_type_flags, @as(u16, encr_aes));
    try putAttr(w, .conn_type_flags, &.{0x01});
    try putAttrInt(w, .config_methods, @as(u16, 0x0080));
    try putAttr(w, .manufacturer, "OpenWrt");
    try putAttr(w, .model_name, "meshkeeper");
    try putAttr(w, .model_number, "1");
    try putAttr(w, .serial_number, "1");
    try putAttr(w, .primary_dev_type, &.{ 0x00, 0x06, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01 });
    try putAttr(w, .dev_name, "meshkeeper");
    try putAttr(w, .rf_bands, &.{m1.rf_bands});
    try putAttrInt(w, .assoc_state, @as(u16, 0));
    try putAttrInt(w, .config_error, @as(u16, 0));
    try putAttrInt(w, .dev_password_id, @as(u16, 0x0004));
    try putAttrInt(w, .os_version, @as(u32, 0x80000000));
    try putAttr(w, .vendor_ext, &(wfa_oui ++ [_]u8{ wfa_elem_version2, 1, 0x20 }));

    // Encrypted Settings: IV || AES-128-CBC(KeyWrapKey, settings || KeyWrapAuthenticator || PKCS#7 pad).
    var plain_buf: [512]u8 = undefined;
    var p: Io.Writer = .fixed(&plain_buf);
    try putAttr(&p, .ssid, bss.ssid);
    try putAttrInt(&p, .auth_type, bss.auth);
    try putAttrInt(&p, .encr_type, @as(u16, encr_aes));
    try putAttr(&p, .network_key, bss.passphrase);
    try putAttr(&p, .mac, m1.mac);
    try putAttr(&p, .vendor_ext, &(wfa_oui ++ [_]u8{ wfa_elem_multi_ap, 1, bss.multi_ap }));
    var kwa: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&kwa, p.buffered(), &keys.auth_key);
    try putAttr(&p, .key_wrap_auth, kwa[0..8]);
    const pad: u8 = @intCast(16 - p.buffered().len % 16);
    try p.splatByteAll(pad, pad);

    const ciphertext = p.buffered();
    cbcEncrypt(&keys.key_wrap_key, secrets.iv, ciphertext);
    try w.writeInt(u16, @intFromEnum(Attr.encr_settings), .big);
    try w.writeInt(u16, @intCast(16 + ciphertext.len), .big);
    try w.writeAll(&secrets.iv);
    try w.writeAll(ciphertext);
}

/// In-place AES-128-CBC over whole blocks. std.crypto only ships the CTR mode
/// (crypto/modes.zig), and WSC fixes CBC, so the chaining is spelled out here.
fn cbcEncrypt(key: *const [16]u8, iv: [16]u8, data: []u8) void {
    std.debug.assert(data.len % 16 == 0);
    const aes = Aes128.initEnc(key.*);
    var prev: @Vector(16, u8) = iv;
    var i: usize = 0;
    while (i < data.len) : (i += 16) {
        const block = data[i..][0..16];
        block.* = @as(@Vector(16, u8), block.*) ^ prev;
        aes.encrypt(block, block);
        prev = block.*;
    }
}

fn putAttr(w: *Io.Writer, t: Attr, v: []const u8) Io.Writer.Error!void {
    try w.writeInt(u16, @intFromEnum(t), .big);
    try w.writeInt(u16, @intCast(v.len), .big);
    try w.writeAll(v);
}

fn putAttrInt(w: *Io.Writer, t: Attr, v: anytype) Io.Writer.Error!void {
    const T = @TypeOf(v);
    try w.writeInt(u16, @intFromEnum(t), .big);
    try w.writeInt(u16, @sizeOf(T), .big);
    try w.writeInt(T, v, .big);
}

fn hexArray(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const vectors = @import("testdata/wsc_vectors.zig");

test "M2 matches the Python builder the AX12 accepted, byte for byte" {
    for (vectors.cases) |case| {
        var m1_buf: [512]u8 = undefined;
        const m1_raw = try std.fmt.hexToBytes(&m1_buf, case.m1);
        const m1: M1 = try .parse(m1_raw);
        try std.testing.expectEqual(case.rf_bands, m1.rf_bands);

        var secrets: Secrets = undefined;
        _ = try std.fmt.hexToBytes(&secrets.dh_private, case.registrar_priv);
        _ = try std.fmt.hexToBytes(&secrets.registrar_nonce, case.registrar_nonce);
        _ = try std.fmt.hexToBytes(&secrets.iv, case.iv);
        var uuid: [16]u8 = undefined;
        _ = try std.fmt.hexToBytes(&uuid, case.registrar_uuid);

        var expected_buf: [1024]u8 = undefined;
        const expected = try std.fmt.hexToBytes(&expected_buf, case.m2);
        var out: [1024]u8 = undefined;
        const m2 = try buildM2(&out, m1, .{ .ssid = case.ssid, .passphrase = case.passphrase }, &uuid, secrets);
        try std.testing.expectEqualSlices(u8, expected, m2);
    }
}

test "M1 parse rejects non-M1 and truncated input" {
    try std.testing.expectError(error.NotM1, M1.parse(&.{ 0x10, 0x22, 0x00, 0x01, msg_m2 }));
    try std.testing.expectError(error.Truncated, M1.parse(&.{ 0x10, 0x22, 0x00, 0x09, msg_m1 }));
}
