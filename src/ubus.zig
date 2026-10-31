//! ubus over ubusd's unix socket: libubus's wire format and blobmsg encoding,
//! without libubus and without starting a `ubus` process for every call.
//! Replies are read in place as blobmsg (`List`), never turned into JSON.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const mem = std.mem;
const Io = std.Io;
const Allocator = mem.Allocator;

pub const socket_path = "/var/run/ubus/ubus.sock";
/// UBUS_MAX_MSGLEN: ubusd refuses anything larger.
const max_msg = 1 << 20;
/// hostapd answers in milliseconds; a stuck one must not stall the poll loop
/// for the CLI's 30 s.
const timeout_ms = 5_000;
const hdr_len = 8; // version, type, seq, peer

const MsgType = enum(u8) { hello, status, data, ping, lookup, invoke, add_object, remove_object, subscribe, unsubscribe, notify, _ };
const Attr = enum(u7) { unspec, status, objpath, objid, method, objtype, signature, data, target, active, no_reply, subscribers, user, group, _ };
const n_attrs = 14;
/// blobmsg value types. Booleans are int8.
const Type = enum(u7) { unspec, array, table, string, int64, int32, int16, int8, double, _ };

const extended: u32 = 0x8000_0000;
const len_mask: u32 = 0x00ff_ffff;

/// UBUS_STATUS_* from 1 on, in order.
const status_errors = [_]error{
    InvalidCommand,
    InvalidArgument,
    MethodNotFound,
    NotFound,
    NoData,
    PermissionDenied,
    Timeout,
    NotSupported,
    UnknownError,
    ConnectionFailed,
    NoMemory,
    ParseError,
    SystemError,
}{
    error.InvalidCommand, error.InvalidArgument,  error.MethodNotFound, error.NotFound,
    error.NoData,         error.PermissionDenied, error.Timeout,        error.NotSupported,
    error.UnknownError,   error.ConnectionFailed, error.NoMemory,       error.ParseError,
    error.SystemError,
};

/// One connection to ubusd, for calls. Reconnects on the next call after a
/// failure, so a ubusd restart costs one failed call.
pub const Conn = struct {
    fd: posix.fd_t = -1,
    seq: u16 = 0,
    /// Holds the last received message; reused so polling doesn't allocate.
    rx: std.ArrayList(u8) = .empty,

    pub fn deinit(c: *Conn, gpa: Allocator) void {
        c.disconnect();
        c.rx.deinit(gpa);
    }

    /// `ubus call <path> <method>` with `args` (a struct, or `.{}`) as the
    /// message. Returns the reply table's members (read them with `List`),
    /// empty when there was none; the caller frees it.
    pub fn call(c: *Conn, gpa: Allocator, path: []const u8, method: []const u8, args: anytype) ![]u8 {
        var buf: [512]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        try putFields(&w, args);
        return c.invoke(gpa, path, method, w.buffered());
    }

    /// Not generic, so each argument type adds only its encoder to the binary.
    fn invoke(c: *Conn, gpa: Allocator, path: []const u8, method: []const u8, args: []const u8) ![]u8 {
        if (c.fd < 0) try c.connect(gpa);
        const id = try c.lookup(gpa, path);

        var buf: [1024]u8 = undefined;
        var w: Io.Writer = .fixed(buf[hdr_len..]);
        const root = try begin(&w, 0, null);
        try putU32(&w, .objid, id);
        try putString(&w, @backingInt(Attr.method), null, method);
        const data = try begin(&w, @backingInt(Attr.data), null);
        try w.writeAll(args);
        try end(&w, data);
        try end(&w, root);
        const seq = try c.request(&buf, w.end, .invoke, id);

        // Copied out: the status message that follows reuses the receive buffer.
        var out: []u8 = &.{};
        errdefer gpa.free(out);
        while (true) {
            const m = try c.recvReply(gpa, seq, id);
            if (m.type == .data) if (m.attrs[@backingInt(Attr.data)]) |d| {
                gpa.free(out); // one reply; keep the last if there were more
                out = &.{};
                out = try gpa.dupe(u8, d);
            };
            if (m.type == .status) {
                try check(m);
                return out;
            }
        }
    }

    fn lookup(c: *Conn, gpa: Allocator, path: []const u8) !u32 {
        var buf: [256]u8 = undefined;
        var w: Io.Writer = .fixed(buf[hdr_len..]);
        const root = try begin(&w, 0, null);
        try putString(&w, @backingInt(Attr.objpath), null, path);
        try end(&w, root);
        return c.objectRequest(gpa, &buf, w.end, .lookup) catch |err| switch (err) {
            error.NoData => error.NotFound,
            else => err,
        };
    }

    /// A request to ubusd itself (lookup, add_object, subscribe): waits for
    /// its status and returns the object id its data reply named, if any.
    fn objectRequest(c: *Conn, gpa: Allocator, buf: []u8, blob_len: usize, t: MsgType) !u32 {
        const seq = try c.request(buf, blob_len, t, 0);
        var id: ?u32 = null;
        while (true) {
            const m = try c.recvReply(gpa, seq, 0);
            if (m.type == .data) id = m.word(.objid) orelse id;
            if (m.type == .status) {
                try check(m);
                return id orelse if (t == .subscribe) 0 else error.NoData;
            }
        }
    }

    fn connect(c: *Conn, gpa: Allocator) !void {
        const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.ConnectionFailed;
        c.fd = @intCast(rc);
        errdefer c.disconnect();
        var addr: linux.sockaddr.un = .{ .path = @splat(0) };
        @memcpy(addr.path[0..socket_path.len], socket_path);
        if (linux.errno(linux.connect(c.fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS) return error.ConnectionFailed;
        if ((try c.recv(gpa)).type != .hello) return error.Malformed;
    }

    fn disconnect(c: *Conn) void {
        if (c.fd >= 0) _ = linux.close(c.fd);
        c.fd = -1;
    }

    /// Sends the message whose blob sits in `buf[hdr_len..][0..blob_len]`.
    fn send(c: *Conn, buf: []u8, blob_len: usize, t: MsgType, seq: u16, peer: u32) !void {
        buf[0] = 0;
        buf[1] = @backingInt(t);
        mem.writeInt(u16, buf[2..4], seq, .big);
        mem.writeInt(u32, buf[4..8], peer, .big);
        var rest = buf[0 .. hdr_len + blob_len];
        while (rest.len > 0) {
            const rc = linux.sendto(c.fd, rest.ptr, rest.len, linux.MSG.NOSIGNAL, null, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => rest = rest[rc..],
                .INTR => {},
                else => {
                    c.disconnect();
                    return error.ConnectionFailed;
                },
            }
        }
    }

    /// Next message answering request `seq` to `peer`. Anything else is
    /// stale (a reply to a call that timed out) or a notification that came
    /// in while we waited.
    fn recvReply(c: *Conn, gpa: Allocator, seq: u16, peer: u32) !Message {
        while (true) {
            const m = try c.recv(gpa);
            if (m.seq == seq and m.peer == peer and (m.type == .data or m.type == .status)) return m;
            if (m.type == .invoke) try c.ack(m, false);
        }
    }

    /// Reads one whole message; it stays valid until the next read.
    fn recv(c: *Conn, gpa: Allocator) !Message {
        errdefer c.disconnect(); // the stream can't be resynchronised
        try c.rx.resize(gpa, hdr_len + 4);
        try c.readExact(c.rx.items);
        const raw = mem.readInt(u32, c.rx.items[hdr_len..][0..4], .big) & len_mask;
        if (raw < 4 or raw > max_msg) return error.Malformed;
        try c.rx.resize(gpa, hdr_len + raw);
        try c.readExact(c.rx.items[hdr_len + 4 ..]);
        return Message.parse(c.rx.items);
    }

    fn readExact(c: *Conn, buf: []u8) !void {
        var got: usize = 0;
        while (got < buf.len) {
            var fds = [_]posix.pollfd{.{ .fd = c.fd, .events = posix.POLL.IN, .revents = 0 }};
            if (try posix.poll(&fds, timeout_ms) == 0) return error.Timeout;
            const n = posix.read(c.fd, buf[got..]) catch return error.ConnectionFailed;
            if (n == 0) return error.ConnectionFailed;
            got += n;
        }
    }

    /// Answers an invoke unless the sender said it wants no reply, as
    /// libubus does; a missing answer would leave the sender waiting.
    fn ack(c: *Conn, m: Message, ok: bool) !void {
        if ((m.byte(.no_reply) orelse 0) != 0) return;
        var buf: [64]u8 = undefined;
        var w: Io.Writer = .fixed(buf[hdr_len..]);
        const root = try begin(&w, 0, null);
        try putU32(&w, .status, if (ok) 0 else 4); // UBUS_STATUS_NOT_FOUND
        try putU32(&w, .objid, m.word(.objid) orelse 0);
        try end(&w, root);
        try c.send(&buf, w.end, .status, m.seq, m.peer);
    }

    /// Sends a request; its replies carry the returned seq.
    fn request(c: *Conn, buf: []u8, blob_len: usize, t: MsgType, peer: u32) !u16 {
        c.seq +%= 1;
        try c.send(buf, blob_len, t, c.seq, peer);
        return c.seq;
    }
};

/// Watches objects' notifications, like `ubus subscribe`: an anonymous object
/// on its own connection, subscribed to each target.
pub const Subscriber = struct {
    conn: Conn = .{},
    id: u32 = 0,

    pub fn deinit(s: *Subscriber, gpa: Allocator) void {
        s.conn.deinit(gpa);
    }

    pub fn active(s: Subscriber) bool {
        return s.conn.fd >= 0;
    }

    pub fn fd(s: Subscriber) posix.fd_t {
        return s.conn.fd;
    }

    pub fn start(s: *Subscriber, gpa: Allocator, paths: []const []const u8) !void {
        s.stop();
        try s.conn.connect(gpa);
        errdefer s.stop();
        var buf: [64]u8 = undefined;
        var w: Io.Writer = .fixed(buf[hdr_len..]);
        const root = try begin(&w, 0, null);
        try end(&w, root);
        s.id = try s.conn.objectRequest(gpa, &buf, w.end, .add_object);

        for (paths) |path| {
            const target = try s.conn.lookup(gpa, path);
            w = .fixed(buf[hdr_len..]);
            const r = try begin(&w, 0, null);
            try putU32(&w, .objid, s.id);
            try putU32(&w, .target, target);
            try end(&w, r);
            _ = try s.conn.objectRequest(gpa, &buf, w.end, .subscribe);
        }
    }

    /// Closing the connection drops the object and its subscriptions in ubusd.
    pub fn stop(s: *Subscriber) void {
        s.conn.disconnect();
    }

    /// One notification: its type (e.g. "probe") and its data table. Valid
    /// until the next read.
    pub const Notification = struct { method: []const u8, data: List };

    /// Reads one message once poll says the socket is readable: a
    /// notification, or null for anything else. An error means the
    /// subscription ended: ubusd went away, or a target object did (a Wi-Fi
    /// reload), which ubusd reports as an unsubscribe.
    pub fn next(s: *Subscriber, gpa: Allocator) !?Notification {
        const m = try s.conn.recv(gpa);
        switch (m.type) {
            .unsubscribe => {
                s.stop();
                return error.Unsubscribed;
            },
            .invoke => {
                const ours = m.word(.objid) == s.id;
                try s.conn.ack(m, ours);
                if (!ours) return null;
                const method = m.string(.method) orelse return null;
                const data = m.attrs[@backingInt(Attr.data)] orelse return null;
                return .{ .method = method, .data = .{ .rest = data } };
            },
            else => return null,
        }
    }
};

const Message = struct {
    type: MsgType,
    seq: u16,
    peer: u32,
    /// Payload of each ubus attribute, by id.
    attrs: [n_attrs]?[]const u8 = @splat(null),

    fn parse(buf: []const u8) !Message {
        if (buf.len < hdr_len + 4 or buf[0] != 0) return error.Malformed;
        var m: Message = .{
            .type = @fromBackingInt(buf[1]),
            .seq = mem.readInt(u16, buf[2..4], .big),
            .peer = mem.readInt(u32, buf[4..8], .big),
        };
        var it: Iter = .{ .rest = buf[hdr_len..] };
        const root = try it.next() orelse return error.Malformed;
        var attrs: Iter = .{ .rest = root.data };
        while (try attrs.next()) |a| {
            if (a.id < n_attrs) m.attrs[a.id] = a.data;
        }
        return m;
    }

    fn word(m: Message, a: Attr) ?u32 {
        const v = m.attrs[@backingInt(a)] orelse return null;
        return if (v.len == 4) mem.readInt(u32, v[0..4], .big) else null;
    }

    fn byte(m: Message, a: Attr) ?u8 {
        const v = m.attrs[@backingInt(a)] orelse return null;
        return if (v.len == 1) v[0] else null;
    }

    fn string(m: Message, a: Attr) ?[]const u8 {
        const v = m.attrs[@backingInt(a)] orelse return null;
        if (v.len == 0 or v[v.len - 1] != 0) return null;
        return mem.sliceTo(v, 0);
    }
};

fn check(m: Message) !void {
    const status = m.word(.status) orelse return error.Malformed;
    if (status == 0) return;
    return if (status <= status_errors.len) status_errors[status - 1] else error.UnknownError;
}

// Encoding. A blob attribute is a big-endian u32 (extended flag, 7-bit id,
// 24-bit length including itself), then its payload, padded to 4 bytes. A
// blobmsg attribute is extended and starts its payload with a name.

/// Starts an attribute (a blobmsg one when `name` is set); `end` patches its length.
fn begin(w: *Io.Writer, id: u7, name: ?[]const u8) !usize {
    const start = w.end;
    try w.writeInt(u32, (if (name != null) extended else 0) | @as(u32, id) << 24, .big);
    if (name) |n| {
        try w.writeInt(u16, @intCast(n.len), .big);
        try w.writeAll(n);
        try w.writeByte(0);
        try pad(w);
    }
    return start;
}

fn end(w: *Io.Writer, start: usize) !void {
    const h = w.buffer[start..][0..4];
    mem.writeInt(u32, h, mem.readInt(u32, h, .big) | @as(u32, @intCast(w.end - start)), .big);
    try pad(w);
}

fn pad(w: *Io.Writer) !void {
    try w.splatByteAll(0, mem.alignForward(usize, w.end, 4) - w.end);
}

fn putU32(w: *Io.Writer, a: Attr, v: u32) !void {
    const s = try begin(w, @backingInt(a), null);
    try w.writeInt(u32, v, .big);
    try end(w, s);
}

fn putString(w: *Io.Writer, id: u7, name: ?[]const u8, v: []const u8) !void {
    const s = try begin(w, id, name);
    try w.writeAll(v);
    try w.writeByte(0);
    try end(w, s);
}

/// A struct's fields as the members of a blobmsg table.
pub fn putFields(w: *Io.Writer, args: anytype) !void {
    inline for (@typeInfo(@TypeOf(args)).@"struct".field_names) |n| try putValue(w, n, @field(args, n));
}

/// Same types `ubus call` gives the equivalent JSON (libubox's
/// blobmsg_add_json_element): integers int32 when they fit, else int64;
/// booleans int8; strings; tuples and slices as arrays; structs as tables.
fn putValue(w: *Io.Writer, name: []const u8, v: anytype) !void {
    const T = @TypeOf(v);
    switch (@typeInfo(T)) {
        .bool => {
            const s = try begin(w, @backingInt(Type.int8), name);
            try w.writeByte(@intFromBool(v));
            try end(w, s);
        },
        .int, .comptime_int => {
            const x: i64 = v;
            const small = std.math.cast(i32, x);
            const s = try begin(w, @backingInt(if (small != null) Type.int32 else Type.int64), name);
            if (small) |y| try w.writeInt(i32, y, .big) else try w.writeInt(i64, x, .big);
            try end(w, s);
        },
        .optional => if (v) |x| try putValue(w, name, x),
        .pointer => |p| {
            const Elem = switch (p.size) {
                .one => @typeInfo(p.child).array.child,
                else => p.child,
            };
            if (Elem == u8) return putString(w, @backingInt(Type.string), name, v);
            const s = try begin(w, @backingInt(Type.array), name);
            for (v) |x| try putValue(w, "", x);
            try end(w, s);
        },
        .@"struct" => |st| {
            const s = try begin(w, @backingInt(if (st.is_tuple) Type.array else Type.table), name);
            inline for (st.field_names) |n| try putValue(w, if (st.is_tuple) "" else n, @field(v, n));
            try end(w, s);
        },
        else => @compileError("no blobmsg type for " ++ @typeName(T)),
    }
}

// Decoding.

const Blob = struct { id: u7, extended: bool, data: []const u8 };

/// Walks a run of attributes, checking each length against what's left.
const Iter = struct {
    rest: []const u8,

    fn next(it: *Iter) !?Blob {
        if (it.rest.len == 0) return null;
        if (it.rest.len < 4) return error.Malformed;
        const h = mem.readInt(u32, it.rest[0..4], .big);
        const raw = h & len_mask;
        const padded = mem.alignForward(usize, raw, 4);
        if (raw < 4 or padded > it.rest.len) return error.Malformed;
        defer it.rest = it.rest[padded..];
        return .{ .id = @truncate(h >> 24), .extended = h & extended != 0, .data = it.rest[4..raw] };
    }
};

/// A blobmsg attribute's name and value.
fn named(b: Blob) !struct { name: []const u8, value: []const u8 } {
    if (!b.extended) return .{ .name = "", .value = b.data };
    if (b.data.len < 2) return error.Malformed;
    const n = mem.readInt(u16, b.data[0..2], .big);
    const hdr = mem.alignForward(usize, 2 + @as(usize, n) + 1, 4);
    if (b.data.len < hdr or b.data[2 + n] != 0) return error.Malformed;
    return .{ .name = b.data[2..][0..n], .value = b.data[hdr..] };
}

/// A blobmsg table's or array's members, read in place. Array members have
/// empty names. Every length is checked, so hostile input only ever yields
/// error.Malformed.
pub const List = struct {
    rest: []const u8,

    pub const Value = union(enum) {
        /// int8 (also booleans), int16, int32 or int64.
        int: i64,
        string: []const u8,
        list: List,
        /// unspec (null) or double; nothing meshkeeper reads is either.
        other,

        pub fn asInt(v: Value) ?i64 {
            return if (v == .int) v.int else null;
        }

        pub fn asString(v: Value) ?[]const u8 {
            return if (v == .string) v.string else null;
        }

        pub fn asList(v: Value) ?List {
            return if (v == .list) v.list else null;
        }
    };

    pub const Member = struct { name: []const u8, value: Value };

    pub fn next(l: *List) !?Member {
        var it: Iter = .{ .rest = l.rest };
        const b = try it.next() orelse return null;
        l.rest = it.rest;
        const e = try named(b);
        const v = e.value;
        return .{ .name = e.name, .value = switch (@as(Type, @fromBackingInt(b.id))) {
            .int8 => .{ .int = @as(i8, @bitCast((try exact(1, v))[0])) },
            .int16 => .{ .int = mem.readInt(i16, try exact(2, v), .big) },
            .int32 => .{ .int = mem.readInt(i32, try exact(4, v), .big) },
            .int64 => .{ .int = mem.readInt(i64, try exact(8, v), .big) },
            .string => if (v.len == 0 or v[v.len - 1] != 0) return error.Malformed else .{ .string = mem.sliceTo(v, 0) },
            .array, .table => .{ .list = .{ .rest = v } },
            .unspec => .other,
            .double => if (v.len != 8) return error.Malformed else .other,
            _ => return error.Malformed,
        } };
    }

    /// The first member called `name`.
    pub fn get(l: List, name: []const u8) !?Value {
        var it = l;
        while (try it.next()) |m| if (mem.eql(u8, m.name, name)) return m.value;
        return null;
    }

    // Typed lookups: null when the member is missing or has another type.
    pub fn int(l: List, name: []const u8) !?i64 {
        return if (try l.get(name)) |v| v.asInt() else null;
    }

    pub fn string(l: List, name: []const u8) !?[]const u8 {
        return if (try l.get(name)) |v| v.asString() else null;
    }

    pub fn list(l: List, name: []const u8) !?List {
        return if (try l.get(name)) |v| v.asList() else null;
    }
};

fn exact(comptime n: usize, v: []const u8) !*const [n]u8 {
    return if (v.len == n) v[0..n] else error.Malformed;
}

const vectors = @import("testdata/blobmsg_vectors.zig");

test "encodes arguments byte for byte like ubus call" {
    const args = .{
        .{ .notify_response = 0 },
        .{ .bss_transition = true },
        .{ .addr = "02:00:00:00:c0:de", .disassociation_imminent = false, .abridged = true, .validity_period = 30, .neighbors = .{"020000a0d94f0f000000802409"} },
        .{ .addr = "02:00:00:00:c0:de", .reason = 3, .deauth = true, .ban_time = 0 },
        .{ .big = 5000000000, .neg = -1, .t = .{ .x = "y" }, .e = .{} },
    };
    inline for (args, 0..) |a, i| {
        var buf: [512]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        try putFields(&w, a);
        var want: [512]u8 = undefined;
        try std.testing.expectEqualSlices(u8, try std.fmt.hexToBytes(&want, vectors.cases[i].hex), w.buffered());
    }
}

/// Visits every member below `l`, so the fuzz test reaches every check.
fn walk(l: List, depth: usize) !usize {
    if (depth == 16) return error.Malformed;
    var it = l;
    var n: usize = 0;
    while (try it.next()) |m| n += 1 + if (m.value.asList()) |sub| try walk(sub, depth + 1) else 0;
    return n;
}

test "reads the replies libubox encodes" {
    const t = std.testing;
    var bytes: [1024]u8 = undefined;
    const one = List{ .rest = try std.fmt.hexToBytes(&bytes, vectors.cases[4].hex) };
    try t.expectEqual(5000000000, (try one.int("big")).?);
    try t.expectEqual(-1, (try one.int("neg")).?);
    try t.expectEqualStrings("y", (try (try one.list("t")).?.string("x")).?);
    try t.expectEqual(0, try walk((try one.list("e")).?, 0));
    try t.expectEqual(null, try one.string("big")); // wrong type
    try t.expectEqual(null, try one.int("missing"));

    var more: [1024]u8 = undefined;
    const clients = List{ .rest = try std.fmt.hexToBytes(&more, vectors.cases[5].hex) };
    try t.expectEqual(5745, (try clients.int("freq")).?);
    const c = (try (try clients.list("clients")).?.list("02:00:00:00:c0:de")).?;
    try t.expectEqual(-74, (try c.int("signal")).?);
    try t.expectEqual(1, (try c.int("auth")).?); // a JSON true
    var caps = (try c.list("extended_capabilities")).?;
    var k: usize = 0;
    while (try caps.next()) |m| : (k += 1) if (k == 2) try t.expectEqual(136, m.value.asInt().?);
    try t.expectEqual(10, k);

    for (vectors.cases) |v| _ = try walk(.{ .rest = try std.fmt.hexToBytes(&bytes, v.hex) }, 0);
}

test "parses a message and maps its status" {
    var buf: [64]u8 = undefined;
    var w: Io.Writer = .fixed(buf[hdr_len..]);
    const root = try begin(&w, 0, null);
    try putU32(&w, .status, 6);
    try putU32(&w, .objid, 0x1234);
    try putString(&w, @backingInt(Attr.method), null, "probe");
    try end(&w, root);
    buf[0..hdr_len].* = .{ 0, @backingInt(MsgType.status), 0, 7, 0, 0, 0, 9 };
    const m = try Message.parse(buf[0 .. hdr_len + w.end]);
    try std.testing.expectEqual(MsgType.status, m.type);
    try std.testing.expectEqual(7, m.seq);
    try std.testing.expectEqual(9, m.peer);
    try std.testing.expectEqual(0x1234, m.word(.objid).?);
    try std.testing.expectEqualStrings("probe", m.string(.method).?);
    try std.testing.expectError(error.PermissionDenied, check(m));
}

test "fuzz: hostile replies never crash the decoder" {
    var prng: std.Random.DefaultPrng = .init(0x0b05);
    const rand = prng.random();
    var bytes: [1024]u8 = undefined;
    for (0..20_000) |i| {
        var len: usize = undefined;
        if (i % 2 == 0) {
            len = rand.uintAtMost(usize, 256);
            rand.bytes(bytes[0..len]);
        } else {
            // Real replies with a few bytes flipped, so decoding gets past the
            // first length check and into names, types and nesting.
            const c = vectors.cases[rand.uintLessThan(usize, vectors.cases.len)];
            len = (std.fmt.hexToBytes(&bytes, c.hex) catch unreachable).len;
            for (0..rand.intRangeAtMost(usize, 1, 4)) |_| bytes[rand.uintLessThan(usize, len)] ^= rand.int(u8) | 1;
            len = rand.intRangeAtMost(usize, len / 2, len);
        }
        _ = walk(.{ .rest = bytes[0..len] }, 0) catch {};
        _ = Message.parse(bytes[0..len]) catch {};
    }
}
