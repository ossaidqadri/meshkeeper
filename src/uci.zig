//! Reader for OpenWrt UCI config files (/etc/config/*). Reading the files
//! directly, as the service user, lets file permissions keep root-only configs
//! (network, system, ...) out of reach; `ubus call uci get` would hand them over.
//!
//! The tokenizer follows libuci's file.c: '...' is literal, "..." takes
//! backslash escapes, an unquoted backslash keeps the next byte as is, adjacent
//! parts join into one value ('it'\''s'), an unquoted # starts a comment and
//! ; separates commands. Only sections and their options are kept; `list`
//! values and `package` lines are accepted and skipped.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const max_file = 64 * 1024;

pub const Section = struct {
    type: []const u8,
    /// Null for anonymous sections, which can't be referenced by name.
    name: ?[]const u8,
    options: std.array_hash_map.String([]const u8) = .empty,

    pub fn get(s: Section, key: []const u8) ?[]const u8 {
        return s.options.get(key);
    }
};

pub const Config = struct {
    sections: []const Section,

    pub fn section(c: Config, name: []const u8) ?*const Section {
        for (c.sections) |*s| if (s.name) |n| if (std.mem.eql(u8, n, name)) return s;
        return null;
    }
};

pub const ParseError = error{
    UnterminatedQuote,
    InvalidCommand,
    MissingArgument,
    TooManyArguments,
    OptionOutsideSection,
} || Allocator.Error;

pub const Diagnostics = struct {
    /// 1-based line where the failing command starts.
    line: usize = 0,
};

/// Parses `text`; every returned slice is allocated in `arena`.
pub fn parse(arena: Allocator, text: []const u8, diag: ?*Diagnostics) ParseError!Config {
    var p: Parser = .{ .text = text };
    var cmd_line: usize = 0;
    errdefer if (diag) |d| {
        d.line = cmd_line + 1;
    };
    var sections: std.ArrayList(Section) = .empty;
    while (p.pos < text.len) {
        cmd_line = p.line;
        var args: [4][]const u8 = undefined;
        var n: usize = 0;
        while (try p.nextArg(arena)) |arg| {
            if (n == args.len) return error.TooManyArguments;
            args[n] = arg;
            n += 1;
        }
        p.endCommand();
        if (n == 0) continue;

        const kw = args[0];
        if (keyword(kw, "config")) {
            if (n < 2) return error.MissingArgument;
            if (n > 3) return error.TooManyArguments;
            try sections.append(arena, .{ .type = args[1], .name = if (n == 3 and args[2].len > 0) args[2] else null });
        } else if (keyword(kw, "option") or keyword(kw, "list")) {
            if (n < 3) return error.MissingArgument;
            if (n > 3) return error.TooManyArguments;
            if (sections.items.len == 0) return error.OptionOutsideSection;
            if (keyword(kw, "option")) try sections.items[sections.items.len - 1].options.put(arena, args[1], args[2]);
        } else if (keyword(kw, "package")) {
            if (n != 2) return error.MissingArgument;
        } else return error.InvalidCommand;
    }
    return .{ .sections = sections.items };
}

/// libuci accepts each keyword in full or as its first letter.
fn keyword(word: []const u8, full: []const u8) bool {
    return std.mem.eql(u8, word, full) or (word.len == 1 and word[0] == full[0]);
}

const Parser = struct {
    text: []const u8,
    pos: usize = 0,
    line: usize = 0,
    /// An escaped newline ended the current command.
    ended: bool = false,

    fn peek(p: Parser) ?u8 {
        return if (p.pos < p.text.len) p.text[p.pos] else null;
    }

    fn take(p: *Parser) u8 {
        const c = p.text[p.pos];
        p.pos += 1;
        if (c == '\n') p.line += 1;
        return c;
    }

    fn isBlank(c: u8) bool {
        return switch (c) {
            ' ', '\t', '\r', 0x0b, 0x0c => true,
            else => false,
        };
    }

    fn skipComment(p: *Parser) void {
        while (p.peek()) |c| {
            if (c == '\n') return;
            p.pos += 1;
        }
    }

    /// Next argument of the current command, or null at its end (newline,
    /// `;` or end of text, which `endCommand` then consumes).
    fn nextArg(p: *Parser, arena: Allocator) ParseError!?[]const u8 {
        if (p.ended) return null;
        while (p.peek()) |c| {
            if (!isBlank(c)) break;
            p.pos += 1;
        }
        const first = p.peek() orelse return null;
        switch (first) {
            '\n', ';' => return null,
            '#' => {
                p.skipComment();
                return null;
            },
            else => {},
        }

        var out: std.ArrayList(u8) = .empty;
        while (p.peek()) |c| switch (c) {
            '\'' => {
                p.pos += 1;
                while (true) {
                    const q = p.peek() orelse return error.UnterminatedQuote;
                    if (q == '\'') break;
                    try out.append(arena, p.take());
                }
                p.pos += 1;
            },
            '"' => {
                p.pos += 1;
                while (true) {
                    const q = p.peek() orelse return error.UnterminatedQuote;
                    if (q == '"') break;
                    if (q == '\\') {
                        p.pos += 1;
                        if (p.peek() == null) return error.UnterminatedQuote;
                    }
                    try out.append(arena, p.take());
                }
                p.pos += 1;
            },
            '\\' => {
                p.pos += 1;
                if (p.peek() == null) break;
                const e = p.take();
                try out.append(arena, e);
                if (e == '\n') {
                    p.ended = true;
                    break;
                }
            },
            '#' => {
                p.skipComment();
                break;
            },
            ';', '\n' => break,
            else => {
                if (isBlank(c)) break;
                try out.append(arena, c);
                p.pos += 1;
            },
        };
        return out.items;
    }

    fn endCommand(p: *Parser) void {
        p.ended = false;
        if (p.peek()) |c| if (c == '\n' or c == ';') {
            _ = p.take();
        };
    }
};

const testing = std.testing;

test "reads a typical wireless file" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const c = try parse(arena.allocator(),
        \\
        \\config wifi-device 'radio0'
        \\    option type 'mac80211'
        \\    list channels '36'
        \\
        \\config wifi-iface 'wifinet1'
        \\    option device radio0
        \\    option ssid 'MK 5GHz'
        \\    option key "s3cret#1"
        \\    option multi_ap '2'
        \\
        \\config wifi-iface
        \\    option ssid 'anonymous'
        \\
    , null);
    try testing.expectEqual(3, c.sections.len);
    const s = c.section("wifinet1").?;
    try testing.expectEqualStrings("wifi-iface", s.type);
    try testing.expectEqualStrings("MK 5GHz", s.get("ssid").?);
    try testing.expectEqualStrings("s3cret#1", s.get("key").?);
    try testing.expectEqualStrings("radio0", s.get("device").?);
    try testing.expectEqual(null, c.sections[2].name);
    try testing.expectEqual(null, c.section("radio0").?.get("channels"));
}

test "quoting follows libuci" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cases = [_]struct { line: []const u8, want: []const u8 }{
        .{ .line = "option v 'it'\\''s'", .want = "it's" }, // how uci commit writes a quote
        .{ .line = "option v 'x'\"y\"z", .want = "xyz" },
        .{ .line = "option v a\\ b", .want = "a b" },
        .{ .line = "option v 'a\\b'", .want = "a\\b" },
        .{ .line = "option v \"q\\\"x\\n\"", .want = "q\"xn" }, // escapes keep the byte, no \n decoding
        .{ .line = "option v b#c", .want = "b" },
        .{ .line = "option v 'b#c'", .want = "b#c" },
        .{ .line = "option v ''", .want = "" },
        .{ .line = "option v 'two\nlines'", .want = "two\nlines" },
        .{ .line = "o v short", .want = "short" },
    };
    for (cases) |case| {
        const text = try std.mem.concat(a, u8, &.{ "c t 's'\n", case.line, "\n" });
        const c = try parse(a, text, null);
        try testing.expectEqualStrings(case.want, c.section("s").?.get("v").?);
    }
}

test "semicolons, comments and package lines" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const c = try parse(arena.allocator(),
        \\package 'wireless'
        \\# a comment
        \\config t 'a'; option k v ; option j 'w'  # trailing
        \\config t 'b' # named, then a comment
    , null);
    try testing.expectEqualStrings("v", c.section("a").?.get("k").?);
    try testing.expectEqualStrings("w", c.section("a").?.get("j").?);
    try testing.expect(c.section("b") != null);
}

test "errors carry the line number" {
    var diag: Diagnostics = .{};
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.UnterminatedQuote, parse(a, "config t 's'\noption k 'open\n", &diag));
    try testing.expectEqual(2, diag.line);
    try testing.expectError(error.OptionOutsideSection, parse(a, "option k v\n", &diag));
    try testing.expectEqual(1, diag.line);
    try testing.expectError(error.InvalidCommand, parse(a, "config t\nbogus k v\n", &diag));
    try testing.expectError(error.MissingArgument, parse(a, "config\n", null));
    try testing.expectError(error.TooManyArguments, parse(a, "config t n extra\n", null));
}

test "fuzz: random config text never crashes the parser" {
    var prng: std.Random.DefaultPrng = .init(0x0c1);
    const rand = prng.random();
    const alphabet = "co ptlin'\"\\#;\n\tkv_xyz";
    var buf: [256]u8 = undefined;
    for (0..20_000) |i| {
        const len = rand.uintAtMost(usize, buf.len);
        if (i % 2 == 0) {
            rand.bytes(buf[0..len]);
        } else for (buf[0..len]) |*b| {
            b.* = alphabet[rand.uintLessThan(usize, alphabet.len)];
        }
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        _ = parse(arena.allocator(), buf[0..len], null) catch continue;
    }
}
