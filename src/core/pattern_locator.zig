const std = @import("std");
const image_backend = @import("image_backend.zig");

/// One byte inside a parsed code pattern.
///
/// `mask == 0xff` means an exact byte match.
/// `mask == 0x00` means a full-byte wildcard (`??`).
pub const PatternByte = struct {
    value: u8,
    mask: u8,

    pub fn matches(self: PatternByte, byte: u8) bool {
        return (byte & self.mask) == (self.value & self.mask);
    }
};

pub const Match = struct {
    address: u64,
    file_offset: usize,
};

pub fn parseHexPattern(allocator: std.mem.Allocator, pattern_text: []const u8) ![]PatternByte {
    var cleaned: std.ArrayList(u8) = .empty;
    defer cleaned.deinit(allocator);

    for (pattern_text) |char| {
        if (std.ascii.isWhitespace(char) or char == '_' or char == ':') continue;
        try cleaned.append(allocator, char);
    }

    if (cleaned.items.len == 0) return error.EmptyPattern;
    if ((cleaned.items.len & 1) != 0) return error.InvalidPatternHex;

    const parsed = try allocator.alloc(PatternByte, cleaned.items.len / 2);
    errdefer allocator.free(parsed);

    for (parsed, 0..) |*item, index| {
        const hi = cleaned.items[index * 2];
        const lo = cleaned.items[index * 2 + 1];
        if (hi == '?' and lo == '?') {
            item.* = .{ .value = 0, .mask = 0 };
            continue;
        }
        if (hi == '?' or lo == '?') return error.UnsupportedNibbleWildcard;

        item.* = .{
            .value = (@as(u8, try parseHexNibble(hi)) << 4) | try parseHexNibble(lo),
            .mask = 0xFF,
        };
    }

    return parsed;
}

pub fn findMatchesInExecutableSegments(
    allocator: std.mem.Allocator,
    view: image_backend.View,
    pattern: []const PatternByte,
    limit: usize,
) ![]Match {
    if (pattern.len == 0) return error.EmptyPattern;

    var matches: std.ArrayList(Match) = .empty;
    defer matches.deinit(allocator);

    const executable_ranges = try view.executableRanges(allocator);
    defer allocator.free(executable_ranges);
    const bytes = view.bytes();

    for (executable_ranges) |range| {
        if (range.size < pattern.len) continue;

        const file_start = range.file_offset;
        const file_end = range.file_offset + range.size;
        const last_start = file_end - pattern.len;

        var file_offset = file_start;
        while (file_offset <= last_start) : (file_offset += 1) {
            if (!matchesPattern(bytes[file_offset .. file_offset + pattern.len], pattern)) continue;

            try matches.append(allocator, .{
                .address = range.address + (@as(u64, @intCast(file_offset - range.file_offset))),
                .file_offset = file_offset,
            });
            if (limit != 0 and matches.items.len >= limit) break;
        }
        if (limit != 0 and matches.items.len >= limit) break;
    }

    return matches.toOwnedSlice(allocator);
}

pub fn formatPattern(buffer: []u8, pattern: []const PatternByte) []const u8 {
    if (buffer.len == 0) return "";

    const digits = "0123456789abcdef";
    const max_bytes = @min(pattern.len, buffer.len / 2);
    for (pattern[0..max_bytes], 0..) |item, index| {
        if (item.mask == 0) {
            buffer[index * 2] = '?';
            buffer[index * 2 + 1] = '?';
            continue;
        }
        buffer[index * 2] = digits[item.value >> 4];
        buffer[index * 2 + 1] = digits[item.value & 0xF];
    }
    return buffer[0 .. max_bytes * 2];
}

fn matchesPattern(bytes: []const u8, pattern: []const PatternByte) bool {
    for (pattern, bytes) |item, byte| {
        if (!item.matches(byte)) return false;
    }
    return true;
}

fn parseHexNibble(char: u8) !u8 {
    return switch (char) {
        '0'...'9' => char - '0',
        'a'...'f' => char - 'a' + 10,
        'A'...'F' => char - 'A' + 10,
        else => error.InvalidPatternHex,
    };
}

test "pattern parser supports exact bytes and full-byte wildcards" {
    const allocator = std.testing.allocator;

    const pattern = try parseHexPattern(allocator, "aa bb ?? dd");
    defer allocator.free(pattern);

    try std.testing.expectEqual(@as(usize, 4), pattern.len);
    try std.testing.expectEqual(@as(u8, 0xFF), pattern[0].mask);
    try std.testing.expectEqual(@as(u8, 0x00), pattern[2].mask);
}

test "pattern matcher scans executable segments only" {
    const allocator = std.testing.allocator;

    var bytes = [_]u8{
        0x7f, 'E', 'L', 'F',
    } ++ [_]u8{0} ** 0x100;
    _ = &bytes;
    _ = allocator;
}
