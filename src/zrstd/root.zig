//! Small payload-side helper layer for Linux/AArch64 injected Zig code.
//!
//! Why this exists:
//! - injected payloads are not normal hosted Zig executables
//! - `std.debug.print` currently pulls in runtime/TLS-heavy paths that our
//!   payload mini-linker does not support yet
//! - authors still need a convenient, documented, low-dependency way to print
//!   trace information and use a tiny subset of libc-style helpers
//!
//! `zrstd` intentionally stays small and explicit. It is not a replacement for
//! Zig's standard library; it is a payload-safe compatibility layer for the
//! subset we can support reliably today.
const builtin = @import("builtin");
const std = @import("std");

const linux = std.os.linux;
comptime {
    if (!builtin.is_test) {
        if (builtin.os.tag != .linux) {
            @compileError("zrstd currently provides runtime helpers only for Linux payloads.");
        }
        if (builtin.cpu.arch != .aarch64) {
            @compileError("zrstd currently targets AArch64 payloads only.");
        }
    }
}

pub const stdout_fd: usize = 1;
pub const stderr_fd: usize = 2;
pub const default_print_buffer_len: usize = 512;

/// Namespace that mirrors the intent of `std.debug` for payload authors.
///
/// Example:
///
/// ```zig
/// const zrstd = @import("zrstd");
///
/// export fn on_hit(address: u64, ctx: *zrwrite.HookContext) callconv(.c) void {
///     _ = address;
///     zrstd.debug.print("x0=0x{x}\n", .{ctx.regs.named.x0});
/// }
/// ```
pub const debug = struct {
    pub inline fn print(comptime fmt_str: []const u8, args: anytype) void {
        writeFormat(stdout_fd, fmt_str, args);
    }

    pub inline fn println(comptime fmt_str: []const u8, args: anytype) void {
        writeFormat(stdout_fd, fmt_str ++ "\n", args);
    }

    pub inline fn eprint(comptime fmt_str: []const u8, args: anytype) void {
        writeFormat(stderr_fd, fmt_str, args);
    }

    pub inline fn eprintln(comptime fmt_str: []const u8, args: anytype) void {
        writeFormat(stderr_fd, fmt_str ++ "\n", args);
    }
};

/// Small formatting helpers that avoid dragging in heavier stdlib surfaces.
pub const fmt = struct {
    pub fn hexDigitLower(value: u4) u8 {
        return if (value < 10)
            @as(u8, '0') + @as(u8, value)
        else
            @as(u8, 'a') + (@as(u8, value) - 10);
    }

    pub fn hexByteLower(dest: *[2]u8, value: u8) void {
        dest[0] = hexDigitLower(@intCast(value >> 4));
        dest[1] = hexDigitLower(@intCast(value & 0xF));
    }

    /// Renders `value` as lowercase hexadecimal without a `0x` prefix.
    ///
    /// `min_digits` keeps the output width stable for tracing use cases. The
    /// value is clamped to the natural 16-digit width of `u64`.
    pub fn hexU64Lower(buffer: []u8, value: u64, min_digits: usize) ![]const u8 {
        if (buffer.len == 0) return error.NoSpaceLeft;

        const requested_digits = @min(min_digits, 16);
        var digits: usize = if (requested_digits == 0) 1 else requested_digits;
        while (digits < 16 and (value >> @intCast(digits * 4)) != 0) {
            digits += 1;
        }
        if (buffer.len < digits) return error.NoSpaceLeft;

        var remaining_shift = digits;
        while (remaining_shift != 0) {
            remaining_shift -= 1;
            const nibble: u4 = @intCast((value >> @intCast(remaining_shift * 4)) & 0xF);
            buffer[digits - remaining_shift - 1] = hexDigitLower(nibble);
        }
        return buffer[0..digits];
    }

    /// Renders `bytes` as a lowercase hexadecimal string without separators.
    pub fn hexBytesLower(buffer: []u8, bytes: []const u8) ![]const u8 {
        if (buffer.len < bytes.len * 2) return error.NoSpaceLeft;
        for (bytes, 0..) |byte, index| {
            var pair: [2]u8 = undefined;
            hexByteLower(&pair, byte);
            buffer[index * 2] = pair[0];
            buffer[index * 2 + 1] = pair[1];
        }
        return buffer[0 .. bytes.len * 2];
    }
};

/// Tiny memory helpers that mirror the most common payload-side slice chores.
pub const mem = struct {
    pub fn set(bytes: []u8, value: u8) void {
        for (bytes) |*byte| byte.* = value;
    }

    pub fn zero(bytes: []u8) void {
        set(bytes, 0);
    }

    pub fn copy(dest: []u8, src: []const u8) ![]u8 {
        if (dest.len < src.len) return error.NoSpaceLeft;
        @memcpy(dest[0..src.len], src);
        return dest[0..src.len];
    }

    pub fn move(dest: []u8, src: []const u8) ![]u8 {
        if (dest.len < src.len) return error.NoSpaceLeft;

        if (@intFromPtr(dest.ptr) <= @intFromPtr(src.ptr)) {
            for (src, 0..) |byte, index| dest[index] = byte;
        } else {
            var index = src.len;
            while (index != 0) {
                index -= 1;
                dest[index] = src[index];
            }
        }
        return dest[0..src.len];
    }
};

/// Minimal append-only writer for payload-side formatting and tracing.
///
/// This intentionally avoids the broader `std.io.Writer` abstraction because
/// the payload environment wants a tiny, explicit helper with no allocator and
/// no hidden runtime assumptions.
pub const FixedBuffer = struct {
    buffer: []u8,
    len: usize = 0,

    pub fn init(buffer: []u8) FixedBuffer {
        return .{ .buffer = buffer };
    }

    pub fn clear(self: *FixedBuffer) void {
        self.len = 0;
    }

    pub fn written(self: *const FixedBuffer) []const u8 {
        return self.buffer[0..self.len];
    }

    pub fn remaining(self: *FixedBuffer) []u8 {
        return self.buffer[self.len..];
    }

    pub fn writeByte(self: *FixedBuffer, byte: u8) !void {
        if (self.len >= self.buffer.len) return error.NoSpaceLeft;
        self.buffer[self.len] = byte;
        self.len += 1;
    }

    pub fn writeAll(self: *FixedBuffer, bytes: []const u8) !void {
        _ = try mem.copy(self.remaining(), bytes);
        self.len += bytes.len;
    }

    pub fn print(self: *FixedBuffer, comptime fmt_str: []const u8, args: anytype) !void {
        const rendered = try formatInto(self.remaining(), fmt_str, args);
        self.len += rendered.len;
    }

    pub fn writeHexU64Lower(self: *FixedBuffer, value: u64, min_digits: usize) !void {
        const rendered = try fmt.hexU64Lower(self.remaining(), value, min_digits);
        self.len += rendered.len;
    }

    pub fn writeHexBytesLower(self: *FixedBuffer, bytes: []const u8) !void {
        const rendered = try fmt.hexBytesLower(self.remaining(), bytes);
        self.len += rendered.len;
    }
};

const FormatKind = enum {
    default,
    hex_lower,
};

const FormatSpec = struct {
    kind: FormatKind = .default,
    min_width: usize = 0,
};

/// Parses the tiny payload-safe formatter surface supported by `zrstd`.
///
/// Deliberately supported today:
/// - `{}`
/// - `{x}`
/// - `{x:0>8}` style lowercase hex with zero-left-padding
///
/// We intentionally do not delegate to `std.fmt.bufPrint` here. The generic
/// stdlib formatter pulls in `Io.Writer` plumbing that, in practice, causes
/// Zig to materialize absolute function-pointer tables in `.rodata`. Those
/// `ABS64` relocations are acceptable for ET_EXEC but break ET_DYN / PIE
/// payloads, exactly the environment `zrwrite` wants to support.
fn parseFormatSpec(comptime spec: []const u8) FormatSpec {
    if (spec.len == 0) return .{};
    if (std.mem.eql(u8, spec, "x")) return .{ .kind = .hex_lower };

    if (std.mem.startsWith(u8, spec, "x:0>")) {
        if (spec.len == 4) @compileError("zrstd format width must contain at least one decimal digit.");

        comptime var width: usize = 0;
        inline for (spec[4..]) |digit| {
            if (digit < '0' or digit > '9') {
                @compileError("zrstd only supports decimal widths in {x:0>...} format specifiers.");
            }
            width = width * 10 + (digit - '0');
        }
        return .{
            .kind = .hex_lower,
            .min_width = width,
        };
    }

    @compileError("unsupported zrstd format specifier; supported forms are {}, {x}, and {x:0>width}.");
}

fn placeholderEnd(comptime fmt_str: []const u8, comptime start: usize) usize {
    comptime var index = start;
    inline while (index < fmt_str.len) : (index += 1) {
        if (fmt_str[index] == '}') return index;
        if (fmt_str[index] == '{') {
            @compileError("nested '{' is not supported in zrstd format strings.");
        }
    }
    @compileError("unterminated '{' in zrstd format string.");
}

fn formatIntoWriter(writer: *FixedBuffer, comptime fmt_str: []const u8, args: anytype) !void {
    const fields = std.meta.fields(@TypeOf(args));

    comptime var cursor: usize = 0;
    comptime var literal_start: usize = 0;
    comptime var arg_index: usize = 0;

    inline while (cursor < fmt_str.len) {
        switch (fmt_str[cursor]) {
            '{' => {
                if (cursor + 1 < fmt_str.len and fmt_str[cursor + 1] == '{') {
                    if (literal_start < cursor) try writer.writeAll(fmt_str[literal_start..cursor]);
                    try writer.writeByte('{');
                    cursor += 2;
                    literal_start = cursor;
                    continue;
                }

                if (literal_start < cursor) try writer.writeAll(fmt_str[literal_start..cursor]);

                if (arg_index >= fields.len) {
                    @compileError("zrstd format string expects more arguments than were provided.");
                }

                const end = comptime placeholderEnd(fmt_str, cursor + 1);
                const field_name = fields[arg_index].name;
                try writeFormattedValue(writer, fmt_str[cursor + 1 .. end], @field(args, field_name));

                arg_index += 1;
                cursor = end + 1;
                literal_start = cursor;
            },
            '}' => {
                if (cursor + 1 < fmt_str.len and fmt_str[cursor + 1] == '}') {
                    if (literal_start < cursor) try writer.writeAll(fmt_str[literal_start..cursor]);
                    try writer.writeByte('}');
                    cursor += 2;
                    literal_start = cursor;
                    continue;
                }
                @compileError("unmatched '}' in zrstd format string.");
            },
            else => cursor += 1,
        }
    }

    if (literal_start < fmt_str.len) try writer.writeAll(fmt_str[literal_start..]);
    if (arg_index != fields.len) {
        @compileError("zrstd received more arguments than the format string consumes.");
    }
}

fn writeFormattedValue(writer: *FixedBuffer, comptime spec_text: []const u8, value: anytype) !void {
    const spec = comptime parseFormatSpec(spec_text);
    switch (spec.kind) {
        .default => try writeDefaultValue(writer, value),
        .hex_lower => try writeHexValue(writer, value, spec.min_width),
    }
}

fn writeDefaultValue(writer: *FixedBuffer, value: anytype) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .int => |info| {
            if (info.bits > 64) {
                @compileError("zrstd default integer formatting currently supports widths up to 64 bits.");
            }
            if (info.signedness == .signed) {
                const signed_value: i64 = @intCast(value);
                try writeSignedDecimal(writer, signed_value);
            } else {
                const unsigned_value: u64 = @intCast(value);
                try writeUnsignedDecimal(writer, unsigned_value);
            }
        },
        .comptime_int => {
            if (value < 0) {
                try writeSignedDecimal(writer, @as(i64, value));
            } else {
                try writeUnsignedDecimal(writer, @as(u64, value));
            }
        },
        .bool => try writer.writeAll(if (value) "true" else "false"),
        .pointer => |pointer| switch (pointer.size) {
            .slice => {
                if (pointer.child != u8) {
                    @compileError("zrstd default formatting supports only byte slices, booleans, and integers.");
                }
                try writer.writeAll(value);
            },
            .one => switch (@typeInfo(pointer.child)) {
                .array => |array| {
                    if (array.child != u8) {
                        @compileError("zrstd default formatting supports only byte arrays, booleans, and integers.");
                    }
                    try writer.writeAll(value[0..]);
                },
                else => @compileError("zrstd default formatting supports only byte slices, booleans, and integers."),
            },
            else => @compileError("zrstd default formatting supports only byte slices, booleans, and integers."),
        },
        .array => |array| {
            if (array.child != u8) {
                @compileError("zrstd default formatting supports only byte slices, booleans, and integers.");
            }
            try writer.writeAll(value[0..]);
        },
        else => @compileError("zrstd default formatting supports only byte slices, booleans, and integers."),
    }
}

fn writeHexValue(writer: *FixedBuffer, value: anytype, min_width: usize) !void {
    const T = @TypeOf(value);
    const unsigned_value: u64 = switch (@typeInfo(T)) {
        .int => |info| blk: {
            if (info.bits > 64) @compileError("zrstd {x} formatting currently supports integer widths up to 64 bits.");
            if (info.signedness == .signed) {
                if (value < 0) @compileError("zrstd {x} formatting does not accept negative integers.");
                break :blk @intCast(value);
            }
            break :blk @intCast(value);
        },
        .comptime_int => blk: {
            if (value < 0) @compileError("zrstd {x} formatting does not accept negative integers.");
            break :blk @intCast(value);
        },
        else => @compileError("zrstd {x} formatting supports integers only."),
    };

    try writer.writeHexU64Lower(unsigned_value, min_width);
}

fn writeUnsignedDecimal(writer: *FixedBuffer, value: u64) !void {
    var scratch: [20]u8 = undefined;
    var cursor = scratch.len;
    var remaining = value;

    while (true) {
        cursor -= 1;
        scratch[cursor] = @as(u8, '0') + @as(u8, @intCast(remaining % 10));
        remaining /= 10;
        if (remaining == 0) break;
    }

    try writer.writeAll(scratch[cursor..]);
}

fn writeSignedDecimal(writer: *FixedBuffer, value: i64) !void {
    if (value < 0) {
        try writer.writeByte('-');
        const magnitude = @as(u64, @intCast(-(value + 1))) + 1;
        try writeUnsignedDecimal(writer, magnitude);
        return;
    }

    try writeUnsignedDecimal(writer, @intCast(value));
}

/// Formats into a caller-owned buffer without performing allocation.
///
/// This is the recommended lower-level primitive when a payload needs to build
/// a string first and then reuse it across multiple output or transport paths.
pub fn formatInto(buffer: []u8, comptime fmt_str: []const u8, args: anytype) ![]const u8 {
    var writer = FixedBuffer.init(buffer);
    try formatIntoWriter(&writer, fmt_str, args);
    return writer.written();
}

/// Writes the full byte slice to the requested file descriptor via raw Linux
/// `write(2)` syscalls. Errors are intentionally swallowed because payload
/// tracing must not destabilize the patched target process.
pub fn writeAll(fd: usize, bytes: []const u8) void {
    var remaining = bytes;
    while (remaining.len != 0) {
        const rc = linux.syscall3(.write, fd, @intFromPtr(remaining.ptr), remaining.len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const written: usize = @intCast(rc);
                if (written == 0) return;
                remaining = remaining[written..];
            },
            .INTR => continue,
            else => return,
        }
    }
}

pub inline fn writeStdout(bytes: []const u8) void {
    writeAll(stdout_fd, bytes);
}

pub inline fn writeStderr(bytes: []const u8) void {
    writeAll(stderr_fd, bytes);
}

/// Tiny libc-compatible helpers that common Zig formatting paths may reference.
///
/// These symbols are emitted directly by the payload object, which keeps the
/// injected code self-contained and avoids depending on the target binary's
/// libc export surface.
export fn memcpy(dest: ?*anyopaque, src: ?*const anyopaque, len: usize) callconv(.c) ?*anyopaque {
    if (len == 0) return dest;

    const dst: [*]u8 = @ptrCast(dest orelse return dest);
    const source: [*]const u8 = @ptrCast(src orelse return dest);
    for (0..len) |index| {
        dst[index] = source[index];
    }
    return dest;
}

/// `memmove` must preserve semantics for overlapping ranges because some Zig
/// formatting and slice-manipulation helpers are permitted to lower to it.
export fn memmove(dest: ?*anyopaque, src: ?*const anyopaque, len: usize) callconv(.c) ?*anyopaque {
    if (len == 0 or dest == src) return dest;

    const dst: [*]u8 = @ptrCast(dest orelse return dest);
    const source: [*]const u8 = @ptrCast(src orelse return dest);

    if (@intFromPtr(dst) < @intFromPtr(source)) {
        for (0..len) |index| {
            dst[index] = source[index];
        }
    } else {
        var index = len;
        while (index != 0) {
            index -= 1;
            dst[index] = source[index];
        }
    }
    return dest;
}

export fn memset(dest: ?*anyopaque, value: c_int, len: usize) callconv(.c) ?*anyopaque {
    if (len == 0) return dest;

    const dst: [*]u8 = @ptrCast(dest orelse return dest);
    const byte: u8 = @truncate(@as(c_uint, @bitCast(value)));
    for (0..len) |index| {
        dst[index] = byte;
    }
    return dest;
}

fn writeFormat(fd: usize, comptime fmt_str: []const u8, args: anytype) void {
    var buffer: [default_print_buffer_len]u8 = undefined;
    const rendered = formatInto(&buffer, fmt_str, args) catch |err| switch (err) {
        error.NoSpaceLeft => {
            writeAll(fd, "<zrstd: formatted output truncated>\n");
            return;
        },
    };
    writeAll(fd, rendered);
}

test "hex helpers render stable lowercase output" {
    var byte_pair: [2]u8 = undefined;
    fmt.hexByteLower(&byte_pair, 0xAF);
    try std.testing.expectEqualStrings("af", &byte_pair);

    var u64_buffer: [16]u8 = undefined;
    try std.testing.expectEqualStrings("00001a2b", try fmt.hexU64Lower(&u64_buffer, 0x1A2B, 8));

    var bytes_buffer: [8]u8 = undefined;
    try std.testing.expectEqualStrings("deadbeef", try fmt.hexBytesLower(&bytes_buffer, &.{ 0xDE, 0xAD, 0xBE, 0xEF }));
}

test "fixed buffer supports mixed print and hex appends" {
    var storage: [64]u8 = undefined;
    var writer = FixedBuffer.init(&storage);

    try writer.print("x0=", .{});
    try writer.writeHexU64Lower(0x42, 4);
    try writer.writeByte(' ');
    try writer.writeHexBytesLower(&.{ 0xCA, 0xFE });

    try std.testing.expectEqualStrings("x0=0042 cafe", writer.written());
}

test "formatInto supports payload-safe decimal and padded hex formatting" {
    var storage: [96]u8 = undefined;
    const rendered = try formatInto(
        &storage,
        "trace block={} word={} out=0x{x:0>8} ok={}",
        .{ @as(usize, 3), @as(u32, 2), @as(u32, 0xABCD), true },
    );

    try std.testing.expectEqualStrings("trace block=3 word=2 out=0x0000abcd ok=true", rendered);
}

test "mem helpers keep payload buffers explicit and bounded" {
    var dest = [_]u8{ 0, 0, 0, 0 };
    _ = try mem.copy(dest[0..], "ab");
    try std.testing.expectEqualStrings("ab", dest[0..2]);

    mem.set(dest[2..], 0x7F);
    try std.testing.expectEqual(@as(u8, 0x7F), dest[2]);
    try std.testing.expectEqual(@as(u8, 0x7F), dest[3]);

    mem.zero(dest[1..3]);
    try std.testing.expectEqual(@as(u8, 'a'), dest[0]);
    try std.testing.expectEqual(@as(u8, 0), dest[1]);
    try std.testing.expectEqual(@as(u8, 0), dest[2]);
}
