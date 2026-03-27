const std = @import("std");
const zrwrite = @import("zrwrite");

pub fn compileAarch64AssemblyObject(
    allocator: std.mem.Allocator,
    source_name: []const u8,
    source: []const u8,
) ![]u8 {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = source_name,
        .data = source,
    });

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const source_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, source_name });
    defer allocator.free(source_path);

    const object_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "payload.o" });
    defer allocator.free(object_path);

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-g0",
        "-fPIC",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        source_path,
        "-o",
        object_path,
    });

    return std.fs.cwd().readFileAlloc(allocator, object_path, std.math.maxInt(usize));
}

pub fn readLeU32(bytes: []const u8, offset: usize) !u32 {
    if (offset + @sizeOf(u32) > bytes.len) return error.EndOfStream;
    const ptr: *const [4]u8 = @ptrCast(bytes[offset .. offset + 4].ptr);
    return std.mem.readInt(u32, ptr, .little);
}

pub fn readLeU64(bytes: []const u8, offset: usize) !u64 {
    if (offset + @sizeOf(u64) > bytes.len) return error.EndOfStream;
    const ptr: *const [8]u8 = @ptrCast(bytes[offset .. offset + 8].ptr);
    return std.mem.readInt(u64, ptr, .little);
}

pub fn readLeI32(bytes: []const u8, offset: usize) !i32 {
    if (offset + @sizeOf(i32) > bytes.len) return error.EndOfStream;
    const ptr: *const [4]u8 = @ptrCast(bytes[offset .. offset + 4].ptr);
    return std.mem.readInt(i32, ptr, .little);
}

pub fn readLeI64(bytes: []const u8, offset: usize) !i64 {
    if (offset + @sizeOf(i64) > bytes.len) return error.EndOfStream;
    const ptr: *const [8]u8 = @ptrCast(bytes[offset .. offset + 8].ptr);
    return std.mem.readInt(i64, ptr, .little);
}

pub fn writeLeU64(bytes: []u8, offset: usize, value: u64) !void {
    if (offset + @sizeOf(u64) > bytes.len) return error.EndOfStream;
    var le = std.mem.nativeToLittle(u64, value);
    @memcpy(bytes[offset .. offset + @sizeOf(u64)], std.mem.asBytes(&le));
}

pub fn overwriteFirstRelaType(object_bytes: []u8, relocation_type: u32) !void {
    return overwriteRelaTypeAtIndex(object_bytes, 0, relocation_type);
}

pub fn overwriteRelaTypeAtIndex(object_bytes: []u8, relocation_index: usize, relocation_type: u32) !void {
    const view = try zrwrite.elf.View.parse(object_bytes);
    var seen: usize = 0;

    for (view.shdrs) |shdr| {
        if (shdr.sh_type != std.elf.SHT_RELA or shdr.sh_size == 0) continue;

        if (shdr.sh_entsize != @sizeOf(std.elf.Elf64_Rela)) return error.InvalidRelocationTable;
        const rela_count: usize = @intCast(shdr.sh_size / shdr.sh_entsize);
        const rela_base: usize = @intCast(shdr.sh_offset);

        for (0..rela_count) |local_index| {
            if (seen != relocation_index) {
                seen += 1;
                continue;
            }

            const rela_offset = rela_base + local_index * @sizeOf(std.elf.Elf64_Rela);
            const info_offset = rela_offset + @offsetOf(std.elf.Elf64_Rela, "r_info");
            const old_info = try readLeU64(object_bytes, info_offset);
            const symbol_index = old_info >> 32;
            const new_info = (symbol_index << 32) | relocation_type;
            try writeLeU64(object_bytes, info_offset, new_info);
            return;
        }
    }

    return error.MissingRelocationSection;
}

pub fn hexStringAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    errdefer allocator.free(out);

    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        out[index * 2] = digits[byte >> 4];
        out[index * 2 + 1] = digits[byte & 0xF];
    }
    return out;
}

pub fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    if (needle.len == 0) return 0;

    var count: usize = 0;
    var cursor: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, cursor, needle)) |index| {
        count += 1;
        cursor = index + needle.len;
    }
    return count;
}

pub fn extractMovWideImmediate(opcode: u32) u16 {
    return @intCast((opcode >> 5) & 0xFFFF);
}

pub fn extractMoveWideOpcode(opcode: u32) u2 {
    return @intCast((opcode >> 29) & 0x3);
}

pub fn expectedSignedMoveWideImmediate(value: i64, shift: u6, negate_slice: bool) u16 {
    const raw: u64 = @bitCast(value);
    const slice: u16 = @intCast((raw >> shift) & 0xFFFF);
    return if (negate_slice) ~slice else slice;
}

pub fn decodeAdrpPageTarget(opcode: u32, site_address: u64) !u64 {
    const immlo = (opcode >> 29) & 0x3;
    const immhi = (opcode >> 5) & 0x7FFFF;
    const raw = immlo | (immhi << 2);
    const page_delta = try decodeSignedScaledImmediate(raw, 21, 12);
    const site_page = site_address & ~@as(u64, 0xFFF);
    const result = @as(i128, @intCast(site_page)) + @as(i128, page_delta);
    if (result < 0 or result > std.math.maxInt(u64)) return error.Overflow;
    return @intCast(result);
}

pub fn extractUnsignedLoadStoreImmediate(opcode: u32, shift: u6) u64 {
    const imm12 = (opcode >> 10) & 0xFFF;
    return @as(u64, imm12) << shift;
}

pub fn decodePcRelativeTarget(opcode: u32, site_address: u64, imm_bits: u6) !u64 {
    const imm = switch (imm_bits) {
        19 => (opcode >> 5) & 0x7FFFF,
        14 => (opcode >> 5) & 0x3FFF,
        else => return error.UnsupportedImmediateWidth,
    };
    const delta = try decodeSignedScaledImmediate(imm, imm_bits, 2);
    const result = @as(i128, @intCast(site_address)) + @as(i128, delta);
    if (result < 0 or result > std.math.maxInt(u64)) return error.Overflow;
    return @intCast(result);
}

pub fn decodeSignedScaledImmediate(raw: u32, bits: u6, shift: u6) !i64 {
    const shift_amount: u5 = @intCast(bits - 1);
    const bits_shift: u5 = @intCast(bits);
    const sign_bit = @as(u32, 1) << shift_amount;
    const extended = if ((raw & sign_bit) != 0)
        raw | ~((@as(u32, 1) << bits_shift) - 1)
    else
        raw;
    const signed: i32 = @bitCast(extended);
    const result = @as(i128, signed) << shift;
    if (result < std.math.minInt(i64) or result > std.math.maxInt(i64)) return error.Overflow;
    return @intCast(result);
}

pub fn runCommand(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        std.debug.print("command failed: {s}\n{s}\n{s}\n", .{
            argv[0],
            result.stdout,
            result.stderr,
        });
        return error.CommandFailed;
    }
}

pub fn runCommandCaptureStdout(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    });
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        defer allocator.free(result.stdout);
        std.debug.print("command failed: {s}\n{s}\n{s}\n", .{
            argv[0],
            result.stdout,
            result.stderr,
        });
        return error.CommandFailed;
    }

    return result.stdout;
}

pub fn runCommandExpectExitCode(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    expected_exit_code: u8,
) !void {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| {
            if (code == expected_exit_code) return;
            std.debug.print("command exited with unexpected code: {s} -> {d} (expected {d})\n{s}\n{s}\n", .{
                argv[0],
                code,
                expected_exit_code,
                result.stdout,
                result.stderr,
            });
            return error.UnexpectedExitCode;
        },
        else => {
            std.debug.print("command did not exit normally: {s}\n{s}\n{s}\n", .{
                argv[0],
                result.stdout,
                result.stderr,
            });
            return error.CommandFailed;
        },
    }
}
