const std = @import("std");
const macho = std.macho;
const elf = std.elf;
const image_backend = @import("../image_backend.zig");
const ElfView = @import("../../format/elf/root.zig").View;

const link_diagnostic_capacity = 1024;
threadlocal var last_link_diagnostic_buf: [link_diagnostic_capacity]u8 = undefined;
threadlocal var last_link_diagnostic_len: usize = 0;

pub const PayloadLayout = struct {
    image_size: usize,
    entry_offset: usize,
    writable_image_size: usize = 0,

    pub fn hasSeparateWritableImage(self: PayloadLayout) bool {
        return self.writable_image_size != 0;
    }
};

pub const LoadedPayload = struct {
    image: []u8,
    entry_offset: usize,
    writable_image: ?[]u8 = null,

    pub fn deinit(self: *LoadedPayload, allocator: std.mem.Allocator) void {
        if (self.writable_image) |image| allocator.free(image);
        allocator.free(self.image);
        self.* = undefined;
    }
};

/// Clears the last payload-linker diagnostic.
///
/// The mini-linker stores a short human-readable explanation for the most
/// recent structured link failure (for example an unsupported relocation).
/// Frontends can query this after a call fails and surface a more useful error
/// than Zig's bare error-set tag alone.
pub fn clearLastLinkDiagnostic() void {
    last_link_diagnostic_len = 0;
}

/// Returns the most recent payload-linker diagnostic, if any.
pub fn lastLinkDiagnosticMessage() ?[]const u8 {
    if (last_link_diagnostic_len == 0) return null;
    return last_link_diagnostic_buf[0..last_link_diagnostic_len];
}

pub fn hasPendingLinkDiagnostic() bool {
    return last_link_diagnostic_len != 0;
}

pub const OutputSection = struct {
    input_index: usize,
    output_offset: usize,
    size: usize,
    alignment: usize,
    region: PayloadImageRegion = .primary,
};

pub const PayloadImageRegion = enum {
    primary,
    writable,
};

pub const PayloadImageBases = struct {
    primary: u64,
    writable: ?u64 = null,
};

pub fn recordLinkDiagnostic(comptime fmt: []const u8, args: anytype) void {
    const message = std.fmt.bufPrint(&last_link_diagnostic_buf, fmt, args) catch |err| switch (err) {
        error.NoSpaceLeft => blk: {
            const fallback = "payload link error (diagnostic truncated)";
            @memcpy(last_link_diagnostic_buf[0..fallback.len], fallback);
            break :blk fallback;
        },
    };
    last_link_diagnostic_len = message.len;
}

pub fn absoluteAddressWithAddend(symbol_address: u64, addend: i64) !u64 {
    const result = @as(i128, @intCast(symbol_address)) + @as(i128, addend);
    if (result < 0 or result > std.math.maxInt(u64)) return error.PayloadRelocationOverflow;
    return @intCast(result);
}

pub fn signedAbsoluteAddressWithAddend(symbol_address: u64, addend: i64) !i64 {
    const result = @as(i128, @intCast(symbol_address)) + @as(i128, addend);
    if (result < std.math.minInt(i64) or result > std.math.maxInt(i64)) {
        return error.PayloadRelocationOverflow;
    }
    return @intCast(result);
}

pub fn relativeDeltaWithAddend(symbol_address: u64, addend: i64, place_address: u64) !i64 {
    const result = @as(i128, @intCast(symbol_address)) +
        @as(i128, addend) -
        @as(i128, @intCast(place_address));
    if (result < std.math.minInt(i64) or result > std.math.maxInt(i64)) return error.PayloadRelocationOverflow;
    return @intCast(result);
}

pub fn baseRelativeDeltaWithAddend(symbol_address: u64, addend: i64, base_address: u64) !i64 {
    const result = @as(i128, @intCast(symbol_address)) +
        @as(i128, addend) -
        @as(i128, @intCast(base_address));
    if (result < std.math.minInt(i64) or result > std.math.maxInt(i64)) return error.PayloadRelocationOverflow;
    return @intCast(result);
}

pub fn addAddressOffset(base: u64, offset: usize) !u64 {
    return std.math.add(u64, base, @intCast(offset));
}

/// Encodes the signed immediate used by AArch64 PC-relative instruction
/// families.
///
/// `bits` is the encoded immediate width after any architectural shift. The
/// relocation helpers call this with:
/// - `(26, shift=2)` for `b` / `bl`
/// - `(19, shift=2)` for literal loads
/// - `(21, shift=0)` for `adr`
pub fn encodeSignedImmediate(comptime bits: u6, byte_delta: i64, shift: u6) !u32 {
    if (shift != 0) {
        const alignment_mask = (@as(i64, 1) << shift) - 1;
        if ((byte_delta & alignment_mask) != 0) return error.UnalignedRelocationTarget;
    }

    const scaled = byte_delta >> shift;
    const min = -(@as(i64, 1) << (bits - 1));
    const max = (@as(i64, 1) << (bits - 1)) - 1;
    if (scaled < min or scaled > max) return error.PayloadRelocationOverflow;

    const signed: i32 = @intCast(scaled);
    const raw: u32 = @bitCast(signed);
    return raw & ((@as(u32, 1) << bits) - 1);
}

pub fn patchBranchImmediate26(image: []u8, patch_offset: usize, byte_delta: i64) !void {
    var instruction = try readU32At(image, patch_offset);
    const imm26 = try encodeSignedImmediate(26, byte_delta, 2);
    instruction = (instruction & ~@as(u32, 0x03FF_FFFF)) | imm26;
    try writeU32At(image, patch_offset, instruction);
}

/// Patches the signed 19-bit displacement used by `b.<cond>`.
///
/// The low condition bits are part of the opcode and must stay intact; only the
/// displacement field in bits `[23:5]` is replaced.
pub fn patchConditionalBranchImmediate19(image: []u8, patch_offset: usize, byte_delta: i64) !void {
    var instruction = try readU32At(image, patch_offset);
    const imm19 = try encodeSignedImmediate(19, byte_delta, 2);
    instruction = (instruction & ~(@as(u32, 0x7FFFF) << 5)) | (imm19 << 5);
    try writeU32At(image, patch_offset, instruction);
}

/// Patches the signed 14-bit displacement used by `tbz` / `tbnz`.
///
/// The tested bit index and the `tbz`/`tbnz` opcode bit live outside the
/// displacement field, so we only replace bits `[18:5]`.
pub fn patchTestBranchImmediate14(image: []u8, patch_offset: usize, byte_delta: i64) !void {
    var instruction = try readU32At(image, patch_offset);
    const imm14 = try encodeSignedImmediate(14, byte_delta, 2);
    instruction = (instruction & ~(@as(u32, 0x3FFF) << 5)) | (imm14 << 5);
    try writeU32At(image, patch_offset, instruction);
}

pub fn patchAdrImmediate21(image: []u8, patch_offset: usize, byte_delta: i64) !void {
    var instruction = try readU32At(image, patch_offset);
    const raw = try encodeSignedImmediate(21, byte_delta, 0);
    instruction = (instruction & ~((@as(u32, 0x3) << 29) | (@as(u32, 0x7FFFF) << 5))) |
        ((raw & 0x3) << 29) |
        (((raw >> 2) & 0x7FFFF) << 5);
    try writeU32At(image, patch_offset, instruction);
}

pub fn patchAdrpImmediate21(
    image: []u8,
    patch_offset: usize,
    place_address: u64,
    target_address: u64,
) !void {
    // `ADRP` does *not* encode a raw byte delta.
    //
    // The instruction stores a signed 21-bit displacement in units of 4 KiB
    // pages, and the CPU implicitly appends the low twelve zero bits at
    // execution time. Feeding the encoder the raw byte delta between the two
    // page bases would therefore over-scale the relocation by another factor
    // of 4096 and produce completely bogus targets such as:
    //
    //   wanted page delta: 7 pages  -> target around +0x7000
    //   buggy encoded delta: 0x7000 -> CPU interprets as 0x7000 pages
    //                                 (= +0x0700_0000 bytes)
    //
    // The Mach-O RX/RW split runtime smoke surfaced this clearly because code
    // in the executable payload image referenced writable state in the
    // separate `__DATA` carrier segment.
    const target_page = target_address & ~@as(u64, 0xFFF);
    const place_page = place_address & ~@as(u64, 0xFFF);
    const page_delta = @as(i128, @intCast(target_page >> 12)) -
        @as(i128, @intCast(place_page >> 12));
    if (page_delta < std.math.minInt(i64) or page_delta > std.math.maxInt(i64)) {
        return error.PayloadRelocationOverflow;
    }
    try patchAdrImmediate21(image, patch_offset, @intCast(page_delta));
}

pub fn patchLiteralLoadImmediate19(image: []u8, patch_offset: usize, byte_delta: i64) !void {
    var instruction = try readU32At(image, patch_offset);
    const imm19 = try encodeSignedImmediate(19, byte_delta, 2);
    instruction = (instruction & ~(@as(u32, 0x7FFFF) << 5)) | (imm19 << 5);
    try writeU32At(image, patch_offset, instruction);
}

/// Patches the 16-bit immediate carried by `movz` / `movk` / `movn`.
///
/// For the supported unsigned absolute relocation family, the linker copies one
/// 16-bit slice of `target_address` into the instruction's imm16 field. The
/// checked variants (`MOVW_UABS_G0/G1/G2`) additionally require that no
/// non-zero bits exist above the addressed slice.
pub fn patchMoveWideImmediate16(
    image: []u8,
    patch_offset: usize,
    target_address: u64,
    shift: u6,
    check_upper_bits: bool,
) !void {
    if (shift % 16 != 0 or shift > 48) return error.UnsupportedPayloadRelocation;

    if (check_upper_bits and shift < 48) {
        if ((target_address >> (shift + 16)) != 0) return error.PayloadRelocationOverflow;
    }

    const imm16 = @as(u16, @intCast((target_address >> shift) & 0xFFFF));
    var instruction = try readU32At(image, patch_offset);
    instruction = (instruction & ~(@as(u32, 0xFFFF) << 5)) | (@as(u32, imm16) << 5);
    try writeU32At(image, patch_offset, instruction);
}

pub const MoveWideOpcode = enum(u2) {
    movn = 0,
    movz = 2,
    movk = 3,
};

pub fn patchMoveWideOpcode(instruction: u32, opcode: MoveWideOpcode) u32 {
    return (instruction & ~(@as(u32, 0x3) << 29)) |
        (@as(u32, @intFromEnum(opcode)) << 29);
}

/// Patches the signed move-wide relocation families used by
/// `MOVW_SABS_*` / `MOVW_PREL_*`.
///
/// These relocations differ from the unsigned absolute family in two ways:
/// - the source value is interpreted as a signed two's-complement number
/// - some slices must morph the instruction kind to `movn`, `movz`, or `movk`
///   according to the ABI-defined signed materialization sequence
pub fn patchMoveWideSignedImmediate16(
    image: []u8,
    patch_offset: usize,
    signed_value: i64,
    shift: u6,
    check_upper_bits: bool,
    opcode: MoveWideOpcode,
) !void {
    if (shift % 16 != 0 or shift > 48) return error.UnsupportedPayloadRelocation;

    if (check_upper_bits and shift < 48) {
        const upper = signed_value >> @intCast(shift + 16);
        if (upper != 0 and upper != -1) return error.PayloadRelocationOverflow;
    }

    const raw: u64 = @bitCast(signed_value);
    const slice: u16 = @intCast((raw >> shift) & 0xFFFF);
    const imm16: u16 = switch (opcode) {
        .movk, .movz => slice,
        .movn => ~slice,
    };

    var instruction = try readU32At(image, patch_offset);
    instruction = patchMoveWideOpcode(instruction, opcode);
    instruction = (instruction & ~(@as(u32, 0xFFFF) << 5)) | (@as(u32, imm16) << 5);
    try writeU32At(image, patch_offset, instruction);
}

/// Patches the shared 12-bit immediate field used by `add` and unsigned
/// load/store encodings.
///
/// `shift` is the scale of the addressed datum:
/// - 0 for byte operations / `add`
/// - 1 for 16-bit accesses
/// - 2 for 32-bit accesses
/// - 3 for 64-bit accesses
/// - 4 for 128-bit accesses
pub fn patchImmediateLo12(
    image: []u8,
    patch_offset: usize,
    target_address: u64,
    shift: u6,
) !void {
    if (shift != 0) {
        const alignment_mask = (@as(u64, 1) << shift) - 1;
        if ((target_address & alignment_mask) != 0) return error.UnalignedRelocationTarget;
    }

    const imm12 = (target_address & 0xFFF) >> shift;
    if (imm12 > 0xFFF) return error.PayloadRelocationOverflow;

    var instruction = try readU32At(image, patch_offset);
    instruction = (instruction & ~(@as(u32, 0xFFF) << 10)) | (@as(u32, @intCast(imm12)) << 10);
    try writeU32At(image, patch_offset, instruction);
}

/// Encodes the scaled unsigned offset form used by `LD64_GOTOFF_LO15`.
///
/// Unlike `patchImmediateLo12`, this relocation does not pair with a separate
/// page-base computation that accounts for the high address bits. The entire
/// base-relative delta must fit in the instruction's scaled 12-bit immediate.
pub fn patchUnsignedScaledOffset(
    image: []u8,
    patch_offset: usize,
    delta: i64,
    shift: u6,
) !void {
    if (delta < 0) return error.PayloadRelocationOverflow;
    const unsigned_delta: u64 = @intCast(delta);

    if (shift != 0) {
        const alignment_mask = (@as(u64, 1) << shift) - 1;
        if ((unsigned_delta & alignment_mask) != 0) return error.UnalignedRelocationTarget;
    }

    const imm12 = unsigned_delta >> shift;
    if (imm12 > 0xFFF) return error.PayloadRelocationOverflow;

    var instruction = try readU32At(image, patch_offset);
    instruction = (instruction & ~(@as(u32, 0xFFF) << 10)) | (@as(u32, @intCast(imm12)) << 10);
    try writeU32At(image, patch_offset, instruction);
}

pub fn elfTargetImage(target_image: ?image_backend.View) !?ElfView {
    if (target_image == null) return null;
    return switch (target_image.?) {
        .elf => |view| view,
        .macho => error.UnsupportedPayloadTargetImage,
    };
}

pub fn lookupTargetImageSymbolAddress(target_image: image_backend.View, symbol_name: []const u8) !u64 {
    return target_image.resolveSymbolAddress(symbol_name) catch |err| {
        if (symbol_name.len != 0 and symbol_name[0] == '_') {
            return target_image.resolveSymbolAddress(symbol_name[1..]);
        }
        return err;
    };
}

pub fn targetImageRequiresPieSafeRelocations(target_image: ?image_backend.View) bool {
    return switch (target_image orelse return false) {
        .elf => |view| view.ehdr.e_type == elf.ET.DYN,
        .macho => |view| view.isPie(),
    };
}

pub fn machoObjectString(strtab: []const u8, offset: u32) []const u8 {
    const start: usize = offset;
    if (start >= strtab.len) return "";
    const end_rel = std.mem.indexOfScalar(u8, strtab[start..], 0) orelse strtab.len - start;
    return strtab[start .. start + end_rel];
}

pub fn matchesUserSymbolName(symbol_name: []const u8, requested_name: []const u8) bool {
    if (std.mem.eql(u8, symbol_name, requested_name)) return true;
    if (symbol_name.len != 0 and symbol_name[0] == '_') {
        return std.mem.eql(u8, symbol_name[1..], requested_name);
    }
    return false;
}

pub fn parseFixedName(name: []const u8) []const u8 {
    const len = std.mem.indexOfScalar(u8, name, 0) orelse name.len;
    return name[0..len];
}

pub fn readU32At(image: []const u8, offset: usize) !u32 {
    if (offset + @sizeOf(u32) > image.len) return error.PayloadRelocationOutOfRange;
    const ptr: *const [4]u8 = @ptrCast(image[offset .. offset + 4].ptr);
    return std.mem.readInt(u32, ptr, .little);
}

pub fn readU64At(image: []const u8, offset: usize) !u64 {
    if (offset + @sizeOf(u64) > image.len) return error.PayloadRelocationOutOfRange;
    const ptr: *const [8]u8 = @ptrCast(image[offset .. offset + 8].ptr);
    return std.mem.readInt(u64, ptr, .little);
}

pub fn writeU32At(image: []u8, offset: usize, value: u32) !void {
    if (offset + @sizeOf(u32) > image.len) return error.PayloadRelocationOutOfRange;
    var le = std.mem.nativeToLittle(u32, value);
    @memcpy(image[offset .. offset + 4], std.mem.asBytes(&le));
}

pub fn writeU16At(image: []u8, offset: usize, value: u16) !void {
    if (offset + @sizeOf(u16) > image.len) return error.PayloadRelocationOutOfRange;
    var le = std.mem.nativeToLittle(u16, value);
    @memcpy(image[offset .. offset + 2], std.mem.asBytes(&le));
}

pub fn writeU64At(image: []u8, offset: usize, value: u64) !void {
    if (offset + @sizeOf(u64) > image.len) return error.PayloadRelocationOutOfRange;
    var le = std.mem.nativeToLittle(u64, value);
    @memcpy(image[offset .. offset + 8], std.mem.asBytes(&le));
}

pub fn writeI16At(image: []u8, offset: usize, value: i16) !void {
    if (offset + @sizeOf(i16) > image.len) return error.PayloadRelocationOutOfRange;
    var le = std.mem.nativeToLittle(i16, value);
    @memcpy(image[offset .. offset + 2], std.mem.asBytes(&le));
}

pub fn writeI32At(image: []u8, offset: usize, value: i32) !void {
    if (offset + @sizeOf(i32) > image.len) return error.PayloadRelocationOutOfRange;
    var le = std.mem.nativeToLittle(i32, value);
    @memcpy(image[offset .. offset + 4], std.mem.asBytes(&le));
}

pub fn writeI64At(image: []u8, offset: usize, value: i64) !void {
    if (offset + @sizeOf(i64) > image.len) return error.PayloadRelocationOutOfRange;
    var le = std.mem.nativeToLittle(i64, value);
    @memcpy(image[offset .. offset + 8], std.mem.asBytes(&le));
}

pub fn sliceStructs(comptime T: type, bytes: []u8, offset: usize, count: usize) []align(1) T {
    const byte_len = count * @sizeOf(T);
    return std.mem.bytesAsSlice(T, bytes[offset .. offset + byte_len]);
}

/// Read-only sibling of `sliceStructs`.
///
/// The Mach-O payload linker walks load commands, sections, symbols, and
/// relocation tables directly out of the original object bytes. Keeping this
/// helper local makes the zero-copy parsing style explicit and avoids sprinkling
/// the alignment-sensitive `bytesAsSlice` pattern throughout the linker.
pub fn sliceConstStructs(comptime T: type, bytes: []const u8, offset: usize, count: usize) []align(1) const T {
    const byte_len = count * @sizeOf(T);
    return std.mem.bytesAsSlice(T, bytes[offset .. offset + byte_len]);
}

test "signed move-wide patch can morph the low slice to MOVN" {
    var image = [_]u8{0} ** 4;
    try writeU32At(&image, 0, 0xD280_0000); // movz x0, #0

    try patchMoveWideSignedImmediate16(&image, 0, -4, 0, false, .movn);

    const opcode = try readU32At(&image, 0);
    try std.testing.expectEqual(@as(u32, 0x9280_0000), opcode & 0xFFC0_001F);
    try std.testing.expectEqual(@as(u16, 3), @as(u16, @intCast((opcode >> 5) & 0xFFFF)));
}

test "signed move-wide patch enforces checked signed slice ranges" {
    var image = [_]u8{0} ** 4;
    try writeU32At(&image, 0, 0xD280_0000); // movz x0, #0

    try std.testing.expectError(
        error.PayloadRelocationOverflow,
        patchMoveWideSignedImmediate16(&image, 0, 0x1_0000, 0, true, .movz),
    );
}
