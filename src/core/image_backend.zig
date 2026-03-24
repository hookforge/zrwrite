const std = @import("std");
const bundle = @import("bundle.zig");
const elf = std.elf;
const macho = std.macho;
const ElfView = @import("../format/elf/root.zig").View;
const MachOView = @import("../format/macho/root.zig").View;

pub const ExecutableRange = struct {
    address: u64,
    file_offset: usize,
    size: usize,
};

/// Uniform image view used by higher layers.
///
/// The immediate goal is not to implement Mach-O rewriting yet, but to stop
/// hard-wiring every caller to `ElfView`. Once this seam exists, the Mach-O
/// backend can grow behind the same address-mapping / symbol / executable-range
/// interface instead of forcing another large cross-cutting refactor later.
pub const View = union(enum) {
    elf: ElfView,
    macho: MachOView,

    pub fn parse(image_bytes: []u8) !View {
        if (isElf(image_bytes)) return .{ .elf = try ElfView.parse(image_bytes) };
        if (isMachO(image_bytes)) return .{ .macho = try MachOView.parse(image_bytes) };
        return error.UnsupportedBinaryFormat;
    }

    pub fn parseAs(image_bytes: []u8, binary_format: bundle.BinaryFormat) !View {
        return switch (binary_format) {
            .elf => .{ .elf = try ElfView.parse(image_bytes) },
            .macho => .{ .macho = try MachOView.parse(image_bytes) },
        };
    }

    pub fn binaryFormat(self: View) bundle.BinaryFormat {
        return switch (self) {
            .elf => .elf,
            .macho => .macho,
        };
    }

    pub fn bytes(self: View) []u8 {
        return switch (self) {
            .elf => |view| view.bytes,
            .macho => |view| view.bytes,
        };
    }

    pub fn addressToOffset(self: View, address: u64) !usize {
        return switch (self) {
            .elf => |view| view.addressToOffset(address),
            .macho => |view| view.addressToOffset(address),
        };
    }

    pub fn offsetToAddress(self: View, file_offset: u64) !u64 {
        return switch (self) {
            .elf => |view| view.offsetToAddress(file_offset),
            .macho => |view| view.offsetToAddress(file_offset),
        };
    }

    pub fn resolveSymbolAddress(self: View, name: []const u8) !u64 {
        return switch (self) {
            .elf => |view| view.resolveSymbolAddress(name),
            .macho => |view| view.resolveSymbolAddress(name),
        };
    }

    pub fn executableRanges(self: View, allocator: std.mem.Allocator) ![]ExecutableRange {
        return switch (self) {
            .elf => |view| executableRangesFromElf(allocator, view),
            .macho => |view| executableRangesFromMachO(allocator, view),
        };
    }

    pub fn hasAarch64BtiProperty(self: View) bool {
        return switch (self) {
            .elf => |view| view.hasAarch64BtiProperty(),
            .macho => |view| view.hasAarch64BtiProperty(),
        };
    }
};

fn executableRangesFromElf(allocator: std.mem.Allocator, view: ElfView) ![]ExecutableRange {
    var ranges: std.ArrayList(ExecutableRange) = .empty;
    defer ranges.deinit(allocator);

    for (view.phdrs) |phdr| {
        if (phdr.p_type != elf.PT_LOAD) continue;
        if ((phdr.p_flags & elf.PF_X) == 0) continue;
        if (phdr.p_filesz == 0) continue;

        try ranges.append(allocator, .{
            .address = phdr.p_vaddr,
            .file_offset = @intCast(phdr.p_offset),
            .size = @intCast(phdr.p_filesz),
        });
    }

    return ranges.toOwnedSlice(allocator);
}

fn executableRangesFromMachO(allocator: std.mem.Allocator, view: MachOView) ![]ExecutableRange {
    const macho_ranges = try view.executableRanges(allocator);
    defer allocator.free(macho_ranges);

    const ranges = try allocator.alloc(ExecutableRange, macho_ranges.len);
    errdefer allocator.free(ranges);

    for (macho_ranges, 0..) |range, index| {
        ranges[index] = .{
            .address = range.address,
            .file_offset = range.file_offset,
            .size = range.size,
        };
    }

    return ranges;
}

fn isElf(bytes: []const u8) bool {
    return bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\x7fELF");
}

fn isMachO(bytes: []const u8) bool {
    if (bytes.len < 4) return false;
    const magic = std.mem.readInt(u32, @ptrCast(bytes[0..4]), .little);
    return switch (magic) {
        macho.MH_MAGIC_64,
        macho.MH_CIGAM_64,
        macho.FAT_MAGIC,
        macho.FAT_CIGAM,
        macho.FAT_MAGIC_64,
        macho.FAT_CIGAM_64,
        => true,
        else => false,
    };
}

test "image backend autodetects ELF inputs" {
    var bytes = [_]u8{
        0x7f, 'E', 'L', 'F',
    } ++ [_]u8{0} ** (@sizeOf(std.elf.Elf64_Ehdr) - 4);
    bytes[4] = std.elf.ELFCLASS64;
    bytes[5] = std.elf.ELFDATA2LSB;

    const header: *align(1) std.elf.Elf64_Ehdr = @ptrCast(&bytes);
    header.e_machine = std.elf.EM.AARCH64;

    const view = try View.parse(bytes[0..]);
    try std.testing.expectEqual(bundle.BinaryFormat.elf, view.binaryFormat());
}

test "image backend detects Mach-O magic and dispatches to Mach-O parsing" {
    var bytes = [_]u8{0} ** @sizeOf(macho.mach_header_64);
    std.mem.writeInt(u32, @ptrCast(bytes[0..4]), macho.MH_MAGIC_64, .little);

    const header: *align(1) macho.mach_header_64 = @ptrCast(&bytes);
    header.cputype = macho.CPU_TYPE_ARM64;

    // The backend should now reach the real Mach-O parser. This synthetic
    // header is intentionally incomplete, so the parse fails on structural
    // validation rather than falling back to "format not implemented".
    try std.testing.expectError(error.UnsupportedMachOFileType, View.parse(bytes[0..]));
}
