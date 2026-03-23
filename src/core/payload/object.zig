const std = @import("std");
const elf = std.elf;
const ElfView = @import("../../format/elf/root.zig").View;
const getString = @import("../../format/elf/root.zig").getString;

pub const LoadedPayload = struct {
    text: []u8,
    entry_offset: usize,
};

/// V1 payload support is intentionally narrow:
/// - one ET_REL object
/// - executable `.text` only
/// - no `.rela.text`
/// - no undefined external symbols
pub fn loadTextOnlyObject(allocator: std.mem.Allocator, object_path: []const u8, handler_symbol: []const u8) !LoadedPayload {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, object_path, std.math.maxInt(usize));
    defer allocator.free(bytes);
    return loadTextOnlyObjectBytes(allocator, bytes, handler_symbol);
}

pub fn loadTextOnlyObjectBytes(allocator: std.mem.Allocator, object_bytes: []const u8, handler_symbol: []const u8) !LoadedPayload {
    const owned_bytes = try allocator.dupe(u8, object_bytes);
    defer allocator.free(owned_bytes);

    const view = try ElfView.parse(owned_bytes);
    if (view.ehdr.e_type != elf.ET.REL) return error.UnsupportedPayloadType;

    const text_index = findTextSection(view) orelse return error.PayloadMissingText;
    try rejectTextRelocations(view, text_index);

    const text = try allocator.dupe(u8, view.sectionData(text_index));
    errdefer allocator.free(text);

    const entry_offset = try resolveSectionRelativeSymbol(view, handler_symbol, text_index);

    return .{
        .text = text,
        .entry_offset = entry_offset,
    };
}

fn findTextSection(view: ElfView) ?usize {
    for (view.shdrs, 0..) |shdr, index| {
        const is_alloc = (shdr.sh_flags & elf.SHF_ALLOC) != 0;
        const is_exec = (shdr.sh_flags & elf.SHF_EXECINSTR) != 0;
        if (is_alloc and is_exec and shdr.sh_type == elf.SHT_PROGBITS) return index;
    }
    return null;
}

fn rejectTextRelocations(view: ElfView, text_index: usize) !void {
    for (view.shdrs) |shdr| {
        if (shdr.sh_info != text_index) continue;
        if ((shdr.sh_type == elf.SHT_RELA or shdr.sh_type == elf.SHT_REL) and shdr.sh_size != 0) {
            return error.UnsupportedPayloadRelocation;
        }
    }
}

fn resolveSectionRelativeSymbol(view: ElfView, name: []const u8, section_index: usize) !usize {
    for (view.shdrs) |shdr| {
        if (shdr.sh_type != elf.SHT_SYMTAB) continue;
        const symbols = std.mem.bytesAsSlice(
            elf.Elf64_Sym,
            sectionDataByHeader(view, shdr),
        );
        const strtab = view.sectionData(shdr.sh_link);

        for (symbols) |symbol| {
            if (symbol.st_name == 0) continue;
            if (symbol.st_shndx != section_index) continue;
            const symbol_name = getString(strtab, symbol.st_name);
            if (!std.mem.eql(u8, symbol_name, name)) continue;
            return @intCast(symbol.st_value);
        }
    }
    return error.PayloadSymbolNotFound;
}

fn sectionDataByHeader(view: ElfView, shdr: elf.Elf64_Shdr) []u8 {
    const start: usize = @intCast(shdr.sh_offset);
    const end: usize = @intCast(shdr.sh_offset + shdr.sh_size);
    return view.bytes[start..end];
}
