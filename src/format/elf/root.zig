const std = @import("std");
const elf = std.elf;

pub const View = struct {
    bytes: []u8,
    ehdr: *align(1) elf.Elf64_Ehdr,
    phdrs: []align(1) elf.Elf64_Phdr,
    shdrs: []align(1) elf.Elf64_Shdr,

    pub fn parse(bytes: []u8) !View {
        if (bytes.len < @sizeOf(elf.Elf64_Ehdr)) return error.InvalidElf;

        const ehdr = std.mem.bytesAsValue(elf.Elf64_Ehdr, bytes[0..@sizeOf(elf.Elf64_Ehdr)]);
        if (!std.mem.eql(u8, ehdr.e_ident[0..4], "\x7FELF")) return error.InvalidElfMagic;
        if (ehdr.e_ident[elf.EI_CLASS] != elf.ELFCLASS64) return error.UnsupportedElfClass;
        if (ehdr.e_ident[elf.EI_DATA] != elf.ELFDATA2LSB) return error.UnsupportedEndianness;
        if (ehdr.e_machine != elf.EM.AARCH64) return error.UnsupportedMachine;

        const phdrs = if (ehdr.e_phoff == 0 or ehdr.e_phnum == 0)
            std.mem.bytesAsSlice(elf.Elf64_Phdr, bytes[0..0])
        else
            sliceStructs(elf.Elf64_Phdr, bytes, @intCast(ehdr.e_phoff), ehdr.e_phnum);

        const shdrs = if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0)
            std.mem.bytesAsSlice(elf.Elf64_Shdr, bytes[0..0])
        else
            sliceStructs(elf.Elf64_Shdr, bytes, @intCast(ehdr.e_shoff), ehdr.e_shnum);

        return .{
            .bytes = bytes,
            .ehdr = ehdr,
            .phdrs = phdrs,
            .shdrs = shdrs,
        };
    }

    pub fn addressToOffset(self: View, address: u64) !usize {
        for (self.phdrs) |phdr| {
            if (phdr.p_type != elf.PT_LOAD) continue;
            const seg_start = phdr.p_vaddr;
            const seg_end = phdr.p_vaddr + phdr.p_filesz;
            if (address >= seg_start and address < seg_end) {
                return @intCast(phdr.p_offset + (address - seg_start));
            }
        }
        return error.AddressNotMapped;
    }

    pub fn offsetToAddress(self: View, file_offset: u64) !u64 {
        for (self.phdrs) |phdr| {
            if (phdr.p_type != elf.PT_LOAD) continue;
            const seg_start = phdr.p_offset;
            const seg_end = phdr.p_offset + phdr.p_filesz;
            if (file_offset >= seg_start and file_offset < seg_end) {
                return phdr.p_vaddr + (file_offset - seg_start);
            }
        }
        return error.OffsetNotMapped;
    }

    pub fn resolveSymbolAddress(self: View, name: []const u8) !u64 {
        var fallback: ?u64 = null;

        for (self.shdrs, 0..) |shdr, index| {
            if (shdr.sh_type != elf.SHT_SYMTAB and shdr.sh_type != elf.SHT_DYNSYM) continue;
            const symbols = sliceStructs(elf.Elf64_Sym, self.bytes, @intCast(shdr.sh_offset), @intCast(shdr.sh_size / shdr.sh_entsize));
            const strtab = self.sectionData(shdr.sh_link);

            for (symbols) |symbol| {
                if (symbol.st_name == 0 or symbol.st_shndx == elf.SHN_UNDEF) continue;
                const symbol_name = getString(strtab, symbol.st_name);
                if (!std.mem.eql(u8, symbol_name, name)) continue;

                if (index < self.shdrs.len and self.shdrs[index].sh_type == elf.SHT_SYMTAB) {
                    return symbol.st_value;
                }
                fallback = symbol.st_value;
            }
        }

        return fallback orelse error.SymbolNotFound;
    }

    pub fn sectionData(self: View, section_index: usize) []u8 {
        const shdr = self.shdrs[section_index];
        const start: usize = @intCast(shdr.sh_offset);
        const end: usize = @intCast(shdr.sh_offset + shdr.sh_size);
        return self.bytes[start..end];
    }

    pub fn lastLoadSegmentIndex(self: View) !usize {
        var result: ?usize = null;
        var best_end: u64 = 0;
        for (self.phdrs, 0..) |phdr, index| {
            if (phdr.p_type != elf.PT_LOAD) continue;
            const file_end = phdr.p_offset + phdr.p_filesz;
            if (result == null or file_end > best_end) {
                result = index;
                best_end = file_end;
            }
        }
        return result orelse error.NoLoadSegment;
    }
};

fn sliceStructs(comptime T: type, bytes: []u8, offset: usize, count: usize) []align(1) T {
    const byte_len = count * @sizeOf(T);
    return std.mem.bytesAsSlice(T, bytes[offset .. offset + byte_len]);
}

pub fn getString(strtab: []const u8, offset: u32) []const u8 {
    const start: usize = @intCast(offset);
    const end_rel = std.mem.indexOfScalar(u8, strtab[start..], 0) orelse strtab.len - start;
    return strtab[start .. start + end_rel];
}
