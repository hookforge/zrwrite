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

    /// Returns `true` when the ELF appears to opt into Linux/AArch64 BTI.
    ///
    /// The parser intentionally stays conservative:
    /// - first prefer the standardized GNU property note
    /// - if the final linked image dropped that note, fall back to detecting
    ///   emitted BTI instructions in executable segments
    ///
    /// The fallback is heuristic, but it is still a net win for static patch
    /// compatibility because emitting BTI-compatible injected entrypoints is
    /// harmless on non-enforcing kernels while missing them can break indirect
    /// branches on enforcing ones.
    pub fn hasAarch64BtiProperty(self: View) bool {
        for (self.shdrs, 0..) |shdr, index| {
            if (shdr.sh_type != elf.SHT_NOTE) continue;
            if (noteSectionHasAarch64Bti(self.sectionData(index))) return true;
        }
        return executableSegmentsContainBtiInstruction(self);
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

const nt_gnu_property_type_0: u32 = 5;
const gnu_property_aarch64_feature_1_and: u32 = 0xC000_0000;
const gnu_property_aarch64_feature_1_bti: u32 = 1 << 0;
const bti_c_instruction: u32 = 0xD503_245F;
const bti_j_instruction: u32 = 0xD503_249F;
const bti_jc_instruction: u32 = 0xD503_24DF;

fn noteSectionHasAarch64Bti(note_bytes: []const u8) bool {
    var cursor: usize = 0;
    while (cursor + 12 <= note_bytes.len) {
        const name_size = readLeU32(note_bytes[cursor..][0..4]);
        const desc_size = readLeU32(note_bytes[cursor..][4..8]);
        const note_type = readLeU32(note_bytes[cursor..][8..12]);
        cursor += 12;

        const aligned_name_size = std.mem.alignForward(usize, name_size, 4);
        const aligned_desc_size = std.mem.alignForward(usize, desc_size, 4);
        if (cursor + aligned_name_size + aligned_desc_size > note_bytes.len) return false;

        const name = note_bytes[cursor .. cursor + name_size];
        cursor += aligned_name_size;
        const desc = note_bytes[cursor .. cursor + desc_size];
        cursor += aligned_desc_size;

        if (note_type != nt_gnu_property_type_0) continue;
        if (name.len < 3 or !std.mem.eql(u8, name[0..3], "GNU")) continue;
        if (gnuPropertyDescHasAarch64Bti(desc)) return true;
    }
    return false;
}

fn gnuPropertyDescHasAarch64Bti(desc: []const u8) bool {
    var cursor: usize = 0;
    while (cursor + 8 <= desc.len) {
        const property_type = readLeU32(desc[cursor..][0..4]);
        const data_size = readLeU32(desc[cursor..][4..8]);
        cursor += 8;

        const aligned_data_size = std.mem.alignForward(usize, data_size, 8);
        if (cursor + aligned_data_size > desc.len) return false;

        if (property_type == gnu_property_aarch64_feature_1_and and data_size >= 4) {
            const feature_bits = readLeU32(desc[cursor..][0..4]);
            if ((feature_bits & gnu_property_aarch64_feature_1_bti) != 0) return true;
        }
        cursor += aligned_data_size;
    }
    return false;
}

fn executableSegmentsContainBtiInstruction(view: View) bool {
    for (view.phdrs) |phdr| {
        if (phdr.p_type != elf.PT_LOAD) continue;
        if ((phdr.p_flags & elf.PF_X) == 0) continue;

        const file_start: usize = @intCast(phdr.p_offset);
        const file_end: usize = @intCast(phdr.p_offset + phdr.p_filesz);
        var file_offset = file_start;
        while (file_offset + 4 <= file_end) : (file_offset += 4) {
            const opcode = readLeU32(view.bytes[file_offset .. file_offset + 4]);
            if (opcode == bti_c_instruction or opcode == bti_j_instruction or opcode == bti_jc_instruction) {
                return true;
            }
        }
    }
    return false;
}

fn readLeU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, @ptrCast(bytes[0..4]), .little);
}
