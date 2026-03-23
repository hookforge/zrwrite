const std = @import("std");
const elf = std.elf;
const ElfView = @import("../../format/elf/root.zig").View;
const getString = @import("../../format/elf/root.zig").getString;

const link_diagnostic_capacity = 1024;
threadlocal var last_link_diagnostic_buf: [link_diagnostic_capacity]u8 = undefined;
threadlocal var last_link_diagnostic_len: usize = 0;

pub const PayloadLayout = struct {
    image_size: usize,
    entry_offset: usize,
};

pub const LoadedPayload = struct {
    image: []u8,
    entry_offset: usize,
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

const OutputSection = struct {
    input_index: usize,
    output_offset: usize,
    size: usize,
    alignment: usize,
};

/// Key that identifies one synthetic GOT slot inside the injected payload.
///
/// AArch64 GOT relocations do not point at the final symbol directly. They
/// point at a pointer cell whose contents are the final absolute symbol
/// address. We therefore need a stable key that survives from the layout pass
/// into the final relocation pass.
const GotSlotKey = struct {
    symtab_section_index: usize,
    symbol_index: u32,
    addend: i64,
};

/// One synthetic GOT entry materialized inside the injected payload image.
///
/// `output_offset` is the byte offset of the 8-byte slot within the final
/// payload image. The slot contents are written during linking once the target
/// image and payload base address are known.
///
/// Important limitation:
/// - the current mini-linker materializes each slot as one final absolute
///   pointer value
/// - that is acceptable for ET_EXEC targets, where link-time VAs are also the
///   runtime VAs
/// - it is not acceptable for ET_DYN / PIE targets, where every absolute
///   pointer cell would need an extra rebasing story at runtime
const GotSlot = struct {
    key: GotSlotKey,
    output_offset: usize,
};

const PreparedObject = struct {
    allocator: std.mem.Allocator,
    section_map: []?usize,
    output_sections: []OutputSection,
    got_slots: []GotSlot,
    entry_offset: usize,
    image_size: usize,

    fn deinit(self: *PreparedObject) void {
        self.allocator.free(self.got_slots);
        self.allocator.free(self.output_sections);
        self.allocator.free(self.section_map);
        self.* = undefined;
    }
};

/// Analyzes a relocatable AArch64 ELF object and computes the size/layout of
/// the injected payload image without applying relocations yet.
///
/// This is the first half of the mini-linker pipeline:
/// - keep every loadable payload section that should become part of the
///   injected image (`.text`, `.rodata*`, `.data*`, `.bss*`)
/// - reject unsupported alloc sections such as TLS
/// - assign final in-image offsets while preserving each section's alignment
/// - resolve the handler symbol to its future section-relative entry offset
pub fn analyzeObject(
    allocator: std.mem.Allocator,
    object_path: []const u8,
    handler_symbol: []const u8,
) !PayloadLayout {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, object_path, std.math.maxInt(usize));
    defer allocator.free(bytes);
    return analyzeObjectBytes(allocator, bytes, handler_symbol);
}

/// In-memory variant of `analyzeObject`.
pub fn analyzeObjectBytes(
    allocator: std.mem.Allocator,
    object_bytes: []const u8,
    handler_symbol: []const u8,
) !PayloadLayout {
    clearLastLinkDiagnostic();
    const mutable_bytes = @constCast(object_bytes);
    const view = try ElfView.parse(mutable_bytes);
    var prepared = try prepareObjectLayout(allocator, view, handler_symbol);
    defer prepared.deinit();

    return .{
        .image_size = prepared.image_size,
        .entry_offset = prepared.entry_offset,
    };
}

/// Loads, lays out, and relocates a real AArch64 ET_REL payload object.
///
/// The resulting `LoadedPayload.image` is the final injected blob that the
/// rewriter copies into the target binary. All supported relocations are
/// resolved against:
/// - the payload image base address (`image_base_address`)
/// - the payload's own loadable sections
/// - optionally, symbols exported by the target ELF image
pub fn linkObject(
    allocator: std.mem.Allocator,
    object_path: []const u8,
    handler_symbol: []const u8,
    image_base_address: u64,
    target_image: ?ElfView,
) !LoadedPayload {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, object_path, std.math.maxInt(usize));
    defer allocator.free(bytes);
    return linkObjectBytes(allocator, bytes, handler_symbol, image_base_address, target_image);
}

/// In-memory variant of `linkObject`.
pub fn linkObjectBytes(
    allocator: std.mem.Allocator,
    object_bytes: []const u8,
    handler_symbol: []const u8,
    image_base_address: u64,
    target_image: ?ElfView,
) !LoadedPayload {
    clearLastLinkDiagnostic();
    const mutable_bytes = @constCast(object_bytes);
    const view = try ElfView.parse(mutable_bytes);
    var prepared = try prepareObjectLayout(allocator, view, handler_symbol);
    defer prepared.deinit();

    const image = try allocator.alloc(u8, prepared.image_size);
    errdefer allocator.free(image);
    @memset(image, 0);

    try copyAllocatedSections(image, view, prepared.output_sections);
    try initializeGotSlots(image, view, prepared, image_base_address, target_image);
    try applyRelocations(image, view, prepared, image_base_address, target_image);

    return .{
        .image = image,
        .entry_offset = prepared.entry_offset,
    };
}

/// Legacy compatibility helper retained for older callers.
///
/// This now links the object at base address zero without any external symbol
/// resolution. It remains useful for self-contained payloads and tests, but the
/// rewriter should prefer `analyzeObjectBytes` + `linkObjectBytes`.
pub fn loadTextOnlyObject(
    allocator: std.mem.Allocator,
    object_path: []const u8,
    handler_symbol: []const u8,
) !LoadedPayload {
    return linkObject(allocator, object_path, handler_symbol, 0, null);
}

/// Legacy compatibility helper retained for older callers.
pub fn loadTextOnlyObjectBytes(
    allocator: std.mem.Allocator,
    object_bytes: []const u8,
    handler_symbol: []const u8,
) !LoadedPayload {
    return linkObjectBytes(allocator, object_bytes, handler_symbol, 0, null);
}

fn prepareObjectLayout(
    allocator: std.mem.Allocator,
    view: ElfView,
    handler_symbol: []const u8,
) !PreparedObject {
    if (view.ehdr.e_type != elf.ET.REL) return error.UnsupportedPayloadType;

    const shstrtab = try sectionStringTable(view);

    const section_map = try allocator.alloc(?usize, view.shdrs.len);
    errdefer allocator.free(section_map);
    for (section_map) |*slot| slot.* = null;

    var output_sections = std.array_list.Managed(OutputSection).init(allocator);
    defer output_sections.deinit();
    var got_slots = std.array_list.Managed(GotSlot).init(allocator);
    defer got_slots.deinit();

    var cursor: usize = 0;
    for (view.shdrs, 0..) |shdr, section_index| {
        const section_name = getString(shstrtab, shdr.sh_name);
        const should_keep = try shouldKeepAllocatedSection(section_name, shdr);
        if (!should_keep) continue;

        const alignment = sectionAlignment(shdr.sh_addralign);
        cursor = std.mem.alignForward(usize, cursor, alignment);
        section_map[section_index] = output_sections.items.len;
        try output_sections.append(.{
            .input_index = section_index,
            .output_offset = cursor,
            .size = @intCast(shdr.sh_size),
            .alignment = alignment,
        });
        cursor += @intCast(shdr.sh_size);
    }

    if (output_sections.items.len == 0) return error.PayloadMissingAllocSections;

    try collectGotSlots(&got_slots, view, section_map);
    if (got_slots.items.len != 0) {
        cursor = std.mem.alignForward(usize, cursor, @alignOf(u64));
        for (got_slots.items) |*slot| {
            slot.output_offset = cursor;
            cursor += @sizeOf(u64);
        }
    }

    const entry_offset = try resolveEntryOffset(view, section_map, output_sections.items, handler_symbol);

    return .{
        .allocator = allocator,
        .section_map = section_map,
        .output_sections = try output_sections.toOwnedSlice(),
        .got_slots = try got_slots.toOwnedSlice(),
        .entry_offset = entry_offset,
        .image_size = cursor,
    };
}

fn sectionStringTable(view: ElfView) ![]const u8 {
    const shstr_index: usize = @intCast(view.ehdr.e_shstrndx);
    if (shstr_index >= view.shdrs.len) return error.InvalidPayloadSectionTable;
    return view.sectionData(shstr_index);
}

fn shouldKeepAllocatedSection(section_name: []const u8, shdr: elf.Elf64_Shdr) !bool {
    if ((shdr.sh_flags & elf.SHF_ALLOC) == 0) return false;
    if ((shdr.sh_flags & elf.SHF_TLS) != 0) return error.UnsupportedPayloadTlsSection;

    // Unwind metadata is intentionally out of scope for the current static
    // patcher. Keeping `.eh_frame` would require a second layer of runtime and
    // image integration that v1 explicitly does not promise yet.
    if (std.mem.eql(u8, section_name, ".eh_frame") or std.mem.eql(u8, section_name, ".eh_frame_hdr")) {
        return false;
    }

    return switch (shdr.sh_type) {
        elf.SHT_PROGBITS, elf.SHT_NOBITS => true,
        else => error.UnsupportedPayloadSectionType,
    };
}

fn sectionAlignment(raw_alignment: u64) usize {
    if (raw_alignment == 0) return 1;
    return @intCast(raw_alignment);
}

fn resolveEntryOffset(
    view: ElfView,
    section_map: []const ?usize,
    output_sections: []const OutputSection,
    handler_symbol: []const u8,
) !usize {
    for (view.shdrs, 0..) |shdr, symtab_section_index| {
        _ = symtab_section_index;
        if (shdr.sh_type != elf.SHT_SYMTAB and shdr.sh_type != elf.SHT_DYNSYM) continue;

        const symbols = try symbolTable(view, shdr);
        const strtab = try linkedStringTable(view, shdr);

        for (symbols) |symbol| {
            if (symbol.st_name == 0 or symbol.st_shndx == elf.SHN_UNDEF) continue;
            const symbol_name = getString(strtab, symbol.st_name);
            if (!std.mem.eql(u8, symbol_name, handler_symbol)) continue;

            const section_index: usize = @intCast(symbol.st_shndx);
            if (section_index >= section_map.len) return error.InvalidPayloadSymbolSection;
            const mapped_index = section_map[section_index] orelse return error.PayloadEntryInUnsupportedSection;
            const output_section = output_sections[mapped_index];
            const symbol_offset: usize = @intCast(symbol.st_value);
            if (symbol_offset > output_section.size) return error.PayloadSymbolOutOfRange;
            return output_section.output_offset + symbol_offset;
        }
    }

    return error.PayloadSymbolNotFound;
}

fn symbolTable(view: ElfView, shdr: elf.Elf64_Shdr) ![]align(1) elf.Elf64_Sym {
    if (shdr.sh_entsize != @sizeOf(elf.Elf64_Sym)) return error.InvalidPayloadSymbolTable;
    return sliceStructs(
        elf.Elf64_Sym,
        view.bytes,
        @intCast(shdr.sh_offset),
        @intCast(shdr.sh_size / shdr.sh_entsize),
    );
}

fn linkedStringTable(view: ElfView, shdr: elf.Elf64_Shdr) ![]const u8 {
    const strtab_index: usize = @intCast(shdr.sh_link);
    if (strtab_index >= view.shdrs.len) return error.InvalidPayloadStringTable;
    return view.sectionData(strtab_index);
}

fn copyAllocatedSections(image: []u8, view: ElfView, output_sections: []const OutputSection) !void {
    for (output_sections) |output_section| {
        const shdr = view.shdrs[output_section.input_index];
        const dest = image[output_section.output_offset .. output_section.output_offset + output_section.size];

        if (shdr.sh_type == elf.SHT_NOBITS) {
            @memset(dest, 0);
            continue;
        }

        const source = view.sectionData(output_section.input_index);
        if (source.len != dest.len) return error.InvalidPayloadSectionSize;
        @memcpy(dest, source);
    }
}

/// Scans relocations that target kept alloc sections and records which AArch64
/// GOT-style references need a synthetic slot in the injected image.
///
/// We deduplicate by `(symtab section, symbol index, addend)` because the same
/// object may reference one symbol from multiple relocation sites, while
/// distinct addends must still receive distinct pointer-cell contents.
fn collectGotSlots(
    got_slots: *std.array_list.Managed(GotSlot),
    view: ElfView,
    section_map: []const ?usize,
) !void {
    for (view.shdrs) |shdr| {
        if (shdr.sh_type != elf.SHT_RELA and shdr.sh_type != elf.SHT_REL) continue;

        const target_section_index: usize = @intCast(shdr.sh_info);
        if (target_section_index >= section_map.len) return error.InvalidPayloadRelocationTarget;
        if (section_map[target_section_index] == null) continue;

        if (shdr.sh_size == 0) continue;
        if (shdr.sh_type != elf.SHT_RELA) return error.UnsupportedPayloadRelocationFormat;
        if (shdr.sh_entsize != @sizeOf(elf.Elf64_Rela)) return error.InvalidPayloadRelocationTable;

        const relas = sliceStructs(
            elf.Elf64_Rela,
            view.bytes,
            @intCast(shdr.sh_offset),
            @intCast(shdr.sh_size / shdr.sh_entsize),
        );
        const symtab_section_index: usize = @intCast(shdr.sh_link);
        if (symtab_section_index >= view.shdrs.len) return error.InvalidPayloadRelocationSymtab;

        for (relas) |rela| {
            switch (rela.r_type()) {
                @intFromEnum(elf.R_AARCH64.ADR_GOT_PAGE),
                @intFromEnum(elf.R_AARCH64.LD64_GOT_LO12_NC),
                => {
                    if (findGotSlotIndex(got_slots.items, symtab_section_index, rela.r_sym(), rela.r_addend) != null) {
                        continue;
                    }

                    try got_slots.append(.{
                        .key = .{
                            .symtab_section_index = symtab_section_index,
                            .symbol_index = rela.r_sym(),
                            .addend = rela.r_addend,
                        },
                        .output_offset = 0,
                    });
                },
                else => {},
            }
        }
    }
}

/// Materializes the contents of every synthetic GOT slot.
///
/// Each slot stores the fully resolved absolute address `(S + A)`. The
/// relocation handlers then patch `adrp/ldr` pairs to point at the slot rather
/// than at the final symbol directly, matching the code shape emitted by Zig
/// for `extern var` references.
fn initializeGotSlots(
    image: []u8,
    view: ElfView,
    prepared: PreparedObject,
    image_base_address: u64,
    target_image: ?ElfView,
) !void {
    if (targetImageRequiresPieSafeRelocations(target_image) and prepared.got_slots.len != 0) {
        try noteEtDynGotSlotFailure(view, prepared.got_slots[0]);
        return error.UnsupportedPayloadRelocation;
    }

    for (prepared.got_slots) |slot| {
        if (slot.key.symtab_section_index >= view.shdrs.len) return error.InvalidPayloadRelocationSymtab;
        const symtab_shdr = view.shdrs[slot.key.symtab_section_index];
        const symbols = try symbolTable(view, symtab_shdr);
        const strtab = try linkedStringTable(view, symtab_shdr);
        const symbol_address = try resolveRelocationSymbolAddress(
            prepared.section_map,
            prepared.output_sections,
            symbols,
            strtab,
            slot.key.symbol_index,
            image_base_address,
            target_image,
        );
        const slot_value = try absoluteAddressWithAddend(symbol_address, slot.key.addend);
        try writeU64At(image, slot.output_offset, slot_value);
    }
}

/// Applies supported AArch64 relocations into the already laid-out payload
/// image.
///
/// The implementation deliberately works in terms of the final injected
/// payload-address space instead of the original object section-address space.
/// That keeps the formulas close to the ELF ABI definitions:
/// - `S` = resolved symbol address
/// - `A` = relocation addend
/// - `P` = place address inside the injected image
fn applyRelocations(
    image: []u8,
    view: ElfView,
    prepared: PreparedObject,
    image_base_address: u64,
    target_image: ?ElfView,
) !void {
    const shstrtab = try sectionStringTable(view);

    for (view.shdrs) |shdr| {
        if (shdr.sh_type != elf.SHT_RELA and shdr.sh_type != elf.SHT_REL) continue;

        const target_section_index: usize = @intCast(shdr.sh_info);
        if (target_section_index >= prepared.section_map.len) return error.InvalidPayloadRelocationTarget;
        const mapped_target = prepared.section_map[target_section_index] orelse continue;

        if (shdr.sh_size == 0) continue;
        if (shdr.sh_type != elf.SHT_RELA) return error.UnsupportedPayloadRelocationFormat;
        if (shdr.sh_entsize != @sizeOf(elf.Elf64_Rela)) return error.InvalidPayloadRelocationTable;

        const relas = sliceStructs(
            elf.Elf64_Rela,
            view.bytes,
            @intCast(shdr.sh_offset),
            @intCast(shdr.sh_size / shdr.sh_entsize),
        );

        const symtab_index: usize = @intCast(shdr.sh_link);
        if (symtab_index >= view.shdrs.len) return error.InvalidPayloadRelocationSymtab;
        const symtab_shdr = view.shdrs[symtab_index];
        const symbols = try symbolTable(view, symtab_shdr);
        const strtab = try linkedStringTable(view, symtab_shdr);
        const target_output_section = prepared.output_sections[mapped_target];
        const target_section_name = getString(shstrtab, view.shdrs[target_section_index].sh_name);

        for (relas) |rela| {
            const patch_offset = try patchOffset(target_output_section, rela);
            try ensureRelocationIsSupportedForTargetImage(
                view,
                shstrtab,
                symbols,
                strtab,
                rela,
                target_section_name,
                target_image,
            );
            const symbol_address = resolveRelocationSymbolAddress(
                prepared.section_map,
                prepared.output_sections,
                symbols,
                strtab,
                rela.r_sym(),
                image_base_address,
                target_image,
            ) catch |err| {
                noteRelocationFailure(view, shstrtab, symbols, strtab, rela, target_section_name, err);
                return err;
            };
            const operands = try relocationOperands(
                prepared.got_slots,
                symtab_index,
                rela,
                image_base_address,
                symbol_address,
            );
            const place_address = try addAddressOffset(image_base_address, patch_offset);
            applyAarch64Relocation(
                image,
                patch_offset,
                place_address,
                operands.symbol_address,
                operands.addend,
                rela.r_type(),
            ) catch |err| {
                noteRelocationFailure(view, shstrtab, symbols, strtab, rela, target_section_name, err);
                return err;
            };
        }
    }
}

fn patchOffset(target_output_section: OutputSection, rela: elf.Elf64_Rela) !usize {
    const section_relative_offset: usize = @intCast(rela.r_offset);
    if (section_relative_offset > target_output_section.size) return error.InvalidPayloadRelocationOffset;
    return target_output_section.output_offset + section_relative_offset;
}

fn resolveRelocationSymbolAddress(
    section_map: []const ?usize,
    output_sections: []const OutputSection,
    symbols: []align(1) const elf.Elf64_Sym,
    strtab: []const u8,
    symbol_index: u32,
    image_base_address: u64,
    target_image: ?ElfView,
) !u64 {
    if (symbol_index >= symbols.len) return error.InvalidPayloadSymbolIndex;
    const symbol = symbols[symbol_index];

    switch (symbol.st_shndx) {
        elf.SHN_UNDEF => {
            if (symbol.st_bind() == elf.STB_WEAK) {
                const weak_name = if (symbol.st_name == 0) "" else getString(strtab, symbol.st_name);
                if (weak_name.len == 0 or target_image == null) return 0;
                return target_image.?.resolveSymbolAddress(weak_name) catch 0;
            }

            if (target_image == null or symbol.st_name == 0) return error.UnsupportedPayloadExternalSymbol;
            return target_image.?.resolveSymbolAddress(getString(strtab, symbol.st_name));
        },
        elf.SHN_ABS => return symbol.st_value,
        elf.SHN_COMMON => return error.UnsupportedPayloadCommonSymbol,
        else => {
            const section_index: usize = @intCast(symbol.st_shndx);
            if (section_index >= section_map.len) return error.InvalidPayloadSymbolSection;
            const mapped_index = section_map[section_index] orelse return error.SymbolTargetsDroppedSection;
            const output_section = output_sections[mapped_index];
            const symbol_offset: usize = @intCast(symbol.st_value);
            if (symbol_offset > output_section.size) return error.PayloadSymbolOutOfRange;
            return addAddressOffset(image_base_address, output_section.output_offset + symbol_offset);
        },
    }
}

fn noteRelocationFailure(
    view: ElfView,
    shstrtab: []const u8,
    symbols: []align(1) const elf.Elf64_Sym,
    strtab: []const u8,
    rela: elf.Elf64_Rela,
    target_section_name: []const u8,
    err: anyerror,
) void {
    switch (err) {
        error.UnsupportedPayloadRelocation => {
            const symbol_name = relocationSymbolName(view, shstrtab, symbols, strtab, rela.r_sym());
            recordLinkDiagnostic(
                "unsupported AArch64 payload relocation {s} for symbol {s} in section {s} (addend={d}, patch_offset=0x{x})",
                .{
                    relocationNameString(rela.r_type()),
                    symbol_name,
                    target_section_name,
                    rela.r_addend,
                    rela.r_offset,
                },
            );
        },
        error.UnsupportedPayloadExternalSymbol, error.SymbolNotFound => {
            const symbol_name = relocationSymbolName(view, shstrtab, symbols, strtab, rela.r_sym());
            recordLinkDiagnostic(
                "unable to resolve payload external symbol {s} for relocation {s} in section {s}",
                .{
                    symbol_name,
                    relocationNameString(rela.r_type()),
                    target_section_name,
                },
            );
        },
        else => {},
    }
}

fn relocationSymbolName(
    view: ElfView,
    shstrtab: []const u8,
    symbols: []align(1) const elf.Elf64_Sym,
    strtab: []const u8,
    symbol_index: u32,
) []const u8 {
    if (symbol_index >= symbols.len) return "<invalid-symbol-index>";
    const symbol = symbols[symbol_index];
    if (symbol.st_name != 0) return getString(strtab, symbol.st_name);

    if (symbol.st_shndx != elf.SHN_UNDEF and symbol.st_shndx < view.shdrs.len) {
        return getString(shstrtab, view.shdrs[symbol.st_shndx].sh_name);
    }

    return "<unnamed-symbol>";
}

fn relocationNameString(relocation_type: u32) []const u8 {
    const enum_value = std.meta.intToEnum(elf.R_AARCH64, relocation_type) catch return "<unknown-relocation>";
    return @tagName(enum_value);
}

fn recordLinkDiagnostic(comptime fmt: []const u8, args: anytype) void {
    const message = std.fmt.bufPrint(&last_link_diagnostic_buf, fmt, args) catch |err| switch (err) {
        error.NoSpaceLeft => blk: {
            const fallback = "payload link error (diagnostic truncated)";
            @memcpy(last_link_diagnostic_buf[0..fallback.len], fallback);
            break :blk fallback;
        },
    };
    last_link_diagnostic_len = message.len;
}

/// Returns whether the target image will be rebased by the loader.
///
/// For ET_DYN binaries the static patcher only knows linked virtual addresses,
/// while the runtime loader will choose the final load bias later. Any payload
/// relocation that writes a full absolute address into code or data is
/// therefore unsafe unless we also provide a runtime rebasing mechanism.
fn targetImageRequiresPieSafeRelocations(target_image: ?ElfView) bool {
    return target_image != null and target_image.?.ehdr.e_type == elf.ET.DYN;
}

/// Relocations in this bucket directly materialize a slide-sensitive absolute
/// address.
///
/// They are safe for ET_EXEC, where the final runtime VA equals the linked VA,
/// but must be rejected for ET_DYN until the payload runtime grows its own
/// rebasing support.
fn relocationEncodesAbsoluteAddress(relocation_type: u32) bool {
    return switch (relocation_type) {
        @intFromEnum(elf.R_AARCH64.ABS64),
        @intFromEnum(elf.R_AARCH64.ABS32),
        @intFromEnum(elf.R_AARCH64.ABS16),
        @intFromEnum(elf.R_AARCH64.MOVW_UABS_G0),
        @intFromEnum(elf.R_AARCH64.MOVW_UABS_G0_NC),
        @intFromEnum(elf.R_AARCH64.MOVW_UABS_G1),
        @intFromEnum(elf.R_AARCH64.MOVW_UABS_G1_NC),
        @intFromEnum(elf.R_AARCH64.MOVW_UABS_G2),
        @intFromEnum(elf.R_AARCH64.MOVW_UABS_G2_NC),
        @intFromEnum(elf.R_AARCH64.MOVW_UABS_G3),
        => true,
        else => false,
    };
}

/// `ADR_GOT_PAGE + LD64_GOT_LO12_NC` is currently unsafe for ET_DYN for a more
/// subtle reason than the raw relocation names suggest: the instruction pair
/// itself is page-relative, but the synthetic GOT slot it loads from contains a
/// fully resolved absolute pointer.
fn relocationUsesSyntheticGotSlot(relocation_type: u32) bool {
    return switch (relocation_type) {
        @intFromEnum(elf.R_AARCH64.ADR_GOT_PAGE),
        @intFromEnum(elf.R_AARCH64.LD64_GOT_LO12_NC),
        => true,
        else => false,
    };
}

/// Note that some relocation names still contain `ABS` even when they are safe
/// for ET_DYN in practice.
///
/// Example: `ADD_ABS_LO12_NC` and `LDST*_ABS_LO12_NC` only inject the target's
/// low 12 bits. In the standard PIC sequence those low bits are paired with an
/// `ADRP`-derived page base, and a PIE slide does not perturb them.
fn ensureRelocationIsSupportedForTargetImage(
    view: ElfView,
    shstrtab: []const u8,
    symbols: []align(1) const elf.Elf64_Sym,
    strtab: []const u8,
    rela: elf.Elf64_Rela,
    target_section_name: []const u8,
    target_image: ?ElfView,
) !void {
    if (!targetImageRequiresPieSafeRelocations(target_image)) return;

    const symbol_name = relocationSymbolName(view, shstrtab, symbols, strtab, rela.r_sym());

    if (relocationUsesSyntheticGotSlot(rela.r_type())) {
        recordLinkDiagnostic(
            "unsupported AArch64 payload relocation {s} for symbol {s} in section {s} when linking into ET_DYN: current synthetic GOT slots store absolute addresses and are not PIE-safe",
            .{
                relocationNameString(rela.r_type()),
                symbol_name,
                target_section_name,
            },
        );
        return error.UnsupportedPayloadRelocation;
    }

    if (relocationEncodesAbsoluteAddress(rela.r_type())) {
        recordLinkDiagnostic(
            "unsupported AArch64 payload relocation {s} for symbol {s} in section {s} when linking into ET_DYN: relocation materializes a slide-sensitive absolute address",
            .{
                relocationNameString(rela.r_type()),
                symbol_name,
                target_section_name,
            },
        );
        return error.UnsupportedPayloadRelocation;
    }
}

fn noteEtDynGotSlotFailure(view: ElfView, slot: GotSlot) !void {
    if (slot.key.symtab_section_index >= view.shdrs.len) return error.InvalidPayloadRelocationSymtab;
    const symtab_shdr = view.shdrs[slot.key.symtab_section_index];
    const symbols = try symbolTable(view, symtab_shdr);
    const strtab = try linkedStringTable(view, symtab_shdr);
    const symbol_name = relocationSymbolName(view, try sectionStringTable(view), symbols, strtab, slot.key.symbol_index);

    recordLinkDiagnostic(
        "unsupported AArch64 payload relocation ADR_GOT_PAGE/LD64_GOT_LO12_NC for symbol {s} when linking into ET_DYN: current synthetic GOT slots store absolute addresses and are not PIE-safe",
        .{symbol_name},
    );
}

const RelocationOperands = struct {
    symbol_address: u64,
    addend: i64,
};

/// Resolves the effective `(S, A)` pair that should be fed into the concrete
/// relocation encoder.
///
/// Most relocations use the symbol's final address and the ELF addend as-is.
/// GOT-style relocations are different: the instruction stream must target the
/// synthetic slot address, and the addend has already been folded into the
/// slot contents during `initializeGotSlots`.
fn relocationOperands(
    got_slots: []const GotSlot,
    symtab_section_index: usize,
    rela: elf.Elf64_Rela,
    image_base_address: u64,
    symbol_address: u64,
) !RelocationOperands {
    switch (rela.r_type()) {
        @intFromEnum(elf.R_AARCH64.ADR_GOT_PAGE),
        @intFromEnum(elf.R_AARCH64.LD64_GOT_LO12_NC),
        => {
            const slot_offset = findGotSlotIndex(got_slots, symtab_section_index, rela.r_sym(), rela.r_addend) orelse {
                return error.InvalidPayloadGotSlot;
            };
            return .{
                .symbol_address = try addAddressOffset(image_base_address, got_slots[slot_offset].output_offset),
                .addend = 0,
            };
        },
        else => return .{
            .symbol_address = symbol_address,
            .addend = rela.r_addend,
        },
    }
}

fn findGotSlotIndex(
    got_slots: []const GotSlot,
    symtab_section_index: usize,
    symbol_index: u32,
    addend: i64,
) ?usize {
    for (got_slots, 0..) |slot, index| {
        if (slot.key.symtab_section_index != symtab_section_index) continue;
        if (slot.key.symbol_index != symbol_index) continue;
        if (slot.key.addend != addend) continue;
        return index;
    }
    return null;
}

/// Applies one AArch64 ELF relocation at `patch_offset`.
///
/// This function is intentionally explicit instead of "clever". Low-level
/// relocation code is exactly the kind of logic that becomes dangerous when it
/// hides the ABI rule it is implementing.
fn applyAarch64Relocation(
    image: []u8,
    patch_offset: usize,
    place_address: u64,
    symbol_address: u64,
    addend: i64,
    relocation_type: u32,
) !void {
    const R = elf.R_AARCH64;

    switch (relocation_type) {
        @intFromEnum(R.ABS64) => {
            const value = try absoluteAddressWithAddend(symbol_address, addend);
            try writeU64At(image, patch_offset, value);
        },
        @intFromEnum(R.ABS16) => {
            const value = try absoluteAddressWithAddend(symbol_address, addend);
            if (value > std.math.maxInt(u16)) return error.PayloadRelocationOverflow;
            try writeU16At(image, patch_offset, @intCast(value));
        },
        @intFromEnum(R.ABS32) => {
            const value = try absoluteAddressWithAddend(symbol_address, addend);
            if (value > std.math.maxInt(u32)) return error.PayloadRelocationOverflow;
            try writeU32At(image, patch_offset, @intCast(value));
        },
        @intFromEnum(R.PREL64) => {
            const delta = try relativeDeltaWithAddend(symbol_address, addend, place_address);
            try writeI64At(image, patch_offset, delta);
        },
        @intFromEnum(R.PREL16) => {
            const delta = try relativeDeltaWithAddend(symbol_address, addend, place_address);
            if (delta < std.math.minInt(i16) or delta > std.math.maxInt(i16)) return error.PayloadRelocationOverflow;
            try writeI16At(image, patch_offset, @intCast(delta));
        },
        @intFromEnum(R.PREL32) => {
            const delta = try relativeDeltaWithAddend(symbol_address, addend, place_address);
            if (delta < std.math.minInt(i32) or delta > std.math.maxInt(i32)) return error.PayloadRelocationOverflow;
            try writeI32At(image, patch_offset, @intCast(delta));
        },
        @intFromEnum(R.MOVW_UABS_G0) => {
            const value = try absoluteAddressWithAddend(symbol_address, addend);
            try patchMoveWideImmediate16(image, patch_offset, value, 0, true);
        },
        @intFromEnum(R.MOVW_UABS_G0_NC) => {
            const value = try absoluteAddressWithAddend(symbol_address, addend);
            try patchMoveWideImmediate16(image, patch_offset, value, 0, false);
        },
        @intFromEnum(R.MOVW_UABS_G1) => {
            const value = try absoluteAddressWithAddend(symbol_address, addend);
            try patchMoveWideImmediate16(image, patch_offset, value, 16, true);
        },
        @intFromEnum(R.MOVW_UABS_G1_NC) => {
            const value = try absoluteAddressWithAddend(symbol_address, addend);
            try patchMoveWideImmediate16(image, patch_offset, value, 16, false);
        },
        @intFromEnum(R.MOVW_UABS_G2) => {
            const value = try absoluteAddressWithAddend(symbol_address, addend);
            try patchMoveWideImmediate16(image, patch_offset, value, 32, true);
        },
        @intFromEnum(R.MOVW_UABS_G2_NC) => {
            const value = try absoluteAddressWithAddend(symbol_address, addend);
            try patchMoveWideImmediate16(image, patch_offset, value, 32, false);
        },
        @intFromEnum(R.MOVW_UABS_G3) => {
            const value = try absoluteAddressWithAddend(symbol_address, addend);
            try patchMoveWideImmediate16(image, patch_offset, value, 48, false);
        },
        @intFromEnum(R.CALL26), @intFromEnum(R.JUMP26) => {
            const delta = try relativeDeltaWithAddend(symbol_address, addend, place_address);
            try patchBranchImmediate26(image, patch_offset, delta);
        },
        @intFromEnum(R.CONDBR19) => {
            const delta = try relativeDeltaWithAddend(symbol_address, addend, place_address);
            try patchConditionalBranchImmediate19(image, patch_offset, delta);
        },
        @intFromEnum(R.TSTBR14) => {
            const delta = try relativeDeltaWithAddend(symbol_address, addend, place_address);
            try patchTestBranchImmediate14(image, patch_offset, delta);
        },
        @intFromEnum(R.ADR_PREL_LO21) => {
            const delta = try relativeDeltaWithAddend(symbol_address, addend, place_address);
            try patchAdrImmediate21(image, patch_offset, delta);
        },
        @intFromEnum(R.ADR_PREL_PG_HI21), @intFromEnum(R.ADR_PREL_PG_HI21_NC) => {
            const target_address = try absoluteAddressWithAddend(symbol_address, addend);
            try patchAdrpImmediate21(image, patch_offset, place_address, target_address);
        },
        @intFromEnum(R.ADR_GOT_PAGE) => {
            const target_address = try absoluteAddressWithAddend(symbol_address, addend);
            try patchAdrpImmediate21(image, patch_offset, place_address, target_address);
        },
        @intFromEnum(R.ADD_ABS_LO12_NC) => {
            const target_address = try absoluteAddressWithAddend(symbol_address, addend);
            try patchImmediateLo12(image, patch_offset, target_address, 0);
        },
        @intFromEnum(R.LDST8_ABS_LO12_NC) => {
            const target_address = try absoluteAddressWithAddend(symbol_address, addend);
            try patchImmediateLo12(image, patch_offset, target_address, 0);
        },
        @intFromEnum(R.LDST16_ABS_LO12_NC) => {
            const target_address = try absoluteAddressWithAddend(symbol_address, addend);
            try patchImmediateLo12(image, patch_offset, target_address, 1);
        },
        @intFromEnum(R.LDST32_ABS_LO12_NC) => {
            const target_address = try absoluteAddressWithAddend(symbol_address, addend);
            try patchImmediateLo12(image, patch_offset, target_address, 2);
        },
        @intFromEnum(R.LDST64_ABS_LO12_NC) => {
            const target_address = try absoluteAddressWithAddend(symbol_address, addend);
            try patchImmediateLo12(image, patch_offset, target_address, 3);
        },
        @intFromEnum(R.LD64_GOT_LO12_NC) => {
            const target_address = try absoluteAddressWithAddend(symbol_address, addend);
            try patchImmediateLo12(image, patch_offset, target_address, 3);
        },
        @intFromEnum(R.LDST128_ABS_LO12_NC) => {
            const target_address = try absoluteAddressWithAddend(symbol_address, addend);
            try patchImmediateLo12(image, patch_offset, target_address, 4);
        },
        @intFromEnum(R.LD_PREL_LO19) => {
            const delta = try relativeDeltaWithAddend(symbol_address, addend, place_address);
            try patchLiteralLoadImmediate19(image, patch_offset, delta);
        },
        else => return error.UnsupportedPayloadRelocation,
    }
}

fn absoluteAddressWithAddend(symbol_address: u64, addend: i64) !u64 {
    const result = @as(i128, @intCast(symbol_address)) + @as(i128, addend);
    if (result < 0 or result > std.math.maxInt(u64)) return error.PayloadRelocationOverflow;
    return @intCast(result);
}

fn relativeDeltaWithAddend(symbol_address: u64, addend: i64, place_address: u64) !i64 {
    const result = @as(i128, @intCast(symbol_address)) +
        @as(i128, addend) -
        @as(i128, @intCast(place_address));
    if (result < std.math.minInt(i64) or result > std.math.maxInt(i64)) return error.PayloadRelocationOverflow;
    return @intCast(result);
}

fn addAddressOffset(base: u64, offset: usize) !u64 {
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
fn encodeSignedImmediate(comptime bits: u6, byte_delta: i64, shift: u6) !u32 {
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

fn patchBranchImmediate26(image: []u8, patch_offset: usize, byte_delta: i64) !void {
    var instruction = try readU32At(image, patch_offset);
    const imm26 = try encodeSignedImmediate(26, byte_delta, 2);
    instruction = (instruction & ~@as(u32, 0x03FF_FFFF)) | imm26;
    try writeU32At(image, patch_offset, instruction);
}

/// Patches the signed 19-bit displacement used by `b.<cond>`.
///
/// The low condition bits are part of the opcode and must stay intact; only the
/// displacement field in bits `[23:5]` is replaced.
fn patchConditionalBranchImmediate19(image: []u8, patch_offset: usize, byte_delta: i64) !void {
    var instruction = try readU32At(image, patch_offset);
    const imm19 = try encodeSignedImmediate(19, byte_delta, 2);
    instruction = (instruction & ~(@as(u32, 0x7FFFF) << 5)) | (imm19 << 5);
    try writeU32At(image, patch_offset, instruction);
}

/// Patches the signed 14-bit displacement used by `tbz` / `tbnz`.
///
/// The tested bit index and the `tbz`/`tbnz` opcode bit live outside the
/// displacement field, so we only replace bits `[18:5]`.
fn patchTestBranchImmediate14(image: []u8, patch_offset: usize, byte_delta: i64) !void {
    var instruction = try readU32At(image, patch_offset);
    const imm14 = try encodeSignedImmediate(14, byte_delta, 2);
    instruction = (instruction & ~(@as(u32, 0x3FFF) << 5)) | (imm14 << 5);
    try writeU32At(image, patch_offset, instruction);
}

fn patchAdrImmediate21(image: []u8, patch_offset: usize, byte_delta: i64) !void {
    var instruction = try readU32At(image, patch_offset);
    const raw = try encodeSignedImmediate(21, byte_delta, 0);
    instruction = (instruction & ~((@as(u32, 0x3) << 29) | (@as(u32, 0x7FFFF) << 5))) |
        ((raw & 0x3) << 29) |
        (((raw >> 2) & 0x7FFFF) << 5);
    try writeU32At(image, patch_offset, instruction);
}

fn patchAdrpImmediate21(
    image: []u8,
    patch_offset: usize,
    place_address: u64,
    target_address: u64,
) !void {
    const page_delta = @as(i128, @intCast(target_address & ~@as(u64, 0xFFF))) -
        @as(i128, @intCast(place_address & ~@as(u64, 0xFFF)));
    if (page_delta < std.math.minInt(i64) or page_delta > std.math.maxInt(i64)) {
        return error.PayloadRelocationOverflow;
    }
    try patchAdrImmediate21(image, patch_offset, @intCast(page_delta));
}

fn patchLiteralLoadImmediate19(image: []u8, patch_offset: usize, byte_delta: i64) !void {
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
fn patchMoveWideImmediate16(
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

/// Patches the shared 12-bit immediate field used by `add` and unsigned
/// load/store encodings.
///
/// `shift` is the scale of the addressed datum:
/// - 0 for byte operations / `add`
/// - 1 for 16-bit accesses
/// - 2 for 32-bit accesses
/// - 3 for 64-bit accesses
/// - 4 for 128-bit accesses
fn patchImmediateLo12(
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

fn readU32At(image: []const u8, offset: usize) !u32 {
    if (offset + @sizeOf(u32) > image.len) return error.PayloadRelocationOutOfRange;
    const ptr: *const [4]u8 = @ptrCast(image[offset .. offset + 4].ptr);
    return std.mem.readInt(u32, ptr, .little);
}

fn writeU32At(image: []u8, offset: usize, value: u32) !void {
    if (offset + @sizeOf(u32) > image.len) return error.PayloadRelocationOutOfRange;
    var le = std.mem.nativeToLittle(u32, value);
    @memcpy(image[offset .. offset + 4], std.mem.asBytes(&le));
}

fn writeU16At(image: []u8, offset: usize, value: u16) !void {
    if (offset + @sizeOf(u16) > image.len) return error.PayloadRelocationOutOfRange;
    var le = std.mem.nativeToLittle(u16, value);
    @memcpy(image[offset .. offset + 2], std.mem.asBytes(&le));
}

fn writeU64At(image: []u8, offset: usize, value: u64) !void {
    if (offset + @sizeOf(u64) > image.len) return error.PayloadRelocationOutOfRange;
    var le = std.mem.nativeToLittle(u64, value);
    @memcpy(image[offset .. offset + 8], std.mem.asBytes(&le));
}

fn writeI16At(image: []u8, offset: usize, value: i16) !void {
    if (offset + @sizeOf(i16) > image.len) return error.PayloadRelocationOutOfRange;
    var le = std.mem.nativeToLittle(i16, value);
    @memcpy(image[offset .. offset + 2], std.mem.asBytes(&le));
}

fn writeI32At(image: []u8, offset: usize, value: i32) !void {
    if (offset + @sizeOf(i32) > image.len) return error.PayloadRelocationOutOfRange;
    var le = std.mem.nativeToLittle(i32, value);
    @memcpy(image[offset .. offset + 4], std.mem.asBytes(&le));
}

fn writeI64At(image: []u8, offset: usize, value: i64) !void {
    if (offset + @sizeOf(i64) > image.len) return error.PayloadRelocationOutOfRange;
    var le = std.mem.nativeToLittle(i64, value);
    @memcpy(image[offset .. offset + 8], std.mem.asBytes(&le));
}

fn sliceStructs(comptime T: type, bytes: []u8, offset: usize, count: usize) []align(1) T {
    const byte_len = count * @sizeOf(T);
    return std.mem.bytesAsSlice(T, bytes[offset .. offset + byte_len]);
}
