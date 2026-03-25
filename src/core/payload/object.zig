const std = @import("std");
const macho = std.macho;
const elf = std.elf;
const bundle = @import("../bundle.zig");
const image_backend = @import("../image_backend.zig");
const ElfView = @import("../../format/elf/root.zig").View;
const getString = @import("../../format/elf/root.zig").getString;
const aarch64 = @import("../../isa/aarch64/root.zig");
const HookContext = @import("../../sdk/aarch64_context.zig").HookContext;
const HookRuntimeInfo = @import("../../sdk/aarch64_context.zig").HookRuntimeInfo;

const aarch64_nop: u32 = 0xD503_201F;

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

fn hasPendingLinkDiagnostic() bool {
    return last_link_diagnostic_len != 0;
}

const OutputSection = struct {
    input_index: usize,
    output_offset: usize,
    size: usize,
    alignment: usize,
    region: PayloadImageRegion = .primary,
};

const PayloadImageRegion = enum {
    primary,
    writable,
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

const PayloadImageBases = struct {
    primary: u64,
    writable: ?u64 = null,
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
    return analyzeObjectBytesForFormat(allocator, .elf, object_bytes, handler_symbol);
}

/// Format-explicit object analysis entrypoint.
///
/// The original payload mini-linker only understood ELF relocatable objects.
/// Mach-O support adds a second object format, so the rewriter needs a way to
/// say "link this as Mach-O" without relying on file-name conventions.
///
/// The legacy `analyzeObjectBytes()` wrapper intentionally remains ELF-default
/// for source compatibility with older direct callers.
pub fn analyzeObjectBytesForFormat(
    allocator: std.mem.Allocator,
    object_format: bundle.ObjectFormat,
    object_bytes: []const u8,
    handler_symbol: []const u8,
) !PayloadLayout {
    clearLastLinkDiagnostic();
    return switch (object_format) {
        .elf => blk: {
            const mutable_bytes = @constCast(object_bytes);
            const view = try ElfView.parse(mutable_bytes);
            var prepared = try prepareObjectLayout(allocator, view, handler_symbol);
            defer prepared.deinit();

            break :blk .{
                .image_size = prepared.image_size,
                .entry_offset = prepared.entry_offset,
            };
        },
        .macho => macho_linker.analyzeObjectBytes(allocator, object_bytes, handler_symbol),
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
    return linkObjectBytesForFormatWithImageBases(
        allocator,
        .elf,
        object_bytes,
        handler_symbol,
        .{ .primary = image_base_address },
        if (target_image) |view| image_backend.View{ .elf = view } else null,
    );
}

/// Format-explicit object linking entrypoint.
///
/// `target_image` is backend-neutral because payload symbols may eventually be
/// resolved against either ELF or Mach-O targets. Today the fully exercised
/// combinations are:
/// - ELF object -> ELF target
/// - Mach-O object -> Mach-O target
pub fn linkObjectBytesForFormat(
    allocator: std.mem.Allocator,
    object_format: bundle.ObjectFormat,
    object_bytes: []const u8,
    handler_symbol: []const u8,
    image_base_address: u64,
    target_image: ?image_backend.View,
) !LoadedPayload {
    return linkObjectBytesForFormatWithImageBases(
        allocator,
        object_format,
        object_bytes,
        handler_symbol,
        .{ .primary = image_base_address },
        target_image,
    );
}

/// Extended linking entrypoint that can place writable payload sections into a
/// second injected image.
///
/// This is currently exercised only by the Mach-O backend:
/// - `primary` holds executable code plus read-only data
/// - `writable`, when present, holds `.data/.bss` state that must not share the
///   executable carrier segment on macOS arm64 because ad-hoc-signed images are
///   effectively W^X at runtime
pub fn linkObjectBytesForFormatWithImageBases(
    allocator: std.mem.Allocator,
    object_format: bundle.ObjectFormat,
    object_bytes: []const u8,
    handler_symbol: []const u8,
    image_bases: PayloadImageBases,
    target_image: ?image_backend.View,
) !LoadedPayload {
    clearLastLinkDiagnostic();
    return switch (object_format) {
        .elf => blk: {
            const mutable_bytes = @constCast(object_bytes);
            const view = try ElfView.parse(mutable_bytes);
            var prepared = try prepareObjectLayout(allocator, view, handler_symbol);
            defer prepared.deinit();

            const image = try allocator.alloc(u8, prepared.image_size);
            errdefer allocator.free(image);
            @memset(image, 0);

            try copyAllocatedSections(image, view, prepared.output_sections);
            try initializeGotSlots(image, view, prepared, image_bases.primary, try elfTargetImage(target_image));
            try applyRelocations(image, view, prepared, image_bases.primary, try elfTargetImage(target_image));

            break :blk .{
                .image = image,
                .entry_offset = prepared.entry_offset,
            };
        },
        .macho => macho_linker.linkObjectBytes(
            allocator,
            object_bytes,
            handler_symbol,
            image_bases,
            target_image,
        ),
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
    if (targetElfImageRequiresPieSafeRelocations(target_image) and prepared.got_slots.len != 0) {
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
fn targetElfImageRequiresPieSafeRelocations(target_image: ?ElfView) bool {
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
    if (!targetElfImageRequiresPieSafeRelocations(target_image)) return;

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

/// Mach-O `MH_OBJECT` mini-linker for arm64 payloads.
///
/// The ELF linker above already proved the general payload-linker design:
/// 1. keep loadable sections
/// 2. assign final in-image offsets
/// 3. resolve symbols against the injected image and optionally the target image
/// 4. apply a carefully bounded relocation subset
///
/// Mach-O object files encode the same high-level problem differently:
/// - sections are identified by 1-based ordinals instead of ELF section indices
/// - symbol names are usually prefixed with `_`
/// - arm64 uses Mach-O-specific relocation kinds such as `PAGE21/PAGEOFF12`
/// - addends for some relocation families live in a preceding `ADDEND`
///   relocation entry instead of the instruction stream itself
///
/// Keeping this logic in its own namespace makes the invariants explicit and
/// avoids letting Mach-O edge cases leak into the already-stable ELF path.
const macho_linker = struct {
    /// `r_symbolnum == 0` is the traditional Mach-O `R_ABS` sentinel for
    /// section-based relocations. Zig's stdlib does not currently expose that
    /// macro, so the mini-linker keeps the ABI value local here.
    const r_abs_symbolnum: u24 = 0;

    const SectionRef = struct {
        ordinal: usize,
        header: macho.section_64,
    };

    /// Key for one framework-owned Mach-O synthetic GOT slot.
    ///
    /// Zig currently lowers `extern var` loads on Mach-O/AArch64 through
    /// `GOT_LOAD_PAGE21 + GOT_LOAD_PAGEOFF12`. The mini-linker therefore needs
    /// the same conceptual tool it already uses on ELF:
    /// materialize one private pointer cell inside the injected payload, patch
    /// the instruction pair to that cell, and seed the cell with the final
    /// linked symbol address.
    const MachOGotSlotKey = struct {
        is_external: bool,
        symbolnum: u24,
        addend: i64,
    };

    const MachOGotSlot = struct {
        key: MachOGotSlotKey,
        /// Offset within the writable payload image.
        output_offset: usize,
    };

    /// One writable payload cell whose linked absolute value must be rebased to
    /// the runtime image layout before user code observes it.
    ///
    /// The emitted payload image stores linked-time absolute addresses because
    /// the static patcher does not extend Mach-O rebase metadata. For PIE
    /// targets, every such cell therefore needs a tiny runtime fixup story:
    /// compute `runtime = linked + load_bias` once after the hook first fires.
    ///
    /// `output_offset` is relative to the writable payload image because the
    /// current Mach-O design only permits one-time mutable rebasing on the RW
    /// carrier image. If a relocation would need the same treatment inside the
    /// RX image, the linker must reject it explicitly instead of silently
    /// emitting a slide-sensitive pointer.
    const MachORuntimeFixup = struct {
        output_offset: usize,
        is_external: bool,
        symbolnum: u24,
    };

    const MachOSymbolReference = struct {
        linked_address: u64,
        requires_load_bias: bool,
    };

    /// Wrapper entrypoint for one payload function.
    ///
    /// When the payload contains framework-owned Mach-O synthetic GOT slots,
    /// callbacks must not jump straight into the user function. They first pass
    /// through a tiny runtime shim that re-seeds those slots from linked
    /// addresses plus the current `load_bias`, then branches to the real
    /// handler. This keeps `extern var` payload loads PIE-safe on macOS arm64.
    const MachOEntryWrapper = struct {
        symbol_index: usize,
        target_offset: usize,
        wrapper_offset: usize,
    };

    const MachOPreparedObject = struct {
        allocator: std.mem.Allocator,
        section_map: []?usize,
        output_sections: []OutputSection,
        got_slots: []MachOGotSlot,
        runtime_fixups: []MachORuntimeFixup,
        entry_wrappers: []MachOEntryWrapper,
        entry_offset: usize,
        primary_image_size: usize,
        writable_image_size: usize,
        runtime_guard_output_offset: usize = 0,
        runtime_common_offset: usize = 0,
        runtime_common_code_size: usize = 0,
        runtime_literal_offset: usize = 0,

        fn deinit(self: *MachOPreparedObject) void {
            self.allocator.free(self.entry_wrappers);
            self.allocator.free(self.runtime_fixups);
            self.allocator.free(self.got_slots);
            self.allocator.free(self.output_sections);
            self.allocator.free(self.section_map);
            self.* = undefined;
        }

        fn needsRuntimeEntryWrapper(self: MachOPreparedObject) bool {
            return self.runtime_fixups.len != 0;
        }
    };

    const PendingAddend = struct {
        address: i32,
        addend: i64,
    };

    const ObjectView = struct {
        bytes: []const u8,
        header: *align(1) const macho.mach_header_64,
        sections: []SectionRef,
        symbols: []align(1) const macho.nlist_64,
        strtab: []const u8,

        /// Parses the small subset of `MH_OBJECT` metadata that the payload
        /// mini-linker needs.
        ///
        /// This intentionally stays zero-copy:
        /// - section/symbol/relocation slices all borrow the original object
        ///   bytes
        /// - the linker can therefore reason about the real on-disk layout
        ///   without building a heavyweight intermediate representation
        fn parse(allocator: std.mem.Allocator, object_bytes: []const u8) !ObjectView {
            if (object_bytes.len < @sizeOf(macho.mach_header_64)) return error.InvalidMachO;

            const magic = std.mem.readInt(u32, @ptrCast(object_bytes[0..4]), .little);
            switch (magic) {
                macho.MH_MAGIC_64 => {},
                macho.FAT_MAGIC, macho.FAT_CIGAM, macho.FAT_MAGIC_64, macho.FAT_CIGAM_64 => {
                    return error.UnsupportedFatMachO;
                },
                macho.MH_CIGAM_64 => return error.UnsupportedBigEndianMachO,
                else => return error.InvalidMachOMagic,
            }

            const header = std.mem.bytesAsValue(macho.mach_header_64, object_bytes[0..@sizeOf(macho.mach_header_64)]);
            if (header.cputype != macho.CPU_TYPE_ARM64) return error.UnsupportedMachine;
            if (header.filetype != macho.MH_OBJECT) return error.UnsupportedPayloadType;

            const load_commands_offset = @sizeOf(macho.mach_header_64);
            const load_commands_size: usize = @intCast(header.sizeofcmds);
            if (load_commands_offset + load_commands_size > object_bytes.len) return error.InvalidMachOLoadCommands;
            const load_commands = object_bytes[load_commands_offset .. load_commands_offset + load_commands_size];

            var section_count: usize = 0;
            var symtab_cmd: ?*align(1) const macho.symtab_command = null;

            var cursor: usize = 0;
            var remaining = header.ncmds;
            while (remaining != 0) : (remaining -= 1) {
                if (cursor + @sizeOf(macho.load_command) > load_commands.len) return error.InvalidMachOLoadCommands;

                const command = std.mem.bytesAsValue(
                    macho.load_command,
                    load_commands[cursor .. cursor + @sizeOf(macho.load_command)],
                );
                if (command.cmdsize < @sizeOf(macho.load_command)) return error.InvalidMachOLoadCommand;
                if (cursor + command.cmdsize > load_commands.len) return error.InvalidMachOLoadCommand;

                if (command.cmd == .SEGMENT_64) {
                    const segment = std.mem.bytesAsValue(
                        macho.segment_command_64,
                        load_commands[cursor .. cursor + @sizeOf(macho.segment_command_64)],
                    );
                    const sections_size = @as(usize, segment.nsects) * @sizeOf(macho.section_64);
                    if (@sizeOf(macho.segment_command_64) + sections_size > command.cmdsize) {
                        return error.InvalidMachOSegmentCommand;
                    }
                    section_count += segment.nsects;
                } else if (command.cmd == .SYMTAB) {
                    symtab_cmd = std.mem.bytesAsValue(
                        macho.symtab_command,
                        load_commands[cursor .. cursor + @sizeOf(macho.symtab_command)],
                    );
                }

                cursor += command.cmdsize;
            }

            const symtab = symtab_cmd orelse return error.InvalidMachOSymbolTable;
            const symbol_count: usize = @intCast(symtab.nsyms);
            const symbol_offset: usize = symtab.symoff;
            const symbol_size = symbol_count * @sizeOf(macho.nlist_64);
            if (symbol_offset + symbol_size > object_bytes.len) return error.InvalidMachOSymbolTable;
            const symbols = sliceConstStructs(macho.nlist_64, object_bytes, symbol_offset, symbol_count);

            const string_offset: usize = symtab.stroff;
            const string_size: usize = symtab.strsize;
            if (string_offset + string_size > object_bytes.len) return error.InvalidMachOStringTable;
            const strtab = object_bytes[string_offset .. string_offset + string_size];

            const sections = try allocator.alloc(SectionRef, section_count);
            errdefer allocator.free(sections);

            cursor = 0;
            remaining = header.ncmds;
            var ordinal: usize = 1;
            while (remaining != 0) : (remaining -= 1) {
                const command = std.mem.bytesAsValue(
                    macho.load_command,
                    load_commands[cursor .. cursor + @sizeOf(macho.load_command)],
                );
                if (command.cmd == .SEGMENT_64) {
                    const segment = std.mem.bytesAsValue(
                        macho.segment_command_64,
                        load_commands[cursor .. cursor + @sizeOf(macho.segment_command_64)],
                    );
                    const sections_offset = cursor + @sizeOf(macho.segment_command_64);
                    const command_sections = sliceConstStructs(
                        macho.section_64,
                        load_commands,
                        sections_offset,
                        segment.nsects,
                    );

                    for (command_sections) |section| {
                        if (!section.isZerofill()) {
                            const section_offset: usize = section.offset;
                            const section_size: usize = @intCast(section.size);
                            if (section_offset + section_size > object_bytes.len) return error.InvalidPayloadSectionSize;
                        }

                        if (section.nreloc != 0) {
                            const reloc_offset: usize = section.reloff;
                            const reloc_size = @as(usize, section.nreloc) * @sizeOf(macho.relocation_info);
                            if (reloc_offset + reloc_size > object_bytes.len) return error.InvalidPayloadRelocationTable;
                        }

                        sections[ordinal - 1] = .{
                            .ordinal = ordinal,
                            .header = section,
                        };
                        ordinal += 1;
                    }
                }
                cursor += command.cmdsize;
            }

            return .{
                .bytes = object_bytes,
                .header = header,
                .sections = sections,
                .symbols = symbols,
                .strtab = strtab,
            };
        }

        fn deinit(self: ObjectView, allocator: std.mem.Allocator) void {
            allocator.free(self.sections);
        }

        fn sectionByOrdinal(self: ObjectView, ordinal: usize) !SectionRef {
            if (ordinal == 0 or ordinal > self.sections.len) return error.InvalidPayloadSectionOrdinal;
            return self.sections[ordinal - 1];
        }

        fn sectionData(self: ObjectView, ordinal: usize) ![]const u8 {
            const section = try self.sectionByOrdinal(ordinal);
            if (section.header.isZerofill()) return self.bytes[0..0];

            const start: usize = section.header.offset;
            const size: usize = @intCast(section.header.size);
            return self.bytes[start .. start + size];
        }

        fn sectionRelocations(self: ObjectView, ordinal: usize) ![]align(1) const macho.relocation_info {
            const section = try self.sectionByOrdinal(ordinal);
            if (section.header.nreloc == 0) return sliceConstStructs(macho.relocation_info, self.bytes, 0, 0);
            return sliceConstStructs(
                macho.relocation_info,
                self.bytes,
                section.header.reloff,
                section.header.nreloc,
            );
        }

        fn symbolNameByIndex(self: ObjectView, symbol_index: usize) []const u8 {
            if (symbol_index >= self.symbols.len) return "<invalid-symbol-index>";
            const symbol = self.symbols[symbol_index];
            return machoObjectString(self.strtab, symbol.n_strx);
        }
    };

    pub fn analyzeObjectBytes(
        allocator: std.mem.Allocator,
        object_bytes: []const u8,
        handler_symbol: []const u8,
    ) !PayloadLayout {
        const view = try ObjectView.parse(allocator, object_bytes);
        defer view.deinit(allocator);

        var prepared = try prepareMachOObjectLayout(allocator, view, handler_symbol);
        defer prepared.deinit();

        return .{
            .image_size = prepared.primary_image_size,
            .entry_offset = prepared.entry_offset,
            .writable_image_size = prepared.writable_image_size,
        };
    }

    pub fn linkObjectBytes(
        allocator: std.mem.Allocator,
        object_bytes: []const u8,
        handler_symbol: []const u8,
        image_bases: PayloadImageBases,
        target_image: ?image_backend.View,
    ) !LoadedPayload {
        const view = try ObjectView.parse(allocator, object_bytes);
        defer view.deinit(allocator);

        var prepared = try prepareMachOObjectLayout(allocator, view, handler_symbol);
        defer prepared.deinit();

        const image = try allocator.alloc(u8, prepared.primary_image_size);
        errdefer allocator.free(image);
        @memset(image, 0);

        const writable_image = if (prepared.writable_image_size != 0)
            try allocator.alloc(u8, prepared.writable_image_size)
        else
            null;
        errdefer if (writable_image) |bytes| allocator.free(bytes);
        if (writable_image) |bytes| @memset(bytes, 0);

        try copyAllocatedSectionsMachO(image, writable_image, view, prepared.output_sections);
        try initializeMachOGotSlots(writable_image, view, prepared, image_bases, target_image);
        try applyMachORelocations(image, writable_image, view, prepared, image_bases, target_image);
        try emitMachORuntimeEntrySupport(image, writable_image, view, prepared, image_bases, target_image);

        return .{
            .image = image,
            .entry_offset = prepared.entry_offset,
            .writable_image = writable_image,
        };
    }

    fn prepareMachOObjectLayout(
        allocator: std.mem.Allocator,
        view: ObjectView,
        handler_symbol: []const u8,
    ) !MachOPreparedObject {
        const section_map = try allocator.alloc(?usize, view.sections.len + 1);
        errdefer allocator.free(section_map);
        for (section_map) |*slot| slot.* = null;

        var output_sections: std.array_list.Managed(OutputSection) = .init(allocator);
        defer output_sections.deinit();

        var primary_cursor: usize = 0;
        var writable_cursor: usize = 0;
        for (view.sections) |section| {
            const should_keep = try shouldKeepSection(section);
            if (!should_keep) continue;

            const region = classifySectionRegion(section);
            const alignment = machoSectionAlignment(section.header.@"align");
            const cursor = switch (region) {
                .primary => &primary_cursor,
                .writable => &writable_cursor,
            };
            cursor.* = std.mem.alignForward(usize, cursor.*, alignment);
            section_map[section.ordinal] = output_sections.items.len;
            try output_sections.append(.{
                .input_index = section.ordinal,
                .output_offset = cursor.*,
                .size = @intCast(section.header.size),
                .alignment = alignment,
                .region = region,
            });
            cursor.* += @intCast(section.header.size);
        }

        if (output_sections.items.len == 0) return error.PayloadMissingAllocSections;

        const got_slots = try collectMachOGotSlots(allocator, view, section_map);
        errdefer allocator.free(got_slots);

        for (got_slots) |*slot| {
            writable_cursor = std.mem.alignForward(usize, writable_cursor, @sizeOf(u64));
            slot.output_offset = writable_cursor;
            writable_cursor += @sizeOf(u64);
        }

        const runtime_fixups = try collectMachORuntimeFixups(
            allocator,
            view,
            section_map,
            output_sections.items,
            got_slots,
        );
        errdefer allocator.free(runtime_fixups);

        var entry_wrappers = try allocator.alloc(MachOEntryWrapper, 0);
        errdefer allocator.free(entry_wrappers);

        var runtime_guard_output_offset: usize = 0;
        var runtime_common_offset: usize = 0;
        var runtime_common_code_size: usize = 0;
        var runtime_literal_offset: usize = 0;

        if (runtime_fixups.len != 0) {
            writable_cursor = std.mem.alignForward(usize, writable_cursor, @sizeOf(u64));
            runtime_guard_output_offset = writable_cursor;
            writable_cursor += @sizeOf(u64);

            runtime_common_offset = std.mem.alignForward(usize, primary_cursor, @sizeOf(u64));
            runtime_common_code_size = runtimeInitCodeSize(runtime_fixups.len);
            runtime_literal_offset = runtime_common_offset + runtime_common_code_size;

            const wrapper_start = runtime_literal_offset +
                @sizeOf(u64) +
                runtime_fixups.len * runtime_fixup_literal_bytes_per_fixup;
            entry_wrappers = try collectMachOEntryWrappers(
                allocator,
                view,
                section_map,
                output_sections.items,
                wrapper_start,
            );
            primary_cursor = wrapper_start + entry_wrappers.len * runtime_wrapper_size;
        }

        const entry_offset = try resolveMachOEntryOffset(
            view,
            section_map,
            output_sections.items,
            entry_wrappers,
            handler_symbol,
        );
        return .{
            .allocator = allocator,
            .section_map = section_map,
            .output_sections = try output_sections.toOwnedSlice(),
            .got_slots = got_slots,
            .runtime_fixups = runtime_fixups,
            .entry_wrappers = entry_wrappers,
            .entry_offset = entry_offset,
            .primary_image_size = primary_cursor,
            .writable_image_size = writable_cursor,
            .runtime_guard_output_offset = runtime_guard_output_offset,
            .runtime_common_offset = runtime_common_offset,
            .runtime_common_code_size = runtime_common_code_size,
            .runtime_literal_offset = runtime_literal_offset,
        };
    }

    /// Decides whether a Mach-O section becomes part of the injected payload.
    ///
    /// The policy intentionally mirrors the ELF linker:
    /// - keep executable/data/readonly sections that materially contribute to
    ///   the payload image
    /// - reject TLS because the static patcher does not yet provide a runtime
    ///   TLS story for injected code
    /// - drop unwind/debug metadata because the current framework does not yet
    ///   integrate them with the target image
    fn shouldKeepSection(section: SectionRef) !bool {
        const segname = parseFixedName(section.header.segname[0..]);
        const sectname = parseFixedName(section.header.sectname[0..]);
        const section_type = section.header.type();

        if (std.mem.eql(u8, segname, "__DWARF") or std.mem.eql(u8, segname, "__LD")) return false;
        if (section.header.isDebug()) return false;

        if (section_type == macho.S_THREAD_LOCAL_REGULAR or
            section_type == macho.S_THREAD_LOCAL_ZEROFILL or
            section_type == macho.S_THREAD_LOCAL_VARIABLES or
            section_type == macho.S_THREAD_LOCAL_VARIABLE_POINTERS or
            section_type == macho.S_THREAD_LOCAL_INIT_FUNCTION_POINTERS)
        {
            return error.UnsupportedPayloadTlsSection;
        }

        if (std.mem.eql(u8, sectname, "__eh_frame") or std.mem.eql(u8, sectname, "__compact_unwind")) {
            return false;
        }

        if (section.header.isSymbolStubs()) return error.UnsupportedPayloadSectionType;

        return switch (section_type) {
            macho.S_REGULAR,
            macho.S_ZEROFILL,
            macho.S_GB_ZEROFILL,
            macho.S_CSTRING_LITERALS,
            macho.S_4BYTE_LITERALS,
            macho.S_8BYTE_LITERALS,
            macho.S_16BYTE_LITERALS,
            macho.S_LITERAL_POINTERS,
            => true,
            else => error.UnsupportedPayloadSectionType,
        };
    }

    /// Chooses which injected Mach-O image will own the section.
    ///
    /// Current split policy:
    /// - executable code and read-only payload data stay in the primary image
    /// - writable state (`__DATA`, `__bss`, zerofill) moves into the writable
    ///   image so Mach-O runtime pages do not need to be both executable and
    ///   writable after ad-hoc code signing
    fn classifySectionRegion(section: SectionRef) PayloadImageRegion {
        const segname = parseFixedName(section.header.segname[0..]);
        const sectname = parseFixedName(section.header.sectname[0..]);

        if (section.header.isZerofill()) return .writable;
        if (std.mem.eql(u8, segname, "__DATA")) return .writable;
        if (std.mem.eql(u8, sectname, "__data") or std.mem.eql(u8, sectname, "__bss")) return .writable;
        return .primary;
    }

    fn machoSectionAlignment(raw_alignment: u32) usize {
        if (raw_alignment == 0) return 1;
        return @as(usize, 1) << @intCast(raw_alignment);
    }

    fn collectMachOGotSlots(
        allocator: std.mem.Allocator,
        view: ObjectView,
        section_map: []const ?usize,
    ) ![]MachOGotSlot {
        var slots: std.array_list.Managed(MachOGotSlot) = .init(allocator);
        defer slots.deinit();

        for (view.sections) |section| {
            if (section.ordinal >= section_map.len) return error.InvalidPayloadSectionOrdinal;
            if (section_map[section.ordinal] == null) continue;

            const relocs = try view.sectionRelocations(section.ordinal);
            var pending_addend: ?PendingAddend = null;
            for (relocs) |reloc| {
                const relocation_type = std.meta.intToEnum(macho.reloc_type_arm64, reloc.r_type) catch {
                    pending_addend = null;
                    continue;
                };

                if (relocation_type == .ARM64_RELOC_ADDEND) {
                    if (pending_addend != null) return error.InvalidPayloadRelocationTable;
                    pending_addend = .{
                        .address = reloc.r_address,
                        .addend = decodeAddend(reloc),
                    };
                    continue;
                }

                const explicit_addend = if (pending_addend) |pair| blk: {
                    if (pair.address != reloc.r_address) return error.InvalidPayloadRelocationTable;
                    pending_addend = null;
                    break :blk pair.addend;
                } else 0;

                switch (relocation_type) {
                    .ARM64_RELOC_GOT_LOAD_PAGE21, .ARM64_RELOC_GOT_LOAD_PAGEOFF12 => {
                        if (findMachOGotSlotIndex(slots.items, reloc.r_extern != 0, reloc.r_symbolnum, explicit_addend) != null) {
                            continue;
                        }
                        try slots.append(.{
                            .key = .{
                                .is_external = reloc.r_extern != 0,
                                .symbolnum = reloc.r_symbolnum,
                                .addend = explicit_addend,
                            },
                            .output_offset = 0,
                        });
                    },
                    else => {},
                }
            }

            if (pending_addend != null) return error.InvalidPayloadRelocationTable;
        }

        return slots.toOwnedSlice();
    }

    fn findMachOGotSlotIndex(
        slots: []const MachOGotSlot,
        is_external: bool,
        symbolnum: u24,
        addend: i64,
    ) ?usize {
        for (slots, 0..) |slot, index| {
            if (slot.key.is_external != is_external) continue;
            if (slot.key.symbolnum != symbolnum) continue;
            if (slot.key.addend != addend) continue;
            return index;
        }
        return null;
    }

    /// Collects writable Mach-O cells that require a runtime `load_bias`
    /// rebase when the payload is injected into a PIE image.
    ///
    /// Two families currently feed this table:
    /// - framework-owned synthetic GOT cells (`extern var` / GOT_LOAD)
    /// - user-authored writable absolute pointer cells (`UNSIGNED` in RW data)
    ///
    /// The linker deliberately records candidates here during layout even
    /// though some of them may later resolve to true absolute values or missing
    /// weak references. Layout needs the worst-case wrapper/runtime footprint
    /// to stay stable before the final target image is known. The later emit
    /// pass decides which entries actually need `+ load_bias`.
    fn collectMachORuntimeFixups(
        allocator: std.mem.Allocator,
        view: ObjectView,
        section_map: []const ?usize,
        output_sections: []const OutputSection,
        got_slots: []const MachOGotSlot,
    ) ![]MachORuntimeFixup {
        var fixups: std.array_list.Managed(MachORuntimeFixup) = .init(allocator);
        defer fixups.deinit();

        for (got_slots) |slot| {
            if (findMachORuntimeFixupIndex(fixups.items, slot.output_offset) != null) continue;
            try fixups.append(.{
                .output_offset = slot.output_offset,
                .is_external = slot.key.is_external,
                .symbolnum = slot.key.symbolnum,
            });
        }

        for (view.sections) |section| {
            if (section.ordinal >= section_map.len) return error.InvalidPayloadSectionOrdinal;
            const mapped_index = section_map[section.ordinal] orelse continue;
            const output_section = output_sections[mapped_index];
            if (output_section.region != .writable) continue;

            const relocs = try view.sectionRelocations(section.ordinal);
            var pending_addend: ?PendingAddend = null;
            for (relocs) |reloc| {
                const relocation_type = std.meta.intToEnum(macho.reloc_type_arm64, reloc.r_type) catch {
                    pending_addend = null;
                    continue;
                };

                if (relocation_type == .ARM64_RELOC_ADDEND) {
                    if (pending_addend != null) return error.InvalidPayloadRelocationTable;
                    pending_addend = .{
                        .address = reloc.r_address,
                        .addend = decodeAddend(reloc),
                    };
                    continue;
                }

                if (pending_addend) |pair| {
                    if (pair.address != reloc.r_address) return error.InvalidPayloadRelocationTable;
                    pending_addend = null;
                }

                if (relocation_type != .ARM64_RELOC_UNSIGNED) continue;
                if (reloc.r_length != 3) continue;

                const patch_offset = try machOPatchOffset(output_section, reloc);
                if (findMachORuntimeFixupIndex(fixups.items, patch_offset) != null) continue;
                try fixups.append(.{
                    .output_offset = patch_offset,
                    .is_external = reloc.r_extern != 0,
                    .symbolnum = reloc.r_symbolnum,
                });
            }

            if (pending_addend != null) return error.InvalidPayloadRelocationTable;
        }

        return fixups.toOwnedSlice();
    }

    fn findMachORuntimeFixupIndex(fixups: []const MachORuntimeFixup, output_offset: usize) ?usize {
        for (fixups, 0..) |fixup, index| {
            if (fixup.output_offset == output_offset) return index;
        }
        return null;
    }

    fn collectMachOEntryWrappers(
        allocator: std.mem.Allocator,
        view: ObjectView,
        section_map: []const ?usize,
        output_sections: []const OutputSection,
        wrapper_start: usize,
    ) ![]MachOEntryWrapper {
        var wrappers: std.array_list.Managed(MachOEntryWrapper) = .init(allocator);
        defer wrappers.deinit();

        var wrapper_offset = wrapper_start;
        for (view.symbols, 0..) |symbol, symbol_index| {
            if (symbol.n_strx == 0 or symbol.stab()) continue;
            if (!symbol.sect()) continue;

            const ordinal: usize = symbol.n_sect;
            if (ordinal >= section_map.len) return error.InvalidPayloadSymbolSection;
            const mapped_index = section_map[ordinal] orelse continue;
            const output_section = output_sections[mapped_index];
            if (output_section.region != .primary) continue;

            const input_section = try view.sectionByOrdinal(ordinal);
            if (!input_section.header.isCode()) continue;
            if (symbol.n_value < input_section.header.addr) return error.PayloadSymbolOutOfRange;
            const symbol_offset = symbol.n_value - input_section.header.addr;
            if (symbol_offset > output_section.size) return error.PayloadSymbolOutOfRange;

            try wrappers.append(.{
                .symbol_index = symbol_index,
                .target_offset = output_section.output_offset + @as(usize, @intCast(symbol_offset)),
                .wrapper_offset = wrapper_offset,
            });
            wrapper_offset += runtime_wrapper_size;
        }

        return wrappers.toOwnedSlice();
    }

    fn resolveMachOEntryOffset(
        view: ObjectView,
        section_map: []const ?usize,
        output_sections: []const OutputSection,
        entry_wrappers: []const MachOEntryWrapper,
        handler_symbol: []const u8,
    ) !usize {
        for (view.symbols, 0..) |symbol, symbol_index| {
            if (symbol.n_strx == 0 or symbol.stab()) continue;
            if (!symbol.sect()) continue;

            const symbol_name = machoObjectString(view.strtab, symbol.n_strx);
            if (!matchesUserSymbolName(symbol_name, handler_symbol)) continue;

            for (entry_wrappers) |wrapper| {
                if (wrapper.symbol_index == symbol_index) return wrapper.wrapper_offset;
            }

            const ordinal: usize = symbol.n_sect;
            if (ordinal >= section_map.len) return error.InvalidPayloadSymbolSection;
            const mapped_index = section_map[ordinal] orelse return error.PayloadEntryInUnsupportedSection;
            const output_section = output_sections[mapped_index];
            if (output_section.region != .primary) return error.PayloadEntryInUnsupportedSection;
            const input_section = try view.sectionByOrdinal(ordinal);
            if (symbol.n_value < input_section.header.addr) return error.PayloadSymbolOutOfRange;
            const symbol_offset = symbol.n_value - input_section.header.addr;
            if (symbol_offset > output_section.size) return error.PayloadSymbolOutOfRange;
            return output_section.output_offset + @as(usize, @intCast(symbol_offset));
        }

        return error.PayloadSymbolNotFound;
    }

    const runtime_wrapper_size = 16;
    const runtime_fixup_literal_bytes_per_fixup = @sizeOf(u64);
    const runtime_guard_state_uninitialized: u16 = 0;
    const runtime_guard_state_initializing: u16 = 1;
    const runtime_guard_state_initialized: u16 = 2;
    const aarch64_condition_eq: u4 = 0x0;
    const aarch64_condition_ne: u4 = 0x1;

    fn runtimeInitCodeSize(fixup_count: usize) usize {
        const raw_code_size = @as(usize, 4) * (19 + fixup_count * 5);
        return std.mem.alignForward(usize, raw_code_size, @sizeOf(u64));
    }

    fn machORuntimeLoadBiasOffset() usize {
        return @offsetOf(HookContext, "runtime") + @offsetOf(HookRuntimeInfo, "load_bias");
    }

    fn encodeLdrLiteral64Local(rt: u5, byte_offset: usize) u32 {
        std.debug.assert((byte_offset & 0x3) == 0);
        const imm19: u19 = @intCast(byte_offset / 4);
        return 0x5800_0000 | (@as(u32, imm19) << 5) | rt;
    }

    fn encodeAddRegister64(rd: u5, rn: u5, rm: u5) u32 {
        return 0x8B00_0000 |
            (@as(u32, rm) << 16) |
            (@as(u32, rn) << 5) |
            rd;
    }

    fn encodeMovZLocal(rd: u5, imm16: u16) u32 {
        return 0xD280_0000 | (@as(u32, imm16) << 5) | rd;
    }

    fn encodeCmpRegister64Local(rn: u5, rm: u5) u32 {
        return 0xEB00_001F | (@as(u32, rm) << 16) | (@as(u32, rn) << 5);
    }

    fn encodeBrLocal(rn: u5) u32 {
        return 0xD61F_0000 | (@as(u32, rn) << 5);
    }

    fn encodeLdrUnsigned64Local(rt: u5, rn: u5, offset: usize) u32 {
        std.debug.assert((offset & 0x7) == 0);
        const imm12: u12 = @intCast(offset / 8);
        return 0xF940_0000 | (@as(u32, imm12) << 10) | (@as(u32, rn) << 5) | rt;
    }

    fn encodeStrUnsigned64Local(rt: u5, rn: u5, offset: usize) u32 {
        std.debug.assert((offset & 0x7) == 0);
        const imm12: u12 = @intCast(offset / 8);
        return 0xF900_0000 | (@as(u32, imm12) << 10) | (@as(u32, rn) << 5) | rt;
    }

    fn encodeLdaxr64Local(rt: u5, rn: u5) u32 {
        return 0xC85F_FC00 | (@as(u32, rn) << 5) | rt;
    }

    fn encodeStlxr64Local(rs: u5, rt: u5, rn: u5) u32 {
        return 0xC800_FC00 |
            (@as(u32, rs) << 16) |
            (@as(u32, rn) << 5) |
            rt;
    }

    fn encodeLdar64Local(rt: u5, rn: u5) u32 {
        return 0xC8DF_FC00 | (@as(u32, rn) << 5) | rt;
    }

    fn encodeStlr64Local(rt: u5, rn: u5) u32 {
        return 0xC89F_FC00 | (@as(u32, rn) << 5) | rt;
    }

    fn copyAllocatedSectionsMachO(
        image: []u8,
        writable_image: ?[]u8,
        view: ObjectView,
        output_sections: []const OutputSection,
    ) !void {
        for (output_sections) |output_section| {
            const input_section = try view.sectionByOrdinal(output_section.input_index);
            const dest_image = try imageSliceForRegion(image, writable_image, output_section.region);
            const dest = dest_image[output_section.output_offset .. output_section.output_offset + output_section.size];
            if (input_section.header.isZerofill()) {
                @memset(dest, 0);
                continue;
            }

            const source = try view.sectionData(input_section.ordinal);
            if (source.len != dest.len) return error.InvalidPayloadSectionSize;
            @memcpy(dest, source);
        }
    }

    fn initializeMachOGotSlots(
        writable_image: ?[]u8,
        view: ObjectView,
        prepared: MachOPreparedObject,
        image_bases: PayloadImageBases,
        target_image: ?image_backend.View,
    ) !void {
        if (prepared.got_slots.len == 0) return;

        const writable = writable_image orelse return error.MissingWritablePayloadImage;
        for (prepared.got_slots) |slot| {
            const symbol_ref = try resolveMachOSymbolReference(
                view,
                prepared,
                slot.key.is_external,
                slot.key.symbolnum,
                image_bases,
                target_image,
            );
            const slot_value = try absoluteAddressWithAddend(symbol_ref.linked_address, slot.key.addend);
            try writeU64At(writable, slot.output_offset, slot_value);
        }
    }

    /// Emits the optional Mach-O runtime-entry shim used by PIE-sensitive
    /// writable absolute cells.
    ///
    /// Why this exists:
    /// - the static patcher writes linked-time absolute values into the payload
    ///   image (`slot = linked_symbol_address`)
    /// - Mach-O rebasing metadata is not extended to cover injected payload
    ///   data, so the loader will not rewrite those cells for us
    /// - on PIE targets, the callback therefore needs a tiny runtime once-pass
    ///   that turns every affected cell into
    ///   `runtime = linked + ctx.runtime.load_bias`
    ///
    /// The initialization is protected by a small one-time guard stored in the
    /// writable payload image:
    /// - state 0: never initialized
    /// - state 1: one thread is currently rebasing the cells
    /// - state 2: fixups are complete and all later entries can jump straight
    ///   to the real handler
    ///
    /// The guard uses acquire/release atomics so multiple hooks and multiple
    /// runtime threads can safely share one injected payload image without
    /// repeatedly overwriting user-managed writable state.
    fn emitMachORuntimeEntrySupport(
        image: []u8,
        writable_image: ?[]u8,
        view: ObjectView,
        prepared: MachOPreparedObject,
        image_bases: PayloadImageBases,
        target_image: ?image_backend.View,
    ) !void {
        if (!prepared.needsRuntimeEntryWrapper()) return;

        if (writable_image == null) return error.MissingWritablePayloadImage;

        const primary_base = image_bases.primary;
        const writable_base = image_bases.writable orelse return error.MissingWritablePayloadImageBase;

        const common_offset = prepared.runtime_common_offset;
        const common_code_size = prepared.runtime_common_code_size;
        const literal_offset = prepared.runtime_literal_offset;
        const common_address = primary_base + common_offset;
        const guard_literal_offset = literal_offset;
        const init_retry_offset = common_offset + 3 * 4;
        const fixup_loop_offset = common_offset + 8 * 4;
        const after_fixup_offset = fixup_loop_offset + prepared.runtime_fixups.len * 5 * 4;
        const state_nonzero_offset = after_fixup_offset + 3 * 4;
        const wait_loop_offset = state_nonzero_offset + 3 * 4;
        const init_done_offset = wait_loop_offset + 3 * 4;

        var code_offset = common_offset;
        try writeU32At(image, code_offset, encodeLdrUnsigned64Local(2, 1, machORuntimeLoadBiasOffset()));
        code_offset += 4;
        try writeU32At(image, code_offset, encodeLdrLiteral64Local(3, guard_literal_offset - code_offset));
        code_offset += 4;
        try writeU32At(image, code_offset, encodeAddRegister64(3, 3, 2));
        code_offset += 4;

        try writeU32At(image, code_offset, encodeLdaxr64Local(4, 3));
        code_offset += 4;
        try writeU32At(
            image,
            code_offset,
            try aarch64.encodeCompareAndBranchDelta(
                4,
                @as(i64, @intCast(state_nonzero_offset)) - @as(i64, @intCast(code_offset)),
                true,
                true,
            ),
        );
        code_offset += 4;
        try writeU32At(image, code_offset, encodeMovZLocal(4, runtime_guard_state_initializing));
        code_offset += 4;
        try writeU32At(image, code_offset, encodeStlxr64Local(5, 4, 3));
        code_offset += 4;
        try writeU32At(
            image,
            code_offset,
            try aarch64.encodeCompareAndBranchDelta(
                5,
                @as(i64, @intCast(init_retry_offset)) - @as(i64, @intCast(code_offset)),
                true,
                false,
            ),
        );
        code_offset += 4;

        for (prepared.runtime_fixups, 0..) |fixup, index| {
            const cell_literal_offset = literal_offset +
                @sizeOf(u64) +
                index * runtime_fixup_literal_bytes_per_fixup;
            const symbol_ref = try resolveMachOSymbolReference(
                view,
                prepared,
                fixup.is_external,
                fixup.symbolnum,
                image_bases,
                target_image,
            );
            const needs_load_bias = symbol_ref.requires_load_bias;

            if (!needs_load_bias) {
                try writeU32At(image, code_offset + 0, aarch64_nop);
                try writeU32At(image, code_offset + 4, aarch64_nop);
                try writeU32At(image, code_offset + 8, aarch64_nop);
                try writeU32At(image, code_offset + 12, aarch64_nop);
                try writeU32At(image, code_offset + 16, aarch64_nop);
                try writeU64At(image, cell_literal_offset, 0);
                code_offset += 20;
                continue;
            }

            try writeU32At(image, code_offset, encodeLdrLiteral64Local(5, cell_literal_offset - code_offset));
            code_offset += 4;
            try writeU32At(image, code_offset, encodeAddRegister64(5, 5, 2));
            code_offset += 4;
            try writeU32At(image, code_offset, encodeLdrUnsigned64Local(6, 5, 0));
            code_offset += 4;
            try writeU32At(image, code_offset, encodeAddRegister64(6, 6, 2));
            code_offset += 4;
            try writeU32At(image, code_offset, encodeStrUnsigned64Local(6, 5, 0));
            code_offset += 4;

            const cell_linked_address = writable_base + fixup.output_offset;
            try writeU64At(image, cell_literal_offset, cell_linked_address);
        }

        std.debug.assert(code_offset == after_fixup_offset);

        try writeU32At(image, code_offset, encodeMovZLocal(4, runtime_guard_state_initialized));
        code_offset += 4;
        try writeU32At(image, code_offset, encodeStlr64Local(4, 3));
        code_offset += 4;
        try writeU32At(
            image,
            code_offset,
            try aarch64.encodeBranchImmediate(
                primary_base + code_offset,
                primary_base + init_done_offset,
            ),
        );
        code_offset += 4;

        std.debug.assert(code_offset == state_nonzero_offset);
        try writeU32At(image, code_offset, encodeMovZLocal(6, runtime_guard_state_initialized));
        code_offset += 4;
        try writeU32At(image, code_offset, encodeCmpRegister64Local(4, 6));
        code_offset += 4;
        try writeU32At(
            image,
            code_offset,
            try aarch64.encodeConditionalBranchDelta(
                aarch64_condition_eq,
                @as(i64, @intCast(init_done_offset)) - @as(i64, @intCast(code_offset)),
            ),
        );
        code_offset += 4;

        std.debug.assert(code_offset == wait_loop_offset);
        try writeU32At(image, code_offset, encodeLdar64Local(4, 3));
        code_offset += 4;
        try writeU32At(image, code_offset, encodeCmpRegister64Local(4, 6));
        code_offset += 4;
        try writeU32At(
            image,
            code_offset,
            try aarch64.encodeConditionalBranchDelta(
                aarch64_condition_ne,
                @as(i64, @intCast(wait_loop_offset)) - @as(i64, @intCast(code_offset)),
            ),
        );
        code_offset += 4;

        std.debug.assert(code_offset == init_done_offset);
        try writeU32At(image, code_offset, encodeAddRegister64(16, 16, 2));
        code_offset += 4;
        try writeU32At(image, code_offset, encodeBrLocal(16));
        code_offset += 4;

        try writeU64At(
            image,
            guard_literal_offset,
            writable_base + prepared.runtime_guard_output_offset,
        );

        while (code_offset < common_offset + common_code_size) : (code_offset += 4) {
            try writeU32At(image, code_offset, aarch64_nop);
        }
        std.debug.assert(code_offset == common_offset + common_code_size);

        for (prepared.entry_wrappers) |wrapper| {
            const wrapper_address = primary_base + wrapper.wrapper_offset;
            const handler_linked_address = primary_base + wrapper.target_offset;
            try writeU32At(image, wrapper.wrapper_offset + 0, encodeLdrLiteral64Local(16, 8));
            try writeU32At(
                image,
                wrapper.wrapper_offset + 4,
                try aarch64.encodeBranchImmediate(wrapper_address + 4, common_address),
            );
            try writeU64At(image, wrapper.wrapper_offset + 8, handler_linked_address);
        }
    }

    /// Applies the supported arm64 Mach-O relocation subset to the emitted
    /// payload image.
    ///
    /// Important invariant:
    /// every relocation is interpreted relative to the final injected payload
    /// base address chosen by the binary rewriter, not relative to the object
    /// file's placeholder addresses.
    fn applyMachORelocations(
        image: []u8,
        writable_image: ?[]u8,
        view: ObjectView,
        prepared: MachOPreparedObject,
        image_bases: PayloadImageBases,
        target_image: ?image_backend.View,
    ) !void {
        for (view.sections) |section| {
            const mapped_target = prepared.section_map[section.ordinal] orelse continue;
            const relocs = try view.sectionRelocations(section.ordinal);
            const output_section = prepared.output_sections[mapped_target];
            const patch_image = try imageSliceForRegion(image, writable_image, output_section.region);
            const place_base = try baseAddressForRegion(image_bases, output_section.region);

            var pending_addend: ?PendingAddend = null;
            for (relocs) |reloc| {
                const relocation_type = std.meta.intToEnum(macho.reloc_type_arm64, reloc.r_type) catch {
                    noteMachORelocationFailure(view, section, reloc, error.UnsupportedPayloadRelocation);
                    return error.UnsupportedPayloadRelocation;
                };

                if (relocation_type == .ARM64_RELOC_ADDEND) {
                    if (pending_addend != null) return error.InvalidPayloadRelocationTable;
                    pending_addend = .{
                        .address = reloc.r_address,
                        .addend = decodeAddend(reloc),
                    };
                    continue;
                }

                const explicit_addend = if (pending_addend) |pair| blk: {
                    if (pair.address != reloc.r_address) return error.InvalidPayloadRelocationTable;
                    pending_addend = null;
                    break :blk pair.addend;
                } else 0;

                const patch_offset = try machOPatchOffset(output_section, reloc);
                const place_address = try addAddressOffset(place_base, patch_offset);

                applyRelocation(
                    patch_image,
                    view,
                    prepared,
                    section,
                    output_section,
                    patch_offset,
                    image_bases,
                    place_address,
                    reloc,
                    relocation_type,
                    explicit_addend,
                    target_image,
                ) catch |err| {
                    noteMachORelocationFailure(view, section, reloc, err);
                    return err;
                };
            }

            if (pending_addend != null) return error.InvalidPayloadRelocationTable;
        }
    }

    /// Converts a Mach-O section-relative relocation address into an offset in
    /// the final emitted payload image.
    ///
    /// The concrete read/write helpers still perform the final width-specific
    /// bounds checks. This helper only guarantees that the relocation starts
    /// inside the mapped output section.
    fn machOPatchOffset(output_section: OutputSection, reloc: macho.relocation_info) !usize {
        if (reloc.r_address < 0) return error.InvalidPayloadRelocationOffset;
        const section_relative_offset: usize = @intCast(reloc.r_address);
        if (section_relative_offset >= output_section.size) {
            return error.InvalidPayloadRelocationOffset;
        }
        return output_section.output_offset + section_relative_offset;
    }

    fn imageSliceForRegion(
        primary_image: []u8,
        writable_image: ?[]u8,
        region: PayloadImageRegion,
    ) ![]u8 {
        return switch (region) {
            .primary => primary_image,
            .writable => writable_image orelse error.MissingWritablePayloadImage,
        };
    }

    fn baseAddressForRegion(image_bases: PayloadImageBases, region: PayloadImageRegion) !u64 {
        return switch (region) {
            .primary => image_bases.primary,
            .writable => image_bases.writable orelse error.MissingWritablePayloadImageBase,
        };
    }

    fn applyRelocation(
        image: []u8,
        view: ObjectView,
        prepared: MachOPreparedObject,
        section: SectionRef,
        output_section: OutputSection,
        patch_offset: usize,
        image_bases: PayloadImageBases,
        place_address: u64,
        reloc: macho.relocation_info,
        relocation_type: macho.reloc_type_arm64,
        explicit_addend: i64,
        target_image: ?image_backend.View,
    ) !void {
        try ensureMachORelocationIsSupportedForTargetImage(view, section, output_section, reloc, relocation_type, target_image);

        switch (relocation_type) {
            .ARM64_RELOC_UNSIGNED => {
                const symbol_ref = try resolveMachORelocationSymbolReference(
                    view,
                    prepared,
                    reloc,
                    image_bases,
                    target_image,
                );
                try ensureMachOUnsignedRuntimeFixupIsSupported(
                    view,
                    section,
                    output_section,
                    reloc,
                    symbol_ref,
                    target_image,
                );
                switch (reloc.r_length) {
                    2 => {
                        const addend = try readU32At(image, patch_offset);
                        const value = try absoluteAddressWithAddend(symbol_ref.linked_address, addend);
                        if (value > std.math.maxInt(u32)) return error.PayloadRelocationOverflow;
                        try writeU32At(image, patch_offset, @intCast(value));
                    },
                    3 => {
                        const addend = try readU64At(image, patch_offset);
                        const value = try absoluteAddressWithAddend(symbol_ref.linked_address, @intCast(addend));
                        try writeU64At(image, patch_offset, value);
                    },
                    else => return error.UnsupportedPayloadRelocation,
                }
            },
            .ARM64_RELOC_BRANCH26 => {
                const symbol_address = try resolveMachORelocationSymbolAddress(
                    view,
                    prepared,
                    reloc,
                    image_bases,
                    target_image,
                );
                const target_address = try absoluteAddressWithAddend(symbol_address, explicit_addend);
                const delta = try relativeDeltaWithAddend(target_address, 0, place_address);
                try patchBranchImmediate26(image, patch_offset, delta);
            },
            .ARM64_RELOC_PAGE21 => {
                const symbol_address = try resolveMachORelocationSymbolAddress(
                    view,
                    prepared,
                    reloc,
                    image_bases,
                    target_image,
                );
                const target_address = try absoluteAddressWithAddend(symbol_address, explicit_addend);
                try patchAdrpImmediate21(image, patch_offset, place_address, target_address);
            },
            .ARM64_RELOC_PAGEOFF12 => {
                const symbol_address = try resolveMachORelocationSymbolAddress(
                    view,
                    prepared,
                    reloc,
                    image_bases,
                    target_image,
                );
                const target_address = try absoluteAddressWithAddend(symbol_address, explicit_addend);
                const opcode = try readU32At(image, patch_offset);
                try patchImmediateLo12(image, patch_offset, target_address, try pageOffShiftForInstruction(opcode));
            },
            .ARM64_RELOC_GOT_LOAD_PAGE21 => {
                const target_address = try resolveMachOGotSlotAddress(prepared, reloc, explicit_addend, image_bases);
                try patchAdrpImmediate21(image, patch_offset, place_address, target_address);
            },
            .ARM64_RELOC_GOT_LOAD_PAGEOFF12 => {
                const target_address = try resolveMachOGotSlotAddress(prepared, reloc, explicit_addend, image_bases);
                const opcode = try readU32At(image, patch_offset);
                try patchImmediateLo12(image, patch_offset, target_address, try pageOffShiftForInstruction(opcode));
            },
            else => return error.UnsupportedPayloadRelocation,
        }
    }

    fn ensureMachORelocationIsSupportedForTargetImage(
        view: ObjectView,
        section: SectionRef,
        output_section: OutputSection,
        reloc: macho.relocation_info,
        relocation_type: macho.reloc_type_arm64,
        target_image: ?image_backend.View,
    ) !void {
        _ = output_section;
        if (!targetImageRequiresPieSafeRelocations(target_image)) return;

        switch (relocation_type) {
            .ARM64_RELOC_POINTER_TO_GOT,
            .ARM64_RELOC_TLVP_LOAD_PAGE21,
            .ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
            .ARM64_RELOC_SUBTRACTOR,
            => {
                recordLinkDiagnostic(
                    "unsupported Mach-O arm64 payload relocation {s} for {s} in section {s},{s} (binding={s}, {s}, width={d}): relocation family is not implemented for PIE-safe injected payloads in a PIE target image yet",
                    .{
                        machORelocationNameString(relocation_type),
                        machORelocationSymbolName(view, reloc),
                        sectionSegName(section),
                        sectionSectName(section),
                        machORelocationBindingString(reloc),
                        machORelocationPlaceString(reloc),
                        machORelocationWidthBits(reloc),
                    },
                );
                return error.UnsupportedPayloadRelocation;
            },
            else => {},
        }
    }

    fn ensureMachOUnsignedRuntimeFixupIsSupported(
        view: ObjectView,
        section: SectionRef,
        output_section: OutputSection,
        reloc: macho.relocation_info,
        symbol_ref: MachOSymbolReference,
        target_image: ?image_backend.View,
    ) !void {
        if (!targetImageRequiresPieSafeRelocations(target_image)) return;
        if (!symbol_ref.requires_load_bias) return;

        if (output_section.region != .writable) {
            recordLinkDiagnostic(
                "unsupported Mach-O arm64 payload relocation {s} for {s} in section {s},{s} (binding={s}, {s}, width={d}): relocation requires a runtime load-bias fixup but the destination cell lives in the primary read-only payload image",
                .{
                    machORelocationNameString(.ARM64_RELOC_UNSIGNED),
                    machORelocationSymbolName(view, reloc),
                    sectionSegName(section),
                    sectionSectName(section),
                    machORelocationBindingString(reloc),
                    machORelocationPlaceString(reloc),
                    machORelocationWidthBits(reloc),
                },
            );
            return error.UnsupportedPayloadRelocation;
        }

        if (reloc.r_length != 3) {
            recordLinkDiagnostic(
                "unsupported Mach-O arm64 payload relocation {s} for {s} in section {s},{s} (binding={s}, {s}, width={d}): relocation requires a runtime load-bias fixup but only writable 64-bit pointer cells are supported",
                .{
                    machORelocationNameString(.ARM64_RELOC_UNSIGNED),
                    machORelocationSymbolName(view, reloc),
                    sectionSegName(section),
                    sectionSectName(section),
                    machORelocationBindingString(reloc),
                    machORelocationPlaceString(reloc),
                    machORelocationWidthBits(reloc),
                },
            );
            return error.UnsupportedPayloadRelocation;
        }
    }

    fn resolveMachORelocationSymbolReference(
        view: ObjectView,
        prepared: MachOPreparedObject,
        reloc: macho.relocation_info,
        image_bases: PayloadImageBases,
        target_image: ?image_backend.View,
    ) !MachOSymbolReference {
        return resolveMachOSymbolReference(
            view,
            prepared,
            reloc.r_extern != 0,
            reloc.r_symbolnum,
            image_bases,
            target_image,
        );
    }

    fn resolveMachORelocationSymbolAddress(
        view: ObjectView,
        prepared: MachOPreparedObject,
        reloc: macho.relocation_info,
        image_bases: PayloadImageBases,
        target_image: ?image_backend.View,
    ) !u64 {
        return (try resolveMachORelocationSymbolReference(
            view,
            prepared,
            reloc,
            image_bases,
            target_image,
        )).linked_address;
    }

    fn resolveMachOSymbolReference(
        view: ObjectView,
        prepared: MachOPreparedObject,
        is_external: bool,
        symbolnum: u24,
        image_bases: PayloadImageBases,
        target_image: ?image_backend.View,
    ) !MachOSymbolReference {
        if (!is_external) {
            if (symbolnum == r_abs_symbolnum) {
                return .{
                    .linked_address = 0,
                    .requires_load_bias = false,
                };
            }
            return .{
                .linked_address = try resolveSectionOrdinalAddress(view, prepared, symbolnum, image_bases),
                .requires_load_bias = true,
            };
        }

        const symbol_index: usize = symbolnum;
        if (symbol_index >= view.symbols.len) return error.InvalidPayloadSymbolIndex;
        const symbol = view.symbols[symbol_index];

        if (symbol.stab()) return error.UnsupportedPayloadRelocation;
        if (symbol.abs()) {
            return .{
                .linked_address = symbol.n_value,
                .requires_load_bias = false,
            };
        }
        if (symbol.sect()) {
            return .{
                .linked_address = try resolveSymbolAddressInPayload(view, prepared, symbol, image_bases),
                .requires_load_bias = true,
            };
        }

        if (symbol.undf()) {
            if (symbol.tentative()) return error.UnsupportedPayloadCommonSymbol;

            const symbol_name = machoObjectString(view.strtab, symbol.n_strx);
            if (symbol.weakRef()) {
                if (symbol_name.len == 0 or target_image == null) {
                    return .{
                        .linked_address = 0,
                        .requires_load_bias = false,
                    };
                }
                const linked_address = lookupTargetImageSymbolAddress(target_image.?, symbol_name) catch 0;
                return .{
                    .linked_address = linked_address,
                    .requires_load_bias = linked_address != 0,
                };
            }

            if (symbol_name.len == 0 or target_image == null) return error.UnsupportedPayloadExternalSymbol;
            return .{
                .linked_address = try lookupTargetImageSymbolAddress(target_image.?, symbol_name),
                .requires_load_bias = true,
            };
        }

        return error.UnsupportedPayloadSymbolType;
    }

    fn resolveMachOGotSlotAddress(
        prepared: MachOPreparedObject,
        reloc: macho.relocation_info,
        explicit_addend: i64,
        image_bases: PayloadImageBases,
    ) !u64 {
        const writable_base = image_bases.writable orelse return error.MissingWritablePayloadImageBase;
        const slot_index = findMachOGotSlotIndex(
            prepared.got_slots,
            reloc.r_extern != 0,
            reloc.r_symbolnum,
            explicit_addend,
        ) orelse return error.InvalidPayloadGotSlot;
        return addAddressOffset(writable_base, prepared.got_slots[slot_index].output_offset);
    }

    /// Resolves a non-external relocation target that names a section ordinal.
    ///
    /// Mach-O `MH_OBJECT` files use 1-based section ordinals. For the regular
    /// arm64 objects emitted by clang/zig cc, section virtual addresses inside
    /// the object are typically zero, so the linked address is simply the
    /// injected image base plus the output-section offset.
    fn resolveSectionOrdinalAddress(
        view: ObjectView,
        prepared: MachOPreparedObject,
        ordinal_u24: anytype,
        image_bases: PayloadImageBases,
    ) !u64 {
        const ordinal: usize = ordinal_u24;
        if (ordinal >= prepared.section_map.len) return error.InvalidPayloadSymbolSection;
        const mapped_index = prepared.section_map[ordinal] orelse return error.SymbolTargetsDroppedSection;
        const output_section = prepared.output_sections[mapped_index];
        _ = try view.sectionByOrdinal(ordinal);
        return addAddressOffset(try baseAddressForRegion(image_bases, output_section.region), output_section.output_offset);
    }

    fn resolveSymbolAddressInPayload(
        view: ObjectView,
        prepared: MachOPreparedObject,
        symbol: macho.nlist_64,
        image_bases: PayloadImageBases,
    ) !u64 {
        const ordinal: usize = symbol.n_sect;
        if (ordinal >= prepared.section_map.len) return error.InvalidPayloadSymbolSection;
        const mapped_index = prepared.section_map[ordinal] orelse return error.SymbolTargetsDroppedSection;
        const output_section = prepared.output_sections[mapped_index];
        const input_section = try view.sectionByOrdinal(ordinal);
        if (symbol.n_value < input_section.header.addr) return error.PayloadSymbolOutOfRange;
        const symbol_offset = symbol.n_value - input_section.header.addr;
        if (symbol_offset > output_section.size) return error.PayloadSymbolOutOfRange;
        return addAddressOffset(
            try baseAddressForRegion(image_bases, output_section.region),
            output_section.output_offset + @as(usize, @intCast(symbol_offset)),
        );
    }

    fn noteMachORelocationFailure(
        view: ObjectView,
        section: SectionRef,
        reloc: macho.relocation_info,
        err: anyerror,
    ) void {
        // Some callers record a more specific reason before bubbling the error
        // back out here, especially PIE-policy rejections. Preserve that richer
        // message instead of overwriting it with a generic "failed to apply"
        // summary that would force the user back into the source to understand
        // what actually happened.
        if (hasPendingLinkDiagnostic() and err == error.UnsupportedPayloadRelocation) return;

        switch (err) {
            error.UnsupportedPayloadRelocation,
            error.UnsupportedPayloadExternalSymbol,
            error.SymbolNotFound,
            => recordLinkDiagnostic(
                "unable to apply Mach-O arm64 payload relocation {s} for {s} in section {s},{s} at 0x{x} (binding={s}, {s}, width={d}): {s}",
                .{
                    machORelocationNameString(std.meta.intToEnum(macho.reloc_type_arm64, reloc.r_type) catch .ARM64_RELOC_UNSIGNED),
                    machORelocationSymbolName(view, reloc),
                    sectionSegName(section),
                    sectionSectName(section),
                    reloc.r_address,
                    machORelocationBindingString(reloc),
                    machORelocationPlaceString(reloc),
                    machORelocationWidthBits(reloc),
                    @errorName(err),
                },
            ),
            else => {},
        }
    }

    fn machORelocationSymbolName(view: ObjectView, reloc: macho.relocation_info) []const u8 {
        if (reloc.r_extern != 0) return view.symbolNameByIndex(reloc.r_symbolnum);
        if (reloc.r_symbolnum == r_abs_symbolnum) return "<absolute>";

        const ordinal: usize = reloc.r_symbolnum;
        if (ordinal == 0 or ordinal > view.sections.len) return "<invalid-section-ordinal>";
        return sectionSectName(view.sections[ordinal - 1]);
    }

    fn machORelocationNameString(relocation_type: macho.reloc_type_arm64) []const u8 {
        return @tagName(relocation_type);
    }

    fn machORelocationBindingString(reloc: macho.relocation_info) []const u8 {
        return if (reloc.r_extern != 0)
            "extern"
        else if (reloc.r_symbolnum == r_abs_symbolnum)
            "absolute"
        else
            "section-local";
    }

    fn machORelocationPlaceString(reloc: macho.relocation_info) []const u8 {
        return if (reloc.r_pcrel != 0) "pcrel" else "absolute-place";
    }

    fn machORelocationWidthBits(reloc: macho.relocation_info) u16 {
        return switch (reloc.r_length) {
            0 => 8,
            1 => 16,
            2 => 32,
            3 => 64,
        };
    }

    fn sectionSegName(section: SectionRef) []const u8 {
        return parseFixedName(section.header.segname[0..]);
    }

    fn sectionSectName(section: SectionRef) []const u8 {
        return parseFixedName(section.header.sectname[0..]);
    }

    fn decodeAddend(reloc: macho.relocation_info) i64 {
        const raw: u32 = reloc.r_symbolnum;
        const extended = if ((raw & 0x0080_0000) != 0)
            raw | 0xFF00_0000
        else
            raw;
        const signed: i32 = @bitCast(extended);
        return signed;
    }

    /// Derives the low-12 relocation scale from the instruction encoding.
    ///
    /// Mach-O arm64 only gives us `PAGEOFF12`; it does not spell out whether
    /// the consumer is `add`, `ldr`, `str`, `ldrh`, and so on. The linker must
    /// therefore inspect the patched instruction and recover the scale from the
    /// encoding class itself.
    fn pageOffShiftForInstruction(opcode: u32) !u6 {
        // ADD/SUB (immediate): imm12 is byte-scaled when sh == 0.
        if ((opcode & 0x1F00_0000) == 0x1100_0000) {
            if (((opcode >> 22) & 1) != 0) return error.UnsupportedPayloadRelocation;
            return 0;
        }

        // Load/store unsigned immediate.
        //
        // Two relevant arm64 encoding families land here:
        // - the classic scalar integer loads/stores, where `size[31:30]`
        //   directly carries the byte scale
        // - the SIMD/FP unsigned-immediate forms Zig also emits for payload
        //   authoring patterns such as copying a 16-byte `{ ptr, len }`
        //   constant into a local `[]u8` slice descriptor before calling
        //   `zrstd.debug.print`
        //
        // The latter matters for Mach-O because PAGEOFF12 only gives us the
        // final symbol address; the linker still has to recover the scale from
        // the consumer instruction itself. Q-register loads/stores encode a
        // 16-byte scale even though `size[31:30] == 0`, so blindly reusing the
        // scalar decoder would patch the raw byte offset into the imm12 field
        // and overshoot the target by another factor of 16 at runtime.
        if ((opcode & 0x3B00_0000) == 0x3900_0000) {
            if (((opcode >> 30) & 0x3) == 0 and ((opcode >> 23) & 1) != 0) {
                return 4;
            }
            return @intCast((opcode >> 30) & 0x3);
        }

        return error.UnsupportedPayloadRelocation;
    }
};

fn elfTargetImage(target_image: ?image_backend.View) !?ElfView {
    if (target_image == null) return null;
    return switch (target_image.?) {
        .elf => |view| view,
        .macho => error.UnsupportedPayloadTargetImage,
    };
}

fn lookupTargetImageSymbolAddress(target_image: image_backend.View, symbol_name: []const u8) !u64 {
    return target_image.resolveSymbolAddress(symbol_name) catch |err| {
        if (symbol_name.len != 0 and symbol_name[0] == '_') {
            return target_image.resolveSymbolAddress(symbol_name[1..]);
        }
        return err;
    };
}

fn targetImageRequiresPieSafeRelocations(target_image: ?image_backend.View) bool {
    return switch (target_image orelse return false) {
        .elf => |view| view.ehdr.e_type == elf.ET.DYN,
        .macho => |view| view.isPie(),
    };
}

fn machoObjectString(strtab: []const u8, offset: u32) []const u8 {
    const start: usize = offset;
    if (start >= strtab.len) return "";
    const end_rel = std.mem.indexOfScalar(u8, strtab[start..], 0) orelse strtab.len - start;
    return strtab[start .. start + end_rel];
}

fn matchesUserSymbolName(symbol_name: []const u8, requested_name: []const u8) bool {
    if (std.mem.eql(u8, symbol_name, requested_name)) return true;
    if (symbol_name.len != 0 and symbol_name[0] == '_') {
        return std.mem.eql(u8, symbol_name[1..], requested_name);
    }
    return false;
}

fn parseFixedName(name: []const u8) []const u8 {
    const len = std.mem.indexOfScalar(u8, name, 0) orelse name.len;
    return name[0..len];
}

fn readU32At(image: []const u8, offset: usize) !u32 {
    if (offset + @sizeOf(u32) > image.len) return error.PayloadRelocationOutOfRange;
    const ptr: *const [4]u8 = @ptrCast(image[offset .. offset + 4].ptr);
    return std.mem.readInt(u32, ptr, .little);
}

fn readU64At(image: []const u8, offset: usize) !u64 {
    if (offset + @sizeOf(u64) > image.len) return error.PayloadRelocationOutOfRange;
    const ptr: *const [8]u8 = @ptrCast(image[offset .. offset + 8].ptr);
    return std.mem.readInt(u64, ptr, .little);
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

/// Read-only sibling of `sliceStructs`.
///
/// The Mach-O payload linker walks load commands, sections, symbols, and
/// relocation tables directly out of the original object bytes. Keeping this
/// helper local makes the zero-copy parsing style explicit and avoids sprinkling
/// the alignment-sensitive `bytesAsSlice` pattern throughout the linker.
fn sliceConstStructs(comptime T: type, bytes: []const u8, offset: usize, count: usize) []align(1) const T {
    const byte_len = count * @sizeOf(T);
    return std.mem.bytesAsSlice(T, bytes[offset .. offset + byte_len]);
}

test "Mach-O PAGEOFF12 scale decoder handles scalar and q-register unsigned loads" {
    try std.testing.expectEqual(@as(u6, 2), try macho_linker.pageOffShiftForInstruction(0xBD40_0400));
    try std.testing.expectEqual(@as(u6, 3), try macho_linker.pageOffShiftForInstruction(0xFD40_0400));
    try std.testing.expectEqual(@as(u6, 4), try macho_linker.pageOffShiftForInstruction(0x3DC0_0100));
    try std.testing.expectEqual(@as(u6, 4), try macho_linker.pageOffShiftForInstruction(0x3D80_0400));
}
