const std = @import("std");
const macho = std.macho;
const image_backend = @import("../image_backend.zig");
const aarch64 = @import("../../isa/aarch64/root.zig");
const HookContext = @import("../../sdk/aarch64_context.zig").HookContext;
const HookRuntimeInfo = @import("../../sdk/aarch64_context.zig").HookRuntimeInfo;
const shared = @import("object_shared.zig");

const aarch64_nop: u32 = 0xD503_201F;
const PayloadLayout = shared.PayloadLayout;
const LoadedPayload = shared.LoadedPayload;
const OutputSection = shared.OutputSection;
const PayloadImageRegion = shared.PayloadImageRegion;
const PayloadImageBases = shared.PayloadImageBases;
const hasPendingLinkDiagnostic = shared.hasPendingLinkDiagnostic;
const recordLinkDiagnostic = shared.recordLinkDiagnostic;
const absoluteAddressWithAddend = shared.absoluteAddressWithAddend;
const relativeDeltaWithAddend = shared.relativeDeltaWithAddend;
const addAddressOffset = shared.addAddressOffset;
const patchBranchImmediate26 = shared.patchBranchImmediate26;
const patchAdrpImmediate21 = shared.patchAdrpImmediate21;
const patchImmediateLo12 = shared.patchImmediateLo12;
const lookupTargetImageSymbolAddress = shared.lookupTargetImageSymbolAddress;
const targetImageRequiresPieSafeRelocations = shared.targetImageRequiresPieSafeRelocations;
const machoObjectString = shared.machoObjectString;
const matchesUserSymbolName = shared.matchesUserSymbolName;
const parseFixedName = shared.parseFixedName;
const readU32At = shared.readU32At;
const readU64At = shared.readU64At;
const writeU32At = shared.writeU32At;
const writeU64At = shared.writeU64At;
const sliceConstStructs = shared.sliceConstStructs;

pub const macho_linker = struct {
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

test "Mach-O PAGEOFF12 scale decoder handles scalar and q-register unsigned loads" {
    try std.testing.expectEqual(@as(u6, 2), try macho_linker.pageOffShiftForInstruction(0xBD40_0400));
    try std.testing.expectEqual(@as(u6, 3), try macho_linker.pageOffShiftForInstruction(0xFD40_0400));
    try std.testing.expectEqual(@as(u6, 4), try macho_linker.pageOffShiftForInstruction(0x3DC0_0100));
    try std.testing.expectEqual(@as(u6, 4), try macho_linker.pageOffShiftForInstruction(0x3D80_0400));
}
