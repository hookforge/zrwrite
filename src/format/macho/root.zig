const std = @import("std");
const macho = std.macho;

const macho_diagnostic_capacity = 1024;
threadlocal var last_macho_diagnostic_buf: [macho_diagnostic_capacity]u8 = undefined;
threadlocal var last_macho_diagnostic_len: usize = 0;

/// The full Mach-O rewrite backend is still under construction.
///
/// `supported` therefore remains `false` even though the lightweight `View`
/// below is now real and already useful for backend-neutral tasks such as:
/// - image-format autodetection
/// - address/file-offset mapping
/// - symbol lookup
/// - code-range enumeration for pattern scanning
pub const supported = false;

/// Clears the most recent Mach-O backend diagnostic.
///
/// The low-level Mach-O mutator occasionally needs to reject an image even
/// though the file is still structurally parseable. Code-signature stripping is
/// the main example today: some layouts are safe to repair for a later
/// `codesign -f -s -`, while others are ambiguous enough that we should stop
/// and explain why instead of emitting a "maybe runnable" output.
pub fn clearLastDiagnostic() void {
    last_macho_diagnostic_len = 0;
}

/// Returns the most recent Mach-O backend diagnostic, if any.
pub fn lastDiagnosticMessage() ?[]const u8 {
    if (last_macho_diagnostic_len == 0) return null;
    return last_macho_diagnostic_buf[0..last_macho_diagnostic_len];
}

pub const ExecutableRange = struct {
    address: u64,
    file_offset: usize,
    size: usize,
};

pub const BlobRange = struct {
    offset: usize,
    size: usize,
};

pub const SegmentRef = struct {
    load_command_index: usize,
    command: *align(1) macho.segment_command_64,
    sections: []align(1) macho.section_64,

    pub fn segName(self: SegmentRef) []const u8 {
        return parseFixedName(self.command.segname[0..]);
    }

    pub fn fileEnd(self: SegmentRef) u64 {
        return self.command.fileoff + self.command.filesize;
    }

    pub fn memoryEnd(self: SegmentRef) u64 {
        return self.command.vmaddr + self.command.vmsize;
    }
};

/// Describes where a future injected payload blob would live inside a Mach-O.
///
/// Current design choice:
/// - do not add a new segment load command yet
/// - instead, extend the last file-backed segment that appears before
///   `__LINKEDIT`
/// - use any existing file slack first
/// - only shift the `__LINKEDIT` tail when the injected blob overflows that
///   slack
///
/// This keeps the first Mach-O mutation stage materially simpler than full
/// segment-table surgery while still matching the current Linux/ELF injection
/// model closely enough for the higher layers.
pub const InjectionPlan = struct {
    carrier_segment_index: usize,
    linkedit_segment_index: usize,
    injection_offset: usize,
    injection_end_offset: usize,
    tail_offset: usize,
    tail_shift: usize,
    total_len: usize,
    payload_base_address: u64,

    pub fn fitsExistingSlack(self: InjectionPlan) bool {
        return self.tail_shift == 0;
    }
};

pub const RegionInjectionPlan = struct {
    carrier_segment_index: usize,
    injection_offset: usize,
    injection_end_offset: usize,
    tail_offset: usize,
    tail_shift: usize,
    payload_base_address: u64,
    make_executable: bool,

    pub fn fitsExistingSlack(self: RegionInjectionPlan) bool {
        return self.tail_shift == 0;
    }
};

/// Two-region Mach-O injection plan used when payload code must stay separate
/// from writable payload state.
///
/// The primary use case is macOS arm64 runtime closure:
/// - executable code and read-only literals live in the executable region
/// - `.data/.bss` state lives in the writable region
/// - the patched output therefore does not rely on a single segment being both
///   executable and writable after ad-hoc signing
pub const SplitInjectionPlan = struct {
    executable: RegionInjectionPlan,
    writable: ?RegionInjectionPlan = null,
    total_len: usize,

    pub fn hasWritableRegion(self: SplitInjectionPlan) bool {
        return self.writable != null;
    }
};

pub const View = struct {
    bytes: []u8,
    header: *align(1) macho.mach_header_64,
    load_commands: []u8,

    pub fn parse(image_bytes: []u8) !View {
        if (image_bytes.len < @sizeOf(macho.mach_header_64)) return error.InvalidMachO;

        const magic = readMagic(image_bytes);
        switch (magic) {
            macho.MH_MAGIC_64 => {},
            macho.FAT_MAGIC, macho.FAT_CIGAM, macho.FAT_MAGIC_64, macho.FAT_CIGAM_64 => {
                return error.UnsupportedFatMachO;
            },
            macho.MH_CIGAM_64 => return error.UnsupportedBigEndianMachO,
            else => return error.InvalidMachOMagic,
        }

        const header = std.mem.bytesAsValue(macho.mach_header_64, image_bytes[0..@sizeOf(macho.mach_header_64)]);
        if (header.cputype != macho.CPU_TYPE_ARM64) return error.UnsupportedMachine;
        switch (header.filetype) {
            macho.MH_EXECUTE, macho.MH_DYLIB, macho.MH_BUNDLE => {},
            else => return error.UnsupportedMachOFileType,
        }

        const load_commands_offset = @sizeOf(macho.mach_header_64);
        const load_commands_size: usize = @intCast(header.sizeofcmds);
        if (load_commands_offset + load_commands_size > image_bytes.len) return error.InvalidMachOLoadCommands;

        var cursor: usize = load_commands_offset;
        var remaining = header.ncmds;
        while (remaining != 0) : (remaining -= 1) {
            if (cursor + @sizeOf(macho.load_command) > load_commands_offset + load_commands_size) {
                return error.InvalidMachOLoadCommands;
            }

            const load_command = std.mem.bytesAsValue(
                macho.load_command,
                image_bytes[cursor .. cursor + @sizeOf(macho.load_command)],
            );
            if (load_command.cmdsize < @sizeOf(macho.load_command)) return error.InvalidMachOLoadCommand;
            if (cursor + load_command.cmdsize > load_commands_offset + load_commands_size) {
                return error.InvalidMachOLoadCommand;
            }

            if (load_command.cmd == .SEGMENT_64) {
                const segment = std.mem.bytesAsValue(
                    macho.segment_command_64,
                    image_bytes[cursor .. cursor + @sizeOf(macho.segment_command_64)],
                );
                const sections_size = @as(usize, segment.nsects) * @sizeOf(macho.section_64);
                if (@sizeOf(macho.segment_command_64) + sections_size > load_command.cmdsize) {
                    return error.InvalidMachOSegmentCommand;
                }
            }

            cursor += load_command.cmdsize;
        }

        return .{
            .bytes = image_bytes,
            .header = header,
            .load_commands = image_bytes[load_commands_offset .. load_commands_offset + load_commands_size],
        };
    }

    pub fn addressToOffset(self: View, address: u64) !usize {
        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;
            const segment = command.segment64();
            if (segment.filesize == 0) continue;

            const seg_start = segment.vmaddr;
            const seg_end = segment.vmaddr + segment.filesize;
            if (address >= seg_start and address < seg_end) {
                return @intCast(segment.fileoff + (address - seg_start));
            }
        }
        return error.AddressNotMapped;
    }

    pub fn offsetToAddress(self: View, file_offset: u64) !u64 {
        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;
            const segment = command.segment64();
            if (segment.filesize == 0) continue;

            const seg_start = segment.fileoff;
            const seg_end = segment.fileoff + segment.filesize;
            if (file_offset >= seg_start and file_offset < seg_end) {
                return segment.vmaddr + (file_offset - seg_start);
            }
        }
        return error.OffsetNotMapped;
    }

    pub fn resolveSymbolAddress(self: View, name: []const u8) !u64 {
        const symtab = (try self.symtabCommand()) orelse return error.SymbolNotFound;
        const symbols = try self.symbolTable(symtab);
        const strtab = try self.stringTable(symtab);

        var fallback: ?u64 = null;
        for (symbols) |symbol| {
            if (symbol.n_strx == 0) continue;
            if (symbol.stab()) continue;
            if (symbol.undf()) continue;

            const symbol_name = getString(strtab, symbol.n_strx);
            if (!matchesUserSymbolName(symbol_name, name)) continue;

            if (symbol.sect() or symbol.abs()) return symbol.n_value;
            fallback = symbol.n_value;
        }

        return fallback orelse error.SymbolNotFound;
    }

    pub fn executableRanges(self: View, allocator: std.mem.Allocator) ![]ExecutableRange {
        var ranges: std.ArrayList(ExecutableRange) = .empty;
        defer ranges.deinit(allocator);

        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;
            const segment = command.segment64();
            if ((segment.initprot & macho.PROT.EXEC) == 0) continue;

            if (segment.nsects == 0) {
                if (segment.filesize == 0) continue;
                try ranges.append(allocator, .{
                    .address = segment.vmaddr,
                    .file_offset = @intCast(segment.fileoff),
                    .size = @intCast(segment.filesize),
                });
                continue;
            }

            for (command.sections64()) |section| {
                if (section.isZerofill()) continue;
                if (!section.isCode()) continue;
                if (section.size == 0) continue;

                try ranges.append(allocator, .{
                    .address = section.addr,
                    .file_offset = section.offset,
                    .size = @intCast(section.size),
                });
            }
        }

        return ranges.toOwnedSlice(allocator);
    }

    pub fn hasAarch64BtiProperty(self: View) bool {
        _ = self;
        return false;
    }

    pub fn isPie(self: View) bool {
        return (self.header.flags & macho.MH_PIE) != 0;
    }

    pub fn segmentByName(self: View, segment_name: []const u8) !SegmentRef {
        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;

            const segment = command.segment64();
            if (!std.mem.eql(u8, parseFixedName(segment.segname[0..]), segment_name)) continue;

            return .{
                .load_command_index = command.index,
                .command = segment,
                .sections = command.sections64(),
            };
        }
        return error.SegmentNotFound;
    }

    /// Returns the highest-addressed file-backed segment that precedes
    /// `__LINKEDIT`.
    ///
    /// That segment becomes the current Mach-O injection carrier. Picking the
    /// segment with the largest in-memory end keeps the injected payload at the
    /// end of the existing mapped image instead of punching a hole between
    /// earlier segments.
    pub fn carrierSegmentForInjection(self: View) !SegmentRef {
        const linkedit = try self.segmentByName("__LINKEDIT");

        var best: ?SegmentRef = null;
        var best_end: u64 = 0;

        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;

            const segment = command.segment64();
            if (segment.filesize == 0) continue;
            if (segment.fileoff >= linkedit.command.fileoff) continue;
            if (std.mem.eql(u8, parseFixedName(segment.segname[0..]), "__PAGEZERO")) continue;

            const end = segment.fileoff + @max(segment.filesize, segment.vmsize);
            if (best == null or end > best_end) {
                best = .{
                    .load_command_index = command.index,
                    .command = segment,
                    .sections = command.sections64(),
                };
                best_end = end;
            }
        }

        return best orelse error.NoInjectableSegment;
    }

    /// Returns the highest-addressed executable, file-backed segment that
    /// precedes `__LINKEDIT`.
    ///
    /// This becomes the carrier for injected code on macOS arm64 once the
    /// payload needs a separate writable region. Reusing an already-executable
    /// segment keeps the runtime page-protection story aligned with the
    /// original binary instead of depending on one carrier segment being both
    /// writable and executable after code signing.
    pub fn executableCarrierSegmentForInjection(self: View) !SegmentRef {
        return self.findCarrierSegmentByProtection(macho.PROT.EXEC, false);
    }

    /// Returns the highest-addressed writable, non-executable file-backed
    /// segment that precedes `__LINKEDIT`.
    pub fn writableCarrierSegmentForInjection(self: View) !SegmentRef {
        return self.findCarrierSegmentByProtection(macho.PROT.WRITE, true);
    }

    /// Plans a split Mach-O injection with distinct executable and writable
    /// payload regions.
    ///
    /// This is the runtime-safe path for Mach-O payloads that mutate internal
    /// `.data/.bss` state. The executable region is planned first because
    /// growing an earlier executable segment may shift every later writable
    /// segment and `__LINKEDIT`.
    pub fn planSplitInjection(
        self: View,
        executable_size: usize,
        writable_size: usize,
        alignment: usize,
    ) !SplitInjectionPlan {
        if (alignment == 0) return error.InvalidAlignment;

        const executable_carrier = try self.executableCarrierSegmentForInjection();
        const executable_tail_offset = try self.nextFileBackedOffsetAfter(executable_carrier.command.fileoff);
        const executable_used_end = try self.segmentUsedEndFileOffset(executable_carrier);
        const executable_plan = try planRegionInjectionFromState(.{
            .carrier_segment_index = executable_carrier.load_command_index,
            .carrier_fileoff = executable_carrier.command.fileoff,
            .carrier_used_end_fileoff = executable_used_end,
            .carrier_filesize = executable_carrier.command.filesize,
            .carrier_vmaddr = executable_carrier.command.vmaddr,
            .carrier_vmsize = executable_carrier.command.vmsize,
            .tail_offset = executable_tail_offset,
            .injected_size = executable_size,
            .alignment = alignment,
            .make_executable = true,
        });

        var total_len = self.bytes.len + executable_plan.tail_shift;

        if (writable_size == 0) {
            return .{
                .executable = executable_plan,
                .writable = null,
                .total_len = total_len,
            };
        }

        const writable_carrier = try self.writableCarrierSegmentForInjection();
        if (writable_carrier.command.fileoff <= executable_carrier.command.fileoff) {
            return error.UnsupportedMachOSplitCarrierOrder;
        }

        const writable_tail_offset = try self.nextFileBackedOffsetAfter(writable_carrier.command.fileoff);
        const writable_used_end = try self.segmentUsedEndFileOffset(writable_carrier);
        const writable_plan = try planRegionInjectionFromState(.{
            .carrier_segment_index = writable_carrier.load_command_index,
            .carrier_fileoff = writable_carrier.command.fileoff + shiftAmountAtOrAfter(writable_carrier.command.fileoff, executable_plan.tail_offset, executable_plan.tail_shift),
            .carrier_used_end_fileoff = writable_used_end + shiftAmountAtOrAfter(writable_used_end, executable_plan.tail_offset, executable_plan.tail_shift),
            .carrier_filesize = writable_carrier.command.filesize,
            .carrier_vmaddr = writable_carrier.command.vmaddr + shiftAmountAtOrAfter(writable_carrier.command.fileoff, executable_plan.tail_offset, executable_plan.tail_shift),
            .carrier_vmsize = writable_carrier.command.vmsize,
            .tail_offset = writable_tail_offset + shiftAmountAtOrAfter(writable_tail_offset, executable_plan.tail_offset, executable_plan.tail_shift),
            .injected_size = writable_size,
            .alignment = alignment,
            .make_executable = false,
        });
        total_len += writable_plan.tail_shift;

        return .{
            .executable = executable_plan,
            .writable = writable_plan,
            .total_len = total_len,
        };
    }

    /// Plans where injected bytes would land if we extend the carrier segment.
    ///
    /// `alignment` is the payload blob alignment, not the Mach-O page size.
    /// The segment still preserves the file/vm delta that was already present
    /// in the original image.
    pub fn planInjection(self: View, injected_size: usize, alignment: usize) !InjectionPlan {
        if (alignment == 0) return error.InvalidAlignment;

        const carrier = try self.carrierSegmentForInjection();
        const linkedit = try self.segmentByName("__LINKEDIT");
        const carrier_used_end = try self.segmentUsedEndFileOffset(carrier);
        const injection_offset = std.mem.alignForward(usize, carrier_used_end, alignment);
        const injection_end_offset = try std.math.add(usize, injection_offset, injected_size);
        const tail_offset: usize = @intCast(linkedit.command.fileoff);
        const tail_shift = planTailShiftForInjectedRange(tail_offset, injection_end_offset);
        const total_len = try std.math.add(usize, self.bytes.len, tail_shift);
        const payload_base_address = carrier.command.vmaddr + (injection_offset - @as(usize, @intCast(carrier.command.fileoff)));

        return .{
            .carrier_segment_index = carrier.load_command_index,
            .linkedit_segment_index = linkedit.load_command_index,
            .injection_offset = injection_offset,
            .injection_end_offset = injection_end_offset,
            .tail_offset = tail_offset,
            .tail_shift = tail_shift,
            .total_len = total_len,
            .payload_base_address = payload_base_address,
        };
    }

    /// Allocates the coarse output image for an injected payload.
    ///
    /// The payload bytes themselves are not written here yet. This helper only
    /// reserves the destination range, preserves the original bytes around it,
    /// and shifts the `__LINKEDIT` tail when the injection outgrows the
    /// existing slack.
    pub fn materializeInjectedImage(
        self: View,
        allocator: std.mem.Allocator,
        plan: InjectionPlan,
    ) ![]u8 {
        const output = try allocator.alloc(u8, plan.total_len);
        errdefer allocator.free(output);
        @memset(output, 0);

        if (plan.tail_shift == 0) {
            @memcpy(output[0..self.bytes.len], self.bytes);
            @memset(output[plan.injection_offset..plan.injection_end_offset], 0);
            return output;
        }

        @memcpy(output[0..plan.injection_offset], self.bytes[0..plan.injection_offset]);
        @memcpy(
            output[plan.injection_end_offset .. plan.injection_end_offset + (self.bytes.len - plan.tail_offset)],
            self.bytes[plan.tail_offset..],
        );
        return output;
    }

    /// Allocates the coarse output image for a split executable/writable
    /// injection.
    ///
    /// The helper copies the original bytes once, then applies each planned
    /// insertion in ascending file-offset order with in-place `memmove`
    /// operations. This keeps the implementation simple while still supporting
    /// the common Mach-O arm64 layout:
    /// `__TEXT ... __DATA_CONST ... __DATA ... __LINKEDIT`.
    pub fn materializeSplitInjectedImage(
        self: View,
        allocator: std.mem.Allocator,
        plan: SplitInjectionPlan,
    ) ![]u8 {
        const output = try allocator.alloc(u8, plan.total_len);
        errdefer allocator.free(output);
        @memset(output, 0);
        @memcpy(output[0..self.bytes.len], self.bytes);

        var current_len = self.bytes.len;
        applyMaterializedRegion(output, current_len, plan.executable);
        current_len += plan.executable.tail_shift;

        if (plan.writable) |region| {
            applyMaterializedRegion(output, current_len, region);
            current_len += region.tail_shift;
        }

        std.debug.assert(current_len == plan.total_len);
        return output;
    }

    /// Repairs Mach-O metadata after `materializeInjectedImage` reserved the
    /// output range for the future payload bytes.
    ///
    /// Important details:
    /// - the carrier segment grows to cover the new injected bytes
    /// - later file-backed metadata (especially `__LINKEDIT`) is shifted when
    ///   the injected payload overflowed the old slack region
    /// - any embedded code signature is removed only when we can prove the
    ///   resulting file still has a clean, re-signable `__LINKEDIT` layout
    ///
    /// The return value is the final logical file size. Successful code-signature
    /// stripping may shrink the output because the stale signature blob at the
    /// end of `__LINKEDIT` becomes dead data and can be truncated away.
    pub fn finalizeInjectedImage(self: View, plan: InjectionPlan, make_executable: bool) !usize {
        clearLastDiagnostic();

        const carrier = try self.segmentAtLoadCommandIndex(plan.carrier_segment_index);
        const existing_segment_size: usize = @intCast(@max(carrier.command.filesize, carrier.command.vmsize));
        const required_segment_size = plan.injection_end_offset - @as(usize, @intCast(carrier.command.fileoff));
        const new_segment_size = @max(existing_segment_size, required_segment_size);
        carrier.command.filesize = @intCast(new_segment_size);
        carrier.command.vmsize = @intCast(new_segment_size);
        if (make_executable) {
            carrier.command.initprot |= macho.PROT.EXEC;
            carrier.command.maxprot |= macho.PROT.EXEC;
        }

        try self.shiftFileOffsetsAtOrAfterRaw(plan.tail_offset, plan.tail_shift);
        try self.applyMetadataFixupsAfterSegmentShift(plan.tail_offset, plan.tail_shift);
        return try self.stripCodeSignatureForResigning();
    }

    /// Repairs Mach-O metadata after a split executable/writable injection was
    /// materialized.
    pub fn finalizeSplitInjectedImage(self: View, plan: SplitInjectionPlan) !usize {
        clearLastDiagnostic();

        // `materializeSplitInjectedImage` has already inserted *both* holes in
        // the backing byte stream before we start mutating load commands.
        //
        // That means any linkedit blob (notably `LC_DYLD_CHAINED_FIXUPS`) is
        // already sitting at its final file offset. If we were to do a full
        // "shift + parse + rewrite" pass after the first region only, the load
        // commands would still describe an intermediate location for that blob
        // and the parser would end up decoding the wrong bytes.
        //
        // So split finalization is intentionally two-phase:
        //  1. apply all raw segment/load-command offset updates
        //  2. once every metadata pointer reflects the final layout, repair the
        //     content that depends on those pointers (dyld chained fixups,
        //     AArch64 pc-relative instructions, ObjC relative metadata)
        try self.applyRegionInjectionMetadataRaw(plan.executable);
        if (plan.writable) |region| {
            try self.applyRegionInjectionMetadataRaw(region);
        }

        try self.applyMetadataFixupsAfterSegmentShift(plan.executable.tail_offset, plan.executable.tail_shift);
        if (plan.writable) |region| {
            try self.applyMetadataFixupsAfterSegmentShift(region.tail_offset, region.tail_shift);
        }

        return try self.stripCodeSignatureForResigning();
    }

    /// Returns the range of the link-edit symbol table, when present.
    pub fn symbolTableRange(self: View) !?BlobRange {
        const symtab = (try self.symtabCommand()) orelse return null;
        return .{
            .offset = symtab.symoff,
            .size = @as(usize, @intCast(symtab.nsyms)) * @sizeOf(macho.nlist_64),
        };
    }

    /// Returns the range of the link-edit string table, when present.
    pub fn stringTableRange(self: View) !?BlobRange {
        const symtab = (try self.symtabCommand()) orelse return null;
        return .{
            .offset = symtab.stroff,
            .size = symtab.strsize,
        };
    }

    /// Returns the embedded code-signature range, when present.
    pub fn codeSignatureRange(self: View) !?BlobRange {
        const command = (try self.codeSignatureCommand()) orelse return null;
        const signature = command.linkeditData();
        return .{
            .offset = signature.dataoff,
            .size = signature.datasize,
        };
    }

    /// Removes a stale embedded code signature when the layout is provably safe
    /// for a later ad-hoc re-sign.
    ///
    /// Why this is strict:
    /// - merely zeroing `LC_CODE_SIGNATURE` is not enough for stable
    ///   `codesign -f -s -` on real Mach-O binaries
    /// - we only want to emit "runtime-ready" outputs from the rewriter once we
    ///   have a coherent `__LINKEDIT` tail again
    ///
    /// Current safety policy:
    /// - `__LINKEDIT` must currently end at the end of file
    /// - the code-signature blob must occupy the tail of `__LINKEDIT`
    /// - the string table must end immediately before that blob, modulo a tiny
    ///   alignment pad that can safely be absorbed into `LC_SYMTAB.strsize`
    /// - `LC_CODE_SIGNATURE` itself may now appear before later load commands;
    ///   we compact the load-command area after removing it
    ///
    /// On success:
    /// - the stale blob is logically removed
    /// - `__LINKEDIT.filesize/vmsize` are shrunk
    /// - `LC_SYMTAB.strsize` is normalized when there was a small tail pad
    /// - the `LC_CODE_SIGNATURE` load command is removed, even when later load
    ///   commands follow it in the header
    /// - the new logical file size is returned so the caller can truncate the
    ///   physical output bytes
    fn stripCodeSignatureForResigning(self: View) !usize {
        const command = (try self.codeSignatureCommand()) orelse return self.bytes.len;

        const signature = command.linkeditData();
        if (signature.dataoff == 0 or signature.datasize == 0) {
            self.removeLoadCommand(command);
            return self.bytes.len;
        }

        const linkedit = self.segmentByName("__LINKEDIT") catch |err| switch (err) {
            error.SegmentNotFound => {
                recordDiagnostic(
                    "Mach-O codesign closure refused: LC_CODE_SIGNATURE exists at 0x{x}+0x{x} but __LINKEDIT is missing",
                    .{ signature.dataoff, signature.datasize },
                );
                return error.UnsafeMachOCodeSignatureLayout;
            },
            else => return err,
        };

        const file_end: u64 = @intCast(self.bytes.len);
        const linkedit_end = try std.math.add(u64, linkedit.command.fileoff, linkedit.command.filesize);
        if (linkedit_end != file_end) {
            recordDiagnostic(
                "Mach-O codesign closure refused: __LINKEDIT ends at 0x{x}, but file ends at 0x{x}",
                .{ linkedit_end, file_end },
            );
            return error.UnsafeMachOCodeSignatureLayout;
        }

        const signature_end = try std.math.add(u64, signature.dataoff, signature.datasize);
        if (signature.dataoff < linkedit.command.fileoff or signature_end != file_end) {
            recordDiagnostic(
                "Mach-O codesign closure refused: code signature range 0x{x}+0x{x} is not the tail of __LINKEDIT [0x{x}, 0x{x})",
                .{ signature.dataoff, signature.datasize, linkedit.command.fileoff, linkedit_end },
            );
            return error.UnsafeMachOCodeSignatureLayout;
        }

        const symtab = (try self.symtabCommand()) orelse {
            recordDiagnostic(
                "Mach-O codesign closure refused: LC_SYMTAB is missing, so the __LINKEDIT tail cannot be normalized safely",
                .{},
            );
            return error.UnsafeMachOCodeSignatureLayout;
        };

        const new_file_size = try std.math.sub(usize, self.bytes.len, signature.datasize);
        const strtab_end = try std.math.add(usize, symtab.stroff, symtab.strsize);
        if (strtab_end > new_file_size) {
            recordDiagnostic(
                "Mach-O codesign closure refused: string table [0x{x}, 0x{x}) overlaps the code-signature tail that would be removed",
                .{ symtab.stroff, strtab_end },
            );
            return error.UnsafeMachOCodeSignatureLayout;
        }

        const string_tail_gap = new_file_size - strtab_end;
        if (string_tail_gap > 0x10) {
            recordDiagnostic(
                "Mach-O codesign closure refused: string table ends 0x{x} bytes before the removable code-signature tail; expected adjacency within 0x10 bytes",
                .{string_tail_gap},
            );
            return error.UnsafeMachOCodeSignatureLayout;
        }

        // Small alignment padding between the string table and the former code
        // signature is common in practice. Once the signature tail is removed,
        // that pad becomes the natural new end of `__LINKEDIT`, so we absorb it
        // into `LC_SYMTAB.strsize` just like insert-dylib does.
        symtab.strsize += @intCast(string_tail_gap);

        const signature_offset: usize = @intCast(signature.dataoff);
        const signature_size: usize = @intCast(signature.datasize);
        @memset(self.bytes[signature_offset .. signature_offset + signature_size], 0);

        linkedit.command.filesize -= signature.datasize;
        linkedit.command.vmsize = alignedSegmentVmSize(linkedit.command.filesize);
        self.removeLoadCommand(command);
        return new_file_size;
    }

    /// Shifts file-backed metadata that points at bytes after `threshold`.
    ///
    /// This is the core primitive needed once an injected payload overflows the
    /// existing slack before `__LINKEDIT`: all later file ranges move forward,
    /// so the load commands that describe them must move too.
    pub fn shiftFileOffsetsAtOrAfter(self: View, threshold: usize, delta: usize) !void {
        try self.shiftFileOffsetsAtOrAfterRaw(threshold, delta);
        try self.applyMetadataFixupsAfterSegmentShift(threshold, delta);
    }

    /// Updates Mach-O load-command / section offsets for a later file shift,
    /// but intentionally does *not* parse or rewrite any dependent payload
    /// blobs yet.
    ///
    /// This split is required for multi-region materialization. During a split
    /// injection the bytes for both new regions already exist in the output
    /// buffer, so linkedit blobs live at their final file offsets before the
    /// first metadata update runs. Parsing those blobs against an intermediate
    /// load-command state would point us at stale addresses.
    fn shiftFileOffsetsAtOrAfterRaw(self: View, threshold: usize, delta: usize) !void {
        if (delta == 0) return;

        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            switch (command.cmd) {
                .SEGMENT_64 => {
                    const segment = command.segment64();
                    const shift_segment = segment.filesize != 0 and segment.fileoff >= threshold;
                    if (shift_segment) {
                        segment.fileoff += delta;
                        segment.vmaddr += delta;
                    }

                    for (command.sections64()) |*section| {
                        if (shift_segment and section.addr != 0) section.addr += delta;
                        if (section.offset != 0 and section.offset >= threshold) section.offset += @intCast(delta);
                        if (section.reloff != 0 and section.reloff >= threshold) section.reloff += @intCast(delta);
                    }
                },
                .SYMTAB => {
                    const symtab = command.symtab();
                    shiftU32Offset(&symtab.symoff, threshold, delta);
                    shiftU32Offset(&symtab.stroff, threshold, delta);
                },
                .DYSYMTAB => {
                    const dysymtab = command.dysymtab();
                    shiftU32Offset(&dysymtab.tocoff, threshold, delta);
                    shiftU32Offset(&dysymtab.modtaboff, threshold, delta);
                    shiftU32Offset(&dysymtab.extrefsymoff, threshold, delta);
                    shiftU32Offset(&dysymtab.indirectsymoff, threshold, delta);
                    shiftU32Offset(&dysymtab.extreloff, threshold, delta);
                    shiftU32Offset(&dysymtab.locreloff, threshold, delta);
                },
                .DYLD_INFO, .DYLD_INFO_ONLY => {
                    const dyld_info = command.dyldInfo();
                    shiftU32Offset(&dyld_info.rebase_off, threshold, delta);
                    shiftU32Offset(&dyld_info.bind_off, threshold, delta);
                    shiftU32Offset(&dyld_info.weak_bind_off, threshold, delta);
                    shiftU32Offset(&dyld_info.lazy_bind_off, threshold, delta);
                    shiftU32Offset(&dyld_info.export_off, threshold, delta);
                },
                else => {
                    if (!isLinkeditDataCommand(command.cmd)) continue;
                    const linkedit_data = command.linkeditData();
                    shiftU32Offset(&linkedit_data.dataoff, threshold, delta);
                },
            }
        }
    }

    /// Repairs on-disk metadata content after every raw offset/vmaddr shift for
    /// one injected region has been reflected in the load commands.
    ///
    /// Callers that apply multiple region shifts must finish all raw structural
    /// updates first, then invoke this helper for each shift in order.
    fn applyMetadataFixupsAfterSegmentShift(self: View, threshold: usize, delta: usize) !void {
        if (delta == 0) return;

        try self.rewriteDyldInfoRebasesAfterSegmentShift(threshold, delta);
        try self.rewriteDyldChainedFixupsAfterSegmentShift(threshold, delta);
        try self.rewriteAarch64PcRelativeTargetsAfterSegmentShift(threshold, delta);
        try self.rewriteObjcRelativeMetadataAfterSegmentShift(threshold, delta);
    }

    fn symtabCommand(self: View) !?*align(1) macho.symtab_command {
        var result: ?*align(1) macho.symtab_command = null;

        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SYMTAB) continue;
            result = command.symtab();
            break;
        }
        return result;
    }

    fn symbolTable(self: View, symtab: *align(1) const macho.symtab_command) ![]align(1) const macho.nlist_64 {
        const count: usize = @intCast(symtab.nsyms);
        const offset: usize = symtab.symoff;
        const size = count * @sizeOf(macho.nlist_64);
        if (offset + size > self.bytes.len) return error.InvalidMachOSymbolTable;
        return std.mem.bytesAsSlice(macho.nlist_64, self.bytes[offset .. offset + size]);
    }

    fn stringTable(self: View, symtab: *align(1) const macho.symtab_command) ![]const u8 {
        const offset: usize = symtab.stroff;
        const size: usize = symtab.strsize;
        if (offset + size > self.bytes.len) return error.InvalidMachOStringTable;
        return self.bytes[offset .. offset + size];
    }

    fn segmentAtLoadCommandIndex(self: View, load_command_index: usize) !SegmentRef {
        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.index != load_command_index) continue;
            if (command.cmd != .SEGMENT_64) return error.InvalidSegmentLoadCommandIndex;

            return .{
                .load_command_index = command.index,
                .command = command.segment64(),
                .sections = command.sections64(),
            };
        }
        return error.InvalidSegmentLoadCommandIndex;
    }

    /// Returns the first free file offset at the tail of an existing carrier
    /// segment.
    ///
    /// Many real Mach-O binaries leave page-tail slack between the last mapped
    /// section and the end of the segment. Reusing that already-owned space is
    /// much cheaper than growing the segment and shifting every later segment,
    /// because it avoids large cascades of metadata rewrites.
    fn segmentUsedEndFileOffset(self: View, segment: SegmentRef) !usize {
        _ = self;

        const segment_end = try std.math.add(u64, segment.command.fileoff, segment.command.filesize);
        var used_end = segment.command.fileoff;

        if (segment.command.nsects == 0) return @intCast(segment_end);

        for (segment.sections) |section| {
            if (section.isZerofill()) continue;
            if (section.size == 0) continue;

            const section_end = try std.math.add(u64, section.offset, section.size);
            if (section_end > segment_end) return error.InvalidMachOSegmentCommand;
            used_end = @max(used_end, section_end);
        }

        return @intCast(used_end);
    }

    fn findCarrierSegmentByProtection(
        self: View,
        required_protection: i32,
        reject_executable: bool,
    ) !SegmentRef {
        const linkedit = try self.segmentByName("__LINKEDIT");

        var best: ?SegmentRef = null;
        var best_end: u64 = 0;

        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;

            const segment = command.segment64();
            if (segment.filesize == 0) continue;
            if (segment.fileoff >= linkedit.command.fileoff) continue;
            if (std.mem.eql(u8, parseFixedName(segment.segname[0..]), "__PAGEZERO")) continue;
            if ((segment.initprot & required_protection) == 0) continue;
            if (reject_executable and (segment.initprot & macho.PROT.EXEC) != 0) continue;

            const end = segment.fileoff + @max(segment.filesize, segment.vmsize);
            if (best == null or end > best_end) {
                best = .{
                    .load_command_index = command.index,
                    .command = segment,
                    .sections = command.sections64(),
                };
                best_end = end;
            }
        }

        return best orelse error.NoInjectableSegment;
    }

    fn nextFileBackedOffsetAfter(self: View, fileoff: u64) !usize {
        var best: ?u64 = null;

        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;

            const segment = command.segment64();
            if (segment.filesize == 0) continue;
            if (segment.fileoff <= fileoff) continue;
            if (best == null or segment.fileoff < best.?) best = segment.fileoff;
        }

        return @intCast(best orelse @as(u64, @intCast(self.bytes.len)));
    }

    fn applyRegionInjectionMetadataRaw(self: View, region: RegionInjectionPlan) !void {
        const carrier = try self.segmentAtLoadCommandIndex(region.carrier_segment_index);
        const existing_segment_size: usize = @intCast(@max(carrier.command.filesize, carrier.command.vmsize));
        const required_segment_size = region.injection_end_offset - @as(usize, @intCast(carrier.command.fileoff));
        const new_segment_size = @max(existing_segment_size, required_segment_size);
        carrier.command.filesize = @intCast(new_segment_size);
        carrier.command.vmsize = @intCast(new_segment_size);
        if (region.make_executable) {
            carrier.command.initprot |= macho.PROT.EXEC;
            carrier.command.maxprot |= macho.PROT.EXEC;
        }

        try self.shiftFileOffsetsAtOrAfterRaw(region.tail_offset, region.tail_shift);
    }

    fn applyRegionInjectionMetadata(self: View, region: RegionInjectionPlan) !void {
        try self.applyRegionInjectionMetadataRaw(region);
        try self.applyMetadataFixupsAfterSegmentShift(region.tail_offset, region.tail_shift);
    }

    fn codeSignatureCommand(self: View) !?LoadCommandView {
        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd == .CODE_SIGNATURE) return command;
        }
        return null;
    }

    fn dyldInfoCommand(self: View) !?LoadCommandView {
        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd == .DYLD_INFO or command.cmd == .DYLD_INFO_ONLY) return command;
        }
        return null;
    }

    fn dyldChainedFixupsCommand(self: View) !?LoadCommandView {
        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd == .DYLD_CHAINED_FIXUPS) return command;
        }
        return null;
    }

    fn removeLoadCommand(self: View, command: LoadCommandView) void {
        const command_offset = @as(usize, @intCast(@intFromPtr(command.bytes.ptr) - @intFromPtr(self.load_commands.ptr)));
        const command_size = command.bytes.len;
        const old_sizeofcmds: usize = @intCast(self.header.sizeofcmds);
        std.debug.assert(command_offset + command_size <= old_sizeofcmds);

        const trailing_start = command_offset + command_size;
        const trailing_len = old_sizeofcmds - trailing_start;
        if (trailing_len != 0) {
            std.mem.copyForwards(
                u8,
                self.load_commands[command_offset .. command_offset + trailing_len],
                self.load_commands[trailing_start .. trailing_start + trailing_len],
            );
        }

        @memset(self.load_commands[old_sizeofcmds - command_size .. old_sizeofcmds], 0);
        self.header.ncmds -= 1;
        self.header.sizeofcmds -= @intCast(command_size);
    }

    /// Returns the preferred unslid image base used by dyld chained fixups.
    ///
    /// For normal userland arm64 Mach-O images this is the lowest VM address of
    /// any file-backed segment other than `__PAGEZERO`, which is typically the
    /// `__TEXT` segment base. `dyld_chained_starts_in_segment.segment_offset`
    /// stores a VM offset relative to that image base, not an absolute VM
    /// address.
    fn preferredImageBase(self: View) !u64 {
        var result: ?u64 = null;

        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;

            const segment = command.segment64();
            if (segment.filesize == 0) continue;
            if (std.mem.eql(u8, parseFixedName(segment.segname[0..]), "__PAGEZERO")) continue;

            result = if (result) |best| @min(best, segment.vmaddr) else segment.vmaddr;
        }

        return result orelse error.InvalidMachOImageBase;
    }

    fn segmentCommandCount(self: View) !usize {
        var count: usize = 0;

        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd == .SEGMENT_64) count += 1;
        }

        return count;
    }

    fn segmentCommandAtOrdinal(self: View, ordinal: usize) !*align(1) macho.segment_command_64 {
        var segment_ordinal: usize = 0;

        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;
            if (segment_ordinal == ordinal) return command.segment64();
            segment_ordinal += 1;
        }

        return error.InvalidMachODyldInfoRebase;
    }

    /// Repairs classic `LC_DYLD_INFO{,_ONLY}` rebase slots after a segment move.
    ///
    /// Why this matters:
    /// - pre-chained Mach-O images write the local unslid target address
    ///   directly into each rebased slot
    /// - the rebase opcode stream only tells dyld where those slots live so it
    ///   can add the ASLR slide later
    /// - when we move `__DATA` / `__DATA_CONST`, every local pointer that
    ///   originally targeted one of those segments must therefore be rewritten
    ///   on disk; otherwise dyld will happily slide an address that is already
    ///   stale in the new image layout
    ///
    /// The real Arc-mobile Mach-O smoke exposed exactly this gap: entries in
    /// `__objc_classlist` still pointed at the pre-shift class addresses, so
    /// libobjc started treating selector-name bytes as `objc_class`.
    fn rewriteDyldInfoRebasesAfterSegmentShift(self: View, threshold: usize, delta: usize) !void {
        const command = (try self.dyldInfoCommand()) orelse return;
        const dyld_info = command.dyldInfo();
        if (dyld_info.rebase_off == 0 or dyld_info.rebase_size == 0) return;

        const blob_offset: usize = dyld_info.rebase_off;
        const blob_size: usize = dyld_info.rebase_size;
        if (blob_offset + blob_size > self.bytes.len) return error.InvalidMachODyldInfoRebase;

        const blob = self.bytes[blob_offset .. blob_offset + blob_size];
        var blob_cursor: usize = 0;
        var rebase_type: u8 = rebase_type_pointer;
        var segment_ordinal: ?usize = null;
        var segment_offset: u64 = 0;

        while (blob_cursor < blob.len) {
            const instruction = blob[blob_cursor];
            blob_cursor += 1;

            const opcode = instruction & rebase_opcode_mask;
            const immediate = instruction & rebase_immediate_mask;

            switch (opcode) {
                rebase_opcode_done => break,
                rebase_opcode_set_type_imm => rebase_type = immediate,
                rebase_opcode_set_segment_and_offset_uleb => {
                    segment_ordinal = immediate;
                    segment_offset = try readUleb128(blob, &blob_cursor);
                },
                rebase_opcode_add_addr_uleb => {
                    segment_offset = try std.math.add(
                        u64,
                        segment_offset,
                        try readUleb128(blob, &blob_cursor),
                    );
                },
                rebase_opcode_add_addr_imm_scaled => {
                    segment_offset = try std.math.add(
                        u64,
                        segment_offset,
                        @as(u64, immediate) * rebase_pointer_stride,
                    );
                },
                rebase_opcode_do_rebase_imm_times => {
                    const ordinal = segment_ordinal orelse return error.InvalidMachODyldInfoRebase;
                    var remaining: usize = immediate;
                    while (remaining != 0) : (remaining -= 1) {
                        try self.rewriteDyldInfoRebaseSlot(
                            rebase_type,
                            ordinal,
                            segment_offset,
                            threshold,
                            delta,
                        );
                        segment_offset = try std.math.add(u64, segment_offset, rebase_pointer_stride);
                    }
                },
                rebase_opcode_do_rebase_uleb_times => {
                    const ordinal = segment_ordinal orelse return error.InvalidMachODyldInfoRebase;
                    var remaining = try readUleb128(blob, &blob_cursor);
                    while (remaining != 0) : (remaining -= 1) {
                        try self.rewriteDyldInfoRebaseSlot(
                            rebase_type,
                            ordinal,
                            segment_offset,
                            threshold,
                            delta,
                        );
                        segment_offset = try std.math.add(u64, segment_offset, rebase_pointer_stride);
                    }
                },
                rebase_opcode_do_rebase_add_addr_uleb => {
                    const ordinal = segment_ordinal orelse return error.InvalidMachODyldInfoRebase;
                    try self.rewriteDyldInfoRebaseSlot(
                        rebase_type,
                        ordinal,
                        segment_offset,
                        threshold,
                        delta,
                    );
                    segment_offset = try std.math.add(
                        u64,
                        segment_offset,
                        rebase_pointer_stride + try readUleb128(blob, &blob_cursor),
                    );
                },
                rebase_opcode_do_rebase_uleb_times_skipping_uleb => {
                    const ordinal = segment_ordinal orelse return error.InvalidMachODyldInfoRebase;
                    var remaining = try readUleb128(blob, &blob_cursor);
                    const skip = try readUleb128(blob, &blob_cursor);
                    while (remaining != 0) : (remaining -= 1) {
                        try self.rewriteDyldInfoRebaseSlot(
                            rebase_type,
                            ordinal,
                            segment_offset,
                            threshold,
                            delta,
                        );
                        segment_offset = try std.math.add(
                            u64,
                            segment_offset,
                            rebase_pointer_stride + skip,
                        );
                    }
                },
                else => return error.UnsupportedMachODyldInfoRebaseOpcode,
            }
        }
    }

    fn rewriteDyldInfoRebaseSlot(
        self: View,
        rebase_type: u8,
        segment_ordinal: usize,
        segment_offset: u64,
        threshold: usize,
        delta: usize,
    ) !void {
        if (rebase_type != rebase_type_pointer) {
            return error.UnsupportedMachODyldInfoRebaseType;
        }

        const segment = try self.segmentCommandAtOrdinal(segment_ordinal);
        const slot_end = try std.math.add(u64, segment_offset, rebase_pointer_stride);
        if (slot_end > segment.filesize) return error.InvalidMachODyldInfoRebase;

        const slot_file_offset_u64 = try std.math.add(u64, segment.fileoff, segment_offset);
        const slot_file_offset: usize = @intCast(slot_file_offset_u64);
        if (slot_file_offset + @sizeOf(u64) > self.bytes.len) return error.InvalidMachODyldInfoRebase;

        const slot_bytes = self.bytes[slot_file_offset .. slot_file_offset + @sizeOf(u64)];
        const old_target = readLittleU64(slot_bytes);
        const new_target = try self.adjustChainedTargetVmAddress(old_target, threshold, delta);
        if (new_target != old_target) {
            writeLittleU64(slot_bytes, new_target);
        }
    }

    /// Repairs `LC_DYLD_CHAINED_FIXUPS` after later file-backed segments moved.
    ///
    /// Two separate structures inside the fixup blob need to stay in sync with
    /// our segment rewrite:
    /// - `dyld_chained_starts_in_segment.segment_offset` tells dyld where each
    ///   fixup-bearing segment now starts relative to the image base
    /// - each on-disk rebase entry stores the target VM offset of the pointer
    ///   it will reconstruct at runtime
    ///
    /// Fixing only the outer load command and the segment-offset table gets us
    /// past dyld's first-level parsing, but Objective-C metadata still crashes
    /// later because many rebased pointers inside `__DATA_CONST` / `__DATA`
    /// still point at the pre-shift VM offsets. That is why this helper also
    /// walks each fixup chain and retargets every rebase whose pointee lived in
    /// a segment that moved.
    fn rewriteDyldChainedFixupsAfterSegmentShift(self: View, threshold: usize, delta: usize) !void {
        const command = (try self.dyldChainedFixupsCommand()) orelse return;
        const fixups = command.linkeditData();
        if (fixups.dataoff == 0 or fixups.datasize == 0) return;

        const blob_offset: usize = @intCast(fixups.dataoff);
        const blob_size: usize = @intCast(fixups.datasize);
        if (blob_offset + blob_size > self.bytes.len) return error.InvalidMachODyldChainedFixups;
        if (blob_size < @sizeOf(DyldChainedFixupsHeader)) return error.InvalidMachODyldChainedFixups;

        const blob = self.bytes[blob_offset .. blob_offset + blob_size];
        const header = std.mem.bytesAsValue(
            DyldChainedFixupsHeader,
            blob[0..@sizeOf(DyldChainedFixupsHeader)],
        );
        const starts_offset: usize = @intCast(header.starts_offset);
        if (starts_offset + @sizeOf(DyldChainedStartsInImageHeader) > blob.len) {
            return error.InvalidMachODyldChainedFixups;
        }

        const starts = blob[starts_offset..];
        const starts_header = std.mem.bytesAsValue(
            DyldChainedStartsInImageHeader,
            starts[0..@sizeOf(DyldChainedStartsInImageHeader)],
        );
        const seg_count: usize = @intCast(starts_header.seg_count);
        const seg_info_bytes_len = try std.math.mul(usize, seg_count, @sizeOf(u32));
        const seg_info_bytes_end = try std.math.add(
            usize,
            @sizeOf(DyldChainedStartsInImageHeader),
            seg_info_bytes_len,
        );
        if (seg_info_bytes_end > starts.len) return error.InvalidMachODyldChainedFixups;

        const segment_count = try self.segmentCommandCount();
        if (segment_count != seg_count) return error.InvalidMachODyldChainedFixups;

        const seg_info_offsets = std.mem.bytesAsSlice(
            u32,
            starts[@sizeOf(DyldChainedStartsInImageHeader)..seg_info_bytes_end],
        );
        const image_base = try self.preferredImageBase();

        var segment_ordinal: usize = 0;
        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |load_command| {
            if (load_command.cmd != .SEGMENT_64) continue;

            const seg_info_offset: usize = @intCast(seg_info_offsets[segment_ordinal]);
            if (seg_info_offset != 0) {
                if (seg_info_offset + @sizeOf(DyldChainedStartsInSegmentHeader) > starts.len) {
                    return error.InvalidMachODyldChainedFixups;
                }

                const starts_in_segment = std.mem.bytesAsValue(
                    DyldChainedStartsInSegmentHeader,
                    starts[seg_info_offset .. seg_info_offset + @sizeOf(DyldChainedStartsInSegmentHeader)],
                );
                if (starts_in_segment.size < dyld_chained_starts_in_segment_prefix_size) {
                    return error.InvalidMachODyldChainedFixups;
                }
                if (seg_info_offset + starts_in_segment.size > starts.len) {
                    return error.InvalidMachODyldChainedFixups;
                }

                const segment = load_command.segment64();
                starts_in_segment.segment_offset = try std.math.sub(u64, segment.vmaddr, image_base);
                try self.rewriteDyldChainedSegmentRebaseTargets(
                    segment,
                    starts,
                    seg_info_offset,
                    starts_in_segment.*,
                    image_base,
                    threshold,
                    delta,
                );
            }

            segment_ordinal += 1;
        }

        std.debug.assert(segment_ordinal == seg_count);
    }

    fn rewriteDyldChainedSegmentRebaseTargets(
        self: View,
        segment: *align(1) macho.segment_command_64,
        starts: []u8,
        seg_info_offset: usize,
        starts_in_segment: DyldChainedStartsInSegmentHeader,
        image_base: u64,
        threshold: usize,
        delta: usize,
    ) !void {
        if (starts_in_segment.page_count == 0) return;

        const page_starts_offset = try std.math.add(
            usize,
            seg_info_offset,
            dyld_chained_starts_in_segment_prefix_size,
        );
        const page_starts_bytes_len = try std.math.mul(
            usize,
            starts_in_segment.page_count,
            @sizeOf(u16),
        );
        const page_starts_end = try std.math.add(usize, page_starts_offset, page_starts_bytes_len);
        const segment_info_end = try std.math.add(usize, seg_info_offset, starts_in_segment.size);
        if (page_starts_end > starts.len or page_starts_end > segment_info_end) {
            return error.InvalidMachODyldChainedFixups;
        }

        const page_starts = std.mem.bytesAsSlice(u16, starts[page_starts_offset..page_starts_end]);
        const chain_starts = std.mem.bytesAsSlice(u16, starts[page_starts_end..segment_info_end]);

        for (page_starts, 0..) |page_start, page_index| {
            if (page_start == dyld_chained_ptr_start_none) continue;

            if ((page_start & dyld_chained_ptr_start_multi) != 0) {
                var chain_index: usize = page_start & ~@as(u16, dyld_chained_ptr_start_multi);
                while (true) {
                    if (chain_index >= chain_starts.len) return error.InvalidMachODyldChainedFixups;

                    const chain_start = chain_starts[chain_index];
                    const start_offset = chain_start & ~@as(u16, dyld_chained_ptr_start_last);
                    try self.rewriteDyldChainedPageRebaseTargets(
                        segment,
                        starts_in_segment.page_size,
                        page_index,
                        start_offset,
                        starts_in_segment.pointer_format,
                        image_base,
                        threshold,
                        delta,
                    );

                    if ((chain_start & dyld_chained_ptr_start_last) != 0) break;
                    chain_index += 1;
                }
                continue;
            }

            try self.rewriteDyldChainedPageRebaseTargets(
                segment,
                starts_in_segment.page_size,
                page_index,
                page_start,
                starts_in_segment.pointer_format,
                image_base,
                threshold,
                delta,
            );
        }
    }

    fn rewriteDyldChainedPageRebaseTargets(
        self: View,
        segment: *align(1) macho.segment_command_64,
        page_size: u16,
        page_index: usize,
        start_offset: u16,
        pointer_format: u16,
        image_base: u64,
        threshold: usize,
        delta: usize,
    ) !void {
        if (page_size == 0) return error.InvalidMachODyldChainedFixups;
        if (start_offset >= page_size) return error.InvalidMachODyldChainedFixups;

        const page_base = try std.math.add(
            u64,
            segment.fileoff,
            try std.math.mul(u64, page_index, page_size),
        );
        var chain_offset: usize = start_offset;

        while (true) {
            if (chain_offset + @sizeOf(u64) > page_size) return error.InvalidMachODyldChainedFixups;

            const slot_offset = try std.math.add(usize, @intCast(page_base), chain_offset);
            if (slot_offset + @sizeOf(u64) > self.bytes.len) return error.InvalidMachODyldChainedFixups;

            switch (pointer_format) {
                dyld_chained_ptr_64, dyld_chained_ptr_64_offset => {
                    var raw = readLittleU64(self.bytes[slot_offset .. slot_offset + @sizeOf(u64)]);
                    const bind = ((raw >> 63) & 0x1) != 0;
                    const next = @as(usize, @intCast((raw >> 51) & 0xFFF));

                    if (!bind) {
                        const old_target = raw & dyld_chained_ptr_64_target_mask;
                        const new_target = if (pointer_format == dyld_chained_ptr_64_offset)
                            try self.adjustChainedTargetVmOffset(old_target, image_base, threshold, delta)
                        else
                            try self.adjustChainedTargetVmAddress(old_target, threshold, delta);

                        if (new_target > dyld_chained_ptr_64_target_mask) {
                            return error.InvalidMachODyldChainedFixups;
                        }

                        if (new_target != old_target) {
                            raw = (raw & ~dyld_chained_ptr_64_target_mask) | new_target;
                            writeLittleU64(self.bytes[slot_offset .. slot_offset + @sizeOf(u64)], raw);
                        }
                    }

                    if (next == 0) break;
                    chain_offset = try std.math.add(usize, chain_offset, next * dyld_chained_ptr_64_stride);
                },
                else => return error.UnsupportedMachODyldChainedFixupPointerFormat,
            }
        }
    }

    fn adjustChainedTargetVmOffset(
        self: View,
        target: u64,
        image_base: u64,
        threshold: usize,
        delta: usize,
    ) !u64 {
        if (delta == 0) return target;

        const shifted_threshold = try std.math.add(usize, threshold, delta);
        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;

            const segment = command.segment64();
            if (segment.filesize == 0) continue;
            if (segment.fileoff < shifted_threshold) continue;

            const old_vmaddr = try std.math.sub(u64, segment.vmaddr, delta);
            const old_start = try std.math.sub(u64, old_vmaddr, image_base);
            const old_end = try std.math.add(u64, old_start, segment.vmsize);
            if (target >= old_start and target < old_end) {
                return try std.math.add(u64, target, delta);
            }
        }

        return target;
    }

    fn adjustChainedTargetVmAddress(self: View, target: u64, threshold: usize, delta: usize) !u64 {
        if (delta == 0) return target;

        const shifted_threshold = try std.math.add(usize, threshold, delta);
        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;

            const segment = command.segment64();
            if (segment.filesize == 0) continue;
            if (segment.fileoff < shifted_threshold) continue;

            const old_vmaddr = try std.math.sub(u64, segment.vmaddr, delta);
            const old_end = try std.math.add(u64, old_vmaddr, segment.vmsize);
            if (target >= old_vmaddr and target < old_end) {
                return try std.math.add(u64, target, delta);
            }
        }

        return target;
    }

    /// Rewrites original target-machine PC-relative instructions whose
    /// immediate still points at the pre-shift VM address of a moved segment.
    ///
    /// Why this is needed even after chained fixups are repaired:
    /// - dyld chained fixups only cover loader-rebased pointers stored in data
    /// - Mach-O text still contains plain AArch64 immediates such as
    ///   `adrp/add` or `adrp/ldr` that materialize local class objects, GOT
    ///   pages, CFStrings, selector refs, etc.
    /// - when payload injection moves `__DATA_CONST` / `__DATA`, those static
    ///   instruction immediates become stale and the program starts reading
    ///   pointers from whatever now occupies the old page
    ///
    /// The Objective-C smoke hits exactly that path: `main` and the stub
    /// veneers materialize class/GOT addresses with `adrp`, so moving the data
    /// segments without repairing text immediates makes the runtime jump into
    /// garbage long before our hook payload itself runs.
    ///
    /// Current scope:
    /// - patch section-backed executable code only, so injected payload bytes
    ///   are left untouched
    /// - currently rewrite `adr` and `adrp`, which is already enough for the
    ///   real Mach-O/ObjC smoke and the common local-address materialization
    ///   patterns produced by Apple's toolchain
    fn rewriteAarch64PcRelativeTargetsAfterSegmentShift(self: View, threshold: usize, delta: usize) !void {
        if (delta == 0) return;

        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;

            const segment = command.segment64();
            if ((segment.initprot & macho.PROT.EXEC) == 0) continue;

            for (command.sections64()) |*section| {
                if (section.isZerofill()) continue;
                if (!section.isCode()) continue;
                if (section.size == 0) continue;

                const section_offset: usize = section.offset;
                const section_size: usize = @intCast(section.size);
                if (section_offset + section_size > self.bytes.len) {
                    return error.InvalidMachOCodeSection;
                }

                var instruction_offset: usize = 0;
                while (instruction_offset + @sizeOf(u32) <= section_size) : (instruction_offset += @sizeOf(u32)) {
                    const site_offset = section_offset + instruction_offset;
                    const site_address = section.addr + instruction_offset;
                    var opcode = readLittleU32(self.bytes[site_offset .. site_offset + @sizeOf(u32)]);

                    if (isAdrpOpcode(opcode)) {
                        const old_target = try decodeAdrLikeTarget(opcode, site_address, true);
                        const new_target = try self.adjustChainedTargetVmAddress(old_target, threshold, delta);
                        if (new_target != old_target) {
                            opcode = try encodeAdrLikeTarget(@intCast(opcode & 0x1F), site_address, new_target, true);
                            writeLittleU32(self.bytes[site_offset .. site_offset + @sizeOf(u32)], opcode);
                        }
                        continue;
                    }

                    if (isAdrOpcode(opcode)) {
                        const old_target = try decodeAdrLikeTarget(opcode, site_address, false);
                        const new_target = try self.adjustChainedTargetVmAddress(old_target, threshold, delta);
                        if (new_target != old_target) {
                            opcode = try encodeAdrLikeTarget(@intCast(opcode & 0x1F), site_address, new_target, false);
                            writeLittleU32(self.bytes[site_offset .. site_offset + @sizeOf(u32)], opcode);
                        }
                    }
                }
            }
        }
    }

    /// Repairs Objective-C small/relative metadata tables whose 32-bit signed
    /// offsets still target the pre-shift VM address of moved segments.
    ///
    /// Mach-O ObjC metadata is a second major "not covered by dyld rebases"
    /// surface after plain `adrp`/`adr` instructions:
    /// - modern method lists in `__objc_methlist` commonly store
    ///   selector/type/IMP references as signed 32-bit deltas
    /// - those deltas are resolved entirely by the Objective-C runtime, so dyld
    ///   chained fixups never sees them
    /// - when `__DATA_CONST` / `__DATA` move, the selector-ref targets inside
    ///   those method entries must move too, otherwise method lookup silently
    ///   points at stale selector cells and the runtime starts reporting
    ///   "unrecognized selector" for methods that still exist in the binary
    ///
    /// Current scope:
    /// - repair relative/small method lists in `__objc_methlist`
    /// - update every entry field independently, so selector refs in moved
    ///   data, type strings in shifted text, or IMPs in future shifted code
    ///   would all be handled by the same helper
    fn rewriteObjcRelativeMetadataAfterSegmentShift(self: View, threshold: usize, delta: usize) !void {
        if (delta == 0) return;

        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .SEGMENT_64) continue;

            for (command.sections64()) |*section| {
                if (!std.mem.eql(u8, parseFixedName(section.sectname[0..]), "__objc_methlist")) continue;
                if (section.size == 0) continue;

                const section_offset: usize = section.offset;
                const section_size: usize = @intCast(section.size);
                if (section_offset + section_size > self.bytes.len) return error.InvalidMachOObjcMetadata;

                try self.rewriteObjcMethodListSection(
                    self.bytes[section_offset .. section_offset + section_size],
                    section.addr,
                    threshold,
                    delta,
                );
            }
        }
    }

    fn rewriteObjcMethodListSection(
        self: View,
        section_bytes: []u8,
        section_address: u64,
        threshold: usize,
        delta: usize,
    ) !void {
        var cursor: usize = 0;

        while (cursor + @sizeOf(ObjcMethodListHeader) <= section_bytes.len) {
            const header = std.mem.bytesAsValue(
                ObjcMethodListHeader,
                section_bytes[cursor .. cursor + @sizeOf(ObjcMethodListHeader)],
            );
            const entry_size = header.entrySize();
            if (entry_size == 0) return error.InvalidMachOObjcMetadata;

            const list_size = try std.math.add(
                usize,
                @sizeOf(ObjcMethodListHeader),
                try std.math.mul(usize, header.count, entry_size),
            );
            if (cursor + list_size > section_bytes.len) return error.InvalidMachOObjcMetadata;

            if (header.isRelativeMethodList()) {
                if (entry_size < @sizeOf(ObjcRelativeMethodEntry)) {
                    return error.InvalidMachOObjcMetadata;
                }

                for (0..header.count) |entry_index| {
                    const entry_offset = cursor + @sizeOf(ObjcMethodListHeader) + entry_index * entry_size;
                    const entry_address = section_address + entry_offset;
                    try self.rewriteObjcRelativeMethodEntry(
                        section_bytes[entry_offset .. entry_offset + entry_size],
                        entry_address,
                        threshold,
                        delta,
                    );
                }
            }

            cursor += list_size;
        }

        if (cursor != section_bytes.len) {
            // Objective-C metadata sections should be fully consumed by the
            // method-list walk. Trailing bytes would mean we desynchronized on
            // one list's `entsize/count`, so fail closed instead of silently
            // patching the wrong relative words.
            return error.InvalidMachOObjcMetadata;
        }
    }

    fn rewriteObjcRelativeMethodEntry(
        self: View,
        entry_bytes: []u8,
        entry_address: u64,
        threshold: usize,
        delta: usize,
    ) !void {
        const entry = std.mem.bytesAsValue(
            ObjcRelativeMethodEntry,
            entry_bytes[0..@sizeOf(ObjcRelativeMethodEntry)],
        );

        try self.rewriteSignedRelativeField(&entry.name_offset, entry_address + @offsetOf(ObjcRelativeMethodEntry, "name_offset"), threshold, delta);
        try self.rewriteSignedRelativeField(&entry.types_offset, entry_address + @offsetOf(ObjcRelativeMethodEntry, "types_offset"), threshold, delta);
        try self.rewriteSignedRelativeField(&entry.imp_offset, entry_address + @offsetOf(ObjcRelativeMethodEntry, "imp_offset"), threshold, delta);
    }

    fn rewriteSignedRelativeField(
        self: View,
        field: *align(1) i32,
        field_address: u64,
        threshold: usize,
        delta: usize,
    ) !void {
        const old_target = try addSignedOffset(field_address, field.*);
        const new_target = try self.adjustChainedTargetVmAddress(old_target, threshold, delta);
        if (new_target == old_target) return;

        const new_delta = @as(i128, @intCast(new_target)) - @as(i128, @intCast(field_address));
        if (new_delta < std.math.minInt(i32) or new_delta > std.math.maxInt(i32)) {
            return error.InvalidMachOObjcMetadata;
        }
        field.* = @intCast(new_delta);
    }
};

const LoadCommandView = struct {
    index: usize,
    cmd: macho.LC,
    bytes: []u8,

    fn segment64(self: LoadCommandView) *align(1) macho.segment_command_64 {
        std.debug.assert(self.cmd == .SEGMENT_64);
        return std.mem.bytesAsValue(macho.segment_command_64, self.bytes[0..@sizeOf(macho.segment_command_64)]);
    }

    fn sections64(self: LoadCommandView) []align(1) macho.section_64 {
        const segment = self.segment64();
        const start = @sizeOf(macho.segment_command_64);
        const len = @as(usize, segment.nsects) * @sizeOf(macho.section_64);
        return std.mem.bytesAsSlice(macho.section_64, self.bytes[start .. start + len]);
    }

    fn symtab(self: LoadCommandView) *align(1) macho.symtab_command {
        std.debug.assert(self.cmd == .SYMTAB);
        return std.mem.bytesAsValue(macho.symtab_command, self.bytes[0..@sizeOf(macho.symtab_command)]);
    }

    fn dysymtab(self: LoadCommandView) *align(1) macho.dysymtab_command {
        std.debug.assert(self.cmd == .DYSYMTAB);
        return std.mem.bytesAsValue(macho.dysymtab_command, self.bytes[0..@sizeOf(macho.dysymtab_command)]);
    }

    fn dyldInfo(self: LoadCommandView) *align(1) macho.dyld_info_command {
        std.debug.assert(self.cmd == .DYLD_INFO or self.cmd == .DYLD_INFO_ONLY);
        return std.mem.bytesAsValue(macho.dyld_info_command, self.bytes[0..@sizeOf(macho.dyld_info_command)]);
    }

    fn linkeditData(self: LoadCommandView) *align(1) macho.linkedit_data_command {
        std.debug.assert(isLinkeditDataCommand(self.cmd));
        return std.mem.bytesAsValue(macho.linkedit_data_command, self.bytes[0..@sizeOf(macho.linkedit_data_command)]);
    }
};

const RegionPlanningState = struct {
    carrier_segment_index: usize,
    carrier_fileoff: u64,
    carrier_used_end_fileoff: usize,
    carrier_filesize: u64,
    carrier_vmaddr: u64,
    carrier_vmsize: u64,
    tail_offset: usize,
    injected_size: usize,
    alignment: usize,
    make_executable: bool,
};

const DyldChainedFixupsHeader = extern struct {
    fixups_version: u32,
    starts_offset: u32,
    imports_offset: u32,
    symbols_offset: u32,
    imports_count: u32,
    imports_format: u32,
    symbols_format: u32,
};

const DyldChainedStartsInImageHeader = extern struct {
    seg_count: u32,
};

const DyldChainedStartsInSegmentHeader = extern struct {
    size: u32,
    page_size: u16,
    pointer_format: u16,
    segment_offset: u64,
    max_valid_pointer: u32,
    page_count: u16,
};

const ObjcMethodListHeader = extern struct {
    entsize_and_flags: u32,
    count: u32,

    fn entrySize(self: ObjcMethodListHeader) usize {
        return self.entsize_and_flags & objc_method_list_entry_size_mask;
    }

    fn isRelativeMethodList(self: ObjcMethodListHeader) bool {
        return (self.entsize_and_flags & objc_method_list_relative_flag) != 0;
    }
};

const ObjcRelativeMethodEntry = extern struct {
    name_offset: i32,
    types_offset: i32,
    imp_offset: i32,
};

const rebase_opcode_mask: u8 = 0xF0;
const rebase_immediate_mask: u8 = 0x0F;
const rebase_opcode_done: u8 = 0x00;
const rebase_opcode_set_type_imm: u8 = 0x10;
const rebase_opcode_set_segment_and_offset_uleb: u8 = 0x20;
const rebase_opcode_add_addr_uleb: u8 = 0x30;
const rebase_opcode_add_addr_imm_scaled: u8 = 0x40;
const rebase_opcode_do_rebase_imm_times: u8 = 0x50;
const rebase_opcode_do_rebase_uleb_times: u8 = 0x60;
const rebase_opcode_do_rebase_add_addr_uleb: u8 = 0x70;
const rebase_opcode_do_rebase_uleb_times_skipping_uleb: u8 = 0x80;
const rebase_type_pointer: u8 = 1;
const rebase_pointer_stride: u64 = @sizeOf(u64);

const dyld_chained_ptr_start_none: u16 = 0xFFFF;
const dyld_chained_ptr_start_multi: u16 = 0x8000;
const dyld_chained_ptr_start_last: u16 = 0x8000;
const dyld_chained_ptr_64: u16 = 2;
const dyld_chained_ptr_64_offset: u16 = 6;
const objc_method_list_relative_flag: u32 = 0x8000_0000;
const objc_method_list_entry_size_mask: u32 = 0x0000_FFFF;
const dyld_chained_starts_in_segment_prefix_size = @offsetOf(
    DyldChainedStartsInSegmentHeader,
    "page_count",
) + @sizeOf(u16);
const dyld_chained_ptr_64_target_mask: u64 = (@as(u64, 1) << 36) - 1;
const dyld_chained_ptr_64_stride: usize = 4;

const LoadCommandCursor = struct {
    bytes: []u8,
    offset: usize = 0,
    index: usize = 0,
    remaining: u32,

    fn next(self: *LoadCommandCursor) !?LoadCommandView {
        if (self.remaining == 0) return null;
        if (self.offset + @sizeOf(macho.load_command) > self.bytes.len) return error.InvalidMachOLoadCommands;

        const command = std.mem.bytesAsValue(
            macho.load_command,
            self.bytes[self.offset .. self.offset + @sizeOf(macho.load_command)],
        );
        if (command.cmdsize < @sizeOf(macho.load_command)) return error.InvalidMachOLoadCommand;
        if (self.offset + command.cmdsize > self.bytes.len) return error.InvalidMachOLoadCommand;

        const result = LoadCommandView{
            .index = self.index,
            .cmd = command.cmd,
            .bytes = self.bytes[self.offset .. self.offset + command.cmdsize],
        };
        self.offset += command.cmdsize;
        self.index += 1;
        self.remaining -= 1;
        return result;
    }
};

fn planRegionInjectionFromState(state: RegionPlanningState) !RegionInjectionPlan {
    const injection_offset = std.mem.alignForward(usize, state.carrier_used_end_fileoff, state.alignment);
    const injection_end_offset = try std.math.add(usize, injection_offset, state.injected_size);
    const tail_shift = planTailShiftForInjectedRange(state.tail_offset, injection_end_offset);
    const payload_base_address = state.carrier_vmaddr + (injection_offset - @as(usize, @intCast(state.carrier_fileoff)));

    return .{
        .carrier_segment_index = state.carrier_segment_index,
        .injection_offset = injection_offset,
        .injection_end_offset = injection_end_offset,
        .tail_offset = state.tail_offset,
        .tail_shift = tail_shift,
        .payload_base_address = payload_base_address,
        .make_executable = state.make_executable,
    };
}

fn applyMaterializedRegion(output: []u8, current_len: usize, region: RegionInjectionPlan) void {
    if (region.tail_shift != 0) {
        const tail_len = current_len - region.tail_offset;
        std.mem.copyBackwards(
            u8,
            output[region.tail_offset + region.tail_shift .. region.tail_offset + region.tail_shift + tail_len],
            output[region.tail_offset .. region.tail_offset + tail_len],
        );
    }
    @memset(output[region.injection_offset..region.injection_end_offset], 0);
}

fn shiftAmountAtOrAfter(value: u64, threshold: usize, delta: usize) u64 {
    if (delta == 0) return 0;
    if (value < threshold) return 0;
    return delta;
}

fn loadCommandCursor(view: View) LoadCommandCursor {
    return .{
        .bytes = view.load_commands,
        .remaining = view.header.ncmds,
    };
}

fn getString(strtab: []const u8, offset: u32) []const u8 {
    const start: usize = offset;
    if (start >= strtab.len) return "";
    const end_rel = std.mem.indexOfScalar(u8, strtab[start..], 0) orelse strtab.len - start;
    return strtab[start .. start + end_rel];
}

fn parseFixedName(name: []const u8) []const u8 {
    const len = std.mem.indexOfScalar(u8, name, 0) orelse name.len;
    return name[0..len];
}

fn matchesUserSymbolName(symbol_name: []const u8, requested_name: []const u8) bool {
    if (std.mem.eql(u8, symbol_name, requested_name)) return true;
    if (symbol_name.len != 0 and symbol_name[0] == '_') {
        return std.mem.eql(u8, symbol_name[1..], requested_name);
    }
    return false;
}

fn shiftU32Offset(field: *align(1) u32, threshold: usize, delta: usize) void {
    if (field.* == 0) return;
    if (field.* < threshold) return;
    field.* += @intCast(delta);
}

fn isLinkeditDataCommand(cmd: macho.LC) bool {
    return switch (cmd) {
        .CODE_SIGNATURE,
        .SEGMENT_SPLIT_INFO,
        .FUNCTION_STARTS,
        .DATA_IN_CODE,
        .DYLIB_CODE_SIGN_DRS,
        .LINKER_OPTIMIZATION_HINT,
        .DYLD_EXPORTS_TRIE,
        .DYLD_CHAINED_FIXUPS,
        => true,
        else => false,
    };
}

/// arm64 Mach-O images on modern Apple platforms use 16 KiB segment alignment.
///
/// We only support thin arm64 executables/dylibs/bundles in this backend, so a
/// fixed 16 KiB segment-page granularity is the correct alignment for
/// `__LINKEDIT.vmsize` normalization today. Once the backend grows to more Mach-O
/// CPU families we can make this a per-architecture policy helper instead.
fn alignedSegmentVmSize(file_size: u64) u64 {
    return std.mem.alignForward(u64, file_size, machOSegmentPageSize());
}

/// Returns the arm64 Mach-O segment page size used by modern Apple loaders.
///
/// This backend currently supports only thin arm64 images, so a fixed 16 KiB
/// segment-page granularity is the right rule for two independent reasons:
/// - `vmaddr` / `fileoff` of file-backed segments must remain page-aligned
/// - once an injected payload crosses into the next segment's page, the next
///   segment must move to the following full page, not merely by the raw byte
///   overlap
fn machOSegmentPageSize() u64 {
    return 0x4000;
}

/// Computes how far the tail of a Mach-O image must move once new bytes have
/// been inserted before `tail_offset`.
///
/// A raw overlap calculation is not sufficient on Apple arm64. Segment starts
/// are page-based loader boundaries, so if the injected bytes consume even one
/// byte of the next segment's page, every later file-backed segment must move
/// to the next full segment page.
///
/// Example:
/// - original next segment starts at `0x4000`
/// - injected range ends at `0x401d`
/// - the correct new next-segment start is `0x8000`
/// - therefore the tail shift is `0x4000`, not `0x1d`
fn planTailShiftForInjectedRange(tail_offset: usize, injection_end_offset: usize) usize {
    if (injection_end_offset <= tail_offset) return 0;

    const aligned_tail_offset = std.mem.alignForward(
        usize,
        injection_end_offset,
        @intCast(machOSegmentPageSize()),
    );
    return aligned_tail_offset - tail_offset;
}

fn recordDiagnostic(comptime fmt: []const u8, args: anytype) void {
    const message = std.fmt.bufPrint(&last_macho_diagnostic_buf, fmt, args) catch |err| switch (err) {
        error.NoSpaceLeft => {
            const fallback = "Mach-O backend error (diagnostic truncated)";
            @memcpy(last_macho_diagnostic_buf[0..fallback.len], fallback);
            last_macho_diagnostic_len = fallback.len;
            return;
        },
    };
    last_macho_diagnostic_len = message.len;
}

fn isAdrOpcode(opcode: u32) bool {
    return (opcode & 0x9F00_0000) == 0x1000_0000;
}

fn isAdrpOpcode(opcode: u32) bool {
    return (opcode & 0x9F00_0000) == 0x9000_0000;
}

fn decodeAdrLikeTarget(opcode: u32, site_address: u64, page_relative: bool) !u64 {
    const immlo = (opcode >> 29) & 0x3;
    const immhi = (opcode >> 5) & 0x7FFFF;
    const raw = immlo | (immhi << 2);
    const signed_offset = signExtend(21, raw) << @as(u6, if (page_relative) 12 else 0);
    const base = if (page_relative) site_address & ~@as(u64, 0xFFF) else site_address;
    return addSignedOffset(base, signed_offset);
}

fn encodeAdrLikeTarget(rd: u5, site_address: u64, target_address: u64, page_relative: bool) !u32 {
    const base = if (page_relative) site_address & ~@as(u64, 0xFFF) else site_address;
    const delta = @as(i128, @intCast(target_address)) - @as(i128, @intCast(base));
    if (delta < std.math.minInt(i64) or delta > std.math.maxInt(i64)) {
        return error.BranchOutOfRange;
    }

    const raw = try encodeSignedPcImmediate(@intCast(delta), if (page_relative) 12 else 0);
    return (if (page_relative) @as(u32, 0x9000_0000) else @as(u32, 0x1000_0000)) |
        ((raw & 0x3) << 29) |
        (((raw >> 2) & 0x7FFFF) << 5) |
        rd;
}

fn encodeSignedPcImmediate(byte_offset: i64, shift: u6) !u32 {
    if (shift != 0) {
        const alignment_mask = (@as(i64, 1) << shift) - 1;
        if ((byte_offset & alignment_mask) != 0) return error.UnalignedBranchTarget;
    }

    const scaled = byte_offset >> shift;
    const min = -(@as(i64, 1) << 20);
    const max = (@as(i64, 1) << 20) - 1;
    if (scaled < min or scaled > max) return error.BranchOutOfRange;

    const signed: i32 = @intCast(scaled);
    const raw: u32 = @bitCast(signed);
    return raw & ((@as(u32, 1) << 21) - 1);
}

fn addSignedOffset(base: u64, signed_offset: i64) !u64 {
    if (signed_offset >= 0) {
        return std.math.add(u64, base, @intCast(signed_offset));
    }
    return std.math.sub(u64, base, @intCast(-signed_offset));
}

fn signExtend(comptime bit_count: comptime_int, value: u64) i64 {
    const shift = 64 - bit_count;
    return @as(i64, @bitCast(value << shift)) >> shift;
}

fn readUleb128(bytes: []const u8, cursor: *usize) !u64 {
    var result: u64 = 0;
    var shift: u6 = 0;

    while (true) {
        if (cursor.* >= bytes.len) return error.InvalidMachODyldInfoRebase;
        const byte = bytes[cursor.*];
        cursor.* += 1;

        if (shift >= 64 and (byte & 0x7F) != 0) {
            return error.InvalidMachODyldInfoRebase;
        }

        result |= @as(u64, byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) return result;

        if (shift > 56) return error.InvalidMachODyldInfoRebase;
        shift += 7;
    }
}

fn readLittleU32(bytes: []const u8) u32 {
    std.debug.assert(bytes.len >= @sizeOf(u32));
    const ptr: *const [4]u8 = @ptrCast(bytes.ptr);
    return std.mem.readInt(u32, ptr, .little);
}

fn writeLittleU32(bytes: []u8, value: u32) void {
    std.debug.assert(bytes.len >= @sizeOf(u32));
    var le_value = std.mem.nativeToLittle(u32, value);
    @memcpy(bytes[0..@sizeOf(u32)], std.mem.asBytes(&le_value));
}

fn readLittleU64(bytes: []const u8) u64 {
    std.debug.assert(bytes.len >= @sizeOf(u64));
    const ptr: *const [8]u8 = @ptrCast(bytes.ptr);
    return std.mem.readInt(u64, ptr, .little);
}

fn writeLittleU64(bytes: []u8, value: u64) void {
    std.debug.assert(bytes.len >= @sizeOf(u64));
    var le_value = std.mem.nativeToLittle(u64, value);
    @memcpy(bytes[0..@sizeOf(u64)], std.mem.asBytes(&le_value));
}

fn readMagic(bytes: []const u8) u32 {
    const ptr: *const [4]u8 = @ptrCast(bytes.ptr);
    return std.mem.readInt(u32, ptr, .little);
}

pub fn notImplemented() error.NotImplemented {
    return error.NotImplemented;
}
