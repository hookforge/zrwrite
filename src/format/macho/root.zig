const std = @import("std");
const macho = std.macho;

/// The full Mach-O rewrite backend is still under construction.
///
/// `supported` therefore remains `false` even though the lightweight `View`
/// below is now real and already useful for backend-neutral tasks such as:
/// - image-format autodetection
/// - address/file-offset mapping
/// - symbol lookup
/// - code-range enumeration for pattern scanning
pub const supported = false;

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

    /// Plans where injected bytes would land if we extend the carrier segment.
    ///
    /// `alignment` is the payload blob alignment, not the Mach-O page size.
    /// The segment still preserves the file/vm delta that was already present
    /// in the original image.
    pub fn planInjection(self: View, injected_size: usize, alignment: usize) !InjectionPlan {
        if (alignment == 0) return error.InvalidAlignment;

        const carrier = try self.carrierSegmentForInjection();
        const linkedit = try self.segmentByName("__LINKEDIT");

        const carrier_end_file_offset: usize = @intCast(
            carrier.command.fileoff + @max(carrier.command.filesize, carrier.command.vmsize),
        );
        const injection_offset = std.mem.alignForward(usize, carrier_end_file_offset, alignment);
        const injection_end_offset = try std.math.add(usize, injection_offset, injected_size);
        const tail_offset: usize = @intCast(linkedit.command.fileoff);
        const tail_shift = if (injection_end_offset > tail_offset)
            injection_end_offset - tail_offset
        else
            0;
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

    /// Repairs Mach-O metadata after `materializeInjectedImage` reserved the
    /// output range for the future payload bytes.
    ///
    /// Important details:
    /// - the carrier segment grows to cover the new injected bytes
    /// - later file-backed metadata (especially `__LINKEDIT`) is shifted when
    ///   the injected payload overflowed the old slack region
    /// - any embedded code signature is cleared because it is now stale
    pub fn finalizeInjectedImage(self: View, plan: InjectionPlan, make_executable: bool) !void {
        const carrier = try self.segmentAtLoadCommandIndex(plan.carrier_segment_index);
        const new_segment_size = plan.injection_end_offset - @as(usize, @intCast(carrier.command.fileoff));
        carrier.command.filesize = @intCast(new_segment_size);
        carrier.command.vmsize = @intCast(new_segment_size);
        if (make_executable) {
            carrier.command.initprot |= macho.PROT.EXEC;
            carrier.command.maxprot |= macho.PROT.EXEC;
        }

        try self.shiftFileOffsetsAtOrAfter(plan.tail_offset, plan.tail_shift);
        _ = try self.clearCodeSignature();
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
        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .CODE_SIGNATURE) continue;
            const signature = command.linkeditData();
            return .{
                .offset = signature.dataoff,
                .size = signature.datasize,
            };
        }
        return null;
    }

    /// Disables the embedded code-signature command in-place.
    ///
    /// This is a practical requirement for local Mach-O rewriting on macOS:
    /// once bytes or load-command offsets change, the previous code-signature
    /// blob is no longer valid. A later milestone can re-sign the output, but
    /// the first backend stage needs a conservative "strip stale signature"
    /// primitive first.
    pub fn clearCodeSignature(self: View) !bool {
        var cursor = loadCommandCursor(self);
        while (try cursor.next()) |command| {
            if (command.cmd != .CODE_SIGNATURE) continue;
            const signature = command.linkeditData();
            signature.dataoff = 0;
            signature.datasize = 0;
            return true;
        }
        return false;
    }

    /// Shifts file-backed metadata that points at bytes after `threshold`.
    ///
    /// This is the core primitive needed once an injected payload overflows the
    /// existing slack before `__LINKEDIT`: all later file ranges move forward,
    /// so the load commands that describe them must move too.
    pub fn shiftFileOffsetsAtOrAfter(self: View, threshold: usize, delta: usize) !void {
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

fn readMagic(bytes: []const u8) u32 {
    const ptr: *const [4]u8 = @ptrCast(bytes.ptr);
    return std.mem.readInt(u32, ptr, .little);
}

pub fn notImplemented() error.NotImplemented {
    return error.NotImplemented;
}
