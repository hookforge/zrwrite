const std = @import("std");
const elf = std.elf;
const bundle = @import("bundle.zig");
const aarch64 = @import("../isa/aarch64/root.zig");
const image_backend = @import("image_backend.zig");
const ElfView = @import("../format/elf/root.zig").View;
const macho_format = @import("../format/macho/root.zig");
const MachOView = macho_format.View;
const MachOInjectionPlan = macho_format.InjectionPlan;
const MachOSplitInjectionPlan = macho_format.SplitInjectionPlan;
const payload = @import("payload/object.zig");
const pattern_locator = @import("pattern_locator.zig");

const rewrite_diagnostic_capacity = 1024;
threadlocal var last_rewrite_diagnostic_buf: [rewrite_diagnostic_capacity]u8 = undefined;
threadlocal var last_rewrite_diagnostic_len: usize = 0;

pub const InstrumentHookSpec = struct {
    payload_object_path: []const u8,
    target: bundle.HookLocator,
    handler_symbol: []const u8,
    log_message: []const u8 = "",
    expected_bytes: []const u8 = "",
    stolen_instruction_count: u8 = 1,
};

pub const InstrumentObjectSpec = struct {
    payload_object_bytes: []const u8,
    target: bundle.HookLocator,
    handler_symbol: []const u8,
    log_message: []const u8 = "",
    expected_bytes: []const u8 = "",
    stolen_instruction_count: u8 = 1,
};

pub const ReplaceHookSpec = struct {
    payload_object_path: []const u8,
    target: bundle.HookLocator,
    replacement_symbol: []const u8,
    expected_bytes: []const u8 = "",
};

pub const ReplaceObjectSpec = struct {
    payload_object_bytes: []const u8,
    target: bundle.HookLocator,
    replacement_symbol: []const u8,
    expected_bytes: []const u8 = "",
};

pub const RewriteReport = struct {
    target_address: u64,
    target_file_offset: usize,
    payload_entry_address: u64,
    trampoline_address: ?u64 = null,
    stub_address: ?u64 = null,
    injection_offset: usize,
    injected_size: usize,
};

pub const InstrumentRewriteReport = RewriteReport;
pub const ReplaceRewriteReport = RewriteReport;

/// Clears the last rewrite diagnostic.
///
/// Patch planning failures often need more context than an error-set tag can
/// provide on its own. For example:
/// - expected-byte mismatches should say what bytes were found instead
/// - widened-window failures should name the first unsupported instruction
/// - incoming-branch rejections should say which source edge blocks the patch
pub fn clearLastRewriteDiagnostic() void {
    last_rewrite_diagnostic_len = 0;
}

/// Returns the most recent rewriter diagnostic, if any.
pub fn lastRewriteDiagnosticMessage() ?[]const u8 {
    if (last_rewrite_diagnostic_len == 0) return null;
    return last_rewrite_diagnostic_buf[0..last_rewrite_diagnostic_len];
}

const ResolvedTarget = struct {
    address: u64,
    file_offset: usize,
};

/// One hook locator resolved against both the pristine input image and the
/// currently-mutated working image.
///
/// Bundle author intent should be stable across multi-hook rewrites:
/// - symbol / pattern / address locators describe the original binary the user
///   inspected
/// - expected-bytes guards should validate that original inspected image
/// - the concrete patch write still has to happen at the target's *current*
///   file offset after earlier injections may have shifted later ranges
const ResolvedPatchTarget = struct {
    address: u64,
    original_file_offset: usize,
    current_file_offset: usize,

    fn original(self: ResolvedPatchTarget) ResolvedTarget {
        return .{
            .address = self.address,
            .file_offset = self.original_file_offset,
        };
    }

    fn current(self: ResolvedPatchTarget) ResolvedTarget {
        return .{
            .address = self.address,
            .file_offset = self.current_file_offset,
        };
    }
};

const IncomingBranchRetarget = struct {
    source_address: u64,
    source_file_offset: usize,
    replay_plan: aarch64.ReplayPlan,
    target_index: usize,
};

const ElfInjectionPlan = struct {
    last_load_index: usize,
    load_end_offset: usize,
    injection_offset: usize,
    tail_output_offset: usize,
    tail_shift: usize,
    total_len: usize,
    payload_base_address: u64,
};

const ImageInjectionPlan = union(enum) {
    elf: ElfInjectionPlan,
    macho: MachOInjectionPlan,

    fn injectionOffset(self: ImageInjectionPlan) usize {
        return switch (self) {
            .elf => |plan| plan.injection_offset,
            .macho => |plan| plan.injection_offset,
        };
    }

    fn payloadBaseAddress(self: ImageInjectionPlan) u64 {
        return switch (self) {
            .elf => |plan| plan.payload_base_address,
            .macho => |plan| plan.payload_base_address,
        };
    }
};

const SharedMachOPayloadState = struct {
    /// File offset of the shared executable/read-only payload image.
    primary_injection_offset: usize,
    /// Size of the executable/read-only payload image.
    primary_image_size: usize,
    /// File offset of the writable payload image, when present.
    writable_injection_offset: ?usize = null,
    /// Size of the writable payload image.
    writable_image_size: usize = 0,
    /// Current linked base address of the writable payload image, when present.
    writable_base_address: ?u64 = null,
};

/// Cache entry for the "inject once, attach many instrument hooks" model.
///
/// User expectation is that one payload object behaves like one module:
/// - its `.text` is emitted once
/// - its writable `.data` / `.bss` live in one shared image
/// - multiple handler symbols inside that object can observe the same globals
///
/// We intentionally key this by the full object bytes plus binary format. That
/// keeps the semantics simple and avoids accidental sharing across different
/// payload builds that merely happen to export the same symbol names.
const SharedInstrumentPayload = struct {
    binary_format: bundle.BinaryFormat,
    object_bytes: []u8,
    primary_base_address: u64,
    macho: ?SharedMachOPayloadState = null,

    fn deinit(self: *SharedInstrumentPayload, allocator: std.mem.Allocator) void {
        allocator.free(self.object_bytes);
        self.* = undefined;
    }
};

/// Session-local record of how much tail space a Mach-O carrier segment has
/// already consumed during this rewrite.
///
/// Section tables only describe the original binary layout. Once we have
/// appended payload bytes into a segment tail, later planning passes need an
/// explicit "used through here" watermark or they will try to reuse the same
/// slack and overlap earlier injections.
const MachOCarrierOccupancy = struct {
    segment_index: usize,
    used_end_fileoff: usize,
};

pub const Rewriter = struct {
    allocator: std.mem.Allocator,
    input_bytes: []u8,
    output_bytes: ?[]u8 = null,
    input_mode: u16,
    /// Instrument hooks reuse previously injected payload images when the same
    /// object bytes are attached again during one rewrite session.
    ///
    /// Scope of this cache:
    /// - applies only to instrument hooks
    /// - shared only within one `Rewriter`
    /// - replace hooks still inject their own standalone payload image
    shared_instrument_payloads: std.ArrayListUnmanaged(SharedInstrumentPayload) = .empty,
    macho_carrier_occupancy: std.ArrayListUnmanaged(MachOCarrierOccupancy) = .empty,

    pub fn initPath(allocator: std.mem.Allocator, input_path: []const u8) !Rewriter {
        const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
        errdefer allocator.free(input_bytes);

        const stat = try std.fs.cwd().statFile(input_path);

        return .{
            .allocator = allocator,
            .input_bytes = input_bytes,
            .input_mode = @intCast(stat.mode & 0o777),
        };
    }

    pub fn deinit(self: *Rewriter) void {
        for (self.shared_instrument_payloads.items) |*entry| entry.deinit(self.allocator);
        self.shared_instrument_payloads.deinit(self.allocator);
        self.macho_carrier_occupancy.deinit(self.allocator);
        if (self.output_bytes) |output| self.allocator.free(output);
        self.allocator.free(self.input_bytes);
        self.* = undefined;
    }

    pub fn bytes(self: *const Rewriter) []const u8 {
        return if (self.output_bytes) |output| output else self.input_bytes;
    }

    fn workingBytes(self: *Rewriter) []u8 {
        return if (self.output_bytes) |output| output else self.input_bytes;
    }

    fn installOutput(self: *Rewriter, output: []u8) void {
        if (self.output_bytes) |previous| self.allocator.free(previous);
        self.output_bytes = output;
    }

    fn effectiveMachOCarrierUsedEnd(
        self: *const Rewriter,
        input_view: MachOView,
        carrier: macho_format.SegmentRef,
    ) !usize {
        var used_end = try input_view.segmentUsedEndFileOffset(carrier);
        for (self.macho_carrier_occupancy.items) |entry| {
            if (entry.segment_index != carrier.load_command_index) continue;
            used_end = @max(used_end, entry.used_end_fileoff);
        }
        return used_end;
    }

    fn rememberMachOCarrierUsedEnd(
        self: *Rewriter,
        segment_index: usize,
        used_end_fileoff: usize,
    ) !void {
        for (self.macho_carrier_occupancy.items) |*entry| {
            if (entry.segment_index != segment_index) continue;
            entry.used_end_fileoff = @max(entry.used_end_fileoff, used_end_fileoff);
            return;
        }
        try self.macho_carrier_occupancy.append(self.allocator, .{
            .segment_index = segment_index,
            .used_end_fileoff = used_end_fileoff,
        });
    }

    fn rememberMachORegionOccupancy(
        self: *Rewriter,
        region: macho_format.RegionInjectionPlan,
    ) !void {
        if (region.usesSyntheticSegment()) return;
        try self.rememberMachOCarrierUsedEnd(region.carrier_segment_index, region.injection_end_offset);
    }

    fn rememberMachOSplitOccupancy(
        self: *Rewriter,
        plan: MachOSplitInjectionPlan,
    ) !void {
        try self.rememberMachORegionOccupancy(plan.executable);
        if (plan.writable) |region| try self.rememberMachORegionOccupancy(region);
    }

    fn planMachOInjectedImage(
        self: *const Rewriter,
        input_view: MachOView,
        injected_size: usize,
    ) !MachOInjectionPlan {
        const carrier = try input_view.carrierSegmentForInjection();
        const used_end = try self.effectiveMachOCarrierUsedEnd(input_view, carrier);
        return try input_view.planInjectionWithUsedEnd(injected_size, 16, used_end);
    }

    fn planMachOSplitInjection(
        self: *const Rewriter,
        input_view: MachOView,
        executable_size: usize,
        writable_size: usize,
        alignment: usize,
    ) !MachOSplitInjectionPlan {
        const executable_carrier = try input_view.executableCarrierSegmentForInjection();
        const executable_used_end = try self.effectiveMachOCarrierUsedEnd(input_view, executable_carrier);

        const writable_used_end: ?usize = if (writable_size == 0)
            null
        else blk: {
            const writable_carrier = input_view.writableCarrierSegmentForInjection() catch |err| switch (err) {
                error.NoInjectableSegment => break :blk null,
                else => return err,
            };
            break :blk try self.effectiveMachOCarrierUsedEnd(input_view, writable_carrier);
        };

        return try input_view.planSplitInjectionWithUsedEnds(
            executable_size,
            writable_size,
            alignment,
            executable_used_end,
            writable_used_end,
        );
    }

    pub fn writeToPath(self: *const Rewriter, output_path: []const u8) !void {
        const file = try std.fs.cwd().createFile(output_path, .{
            .truncate = true,
            .mode = self.input_mode,
        });
        defer file.close();
        try file.writeAll(self.bytes());
    }

    pub fn addInstrumentHook(self: *Rewriter, spec: InstrumentHookSpec) !InstrumentRewriteReport {
        clearLastRewriteDiagnostic();
        const payload_bytes = try std.fs.cwd().readFileAlloc(self.allocator, spec.payload_object_path, std.math.maxInt(usize));
        defer self.allocator.free(payload_bytes);

        return self.addInstrumentHookObject(.{
            .payload_object_bytes = payload_bytes,
            .target = spec.target,
            .handler_symbol = spec.handler_symbol,
            .log_message = spec.log_message,
            .expected_bytes = spec.expected_bytes,
            .stolen_instruction_count = spec.stolen_instruction_count,
        });
    }

    pub fn addReplaceHook(self: *Rewriter, spec: ReplaceHookSpec) !ReplaceRewriteReport {
        clearLastRewriteDiagnostic();
        const payload_bytes = try std.fs.cwd().readFileAlloc(self.allocator, spec.payload_object_path, std.math.maxInt(usize));
        defer self.allocator.free(payload_bytes);

        return self.addReplaceHookObject(.{
            .payload_object_bytes = payload_bytes,
            .target = spec.target,
            .replacement_symbol = spec.replacement_symbol,
            .expected_bytes = spec.expected_bytes,
        });
    }

    pub fn addInstrumentHookObject(self: *Rewriter, spec: InstrumentObjectSpec) !InstrumentRewriteReport {
        return self.addInstrumentHookObjectForFormat(.elf, spec);
    }

    pub fn addInstrumentHookObjectForFormat(
        self: *Rewriter,
        binary_format: bundle.BinaryFormat,
        spec: InstrumentObjectSpec,
    ) !InstrumentRewriteReport {
        clearLastRewriteDiagnostic();
        const base_bytes = self.workingBytes();
        const input_view = try image_backend.View.parseAs(base_bytes, binary_format);
        const original_input_view = try image_backend.View.parseAs(self.input_bytes, binary_format);
        // Repeated instrument attachments of the same payload object should
        // look like multiple entry points into one payload module, not like N
        // silently duplicated modules with isolated global state.
        const shared_payload_index = self.findSharedInstrumentPayloadIndex(binary_format, spec.payload_object_bytes);
        const shared_payload = if (shared_payload_index) |index| self.shared_instrument_payloads.items[index] else null;
        return switch (input_view) {
            .elf => |view| self.addInstrumentHookObjectElf(
                view,
                original_input_view.elf,
                spec,
                shared_payload,
            ),
            .macho => |view| self.addInstrumentHookObjectMachO(
                view,
                original_input_view.macho,
                spec,
                shared_payload,
                shared_payload_index,
            ),
        };
    }

    fn addInstrumentHookObjectElf(
        self: *Rewriter,
        input_view: ElfView,
        original_input_view: ElfView,
        spec: InstrumentObjectSpec,
        shared_payload: ?SharedInstrumentPayload,
    ) !InstrumentRewriteReport {
        const target_view: image_backend.View = .{ .elf = input_view };
        const original_target_view: image_backend.View = .{ .elf = original_input_view };
        const base_bytes = self.workingBytes();
        const resolved_target = try resolvePatchTargetLocation(
            self.allocator,
            original_target_view,
            target_view,
            spec.target,
        );
        const target = resolved_target.current();
        const stolen_instruction_count = try validateStolenInstructionCount(spec.stolen_instruction_count);
        const stolen_window_size = stolen_instruction_count * @sizeOf(u32);
        try validatePatchWindowMapping(original_target_view, resolved_target.original(), stolen_instruction_count);
        try validateExpectedBytes(
            self.allocator,
            self.input_bytes,
            resolved_target.original(),
            spec.expected_bytes,
        );

        const window_plan = try analyzeInstrumentWindowPlan(
            base_bytes,
            target,
            stolen_instruction_count,
        );
        const incoming_branches = try collectIncomingBranchRetargets(
            self.allocator,
            target_view,
            target.address,
            stolen_instruction_count,
            window_plan,
        );
        defer self.allocator.free(incoming_branches);
        const replay_plan = window_plan.singleReplayPlan() orelse aarch64.ReplayPlan{ .trampoline = {} };
        const needs_raw_trampoline = windowNeedsRawTrampoline(window_plan);
        const enable_bti = target_view.hasAarch64BtiProperty();
        const bti_prefix_size: usize = if (enable_bti) @sizeOf(u32) else 0;
        const semantic_entry_layout = aarch64.planSemanticInteriorEntryLayout(window_plan, enable_bti);
        const payload_layout = try payload.analyzeObjectBytesForFormat(
            self.allocator,
            .elf,
            spec.payload_object_bytes,
            spec.handler_symbol,
        );

        const payload_image_size: usize = if (shared_payload == null) payload_layout.image_size else 0;
        const trampoline_offset = std.mem.alignForward(usize, payload_image_size, 8);
        const trampoline_size = if (needs_raw_trampoline)
            if (stolen_instruction_count == 1 and replay_plan.requiresRawTrampoline())
                aarch64.original_trampoline_size + bti_prefix_size
            else
                stolen_window_size + aarch64.long_detour_size + bti_prefix_size
        else
            0;
        const semantic_entry_offset = std.mem.alignForward(usize, trampoline_offset + trampoline_size, 8);
        const stub_offset = std.mem.alignForward(
            usize,
            semantic_entry_offset + semantic_entry_layout.total_size,
            8,
        );

        const stub = try aarch64.buildInstrumentStub(.{
            .allocator = self.allocator,
            .site_address = target.address,
            .callback_address = 0,
            .trampoline_address = 0,
            .stub_address = 0,
            .replay_plan = replay_plan,
            .window_plan = window_plan,
            .enable_bti = enable_bti,
            .debug_write_abi = .linux_aarch64,
            .log_message = spec.log_message,
        });
        const stub_size = stub.len;
        defer self.allocator.free(stub);
        std.debug.assert(stub.len == stub_size);

        const injected_size = stub_offset + stub_size;
        const plan = try planInjectedImage(target_view, injected_size);
        const callback_address = if (shared_payload) |entry|
            entry.primary_base_address + payload_layout.entry_offset
        else
            plan.payloadBaseAddress() + payload_layout.entry_offset;
        const trampoline_address = if (needs_raw_trampoline)
            plan.payloadBaseAddress() + trampoline_offset
        else
            0;
        const semantic_entry_address = if (semantic_entry_layout.total_size != 0)
            plan.payloadBaseAddress() + semantic_entry_offset
        else
            0;
        const stub_address = plan.payloadBaseAddress() + stub_offset;

        const fixed_stub = try aarch64.buildInstrumentStub(.{
            .allocator = self.allocator,
            .site_address = target.address,
            .callback_address = callback_address,
            .trampoline_address = trampoline_address,
            .stub_address = stub_address,
            .replay_plan = replay_plan,
            .window_plan = window_plan,
            .enable_bti = enable_bti,
            .debug_write_abi = .linux_aarch64,
            .log_message = spec.log_message,
        });
        defer self.allocator.free(fixed_stub);
        std.debug.assert(fixed_stub.len == stub_size);

        var output = try materializeInjectedOutput(self, target_view, base_bytes, plan);
        errdefer self.allocator.free(output);

        if (shared_payload == null) {
            const loaded_payload = try payload.linkObjectBytes(
                self.allocator,
                spec.payload_object_bytes,
                spec.handler_symbol,
                plan.payloadBaseAddress(),
                input_view,
            );
            defer self.allocator.free(loaded_payload.image);
            std.debug.assert(loaded_payload.entry_offset == payload_layout.entry_offset);
            std.debug.assert(loaded_payload.image.len == payload_layout.image_size);

            @memcpy(
                output[plan.injectionOffset() .. plan.injectionOffset() + loaded_payload.image.len],
                loaded_payload.image,
            );
        }

        if (needs_raw_trampoline) {
            const stolen_bytes = base_bytes[target.file_offset .. target.file_offset + stolen_window_size];
            if (stolen_instruction_count == 1 and replay_plan.requiresRawTrampoline()) {
                var original_instruction: [4]u8 = undefined;
                @memcpy(&original_instruction, stolen_bytes);
                const trampoline = try aarch64.buildOriginalTrampolineBytes(
                    self.allocator,
                    original_instruction,
                    trampoline_address,
                    target.address + 4,
                    enable_bti,
                );
                defer self.allocator.free(trampoline);
                @memcpy(
                    output[plan.injectionOffset() + trampoline_offset .. plan.injectionOffset() + trampoline_offset + trampoline.len],
                    trampoline,
                );
            } else {
                const trampoline = try aarch64.buildRawTrampoline(
                    self.allocator,
                    stolen_bytes,
                    trampoline_address,
                    target.address + stolen_window_size,
                    enable_bti,
                );
                defer self.allocator.free(trampoline);
                @memcpy(
                    output[plan.injectionOffset() + trampoline_offset .. plan.injectionOffset() + trampoline_offset + trampoline.len],
                    trampoline,
                );
            }
        }

        if (semantic_entry_layout.total_size != 0) {
            const semantic_entries = try aarch64.buildSemanticInteriorEntries(
                self.allocator,
                window_plan,
                semantic_entry_layout,
                semantic_entry_address,
                trampoline_address,
                target.address,
                enable_bti,
            );
            defer self.allocator.free(semantic_entries);
            @memcpy(
                output[plan.injectionOffset() + semantic_entry_offset .. plan.injectionOffset() + semantic_entry_offset + semantic_entries.len],
                semantic_entries,
            );
        }

        @memcpy(output[plan.injectionOffset() + stub_offset .. plan.injectionOffset() + stub_offset + fixed_stub.len], fixed_stub);

        output = try finalizeInjectedOutput(self.allocator, target_view, output, plan, true);

        try writeInstrumentDetourPatch(
            output,
            target.file_offset,
            target.address,
            stub_address,
            stolen_instruction_count,
        );
        if (incoming_branches.len != 0) {
            try retargetIncomingBranches(
                output,
                incoming_branches,
                window_plan,
                trampoline_address,
                semantic_entry_address,
                semantic_entry_layout,
                enable_bti,
            );
        }

        if (shared_payload == null) {
            try self.rememberSharedInstrumentPayload(
                .elf,
                spec.payload_object_bytes,
                plan.payloadBaseAddress(),
            );
        }
        self.installOutput(output);

        return .{
            .target_address = target.address,
            .target_file_offset = target.file_offset,
            .payload_entry_address = callback_address,
            .trampoline_address = if (needs_raw_trampoline) trampoline_address else null,
            .stub_address = stub_address,
            .injection_offset = plan.injectionOffset(),
            .injected_size = injected_size,
        };
    }

    fn addInstrumentHookObjectMachO(
        self: *Rewriter,
        input_view: MachOView,
        original_input_view: MachOView,
        spec: InstrumentObjectSpec,
        shared_payload: ?SharedInstrumentPayload,
        shared_payload_index: ?usize,
    ) !InstrumentRewriteReport {
        const target_view: image_backend.View = .{ .macho = input_view };
        const original_target_view: image_backend.View = .{ .macho = original_input_view };
        const resolved_target = try resolvePatchTargetLocation(
            self.allocator,
            original_target_view,
            target_view,
            spec.target,
        );
        const target = resolved_target.current();
        const stolen_instruction_count = try validateStolenInstructionCount(spec.stolen_instruction_count);
        const stolen_window_size = stolen_instruction_count * @sizeOf(u32);
        try validatePatchWindowMapping(original_target_view, resolved_target.original(), stolen_instruction_count);
        try validateExpectedBytes(
            self.allocator,
            self.input_bytes,
            resolved_target.original(),
            spec.expected_bytes,
        );

        // All detour / trampoline / incoming-branch logic is shared with the
        // ELF path. Once the Mach-O image backend can plan/finalize injection
        // and the Mach-O payload mini-linker can produce a relocated callback
        // image, the rest of the instrument pipeline becomes backend-neutral.
        //
        // In other words, the hard Mach-O-specific work lives at the edges:
        // - mapping target addresses/file offsets in the input image
        // - choosing where the injected blob will live in the output image
        // - linking a native Mach-O payload object against that final address
        const preliminary_window_plan = try analyzeInstrumentWindowPlan(
            self.input_bytes,
            resolved_target.original(),
            stolen_instruction_count,
        );
        const preliminary_replay_plan = preliminary_window_plan.singleReplayPlan() orelse aarch64.ReplayPlan{ .trampoline = {} };
        const needs_raw_trampoline = windowNeedsRawTrampoline(preliminary_window_plan);
        const enable_bti = target_view.hasAarch64BtiProperty();
        const bti_prefix_size: usize = if (enable_bti) @sizeOf(u32) else 0;
        const preliminary_semantic_entry_layout = aarch64.planSemanticInteriorEntryLayout(
            preliminary_window_plan,
            enable_bti,
        );

        const payload_layout = try payload.analyzeObjectBytesForFormat(
            self.allocator,
            .macho,
            spec.payload_object_bytes,
            spec.handler_symbol,
        );

        const payload_image_size: usize = if (shared_payload == null) payload_layout.image_size else 0;
        const writable_image_size: usize = if (shared_payload == null) payload_layout.writable_image_size else 0;
        const trampoline_offset = std.mem.alignForward(usize, payload_image_size, 8);
        const trampoline_size = if (needs_raw_trampoline)
            if (stolen_instruction_count == 1 and preliminary_replay_plan.requiresRawTrampoline())
                aarch64.original_trampoline_size + bti_prefix_size
            else
                stolen_window_size + aarch64.long_detour_size + bti_prefix_size
        else
            0;
        const semantic_entry_offset = std.mem.alignForward(usize, trampoline_offset + trampoline_size, 8);
        const stub_offset = std.mem.alignForward(
            usize,
            semantic_entry_offset + preliminary_semantic_entry_layout.total_size,
            8,
        );

        const stub = try aarch64.buildInstrumentStub(.{
            .allocator = self.allocator,
            .site_address = target.address,
            .callback_address = 0,
            .trampoline_address = 0,
            .stub_address = 0,
            .replay_plan = preliminary_replay_plan,
            .window_plan = preliminary_window_plan,
            .enable_bti = enable_bti,
            .debug_write_abi = .darwin_arm64,
            .log_message = spec.log_message,
        });
        const stub_size = stub.len;
        defer self.allocator.free(stub);
        std.debug.assert(stub.len == stub_size);

        const executable_injected_size = stub_offset + stub_size;
        const split_plan = try self.planMachOSplitInjection(
            input_view,
            executable_injected_size,
            writable_image_size,
            16,
        );
        if (shared_payload_index) |index| {
            try self.validateSharedMachOPayloadPlanCompatibility(split_plan, index);
        }
        const callback_address = if (shared_payload) |entry|
            entry.primary_base_address + payload_layout.entry_offset
        else
            split_plan.executable.payload_base_address + payload_layout.entry_offset;
        const trampoline_address = if (needs_raw_trampoline)
            split_plan.executable.payload_base_address + trampoline_offset
        else
            0;
        const semantic_entry_address = if (preliminary_semantic_entry_layout.total_size != 0)
            split_plan.executable.payload_base_address + semantic_entry_offset
        else
            0;
        const stub_address = split_plan.executable.payload_base_address + stub_offset;

        var output = try input_view.materializeSplitInjectedImage(self.allocator, split_plan);
        errdefer self.allocator.free(output);
        output = try finalizeMachOSplitOutput(self.allocator, output, split_plan);

        const finalized_view = try MachOView.parse(output);
        const finalized_target_view: image_backend.View = .{ .macho = finalized_view };
        const finalized_target = ResolvedTarget{
            .address = target.address,
            .file_offset = try finalized_target_view.addressToOffset(target.address),
        };
        const finalized_window_plan = try analyzeInstrumentWindowPlan(
            output,
            finalized_target,
            stolen_instruction_count,
        );
        const finalized_replay_plan = finalized_window_plan.singleReplayPlan() orelse aarch64.ReplayPlan{ .trampoline = {} };
        const finalized_needs_raw_trampoline = windowNeedsRawTrampoline(finalized_window_plan);
        const finalized_semantic_entry_layout = aarch64.planSemanticInteriorEntryLayout(
            finalized_window_plan,
            enable_bti,
        );

        if (finalized_needs_raw_trampoline != needs_raw_trampoline) {
            recordRewriteDiagnostic(
                "Mach-O relocated patch window at 0x{x} changed replay shape after segment-shift fixups; planned raw-trampoline={s}, finalized raw-trampoline={s}",
                .{
                    target.address,
                    if (needs_raw_trampoline) "true" else "false",
                    if (finalized_needs_raw_trampoline) "true" else "false",
                },
            );
            return error.UnsupportedRelocatedPatchWindow;
        }
        if (finalized_semantic_entry_layout.total_size > preliminary_semantic_entry_layout.total_size) {
            recordRewriteDiagnostic(
                "Mach-O relocated patch window at 0x{x} needs larger semantic interior entries after segment-shift fixups ({d} bytes > reserved {d})",
                .{
                    target.address,
                    finalized_semantic_entry_layout.total_size,
                    preliminary_semantic_entry_layout.total_size,
                },
            );
            return error.UnsupportedRelocatedPatchWindow;
        }

        const finalized_stub = try aarch64.buildInstrumentStub(.{
            .allocator = self.allocator,
            .site_address = target.address,
            .callback_address = callback_address,
            .trampoline_address = trampoline_address,
            .stub_address = stub_address,
            .replay_plan = finalized_replay_plan,
            .window_plan = finalized_window_plan,
            .enable_bti = enable_bti,
            .debug_write_abi = .darwin_arm64,
            .log_message = spec.log_message,
        });
        defer self.allocator.free(finalized_stub);
        if (finalized_stub.len > stub_size) {
            recordRewriteDiagnostic(
                "Mach-O relocated patch window at 0x{x} needs a larger bridge after segment-shift fixups ({d} bytes > reserved {d})",
                .{ target.address, finalized_stub.len, stub_size },
            );
            return error.UnsupportedRelocatedPatchWindow;
        }

        if (shared_payload == null) {
            var loaded_payload = try payload.linkObjectBytesForFormatWithImageBases(
                self.allocator,
                .macho,
                spec.payload_object_bytes,
                spec.handler_symbol,
                .{
                    .primary = split_plan.executable.payload_base_address,
                    .writable = if (split_plan.writable) |region| region.payload_base_address else null,
                },
                finalized_target_view,
            );
            defer loaded_payload.deinit(self.allocator);
            std.debug.assert(loaded_payload.entry_offset == payload_layout.entry_offset);
            std.debug.assert(loaded_payload.image.len == payload_layout.image_size);
            if (payload_layout.writable_image_size == 0) {
                std.debug.assert(loaded_payload.writable_image == null);
            } else {
                std.debug.assert(loaded_payload.writable_image != null);
                std.debug.assert(loaded_payload.writable_image.?.len == payload_layout.writable_image_size);
            }

            @memcpy(
                output[split_plan.executable.injection_offset .. split_plan.executable.injection_offset + loaded_payload.image.len],
                loaded_payload.image,
            );
            if (loaded_payload.writable_image) |writable_image| {
                const writable_plan = split_plan.writable orelse return error.MissingWritablePayloadImageBase;
                @memcpy(
                    output[writable_plan.injection_offset .. writable_plan.injection_offset + writable_image.len],
                    writable_image,
                );
            }
        }

        if (finalized_needs_raw_trampoline) {
            const stolen_bytes = output[finalized_target.file_offset .. finalized_target.file_offset + stolen_window_size];
            if (stolen_instruction_count == 1 and finalized_replay_plan.requiresRawTrampoline()) {
                var relocated_instruction: [4]u8 = undefined;
                @memcpy(&relocated_instruction, stolen_bytes);
                const trampoline = try aarch64.buildOriginalTrampolineBytes(
                    self.allocator,
                    relocated_instruction,
                    trampoline_address,
                    target.address + 4,
                    enable_bti,
                );
                defer self.allocator.free(trampoline);
                @memcpy(
                    output[split_plan.executable.injection_offset + trampoline_offset .. split_plan.executable.injection_offset + trampoline_offset + trampoline.len],
                    trampoline,
                );
            } else {
                const trampoline = try aarch64.buildRawTrampoline(
                    self.allocator,
                    stolen_bytes,
                    trampoline_address,
                    target.address + stolen_window_size,
                    enable_bti,
                );
                defer self.allocator.free(trampoline);
                @memcpy(
                    output[split_plan.executable.injection_offset + trampoline_offset .. split_plan.executable.injection_offset + trampoline_offset + trampoline.len],
                    trampoline,
                );
            }
        }

        if (finalized_semantic_entry_layout.total_size != 0) {
            const semantic_entries = try aarch64.buildSemanticInteriorEntries(
                self.allocator,
                finalized_window_plan,
                finalized_semantic_entry_layout,
                semantic_entry_address,
                trampoline_address,
                finalized_target.address,
                enable_bti,
            );
            defer self.allocator.free(semantic_entries);
            @memcpy(
                output[split_plan.executable.injection_offset + semantic_entry_offset .. split_plan.executable.injection_offset + semantic_entry_offset + semantic_entries.len],
                semantic_entries,
            );
        }

        @memcpy(
            output[split_plan.executable.injection_offset + stub_offset .. split_plan.executable.injection_offset + stub_offset + finalized_stub.len],
            finalized_stub,
        );

        const incoming_branches = try collectIncomingBranchRetargets(
            self.allocator,
            finalized_target_view,
            finalized_target.address,
            stolen_instruction_count,
            finalized_window_plan,
        );
        defer self.allocator.free(incoming_branches);

        try writeInstrumentDetourPatch(
            output,
            finalized_target.file_offset,
            finalized_target.address,
            stub_address,
            stolen_instruction_count,
        );
        if (incoming_branches.len != 0) {
            try retargetIncomingBranches(
                output,
                incoming_branches,
                finalized_window_plan,
                trampoline_address,
                semantic_entry_address,
                finalized_semantic_entry_layout,
                enable_bti,
            );
        }

        if (shared_payload_index) |index| {
            try self.refreshSharedMachOPayloadAfterPlan(
                output,
                finalized_target_view,
                split_plan,
                index,
                spec.handler_symbol,
            );
        }

        if (shared_payload == null) {
            try self.rememberSharedInstrumentPayloadMachO(
                .macho,
                spec.payload_object_bytes,
                split_plan.executable.payload_base_address,
                .{
                    .primary_injection_offset = split_plan.executable.injection_offset,
                    .primary_image_size = payload_layout.image_size,
                    .writable_injection_offset = if (split_plan.writable) |region| region.injection_offset else null,
                    .writable_image_size = payload_layout.writable_image_size,
                    .writable_base_address = if (split_plan.writable) |region| region.payload_base_address else null,
                },
            );
        }
        try self.rememberMachOSplitOccupancy(split_plan);
        self.installOutput(output);

        return .{
            .target_address = finalized_target.address,
            .target_file_offset = finalized_target.file_offset,
            .payload_entry_address = callback_address,
            .trampoline_address = if (finalized_needs_raw_trampoline) trampoline_address else null,
            .stub_address = stub_address,
            .injection_offset = split_plan.executable.injection_offset,
            .injected_size = executable_injected_size + writable_image_size,
        };
    }

    fn findSharedInstrumentPayloadIndex(
        self: *const Rewriter,
        binary_format: bundle.BinaryFormat,
        object_bytes: []const u8,
    ) ?usize {
        for (self.shared_instrument_payloads.items, 0..) |entry, index| {
            if (entry.binary_format != binary_format) continue;
            if (!std.mem.eql(u8, entry.object_bytes, object_bytes)) continue;
            return index;
        }
        return null;
    }

    fn rememberSharedInstrumentPayload(
        self: *Rewriter,
        binary_format: bundle.BinaryFormat,
        object_bytes: []const u8,
        primary_base_address: u64,
    ) !void {
        // The first hook that injects a payload image becomes the canonical
        // storage location for later hooks that reuse the same object bytes.
        // Later hooks only need their own local detour/trampoline/stub pieces;
        // their callback address is recovered as:
        //   shared primary base + handler entry offset
        if (self.findSharedInstrumentPayloadIndex(binary_format, object_bytes) != null) return;

        const owned_bytes = try self.allocator.dupe(u8, object_bytes);
        errdefer self.allocator.free(owned_bytes);

        try self.shared_instrument_payloads.append(self.allocator, .{
            .binary_format = binary_format,
            .object_bytes = owned_bytes,
            .primary_base_address = primary_base_address,
        });
    }

    fn rememberSharedInstrumentPayloadMachO(
        self: *Rewriter,
        binary_format: bundle.BinaryFormat,
        object_bytes: []const u8,
        primary_base_address: u64,
        macho_state: SharedMachOPayloadState,
    ) !void {
        if (self.findSharedInstrumentPayloadIndex(binary_format, object_bytes) != null) return;

        const owned_bytes = try self.allocator.dupe(u8, object_bytes);
        errdefer self.allocator.free(owned_bytes);

        try self.shared_instrument_payloads.append(self.allocator, .{
            .binary_format = binary_format,
            .object_bytes = owned_bytes,
            .primary_base_address = primary_base_address,
            .macho = macho_state,
        });
    }

    /// Shared Mach-O payload reuse is only safe while the previously emitted
    /// executable payload image remains at the same linked address.
    ///
    /// If a later rewrite were to move that shared executable image, every
    /// already-installed detour would still branch to the stale callback
    /// address embedded in its older stub. The framework does not yet carry a
    /// "rewrite old stubs and retarget their patch sites" pass, so such plans
    /// must be rejected explicitly instead of silently emitting a corrupted
    /// binary.
    ///
    /// Writable-image movement is narrower in scope and is handled later by
    /// `refreshSharedMachOPayloadAfterPlan`, which re-links the shared payload
    /// object against the new writable base and overwrites the shared payload
    /// bytes in place.
    fn validateSharedMachOPayloadPlanCompatibility(
        self: *const Rewriter,
        split_plan: MachOSplitInjectionPlan,
        shared_payload_index: usize,
    ) !void {
        const entry = self.shared_instrument_payloads.items[shared_payload_index];
        const macho_state = entry.macho orelse return;

        if (split_plan.usesSyntheticSegments()) {
            recordRewriteDiagnostic(
                "shared Mach-O payload reuse for this object would require a later synthetic-segment relayout; rewriting already-installed hook stubs after synthetic shared-payload movement is not implemented yet",
                .{},
            );
            return error.UnsupportedSharedMachOPayloadRelayout;
        }

        const shifted_primary_offset = shiftMachOOffsetAfterSplitPlan(
            macho_state.primary_injection_offset,
            split_plan,
        );
        if (shifted_primary_offset != macho_state.primary_injection_offset) {
            recordRewriteDiagnostic(
                "shared Mach-O payload reuse would move the already-injected executable image from file offset 0x{x} to 0x{x}; refreshing older hook stubs for moved shared payloads is not implemented yet",
                .{
                    macho_state.primary_injection_offset,
                    shifted_primary_offset,
                },
            );
            return error.UnsupportedSharedMachOPayloadRelayout;
        }
    }

    fn refreshSharedMachOPayloadAfterPlan(
        self: *Rewriter,
        output: []u8,
        finalized_target_view: image_backend.View,
        split_plan: MachOSplitInjectionPlan,
        shared_payload_index: usize,
        handler_symbol: []const u8,
    ) !void {
        if (split_plan.usesSyntheticSegments()) return error.UnsupportedSharedMachOPayloadRelayout;

        var entry = &self.shared_instrument_payloads.items[shared_payload_index];
        var macho_state = entry.macho orelse return;

        const shifted_primary_offset = shiftMachOOffsetAfterSplitPlan(
            macho_state.primary_injection_offset,
            split_plan,
        );
        const shifted_writable_offset = if (macho_state.writable_injection_offset) |offset|
            shiftMachOOffsetAfterSplitPlan(offset, split_plan)
        else
            null;

        const new_primary_base = try finalized_target_view.offsetToAddress(shifted_primary_offset);
        const new_writable_base = if (shifted_writable_offset) |offset|
            try finalized_target_view.offsetToAddress(offset)
        else
            null;

        const primary_changed = new_primary_base != entry.primary_base_address;
        const writable_changed = new_writable_base != macho_state.writable_base_address;
        const offset_changed = shifted_primary_offset != macho_state.primary_injection_offset or
            shifted_writable_offset != macho_state.writable_injection_offset;
        if (!primary_changed and !writable_changed and !offset_changed) return;

        if (primary_changed) {
            recordRewriteDiagnostic(
                "shared Mach-O payload reuse changed executable base from 0x{x} to 0x{x}; executable shared-image retargeting is not implemented yet",
                .{ entry.primary_base_address, new_primary_base },
            );
            return error.UnsupportedSharedMachOPayloadRelayout;
        }

        var relinked_payload = try payload.linkObjectBytesForFormatWithImageBases(
            self.allocator,
            .macho,
            entry.object_bytes,
            handler_symbol,
            .{
                .primary = new_primary_base,
                .writable = new_writable_base,
            },
            finalized_target_view,
        );
        defer relinked_payload.deinit(self.allocator);

        std.debug.assert(relinked_payload.image.len == macho_state.primary_image_size);
        @memcpy(
            output[shifted_primary_offset .. shifted_primary_offset + relinked_payload.image.len],
            relinked_payload.image,
        );

        if (macho_state.writable_image_size == 0) {
            std.debug.assert(relinked_payload.writable_image == null);
        } else {
            const writable_offset = shifted_writable_offset orelse return error.MissingWritablePayloadImageBase;
            const writable_image = relinked_payload.writable_image orelse return error.MissingWritablePayloadImage;
            std.debug.assert(writable_image.len == macho_state.writable_image_size);
            @memcpy(
                output[writable_offset .. writable_offset + writable_image.len],
                writable_image,
            );
        }

        entry.primary_base_address = new_primary_base;
        macho_state.primary_injection_offset = shifted_primary_offset;
        macho_state.writable_injection_offset = shifted_writable_offset;
        macho_state.writable_base_address = new_writable_base;
        entry.macho = macho_state;
    }

    pub fn addReplaceHookObject(self: *Rewriter, spec: ReplaceObjectSpec) !ReplaceRewriteReport {
        return self.addReplaceHookObjectForFormat(.elf, spec);
    }

    pub fn addReplaceHookObjectForFormat(
        self: *Rewriter,
        binary_format: bundle.BinaryFormat,
        spec: ReplaceObjectSpec,
    ) !ReplaceRewriteReport {
        clearLastRewriteDiagnostic();
        const base_bytes = self.workingBytes();
        const input_view = try image_backend.View.parseAs(base_bytes, binary_format);
        const original_input_view = try image_backend.View.parseAs(self.input_bytes, binary_format);
        return switch (input_view) {
            .elf => |view| self.addReplaceHookObjectElf(view, original_input_view.elf, spec),
            .macho => |view| self.addReplaceHookObjectMachO(view, original_input_view.macho, spec),
        };
    }

    fn addReplaceHookObjectElf(
        self: *Rewriter,
        input_view: ElfView,
        original_input_view: ElfView,
        spec: ReplaceObjectSpec,
    ) !ReplaceRewriteReport {
        const target_view: image_backend.View = .{ .elf = input_view };
        const original_target_view: image_backend.View = .{ .elf = original_input_view };
        const base_bytes = self.workingBytes();
        const resolved_target = try resolvePatchTargetLocation(
            self.allocator,
            original_target_view,
            target_view,
            spec.target,
        );
        const target = resolved_target.current();
        try validateExpectedBytes(
            self.allocator,
            self.input_bytes,
            resolved_target.original(),
            spec.expected_bytes,
        );

        // Replace hooks reuse the same two-phase payload mini-linker pipeline as
        // instrument hooks; they simply do not need the extra trampoline/stub
        // regions that wrap the linked payload image.
        const payload_layout = try payload.analyzeObjectBytes(self.allocator, spec.payload_object_bytes, spec.replacement_symbol);

        const injected_size = payload_layout.image_size;
        const plan = try planInjectedImage(target_view, injected_size);
        const payload_entry_address = plan.payloadBaseAddress() + payload_layout.entry_offset;

        const loaded_payload = try payload.linkObjectBytes(
            self.allocator,
            spec.payload_object_bytes,
            spec.replacement_symbol,
            plan.payloadBaseAddress(),
            input_view,
        );
        defer self.allocator.free(loaded_payload.image);
        std.debug.assert(loaded_payload.entry_offset == payload_layout.entry_offset);
        std.debug.assert(loaded_payload.image.len == payload_layout.image_size);

        var output = try materializeInjectedOutput(self, target_view, base_bytes, plan);
        errdefer self.allocator.free(output);
        @memcpy(output[plan.injectionOffset() .. plan.injectionOffset() + loaded_payload.image.len], loaded_payload.image);

        output = try finalizeInjectedOutput(self.allocator, target_view, output, plan, true);

        const branch_opcode = aarch64.encodeBranchImmediate(target.address, payload_entry_address) catch |err| {
            if (err == error.BranchOutOfRange) {
                recordRewriteDiagnostic(
                    "replace hook target 0x{x} cannot reach replacement entry 0x{x} with a direct branch",
                    .{ target.address, payload_entry_address },
                );
            }
            return err;
        };
        writeU32(output[target.file_offset .. target.file_offset + 4], branch_opcode);

        self.installOutput(output);

        return .{
            .target_address = target.address,
            .target_file_offset = target.file_offset,
            .payload_entry_address = payload_entry_address,
            .injection_offset = plan.injectionOffset(),
            .injected_size = injected_size,
        };
    }

    fn addReplaceHookObjectMachO(
        self: *Rewriter,
        input_view: MachOView,
        original_input_view: MachOView,
        spec: ReplaceObjectSpec,
    ) !ReplaceRewriteReport {
        const target_view: image_backend.View = .{ .macho = input_view };
        const original_target_view: image_backend.View = .{ .macho = original_input_view };
        const resolved_target = try resolvePatchTargetLocation(
            self.allocator,
            original_target_view,
            target_view,
            spec.target,
        );
        const target = resolved_target.current();
        try validateExpectedBytes(
            self.allocator,
            self.input_bytes,
            resolved_target.original(),
            spec.expected_bytes,
        );

        // Replace hooks are the smallest end-to-end Mach-O payload exercise:
        // no trampoline is needed, but we still prove that the new Mach-O
        // payload linker can produce a fully relocated injected image whose
        // entry point is reachable from the patch site with a direct branch.
        const payload_layout = try payload.analyzeObjectBytesForFormat(
            self.allocator,
            .macho,
            spec.payload_object_bytes,
            spec.replacement_symbol,
        );

        const split_plan = try self.planMachOSplitInjection(
            input_view,
            payload_layout.image_size,
            payload_layout.writable_image_size,
            16,
        );
        const payload_entry_address = split_plan.executable.payload_base_address + payload_layout.entry_offset;

        var loaded_payload = try payload.linkObjectBytesForFormatWithImageBases(
            self.allocator,
            .macho,
            spec.payload_object_bytes,
            spec.replacement_symbol,
            .{
                .primary = split_plan.executable.payload_base_address,
                .writable = if (split_plan.writable) |region| region.payload_base_address else null,
            },
            target_view,
        );
        defer loaded_payload.deinit(self.allocator);
        std.debug.assert(loaded_payload.entry_offset == payload_layout.entry_offset);
        std.debug.assert(loaded_payload.image.len == payload_layout.image_size);
        if (payload_layout.writable_image_size == 0) {
            std.debug.assert(loaded_payload.writable_image == null);
        } else {
            std.debug.assert(loaded_payload.writable_image != null);
            std.debug.assert(loaded_payload.writable_image.?.len == payload_layout.writable_image_size);
        }

        var output = try input_view.materializeSplitInjectedImage(self.allocator, split_plan);
        errdefer self.allocator.free(output);
        @memcpy(
            output[split_plan.executable.injection_offset .. split_plan.executable.injection_offset + loaded_payload.image.len],
            loaded_payload.image,
        );
        if (loaded_payload.writable_image) |writable_image| {
            const writable_plan = split_plan.writable orelse return error.MissingWritablePayloadImageBase;
            @memcpy(
                output[writable_plan.injection_offset .. writable_plan.injection_offset + writable_image.len],
                writable_image,
            );
        }

        output = try finalizeMachOSplitOutput(self.allocator, output, split_plan);

        const branch_opcode = aarch64.encodeBranchImmediate(target.address, payload_entry_address) catch |err| {
            if (err == error.BranchOutOfRange) {
                recordRewriteDiagnostic(
                    "replace hook target 0x{x} cannot reach replacement entry 0x{x} with a direct branch",
                    .{ target.address, payload_entry_address },
                );
            }
            return err;
        };
        writeU32(output[target.file_offset .. target.file_offset + 4], branch_opcode);

        try self.rememberMachOSplitOccupancy(split_plan);
        self.installOutput(output);

        return .{
            .target_address = target.address,
            .target_file_offset = target.file_offset,
            .payload_entry_address = payload_entry_address,
            .injection_offset = split_plan.executable.injection_offset,
            .injected_size = payload_layout.image_size + payload_layout.writable_image_size,
        };
    }
};

fn recordRewriteDiagnostic(comptime fmt: []const u8, args: anytype) void {
    const message = std.fmt.bufPrint(&last_rewrite_diagnostic_buf, fmt, args) catch |err| switch (err) {
        error.NoSpaceLeft => blk: {
            const fallback = "rewrite error (diagnostic truncated)";
            @memcpy(last_rewrite_diagnostic_buf[0..fallback.len], fallback);
            break :blk fallback;
        },
    };
    last_rewrite_diagnostic_len = message.len;
}

fn validateExpectedBytes(
    allocator: std.mem.Allocator,
    base_bytes: []const u8,
    target: ResolvedTarget,
    expected_bytes_hex: []const u8,
) !void {
    if (expected_bytes_hex.len == 0) return;

    const expected = try decodeExpectedBytesHex(allocator, expected_bytes_hex);
    defer allocator.free(expected);

    if (expected.len == 0) {
        recordRewriteDiagnostic(
            "expected-bytes guard at 0x{x} decoded to an empty byte string",
            .{target.address},
        );
        return error.InvalidExpectedBytesHex;
    }

    if (target.file_offset + expected.len > base_bytes.len) {
        recordRewriteDiagnostic(
            "expected-bytes guard at 0x{x} extends past the end of the input image (need {d} bytes)",
            .{ target.address, expected.len },
        );
        return error.ExpectedBytesMismatch;
    }

    const actual = base_bytes[target.file_offset .. target.file_offset + expected.len];
    if (!std.mem.eql(u8, expected, actual)) {
        var expected_hex: [256]u8 = undefined;
        var actual_hex: [256]u8 = undefined;
        recordRewriteDiagnostic(
            "expected-bytes mismatch at 0x{x}: expected {s}, found {s}",
            .{
                target.address,
                formatHexBytes(&expected_hex, expected),
                formatHexBytes(&actual_hex, actual),
            },
        );
        return error.ExpectedBytesMismatch;
    }
}

fn decodeExpectedBytesHex(allocator: std.mem.Allocator, expected_bytes_hex: []const u8) ![]u8 {
    var cleaned: std.ArrayList(u8) = .empty;
    defer cleaned.deinit(allocator);

    for (expected_bytes_hex) |char| {
        if (std.ascii.isWhitespace(char) or char == '_' or char == ':') continue;
        try cleaned.append(allocator, char);
    }

    if (cleaned.items.len == 0) return allocator.alloc(u8, 0);
    if ((cleaned.items.len & 1) != 0) return error.InvalidExpectedBytesHex;

    const decoded = try allocator.alloc(u8, cleaned.items.len / 2);
    errdefer allocator.free(decoded);

    for (decoded, 0..) |*byte, index| {
        const hi = try parseHexNibble(cleaned.items[index * 2]);
        const lo = try parseHexNibble(cleaned.items[index * 2 + 1]);
        byte.* = (@as(u8, hi) << 4) | lo;
    }

    return decoded;
}

fn parseHexNibble(char: u8) !u8 {
    return switch (char) {
        '0'...'9' => char - '0',
        'a'...'f' => char - 'a' + 10,
        'A'...'F' => char - 'A' + 10,
        else => error.InvalidExpectedBytesHex,
    };
}

fn formatHexBytes(buffer: []u8, bytes: []const u8) []const u8 {
    if (buffer.len == 0) return "";

    const digits = "0123456789abcdef";
    const max_bytes = @min(bytes.len, buffer.len / 2);
    for (bytes[0..max_bytes], 0..) |byte, index| {
        buffer[index * 2] = digits[byte >> 4];
        buffer[index * 2 + 1] = digits[byte & 0xF];
    }
    return buffer[0 .. max_bytes * 2];
}

fn resolveTargetLocation(
    allocator: std.mem.Allocator,
    view: image_backend.View,
    target: bundle.HookLocator,
) !ResolvedTarget {
    return switch (target.kind) {
        .symbol => blk: {
            if (target.symbol.len == 0) return error.MissingTargetSymbol;
            const address = try view.resolveSymbolAddress(target.symbol);
            break :blk .{
                .address = address,
                .file_offset = try view.addressToOffset(address),
            };
        },
        .virtual_address => .{
            .address = target.virtual_address,
            .file_offset = try view.addressToOffset(target.virtual_address),
        },
        .file_offset => .{
            .address = try view.offsetToAddress(target.file_offset),
            .file_offset = @intCast(target.file_offset),
        },
        .pattern => try resolvePatternTargetLocation(allocator, view, target),
    };
}

fn resolvePatchTargetLocation(
    allocator: std.mem.Allocator,
    original_view: image_backend.View,
    current_view: image_backend.View,
    target: bundle.HookLocator,
) !ResolvedPatchTarget {
    const original = try resolveTargetLocation(allocator, original_view, target);
    return .{
        .address = original.address,
        .original_file_offset = original.file_offset,
        .current_file_offset = try current_view.addressToOffset(original.address),
    };
}

fn resolvePatternTargetLocation(
    allocator: std.mem.Allocator,
    view: image_backend.View,
    target: bundle.HookLocator,
) !ResolvedTarget {
    if (target.pattern.len == 0) return error.MissingTargetLocator;

    const parsed_pattern = try pattern_locator.parseHexPattern(allocator, target.pattern);
    defer allocator.free(parsed_pattern);

    if (target.pattern_offset >= parsed_pattern.len) {
        recordRewriteDiagnostic(
            "pattern locator offset {d} exceeds pattern length {d}",
            .{ target.pattern_offset, parsed_pattern.len },
        );
        return error.InvalidPatternOffset;
    }

    const matches = try pattern_locator.findMatchesInExecutableSegments(allocator, view, parsed_pattern, 3);
    defer allocator.free(matches);

    if (matches.len == 0) {
        recordRewriteDiagnostic(
            "pattern locator did not match any executable bytes: {s}",
            .{target.pattern},
        );
        return error.PatternNotFound;
    }

    if (matches.len > 1) {
        recordRewriteDiagnostic(
            "pattern locator matched multiple executable locations for {s}: 0x{x}, 0x{x}",
            .{
                target.pattern,
                matches[0].address + target.pattern_offset,
                matches[1].address + target.pattern_offset,
            },
        );
        return error.PatternNotUnique;
    }

    return .{
        .address = matches[0].address + target.pattern_offset,
        .file_offset = matches[0].file_offset + @as(usize, @intCast(target.pattern_offset)),
    };
}

fn validateStolenInstructionCount(count: u8) !usize {
    if (count == 0 or count > aarch64.max_stolen_instruction_count) {
        recordRewriteDiagnostic(
            "unsupported stolen-instruction count {d}; current cap is {d}",
            .{ count, aarch64.max_stolen_instruction_count },
        );
        return error.UnsupportedStolenInstructionCount;
    }
    return count;
}

/// Multi-instruction patch windows are only safe when every displaced address
/// maps contiguously through the executable image. This keeps the current
/// implementation honest: the widened detour steals a straight-line file slice,
/// not an arbitrary cross-segment instruction list.
fn validatePatchWindowMapping(
    view: image_backend.View,
    target: ResolvedTarget,
    stolen_instruction_count: usize,
) !void {
    for (0..stolen_instruction_count) |index| {
        const address = target.address + index * 4;
        const expected_file_offset = target.file_offset + index * 4;
        if (try view.addressToOffset(address) != expected_file_offset) {
            recordRewriteDiagnostic(
                "patch window at 0x{x} is not a contiguous executable mapping at instruction index {d}",
                .{ target.address, index },
            );
            return error.NonContiguousPatchWindow;
        }
    }
}

fn analyzeInstrumentWindowPlan(
    base_bytes: []const u8,
    target: ResolvedTarget,
    stolen_instruction_count: usize,
) !aarch64.WindowPlan {
    if (target.file_offset + stolen_instruction_count * 4 > base_bytes.len) {
        recordRewriteDiagnostic(
            "patch window at 0x{x} with {d} instructions extends beyond the input image",
            .{ target.address, stolen_instruction_count },
        );
        return error.PatchWindowOutOfRange;
    }

    var opcodes: [aarch64.max_stolen_instruction_count]u32 = undefined;
    for (0..stolen_instruction_count) |index| {
        const file_offset = target.file_offset + index * 4;
        opcodes[index] = readU32(base_bytes[file_offset .. file_offset + 4]);
    }

    const window_plan = try aarch64.planWindow(target.address, opcodes[0..stolen_instruction_count]);
    if (stolen_instruction_count == 1) return window_plan;

    if (window_plan.isFullyRawTrampolineSafe()) return window_plan;
    if (window_plan.supportsLinearSemanticPrefixReplay()) return window_plan;
    if (window_plan.supportsTerminalControlToRawSuffixReplay()) return window_plan;
    if (window_plan.supportsSequentialSemanticReplay()) return window_plan;

    for (window_plan.steps[0..window_plan.count], 0..) |step, index| {
        if (!step.usesSemanticReplay()) continue;

        switch (step) {
            .semantic => |replay_plan| {
                recordRewriteDiagnostic(
                    "unsupported widened patch window at 0x{x}: step {d} ({s}) is not yet supported for multi-instruction replay",
                    .{
                        target.address,
                        index,
                        aarch64.replayPlanName(replay_plan),
                    },
                );
            },
            .raw => unreachable,
        }
        break;
    }
    return error.UnsupportedMultiInstructionPatchWindow;
}

fn windowNeedsRawTrampoline(window_plan: aarch64.WindowPlan) bool {
    for (window_plan.steps[0..window_plan.count]) |window_step| {
        switch (window_step) {
            .raw => return true,
            .semantic => {},
        }
    }
    return false;
}

/// Collects direct control-flow edges that land inside the widened patch
/// window.
///
/// Today only interior entries that map to a relocated raw trampoline step are
/// retargetable. Landing in a semantic-only step would require a dedicated
/// entry stub that replays the remaining window from that instruction onward,
/// which is left for a later milestone.
fn collectIncomingBranchRetargets(
    allocator: std.mem.Allocator,
    view: image_backend.View,
    window_start: u64,
    stolen_instruction_count: usize,
    window_plan: aarch64.WindowPlan,
) ![]IncomingBranchRetarget {
    if (stolen_instruction_count <= 1) return allocator.alloc(IncomingBranchRetarget, 0);

    var incoming: std.ArrayList(IncomingBranchRetarget) = .empty;
    defer incoming.deinit(allocator);

    const executable_ranges = try view.executableRanges(allocator);
    defer allocator.free(executable_ranges);
    const bytes = view.bytes();

    const interior_start = window_start + 4;
    const window_end = window_start + stolen_instruction_count * 4;

    for (executable_ranges) |range| {
        var file_offset = range.file_offset;
        const file_end = range.file_offset + range.size;
        while (file_offset + 4 <= file_end) : (file_offset += 4) {
            const source_address = range.address + @as(u64, @intCast(file_offset - range.file_offset));
            if (source_address >= window_start and source_address < window_end) continue;

            const opcode = readU32(bytes[file_offset .. file_offset + 4]);
            const replay_plan = aarch64.planReplay(source_address, opcode) catch continue;
            const branch_target = replayBranchTarget(replay_plan) orelse continue;
            if (branch_target >= interior_start and branch_target < window_end) {
                const target_index: usize = @intCast((branch_target - window_start) / 4);
                if (!windowStepSupportsInteriorRetarget(window_plan, target_index)) {
                    recordRewriteDiagnostic(
                        "incoming branch from 0x{x} targets semantic-only interior step {d} of widened patch window [0x{x}, 0x{x}) at 0x{x}",
                        .{ source_address, target_index, window_start, window_end, branch_target },
                    );
                    return error.IncomingBranchIntoPatchWindow;
                }
                try incoming.append(allocator, .{
                    .source_address = source_address,
                    .source_file_offset = file_offset,
                    .replay_plan = replay_plan,
                    .target_index = target_index,
                });
            }
        }
    }

    return incoming.toOwnedSlice(allocator);
}

fn windowStepSupportsInteriorRetarget(window_plan: aarch64.WindowPlan, index: usize) bool {
    return switch (window_plan.step(index)) {
        .raw => true,
        // Raw interior targets can keep using the relocated trampoline bytes.
        // Semantic interior targets need a dedicated direct-execution entry
        // trampoline generated by the ISA backend.
        .semantic => aarch64.supportsSemanticInteriorEntry(window_plan, index),
    };
}

fn retargetIncomingBranches(
    output: []u8,
    incoming_branches: []const IncomingBranchRetarget,
    window_plan: aarch64.WindowPlan,
    trampoline_address: u64,
    semantic_entry_base_address: u64,
    semantic_entry_layout: aarch64.SemanticInteriorEntryLayout,
    enable_bti: bool,
) !void {
    const trampoline_prefix_size: u64 = if (enable_bti) @sizeOf(u32) else 0;

    for (incoming_branches) |incoming_branch| {
        const new_target_address = switch (window_plan.step(incoming_branch.target_index)) {
            .raw => trampoline_address + trampoline_prefix_size + incoming_branch.target_index * 4,
            .semantic => aarch64.semanticInteriorTargetAddress(
                semantic_entry_layout,
                semantic_entry_base_address,
                incoming_branch.target_index,
            ) orelse return error.UnsupportedIncomingBranchRetarget,
        };

        const replacement_opcode = encodeRetargetedBranch(
            incoming_branch.source_address,
            new_target_address,
            incoming_branch.replay_plan,
        ) catch |err| {
            if (err == error.BranchOutOfRange) {
                recordRewriteDiagnostic(
                    "incoming branch at 0x{x} cannot be retargeted to relocated interior entry 0x{x}; branch encoding is out of range",
                    .{ incoming_branch.source_address, new_target_address },
                );
            }
            return err;
        };

        writeU32(
            output[incoming_branch.source_file_offset .. incoming_branch.source_file_offset + 4],
            replacement_opcode,
        );
    }
}

fn replayBranchTarget(plan: aarch64.ReplayPlan) ?u64 {
    return switch (plan) {
        .branch => |op| op.target,
        .branch_with_link => |op| op.target,
        .conditional_branch => |op| op.target,
        .compare_and_branch => |op| op.target,
        .test_bit_and_branch => |op| op.target,
        else => null,
    };
}

fn encodeRetargetedBranch(source_address: u64, new_target_address: u64, replay_plan: aarch64.ReplayPlan) !u32 {
    const delta = @as(i64, @intCast(new_target_address)) - @as(i64, @intCast(source_address));

    return switch (replay_plan) {
        .branch => try aarch64.encodeBranchImmediate(source_address, new_target_address),
        .branch_with_link => try aarch64.encodeBranchWithLinkImmediate(source_address, new_target_address),
        .conditional_branch => |op| try aarch64.encodeConditionalBranchDelta(op.cond, delta),
        .compare_and_branch => |op| try aarch64.encodeCompareAndBranchDelta(
            op.rt,
            delta,
            !op.branch_on_zero,
            op.is_64bit,
        ),
        .test_bit_and_branch => |op| try aarch64.encodeTestBitAndBranchDelta(
            op.rt,
            op.bit_index,
            delta,
            !op.branch_on_zero,
        ),
        else => error.UnsupportedIncomingBranchRetarget,
    };
}

/// Emits the final patch-site detour.
///
/// Fast path:
/// - use the classic single-word `b stub` when the injected bridge stays within
///   AArch64's ±128 MiB immediate-branch range
///
/// Fallback:
/// - if the hook already widened the patch window to at least 16 bytes, emit a
///   page-relative long detour (`adrp/add/br/nop`)
///
/// This keeps the existing compact encoding for common nearby injections while
/// allowing larger in-image distances without baking a slide-sensitive absolute
/// pointer into the patched target image.
fn writeInstrumentDetourPatch(
    output: []u8,
    target_file_offset: usize,
    target_address: u64,
    stub_address: u64,
    stolen_instruction_count: usize,
) !void {
    const stolen_window_size = stolen_instruction_count * 4;
    const branch_opcode = aarch64.encodeBranchImmediate(target_address, stub_address) catch |err| switch (err) {
        error.BranchOutOfRange => {
            if (stolen_window_size < aarch64.long_detour_size) {
                recordRewriteDiagnostic(
                    "instrument detour from 0x{x} to 0x{x} needs a 16-byte long detour but the stolen window is only {d} bytes",
                    .{ target_address, stub_address, stolen_window_size },
                );
                return error.InsufficientPatchWindowForLongDetour;
            }

            const detour = try aarch64.buildLongDetour(target_address, stub_address);
            @memcpy(
                output[target_file_offset .. target_file_offset + aarch64.long_detour_size],
                &detour,
            );

            for (aarch64.long_detour_size / 4..stolen_instruction_count) |index| {
                writeU32(
                    output[target_file_offset + index * 4 .. target_file_offset + (index + 1) * 4],
                    aarch64.nop_instruction,
                );
            }
            return;
        },
        else => return err,
    };

    writeU32(output[target_file_offset .. target_file_offset + 4], branch_opcode);
    for (1..stolen_instruction_count) |index| {
        writeU32(
            output[target_file_offset + index * 4 .. target_file_offset + (index + 1) * 4],
            aarch64.nop_instruction,
        );
    }
}

/// Chooses where the injected payload blob will live inside the output image.
///
/// The rewriter now routes this through a backend-neutral wrapper so the main
/// hook pipeline can stay structurally identical across ELF and Mach-O:
/// - ELF extends the last `PT_LOAD`
/// - Mach-O extends the carrier segment that precedes `__LINKEDIT`
///
/// The payload linker is still ELF-only today, but the injection planning seam
/// is already shared so adding the Mach-O linker will not require another
/// cross-cutting refactor through the rewrite skeleton.
fn planInjectedImage(input_view: image_backend.View, injected_size: usize) !ImageInjectionPlan {
    return switch (input_view) {
        .elf => |view| .{ .elf = try planElfInjection(view, injected_size) },
        .macho => |view| .{ .macho = try view.planInjection(injected_size, 16) },
    };
}

/// ELF-specific injection planning policy.
///
/// The current ELF strategy is intentionally simple:
/// - locate the last `PT_LOAD`
/// - grow that segment
/// - insert new bytes at the first aligned offset after its in-memory extent
/// - shift the non-loaded file tail forward
fn planElfInjection(input_view: ElfView, injected_size: usize) !ElfInjectionPlan {
    const last_load_index = try input_view.lastLoadSegmentIndex();
    const last_load = input_view.phdrs[last_load_index];
    const load_end_offset: usize = @intCast(last_load.p_offset + last_load.p_filesz);
    const mem_end_offset: usize = @intCast(last_load.p_offset + last_load.p_memsz);
    const injection_offset = std.mem.alignForward(usize, mem_end_offset, 16);
    const tail_output_offset = injection_offset + injected_size;
    const tail_len = input_view.bytes.len - load_end_offset;
    const total_len = tail_output_offset + tail_len;
    const payload_base_address = last_load.p_vaddr + (@as(u64, @intCast(injection_offset)) - last_load.p_offset);

    return .{
        .last_load_index = last_load_index,
        .load_end_offset = load_end_offset,
        .injection_offset = injection_offset,
        .tail_output_offset = tail_output_offset,
        .tail_shift = tail_output_offset - load_end_offset,
        .total_len = total_len,
        .payload_base_address = payload_base_address,
    };
}

/// Allocates the future output image and performs the coarse file-level move.
///
/// The backend-neutral wrapper dispatches to:
/// - the existing ELF "grow last load segment and shift tail" logic
/// - the Mach-O image materializer that preserves bytes up to the injection
///   site and shifts the `__LINKEDIT` tail only when needed
fn materializeInjectedOutput(
    self: *Rewriter,
    input_view: image_backend.View,
    source_bytes: []const u8,
    plan: ImageInjectionPlan,
) ![]u8 {
    return switch (plan) {
        .elf => |elf_plan| materializeElfInjectedOutput(self, source_bytes, elf_plan),
        .macho => |macho_plan| switch (input_view) {
            .macho => |view| view.materializeInjectedImage(self.allocator, macho_plan),
            .elf => unreachable,
        },
    };
}

/// ELF-specific output materialization.
fn materializeElfInjectedOutput(self: *Rewriter, source_bytes: []const u8, plan: ElfInjectionPlan) ![]u8 {
    const output = try self.allocator.alloc(u8, plan.total_len);
    @memset(output, 0);

    @memcpy(output[0..plan.load_end_offset], source_bytes[0..plan.load_end_offset]);

    const tail = source_bytes[plan.load_end_offset..];
    @memcpy(output[plan.tail_output_offset .. plan.tail_output_offset + tail.len], tail);

    return output;
}

/// Repairs image metadata after the new payload bytes have been inserted.
///
/// ELF and Mach-O have very different metadata surfaces, but the rewrite
/// pipeline only needs one abstract operation here:
/// "the injected bytes are now in place, repair the executable image so the
/// loader and later address lookups agree with that new layout".
///
/// Mach-O may additionally shrink the output:
/// - stale `LC_CODE_SIGNATURE` data is removed when the layout is provably safe
///   for later ad-hoc re-signing
/// - the physical byte slice is then truncated so `writeToPath()` emits the
///   same file extent that the repaired load commands now describe
fn finalizeInjectedOutput(
    allocator: std.mem.Allocator,
    input_view: image_backend.View,
    output: []u8,
    plan: ImageInjectionPlan,
    make_executable: bool,
) ![]u8 {
    return switch (plan) {
        .elf => |elf_plan| switch (input_view) {
            .elf => |view| blk: {
                try finalizeElfInjectedOutput(view, output, elf_plan, make_executable);
                break :blk output;
            },
            .macho => unreachable,
        },
        .macho => |macho_plan| {
            var output_view = try MachOView.parse(output);
            const final_size = output_view.finalizeInjectedImage(macho_plan, make_executable) catch |err| switch (err) {
                error.UnsafeMachOCodeSignatureLayout => {
                    if (macho_format.lastDiagnosticMessage()) |message| {
                        recordRewriteDiagnostic("{s}", .{message});
                    } else {
                        recordRewriteDiagnostic(
                            "Mach-O codesign closure refused: output would remain only structurally parseable, not safely re-signable",
                            .{},
                        );
                    }
                    return err;
                },
                else => return err,
            };

            if (final_size == output.len) return output;
            return try allocator.realloc(output, final_size);
        },
    };
}

fn finalizeMachOSplitOutput(
    allocator: std.mem.Allocator,
    output: []u8,
    plan: MachOSplitInjectionPlan,
) ![]u8 {
    var output_view = try MachOView.parse(output);
    const final_size = output_view.finalizeSplitInjectedImage(plan) catch |err| switch (err) {
        error.UnsafeMachOCodeSignatureLayout => {
            if (macho_format.lastDiagnosticMessage()) |message| {
                recordRewriteDiagnostic("{s}", .{message});
            } else {
                recordRewriteDiagnostic(
                    "Mach-O codesign closure refused: output would remain only structurally parseable, not safely re-signable",
                    .{},
                );
            }
            return err;
        },
        else => return err,
    };

    if (final_size == output.len) return output;
    return try allocator.realloc(output, final_size);
}

fn shiftOffsetAtOrAfter(value: usize, threshold: usize, delta: usize) usize {
    if (delta == 0) return value;
    if (value < threshold) return value;
    return value + delta;
}

fn shiftMachOOffsetAfterSplitPlan(
    original_offset: usize,
    plan: MachOSplitInjectionPlan,
) usize {
    if (plan.usesSyntheticSegments()) {
        return shiftOffsetAtOrAfter(original_offset, plan.synthetic_tail_offset, plan.synthetic_tail_shift);
    }

    var shifted = shiftOffsetAtOrAfter(original_offset, plan.executable.tail_offset, plan.executable.tail_shift);
    if (plan.writable) |region| {
        shifted = shiftOffsetAtOrAfter(shifted, region.tail_offset, region.tail_shift);
    }
    return shifted;
}

/// Repairs ELF metadata after the new payload bytes have been inserted.
fn finalizeElfInjectedOutput(
    input_view: ElfView,
    output: []u8,
    plan: ElfInjectionPlan,
    make_executable: bool,
) !void {
    if (input_view.ehdr.e_shoff != 0 and input_view.ehdr.e_shnum != 0) {
        const old_e_shoff: usize = @intCast(input_view.ehdr.e_shoff);
        if (old_e_shoff >= plan.load_end_offset) {
            writeU64(
                output[@offsetOf(elf.Elf64_Ehdr, "e_shoff") .. @offsetOf(elf.Elf64_Ehdr, "e_shoff") + @sizeOf(u64)],
                @intCast(old_e_shoff + plan.tail_shift),
            );
        }
    }

    var output_view = try ElfView.parse(output);
    const output_last_load = &output_view.phdrs[plan.last_load_index];
    const new_segment_file_size = plan.tail_output_offset - @as(usize, @intCast(output_last_load.p_offset));
    output_last_load.p_filesz = @intCast(new_segment_file_size);
    output_last_load.p_memsz = @intCast(new_segment_file_size);
    if (make_executable) output_last_load.p_flags |= elf.PF_X;

    if (output_view.ehdr.e_shoff != 0 and output_view.ehdr.e_shnum != 0) {
        for (output_view.shdrs) |*shdr| {
            if (shdr.sh_type == elf.SHT_NOBITS) continue;
            if (shdr.sh_offset < plan.load_end_offset) continue;
            shdr.sh_offset += plan.tail_shift;
        }
    }
}

fn readU32(bytes: []const u8) u32 {
    const ptr: *const [4]u8 = @ptrCast(bytes.ptr);
    return std.mem.readInt(u32, ptr, .little);
}

fn writeU32(bytes: []u8, value: u32) void {
    var le = std.mem.nativeToLittle(u32, value);
    @memcpy(bytes, std.mem.asBytes(&le));
}

fn writeU64(bytes: []u8, value: u64) void {
    var le = std.mem.nativeToLittle(u64, value);
    @memcpy(bytes, std.mem.asBytes(&le));
}
