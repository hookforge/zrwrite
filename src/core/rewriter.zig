const std = @import("std");
const elf = std.elf;
const bundle = @import("bundle.zig");
const aarch64 = @import("../isa/aarch64/root.zig");
const image_backend = @import("image_backend.zig");
const ElfView = @import("../format/elf/root.zig").View;
const MachOView = @import("../format/macho/root.zig").View;
const MachOInjectionPlan = @import("../format/macho/root.zig").InjectionPlan;
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

pub const Rewriter = struct {
    allocator: std.mem.Allocator,
    input_bytes: []u8,
    output_bytes: ?[]u8 = null,
    input_mode: u16,

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
        return switch (input_view) {
            .elf => |view| self.addInstrumentHookObjectElf(view, spec),
            .macho => |view| self.addInstrumentHookObjectMachO(view, spec),
        };
    }

    fn addInstrumentHookObjectElf(
        self: *Rewriter,
        input_view: ElfView,
        spec: InstrumentObjectSpec,
    ) !InstrumentRewriteReport {
        const target_view: image_backend.View = .{ .elf = input_view };
        const base_bytes = self.workingBytes();
        const target = try resolveTargetLocation(self.allocator, target_view, spec.target);
        const stolen_instruction_count = try validateStolenInstructionCount(spec.stolen_instruction_count);
        const stolen_window_size = stolen_instruction_count * @sizeOf(u32);
        try validatePatchWindowMapping(target_view, target, stolen_instruction_count);
        try validateExpectedBytes(self.allocator, base_bytes, target, spec.expected_bytes);

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

        // The mini-linker runs in two phases:
        // 1. analyze the object so we know how large the injected image must be
        // 2. after the final injection VA is chosen, link/relocate the payload
        //    against that concrete base address and the target ELF symbol set
        const payload_layout = try payload.analyzeObjectBytes(self.allocator, spec.payload_object_bytes, spec.handler_symbol);

        const callback_offset = 0;
        const trampoline_offset = std.mem.alignForward(usize, payload_layout.image_size, 8);
        const trampoline_size = if (needs_raw_trampoline)
            if (stolen_instruction_count == 1 and replay_plan.requiresRawTrampoline())
                aarch64.original_trampoline_size + bti_prefix_size
            else
                stolen_window_size + aarch64.long_detour_size + bti_prefix_size
        else
            0;
        const stub_offset = std.mem.alignForward(usize, trampoline_offset + trampoline_size, 8);

        const stub = try aarch64.buildInstrumentStub(.{
            .allocator = self.allocator,
            .site_address = target.address,
            .callback_address = 0,
            .trampoline_address = 0,
            .stub_address = 0,
            .replay_plan = replay_plan,
            .window_plan = window_plan,
            .enable_bti = enable_bti,
            .log_message = spec.log_message,
        });
        const stub_size = stub.len;
        defer self.allocator.free(stub);
        std.debug.assert(stub.len == stub_size);

        const injected_size = stub_offset + stub_size;
        const plan = try planInjectedImage(target_view, injected_size);
        const callback_address = plan.payloadBaseAddress() + callback_offset + payload_layout.entry_offset;
        const trampoline_address = if (needs_raw_trampoline)
            plan.payloadBaseAddress() + trampoline_offset
        else
            0;
        const stub_address = plan.payloadBaseAddress() + stub_offset;

        const loaded_payload = try payload.linkObjectBytes(
            self.allocator,
            spec.payload_object_bytes,
            spec.handler_symbol,
            plan.payloadBaseAddress() + callback_offset,
            input_view,
        );
        defer self.allocator.free(loaded_payload.image);
        std.debug.assert(loaded_payload.entry_offset == payload_layout.entry_offset);
        std.debug.assert(loaded_payload.image.len == payload_layout.image_size);

        const fixed_stub = try aarch64.buildInstrumentStub(.{
            .allocator = self.allocator,
            .site_address = target.address,
            .callback_address = callback_address,
            .trampoline_address = trampoline_address,
            .stub_address = stub_address,
            .replay_plan = replay_plan,
            .window_plan = window_plan,
            .enable_bti = enable_bti,
            .log_message = spec.log_message,
        });
        defer self.allocator.free(fixed_stub);
        std.debug.assert(fixed_stub.len == stub_size);

        const output = try materializeInjectedOutput(self, target_view, base_bytes, plan);
        errdefer self.allocator.free(output);

        @memcpy(
            output[plan.injectionOffset() + callback_offset .. plan.injectionOffset() + callback_offset + loaded_payload.image.len],
            loaded_payload.image,
        );

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

        @memcpy(output[plan.injectionOffset() + stub_offset .. plan.injectionOffset() + stub_offset + fixed_stub.len], fixed_stub);

        try finalizeInjectedOutput(target_view, output, plan, true);

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
                enable_bti,
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
        spec: InstrumentObjectSpec,
    ) !InstrumentRewriteReport {
        const target_view: image_backend.View = .{ .macho = input_view };
        const base_bytes = self.workingBytes();
        const target = try resolveTargetLocation(self.allocator, target_view, spec.target);
        const stolen_instruction_count = try validateStolenInstructionCount(spec.stolen_instruction_count);
        const stolen_window_size = stolen_instruction_count * @sizeOf(u32);
        try validatePatchWindowMapping(target_view, target, stolen_instruction_count);
        try validateExpectedBytes(self.allocator, base_bytes, target, spec.expected_bytes);

        // All detour / trampoline / incoming-branch logic is shared with the
        // ELF path. Once the Mach-O image backend can plan/finalize injection
        // and the Mach-O payload mini-linker can produce a relocated callback
        // image, the rest of the instrument pipeline becomes backend-neutral.
        //
        // In other words, the hard Mach-O-specific work lives at the edges:
        // - mapping target addresses/file offsets in the input image
        // - choosing where the injected blob will live in the output image
        // - linking a native Mach-O payload object against that final address
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

        const payload_layout = try payload.analyzeObjectBytesForFormat(
            self.allocator,
            .macho,
            spec.payload_object_bytes,
            spec.handler_symbol,
        );

        const callback_offset = 0;
        const trampoline_offset = std.mem.alignForward(usize, payload_layout.image_size, 8);
        const trampoline_size = if (needs_raw_trampoline)
            if (stolen_instruction_count == 1 and replay_plan.requiresRawTrampoline())
                aarch64.original_trampoline_size + bti_prefix_size
            else
                stolen_window_size + aarch64.long_detour_size + bti_prefix_size
        else
            0;
        const stub_offset = std.mem.alignForward(usize, trampoline_offset + trampoline_size, 8);

        const stub = try aarch64.buildInstrumentStub(.{
            .allocator = self.allocator,
            .site_address = target.address,
            .callback_address = 0,
            .trampoline_address = 0,
            .stub_address = 0,
            .replay_plan = replay_plan,
            .window_plan = window_plan,
            .enable_bti = enable_bti,
            .log_message = spec.log_message,
        });
        const stub_size = stub.len;
        defer self.allocator.free(stub);
        std.debug.assert(stub.len == stub_size);

        const injected_size = stub_offset + stub_size;
        const plan = try planInjectedImage(target_view, injected_size);
        const callback_address = plan.payloadBaseAddress() + callback_offset + payload_layout.entry_offset;
        const trampoline_address = if (needs_raw_trampoline)
            plan.payloadBaseAddress() + trampoline_offset
        else
            0;
        const stub_address = plan.payloadBaseAddress() + stub_offset;

        const loaded_payload = try payload.linkObjectBytesForFormat(
            self.allocator,
            .macho,
            spec.payload_object_bytes,
            spec.handler_symbol,
            plan.payloadBaseAddress() + callback_offset,
            target_view,
        );
        defer self.allocator.free(loaded_payload.image);
        std.debug.assert(loaded_payload.entry_offset == payload_layout.entry_offset);
        std.debug.assert(loaded_payload.image.len == payload_layout.image_size);

        const fixed_stub = try aarch64.buildInstrumentStub(.{
            .allocator = self.allocator,
            .site_address = target.address,
            .callback_address = callback_address,
            .trampoline_address = trampoline_address,
            .stub_address = stub_address,
            .replay_plan = replay_plan,
            .window_plan = window_plan,
            .enable_bti = enable_bti,
            .log_message = spec.log_message,
        });
        defer self.allocator.free(fixed_stub);
        std.debug.assert(fixed_stub.len == stub_size);

        const output = try materializeInjectedOutput(self, target_view, base_bytes, plan);
        errdefer self.allocator.free(output);

        @memcpy(
            output[plan.injectionOffset() + callback_offset .. plan.injectionOffset() + callback_offset + loaded_payload.image.len],
            loaded_payload.image,
        );

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

        @memcpy(output[plan.injectionOffset() + stub_offset .. plan.injectionOffset() + stub_offset + fixed_stub.len], fixed_stub);

        try finalizeInjectedOutput(target_view, output, plan, true);

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
                enable_bti,
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
        return switch (input_view) {
            .elf => |view| self.addReplaceHookObjectElf(view, spec),
            .macho => |view| self.addReplaceHookObjectMachO(view, spec),
        };
    }

    fn addReplaceHookObjectElf(
        self: *Rewriter,
        input_view: ElfView,
        spec: ReplaceObjectSpec,
    ) !ReplaceRewriteReport {
        const target_view: image_backend.View = .{ .elf = input_view };
        const base_bytes = self.workingBytes();
        const target = try resolveTargetLocation(self.allocator, target_view, spec.target);
        try validateExpectedBytes(self.allocator, base_bytes, target, spec.expected_bytes);

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

        const output = try materializeInjectedOutput(self, target_view, base_bytes, plan);
        errdefer self.allocator.free(output);
        @memcpy(output[plan.injectionOffset() .. plan.injectionOffset() + loaded_payload.image.len], loaded_payload.image);

        try finalizeInjectedOutput(target_view, output, plan, true);

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
        spec: ReplaceObjectSpec,
    ) !ReplaceRewriteReport {
        const target_view: image_backend.View = .{ .macho = input_view };
        const base_bytes = self.workingBytes();
        const target = try resolveTargetLocation(self.allocator, target_view, spec.target);
        try validateExpectedBytes(self.allocator, base_bytes, target, spec.expected_bytes);

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

        const injected_size = payload_layout.image_size;
        const plan = try planInjectedImage(target_view, injected_size);
        const payload_entry_address = plan.payloadBaseAddress() + payload_layout.entry_offset;

        const loaded_payload = try payload.linkObjectBytesForFormat(
            self.allocator,
            .macho,
            spec.payload_object_bytes,
            spec.replacement_symbol,
            plan.payloadBaseAddress(),
            target_view,
        );
        defer self.allocator.free(loaded_payload.image);
        std.debug.assert(loaded_payload.entry_offset == payload_layout.entry_offset);
        std.debug.assert(loaded_payload.image.len == payload_layout.image_size);

        const output = try materializeInjectedOutput(self, target_view, base_bytes, plan);
        errdefer self.allocator.free(output);
        @memcpy(output[plan.injectionOffset() .. plan.injectionOffset() + loaded_payload.image.len], loaded_payload.image);

        try finalizeInjectedOutput(target_view, output, plan, true);

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
        .semantic => false,
    };
}

fn retargetIncomingBranches(
    output: []u8,
    incoming_branches: []const IncomingBranchRetarget,
    window_plan: aarch64.WindowPlan,
    trampoline_address: u64,
    enable_bti: bool,
) !void {
    const trampoline_prefix_size: u64 = if (enable_bti) @sizeOf(u32) else 0;

    for (incoming_branches) |incoming_branch| {
        const new_target_address = switch (window_plan.step(incoming_branch.target_index)) {
            .raw => trampoline_address + trampoline_prefix_size + incoming_branch.target_index * 4,
            .semantic => unreachable,
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
fn finalizeInjectedOutput(
    input_view: image_backend.View,
    output: []u8,
    plan: ImageInjectionPlan,
    make_executable: bool,
) !void {
    return switch (plan) {
        .elf => |elf_plan| switch (input_view) {
            .elf => |view| finalizeElfInjectedOutput(view, output, elf_plan, make_executable),
            .macho => unreachable,
        },
        .macho => |macho_plan| {
            var output_view = try MachOView.parse(output);
            try output_view.finalizeInjectedImage(macho_plan, make_executable);
        },
    };
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
