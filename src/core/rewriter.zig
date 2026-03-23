const std = @import("std");
const elf = std.elf;
const bundle = @import("bundle.zig");
const aarch64 = @import("../isa/aarch64/root.zig");
const ElfView = @import("../format/elf/root.zig").View;
const payload = @import("payload/object.zig");

pub const InstrumentHookSpec = struct {
    payload_object_path: []const u8,
    target: bundle.HookLocator,
    handler_symbol: []const u8,
    log_message: []const u8 = "",
};

pub const InstrumentObjectSpec = struct {
    payload_object_bytes: []const u8,
    target: bundle.HookLocator,
    handler_symbol: []const u8,
    log_message: []const u8 = "",
};

pub const ReplaceHookSpec = struct {
    payload_object_path: []const u8,
    target: bundle.HookLocator,
    replacement_symbol: []const u8,
};

pub const ReplaceObjectSpec = struct {
    payload_object_bytes: []const u8,
    target: bundle.HookLocator,
    replacement_symbol: []const u8,
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

const ResolvedTarget = struct {
    address: u64,
    file_offset: usize,
};

const InjectionPlan = struct {
    last_load_index: usize,
    load_end_offset: usize,
    injection_offset: usize,
    tail_output_offset: usize,
    tail_shift: usize,
    total_len: usize,
    payload_base_address: u64,
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

    pub fn writeToPath(self: *const Rewriter, output_path: []const u8) !void {
        const file = try std.fs.cwd().createFile(output_path, .{
            .truncate = true,
            .mode = self.input_mode,
        });
        defer file.close();
        try file.writeAll(self.bytes());
    }

    pub fn addInstrumentHook(self: *Rewriter, spec: InstrumentHookSpec) !InstrumentRewriteReport {
        const payload_bytes = try std.fs.cwd().readFileAlloc(self.allocator, spec.payload_object_path, std.math.maxInt(usize));
        defer self.allocator.free(payload_bytes);

        return self.addInstrumentHookObject(.{
            .payload_object_bytes = payload_bytes,
            .target = spec.target,
            .handler_symbol = spec.handler_symbol,
            .log_message = spec.log_message,
        });
    }

    pub fn addReplaceHook(self: *Rewriter, spec: ReplaceHookSpec) !ReplaceRewriteReport {
        const payload_bytes = try std.fs.cwd().readFileAlloc(self.allocator, spec.payload_object_path, std.math.maxInt(usize));
        defer self.allocator.free(payload_bytes);

        return self.addReplaceHookObject(.{
            .payload_object_bytes = payload_bytes,
            .target = spec.target,
            .replacement_symbol = spec.replacement_symbol,
        });
    }

    pub fn addInstrumentHookObject(self: *Rewriter, spec: InstrumentObjectSpec) !InstrumentRewriteReport {
        if (self.output_bytes != null) return error.MultipleHooksUnsupported;

        const input_view = try ElfView.parse(self.input_bytes);
        const target = try resolveTargetLocation(input_view, spec.target);

        var original_instruction: [4]u8 = undefined;
        @memcpy(&original_instruction, self.input_bytes[target.file_offset .. target.file_offset + 4]);
        const original_opcode = readU32(original_instruction[0..]);
        const replay_plan = try aarch64.planReplay(target.address, original_opcode);

        const loaded_payload = try payload.loadTextOnlyObjectBytes(self.allocator, spec.payload_object_bytes, spec.handler_symbol);
        defer self.allocator.free(loaded_payload.text);

        const callback_offset = 0;
        const trampoline_offset = std.mem.alignForward(usize, loaded_payload.text.len, 8);
        const trampoline_size = if (replay_plan.requiresRawTrampoline()) aarch64.original_trampoline_size else 0;
        const stub_offset = std.mem.alignForward(usize, trampoline_offset + trampoline_size, 8);

        const stub = try aarch64.buildInstrumentStub(.{
            .allocator = self.allocator,
            .site_address = target.address,
            .callback_address = 0,
            .trampoline_address = 0,
            .stub_address = 0,
            .replay_plan = replay_plan,
            .log_message = spec.log_message,
        });
        const stub_size = stub.len;
        defer self.allocator.free(stub);
        std.debug.assert(stub.len == stub_size);

        const injected_size = stub_offset + stub_size;
        const plan = try planInjection(input_view, injected_size);
        const callback_address = plan.payload_base_address + callback_offset + loaded_payload.entry_offset;
        const trampoline_address = if (replay_plan.requiresRawTrampoline())
            plan.payload_base_address + trampoline_offset
        else
            0;
        const stub_address = plan.payload_base_address + stub_offset;

        const fixed_stub = try aarch64.buildInstrumentStub(.{
            .allocator = self.allocator,
            .site_address = target.address,
            .callback_address = callback_address,
            .trampoline_address = trampoline_address,
            .stub_address = stub_address,
            .replay_plan = replay_plan,
            .log_message = spec.log_message,
        });
        defer self.allocator.free(fixed_stub);
        std.debug.assert(fixed_stub.len == stub_size);

        const output = try allocateInjectedOutput(self, plan);
        errdefer self.allocator.free(output);

        @memcpy(output[plan.injection_offset + callback_offset .. plan.injection_offset + callback_offset + loaded_payload.text.len], loaded_payload.text);

        if (replay_plan.requiresRawTrampoline()) {
            const trampoline = try aarch64.buildOriginalTrampoline(
                original_instruction,
                trampoline_address,
                target.address + 4,
            );
            @memcpy(output[plan.injection_offset + trampoline_offset .. plan.injection_offset + trampoline_offset + trampoline.len], &trampoline);
        }

        @memcpy(output[plan.injection_offset + stub_offset .. plan.injection_offset + stub_offset + fixed_stub.len], fixed_stub);

        try finalizeInjectedOutput(input_view, output, plan, true);

        const branch_opcode = try aarch64.encodeBranchImmediate(target.address, stub_address);
        writeU32(output[target.file_offset .. target.file_offset + 4], branch_opcode);

        self.output_bytes = output;

        return .{
            .target_address = target.address,
            .target_file_offset = target.file_offset,
            .payload_entry_address = callback_address,
            .trampoline_address = if (replay_plan.requiresRawTrampoline()) trampoline_address else null,
            .stub_address = stub_address,
            .injection_offset = plan.injection_offset,
            .injected_size = injected_size,
        };
    }

    pub fn addReplaceHookObject(self: *Rewriter, spec: ReplaceObjectSpec) !ReplaceRewriteReport {
        if (self.output_bytes != null) return error.MultipleHooksUnsupported;

        const input_view = try ElfView.parse(self.input_bytes);
        const target = try resolveTargetLocation(input_view, spec.target);

        const loaded_payload = try payload.loadTextOnlyObjectBytes(self.allocator, spec.payload_object_bytes, spec.replacement_symbol);
        defer self.allocator.free(loaded_payload.text);

        const injected_size = loaded_payload.text.len;
        const plan = try planInjection(input_view, injected_size);
        const payload_entry_address = plan.payload_base_address + loaded_payload.entry_offset;

        const output = try allocateInjectedOutput(self, plan);
        errdefer self.allocator.free(output);
        @memcpy(output[plan.injection_offset .. plan.injection_offset + loaded_payload.text.len], loaded_payload.text);

        try finalizeInjectedOutput(input_view, output, plan, true);

        const branch_opcode = try aarch64.encodeBranchImmediate(target.address, payload_entry_address);
        writeU32(output[target.file_offset .. target.file_offset + 4], branch_opcode);

        self.output_bytes = output;

        return .{
            .target_address = target.address,
            .target_file_offset = target.file_offset,
            .payload_entry_address = payload_entry_address,
            .injection_offset = plan.injection_offset,
            .injected_size = injected_size,
        };
    }
};

fn resolveTargetLocation(view: ElfView, target: bundle.HookLocator) !ResolvedTarget {
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
    };
}

/// Chooses where the injected payload blob will live inside the output image.
///
/// The current ELF strategy is intentionally simple:
/// - locate the last `PT_LOAD`
/// - grow that segment
/// - insert new bytes at the first aligned offset after its in-memory extent
/// - shift the non-loaded file tail forward
///
/// This is good enough for the current single-image ELF MVP, but the function
/// is documented in detail because future PIE / multi-segment work will almost
/// certainly need to evolve this policy.
fn planInjection(input_view: ElfView, injected_size: usize) !InjectionPlan {
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

/// Allocates the future output image and performs the coarse file-level move:
/// keep the bytes before the old load tail in place, reserve zeroed space for
/// the injection, and shift the remaining file tail to its new offset.
fn allocateInjectedOutput(self: *Rewriter, plan: InjectionPlan) ![]u8 {
    const output = try self.allocator.alloc(u8, plan.total_len);
    @memset(output, 0);

    @memcpy(output[0..plan.load_end_offset], self.input_bytes[0..plan.load_end_offset]);

    const tail = self.input_bytes[plan.load_end_offset..];
    @memcpy(output[plan.tail_output_offset .. plan.tail_output_offset + tail.len], tail);

    return output;
}

/// Repairs ELF metadata after the new payload bytes have been inserted.
///
/// Important details:
/// - the section header table may move when it lives after the injected blob
/// - section file offsets after the old load tail must be shifted forward
/// - the final load segment must grow to cover the injected bytes
/// - the segment is optionally marked executable when code was injected
fn finalizeInjectedOutput(input_view: ElfView, output: []u8, plan: InjectionPlan, make_executable: bool) !void {
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
