const std = @import("std");
const HookContext = @import("../../sdk/root.zig").HookContext;
const replay = @import("replay_plan.zig");

pub const original_trampoline_size: usize = 20;
pub const nop_instruction: u32 = 0xD503_201F;
pub const max_stolen_instruction_count: usize = 4;
pub const ldr_x17_literal_8: u32 = 0x5800_0051;
pub const br_x17: u32 = 0xD61F_0220;
/// Legacy export name retained for compatibility with older callers/tests.
pub const ldr_x16_literal_8: u32 = ldr_x17_literal_8;
/// Legacy export name retained for compatibility with older callers/tests.
pub const br_x16: u32 = br_x17;
pub const ReplayPlan = replay.ReplayPlan;
pub const planReplay = replay.planReplay;
pub const applyReplay = replay.applyReplay;

/// Per-hook parameters used when synthesizing the injected AArch64 instrument
/// bridge.
///
/// The bridge is emitted as raw machine code because the current ELF injector
/// cannot yet mini-link an auxiliary runtime object. Even so, the public ABI is
/// already modeled around the future runtime contract:
/// - the callback receives `(site_address, *HookContext)`
/// - `HookContext.pc` starts at the original site, not the trampoline
/// - if the callback leaves `pc` untouched, the bridge consumes `replay_plan`
///   and decides how execution should continue
///
/// Current implementation limitation:
/// - a truly dynamic indirect resume still needs one terminal branch-carrier
///   register for `br <reg>`
/// - the bridge now avoids that fallback whenever it can: if `ctx.sp` still
///   matches the architectural hook-site SP and `ctx.pc` resolves to one of
///   the bridge-known replay targets, it restores the full GPR bank (including
///   `x16` and `x17`) and resumes via a direct branch
/// - only the remaining generic indirect-resume path still uses `x17` as the
///   branch-carrier scratch register
pub const InstrumentStubOptions = struct {
    allocator: std.mem.Allocator,
    site_address: u64,
    callback_address: u64,
    trampoline_address: u64,
    stub_address: u64,
    replay_plan: ReplayPlan,
    log_message: []const u8,
};

const HookLayout = struct {
    frame_size: usize = std.mem.alignForward(usize, @sizeOf(HookContext) + @sizeOf(u64), 16),
    regs_offset: usize = @offsetOf(HookContext, "regs"),
    sp_offset: usize = @offsetOf(HookContext, "sp"),
    pc_offset: usize = @offsetOf(HookContext, "pc"),
    cpsr_offset: usize = @offsetOf(HookContext, "cpsr"),
    pad_offset: usize = @offsetOf(HookContext, "pad"),
    fpregs_offset: usize = @offsetOf(HookContext, "fpregs"),
    fpsr_offset: usize = @offsetOf(HookContext, "fpsr"),
    fpcr_offset: usize = @offsetOf(HookContext, "fpcr"),
    scratch_offset: usize = std.mem.alignForward(usize, @sizeOf(HookContext) + @sizeOf(u64), 16) - @sizeOf(u64),
};

comptime {
    const layout = HookLayout{};
    std.debug.assert(layout.frame_size >= @sizeOf(HookContext) + @sizeOf(u64));
    std.debug.assert(layout.scratch_offset >= @sizeOf(HookContext));
    std.debug.assert(layout.scratch_offset + @sizeOf(u64) <= layout.frame_size);
}

const Condition = struct {
    const eq: u4 = 0x0;
    const ne: u4 = 0x1;
};

const LiteralLoadRef = struct {
    instruction_offset: usize,
    rt: u5,
    literal_index: u32,
};

const DirectResumeTargets = struct {
    count: usize = 0,
    values: [2]u64 = .{ 0, 0 },

    fn appendUnique(self: *DirectResumeTargets, address: u64) void {
        for (self.values[0..self.count]) |existing| {
            if (existing == address) return;
        }
        std.debug.assert(self.count < self.values.len);
        self.values[self.count] = address;
        self.count += 1;
    }
};

const DirectResumeBranch = struct {
    target_address: u64,
    compare_branch_offset: usize,
    epilogue_offset: usize = 0,
    final_branch_offset: usize = 0,
};

const InstrumentStubBuilder = struct {
    allocator: std.mem.Allocator,
    code: std.array_list.Managed(u8),
    literals: std.array_list.Managed(u64),
    literal_loads: std.array_list.Managed(LiteralLoadRef),

    fn init(allocator: std.mem.Allocator) InstrumentStubBuilder {
        return .{
            .allocator = allocator,
            .code = std.array_list.Managed(u8).init(allocator),
            .literals = std.array_list.Managed(u64).init(allocator),
            .literal_loads = std.array_list.Managed(LiteralLoadRef).init(allocator),
        };
    }

    fn deinit(self: *InstrumentStubBuilder) void {
        self.literal_loads.deinit();
        self.literals.deinit();
        self.code.deinit();
        self.* = undefined;
    }

    fn emitU32(self: *InstrumentStubBuilder, value: u32) !usize {
        const offset = self.code.items.len;
        var le = std.mem.nativeToLittle(u32, value);
        try self.code.appendSlice(std.mem.asBytes(&le));
        return offset;
    }

    fn patchU32(self: *InstrumentStubBuilder, offset: usize, value: u32) void {
        writeU32(self.code.items[offset .. offset + @sizeOf(u32)], value);
    }

    fn reserveLiteral(self: *InstrumentStubBuilder) !u32 {
        try self.literals.append(0);
        return @intCast(self.literals.items.len - 1);
    }

    fn addLiteral(self: *InstrumentStubBuilder, value: u64) !u32 {
        const index = try self.reserveLiteral();
        self.literals.items[index] = value;
        return index;
    }

    fn setLiteral(self: *InstrumentStubBuilder, index: u32, value: u64) void {
        self.literals.items[index] = value;
    }

    fn emitLoadLiteralIndex(self: *InstrumentStubBuilder, rt: u5, literal_index: u32) !void {
        const instruction_offset = try self.emitU32(0);
        try self.literal_loads.append(.{
            .instruction_offset = instruction_offset,
            .rt = rt,
            .literal_index = literal_index,
        });
    }

    fn emitLoadLiteral(self: *InstrumentStubBuilder, rt: u5, value: u64) !void {
        const literal_index = try self.addLiteral(value);
        try self.emitLoadLiteralIndex(rt, literal_index);
    }

    fn alignCode(self: *InstrumentStubBuilder, alignment: usize) !void {
        std.debug.assert((alignment & (alignment - 1)) == 0);
        while ((self.code.items.len & (alignment - 1)) != 0) {
            _ = try self.emitU32(nop);
        }
    }

    fn literalPoolSize(self: *const InstrumentStubBuilder) usize {
        return self.literals.items.len * @sizeOf(u64);
    }

    fn finish(self: *InstrumentStubBuilder, log_message: []const u8) ![]u8 {
        const code_size = self.code.items.len;
        const literal_size = self.literalPoolSize();
        const message_size = if (log_message.len == 0) 0 else log_message.len + 1;
        const total_size = code_size + literal_size + message_size;

        var bytes = try self.allocator.alloc(u8, total_size);
        errdefer self.allocator.free(bytes);
        @memset(bytes, 0);

        @memcpy(bytes[0..code_size], self.code.items);

        var cursor = code_size;
        for (self.literals.items) |value| {
            writeU64(bytes[cursor .. cursor + @sizeOf(u64)], value);
            cursor += @sizeOf(u64);
        }

        for (self.literal_loads.items) |load| {
            const literal_offset = code_size + @as(usize, load.literal_index) * @sizeOf(u64);
            const byte_offset = literal_offset - load.instruction_offset;
            writeU32(
                bytes[load.instruction_offset .. load.instruction_offset + @sizeOf(u32)],
                encodeLdrLiteralDelta(load.rt, byte_offset),
            );
        }

        if (log_message.len != 0) {
            @memcpy(bytes[cursor .. cursor + log_message.len], log_message);
            bytes[cursor + log_message.len] = 0;
        }

        return bytes;
    }
};

/// Rejects instructions that cannot be replayed correctly by the legacy raw
/// copy-and-branch trampoline.
///
/// The instrument path no longer relies on this helper directly: it now plans
/// replay first and lets the generated bridge decide between raw trampoline
/// replay and semantic replay at runtime. The function still exists as an
/// explicit policy check for callers that only support the raw trampoline path.
pub fn validateTrampolineOpcode(site_address: u64, opcode: u32) !void {
    try replay.validateRawTrampolineOpcode(site_address, opcode);
}

/// Builds the tiny out-of-line trampoline used when the replay plan says the
/// displaced instruction is safe to execute verbatim from a different address.
///
/// Emitted sequence:
/// 1. original 32-bit instruction
/// 2. direct `b resume_pc`
/// 3. trailing `nop` padding (keeps the legacy fixed trampoline size)
pub fn buildOriginalTrampoline(
    original_instruction: [4]u8,
    trampoline_address: u64,
    resume_pc: u64,
) ![original_trampoline_size]u8 {
    var buffer: [original_trampoline_size]u8 = undefined;
    @memcpy(buffer[0..4], &original_instruction);
    writeU32(buffer[4..8], try encodeBranchImmediate(trampoline_address + 4, resume_pc));
    writeU32(buffer[8..12], nop);
    writeU32(buffer[12..16], nop);
    writeU32(buffer[16..20], nop);
    return buffer;
}

/// Builds a variable-sized raw trampoline for a widened straight-line patch
/// window.
///
/// The caller provides the exact bytes that were displaced at the original
/// hook site. The trampoline copies them verbatim and then emits one direct
/// branch back to the first instruction after the stolen window.
pub fn buildRawTrampoline(
    allocator: std.mem.Allocator,
    stolen_bytes: []const u8,
    trampoline_address: u64,
    resume_pc: u64,
) ![]u8 {
    if ((stolen_bytes.len & 0x3) != 0) return error.InvalidStolenInstructionBytes;

    const total_size = stolen_bytes.len + @sizeOf(u32);
    var buffer = try allocator.alloc(u8, total_size);
    errdefer allocator.free(buffer);

    @memcpy(buffer[0..stolen_bytes.len], stolen_bytes);
    writeU32(
        buffer[stolen_bytes.len .. stolen_bytes.len + 4],
        try encodeBranchImmediate(trampoline_address + stolen_bytes.len, resume_pc),
    );
    return buffer;
}

/// Builds the injected AArch64 instrument bridge.
///
/// The bridge is intentionally split into three conceptual phases:
/// 1. materialize the public `HookContext` snapshot on the stack
/// 2. invoke the user callback and, if `ctx.pc` still equals the original site,
///    apply the precomputed replay plan
/// 3. restore architectural state from `HookContext` and branch to `ctx.pc`
///
/// This is still a transitional implementation because the injector cannot yet
/// mini-link a reusable runtime object. The code is therefore emitted directly
/// as machine instructions, but the control-flow policy already mirrors the
/// future runtime helper design.
pub fn buildInstrumentStub(options: InstrumentStubOptions) ![]u8 {
    if (options.replay_plan.requiresRawTrampoline() and options.trampoline_address == 0 and options.stub_address != 0) {
        return error.MissingTrampolineAddress;
    }
    if (options.log_message.len > std.math.maxInt(u16)) return error.LogMessageTooLarge;

    const layout = HookLayout{};
    var builder = InstrumentStubBuilder.init(options.allocator);
    defer builder.deinit();

    const message_literal_index = if (options.log_message.len == 0)
        null
    else
        try builder.reserveLiteral();

    try emitStubPrologue(&builder, layout, options.site_address);
    if (message_literal_index) |literal_index| {
        try emitDebugWrite(&builder, literal_index, options.log_message.len);
    }
    try emitCallbackInvocation(&builder, options.site_address, options.callback_address);

    const skip_replay_branch = try emitReplayBypassGuard(&builder, layout, options.site_address);
    try emitReplaySequence(&builder, layout, options);
    const resume_offset = builder.code.items.len;
    builder.patchU32(
        skip_replay_branch,
        try encodeConditionalBranchDelta(
            Condition.ne,
            @as(i64, @intCast(resume_offset)) - @as(i64, @intCast(skip_replay_branch)),
        ),
    );

    try emitResumeDispatcherAndEpilogues(&builder, layout, options);
    try builder.alignCode(8);

    if (message_literal_index) |literal_index| {
        const message_address = options.stub_address +
            @as(u64, @intCast(builder.code.items.len + builder.literalPoolSize()));
        builder.setLiteral(literal_index, message_address);
    }

    return builder.finish(options.log_message);
}

pub fn decodeBranchTarget(branch_opcode: u32, site_address: u64) !u64 {
    if ((branch_opcode & 0x7C00_0000) != 0x1400_0000) return error.NotDirectBranch;
    const imm26: u26 = @truncate(branch_opcode);
    const offset = signExtend(26, @as(u64, imm26)) << 2;
    return addSignedOffset(site_address, offset);
}

pub fn encodeBranchImmediate(from_address: u64, to_address: u64) !u32 {
    const diff = @as(i128, @intCast(to_address)) - @as(i128, @intCast(from_address));
    if ((diff & 0x3) != 0) return error.UnalignedBranchTarget;

    const min_offset = -(@as(i128, 1) << 27);
    const max_offset = (@as(i128, 1) << 27) - 4;
    if (diff < min_offset or diff > max_offset) return error.BranchOutOfRange;

    const imm26: i32 = @intCast(diff >> 2);
    const raw: u32 = @bitCast(imm26);
    return 0x1400_0000 | (raw & 0x03FF_FFFF);
}

fn emitStubPrologue(builder: *InstrumentStubBuilder, layout: HookLayout, site_address: u64) !void {
    _ = try builder.emitU32(encodeSubImmediateSp(layout.frame_size));

    inline for (0..15) |pair_index| {
        const first_reg: u5 = @intCast(pair_index * 2);
        const second_reg: u5 = @intCast(pair_index * 2 + 1);
        _ = try builder.emitU32(
            encodeStpUnsigned(first_reg, second_reg, 31, layout.regs_offset + pair_index * 16),
        );
    }
    _ = try builder.emitU32(encodeStrUnsigned64(30, 31, xRegisterOffset(layout, 30)));

    // `ctx.sp` records the architectural stack pointer visible at the hook
    // site, not the bridge-local frame pointer after `sub sp, sp, #frame_size`.
    _ = try builder.emitU32(encodeAddImmediate(9, 31, layout.frame_size));
    _ = try builder.emitU32(encodeStrUnsigned64(9, 31, layout.sp_offset));

    // The callback sees `ctx.pc == site_address`. Later, the bridge interprets
    // "callback left pc untouched" as "execute the default replay policy".
    try builder.emitLoadLiteral(10, site_address);
    _ = try builder.emitU32(encodeStrUnsigned64(10, 31, layout.pc_offset));

    _ = try builder.emitU32(encodeMrsNzcv(10));
    _ = try builder.emitU32(encodeStrUnsigned32(10, 31, layout.cpsr_offset));
    _ = try builder.emitU32(encodeStrUnsigned32(31, 31, layout.pad_offset));

    inline for (0..16) |pair_index| {
        const first_reg: u5 = @intCast(pair_index * 2);
        const second_reg: u5 = @intCast(pair_index * 2 + 1);
        _ = try builder.emitU32(
            encodeStpSimdUnsigned(first_reg, second_reg, 31, layout.fpregs_offset + pair_index * 32),
        );
    }
    _ = try builder.emitU32(encodeMrsFpsr(10));
    _ = try builder.emitU32(encodeStrUnsigned32(10, 31, layout.fpsr_offset));
    _ = try builder.emitU32(encodeMrsFpcr(10));
    _ = try builder.emitU32(encodeStrUnsigned32(10, 31, layout.fpcr_offset));
}

fn emitDebugWrite(
    builder: *InstrumentStubBuilder,
    message_literal_index: u32,
    log_message_len: usize,
) !void {

    // Linux/AArch64 raw syscall ABI:
    // - x0: fd
    // - x1: buffer
    // - x2: length
    // - x8: syscall number
    _ = try builder.emitU32(encodeMovZ(0, 1));
    try builder.emitLoadLiteralIndex(1, message_literal_index);
    _ = try builder.emitU32(encodeMovZ(2, @intCast(log_message_len)));
    _ = try builder.emitU32(encodeMovZ(8, 64));
    _ = try builder.emitU32(svc_0);
}

fn emitCallbackInvocation(
    builder: *InstrumentStubBuilder,
    site_address: u64,
    callback_address: u64,
) !void {
    try builder.emitLoadLiteral(0, site_address);
    _ = try builder.emitU32(encodeAddImmediate(1, 31, 0));
    try builder.emitLoadLiteral(16, callback_address);
    _ = try builder.emitU32(encodeBlr(16));
}

fn emitReplayBypassGuard(
    builder: *InstrumentStubBuilder,
    layout: HookLayout,
    site_address: u64,
) !usize {
    _ = try builder.emitU32(encodeLdrUnsigned64(16, 31, layout.pc_offset));
    try builder.emitLoadLiteral(17, site_address);
    _ = try builder.emitU32(encodeCmpRegister64(16, 17));
    return builder.emitU32(0);
}

fn emitReplaySequence(
    builder: *InstrumentStubBuilder,
    layout: HookLayout,
    options: InstrumentStubOptions,
) !void {
    const next_pc = options.site_address + 4;

    switch (options.replay_plan) {
        .trampoline => {
            try emitStoreContextPcLiteral(builder, layout, options.trampoline_address);
        },
        .adr => |op| {
            try emitStoreContextRegisterLiteral(builder, layout, op.rd, op.absolute);
            try emitStoreContextPcLiteral(builder, layout, next_pc);
        },
        .adrp => |op| {
            try emitStoreContextRegisterLiteral(builder, layout, op.rd, op.page_base);
            try emitStoreContextPcLiteral(builder, layout, next_pc);
        },
        .ldr_literal_w => |op| {
            try builder.emitLoadLiteral(9, op.literal_address);
            _ = try builder.emitU32(encodeLdrUnsigned32(10, 9, 0));
            _ = try builder.emitU32(encodeStrUnsigned64(10, 31, xRegisterOffset(layout, op.rt)));
            try emitStoreContextPcLiteral(builder, layout, next_pc);
        },
        .ldr_literal_x => |op| {
            try builder.emitLoadLiteral(9, op.literal_address);
            _ = try builder.emitU32(encodeLdrUnsigned64(10, 9, 0));
            _ = try builder.emitU32(encodeStrUnsigned64(10, 31, xRegisterOffset(layout, op.rt)));
            try emitStoreContextPcLiteral(builder, layout, next_pc);
        },
        .ldr_literal_s => |op| {
            const fp_offset = fpRegisterOffset(layout, op.rt);
            try builder.emitLoadLiteral(9, op.literal_address);
            _ = try builder.emitU32(encodeLdrUnsigned32(10, 9, 0));
            _ = try builder.emitU32(encodeStrUnsigned32(10, 31, fp_offset + 0));
            _ = try builder.emitU32(encodeStrUnsigned32(31, 31, fp_offset + 4));
            _ = try builder.emitU32(encodeStrUnsigned64(31, 31, fp_offset + 8));
            try emitStoreContextPcLiteral(builder, layout, next_pc);
        },
        .ldr_literal_d => |op| {
            const fp_offset = fpRegisterOffset(layout, op.rt);
            try builder.emitLoadLiteral(9, op.literal_address);
            _ = try builder.emitU32(encodeLdrUnsigned64(10, 9, 0));
            _ = try builder.emitU32(encodeStrUnsigned64(10, 31, fp_offset + 0));
            _ = try builder.emitU32(encodeStrUnsigned64(31, 31, fp_offset + 8));
            try emitStoreContextPcLiteral(builder, layout, next_pc);
        },
        .ldr_literal_q => |op| {
            const fp_offset = fpRegisterOffset(layout, op.rt);
            try builder.emitLoadLiteral(9, op.literal_address);
            _ = try builder.emitU32(encodeLdrUnsigned64(10, 9, 0));
            _ = try builder.emitU32(encodeLdrUnsigned64(11, 9, 8));
            _ = try builder.emitU32(encodeStrUnsigned64(10, 31, fp_offset + 0));
            _ = try builder.emitU32(encodeStrUnsigned64(11, 31, fp_offset + 8));
            try emitStoreContextPcLiteral(builder, layout, next_pc);
        },
        .ldrsw_literal => |op| {
            try builder.emitLoadLiteral(9, op.literal_address);
            _ = try builder.emitU32(encodeLdrswUnsigned(10, 9, 0));
            _ = try builder.emitU32(encodeStrUnsigned64(10, 31, xRegisterOffset(layout, op.rt)));
            try emitStoreContextPcLiteral(builder, layout, next_pc);
        },
        .prfm_literal => {
            try emitStoreContextPcLiteral(builder, layout, next_pc);
        },
        .branch => |op| {
            try emitStoreContextPcLiteral(builder, layout, op.target);
        },
        .branch_with_link => |op| {
            try emitStoreContextRegisterLiteral(builder, layout, 30, next_pc);
            try emitStoreContextPcLiteral(builder, layout, op.target);
        },
        .conditional_branch => |op| {
            _ = try builder.emitU32(encodeLdrUnsigned32(9, 31, layout.cpsr_offset));
            _ = try builder.emitU32(encodeMsrNzcv(9));
            const branch_to_taken = try builder.emitU32(0);
            try emitStoreContextPcLiteral(builder, layout, next_pc);
            const branch_to_done = try builder.emitU32(0);
            const taken_offset = builder.code.items.len;
            builder.patchU32(
                branch_to_taken,
                try encodeConditionalBranchDelta(
                    op.cond,
                    @as(i64, @intCast(taken_offset)) - @as(i64, @intCast(branch_to_taken)),
                ),
            );
            try emitStoreContextPcLiteral(builder, layout, op.target);
            const done_offset = builder.code.items.len;
            builder.patchU32(
                branch_to_done,
                try encodeBranchDelta(
                    @as(i64, @intCast(done_offset)) - @as(i64, @intCast(branch_to_done)),
                ),
            );
        },
        .compare_and_branch => |op| {
            if (op.is_64bit) {
                _ = try builder.emitU32(encodeLdrUnsigned64(9, 31, xRegisterOffset(layout, op.rt)));
            } else {
                _ = try builder.emitU32(encodeLdrUnsigned32(9, 31, xRegisterOffset(layout, op.rt)));
            }
            const branch_to_taken = try builder.emitU32(0);
            try emitStoreContextPcLiteral(builder, layout, next_pc);
            const branch_to_done = try builder.emitU32(0);
            const taken_offset = builder.code.items.len;
            builder.patchU32(
                branch_to_taken,
                try encodeCompareAndBranchDelta(
                    9,
                    @as(i64, @intCast(taken_offset)) - @as(i64, @intCast(branch_to_taken)),
                    !op.branch_on_zero,
                    op.is_64bit,
                ),
            );
            try emitStoreContextPcLiteral(builder, layout, op.target);
            const done_offset = builder.code.items.len;
            builder.patchU32(
                branch_to_done,
                try encodeBranchDelta(
                    @as(i64, @intCast(done_offset)) - @as(i64, @intCast(branch_to_done)),
                ),
            );
        },
        .test_bit_and_branch => |op| {
            _ = try builder.emitU32(encodeLdrUnsigned64(9, 31, xRegisterOffset(layout, op.rt)));
            const branch_to_taken = try builder.emitU32(0);
            try emitStoreContextPcLiteral(builder, layout, next_pc);
            const branch_to_done = try builder.emitU32(0);
            const taken_offset = builder.code.items.len;
            builder.patchU32(
                branch_to_taken,
                try encodeTestBitAndBranchDelta(
                    9,
                    op.bit_index,
                    @as(i64, @intCast(taken_offset)) - @as(i64, @intCast(branch_to_taken)),
                    !op.branch_on_zero,
                ),
            );
            try emitStoreContextPcLiteral(builder, layout, op.target);
            const done_offset = builder.code.items.len;
            builder.patchU32(
                branch_to_done,
                try encodeBranchDelta(
                    @as(i64, @intCast(done_offset)) - @as(i64, @intCast(branch_to_done)),
                ),
            );
        },
    }
}

fn collectDirectResumeTargets(options: InstrumentStubOptions) DirectResumeTargets {
    var targets = DirectResumeTargets{};
    const next_pc = options.site_address + 4;

    switch (options.replay_plan) {
        .trampoline => targets.appendUnique(options.trampoline_address),
        .adr,
        .adrp,
        .ldr_literal_w,
        .ldr_literal_x,
        .ldr_literal_s,
        .ldr_literal_d,
        .ldr_literal_q,
        .ldrsw_literal,
        .prfm_literal,
        => targets.appendUnique(next_pc),
        .branch => |op| targets.appendUnique(op.target),
        .branch_with_link => |op| targets.appendUnique(op.target),
        .conditional_branch => |op| {
            targets.appendUnique(next_pc);
            targets.appendUnique(op.target);
        },
        .compare_and_branch => |op| {
            targets.appendUnique(next_pc);
            targets.appendUnique(op.target);
        },
        .test_bit_and_branch => |op| {
            targets.appendUnique(next_pc);
            targets.appendUnique(op.target);
        },
    }

    return targets;
}

/// Emits the runtime resume dispatcher together with both epilogue forms.
///
/// The direct epilogue is the new correctness closure for `x17`: when the
/// callback leaves `ctx.sp` equal to the architectural hook-site SP and the
/// final `ctx.pc` matches one of the bridge-known replay targets, the bridge
/// can restore every GPR and resume with a plain direct branch.
///
/// Only the remaining generic indirect path still needs a terminal branch
/// carrier register.
fn emitResumeDispatcherAndEpilogues(
    builder: *InstrumentStubBuilder,
    layout: HookLayout,
    options: InstrumentStubOptions,
) !void {
    const targets = collectDirectResumeTargets(options);
    var target_branches: [2]DirectResumeBranch = undefined;

    // The fully preserving direct path can only recover SP with `add sp, sp,
    // #frame_size`. That is valid exactly when `ctx.sp` still equals the
    // architectural SP visible at the hook site.
    _ = try builder.emitU32(encodeLdrUnsigned64(9, 31, layout.sp_offset));
    _ = try builder.emitU32(encodeAddImmediate(10, 31, layout.frame_size));
    _ = try builder.emitU32(encodeCmpRegister64(9, 10));
    const direct_sp_guard_branch = try builder.emitU32(nop);

    _ = try builder.emitU32(encodeLdrUnsigned64(9, 31, layout.pc_offset));
    for (targets.values[0..targets.count], 0..) |target_address, index| {
        try builder.emitLoadLiteral(10, target_address);
        _ = try builder.emitU32(encodeCmpRegister64(9, 10));
        target_branches[index] = .{
            .target_address = target_address,
            .compare_branch_offset = try builder.emitU32(nop),
        };
    }

    const indirect_epilogue_offset = builder.code.items.len;
    try emitIndirectResumeEpilogue(builder, layout);

    if (options.stub_address != 0) {
        builder.patchU32(
            direct_sp_guard_branch,
            try encodeConditionalBranchDelta(
                Condition.ne,
                @as(i64, @intCast(indirect_epilogue_offset)) - @as(i64, @intCast(direct_sp_guard_branch)),
            ),
        );
    }

    for (targets.values[0..targets.count], 0..) |_, index| {
        target_branches[index].epilogue_offset = builder.code.items.len;
        target_branches[index].final_branch_offset = try emitDirectResumeEpilogue(builder, layout);

        if (options.stub_address == 0) continue;

        const branch_opcode = encodeBranchImmediate(
            options.stub_address + @as(u64, @intCast(target_branches[index].final_branch_offset)),
            target_branches[index].target_address,
        ) catch null;

        if (branch_opcode) |opcode| {
            builder.patchU32(target_branches[index].final_branch_offset, opcode);
            builder.patchU32(
                target_branches[index].compare_branch_offset,
                try encodeConditionalBranchDelta(
                    Condition.eq,
                    @as(i64, @intCast(target_branches[index].epilogue_offset)) -
                        @as(i64, @intCast(target_branches[index].compare_branch_offset)),
                ),
            );
        }
    }
}

/// Restores architectural state from `HookContext` and resumes via a direct
/// branch to a bridge-known target.
///
/// This path preserves the full GPR bank because:
/// - the dispatcher already proved that `ctx.sp` still equals the hook-site SP
/// - SP can therefore be recovered with `add sp, sp, #frame_size`
/// - the final control transfer is a direct `b`, so no GPR must remain live as
///   an indirect branch carrier
fn emitDirectResumeEpilogue(builder: *InstrumentStubBuilder, layout: HookLayout) !usize {
    inline for (0..16) |pair_index| {
        const first_reg: u5 = @intCast(pair_index * 2);
        const second_reg: u5 = @intCast(pair_index * 2 + 1);
        _ = try builder.emitU32(
            encodeLdpSimdUnsigned(first_reg, second_reg, 31, layout.fpregs_offset + pair_index * 32),
        );
    }

    _ = try builder.emitU32(encodeLdrUnsigned32(10, 31, layout.cpsr_offset));
    _ = try builder.emitU32(encodeLdrUnsigned32(11, 31, layout.fpsr_offset));
    _ = try builder.emitU32(encodeLdrUnsigned32(12, 31, layout.fpcr_offset));
    _ = try builder.emitU32(encodeMsrNzcv(10));
    _ = try builder.emitU32(encodeMsrFpsr(11));
    _ = try builder.emitU32(encodeMsrFpcr(12));

    inline for (0..15) |pair_index| {
        const first_reg: u5 = @intCast(pair_index * 2);
        const second_reg: u5 = @intCast(pair_index * 2 + 1);
        _ = try builder.emitU32(
            encodeLdpUnsigned(first_reg, second_reg, 31, layout.regs_offset + pair_index * 16),
        );
    }
    _ = try builder.emitU32(encodeLdrUnsigned64(30, 31, xRegisterOffset(layout, 30)));
    _ = try builder.emitU32(encodeAddImmediate(31, 31, layout.frame_size));
    return builder.emitU32(nop);
}

/// Restores architectural state from `HookContext` and resumes through the
/// generic indirect path.
///
/// This remains necessary when the callback requests a truly dynamic resume PC
/// or custom SP. In that case the bridge still needs one live register for the
/// terminal `br <reg>`, and `x17` currently carries that role.
fn emitIndirectResumeEpilogue(builder: *InstrumentStubBuilder, layout: HookLayout) !void {
    // Persist the final resume PC into the trailing scratch slot while the hook
    // frame is still addressed by SP. After restoring the original SP the same
    // scratch value is reachable as `[sp, #-8]`.
    _ = try builder.emitU32(encodeLdrUnsigned64(17, 31, layout.pc_offset));
    _ = try builder.emitU32(encodeStrUnsigned64(17, 31, layout.scratch_offset));

    inline for (0..16) |pair_index| {
        const first_reg: u5 = @intCast(pair_index * 2);
        const second_reg: u5 = @intCast(pair_index * 2 + 1);
        _ = try builder.emitU32(
            encodeLdpSimdUnsigned(first_reg, second_reg, 31, layout.fpregs_offset + pair_index * 32),
        );
    }

    _ = try builder.emitU32(encodeLdrUnsigned32(10, 31, layout.cpsr_offset));
    _ = try builder.emitU32(encodeLdrUnsigned32(11, 31, layout.fpsr_offset));
    _ = try builder.emitU32(encodeLdrUnsigned32(12, 31, layout.fpcr_offset));
    _ = try builder.emitU32(encodeMsrNzcv(10));
    _ = try builder.emitU32(encodeMsrFpsr(11));
    _ = try builder.emitU32(encodeMsrFpcr(12));

    inline for (0..8) |pair_index| {
        const first_reg: u5 = @intCast(pair_index * 2);
        const second_reg: u5 = @intCast(pair_index * 2 + 1);
        _ = try builder.emitU32(
            encodeLdpUnsigned(first_reg, second_reg, 31, layout.regs_offset + pair_index * 16),
        );
    }

    // `x17` is the one remaining architectural scratch register used by the
    // final resume branch. Restore `x16` explicitly before that hand-off so
    // callbacks may safely edit it.
    _ = try builder.emitU32(encodeLdrUnsigned64(16, 31, xRegisterOffset(layout, 16)));

    inline for (9..15) |pair_index| {
        const first_reg: u5 = @intCast(pair_index * 2);
        const second_reg: u5 = @intCast(pair_index * 2 + 1);
        _ = try builder.emitU32(
            encodeLdpUnsigned(first_reg, second_reg, 31, layout.regs_offset + pair_index * 16),
        );
    }
    _ = try builder.emitU32(encodeLdrUnsigned64(30, 31, xRegisterOffset(layout, 30)));

    _ = try builder.emitU32(encodeLdrUnsigned64(17, 31, layout.sp_offset));
    _ = try builder.emitU32(encodeAddImmediate(31, 17, 0));
    _ = try builder.emitU32(encodeLdur64(17, 31, -8));
    _ = try builder.emitU32(encodeBr(17));
}

fn emitStoreContextPcLiteral(
    builder: *InstrumentStubBuilder,
    layout: HookLayout,
    value: u64,
) !void {
    try builder.emitLoadLiteral(9, value);
    _ = try builder.emitU32(encodeStrUnsigned64(9, 31, layout.pc_offset));
}

fn emitStoreContextRegisterLiteral(
    builder: *InstrumentStubBuilder,
    layout: HookLayout,
    reg: u5,
    value: u64,
) !void {
    if (reg == 31) return;
    try builder.emitLoadLiteral(9, value);
    _ = try builder.emitU32(encodeStrUnsigned64(9, 31, xRegisterOffset(layout, reg)));
}

fn xRegisterOffset(layout: HookLayout, reg: u5) usize {
    return layout.regs_offset + @as(usize, reg) * @sizeOf(u64);
}

fn fpRegisterOffset(layout: HookLayout, reg: u5) usize {
    return layout.fpregs_offset + @as(usize, reg) * @sizeOf(u128);
}

fn writeU32(dest: []u8, value: u32) void {
    var le = std.mem.nativeToLittle(u32, value);
    @memcpy(dest, std.mem.asBytes(&le));
}

fn writeU64(dest: []u8, value: u64) void {
    var le = std.mem.nativeToLittle(u64, value);
    @memcpy(dest, std.mem.asBytes(&le));
}

fn encodeSubImmediateSp(imm: usize) u32 {
    std.debug.assert(imm <= 0xFFF);
    return 0xD100_0000 | (@as(u32, @intCast(imm)) << 10) | (31 << 5) | 31;
}

fn encodeAddImmediate(rd: u5, rn: u5, imm: usize) u32 {
    std.debug.assert(imm <= 0xFFF);
    return 0x9100_0000 | (@as(u32, @intCast(imm)) << 10) | (@as(u32, rn) << 5) | rd;
}

fn encodeStpUnsigned(rt: u5, rt2: u5, rn: u5, offset: usize) u32 {
    std.debug.assert((offset & 0x7) == 0);
    const imm7: u7 = @intCast(offset / 8);
    return 0xA900_0000 | (@as(u32, imm7) << 15) | (@as(u32, rt2) << 10) | (@as(u32, rn) << 5) | rt;
}

fn encodeLdpUnsigned(rt: u5, rt2: u5, rn: u5, offset: usize) u32 {
    std.debug.assert((offset & 0x7) == 0);
    const imm7: u7 = @intCast(offset / 8);
    return 0xA940_0000 | (@as(u32, imm7) << 15) | (@as(u32, rt2) << 10) | (@as(u32, rn) << 5) | rt;
}

fn encodeStpSimdUnsigned(rt: u5, rt2: u5, rn: u5, offset: usize) u32 {
    std.debug.assert((offset & 0xF) == 0);
    const imm7: u7 = @intCast(offset / 16);
    return 0xAD00_0000 | (@as(u32, imm7) << 15) | (@as(u32, rt2) << 10) | (@as(u32, rn) << 5) | rt;
}

fn encodeLdpSimdUnsigned(rt: u5, rt2: u5, rn: u5, offset: usize) u32 {
    std.debug.assert((offset & 0xF) == 0);
    const imm7: u7 = @intCast(offset / 16);
    return 0xAD40_0000 | (@as(u32, imm7) << 15) | (@as(u32, rt2) << 10) | (@as(u32, rn) << 5) | rt;
}

fn encodeStrUnsigned64(rt: u5, rn: u5, offset: usize) u32 {
    std.debug.assert((offset & 0x7) == 0);
    return 0xF900_0000 | (@as(u32, @intCast(offset / 8)) << 10) | (@as(u32, rn) << 5) | rt;
}

fn encodeLdrUnsigned64(rt: u5, rn: u5, offset: usize) u32 {
    std.debug.assert((offset & 0x7) == 0);
    return 0xF940_0000 | (@as(u32, @intCast(offset / 8)) << 10) | (@as(u32, rn) << 5) | rt;
}

fn encodeStrUnsigned32(rt: u5, rn: u5, offset: usize) u32 {
    std.debug.assert((offset & 0x3) == 0);
    return 0xB900_0000 | (@as(u32, @intCast(offset / 4)) << 10) | (@as(u32, rn) << 5) | rt;
}

fn encodeLdrUnsigned32(rt: u5, rn: u5, offset: usize) u32 {
    std.debug.assert((offset & 0x3) == 0);
    return 0xB940_0000 | (@as(u32, @intCast(offset / 4)) << 10) | (@as(u32, rn) << 5) | rt;
}

fn encodeLdrswUnsigned(rt: u5, rn: u5, offset: usize) u32 {
    std.debug.assert((offset & 0x3) == 0);
    return 0xB980_0000 | (@as(u32, @intCast(offset / 4)) << 10) | (@as(u32, rn) << 5) | rt;
}

fn encodeLdur64(rt: u5, rn: u5, offset: i16) u32 {
    std.debug.assert(offset >= -256 and offset <= 255);
    const imm9: u9 = @bitCast(@as(i9, @intCast(offset)));
    return 0xF840_0000 | (@as(u32, imm9) << 12) | (@as(u32, rn) << 5) | rt;
}

fn encodeMovZ(rd: u5, imm16: u16) u32 {
    return 0xD280_0000 | (@as(u32, imm16) << 5) | rd;
}

fn encodeCmpRegister64(rn: u5, rm: u5) u32 {
    return 0xEB00_001F | (@as(u32, rm) << 16) | (@as(u32, rn) << 5);
}

fn encodeLdrLiteralDelta(rt: u5, byte_offset: usize) u32 {
    std.debug.assert((byte_offset & 0x3) == 0);
    const imm19: u19 = @intCast(byte_offset / 4);
    return 0x5800_0000 | (@as(u32, imm19) << 5) | rt;
}

fn encodeConditionalBranchDelta(cond: u4, byte_offset: i64) !u32 {
    if ((byte_offset & 0x3) != 0) return error.UnalignedBranchTarget;
    const imm19 = try encodeSignedBranchImmediate(19, byte_offset);
    return 0x5400_0000 | (@as(u32, imm19) << 5) | cond;
}

fn encodeCompareAndBranchDelta(rt: u5, byte_offset: i64, nonzero: bool, is_64bit: bool) !u32 {
    if ((byte_offset & 0x3) != 0) return error.UnalignedBranchTarget;
    const imm19 = try encodeSignedBranchImmediate(19, byte_offset);
    const sf: u32 = if (is_64bit) 1 else 0;
    const op: u32 = if (nonzero) 1 else 0;
    return (sf << 31) | 0x3400_0000 | (op << 24) | (@as(u32, imm19) << 5) | rt;
}

fn encodeTestBitAndBranchDelta(rt: u5, bit_index: u6, byte_offset: i64, nonzero: bool) !u32 {
    if ((byte_offset & 0x3) != 0) return error.UnalignedBranchTarget;
    const imm14 = try encodeSignedBranchImmediate(14, byte_offset);
    const op: u32 = if (nonzero) 1 else 0;
    const b40: u32 = bit_index & 0x1F;
    const b5: u32 = bit_index >> 5;
    return (b5 << 31) |
        0x3600_0000 |
        (b40 << 19) |
        (op << 24) |
        (@as(u32, imm14) << 5) |
        rt;
}

fn encodeBranchDelta(byte_offset: i64) !u32 {
    if ((byte_offset & 0x3) != 0) return error.UnalignedBranchTarget;
    const imm26 = try encodeSignedBranchImmediate(26, byte_offset);
    return 0x1400_0000 | imm26;
}

fn encodeSignedBranchImmediate(comptime bits: u6, byte_offset: i64) !u32 {
    const shifted = byte_offset >> 2;
    const min = -(@as(i64, 1) << (bits - 1));
    const max = (@as(i64, 1) << (bits - 1)) - 1;
    if (shifted < min or shifted > max) return error.BranchOutOfRange;

    const signed: i32 = @intCast(shifted);
    const raw: u32 = @bitCast(signed);
    return raw & ((@as(u32, 1) << bits) - 1);
}

fn encodeMrsNzcv(rt: u5) u32 {
    return 0xD53B_4200 | @as(u32, rt);
}

fn encodeMsrNzcv(rt: u5) u32 {
    return 0xD51B_4200 | @as(u32, rt);
}

fn encodeMrsFpsr(rt: u5) u32 {
    return 0xD53B_4420 | @as(u32, rt);
}

fn encodeMsrFpsr(rt: u5) u32 {
    return 0xD51B_4420 | @as(u32, rt);
}

fn encodeMrsFpcr(rt: u5) u32 {
    return 0xD53B_4400 | @as(u32, rt);
}

fn encodeMsrFpcr(rt: u5) u32 {
    return 0xD51B_4400 | @as(u32, rt);
}

fn encodeBlr(rn: u5) u32 {
    return 0xD63F_0000 | (@as(u32, rn) << 5);
}

fn encodeBr(rn: u5) u32 {
    return 0xD61F_0000 | (@as(u32, rn) << 5);
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

const nop: u32 = nop_instruction;
const svc_0: u32 = 0xD400_0001;

test "original trampoline resumes with a direct branch" {
    const trampoline_address: u64 = 0x1122_3344_5566_0000;
    const resume_pc: u64 = 0x1122_3344_5566_7788;
    const trampoline = try buildOriginalTrampoline(
        std.mem.toBytes(@as(u32, nop)),
        trampoline_address,
        resume_pc,
    );

    const branch_opcode = std.mem.readInt(u32, trampoline[4..8], .little);
    try std.testing.expectEqual(resume_pc, try decodeBranchTarget(branch_opcode, trampoline_address + 4));
    try std.testing.expectEqual(nop, std.mem.readInt(u32, trampoline[8..12], .little));
    try std.testing.expectEqual(nop, std.mem.readInt(u32, trampoline[12..16], .little));
    try std.testing.expectEqual(nop, std.mem.readInt(u32, trampoline[16..20], .little));
}
