//! AArch64 replay planning and semantic replay helpers.
//!
//! `zrwrite` currently rewrites one 32-bit AArch64 instruction into an
//! out-of-line branch. Some displaced instructions remain correct when copied
//! verbatim into a trampoline; others are PC-relative and therefore change
//! meaning as soon as they move to a different address.
//!
//! This module makes that distinction explicit:
//! - `planReplay(...)` classifies an opcode and computes the metadata needed to
//!   reproduce its architectural effect at the original site.
//! - `applyReplay(...)` can later materialize that effect against a mutable
//!   `HookContext`.
//! - `validateRawTrampolineOpcode(...)` is the bridge back to the current v1
//!   rewriter, which still only knows how to replay "copy-as-is" instructions.
//!
//! The design intentionally mirrors the future direction described in
//! `timeline.md`: keep opcode classification separate from trampoline emission
//! so the static patcher can gradually move from "reject difficult opcodes" to
//! "support semantic replay where safe".

const std = @import("std");
const HookContext = @import("../../sdk/root.zig").HookContext;

/// Current planning cap for one widened patch window.
///
/// The rewriter still fails closed on many multi-instruction shapes today, but
/// raising the cap early lets the planning/data-model layer grow before the
/// execution layer catches up. This keeps Milestone 1 focused on foundation
/// work rather than baking the old 4-instruction assumption deeper into the
/// ABI between the planner and rewriter.
pub const max_window_instruction_count: usize = 16;

/// Replay strategy chosen for a displaced AArch64 instruction.
///
/// `.trampoline` means the opcode may be copied verbatim into an out-of-line
/// trampoline without changing its meaning. Every other tag carries the data
/// needed to re-execute the instruction semantically at the original site.
pub const ReplayPlan = union(enum) {
    /// The instruction is safe to replay from a raw out-of-line trampoline.
    trampoline: void,

    /// `adr xd, label`
    adr: struct {
        rd: u5,
        absolute: u64,
    },

    /// `adrp xd, label`
    adrp: struct {
        rd: u5,
        page_base: u64,
    },

    /// `ldr wt, label`
    ldr_literal_w: struct {
        rt: u5,
        literal_address: u64,
    },

    /// `ldr xt, label`
    ldr_literal_x: struct {
        rt: u5,
        literal_address: u64,
    },

    /// `ldr st, label`
    ///
    /// Scalar FP literal loads target the architectural `vN` register bank. The
    /// low 32 bits are replaced and the remaining 96 bits are cleared.
    ldr_literal_s: struct {
        rt: u5,
        literal_address: u64,
    },

    /// `ldr dt, label`
    ///
    /// The low 64 bits are replaced and the high 64 bits are cleared.
    ldr_literal_d: struct {
        rt: u5,
        literal_address: u64,
    },

    /// `ldr qt, label`
    ldr_literal_q: struct {
        rt: u5,
        literal_address: u64,
    },

    /// `ldrsw xt, label`
    ldrsw_literal: struct {
        rt: u5,
        literal_address: u64,
    },

    /// `prfm <op>, label`
    ///
    /// `prfm` is only a performance hint, so semantic replay becomes "advance
    /// to the next instruction".
    prfm_literal: struct {
        literal_address: u64,
    },

    /// `b label`
    branch: struct {
        target: u64,
    },

    /// `bl label`
    branch_with_link: struct {
        target: u64,
    },

    /// `b.<cond> label`
    conditional_branch: struct {
        cond: u4,
        target: u64,
    },

    /// `cbz` / `cbnz`
    compare_and_branch: struct {
        rt: u5,
        target: u64,
        branch_on_zero: bool,
        is_64bit: bool,
    },

    /// `tbz` / `tbnz`
    test_bit_and_branch: struct {
        rt: u5,
        bit_index: u6,
        target: u64,
        branch_on_zero: bool,
    },

    /// `cmp wn/xn, #imm`
    ///
    /// Terminal widened windows such as `cmp + b.cond` need this explicit
    /// replay shape so the bridge can reproduce the architectural NZCV flags
    /// before evaluating the following semantic branch.
    compare_immediate: struct {
        rn: u5,
        immediate: u64,
        is_64bit: bool,
    },

    /// `cmp wn/xn, wm/xm {, <shift> #amount}`
    compare_register: struct {
        rn: u5,
        rm: u5,
        shift: u2,
        shift_amount: u6,
        is_64bit: bool,
    },

    /// Returns `true` when the current v1 rewriter may still use its raw
    /// "copy original opcode into trampoline" strategy.
    pub fn requiresRawTrampoline(plan: ReplayPlan) bool {
        return switch (plan) {
            .trampoline => true,
            else => false,
        };
    }
};

/// One decoded instruction inside a widened patch window.
///
/// A window step is either:
/// - `.raw`: the original 32-bit opcode may still execute verbatim from a raw
///   trampoline chunk
/// - `.semantic`: the instruction must be replayed by reproducing its
///   architectural effect instead of relocating its bytes
pub const WindowStep = union(enum) {
    raw: struct {
        address: u64,
        opcode: u32,
    },
    semantic: ReplayPlan,

    pub fn usesSemanticReplay(self: WindowStep) bool {
        return switch (self) {
            .raw => false,
            .semantic => true,
        };
    }

    pub fn isControlFlow(self: WindowStep) bool {
        return switch (self) {
            .raw => false,
            .semantic => |plan| switch (plan) {
                .branch,
                .branch_with_link,
                .conditional_branch,
                .compare_and_branch,
                .test_bit_and_branch,
                => true,
                else => false,
            },
        };
    }

    pub fn replayName(self: WindowStep) []const u8 {
        return switch (self) {
            .raw => "raw",
            .semantic => |plan| replayPlanName(plan),
        };
    }
};

/// Planning result for a widened patch window.
///
/// This structure is intentionally introduced before widened semantic replay is
/// fully implemented. Today it already improves diagnostics and removes the
/// hard-coded assumption that "a hook site means exactly one replay plan".
/// Future milestones can reuse the same shape when one window needs a mix of
/// raw trampoline chunks and semantic replay steps.
pub const WindowPlan = struct {
    count: usize = 0,
    steps: [max_window_instruction_count]WindowStep = undefined,

    pub fn appendDecoded(
        self: *WindowPlan,
        address: u64,
        opcode: u32,
        replay_plan: ReplayPlan,
    ) !void {
        if (self.count >= self.steps.len) return error.UnsupportedStolenInstructionCount;

        self.steps[self.count] = switch (replay_plan) {
            .trampoline => .{ .raw = .{
                .address = address,
                .opcode = opcode,
            } },
            else => .{ .semantic = replay_plan },
        };
        self.count += 1;
    }

    pub fn step(self: *const WindowPlan, index: usize) WindowStep {
        std.debug.assert(index < self.count);
        return self.steps[index];
    }

    pub fn hasSemanticReplay(self: *const WindowPlan) bool {
        for (self.steps[0..self.count]) |window_step| {
            if (window_step.usesSemanticReplay()) return true;
        }
        return false;
    }

    pub fn hasControlFlow(self: *const WindowPlan) bool {
        for (self.steps[0..self.count]) |window_step| {
            if (window_step.isControlFlow()) return true;
        }
        return false;
    }

    pub fn isFullyRawTrampolineSafe(self: *const WindowPlan) bool {
        return !self.hasSemanticReplay();
    }

    pub fn leadingSemanticStepCount(self: *const WindowPlan) usize {
        var count: usize = 0;
        while (count < self.count) : (count += 1) {
            if (!self.steps[count].usesSemanticReplay()) break;
        }
        return count;
    }

    /// Returns `true` when the window can be executed as:
    /// 1. semantic replay of a fallthrough-only prefix inside the bridge
    /// 2. optional raw execution of the remaining suffix from the trampoline
    ///
    /// This is the first widened semantic-replay shape because it covers common
    /// `adrp + add/ldr` style address materialization without yet needing a
    /// fully general block interpreter.
    pub fn supportsLinearSemanticPrefixReplay(self: *const WindowPlan) bool {
        if (!self.hasSemanticReplay()) return false;

        const prefix_len = self.leadingSemanticStepCount();
        if (prefix_len == 0) return false;

        for (self.steps[0..prefix_len]) |window_step| {
            if (window_step.isControlFlow()) return false;
        }
        for (self.steps[prefix_len..self.count]) |window_step| {
            if (window_step.usesSemanticReplay()) return false;
        }
        return true;
    }

    /// Returns `true` when every displaced instruction can be replayed
    /// semantically in-order inside the bridge.
    ///
    /// This is the first widened control-flow-capable shape:
    /// - every step must be semantic
    /// - every step before the last must be fallthrough-only
    /// - the final step may either fall through or terminate with a semantic
    ///   branch (`b.cond`, `cbz`, `tbz`, ...)
    pub fn supportsSequentialSemanticReplay(self: *const WindowPlan) bool {
        if (!self.hasSemanticReplay()) return false;

        for (self.steps[0..self.count], 0..) |window_step, index| {
            if (!window_step.usesSemanticReplay()) return false;
            if (index + 1 != self.count and window_step.isControlFlow()) return false;
        }
        return true;
    }

    pub fn singleReplayPlan(self: *const WindowPlan) ?ReplayPlan {
        if (self.count != 1) return null;
        return switch (self.steps[0]) {
            .raw => .{ .trampoline = {} },
            .semantic => |plan| plan,
        };
    }
};

/// Computes the replay plan for the opcode located at `address`.
///
/// Policy:
/// - recognized PC-relative instruction families return semantic replay plans
/// - ordinary instructions default to `.trampoline`
/// - unsupported but recognized PC-relative encodings fail closed
pub fn planReplay(address: u64, opcode: u32) !ReplayPlan {
    if ((address & 0b11) != 0) return error.InvalidAddress;

    const adr_adrp: AdrAdrpInstruction = @bitCast(opcode);
    if (adr_adrp.fixed_op == adr_adrp_fixed_op) {
        return planAdrAdrp(address, adr_adrp);
    }

    const literal_load: LiteralLoadInstruction = @bitCast(opcode);
    if (literal_load.fixed_low == literal_load_fixed_low and
        literal_load.fixed_high == literal_load_fixed_high)
    {
        return planLiteralLoad(address, literal_load);
    }

    const unconditional_branch: UnconditionalImmediateBranchInstruction = @bitCast(opcode);
    if (unconditional_branch.fixed_op == unconditional_immediate_branch_fixed_op) {
        return planImmediateBranch(address, unconditional_branch);
    }

    const conditional_branch: ConditionalImmediateBranchInstruction = @bitCast(opcode);
    if (conditional_branch.fixed_zero == conditional_immediate_branch_fixed_zero and
        conditional_branch.fixed_op == conditional_immediate_branch_fixed_op)
    {
        return planConditionalBranch(address, conditional_branch);
    }

    const add_sub_immediate: AddSubImmediateInstruction = @bitCast(opcode);
    if (add_sub_immediate.fixed_op == add_sub_immediate_fixed_op and
        add_sub_immediate.op == 1 and
        add_sub_immediate.s == 1 and
        add_sub_immediate.rd == 31)
    {
        return planCompareImmediate(add_sub_immediate);
    }

    const add_sub_shifted_register: AddSubShiftedRegisterInstruction = @bitCast(opcode);
    if (add_sub_shifted_register.fixed_zero == add_sub_shifted_register_fixed_zero and
        add_sub_shifted_register.fixed_op == add_sub_shifted_register_fixed_op and
        add_sub_shifted_register.op == 1 and
        add_sub_shifted_register.s == 1 and
        add_sub_shifted_register.rd == 31)
    {
        return planCompareRegister(add_sub_shifted_register);
    }

    const compare_and_branch: CompareAndBranchInstruction = @bitCast(opcode);
    if (compare_and_branch.fixed_op == compare_and_branch_fixed_op) {
        return planCompareAndBranch(address, compare_and_branch);
    }

    const test_bit_and_branch: TestBitAndBranchInstruction = @bitCast(opcode);
    if (test_bit_and_branch.fixed_op == test_bit_and_branch_fixed_op) {
        return planTestBitAndBranch(address, test_bit_and_branch);
    }

    return .{ .trampoline = {} };
}

/// Plans one contiguous instruction window.
///
/// The current rewriter still enforces a narrower execution policy than this
/// planner can describe, but collecting window steps up front gives later
/// widening milestones a stable representation to build on.
pub fn planWindow(start_address: u64, opcodes: []const u32) !WindowPlan {
    if (opcodes.len == 0 or opcodes.len > max_window_instruction_count) {
        return error.UnsupportedStolenInstructionCount;
    }

    var window = WindowPlan{};
    for (opcodes, 0..) |opcode, index| {
        const address = start_address + index * 4;
        try window.appendDecoded(address, opcode, try planReplay(address, opcode));
    }
    return window;
}

pub fn replayPlanName(plan: ReplayPlan) []const u8 {
    return switch (plan) {
        .trampoline => "trampoline",
        .adr => "adr",
        .adrp => "adrp",
        .ldr_literal_w => "ldr_literal_w",
        .ldr_literal_x => "ldr_literal_x",
        .ldr_literal_s => "ldr_literal_s",
        .ldr_literal_d => "ldr_literal_d",
        .ldr_literal_q => "ldr_literal_q",
        .ldrsw_literal => "ldrsw_literal",
        .prfm_literal => "prfm_literal",
        .branch => "branch",
        .branch_with_link => "branch_with_link",
        .conditional_branch => "conditional_branch",
        .compare_and_branch => "compare_and_branch",
        .compare_immediate => "compare_immediate",
        .compare_register => "compare_register",
        .test_bit_and_branch => "test_bit_and_branch",
    };
}

/// Rejects opcodes that the current raw trampoline implementation cannot
/// replay correctly.
///
/// This helper is the compatibility seam for the existing rewriter. As long as
/// the injected instrument stub only knows how to execute the displaced opcode
/// from a copied trampoline, every semantic replay plan must still fail here.
pub fn validateRawTrampolineOpcode(address: u64, opcode: u32) !void {
    const plan = try planReplay(address, opcode);
    if (!plan.requiresRawTrampoline()) return error.UnsupportedOriginalInstruction;
}

/// Applies a previously computed replay plan to a mutable hook context.
///
/// The caller is responsible for invoking the user callback first. If the
/// callback leaves `ctx.pc` untouched and the selected hook mode says
/// "execute original", this helper can reproduce the architectural side
/// effects of the displaced instruction without ever executing it in a raw
/// trampoline.
pub fn applyReplay(plan: ReplayPlan, address: u64, ctx: *HookContext) !void {
    const next_pc = address + 4;

    switch (plan) {
        .trampoline => return error.UnsupportedOriginalInstruction,
        .adr => |op| {
            writeXRegister(ctx, op.rd, op.absolute);
            ctx.pc = next_pc;
        },
        .adrp => |op| {
            writeXRegister(ctx, op.rd, op.page_base);
            ctx.pc = next_pc;
        },
        .ldr_literal_w => |op| {
            var buffer: [4]u8 = undefined;
            readMemoryInto(op.literal_address, buffer[0..]);
            writeWRegister(ctx, op.rt, std.mem.readInt(u32, buffer[0..], .little));
            ctx.pc = next_pc;
        },
        .ldr_literal_x => |op| {
            var buffer: [8]u8 = undefined;
            readMemoryInto(op.literal_address, buffer[0..]);
            writeXRegister(ctx, op.rt, std.mem.readInt(u64, buffer[0..], .little));
            ctx.pc = next_pc;
        },
        .ldr_literal_s => |op| {
            var buffer: [4]u8 = undefined;
            readMemoryInto(op.literal_address, buffer[0..]);
            writeSRegister(ctx, op.rt, std.mem.readInt(u32, buffer[0..], .little));
            ctx.pc = next_pc;
        },
        .ldr_literal_d => |op| {
            var buffer: [8]u8 = undefined;
            readMemoryInto(op.literal_address, buffer[0..]);
            writeDRegister(ctx, op.rt, std.mem.readInt(u64, buffer[0..], .little));
            ctx.pc = next_pc;
        },
        .ldr_literal_q => |op| {
            var buffer: [16]u8 = undefined;
            readMemoryInto(op.literal_address, buffer[0..]);
            writeQRegister(ctx, op.rt, std.mem.readInt(u128, buffer[0..], .little));
            ctx.pc = next_pc;
        },
        .ldrsw_literal => |op| {
            var buffer: [4]u8 = undefined;
            readMemoryInto(op.literal_address, buffer[0..]);
            const signed = std.mem.readInt(i32, buffer[0..], .little);
            writeXRegister(ctx, op.rt, @as(u64, @bitCast(@as(i64, signed))));
            ctx.pc = next_pc;
        },
        .prfm_literal => {
            ctx.pc = next_pc;
        },
        .branch => |op| {
            ctx.pc = op.target;
        },
        .branch_with_link => |op| {
            writeXRegister(ctx, 30, next_pc);
            ctx.pc = op.target;
        },
        .conditional_branch => |op| {
            ctx.pc = if (conditionHolds(ctx.cpsr, op.cond)) op.target else next_pc;
        },
        .compare_immediate => |op| {
            applyCompare(
                ctx,
                op.is_64bit,
                readCompareOperand(ctx, op.rn, op.is_64bit),
                op.immediate,
            );
            ctx.pc = next_pc;
        },
        .compare_register => |op| {
            applyCompare(
                ctx,
                op.is_64bit,
                readCompareOperand(ctx, op.rn, op.is_64bit),
                applyCompareShift(
                    readCompareOperand(ctx, op.rm, op.is_64bit),
                    op.shift,
                    op.shift_amount,
                    op.is_64bit,
                ),
            );
            ctx.pc = next_pc;
        },
        .compare_and_branch => |op| {
            const register_value = readXRegister(ctx, op.rt);
            const is_zero = if (op.is_64bit)
                register_value == 0
            else
                @as(u32, @truncate(register_value)) == 0;

            const should_branch = if (op.branch_on_zero) is_zero else !is_zero;
            ctx.pc = if (should_branch) op.target else next_pc;
        },
        .test_bit_and_branch => |op| {
            const register_value = readXRegister(ctx, op.rt);
            const bit_is_zero = ((register_value >> op.bit_index) & 1) == 0;
            const should_branch = if (op.branch_on_zero) bit_is_zero else !bit_is_zero;
            ctx.pc = if (should_branch) op.target else next_pc;
        },
    }
}

/// `ADR` / `ADRP` immediate encoding class.
const AdrAdrpInstruction = packed struct(u32) {
    rd: u5,
    immhi: u19,
    fixed_op: u5,
    immlo: u2,
    op: u1,
};

/// `LDR (literal)`, `LDRSW (literal)`, and `PRFM (literal)` encoding class.
const LiteralLoadInstruction = packed struct(u32) {
    rt: u5,
    imm19: u19,
    fixed_low: u2,
    v: u1,
    fixed_high: u3,
    opc: u2,
};

/// `B` / `BL` immediate branch encoding class.
const UnconditionalImmediateBranchInstruction = packed struct(u32) {
    imm26: u26,
    fixed_op: u5,
    op: u1,
};

/// `B.<cond>` immediate branch encoding class.
const ConditionalImmediateBranchInstruction = packed struct(u32) {
    cond: u4,
    fixed_zero: u1,
    imm19: u19,
    fixed_op: u8,
};

/// `ADD/SUB (immediate)` encoding class.
const AddSubImmediateInstruction = packed struct(u32) {
    rd: u5,
    rn: u5,
    imm12: u12,
    sh: u1,
    fixed_op: u6,
    s: u1,
    op: u1,
    sf: u1,
};

/// `ADD/SUB (shifted register)` encoding class.
const AddSubShiftedRegisterInstruction = packed struct(u32) {
    rd: u5,
    rn: u5,
    imm6: u6,
    rm: u5,
    fixed_zero: u1,
    shift: u2,
    fixed_op: u5,
    s: u1,
    op: u1,
    sf: u1,
};

/// `CBZ` / `CBNZ` encoding class.
const CompareAndBranchInstruction = packed struct(u32) {
    rt: u5,
    imm19: u19,
    op: u1,
    fixed_op: u6,
    sf: u1,
};

/// `TBZ` / `TBNZ` encoding class.
const TestBitAndBranchInstruction = packed struct(u32) {
    rt: u5,
    imm14: u14,
    b40: u5,
    op: u1,
    fixed_op: u6,
    b5: u1,
};

fn assertInstructionWordLayout(comptime T: type, comptime type_name: []const u8) void {
    if (@bitSizeOf(T) != 32) {
        @compileError(type_name ++ " must remain a 32-bit packed view.");
    }
}

comptime {
    assertInstructionWordLayout(AdrAdrpInstruction, "AdrAdrpInstruction");
    assertInstructionWordLayout(LiteralLoadInstruction, "LiteralLoadInstruction");
    assertInstructionWordLayout(
        UnconditionalImmediateBranchInstruction,
        "UnconditionalImmediateBranchInstruction",
    );
    assertInstructionWordLayout(
        ConditionalImmediateBranchInstruction,
        "ConditionalImmediateBranchInstruction",
    );
    assertInstructionWordLayout(AddSubImmediateInstruction, "AddSubImmediateInstruction");
    assertInstructionWordLayout(
        AddSubShiftedRegisterInstruction,
        "AddSubShiftedRegisterInstruction",
    );
    assertInstructionWordLayout(CompareAndBranchInstruction, "CompareAndBranchInstruction");
    assertInstructionWordLayout(TestBitAndBranchInstruction, "TestBitAndBranchInstruction");
}

const adr_adrp_fixed_op: u5 = 0b10000;
const literal_load_fixed_low: u2 = 0b00;
const literal_load_fixed_high: u3 = 0b011;
const unconditional_immediate_branch_fixed_op: u5 = 0b00101;
const conditional_immediate_branch_fixed_zero: u1 = 0;
const conditional_immediate_branch_fixed_op: u8 = 0x54;
const add_sub_immediate_fixed_op: u6 = 0b100010;
const add_sub_shifted_register_fixed_zero: u1 = 0;
const add_sub_shifted_register_fixed_op: u5 = 0b01011;
const compare_and_branch_fixed_op: u6 = 0b011010;
const test_bit_and_branch_fixed_op: u6 = 0b011011;

fn planAdrAdrp(address: u64, instr: AdrAdrpInstruction) !ReplayPlan {
    const imm21: u21 = (@as(u21, instr.immhi) << 2) | @as(u21, instr.immlo);
    const signed_imm = signExtend(21, @as(u64, imm21));

    if (instr.op == 1) {
        const page_base = try addSignedOffset(address & ~@as(u64, 0xFFF), signed_imm << 12);
        return .{ .adrp = .{ .rd = instr.rd, .page_base = page_base } };
    }

    const absolute = try addSignedOffset(address, signed_imm);
    return .{ .adr = .{ .rd = instr.rd, .absolute = absolute } };
}

fn planLiteralLoad(address: u64, instr: LiteralLoadInstruction) !ReplayPlan {
    const literal_address = try addSignedOffset(address, signExtend(19, @as(u64, instr.imm19)) << 2);

    if (instr.v == 1) {
        return switch (instr.opc) {
            0 => .{ .ldr_literal_s = .{ .rt = instr.rt, .literal_address = literal_address } },
            1 => .{ .ldr_literal_d = .{ .rt = instr.rt, .literal_address = literal_address } },
            2 => .{ .ldr_literal_q = .{ .rt = instr.rt, .literal_address = literal_address } },
            3 => error.UnsupportedOriginalInstruction,
        };
    }

    return switch (instr.opc) {
        0 => .{ .ldr_literal_w = .{ .rt = instr.rt, .literal_address = literal_address } },
        1 => .{ .ldr_literal_x = .{ .rt = instr.rt, .literal_address = literal_address } },
        2 => .{ .ldrsw_literal = .{ .rt = instr.rt, .literal_address = literal_address } },
        3 => .{ .prfm_literal = .{ .literal_address = literal_address } },
    };
}

fn planImmediateBranch(address: u64, instr: UnconditionalImmediateBranchInstruction) !ReplayPlan {
    const target = try addSignedOffset(address, signExtend(26, @as(u64, instr.imm26)) << 2);

    if (instr.op == 1) {
        return .{ .branch_with_link = .{ .target = target } };
    }
    return .{ .branch = .{ .target = target } };
}

fn planConditionalBranch(address: u64, instr: ConditionalImmediateBranchInstruction) !ReplayPlan {
    const target = try addSignedOffset(address, signExtend(19, @as(u64, instr.imm19)) << 2);
    if (instr.cond == 0xF) return error.UnsupportedOriginalInstruction;

    return .{ .conditional_branch = .{ .cond = instr.cond, .target = target } };
}

fn planCompareImmediate(instr: AddSubImmediateInstruction) !ReplayPlan {
    // `SUBS (immediate)` with `rn == 31` aliases the stack pointer form rather
    // than a plain GPR compare. The current semantic bridge does not model SP
    // reads here yet, so keep that corner case fail-closed.
    if (instr.rn == 31) return error.UnsupportedOriginalInstruction;

    const immediate = @as(u64, instr.imm12) << @as(u6, if (instr.sh == 1) 12 else 0);
    return .{
        .compare_immediate = .{
            .rn = instr.rn,
            .immediate = immediate,
            .is_64bit = instr.sf == 1,
        },
    };
}

fn planCompareRegister(instr: AddSubShiftedRegisterInstruction) !ReplayPlan {
    if (instr.shift == 0b11) return error.UnsupportedOriginalInstruction;
    if (instr.sf == 0 and instr.imm6 >= 32) return error.UnsupportedOriginalInstruction;

    return .{
        .compare_register = .{
            .rn = instr.rn,
            .rm = instr.rm,
            .shift = instr.shift,
            .shift_amount = instr.imm6,
            .is_64bit = instr.sf == 1,
        },
    };
}

fn planCompareAndBranch(address: u64, instr: CompareAndBranchInstruction) !ReplayPlan {
    const target = try addSignedOffset(address, signExtend(19, @as(u64, instr.imm19)) << 2);
    return .{
        .compare_and_branch = .{
            .rt = instr.rt,
            .target = target,
            .branch_on_zero = instr.op == 0,
            .is_64bit = instr.sf == 1,
        },
    };
}

fn planTestBitAndBranch(address: u64, instr: TestBitAndBranchInstruction) !ReplayPlan {
    const target = try addSignedOffset(address, signExtend(14, @as(u64, instr.imm14)) << 2);
    const bit_index: u6 = (@as(u6, instr.b5) << 5) | @as(u6, instr.b40);
    return .{
        .test_bit_and_branch = .{
            .rt = instr.rt,
            .bit_index = bit_index,
            .target = target,
            .branch_on_zero = instr.op == 0,
        },
    };
}

fn addSignedOffset(base: u64, offset: i64) !u64 {
    const sum = @as(i128, @intCast(base)) + @as(i128, offset);
    if (sum < 0 or sum > std.math.maxInt(u64)) return error.InvalidAddress;
    return @intCast(sum);
}

fn signExtend(comptime bits: u7, raw: u64) i64 {
    const shift = 64 - bits;
    return @as(i64, @bitCast(raw << shift)) >> shift;
}

fn readMemoryInto(address: u64, out: []u8) void {
    const source: [*]const u8 = @ptrFromInt(@as(usize, @intCast(address)));
    @memcpy(out, source[0..out.len]);
}

fn readCompareOperand(ctx: *HookContext, reg: u5, is_64bit: bool) u64 {
    const value = readXRegister(ctx, reg);
    return if (is_64bit) value else @as(u64, @truncate(value));
}

fn readXRegister(ctx: *HookContext, reg: u5) u64 {
    if (reg == 31) return 0;
    return ctx.regs.x[reg];
}

fn writeXRegister(ctx: *HookContext, reg: u5, value: u64) void {
    if (reg == 31) return;
    ctx.regs.x[reg] = value;
}

fn writeWRegister(ctx: *HookContext, reg: u5, value: u32) void {
    writeXRegister(ctx, reg, @as(u64, value));
}

fn writeSRegister(ctx: *HookContext, reg: u5, value: u32) void {
    ctx.fpregs.v[reg] = value;
}

fn writeDRegister(ctx: *HookContext, reg: u5, value: u64) void {
    ctx.fpregs.v[reg] = value;
}

fn writeQRegister(ctx: *HookContext, reg: u5, value: u128) void {
    ctx.fpregs.v[reg] = value;
}

fn applyCompare(ctx: *HookContext, is_64bit: bool, lhs: u64, rhs: u64) void {
    ctx.cpsr = if (is_64bit)
        mergeNzcv(ctx.cpsr, subtractNzcv64(lhs, rhs))
    else
        mergeNzcv(ctx.cpsr, subtractNzcv32(@truncate(lhs), @truncate(rhs)));
}

fn applyCompareShift(value: u64, shift: u2, shift_amount: u6, is_64bit: bool) u64 {
    if (is_64bit) {
        return switch (shift) {
            0b00 => value << shift_amount,
            0b01 => value >> shift_amount,
            0b10 => @bitCast(@as(i64, @bitCast(value)) >> shift_amount),
            0b11 => unreachable,
        };
    }

    const narrowed: u32 = @truncate(value);
    return switch (shift) {
        0b00 => @as(u64, narrowed << @as(u5, @truncate(shift_amount))),
        0b01 => @as(u64, narrowed >> @as(u5, @truncate(shift_amount))),
        0b10 => blk: {
            const signed: i32 = @bitCast(narrowed);
            const shifted: i32 = signed >> @as(u5, @truncate(shift_amount));
            break :blk @as(u64, @bitCast(@as(u32, @bitCast(shifted))));
        },
        0b11 => unreachable,
    };
}

fn mergeNzcv(cpsr: u32, nzcv: u4) u32 {
    return (cpsr & 0x0FFF_FFFF) | (@as(u32, nzcv) << 28);
}

fn subtractNzcv64(lhs: u64, rhs: u64) u4 {
    const result, const borrow = @subWithOverflow(lhs, rhs);
    const lhs_signed: i64 = @bitCast(lhs);
    const rhs_signed: i64 = @bitCast(rhs);
    const result_signed: i64 = @bitCast(result);
    const overflow = ((lhs_signed ^ rhs_signed) & (lhs_signed ^ result_signed)) < 0;

    return packNzcv(
        (result >> 63) != 0,
        result == 0,
        borrow == 0,
        overflow,
    );
}

fn subtractNzcv32(lhs: u32, rhs: u32) u4 {
    const result, const borrow = @subWithOverflow(lhs, rhs);
    const lhs_signed: i32 = @bitCast(lhs);
    const rhs_signed: i32 = @bitCast(rhs);
    const result_signed: i32 = @bitCast(result);
    const overflow = ((lhs_signed ^ rhs_signed) & (lhs_signed ^ result_signed)) < 0;

    return packNzcv(
        (result >> 31) != 0,
        result == 0,
        borrow == 0,
        overflow,
    );
}

fn packNzcv(n: bool, z: bool, c: bool, v: bool) u4 {
    return (@as(u4, if (n) 1 else 0) << 3) |
        (@as(u4, if (z) 1 else 0) << 2) |
        (@as(u4, if (c) 1 else 0) << 1) |
        @as(u4, if (v) 1 else 0);
}

fn conditionHolds(cpsr: u32, cond: u4) bool {
    const n = ((cpsr >> 31) & 1) != 0;
    const z = ((cpsr >> 30) & 1) != 0;
    const c = ((cpsr >> 29) & 1) != 0;
    const v = ((cpsr >> 28) & 1) != 0;

    return switch (cond) {
        0x0 => z,
        0x1 => !z,
        0x2 => c,
        0x3 => !c,
        0x4 => n,
        0x5 => !n,
        0x6 => v,
        0x7 => !v,
        0x8 => c and !z,
        0x9 => !c or z,
        0xA => n == v,
        0xB => n != v,
        0xC => !z and (n == v),
        0xD => z or (n != v),
        0xE => true,
        0xF => false,
    };
}

test "replay planner recognizes common PC-relative families" {
    try std.testing.expectEqualDeep(
        ReplayPlan{ .adr = .{ .rd = 0, .absolute = 0x1004 } },
        try planReplay(0x1000, 0x1000_0020),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{ .adrp = .{ .rd = 0, .page_base = 0x1000 } },
        try planReplay(0x1234, 0x9000_0000),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{ .ldr_literal_x = .{ .rt = 1, .literal_address = 0x38 } },
        try planReplay(0x8, 0x5800_0181),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{ .ldr_literal_w = .{ .rt = 2, .literal_address = 0x34 } },
        try planReplay(0xC, 0x1800_0142),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{ .ldr_literal_s = .{ .rt = 0, .literal_address = 0x8 } },
        try planReplay(0x0, 0x1C00_0040),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{ .ldr_literal_d = .{ .rt = 0, .literal_address = 0x14 } },
        try planReplay(0xC, 0x5C00_0040),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{ .ldr_literal_q = .{ .rt = 0, .literal_address = 0x24 } },
        try planReplay(0x1C, 0x9C00_0040),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{ .ldrsw_literal = .{ .rt = 3, .literal_address = 0x34 } },
        try planReplay(0x10, 0x9800_0123),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{ .prfm_literal = .{ .literal_address = 0x18 } },
        try planReplay(0x0, 0xD800_00C0),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{ .branch = .{ .target = 0x30 } },
        try planReplay(0x14, 0x1400_0007),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{ .branch_with_link = .{ .target = 0x30 } },
        try planReplay(0x18, 0x9400_0006),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{ .conditional_branch = .{ .cond = 0, .target = 0x30 } },
        try planReplay(0x1C, 0x5400_00A0),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{
            .compare_immediate = .{
                .rn = 0,
                .immediate = 7,
                .is_64bit = false,
            },
        },
        try planReplay(0x20, 0x7100_1C1F),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{
            .compare_register = .{
                .rn = 1,
                .rm = 2,
                .shift = 0,
                .shift_amount = 0,
                .is_64bit = true,
            },
        },
        try planReplay(0x24, 0xEB02_003F),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{
            .compare_and_branch = .{
                .rt = 4,
                .target = 0x30,
                .branch_on_zero = true,
                .is_64bit = true,
            },
        },
        try planReplay(0x20, 0xB400_0084),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{
            .compare_and_branch = .{
                .rt = 4,
                .target = 0x18,
                .branch_on_zero = false,
                .is_64bit = true,
            },
        },
        try planReplay(0x4, 0xB500_00A4),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{
            .test_bit_and_branch = .{
                .rt = 6,
                .bit_index = 3,
                .target = 0x30,
                .branch_on_zero = true,
            },
        },
        try planReplay(0x28, 0x3618_0046),
    );
    try std.testing.expectEqualDeep(
        ReplayPlan{
            .test_bit_and_branch = .{
                .rt = 6,
                .bit_index = 3,
                .target = 0x18,
                .branch_on_zero = false,
            },
        },
        try planReplay(0x8, 0x3718_0086),
    );
}

test "ordinary non PC-relative instructions remain raw-trampoline safe" {
    try std.testing.expectEqualDeep(
        ReplayPlan{ .trampoline = {} },
        try planReplay(0x0, 0xA940_0440),
    ); // ldp x0, x1, [x2]
    try std.testing.expectEqualDeep(
        ReplayPlan{ .trampoline = {} },
        try planReplay(0x4, 0xA900_10A3),
    ); // stp x3, x4, [x5]
    try std.testing.expectEqualDeep(
        ReplayPlan{ .trampoline = {} },
        try planReplay(0x8, 0x9104_8CE6),
    ); // add x6, x7, #0x123
}

test "raw trampoline validation rejects semantic replay cases" {
    try validateRawTrampolineOpcode(0x1000, 0x9104_8CE6);
    try std.testing.expectError(
        error.UnsupportedOriginalInstruction,
        validateRawTrampolineOpcode(0x1000, 0x1000_0020),
    );
    try std.testing.expectError(
        error.UnsupportedOriginalInstruction,
        validateRawTrampolineOpcode(0x1000, 0x9400_0006),
    );
}

test "window planner tracks mixed raw and semantic steps" {
    const window = try planWindow(0x1000, &.{
        0x9000_0000, // adrp x0, ...
        0x9104_8CE6, // add x6, x7, #0x123
    });

    try std.testing.expectEqual(@as(usize, 2), window.count);
    try std.testing.expect(window.hasSemanticReplay());
    try std.testing.expect(!window.hasControlFlow());
    try std.testing.expect(!window.isFullyRawTrampolineSafe());
    try std.testing.expectEqualStrings("adrp", window.step(0).replayName());
    try std.testing.expectEqualStrings("raw", window.step(1).replayName());
    try std.testing.expectEqual(@as(usize, 1), window.leadingSemanticStepCount());
    try std.testing.expect(window.supportsLinearSemanticPrefixReplay());
}

test "condition evaluator matches common NZCV predicates" {
    const z_set: u32 = 1 << 30;
    const c_set: u32 = 1 << 29;
    const n_set: u32 = 1 << 31;
    const v_set: u32 = 1 << 28;

    try std.testing.expect(conditionHolds(z_set, 0x0));
    try std.testing.expect(!conditionHolds(0, 0x0));
    try std.testing.expect(conditionHolds(c_set, 0x2));
    try std.testing.expect(conditionHolds(n_set | v_set, 0xA));
    try std.testing.expect(conditionHolds(n_set, 0xB));
    try std.testing.expect(conditionHolds(0, 0xE));
}

test "compare replay updates NZCV for widened terminal branch windows" {
    var ctx = std.mem.zeroes(HookContext);
    ctx.regs.x[0] = 7;
    ctx.regs.x[1] = 8;

    try applyReplay(
        .{
            .compare_immediate = .{
                .rn = 0,
                .immediate = 7,
                .is_64bit = false,
            },
        },
        0x1000,
        &ctx,
    );
    try std.testing.expect(conditionHolds(ctx.cpsr, 0x0));
    try std.testing.expectEqual(@as(u64, 0x1004), ctx.pc);

    try applyReplay(
        .{
            .compare_register = .{
                .rn = 1,
                .rm = 0,
                .shift = 0,
                .shift_amount = 0,
                .is_64bit = true,
            },
        },
        0x1004,
        &ctx,
    );
    try std.testing.expect(conditionHolds(ctx.cpsr, 0x1));
    try std.testing.expect(conditionHolds(ctx.cpsr, 0x2));
    try std.testing.expectEqual(@as(u64, 0x1008), ctx.pc);
}

test "FP literal replay updates q registers with the correct scalar semantics" {
    const literal_s: u32 = 0x3F80_0000;
    const literal_d: u64 = 0x4000_0000_0000_0000;
    const literal_q: u128 =
        (@as(u128, 0x0F1E_2D3C_4B5A_6978) << 64) | 0x8877_6655_4433_2211;

    var ctx = std.mem.zeroes(HookContext);
    ctx.fpregs.v[1] = std.math.maxInt(u128);
    ctx.fpregs.v[2] = std.math.maxInt(u128);
    ctx.fpregs.v[3] = std.math.maxInt(u128);

    try applyReplay(
        .{ .ldr_literal_s = .{ .rt = 1, .literal_address = @intFromPtr(&literal_s) } },
        0x1000,
        &ctx,
    );
    try std.testing.expectEqual(@as(u128, literal_s), ctx.fpregs.v[1]);
    try std.testing.expectEqual(@as(u64, 0x1004), ctx.pc);

    try applyReplay(
        .{ .ldr_literal_d = .{ .rt = 2, .literal_address = @intFromPtr(&literal_d) } },
        0x2000,
        &ctx,
    );
    try std.testing.expectEqual(@as(u128, literal_d), ctx.fpregs.v[2]);
    try std.testing.expectEqual(@as(u64, 0x2004), ctx.pc);

    try applyReplay(
        .{ .ldr_literal_q = .{ .rt = 3, .literal_address = @intFromPtr(&literal_q) } },
        0x3000,
        &ctx,
    );
    try std.testing.expectEqual(literal_q, ctx.fpregs.v[3]);
    try std.testing.expectEqual(@as(u64, 0x3004), ctx.pc);
}
