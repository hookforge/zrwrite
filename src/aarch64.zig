const impl = @import("isa/aarch64/root.zig");

pub const original_trampoline_size = impl.original_trampoline_size;
pub const nop_instruction = impl.nop_instruction;
pub const max_stolen_instruction_count = impl.max_stolen_instruction_count;
pub const ldr_x17_literal_8 = impl.ldr_x17_literal_8;
pub const br_x17 = impl.br_x17;
pub const ldr_x16_literal_8 = impl.ldr_x16_literal_8;
pub const br_x16 = impl.br_x16;
pub const InstrumentStubOptions = impl.InstrumentStubOptions;
pub const ReplayPlan = impl.ReplayPlan;

pub const validateTrampolineOpcode = impl.validateTrampolineOpcode;
pub const buildOriginalTrampoline = impl.buildOriginalTrampoline;
pub const buildRawTrampoline = impl.buildRawTrampoline;
pub const buildInstrumentStub = impl.buildInstrumentStub;
pub const decodeBranchTarget = impl.decodeBranchTarget;
pub const encodeBranchImmediate = impl.encodeBranchImmediate;
pub const planReplay = impl.planReplay;
pub const applyReplay = impl.applyReplay;
