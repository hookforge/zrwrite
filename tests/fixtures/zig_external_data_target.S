// Raw-trampoline-friendly patch target for exercising Zig `extern var`
// support in the ELF/AArch64 mini-linker.
//
// The callback reads `target_value` from the target ELF via a GOT-style access
// pattern emitted by Zig (`ADR_GOT_PAGE + LD64_GOT_LO12_NC`) and writes the
// loaded value plus one back into `ctx.regs.x0`. If external data resolution is
// correct, the resumed function returns 42 to `main`.

.text
.p2align 2
.global read_x0_after_zig_external_data
.global zig_external_data_patchpoint
.type read_x0_after_zig_external_data, %function
read_x0_after_zig_external_data:
    mov x0, xzr
zig_external_data_patchpoint:
    nop
    ret
.size read_x0_after_zig_external_data, .-read_x0_after_zig_external_data
