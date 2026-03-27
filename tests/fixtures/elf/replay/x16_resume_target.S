// Raw-trampoline x16 preservation smoke target.
//
// `x16_patchpoint` lands on a plain `nop`, so the displaced instruction is raw
// trampoline safe. The callback then writes `ctx.regs.x16`, and the following
// `mov x0, x16` proves whether both the bridge and the raw trampoline preserved
// that value all the way back into resumed execution.

.text
.p2align 2
.global read_x16_after_hook
.global x16_patchpoint
.type read_x16_after_hook, %function
read_x16_after_hook:
    mov x16, xzr
x16_patchpoint:
    nop
    mov x0, x16
    ret
.size read_x16_after_hook, .-read_x16_after_hook
