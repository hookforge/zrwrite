// Assembly payload that forces a cross-section R_AARCH64_TSTBR14 relocation.
//
// We zero x2 locally so `tbz x2, #0, ...` always takes the branch into the
// helper section. The helper writes 88 to `ctx.regs.x0` and returns.

.text
.p2align 2
.global on_hit
.type on_hit, %function
on_hit:
    mov x2, xzr
    tbz x2, #0, tstbr_helper
    ret
.size on_hit, .-on_hit

.section .text.tstbr_helper,"ax",@progbits
.p2align 2
.global tstbr_helper
.type tstbr_helper, %function
tstbr_helper:
    mov x2, #88
    str x2, [x1]
    ret
.size tstbr_helper, .-tstbr_helper
