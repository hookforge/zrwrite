// Assembly payload that forces a cross-section R_AARCH64_CONDBR19 relocation.
//
// `cmp x0, x0` is always equal, so the conditional branch always lands in the
// helper section. The helper writes 77 to `ctx.regs.x0` and returns.

.text
.p2align 2
.global on_hit
.type on_hit, %function
on_hit:
    cmp x0, x0
    b.eq condbr_helper
    ret
.size on_hit, .-on_hit

.section .text.condbr_helper,"ax",@progbits
.p2align 2
.global condbr_helper
.type condbr_helper, %function
condbr_helper:
    mov x2, #77
    str x2, [x1]
    ret
.size condbr_helper, .-condbr_helper
