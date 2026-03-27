// Raw-trampoline-friendly patch target for the CONDBR19 runtime smoke.

.text
.p2align 2
.global read_x0_after_condbr
.global condbr_patchpoint
.type read_x0_after_condbr, %function
read_x0_after_condbr:
    mov x0, xzr
condbr_patchpoint:
    nop
    ret
.size read_x0_after_condbr, .-read_x0_after_condbr
