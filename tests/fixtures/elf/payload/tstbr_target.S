// Raw-trampoline-friendly patch target for the TSTBR14 runtime smoke.

.text
.p2align 2
.global read_x0_after_tstbr
.global tstbr_patchpoint
.type read_x0_after_tstbr, %function
read_x0_after_tstbr:
    mov x0, xzr
tstbr_patchpoint:
    nop
    ret
.size read_x0_after_tstbr, .-read_x0_after_tstbr
