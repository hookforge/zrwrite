// Larger straight-line patchpoint used to validate the raised stolen-window cap.
//
// The hook window starts at `wide8_patchpoint` and spans eight arithmetic
// instructions. The current implementation still replays these instructions
// through one raw trampoline, but Milestone 1 should at least prove that the
// planner/rewriter no longer hard-code a 4-instruction ceiling.

.text
.p2align 2
.global read_x0_after_wide8_patch
.global wide8_patchpoint
.type read_x0_after_wide8_patch, %function
read_x0_after_wide8_patch:
    mov x0, #1
wide8_patchpoint:
    add x0, x0, #2
    add x0, x0, #3
    add x0, x0, #4
    add x0, x0, #5
    add x0, x0, #6
    add x0, x0, #7
    add x0, x0, #8
    add x0, x0, #9
    ret
.size read_x0_after_wide8_patch, .-read_x0_after_wide8_patch
