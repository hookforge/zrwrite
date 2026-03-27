// Straight-line patchpoint used to validate widened multi-instruction steals.
//
// The hook window starts at `wide_patchpoint` and spans four arithmetic
// instructions. A widened instrument detour should:
// - invoke the callback before the first add
// - replay all four displaced instructions in order
// - resume at the trailing `ret`

.text
.p2align 2
.global read_x0_after_wide_patch
.global wide_patchpoint
.type read_x0_after_wide_patch, %function
read_x0_after_wide_patch:
    mov x0, #1
wide_patchpoint:
    add x0, x0, #2
    add x0, x0, #3
    add x0, x0, #4
    add x0, x0, #5
    ret
.size read_x0_after_wide_patch, .-read_x0_after_wide_patch
