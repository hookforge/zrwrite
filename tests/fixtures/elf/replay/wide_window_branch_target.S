// Negative fixture for widened patch windows.
//
// `branch_to_mid` jumps directly into the second displaced instruction. A
// widened 4-instruction steal starting at `wide_branch_patchpoint` must reject
// this binary because overwriting the interior entry point would silently
// change control flow.

.text
.p2align 2
.global read_x0_after_wide_branch_patch
.global wide_branch_patchpoint
.global branch_to_mid
.type read_x0_after_wide_branch_patch, %function
read_x0_after_wide_branch_patch:
    mov x0, #1
wide_branch_patchpoint:
    add x0, x0, #2
wide_branch_mid:
    add x0, x0, #3
    add x0, x0, #4
    add x0, x0, #5
    ret
.size read_x0_after_wide_branch_patch, .-read_x0_after_wide_branch_patch

.type branch_to_mid, %function
branch_to_mid:
    b wide_branch_mid
.size branch_to_mid, .-branch_to_mid
