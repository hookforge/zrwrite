// Patch target for the composite Zig regression.
//
// The patched function starts with x0 = 0 and returns immediately after the
// instrument callback resumes execution. The target also exports
// `target_helper`, which the payload calls after reading external data and
// writing internal `.bss` state.

.text
.p2align 2
.global read_x0_after_zig_composite
.global zig_composite_patchpoint
.global target_helper
.type read_x0_after_zig_composite, %function
read_x0_after_zig_composite:
    mov x0, xzr
zig_composite_patchpoint:
    nop
    ret
.size read_x0_after_zig_composite, .-read_x0_after_zig_composite

.type target_helper, %function
target_helper:
    add x0, x0, #5
    ret
.size target_helper, .-target_helper
