// BTI-enabled far-detour fixture.
//
// This is the same logical shape as `far_detour_target.S`, but it also
// advertises GNU_PROPERTY_AARCH64_FEATURE_1_BTI so the rewriter must emit
// BTI-compatible injected entrypoints.

.section .note.gnu.property, "a", %note
.p2align 3
    .long 4
    .long 16
    .long 5
    .asciz "GNU"
    .p2align 3
    .long 0xC0000000
    .long 4
    .long 1
    .long 0

.text
.p2align 2
.global read_x0_after_bti_far_detour
.global bti_far_patchpoint
.type read_x0_after_bti_far_detour, %function
read_x0_after_bti_far_detour:
    bti c
    mov x0, #1
bti_far_patchpoint:
    add x0, x0, #2
    add x0, x0, #3
    add x0, x0, #4
    add x0, x0, #5
    ret
.size read_x0_after_bti_far_detour, .-read_x0_after_bti_far_detour

.bss
.p2align 12
.global bti_far_padding_blob
bti_far_padding_blob:
    .skip 0x08100000
