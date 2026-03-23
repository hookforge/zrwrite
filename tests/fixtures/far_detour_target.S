// Out-of-range detour fixture.
//
// The huge `.bss` tail forces the injected payload blob to land more than
// ±128 MiB away from the hook site, so a plain `b stub` can no longer reach
// the instrument bridge. `zrwrite` must therefore fall back to a 16-byte
// absolute detour at the patch site.

.text
.p2align 2
.global read_x0_after_far_detour
.global far_patchpoint
.type read_x0_after_far_detour, %function
read_x0_after_far_detour:
    mov x0, #1
far_patchpoint:
    add x0, x0, #2
    add x0, x0, #3
    add x0, x0, #4
    add x0, x0, #5
    ret
.size read_x0_after_far_detour, .-read_x0_after_far_detour

.bss
.p2align 12
.global far_padding_blob
far_padding_blob:
    .skip 0x08100000
