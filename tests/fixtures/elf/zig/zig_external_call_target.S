// Target used to validate that the mini-linker can resolve undefined payload
// symbols against functions exported by the target ELF image itself.

.text
.p2align 2
.global read_x0_after_external_call
.global zig_external_call_patchpoint
.type read_x0_after_external_call, %function
read_x0_after_external_call:
    mov x0, xzr
zig_external_call_patchpoint:
    nop
    ret
.size read_x0_after_external_call, .-read_x0_after_external_call
