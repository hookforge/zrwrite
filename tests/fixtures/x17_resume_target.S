// Raw-trampoline x17 preservation smoke target.
//
// The patchpoint lands on a `nop`, so the bridge can take its fully preserving
// direct-resume path when the callback only edits architectural state and
// leaves `ctx.sp` / `ctx.pc` on the default replay route.

.text
.p2align 2
.global read_x17_after_hook
.global x17_patchpoint
.type read_x17_after_hook, %function
read_x17_after_hook:
    mov x17, xzr
x17_patchpoint:
    nop
    mov x0, x17
    ret
.size read_x17_after_hook, .-read_x17_after_hook
