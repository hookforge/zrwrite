// A simple raw-trampoline-friendly patch target for exercising the ELF/AArch64
// mini-linker with a real Zig-authored payload object.
//
// The hook callback rewrites `ctx.regs.x0` using values loaded from `.rodata`,
// `.data`, and `.bss` inside the injected payload image. If relocation/linking
// succeeds, the resumed function returns that computed value to `main`.

.text
.p2align 2
.global read_x0_after_zig_payload
.global zig_payload_patchpoint
.type read_x0_after_zig_payload, %function
read_x0_after_zig_payload:
    mov x0, xzr
zig_payload_patchpoint:
    nop
    ret
.size read_x0_after_zig_payload, .-read_x0_after_zig_payload
