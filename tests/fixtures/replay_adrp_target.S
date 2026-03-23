// A minimal semantic-replay smoke target.
//
// The original source sequence is `adrp + add`, but the static linker relaxes
// that pair into `nop + adr` because the data symbol ends up close enough.
// `load_magic_patchpoint` intentionally lands on the relaxed `adr`, which is
// still PC-relative and therefore still requires semantic replay instead of a
// raw out-of-line trampoline.

.text
.p2align 2
.global load_magic
.global load_magic_patchpoint
.type load_magic, %function
load_magic:
    adrp x0, replay_magic_value
load_magic_patchpoint:
    add  x0, x0, :lo12:replay_magic_value
    ldr  w0, [x0]
    ret
.size load_magic, .-load_magic

.section .rodata
.p2align 2
.global replay_magic_value
replay_magic_value:
    .word 0x12345678
