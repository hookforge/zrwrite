.text
.p2align 2
.globl _read_global
_read_global:
    adrp x8, _g_value@PAGE
    add x8, x8, _g_value@PAGEOFF
    ldr w0, [x8]
    ret

.globl _main
_main:
    b _read_global

.data
.p2align 2
_g_value:
    .long 7
