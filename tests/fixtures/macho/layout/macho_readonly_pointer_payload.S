.text
.p2align 2
.globl _on_hit
_on_hit:
    adrp x8, _ro_ptr@PAGE
    ldr x8, [x8, _ro_ptr@PAGEOFF]
    ldr x8, [x8]
    add x8, x8, #0x1
    str x8, [x1]
    ret

.section __TEXT,__const
.p2align 3
_ro_ptr:
    .quad _local_value

.data
.p2align 3
_local_value:
    .quad 41
