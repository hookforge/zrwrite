// Widened semantic-prefix replay smoke target.
//
// The hook window begins at `semantic_wide_patchpoint` and spans:
// 1. `adrp x0, semantic_wide_page`
// 2. `add  x0, x0, #0x100`
// 3. `ldr  w0, [x0]`
//
// Only the leading `adrp` is PC-relative. The widened bridge should therefore
// replay the prefix semantically, then resume into the copied raw trampoline
// tail at the second displaced instruction.

.text
.p2align 2
.global read_semantic_wide
.global semantic_wide_patchpoint
.type read_semantic_wide, %function
read_semantic_wide:
semantic_wide_patchpoint:
    adrp x0, semantic_wide_page
    add  x0, x0, #0x100
    ldr  w0, [x0]
    ret
.size read_semantic_wide, .-read_semantic_wide

.section .rodata
.p2align 12
semantic_wide_page:
    .space 0x100
.global semantic_wide_magic
semantic_wide_magic:
    .word 0x13572468
