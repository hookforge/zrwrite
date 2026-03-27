// Combined semantic-prefix + incoming-interior-entry fixture.
//
// The widened hook window starts at `semantic_branch_patchpoint`:
// 1. `adrp x0, semantic_branch_page`   (semantic replay)
// 2. `add  x0, x0, #0x100`             (raw retargetable interior entry)
// 3. `ldr  w0, [x0]`                   (raw retargetable interior entry)
//
// `branch_to_semantic_branch_mid` materializes the same page base locally and
// then branches directly into the second displaced instruction. After
// patching, that edge must be retargeted into the relocated raw trampoline
// suffix rather than being rejected.

.text
.p2align 2
.global read_semantic_branch_value
.global semantic_branch_patchpoint
.global branch_to_semantic_branch_mid
.type read_semantic_branch_value, %function
read_semantic_branch_value:
semantic_branch_patchpoint:
    adrp x0, semantic_branch_page
semantic_branch_mid:
    add  x0, x0, #0x100
    ldr  w0, [x0]
    ret
.size read_semantic_branch_value, .-read_semantic_branch_value

.type branch_to_semantic_branch_mid, %function
branch_to_semantic_branch_mid:
    adrp x0, semantic_branch_page
    b semantic_branch_mid
.size branch_to_semantic_branch_mid, .-branch_to_semantic_branch_mid

.section .rodata
.p2align 12
semantic_branch_page:
    .space 0x100
.global semantic_branch_magic
semantic_branch_magic:
    .word 0x24681357
