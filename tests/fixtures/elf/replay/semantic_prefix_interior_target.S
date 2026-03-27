// Semantic-prefix interior-entry fixture.
//
// `branch_to_semantic_prefix_interior_mid` lands on the semantic `adrp`
// interior step inside a widened linear semantic-prefix window:
// 1. `cmp  w0, #7`                  (semantic)
// 2. `adrp x1, semantic_prefix_page` (semantic interior entry target)
// 3. `add  x1, x1, #0x100`          (raw tail)
// 4. `ldr  w0, [x1]`                (raw tail)
//
// After patching, the incoming branch must be retargeted into a dedicated
// semantic interior-entry blob that replays the displaced `adrp` directly and
// then falls through into the relocated raw suffix.

.text
.p2align 2
.global read_semantic_prefix_interior_value
.global semantic_prefix_interior_patchpoint
.global branch_to_semantic_prefix_interior_mid
.type read_semantic_prefix_interior_value, %function
read_semantic_prefix_interior_value:
    mov w0, #7
semantic_prefix_interior_patchpoint:
    cmp  w0, #7
semantic_prefix_interior_mid:
    adrp x1, semantic_prefix_page
    add  x1, x1, #0x100
    ldr  w0, [x1]
    ret
.size read_semantic_prefix_interior_value, .-read_semantic_prefix_interior_value

.type branch_to_semantic_prefix_interior_mid, %function
branch_to_semantic_prefix_interior_mid:
    b semantic_prefix_interior_mid
.size branch_to_semantic_prefix_interior_mid, .-branch_to_semantic_prefix_interior_mid

.section .rodata
.p2align 12
semantic_prefix_page:
    .space 0x100
.global semantic_prefix_magic
semantic_prefix_magic:
    .word 0x13579BDF
