// Unsupported semantic interior-entry fixture.
//
// `branch_to_unsupported_semantic_interior_mid` lands on a semantic
// `ldr d0, literal` step inside a widened window:
// 1. `cmp  w0, #0`                    (semantic)
// 2. `ldr  d0, unsupported_fp_literal` (semantic interior entry target)
// 3. `fmov x0, d0`                    (raw tail)
//
// Scalar FP literal loads still require an architectural `vN` update that the
// direct interior-entry runtime does not synthesize yet. The rewriter must
// therefore keep this case fail-closed.

.text
.p2align 2
.global read_unsupported_semantic_interior_value
.global unsupported_semantic_interior_patchpoint
.global branch_to_unsupported_semantic_interior_mid
.type read_unsupported_semantic_interior_value, %function
read_unsupported_semantic_interior_value:
    mov w0, #0
unsupported_semantic_interior_patchpoint:
    cmp  w0, #0
unsupported_semantic_interior_mid:
    ldr  d0, unsupported_semantic_fp_literal
    fmov x0, d0
    ret
.size read_unsupported_semantic_interior_value, .-read_unsupported_semantic_interior_value

.type branch_to_unsupported_semantic_interior_mid, %function
branch_to_unsupported_semantic_interior_mid:
    b unsupported_semantic_interior_mid
.size branch_to_unsupported_semantic_interior_mid, .-branch_to_unsupported_semantic_interior_mid

.section .rodata
.p2align 3
unsupported_semantic_fp_literal:
    .8byte 0x1122334455667788
