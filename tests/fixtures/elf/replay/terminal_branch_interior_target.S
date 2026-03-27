// Negative widened terminal-branch fixture.
//
// `branch_to_terminal_branch_mid` lands directly on the semantic `b.eq` step
// inside the widened `cmp + b.cond` window. That entry point cannot yet be
// reconstructed out-of-line, so the rewriter must still fail closed.

.text
.p2align 2
.global read_terminal_branch_interior_value
.global terminal_branch_interior_patchpoint
.global branch_to_terminal_branch_mid
.type read_terminal_branch_interior_value, %function
read_terminal_branch_interior_value:
    mov w0, #7
terminal_branch_interior_patchpoint:
    cmp w0, #7
terminal_branch_interior_mid:
    b.eq terminal_branch_interior_taken
    mov w0, #1
    ret
terminal_branch_interior_taken:
    mov w0, #2
    ret
.size read_terminal_branch_interior_value, .-read_terminal_branch_interior_value

.type branch_to_terminal_branch_mid, %function
branch_to_terminal_branch_mid:
    b terminal_branch_interior_mid
.size branch_to_terminal_branch_mid, .-branch_to_terminal_branch_mid
