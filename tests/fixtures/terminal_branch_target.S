// Terminal semantic-branch replay smoke target.
//
// The widened patch window covers:
// 1. `cmp w0, #7`
// 2. `b.eq terminal_branch_taken`
//
// Both instructions must be replayed semantically in-order. This exercises the
// first widened control-flow shape where a fallthrough semantic prefix feeds a
// terminal semantic branch.

.text
.p2align 2
.global read_terminal_branch_value
.global terminal_branch_patchpoint
.type read_terminal_branch_value, %function
read_terminal_branch_value:
    mov w0, #7
terminal_branch_patchpoint:
    cmp w0, #7
    b.eq terminal_branch_taken
    mov w0, #1
    ret
terminal_branch_taken:
    mov w0, #2
    ret
.size read_terminal_branch_value, .-read_terminal_branch_value
