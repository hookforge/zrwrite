// Widened add-immediate + terminal-branch fixture.
//
// The hook window begins at `add_terminal_branch_patchpoint`:
// 1. `add x0, x0, #0x100`    (optional semantic-prefix promotion)
// 2. `cbz x0, ...`           (semantic terminal branch)
// 3. `mov w0, #1`            (raw suffix)
// 4. `ret`                   (raw suffix)
//
// This shape mirrors optimized code that performs one cheap address/index
// adjustment immediately before a semantic control-flow instruction.

.text
.p2align 2
.global read_add_terminal_branch_value
.global add_terminal_branch_patchpoint
.type read_add_terminal_branch_value, %function
read_add_terminal_branch_value:
    mov x0, #0
add_terminal_branch_patchpoint:
    add x0, x0, #0x100
    cbz x0, add_terminal_branch_taken
    mov w0, #1
    ret
add_terminal_branch_taken:
    mov w0, #2
    ret
.size read_add_terminal_branch_value, .-read_add_terminal_branch_value
