#include <stdint.h>

extern uint64_t read_x0_after_wide_branch_patch(void);

int main(void) {
    return read_x0_after_wide_branch_patch() == 15u ? 0 : 1;
}
