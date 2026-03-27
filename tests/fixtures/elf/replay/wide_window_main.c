#include <stdint.h>

extern uint64_t read_x0_after_wide_patch(void);

int main(void) {
    return read_x0_after_wide_patch() == 22u ? 0 : 1;
}
