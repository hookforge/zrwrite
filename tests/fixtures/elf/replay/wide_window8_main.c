#include <stdint.h>

extern uint64_t read_x0_after_wide8_patch(void);

int main(void) {
    return read_x0_after_wide8_patch() == 45u ? 0 : 1;
}
