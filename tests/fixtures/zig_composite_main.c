#include <stdint.h>

uint64_t target_value = 41;

extern uint64_t read_x0_after_zig_composite(void);

int main(void) {
    return read_x0_after_zig_composite() == 48u ? 0 : 1;
}
