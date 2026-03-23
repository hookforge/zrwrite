#include <stdint.h>

uint64_t target_value = 41;

extern uint64_t read_x0_after_zig_external_data(void);

int main(void) {
    return read_x0_after_zig_external_data() == 42u ? 0 : 1;
}
