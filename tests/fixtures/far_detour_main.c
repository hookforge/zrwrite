#include <stdint.h>

extern uint64_t read_x0_after_far_detour(void);

int main(void) {
    return read_x0_after_far_detour() == 22u ? 0 : 1;
}
