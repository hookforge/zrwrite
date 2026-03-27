#include <stdint.h>

uint64_t target_helper(uint64_t x) {
    return x + 10u;
}

extern uint64_t read_x0_after_external_call(void);

int main(void) {
    return read_x0_after_external_call() == 35u ? 0 : 1;
}
