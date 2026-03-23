#include <stdint.h>

extern uint64_t read_x0_after_zig_payload(void);

int main(void) {
    return read_x0_after_zig_payload() == 72u ? 0 : 1;
}
