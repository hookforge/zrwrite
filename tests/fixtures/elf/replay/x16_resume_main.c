#include <stdint.h>

extern uint64_t read_x16_after_hook(void);

int main(void) {
    return read_x16_after_hook() == 0x1234u ? 0 : 1;
}
