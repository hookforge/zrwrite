#include <stdint.h>

extern uint64_t read_x17_after_hook(void);

int main(void) {
    return read_x17_after_hook() == 0x5678u ? 0 : 1;
}
