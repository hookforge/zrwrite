#include <stdint.h>

extern uint32_t load_magic(void);

int main(void) {
    return load_magic() == 0x12345678u ? 0 : 1;
}
