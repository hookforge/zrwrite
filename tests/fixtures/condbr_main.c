#include <stdint.h>

extern uint64_t read_x0_after_condbr(void);

int main(void) {
    return read_x0_after_condbr() == 77u ? 0 : 1;
}
