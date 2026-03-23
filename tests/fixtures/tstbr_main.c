#include <stdint.h>

extern uint64_t read_x0_after_tstbr(void);

int main(void) {
    return read_x0_after_tstbr() == 88u ? 0 : 1;
}
