#include <stdint.h>

__attribute__((visibility("default")))
int replacement_compute(int x) {
    int y = (x ^ 0x55) + 11;
    y = (y * 5) - 3;
    return y;
}
