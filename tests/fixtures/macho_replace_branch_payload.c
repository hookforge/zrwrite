#include <stdint.h>

__attribute__((noinline))
static int tweak(int y) {
    return (y * 4) - 5;
}

__attribute__((visibility("default")))
int replacement_compute(int x) {
    int y = x + 10;
    return tweak(y);
}
