#include <stdint.h>

__attribute__((noinline)) int compute(int x) {
    int scaled = x * 3;
    return scaled + 5;
}

int main(void) {
    return compute(7);
}
