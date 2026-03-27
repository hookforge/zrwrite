#include <stdint.h>

__attribute__((noinline)) int compute_left(int x) {
    int scaled = x * 2;
    return scaled + 1;
}

__attribute__((noinline)) int compute_right(int x) {
    int scaled = x * 5;
    return scaled - 7;
}

int main(void) {
    return compute_left(3) + compute_right(4);
}
