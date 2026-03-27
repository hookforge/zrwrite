#include <stdint.h>

// This target intentionally carries a small writable data segment so the
// Mach-O backend can exercise the "synthetic executable segment + native
// writable carrier" path.
static int gBias = 3;
static int gState = 11;
static const char *gBanner = "hello";

__attribute__((noinline)) int compute(int x) {
    return x * 2 + gBias + (gState & 1) + (int)gBanner[0] - 'h';
}

int main(void) {
    return compute(5);
}
