#include "zrwrite_sdk.h"

// Runtime smoke for Mach-O Phase M1:
// keep the callback fully self-contained and read-only so the test isolates
// "patch -> ad-hoc codesign -> execute" closure. Writable payload state
// (`.data/.bss`) is still covered by the structural linker test and will need a
// later Mach-O RX/RW injection split before it becomes a stable runtime case.
static const uint64_t kDelta = 9;

__attribute__((visibility("default")))
void on_hit(uint64_t address, zrwrite_hook_context_t *ctx) {
    (void)address;
    ctx->regs.named.x0 += kDelta;
}
