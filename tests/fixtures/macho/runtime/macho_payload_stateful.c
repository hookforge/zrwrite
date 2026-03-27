#include "zrwrite_sdk.h"

static const uint64_t kDeltas[2] = {3, 4};
static uint64_t gCounter;
static uint64_t gBias = 2;

__attribute__((visibility("default")))
void on_hit(uint64_t address, zrwrite_hook_context_t *ctx) {
    (void)address;
    gCounter += kDeltas[0];
    ctx->regs.named.x0 += gCounter + kDeltas[1] + gBias;
}
