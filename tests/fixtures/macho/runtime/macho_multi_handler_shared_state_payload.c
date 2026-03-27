#include "zrwrite_sdk.h"

static unsigned long long gCounter;

static void bump_shared_counter(zrwrite_hook_context_t *ctx) {
    gCounter += 1;
    ctx->regs.named.x0 += gCounter;
}

__attribute__((visibility("default")))
void on_left(uint64_t address, zrwrite_hook_context_t *ctx) {
    (void)address;
    bump_shared_counter(ctx);
}

__attribute__((visibility("default")))
void on_right(uint64_t address, zrwrite_hook_context_t *ctx) {
    (void)address;
    bump_shared_counter(ctx);
}
