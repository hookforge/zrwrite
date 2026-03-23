#include "zrwrite_sdk.h"

__attribute__((visibility("default")))
void on_hit(uint64_t address, zrwrite_hook_context_t *ctx) {
    (void)address;
    ctx->regs.named.x0 += 7;
}
