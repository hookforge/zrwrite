#include "zrwrite_sdk.h"

static unsigned long long local_value = 41;
static unsigned long long *cached_ptr = &local_value;

__attribute__((visibility("default")))
void on_hit(uint64_t address, zrwrite_hook_context_t *ctx) {
    (void)address;
    ctx->regs.x[0] = *cached_ptr + 1;
}
