#include "zrwrite_sdk.h"

__attribute__((visibility("default")))
void on_hit(uint64_t address, zrwrite_hook_context_t *ctx) {
    (void)address;
    (void)ctx;
}
