#include "zrwrite_sdk.h"

// Deliberately large read-only payload blob.
//
// This fixture exists to force the Mach-O backend past the tiny "__TEXT tail
// slack is enough" happy path. The real requirement is that larger payloads do
// not start moving the target's original __DATA / __DATA_CONST layout unless we
// have no safer option left.
static const unsigned char kLargeTable[0x6000] = {
    [0] = 1,
    [0x5FFF] = 2,
};

static uint64_t gCounter;
static uint64_t gBias = 7;

__attribute__((visibility("default")))
void on_hit(uint64_t address, zrwrite_hook_context_t *ctx) {
    (void)address;
    gCounter += (uint64_t)kLargeTable[0] + (uint64_t)kLargeTable[0x5FFF];
    ctx->regs.named.x0 += gCounter + gBias;
}
