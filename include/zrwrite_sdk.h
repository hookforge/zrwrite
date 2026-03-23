#ifndef ZRWRITE_SDK_H
#define ZRWRITE_SDK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zrwrite_xregs_named {
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;
    uint64_t x5;
    uint64_t x6;
    uint64_t x7;
    uint64_t x8;
    uint64_t x9;
    uint64_t x10;
    uint64_t x11;
    uint64_t x12;
    uint64_t x13;
    uint64_t x14;
    uint64_t x15;
    uint64_t x16;
    uint64_t x17;
    uint64_t x18;
    uint64_t x19;
    uint64_t x20;
    uint64_t x21;
    uint64_t x22;
    uint64_t x23;
    uint64_t x24;
    uint64_t x25;
    uint64_t x26;
    uint64_t x27;
    uint64_t x28;
    uint64_t x29;
    uint64_t x30;
} zrwrite_xregs_named_t;

typedef union zrwrite_xregs {
    uint64_t x[31];
    zrwrite_xregs_named_t named;
} zrwrite_xregs_t;

typedef struct zrwrite_fpregs_named {
    __uint128_t v0;
    __uint128_t v1;
    __uint128_t v2;
    __uint128_t v3;
    __uint128_t v4;
    __uint128_t v5;
    __uint128_t v6;
    __uint128_t v7;
    __uint128_t v8;
    __uint128_t v9;
    __uint128_t v10;
    __uint128_t v11;
    __uint128_t v12;
    __uint128_t v13;
    __uint128_t v14;
    __uint128_t v15;
    __uint128_t v16;
    __uint128_t v17;
    __uint128_t v18;
    __uint128_t v19;
    __uint128_t v20;
    __uint128_t v21;
    __uint128_t v22;
    __uint128_t v23;
    __uint128_t v24;
    __uint128_t v25;
    __uint128_t v26;
    __uint128_t v27;
    __uint128_t v28;
    __uint128_t v29;
    __uint128_t v30;
    __uint128_t v31;
} zrwrite_fpregs_named_t;

typedef union zrwrite_fpregs {
    __uint128_t v[32];
    zrwrite_fpregs_named_t named;
} zrwrite_fpregs_t;

typedef struct zrwrite_hook_context {
    zrwrite_xregs_t regs;
    uint64_t sp;
    uint64_t pc;
    uint32_t cpsr;
    uint32_t pad;
    zrwrite_fpregs_t fpregs;
    uint32_t fpsr;
    uint32_t fpcr;
} zrwrite_hook_context_t;

typedef void (*zrwrite_instrument_callback_t)(uint64_t address, zrwrite_hook_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
