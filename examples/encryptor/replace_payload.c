#include <stddef.h>
#include <stdint.h>

static uint32_t rotl32(uint32_t value, unsigned shift) {
    return (value << shift) | (value >> (32 - shift));
}

__attribute__((visibility("default")))
uint32_t replacement_encrypt_buffer(uint8_t *buf, size_t len, uint32_t key) {
    uint32_t state = key ^ 0x13579BDFu;
    for (size_t i = 0; i < len; ++i) {
        uint32_t lane = state + (uint32_t)i * 0x1F123BB5u;
        uint8_t mixed = (uint8_t)(buf[i] + (uint8_t)lane);
        mixed ^= (uint8_t)(lane >> 7);
        mixed = (uint8_t)((mixed >> 2) | (mixed << 6));
        mixed ^= (uint8_t)(state >> ((i & 3) * 8));
        buf[i] = mixed;
        state = rotl32(state + mixed + (uint32_t)(i * 17u), 7) ^ 0x7F4A7C15u;
    }
    return state;
}
