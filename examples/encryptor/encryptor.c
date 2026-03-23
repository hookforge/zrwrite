#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static uint32_t rotl32(uint32_t value, unsigned shift) {
    return (value << shift) | (value >> (32 - shift));
}

static uint32_t checksum_buffer(const uint8_t *buf, size_t len) {
    uint32_t acc = 0x811C9DC5u;
    for (size_t i = 0; i < len; ++i) {
        acc ^= buf[i];
        acc *= 16777619u;
    }
    return acc;
}

__attribute__((noinline))
uint32_t encrypt_buffer(uint8_t *buf, size_t len, uint32_t key) {
    uint32_t state = key ^ 0xA55AA55Au;
    for (size_t i = 0; i < len; ++i) {
        uint32_t lane = state + (uint32_t)i * 0x045D9F3Bu;
        uint8_t mixed = (uint8_t)(buf[i] ^ (uint8_t)lane ^ (uint8_t)(lane >> 11));
        mixed = (uint8_t)((mixed << 3) | (mixed >> 5));
        mixed ^= (uint8_t)(state >> ((i & 3) * 8));
        buf[i] = mixed;
        state = rotl32(state ^ mixed ^ (uint32_t)i, 5) + 0x9E3779B9u;
    }
    return state;
}

static uint8_t *read_file(const char *path, size_t *size_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("fopen(input)");
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(fp);
        return NULL;
    }

    long end = ftell(fp);
    if (end < 0) {
        perror("ftell");
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("fseek");
        fclose(fp);
        return NULL;
    }

    size_t size = (size_t)end;
    uint8_t *buf = (uint8_t *)malloc(size == 0 ? 1 : size);
    if (!buf) {
        perror("malloc");
        fclose(fp);
        return NULL;
    }

    if (size != 0 && fread(buf, 1, size, fp) != size) {
        perror("fread");
        free(buf);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    *size_out = size;
    return buf;
}

static int write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        perror("fopen(output)");
        return -1;
    }
    if (len != 0 && fwrite(buf, 1, len, fp) != len) {
        perror("fwrite");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <input> <output>\n", argv[0]);
        return 2;
    }

    size_t len = 0;
    uint8_t *buf = read_file(argv[1], &len);
    if (!buf) return 1;

    uint32_t final_state = encrypt_buffer(buf, len, 0xC0FFEE11u);
    uint32_t digest = checksum_buffer(buf, len) ^ final_state;

    if (write_file(argv[2], buf, len) != 0) {
        free(buf);
        return 1;
    }

    printf("encrypted bytes=%zu digest=%08x final=%08x\n", len, digest, final_state);
    free(buf);
    return 0;
}
