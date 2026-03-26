#include <stdint.h>
#include <stddef.h>

#define ROTL64(x, b) ((x << b) | (x >> (64 - b)))

#define SIPROUND                           \
    do {                                   \
        v0 += v1;                          \
        v1 = ROTL64(v1, 13);               \
        v1 ^= v0;                          \
        v0 = ROTL64(v0, 32);               \
        v2 += v3;                          \
        v3 = ROTL64(v3, 16);               \
        v3 ^= v2;                          \
        v0 += v3;                          \
        v3 = ROTL64(v3, 21);               \
        v3 ^= v0;                          \
        v2 += v1;                          \
        v1 = ROTL64(v1, 17);               \
        v1 ^= v2;                          \
        v2 = ROTL64(v2, 32);               \
    } while (0)

    uint64_t siphash128(uint64_t key1, uint64_t key2, const void* message, size_t length);
    uint64_t siphash(const unsigned char key[16], const unsigned char *m, const uint64_t n);