#include "siphash.h"

uint64_t siphash128(uint64_t key1, uint64_t key2, const void* message, size_t length) {
    const uint8_t* m = (const uint8_t*)message;
    uint64_t v0 = key1 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = key2 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = key1 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = key2 ^ 0x7465646279746573ULL;
    uint64_t b = (uint64_t)length << 56;
    uint64_t mlast;
    const uint8_t* end = m + length - (length % 8);

    while (m != end) {
        uint64_t mi = *(const uint64_t*)m;
        m += 8;
        v3 ^= mi;
        SIPROUND;
        SIPROUND;
        v0 ^= mi;
    }

    switch (length & 7) {
        case 7: b |= (uint64_t)m[6] << 48;
        case 6: b |= (uint64_t)m[5] << 40;
        case 5: b |= (uint64_t)m[4] << 32;
        case 4: b |= (uint64_t)m[3] << 24;
        case 3: b |= (uint64_t)m[2] << 16;
        case 2: b |= (uint64_t)m[1] << 8;
        case 1: b |= (uint64_t)m[0];
    }

    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;

    return v0 ^ v1 ^ v2 ^ v3;
}