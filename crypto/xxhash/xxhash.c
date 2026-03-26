#include "xxhash.h"

uint64_t xxhash64(const void *input, size_t length)
{
    const uint8_t *p = (const uint8_t *)input;
    const uint8_t *end = p + length;
    uint64_t h64;

    if (length >= 32)
    {
        const uint8_t *limit = end - 32;
        uint64_t v1 = XXHASH_PRIME64_1 + XXHASH_PRIME64_2;
        uint64_t v2 = XXHASH_PRIME64_2;
        uint64_t v3 = 0;
        uint64_t v4 = 0 - XXHASH_PRIME64_1;

        do
        {
            v1 += *(const uint64_t *)p * XXHASH_PRIME64_2;
            v1 = (v1 << 31) | (v1 >> 33);
            v1 *= XXHASH_PRIME64_1;
            p += 8;

            v2 += *(const uint64_t *)p * XXHASH_PRIME64_2;
            v2 = (v2 << 31) | (v2 >> 33);
            v2 *= XXHASH_PRIME64_1;
            p += 8;

            v3 += *(const uint64_t *)p * XXHASH_PRIME64_2;
            v3 = (v3 << 31) | (v3 >> 33);
            v3 *= XXHASH_PRIME64_1;
            p += 8;

            v4 += *(const uint64_t *)p * XXHASH_PRIME64_2;
            v4 = (v4 << 31) | (v4 >> 33);
            v4 *= XXHASH_PRIME64_1;
            p += 8;
        } while (p <= limit);

        h64 = ((v1 << 1) | (v1 >> 63)) +
              ((v2 << 7) | (v2 >> 57)) +
              ((v3 << 12) | (v3 >> 52)) +
              ((v4 << 18) | (v4 >> 46));

        v1 *= XXHASH_PRIME64_2;
        v1 = (v1 << 31) | (v1 >> 33);
        v1 *= XXHASH_PRIME64_1;
        h64 ^= v1;
        h64 = h64 * XXHASH_PRIME64_1 + XXHASH_PRIME64_4;

        v2 *= XXHASH_PRIME64_2;
        v2 = (v2 << 31) | (v2 >> 33);
        v2 *= XXHASH_PRIME64_1;
        h64 ^= v2;
        h64 = h64 * XXHASH_PRIME64_1 + XXHASH_PRIME64_4;

        v3 *= XXHASH_PRIME64_2;
        v3 = (v3 << 31) | (v3 >> 33);
        v3 *= XXHASH_PRIME64_1;
        h64 ^= v3;
        h64 = h64 * XXHASH_PRIME64_1 + XXHASH_PRIME64_4;

        v4 *= XXHASH_PRIME64_2;
        v4 = (v4 << 31) | (v4 >> 33);
        v4 *= XXHASH_PRIME64_1;
        h64 ^= v4;
        h64 = h64 * XXHASH_PRIME64_1 + XXHASH_PRIME64_4;
    }
    else
    {
        h64 = XXHASH_PRIME64_5;
    }

    h64 += (uint64_t)length;

    while (p + 8 <= end)
    {
        uint64_t k1 = *(const uint64_t *)p;
        k1 *= XXHASH_PRIME64_2;
        k1 = (k1 << 31) | (k1 >> 33);
        k1 *= XXHASH_PRIME64_1;
        h64 ^= k1;
        h64 = (h64 << 27) | (h64 >> 37);
        h64 = h64 * XXHASH_PRIME64_1 + XXHASH_PRIME64_4;
        p += 8;
    }

    if (p + 4 <= end)
    {
        h64 ^= (uint64_t)(*(const uint32_t *)p) * XXHASH_PRIME64_1;
        h64 = (h64 << 23) | (h64 >> 41);
        h64 = h64 * XXHASH_PRIME64_2 + XXHASH_PRIME64_3;
        p += 4;
    }

    while (p < end)
    {
        h64 ^= (uint64_t)(*p) * XXHASH_PRIME64_5;
        h64 = (h64 << 11) | (h64 >> 53);
        h64 = h64 * XXHASH_PRIME64_1;
        p++;
    }

    h64 ^= h64 >> 33;
    h64 *= XXHASH_PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= XXHASH_PRIME64_3;
    h64 ^= h64 >> 32;

    return h64;
}