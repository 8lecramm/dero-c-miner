#include "fnv1a.h"

// FNV-1a constants

#define FNV_INIT64 14695981039346656037ULL
#define FNV_PRIME64 1099511628211ULL

uint64_t fnv1a_hash(const uint8_t *data, size_t len)
{
    return AddBytes64(FNV_INIT64, data, len);
}

uint64_t AddBytes64(uint64_t h, const uint8_t *b, size_t len)
{
    while (len >= 8)
    {
        for (int i = 0; i < 8; i++)
        {
            h = (h ^ (uint64_t)b[i]) * FNV_PRIME64;
        }
        b += 8;
        len -= 8;
    }

    if (len >= 4)
    {
        for (int i = 0; i < 4; i++)
        {
            h = (h ^ (uint64_t)b[i]) * FNV_PRIME64;
        }
        b += 4;
        len -= 4;
    }

    if (len >= 2)
    {
        for (int i = 0; i < 2; i++)
        {
            h = (h ^ (uint64_t)b[i]) * FNV_PRIME64;
        }
        b += 2;
        len -= 2;
    }

    if (len > 0)
    {
        h = (h ^ (uint64_t)b[0]) * FNV_PRIME64;
    }

    return h;
}