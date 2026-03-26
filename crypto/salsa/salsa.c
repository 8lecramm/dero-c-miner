/*
 * Salsa20 Stream Cipher Implementation
 * Includes both portable C implementation and SSE4.1-optimized variant
 * Runtime CPU detection is performed to select the best available implementation
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "salsa.h"

#ifdef __x86_64__
#include <emmintrin.h>
#endif

#define ROTL32(value, shift) ((value << shift) | (value >> (32 - shift)));

/* ============================================================================
 * Portable Salsa20 Implementation (C)
 * ============================================================================ */

static void salsa20_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *b ^= ((*a + *d) << 7) | ((*a + *d) >> (32 - 7));
    *c ^= ((*b + *a) << 9) | ((*b + *a) >> (32 - 9));
    *d ^= ((*c + *b) << 13) | ((*c + *b) >> (32 - 13));
    *a ^= ((*d + *c) << 18) | ((*d + *c) >> (32 - 18));
}

static void salsa20_double_round(uint32_t *x)
{
    salsa20_quarter_round(&x[0], &x[4], &x[8], &x[12]);
    salsa20_quarter_round(&x[5], &x[9], &x[13], &x[1]);
    salsa20_quarter_round(&x[10], &x[14], &x[2], &x[6]);
    salsa20_quarter_round(&x[15], &x[3], &x[7], &x[11]);
    salsa20_quarter_round(&x[0], &x[1], &x[2], &x[3]);
    salsa20_quarter_round(&x[5], &x[6], &x[7], &x[4]);
    salsa20_quarter_round(&x[10], &x[11], &x[8], &x[9]);
    salsa20_quarter_round(&x[15], &x[12], &x[13], &x[14]);
}

static void salsa20_core(uint8_t *block, const uint8_t *counter, const uint8_t *key)
{
    uint32_t x[16];
    uint32_t j[16];

    j[0] = (uint32_t)sigma[0] | ((uint32_t)sigma[1] << 8) | ((uint32_t)sigma[2] << 16) | ((uint32_t)sigma[3] << 24);
    j[1] = key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24);
    j[2] = key[4] | (key[5] << 8) | (key[6] << 16) | (key[7] << 24);
    j[3] = key[8] | (key[9] << 8) | (key[10] << 16) | (key[11] << 24);
    j[4] = key[12] | (key[13] << 8) | (key[14] << 16) | (key[15] << 24);
    j[5] = (uint32_t)sigma[4] | ((uint32_t)sigma[5] << 8) | ((uint32_t)sigma[6] << 16) | ((uint32_t)sigma[7] << 24);
    j[6] = counter[0] | (counter[1] << 8) | (counter[2] << 16) | (counter[3] << 24);
    j[7] = counter[4] | (counter[5] << 8) | (counter[6] << 16) | (counter[7] << 24);
    j[8] = counter[8] | (counter[9] << 8) | (counter[10] << 16) | (counter[11] << 24);
    j[9] = counter[12] | (counter[13] << 8) | (counter[14] << 16) | (counter[15] << 24);
    j[10] = (uint32_t)sigma[8] | ((uint32_t)sigma[9] << 8) | ((uint32_t)sigma[10] << 16) | ((uint32_t)sigma[11] << 24);
    j[11] = key[16] | (key[17] << 8) | (key[18] << 16) | (key[19] << 24);
    j[12] = key[20] | (key[21] << 8) | (key[22] << 16) | (key[23] << 24);
    j[13] = key[24] | (key[25] << 8) | (key[26] << 16) | (key[27] << 24);
    j[14] = key[28] | (key[29] << 8) | (key[30] << 16) | (key[31] << 24);
    j[15] = (uint32_t)sigma[12] | ((uint32_t)sigma[13] << 8) | ((uint32_t)sigma[14] << 16) | ((uint32_t)sigma[15] << 24);

    for (int i = 0; i < 16; i++)
    {
        x[i] = j[i];
    }

    for (int i = 0; i < ROUNDS; i += 2)
    {
        salsa20_double_round(x);
    }

    for (int i = 0; i < 16; ++i)
    {
        x[i] += j[i];
    }

    for (int i = 0; i < 16; ++i)
    {
        block[i * 4] = (uint8_t)x[i];
        block[(i * 4) + 1] = (uint8_t)(x[i] >> 8);
        block[(i * 4) + 2] = (uint8_t)(x[i] >> 16);
        block[(i * 4) + 3] = (uint8_t)(x[i] >> 24);
    }
}

void XORKeyStream(uint8_t *out, const uint8_t *in, const uint8_t *nonce, const uint8_t *key, size_t size)
{
    uint8_t block[64];
    uint8_t counterCopy[16];
    memset(counterCopy, 0, sizeof(counterCopy));

    // Set the nonce and counter
    memcpy(counterCopy, nonce, 16);

    while (size >= 64)
    {
        salsa20_core(block, counterCopy, key);
        for (int i = 0; i < 64; ++i)
        {
            out[i] = in[i] ^ (uint8_t)block[i];
        }

        uint32_t u = 1;
        for (int i = 8; i < 16; i++)
        {
            u += (uint32_t)counterCopy[i];
            counterCopy[i] = (uint8_t)u;
            u = u >> 8;
        }

        in += 64;
        out += 64;
        size -= 64;
    }

    if (size > 0)
    {
        salsa20_core(block, counterCopy, key);
        for (size_t i = 0; i < size; ++i)
        {
            out[i] = in[i] ^ (uint8_t)block[i];
        }
    }
}

/* ============================================================================
 * SSE4.1-Optimized Salsa20 Implementation (x86-64)
 * ============================================================================ */

#ifdef __x86_64__

static union
{
    __m128i v[4];
    uint32_t i[16];
} _state;

/* SSE4.1-optimized implementation
 * These functions require SSE4.1 CPU support at runtime */
void salsa20_sse4_1(const void *key, const void *iv)
{
    const uint32_t *const k = (const uint32_t *)key;
    _state.i[0] = 0x61707865;
    _state.i[1] = 0x3320646e;
    _state.i[2] = 0x79622d32;
    _state.i[3] = 0x6b206574;
    _state.i[4] = k[3];
    _state.i[5] = 0;
    _state.i[6] = k[7];
    _state.i[7] = k[2];
    _state.i[8] = 0;
    _state.i[9] = k[6];
    _state.i[10] = k[1];
    _state.i[11] = ((const uint32_t *)iv)[1];
    _state.i[12] = k[5];
    _state.i[13] = k[0];
    _state.i[14] = ((const uint32_t *)iv)[0];
    _state.i[15] = k[4];
}

void salsa20_keystream_sse4_1(void *out, unsigned int bytes)
{
    uint8_t tmp[64];
    uint8_t *c = (uint8_t *)out;
    uint8_t *ctarget = c;
    unsigned int i;

    if (!bytes)
        return;

    for (;;)
    {
        if (bytes < 64)
        {
            for (i = 0; i < bytes; ++i)
                tmp[i] = 0;
            ctarget = c;
            c = tmp;
        }

        __m128i X0 = _mm_loadu_si128((const __m128i *)&(_state.v[0]));
        __m128i X1 = _mm_loadu_si128((const __m128i *)&(_state.v[1]));
        __m128i X2 = _mm_loadu_si128((const __m128i *)&(_state.v[2]));
        __m128i X3 = _mm_loadu_si128((const __m128i *)&(_state.v[3]));
        __m128i T;
        __m128i X0s = X0;
        __m128i X1s = X1;
        __m128i X2s = X2;
        __m128i X3s = X3;

/* Double round iterations (20 rounds = 10 double rounds) */
#define DOUBLE_ROUND()                                                                   \
    T = _mm_add_epi32(X0, X3);                                                           \
    X1 = _mm_xor_si128(_mm_xor_si128(X1, _mm_slli_epi32(T, 7)), _mm_srli_epi32(T, 25));  \
    T = _mm_add_epi32(X1, X0);                                                           \
    X2 = _mm_xor_si128(_mm_xor_si128(X2, _mm_slli_epi32(T, 9)), _mm_srli_epi32(T, 23));  \
    T = _mm_add_epi32(X2, X1);                                                           \
    X3 = _mm_xor_si128(_mm_xor_si128(X3, _mm_slli_epi32(T, 13)), _mm_srli_epi32(T, 19)); \
    T = _mm_add_epi32(X3, X2);                                                           \
    X0 = _mm_xor_si128(_mm_xor_si128(X0, _mm_slli_epi32(T, 18)), _mm_srli_epi32(T, 14)); \
    X1 = _mm_shuffle_epi32(X1, 0x93);                                                    \
    X2 = _mm_shuffle_epi32(X2, 0x4E);                                                    \
    X3 = _mm_shuffle_epi32(X3, 0x39);                                                    \
    T = _mm_add_epi32(X0, X1);                                                           \
    X3 = _mm_xor_si128(_mm_xor_si128(X3, _mm_slli_epi32(T, 7)), _mm_srli_epi32(T, 25));  \
    T = _mm_add_epi32(X3, X0);                                                           \
    X2 = _mm_xor_si128(_mm_xor_si128(X2, _mm_slli_epi32(T, 9)), _mm_srli_epi32(T, 23));  \
    T = _mm_add_epi32(X2, X3);                                                           \
    X1 = _mm_xor_si128(_mm_xor_si128(X1, _mm_slli_epi32(T, 13)), _mm_srli_epi32(T, 19)); \
    T = _mm_add_epi32(X1, X2);                                                           \
    X0 = _mm_xor_si128(_mm_xor_si128(X0, _mm_slli_epi32(T, 18)), _mm_srli_epi32(T, 14)); \
    X1 = _mm_shuffle_epi32(X1, 0x39);                                                    \
    X2 = _mm_shuffle_epi32(X2, 0x4E);                                                    \
    X3 = _mm_shuffle_epi32(X3, 0x93)

        DOUBLE_ROUND();
        DOUBLE_ROUND();
        DOUBLE_ROUND();
        DOUBLE_ROUND();
        DOUBLE_ROUND();
        DOUBLE_ROUND();
        DOUBLE_ROUND();
        DOUBLE_ROUND();
        DOUBLE_ROUND();
        DOUBLE_ROUND();

#undef DOUBLE_ROUND

        X0 = _mm_add_epi32(X0s, X0);
        X1 = _mm_add_epi32(X1s, X1);
        X2 = _mm_add_epi32(X2s, X2);
        X3 = _mm_add_epi32(X3s, X3);

        __m128i k02 = _mm_shuffle_epi32(_mm_or_si128(_mm_slli_epi64(X0, 32), _mm_srli_epi64(X3, 32)), _MM_SHUFFLE(0, 1, 2, 3));
        __m128i k13 = _mm_shuffle_epi32(_mm_or_si128(_mm_slli_epi64(X1, 32), _mm_srli_epi64(X0, 32)), _MM_SHUFFLE(0, 1, 2, 3));
        __m128i k20 = _mm_or_si128(_mm_and_si128(X2, _mm_shuffle_epi32(_mm_cvtsi32_si128(-1), _MM_SHUFFLE(1, 0, 1, 0))), _mm_and_si128(X1, _mm_slli_epi64(_mm_shuffle_epi32(_mm_cvtsi32_si128(-1), _MM_SHUFFLE(1, 0, 1, 0)), 32)));
        __m128i k31 = _mm_or_si128(_mm_and_si128(X3, _mm_shuffle_epi32(_mm_cvtsi32_si128(-1), _MM_SHUFFLE(1, 0, 1, 0))), _mm_and_si128(X2, _mm_slli_epi64(_mm_shuffle_epi32(_mm_cvtsi32_si128(-1), _MM_SHUFFLE(1, 0, 1, 0)), 32)));
        _mm_storeu_ps((float *)c, _mm_castsi128_ps(_mm_unpackhi_epi64(k02, k20)));
        _mm_storeu_ps((float *)c + 4, _mm_castsi128_ps(_mm_unpackhi_epi64(k13, k31)));
        _mm_storeu_ps((float *)c + 8, _mm_castsi128_ps(_mm_unpacklo_epi64(k20, k02)));
        _mm_storeu_ps((float *)c + 12, _mm_castsi128_ps(_mm_unpacklo_epi64(k31, k13)));

        if (!(++_state.i[8]))
        {
            ++_state.i[5]; // state reordered for SSE
            /* stopping at 2^70 bytes per nonce is user's responsibility */
        }

        if (bytes <= 64)
        {
            if (bytes < 64)
            {
                for (i = 0; i < bytes; ++i)
                    ctarget[i] = c[i];
            }
            return;
        }

        bytes -= 64;
        c += 64;
    }
}

#endif /* SSE4.1-Optimized Salsa20 Implementation */

/* ============================================================================
 * Runtime CPU Feature Detection & Dispatch
 * ============================================================================
 * These functions detect CPU capabilities at runtime and dispatch to the
 * most efficient available implementation (SSE4.1 or portable C).
 */

/* Cached CPU capability check result (-1 = unchecked, 0 = unavailable, 1 = available) */
static int cpu_has_sse4_1 = -1;

/**
 * Check if the CPU supports SSE4.1 instruction set
 * Uses CPUID instruction for direct CPU feature detection
 */
static int check_sse4_1_support(void)
{
    if (cpu_has_sse4_1 != -1)
        return cpu_has_sse4_1;

#ifdef __x86_64__
    /* SSE4.1 is indicated by CPUID.01h:ECX bit 19 */
    unsigned int eax = 1, ebx, ecx = 0, edx;

    asm volatile(
        "cpuid"
        : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));

    /* Check if SSE4.1 is supported (ECX bit 19) */
    cpu_has_sse4_1 = (ecx & (1 << 19)) ? 1 : 0;
#else
    /* No SSE4.1 support on non-x86-64 systems */
    cpu_has_sse4_1 = 0;
#endif

    return cpu_has_sse4_1;
}

/**
 * Print information about which Salsa20 implementation will be used
 */
void print_salsa20_info(void)
{
    if (check_sse4_1_support())
    {
        printf("Salsa20: Using SSE4.1-optimized implementation\n");
    }
    else
    {
        printf("Salsa20: Using portable C implementation\n");
    }
}

#ifdef __x86_64__

/**
 * Salsa20 initialization wrapper
 * Dispatches to SSE4.1 version if available, otherwise uses fallback
 */
void salsa20(const void *key, const void *iv, void *out)
{
    if (check_sse4_1_support())
    {
        salsa20_sse4_1(key, iv);
        salsa20_keystream_sse4_1(out, 256);
    }
    else
    {
        XORKeyStream(out, out, iv, key, 256);
    }
}

#endif /* __x86_64__ */