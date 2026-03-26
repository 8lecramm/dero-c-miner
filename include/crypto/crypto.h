/*
 * Cryptographic Functions - Public Header
 * Unified interface for all crypto algorithms
 */

#ifndef C_MINER_CRYPTO_H
#define C_MINER_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================================
 * AstroBWT
 * ============================================================================ */

#define MINIBLOCK_SIZE 48
#define STEP_3_SIZE 256
#define SCRATCHSIZE 71680
#define MEMORY (2 << 20)
#define WORKSIZE (2 << 18)
#define NO_OF_BITS 8
#define count_ones __builtin_popcount

void AstroBWTv3(uint8_t *input, uint8_t *output);

/* ============================================================================
 * FNV-1a Hash
 * ============================================================================ */

uint64_t AddBytes64(uint64_t h, const uint8_t *b, size_t len);
uint64_t fnv1a_hash(const uint8_t *data, size_t len);

/* ============================================================================
 * RC4
 * ============================================================================ */

struct rc4_cipher
{
    uint32_t s[256];
    uint8_t i, j;
};

void rc4_init(struct rc4_cipher *c, unsigned char *key);
void rc4_xor(struct rc4_cipher *c, unsigned char *plaintext, unsigned char *ciphertext);

/* ============================================================================
 * Salsa20
 * ============================================================================ */

#define SALSA_ROUNDS 20

void XORKeyStream(uint8_t *out, const uint8_t *in, const uint8_t *nonce,
                  const uint8_t *key, size_t size);

/* SSE4.1-optimized Salsa20 (available on x86-64 systems with SSE4.1 support)
 * Runtime CPU detection is performed in the implementation */
void salsa20(const void *key, const void *iv);
void salsa20_init(const void *key, const void *iv);
void salsa20_keystream(void *out, unsigned int bytes);

/* ============================================================================
 * SipHash
 * ============================================================================ */

#define ROTL64(x, b) ((x << b) | (x >> (64 - b)))

uint64_t siphash128(uint64_t key1, uint64_t key2, const void *message, size_t length);
uint64_t siphash(const unsigned char key[16], const unsigned char *m, const uint64_t n);

/* ============================================================================
 * XXHash
 * ============================================================================ */

#define XXHASH_PRIME64_1 11400714785074694791ULL
#define XXHASH_PRIME64_2 14029467366897019727ULL
#define XXHASH_PRIME64_3 1609587929392839161ULL
#define XXHASH_PRIME64_4 9650029242287828579ULL
#define XXHASH_PRIME64_5 2870177450012600261ULL

uint64_t xxhash64(const void *input, size_t length);

#endif /* C_MINER_CRYPTO_H */
