/*
 * Hash Function Interface
 * Unified interface for all hash operations
 */

#ifndef C_MINER_HASH_H
#define C_MINER_HASH_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <gmp.h>

/* PoW comparison */
void hash_init();
int checkPoW(uint8_t *pow, double diff);
static inline void hash2big(uint8_t *in, mpz_t *out);
static inline void convertIntDiff2Big(mpz_t *in);
static inline void uint2big(double difficulty, mpz_t *diffBig);

#endif /* C_MINER_HASH_H */
