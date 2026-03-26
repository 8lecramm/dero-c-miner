#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "../include/pow.h"

#define HASH_SIZE 32

mpz_t bigZero, bigOne, bigOneLsh256;

void hash_init()
{
    mpz_init(bigZero);
    mpz_init(bigOne);
    mpz_init(bigOneLsh256);
    mpz_add_ui(bigZero, bigZero, 0);
    mpz_add_ui(bigOne, bigZero, 1);
    mpz_mul_2exp(bigOneLsh256, bigOne, 256);
}

int checkPoW(uint8_t *pow, double diff)
{
    mpz_t bigDiff, bigPow;

    hash2big(pow, &bigPow);
    uint2big(diff, &bigDiff);
    convertIntDiff2Big(&bigDiff);

    int rc = mpz_cmp(bigPow, bigDiff);
    mpz_clear(bigDiff);
    mpz_clear(bigPow);

    return rc;
}

static inline void hash2big(uint8_t *in, mpz_t *out)
{

    mpz_init(*out);
    uint8_t reverse[HASH_SIZE];

    for (int i = 0; i < HASH_SIZE; i++)
        reverse[i] = in[HASH_SIZE - 1 - i];
    mpz_import(*out, HASH_SIZE, 1, 1, 0, 0, reverse);
}

static inline void convertIntDiff2Big(mpz_t *in)
{
    mpz_cdiv_q(*in, bigOneLsh256, *in);
}

static inline void uint2big(double difficulty, mpz_t *bigInt)
{
    mpz_t bigConverted;

    mpz_init(*bigInt);
    mpz_init(bigConverted);
    mpz_set_d(bigConverted, difficulty);

    mpz_add(*bigInt, bigZero, bigConverted);
    mpz_clear(bigConverted);
}