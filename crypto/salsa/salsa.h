/*
 * Salsa20 Stream Cipher Interface
 * Includes both portable C and SSE4.1-optimized implementations
 */

#ifndef SALSA_H
#define SALSA_H

#include <stdint.h>
#include <string.h>

#define ROUNDS 20

static const char sigma[16] = "expand 32-byte k";

/* Portable Salsa20 implementation */
void XORKeyStream(uint8_t *out, const uint8_t *in, const uint8_t *nonce,
                  const uint8_t *key, size_t size);

/* Salsa20 with runtime CPU detection
 * These functions automatically select the best implementation:
 * - SSE4.1 optimized on x86-64 systems that support it
 * - Portable C fallback on other systems */
void salsa20(const void *key, const void *iv);
void salsa20_init(const void *key, const void *iv);
void salsa20_keystream(void *out, unsigned int bytes);

/* Print information about which Salsa20 implementation will be used */
void print_salsa20_info(void);

#endif /* SALSA_H */