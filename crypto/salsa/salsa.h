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

#ifdef __x86_64__
/* Salsa20 wrapper - x86-64 only
 * Automatically selects best implementation:
 * - SSE4.1 optimized if CPU supports it
 * - Portable C fallback otherwise */
void salsa20(const void *key, const void *iv, void *out);
#endif /* __x86_64__ */

/* Print information about which Salsa20 implementation will be used */
void print_salsa20_info(void);

#endif /* SALSA_H */