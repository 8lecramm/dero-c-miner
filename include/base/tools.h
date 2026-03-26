/*
 * Tools and Utility Functions
 */

#ifndef C_MINER_TOOLS_H
#define C_MINER_TOOLS_H

#include <stdint.h>

/* String/Hex conversion */
void stringToHex(uint8_t *in, uint32_t N, uint8_t *out);
void hexToString(uint8_t *in, uint8_t *out);

#endif /* C_MINER_TOOLS_H */
