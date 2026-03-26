#include <stddef.h>
#include <stdint.h>

uint64_t AddBytes64(uint64_t h, const uint8_t* b, size_t len);
uint64_t fnv1a_hash(const uint8_t* data, size_t len);