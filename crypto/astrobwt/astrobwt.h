#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#define MINIBLOCK_SIZE 48
#define STEP_3_SIZE 256
#define SCRATCHSIZE 71680
#define MEMORY 2 << 20
#define WORKSIZE 2 << 18
#define NO_OF_BITS 8
#define count_ones __builtin_popcount

void AstroBWTv3(uint8_t *, uint8_t *);