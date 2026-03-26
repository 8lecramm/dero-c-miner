#include "astrobwt.h"
#include "divsufsort.h"
#include "../salsa/salsa.h"
#include "../fnv1a/fnv1a.h"
#include "../xxhash/xxhash.h"
#include "../siphash/siphash.h"
#include <openssl/sha.h>
#include <openssl/rc4.h>

static inline uint8_t reverse_bits(uint8_t num)
{
	uint8_t reverse_num = 0;
	for (int i = 0; i < NO_OF_BITS; i++)
		if ((num & (1 << i)))
			reverse_num |= 1 << ((NO_OF_BITS - 1) - i);
	return reverse_num;
}

static inline uint8_t rotate_bits(uint8_t value, uint8_t shift)
{
	return ((value << (shift % 8)) | value >> (8 - (shift % 8)));
}

static inline uint32_t convertToDataLen(uint32_t tries, uint8_t *step_3)
{
	return ((tries - 4) * 256) + ((((uint32_t)step_3[253] << 8) | step_3[254]) & 0x3FF);
}

void AstroBWTv3(uint8_t *input, uint8_t *output)
{

	uint8_t *scratchdata = &input[MINIBLOCK_SIZE + STEP_3_SIZE];
	uint8_t *step_3 = &input[MINIBLOCK_SIZE];
	int32_t *indices = &input[MINIBLOCK_SIZE + STEP_3_SIZE + SCRATCHSIZE];
	uint8_t op;
	uint8_t digest[32];
	uint8_t counter[16] = {0};
	uint8_t pos1, pos2;

	uint32_t data_len;
	uint64_t lhash, prev_lhash, random_switcher;
	uint64_t tries = 0;
	SHA256_CTX c;
	RC4_KEY rc4_key;

	memset(step_3, 0, STEP_3_SIZE);

	SHA256_Init(&c);
	SHA256_Update(&c, input, MINIBLOCK_SIZE);
	SHA256_Final(digest, &c);

	// falsa (fast + salsa = falsa) is much faster than native implementation
	// copied and modified from libsodium
	// Runtime CPU detection is performed inside salsa20 functions
	salsa20(digest, counter);
	salsa20_keystream(step_3, STEP_3_SIZE);

	RC4_set_key(&rc4_key, STEP_3_SIZE, step_3);
	RC4(&rc4_key, STEP_3_SIZE, step_3, step_3);

	lhash = fnv1a_hash(step_3, STEP_3_SIZE);
	prev_lhash = lhash;

	do
	{
		SHA256_Init(&c);
		tries++;
		random_switcher = prev_lhash ^ lhash ^ tries;
		op = (uint8_t)random_switcher;

		pos1 = (uint8_t)(random_switcher >> 8);
		pos2 = (uint8_t)(random_switcher >> 16);

		if (pos1 > pos2)
		{
			uint8_t temp;
			temp = pos1;
			pos1 = pos2;
			pos2 = temp;
		}
		if ((pos2 - pos1) > 32)
			pos2 = pos1 + ((pos2 - pos1) & 0x1f);

		switch (op)
		{
		case 0:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate bits by 5
				step_3[i] *= step_3[i];						   // *
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate bits by random

				uint8_t temp = step_3[pos2];
				step_3[pos2] = reverse_bits(step_3[pos1]);
				step_3[pos1] = reverse_bits(temp);
			}
			break;
		case 1:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = rotate_bits(step_3[i], 1);	  // rotate  bits by 1
				step_3[i] = step_3[i] & step_3[pos2];	  // AND
				step_3[i] += step_3[i];					  // +
			}
			break;
		case 2:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
			}
			break;
		case 3:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
			}
			break;
		case 4:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = ~step_3[i];						   // binary NOT operator
				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
			}
			break;
		case 5:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
			}
			break;
		case 6:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = rotate_bits(step_3[i], 3);	  // rotate  bits by 3
				step_3[i] = ~step_3[i];					  // binary NOT operator
				step_3[i] -= (step_3[i] ^ 97);			  // XOR and -
			}
			break;
		case 7:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] += step_3[i];						   // +
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = ~step_3[i];						   // binary NOT operator
			}
			break;
		case 8:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = ~step_3[i];					  // binary NOT operator
				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
			}
			break;
		case 9:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 10:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = ~step_3[i];				   // binary NOT operator
				step_3[i] *= step_3[i];				   // *
				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
				step_3[i] *= step_3[i];				   // *
			}
			break;
		case 11:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
			}
			break;
		case 12:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] *= step_3[i];							   // *
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = ~step_3[i];							   // binary NOT operator
			}
			break;
		case 13:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);	  // rotate  bits by 1
				step_3[i] = step_3[i] ^ step_3[pos2];	  // XOR
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
			}
			break;
		case 14:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] *= step_3[i];					  // *
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
			}
			break;
		case 15:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] -= (step_3[i] ^ 97);					   // XOR and -
			}
			break;
		case 16:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] *= step_3[i];							   // *
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] = ~step_3[i];							   // binary NOT operator
			}
			break;
		case 17:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];  // XOR
				step_3[i] *= step_3[i];				   // *
				step_3[i] = rotate_bits(step_3[i], 5); // rotate  bits by 5
				step_3[i] = ~step_3[i];				   // binary NOT operator
			}
			break;
		case 18:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
			}
			break;
		case 19:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] -= (step_3[i] ^ 97);			  // XOR and -
				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] += step_3[i];					  // +
			}
			break;
		case 20:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 21:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1); // rotate  bits by 1
				step_3[i] = step_3[i] ^ step_3[pos2];  // XOR
				step_3[i] += step_3[i];				   // +
				step_3[i] = step_3[i] & step_3[pos2];  // AND
			}
			break;
		case 22:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = reverse_bits(step_3[i]);	  // reverse bits
				step_3[i] *= step_3[i];					  // *
				step_3[i] = rotate_bits(step_3[i], 1);	  // rotate  bits by 1
			}
			break;
		case 23:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
			}
			break;
		case 24:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];							   // +
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
			}
			break;
		case 25:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
			}
			break;
		case 26:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] *= step_3[i];						   // *
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] += step_3[i];						   // +
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
			}
			break;
		case 27:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
			}
			break;
		case 28:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] += step_3[i];					  // +
				step_3[i] += step_3[i];					  // +
				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
			}
			break;
		case 29:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] *= step_3[i];					  // *
				step_3[i] = step_3[i] ^ step_3[pos2];	  // XOR
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] += step_3[i];					  // +
			}
			break;
		case 30:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
			}
			break;
		case 31:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] *= step_3[i];							   // *
			}
			break;
		case 32:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 33:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] *= step_3[i];							   // *
			}
			break;
		case 34:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] -= (step_3[i] ^ 97);			  // XOR and -
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] -= (step_3[i] ^ 97);			  // XOR and -
			}
			break;
		case 35:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];				   // +
				step_3[i] = ~step_3[i];				   // binary NOT operator
				step_3[i] = rotate_bits(step_3[i], 1); // rotate  bits by 1
				step_3[i] = step_3[i] ^ step_3[pos2];  // XOR
			}
			break;
		case 36:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
			}
			break;
		case 37:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] *= step_3[i];						   // *
			}
			break;
		case 38:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
			}
			break;
		case 39:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
			}
			break;
		case 40:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
			}
			break;
		case 41:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] -= (step_3[i] ^ 97);					   // XOR and -
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 42:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
			}
			break;
		case 43:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2]; // AND
				step_3[i] += step_3[i];				  // +
				step_3[i] = step_3[i] & step_3[pos2]; // AND
				step_3[i] -= (step_3[i] ^ 97);		  // XOR and -
			}
			break;
		case 44:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
			}
			break;
		case 45:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
			}
			break;
		case 46:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] += step_3[i];							   // +
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 47:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
				step_3[i] = step_3[i] & step_3[pos2];	  // AND
				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
			}
			break;
		case 48:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = ~step_3[i];						   // binary NOT operator
				step_3[i] = ~step_3[i];						   // binary NOT operator
				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
			}
			break;
		case 49:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] += step_3[i];							   // +
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 50:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]);   // reverse bits
				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
				step_3[i] += step_3[i];				   // +
				step_3[i] = rotate_bits(step_3[i], 1); // rotate  bits by 1
			}
			break;
		case 51:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
			}
			break;
		case 52:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] = ~step_3[i];						   // binary NOT operator
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
			}
			break;
		case 53:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];							   // +
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 54:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]);  // reverse bits
				step_3[i] = step_3[i] ^ step_3[pos2]; // XOR
				step_3[i] = ~step_3[i];				  // binary NOT operator
				step_3[i] = ~step_3[i];				  // binary NOT operator
			}
			break;
		case 55:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
			}
			break;
		case 56:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] *= step_3[i];							   // *
				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
			}
			break;
		case 57:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
			}
			break;
		case 58:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] += step_3[i];							   // +
			}
			break;
		case 59:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
				step_3[i] *= step_3[i];						   // *
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = ~step_3[i];						   // binary NOT operator
			}
			break;
		case 60:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];  // XOR
				step_3[i] = ~step_3[i];				   // binary NOT operator
				step_3[i] *= step_3[i];				   // *
				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
			}
			break;
		case 61:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = rotate_bits(step_3[i], 3);	  // rotate  bits by 3
				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
			}
			break;
		case 62:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] += step_3[i];							   // +
			}
			break;
		case 63:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
				step_3[i] += step_3[i];						   // +
			}
			break;
		case 64:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] *= step_3[i];							   // *
			}
			break;
		case 65:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] *= step_3[i];							   // *
			}
			break;
		case 66:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
			}
			break;
		case 67:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
			}
			break;
		case 68:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
			}
			break;
		case 69:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];					  // +
				step_3[i] *= step_3[i];					  // *
				step_3[i] = reverse_bits(step_3[i]);	  // reverse bits
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
			}
			break;
		case 70:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] *= step_3[i];							   // *
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 71:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
				step_3[i] = ~step_3[i];					  // binary NOT operator
				step_3[i] *= step_3[i];					  // *
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
			}
			break;
		case 72:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
			}
			break;
		case 73:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
			}
			break;
		case 74:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] *= step_3[i];				   // *
				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
				step_3[i] = reverse_bits(step_3[i]);   // reverse bits
				step_3[i] = step_3[i] & step_3[pos2];  // AND
			}
			break;
		case 75:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] *= step_3[i];							   // *
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 76:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
			}
			break;
		case 77:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] += step_3[i];						   // +
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
			}
			break;
		case 78:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
				step_3[i] *= step_3[i];						   // *
				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
			}
			break;
		case 79:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] += step_3[i];							   // +
				step_3[i] *= step_3[i];							   // *
			}
			break;
		case 80:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
				step_3[i] += step_3[i];						   // +
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
			}
			break;
		case 81:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
			}
			break;
		case 82:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];	  // XOR
				step_3[i] = ~step_3[i];					  // binary NOT operator
				step_3[i] = ~step_3[i];					  // binary NOT operator
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
			}
			break;
		case 83:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = reverse_bits(step_3[i]);	  // reverse bits
				step_3[i] = rotate_bits(step_3[i], 3);	  // rotate  bits by 3
				step_3[i] = reverse_bits(step_3[i]);	  // reverse bits
			}
			break;
		case 84:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] -= (step_3[i] ^ 97);			  // XOR and -
				step_3[i] = rotate_bits(step_3[i], 1);	  // rotate  bits by 1
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] += step_3[i];					  // +
			}
			break;
		case 85:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
			}
			break;
		case 86:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = ~step_3[i];							   // binary NOT operator
			}
			break;
		case 87:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];							   // +
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] += step_3[i];							   // +
			}
			break;
		case 88:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] *= step_3[i];							   // *
				step_3[i] = ~step_3[i];							   // binary NOT operator
			}
			break;
		case 89:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];							   // +
				step_3[i] *= step_3[i];							   // *
				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 90:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]);	  // reverse bits
				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
				step_3[i] = rotate_bits(step_3[i], 1);	  // rotate  bits by 1
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
			}
			break;
		case 91:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
			}
			break;
		case 92:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = ~step_3[i];						   // binary NOT operator
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
			}
			break;
		case 93:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] *= step_3[i];							   // *
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] += step_3[i];							   // +
			}
			break;
		case 94:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
			}
			break;
		case 95:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1); // rotate  bits by 1
				step_3[i] = ~step_3[i];				   // binary NOT operator
				step_3[i] = rotate_bits(step_3[i], 5); // rotate  bits by 5
				step_3[i] = rotate_bits(step_3[i], 5); // rotate  bits by 5
			}
			break;
		case 96:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
			}
			break;
		case 97:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
			}
			break;
		case 98:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 99:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] -= (step_3[i] ^ 97);					   // XOR and -
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
			}
			break;
		case 100:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
			}
			break;
		case 101:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] = ~step_3[i];						   // binary NOT operator
			}
			break;
		case 102:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
				step_3[i] -= (step_3[i] ^ 97);		   // XOR and -
				step_3[i] += step_3[i];				   // +
				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
			}
			break;
		case 103:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
			}
			break;
		case 104:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] += step_3[i];						   // +
			}
			break;
		case 105:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 106:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] *= step_3[i];							   // *
			}
			break;
		case 107:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
			}
			break;
		case 108:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 109:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] *= step_3[i];							   // *
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 110:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];							   // +
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
			}
			break;
		case 111:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] *= step_3[i];					  // *
				step_3[i] = reverse_bits(step_3[i]);	  // reverse bits
				step_3[i] *= step_3[i];					  // *
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
			}
			break;
		case 112:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
				step_3[i] = ~step_3[i];				   // binary NOT operator
				step_3[i] = rotate_bits(step_3[i], 5); // rotate  bits by 5
				step_3[i] -= (step_3[i] ^ 97);		   // XOR and -
			}
			break;
		case 113:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = ~step_3[i];						   // binary NOT operator
			}
			break;
		case 114:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = ~step_3[i];						   // binary NOT operator
			}
			break;
		case 115:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
			}
			break;
		case 116:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];		   // AND
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
			}
			break;
		case 117:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = rotate_bits(step_3[i], 3);	  // rotate  bits by 3
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = step_3[i] & step_3[pos2];	  // AND
			}
			break;
		case 118:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] += step_3[i];					  // +
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
			}
			break;
		case 119:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
			}
			break;
		case 120:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] *= step_3[i];							   // *
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
			}
			break;
		case 121:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] += step_3[i];						   // +
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] *= step_3[i];						   // *
			}
			break;
		case 122:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 123:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];  // AND
				step_3[i] = ~step_3[i];				   // binary NOT operator
				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
			}
			break;
		case 124:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = ~step_3[i];							   // binary NOT operator
			}
			break;
		case 125:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] += step_3[i];							   // +
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
			}
			break;
		case 126:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
				step_3[i] = rotate_bits(step_3[i], 1); // rotate  bits by 1
				step_3[i] = rotate_bits(step_3[i], 5); // rotate  bits by 5
				step_3[i] = reverse_bits(step_3[i]);   // reverse bits
			}
			break;
		case 127:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] *= step_3[i];					  // *
				step_3[i] = step_3[i] & step_3[pos2];	  // AND
				step_3[i] = step_3[i] ^ step_3[pos2];	  // XOR
			}
			break;
		case 128:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
			}
			break;
		case 129:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];						   // binary NOT operator
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
			}
			break;
		case 130:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 131:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] *= step_3[i];						   // *
			}
			break;
		case 132:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 133:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
			}
			break;
		case 134:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
			}
			break;
		case 135:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] += step_3[i];							   // +
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
			}
			break;
		case 136:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] -= (step_3[i] ^ 97);			  // XOR and -
				step_3[i] = step_3[i] ^ step_3[pos2];	  // XOR
				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
			}
			break;
		case 137:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
			}
			break;
		case 138:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2]; // XOR
				step_3[i] = step_3[i] ^ step_3[pos2]; // XOR
				step_3[i] += step_3[i];				  // +
				step_3[i] -= (step_3[i] ^ 97);		  // XOR and -
			}
			break;
		case 139:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
			}
			break;
		case 140:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
			}
			break;
		case 141:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] += step_3[i];						   // +
			}
			break;
		case 142:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 143:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];	  // AND
				step_3[i] = rotate_bits(step_3[i], 3);	  // rotate  bits by 3
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
			}
			break;
		case 144:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
				step_3[i] = ~step_3[i];						   // binary NOT operator
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
			}
			break;
		case 145:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 146:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];		   // AND
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
			}
			break;
		case 147:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] *= step_3[i];							   // *
			}
			break;
		case 148:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];	  // AND
				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] -= (step_3[i] ^ 97);			  // XOR and -
			}
			break;
		case 149:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2]; // XOR
				step_3[i] = reverse_bits(step_3[i]);  // reverse bits
				step_3[i] -= (step_3[i] ^ 97);		  // XOR and -
				step_3[i] += step_3[i];				  // +
			}
			break;
		case 150:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = step_3[i] & step_3[pos2];	  // AND
			}
			break;
		case 151:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];					  // +
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] *= step_3[i];					  // *
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
			}
			break;
		case 152:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 153:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1); // rotate  bits by 1
				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
				step_3[i] = ~step_3[i];				   // binary NOT operator
				step_3[i] = ~step_3[i];				   // binary NOT operator
			}
			break;
		case 154:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] = ~step_3[i];						   // binary NOT operator
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
			}
			break;
		case 155:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
			}
			break;
		case 156:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = rotate_bits(step_3[i], 3);	  // rotate  bits by 3
				step_3[i] = rotate_bits(step_3[i], 1);	  // rotate  bits by 1
			}
			break;
		case 157:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
			}
			break;
		case 158:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] += step_3[i];						   // +
				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
			}
			break;
		case 159:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
			}
			break;
		case 160:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = reverse_bits(step_3[i]);	  // reverse bits
				step_3[i] = rotate_bits(step_3[i], 1);	  // rotate  bits by 1
				step_3[i] = rotate_bits(step_3[i], 3);	  // rotate  bits by 3
			}
			break;
		case 161:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
			}
			break;
		case 162:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] *= step_3[i];							   // *
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] -= (step_3[i] ^ 97);					   // XOR and -
			}
			break;
		case 163:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] -= (step_3[i] ^ 97);					   // XOR and -
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
			}
			break;
		case 164:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] *= step_3[i];						   // *
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
				step_3[i] = ~step_3[i];						   // binary NOT operator
			}
			break;
		case 165:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] += step_3[i];							   // +
			}
			break;
		case 166:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] += step_3[i];							   // +
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = ~step_3[i];							   // binary NOT operator
			}
			break;
		case 167:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];					  // binary NOT operator
				step_3[i] = ~step_3[i];					  // binary NOT operator
				step_3[i] *= step_3[i];					  // *
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
			}
			break;
		case 168:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
			}
			break;
		case 169:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
			}
			break;
		case 170:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] -= (step_3[i] ^ 97);		 // XOR and -
				step_3[i] = reverse_bits(step_3[i]); // reverse bits
				step_3[i] -= (step_3[i] ^ 97);		 // XOR and -
				step_3[i] *= step_3[i];				 // *
			}
			break;
		case 171:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
			}
			break;
		case 172:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] -= (step_3[i] ^ 97);					   // XOR and -
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
			}
			break;
		case 173:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];					  // binary NOT operator
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] *= step_3[i];					  // *
				step_3[i] += step_3[i];					  // +
			}
			break;
		case 174:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];						   // binary NOT operator
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
			}
			break;
		case 175:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
				step_3[i] -= (step_3[i] ^ 97);		   // XOR and -
				step_3[i] *= step_3[i];				   // *
				step_3[i] = rotate_bits(step_3[i], 5); // rotate  bits by 5
			}
			break;
		case 176:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];  // XOR
				step_3[i] *= step_3[i];				   // *
				step_3[i] = step_3[i] ^ step_3[pos2];  // XOR
				step_3[i] = rotate_bits(step_3[i], 5); // rotate  bits by 5
			}
			break;
		case 177:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
			}
			break;
		case 178:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];  // AND
				step_3[i] += step_3[i];				   // +
				step_3[i] = ~step_3[i];				   // binary NOT operator
				step_3[i] = rotate_bits(step_3[i], 1); // rotate  bits by 1
			}
			break;
		case 179:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] += step_3[i];							   // +
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
			}
			break;
		case 180:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] -= (step_3[i] ^ 97);					   // XOR and -
			}
			break;
		case 181:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
			}
			break;
		case 182:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 183:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];		   // +
				step_3[i] -= (step_3[i] ^ 97); // XOR and -
				step_3[i] -= (step_3[i] ^ 97); // XOR and -
				step_3[i] *= step_3[i];		   // *
			}
			break;
		case 184:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] *= step_3[i];					  // *
				step_3[i] = rotate_bits(step_3[i], 5);	  // rotate  bits by 5
				step_3[i] = step_3[i] ^ step_3[pos2];	  // XOR
			}
			break;
		case 185:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
			}
			break;
		case 186:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] -= (step_3[i] ^ 97);					   // XOR and -
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
			}
			break;
		case 187:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];  // XOR
				step_3[i] = ~step_3[i];				   // binary NOT operator
				step_3[i] += step_3[i];				   // +
				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
			}
			break;
		case 188:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 189:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] -= (step_3[i] ^ 97);					   // XOR and -
			}
			break;
		case 190:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 191:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];						   // +
				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
			}
			break;
		case 192:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];					  // +
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] += step_3[i];					  // +
				step_3[i] *= step_3[i];					  // *
			}
			break;
		case 193:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];		   // AND
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
			}
			break;
		case 194:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];		   // AND
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = step_3[i] << (step_3[i] & 3);	   // shift left
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
			}
			break;
		case 195:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 196:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3);	  // rotate  bits by 3
				step_3[i] = reverse_bits(step_3[i]);	  // reverse bits
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = rotate_bits(step_3[i], 1);	  // rotate  bits by 1
			}
			break;
		case 197:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] *= step_3[i];							   // *
				step_3[i] *= step_3[i];							   // *
			}
			break;
		case 198:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = reverse_bits(step_3[i]);	  // reverse bits
				step_3[i] = rotate_bits(step_3[i], 1);	  // rotate  bits by 1
			}
			break;
		case 199:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];				  // binary NOT operator
				step_3[i] += step_3[i];				  // +
				step_3[i] *= step_3[i];				  // *
				step_3[i] = step_3[i] ^ step_3[pos2]; // XOR
			}
			break;
		case 200:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
			}
			break;
		case 201:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = ~step_3[i];							   // binary NOT operator
			}
			break;
		case 202:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = ~step_3[i];						   // binary NOT operator
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
			}
			break;
		case 203:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
			}
			break;
		case 204:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
			}
			break;
		case 205:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] += step_3[i];							   // +
			}
			break;
		case 206:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
			}
			break;
		case 207:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
			}
			break;
		case 208:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];					  // +
				step_3[i] += step_3[i];					  // +
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = rotate_bits(step_3[i], 3);	  // rotate  bits by 3
			}
			break;
		case 209:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
				step_3[i] = reverse_bits(step_3[i]);		   // reverse bits
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
			}
			break;
		case 210:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = ~step_3[i];							   // binary NOT operator
			}
			break;
		case 211:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] += step_3[i];							   // +
				step_3[i] -= (step_3[i] ^ 97);					   // XOR and -
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
			}
			break;
		case 212:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
			}
			break;
		case 213:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];					  // +
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = rotate_bits(step_3[i], 3);	  // rotate  bits by 3
				step_3[i] -= (step_3[i] ^ 97);			  // XOR and -
			}
			break;
		case 214:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];	  // XOR
				step_3[i] -= (step_3[i] ^ 97);			  // XOR and -
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = ~step_3[i];					  // binary NOT operator
			}
			break;
		case 215:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2];	  // XOR
				step_3[i] = step_3[i] & step_3[pos2];	  // AND
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] *= step_3[i];					  // *
			}
			break;
		case 216:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = ~step_3[i];						   // binary NOT operator
				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
			}
			break;
		case 217:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] += step_3[i];							   // +
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 218:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]); // reverse bits
				step_3[i] = ~step_3[i];				 // binary NOT operator
				step_3[i] *= step_3[i];				 // *
				step_3[i] -= (step_3[i] ^ 97);		 // XOR and -
			}
			break;
		case 219:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
			}
			break;
		case 220:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);	  // rotate  bits by 1
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = reverse_bits(step_3[i]);	  // reverse bits
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
			}
			break;
		case 221:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5); // rotate  bits by 5
				step_3[i] = step_3[i] ^ step_3[pos2];  // XOR
				step_3[i] = ~step_3[i];				   // binary NOT operator
				step_3[i] = reverse_bits(step_3[i]);   // reverse bits
			}
			break;
		case 222:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] = step_3[i] ^ step_3[pos2];	  // XOR
				step_3[i] *= step_3[i];					  // *
			}
			break;
		case 223:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] = step_3[i] ^ step_3[pos2];		   // XOR
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
			}
			break;
		case 224:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
			}
			break;
		case 225:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];					  // binary NOT operator
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = reverse_bits(step_3[i]);	  // reverse bits
				step_3[i] = rotate_bits(step_3[i], 3);	  // rotate  bits by 3
			}
			break;
		case 226:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = reverse_bits(step_3[i]);  // reverse bits
				step_3[i] -= (step_3[i] ^ 97);		  // XOR and -
				step_3[i] *= step_3[i];				  // *
				step_3[i] = step_3[i] ^ step_3[pos2]; // XOR
			}
			break;
		case 227:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];					  // binary NOT operator
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
				step_3[i] -= (step_3[i] ^ 97);			  // XOR and -
				step_3[i] = step_3[i] & step_3[pos2];	  // AND
			}
			break;
		case 228:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];						   // +
				step_3[i] = step_3[i] >> (step_3[i] & 3);	   // shift right
				step_3[i] += step_3[i];						   // +
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
			}
			break;
		case 229:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
			}
			break;
		case 230:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] *= step_3[i];						   // *
				step_3[i] = step_3[i] & step_3[pos2];		   // AND
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
				step_3[i] = rotate_bits(step_3[i], step_3[i]); // rotate  bits by random
			}
			break;
		case 231:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 3);	  // rotate  bits by 3
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = step_3[i] ^ step_3[pos2];	  // XOR
				step_3[i] = reverse_bits(step_3[i]);	  // reverse bits
			}
			break;
		case 232:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] *= step_3[i];							   // *
				step_3[i] *= step_3[i];							   // *
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
			}
			break;
		case 233:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 1);		   // rotate  bits by 1
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = rotate_bits(step_3[i], 3);		   // rotate  bits by 3
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
			}
			break;
		case 234:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] & step_3[pos2];	  // AND
				step_3[i] *= step_3[i];					  // *
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] = step_3[i] ^ step_3[pos2];	  // XOR
			}
			break;
		case 235:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] *= step_3[i];							   // *
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = ~step_3[i];							   // binary NOT operator
			}
			break;
		case 236:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ step_3[pos2]; // XOR
				step_3[i] += step_3[i];				  // +
				step_3[i] = step_3[i] & step_3[pos2]; // AND
				step_3[i] -= (step_3[i] ^ 97);		  // XOR and -
			}
			break;
		case 237:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
			}
			break;
		case 238:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];				   // +
				step_3[i] += step_3[i];				   // +
				step_3[i] = rotate_bits(step_3[i], 3); // rotate  bits by 3
				step_3[i] -= (step_3[i] ^ 97);		   // XOR and -
			}
			break;
		case 239:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5); // rotate  bits by 5
				step_3[i] = rotate_bits(step_3[i], 1); // rotate  bits by 1
				step_3[i] *= step_3[i];				   // *
				step_3[i] = step_3[i] & step_3[pos2];  // AND
			}
			break;
		case 240:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];					  // binary NOT operator
				step_3[i] += step_3[i];					  // +
				step_3[i] = step_3[i] & step_3[pos2];	  // AND
				step_3[i] = step_3[i] << (step_3[i] & 3); // shift left
			}
			break;
		case 241:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
			}
			break;
		case 242:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];				  // +
				step_3[i] += step_3[i];				  // +
				step_3[i] -= (step_3[i] ^ 97);		  // XOR and -
				step_3[i] = step_3[i] ^ step_3[pos2]; // XOR
			}
			break;
		case 243:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = rotate_bits(step_3[i], 1);			   // rotate  bits by 1
			}
			break;
		case 244:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];							   // binary NOT operator
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
			}
			break;
		case 245:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] -= (step_3[i] ^ 97);					   // XOR and -
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] >> (step_3[i] & 3);		   // shift right
			}
			break;
		case 246:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] += step_3[i];					  // +
				step_3[i] = rotate_bits(step_3[i], 1);	  // rotate  bits by 1
				step_3[i] = step_3[i] >> (step_3[i] & 3); // shift right
				step_3[i] += step_3[i];					  // +
			}
			break;
		case 247:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 5);			   // rotate  bits by 5
				step_3[i] = ~step_3[i];							   // binary NOT operator
			}
			break;
		case 248:
			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = ~step_3[i];						   // binary NOT operator
				step_3[i] -= (step_3[i] ^ 97);				   // XOR and -
				step_3[i] = step_3[i] ^ count_ones(step_3[i]); // ones count bits
				step_3[i] = rotate_bits(step_3[i], 5);		   // rotate  bits by 5
			}
			break;
		case 249:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
			}
			break;
		case 250:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = step_3[i] & step_3[pos2];			   // AND
				step_3[i] = rotate_bits(step_3[i], step_3[i]);	   // rotate  bits by random
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
			}
			break;
		case 251:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] += step_3[i];							   // +
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
			}
			break;
		case 252:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = reverse_bits(step_3[i]);			   // reverse bits
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 4); // rotate  bits by 4
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] << (step_3[i] & 3);		   // shift left
			}
			break;
		case 253:
			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = step_3[i] ^ step_3[pos2];			   // XOR
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3

				prev_lhash = lhash + prev_lhash;
				lhash = xxhash64(step_3, pos2); // more deviations
			}
			break;

		case 254: // 0.7% chance of execution every loop
			RC4_set_key(&rc4_key, STEP_3_SIZE, step_3);

			for (size_t i = pos1; i < pos2; i++)
			{

				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
			}
			break;

		case 255: // 0.7% chance of execution every loop
			RC4_set_key(&rc4_key, STEP_3_SIZE, step_3);

			for (size_t i = pos1; i < pos2; i++)
			{
				step_3[i] = step_3[i] ^ count_ones(step_3[i]);	   // ones count bits
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
				step_3[i] = step_3[i] ^ rotate_bits(step_3[i], 2); // rotate  bits by 2
				step_3[i] = rotate_bits(step_3[i], 3);			   // rotate  bits by 3
			}
			break;

		default:
			break;
		}

		if ((uint8_t)(step_3[pos1] - step_3[pos2]) < 0x10)
		{ // 6.25 % probability
			prev_lhash = lhash + prev_lhash;
			lhash = xxhash64(step_3, pos2); // more deviations
		}

		if ((uint8_t)(step_3[pos1] - step_3[pos2]) < 0x20)
		{ // 12.5 % probability
			prev_lhash = lhash + prev_lhash;
			lhash = fnv1a_hash(step_3, pos2); // more deviations
		}

		if ((uint8_t)(step_3[pos1] - step_3[pos2]) < 0x30)
		{ // 18.75 % probability
			prev_lhash = lhash + prev_lhash;
			lhash = siphash128(tries, prev_lhash, step_3, pos2); // more deviations
		}

		if ((uint8_t)(step_3[pos1] - step_3[pos2]) <= 0x40)
		{ // 25% probablility
			RC4(&rc4_key, STEP_3_SIZE, step_3, step_3);
		}

		step_3[255] = step_3[255] ^ step_3[pos1] ^ step_3[pos2];

		memcpy(&scratchdata[(tries - 1) * 256], step_3, STEP_3_SIZE); // copy all the tmp states

		if ((tries > 260) && (step_3[255] >= 0xf0))
			break;
	} while (tries <= 260 + 16);

	data_len = convertToDataLen(tries, step_3);

	// suffix array sorting
	sais(scratchdata, data_len, indices);

	SHA256_Update(&c, (uint8_t *)indices, data_len * 4);
	SHA256_Final(output, &c);
}