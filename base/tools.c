#include "../include/pow.h"

inline void stringToHex(uint8_t *in, uint32_t N, uint8_t *out)
{
    uint8_t a[2];
    for (int i = 0; i < N; i += 2)
    {
        for (int j = 0; j < 2; j++)
            if (in[i + j] > 96)
                a[j] = in[i + j] - 87;
            else
                a[j] = in[i + j] - 48;
        out[i / 2] = (a[0] << 4) | a[1];
    }
}

inline void hexToString(uint8_t *in, uint8_t *out)
{
    uint8_t value = 0;
    uint8_t pos = 0;

    for (int i = 0; i < 48; i++)
    {
        for (int j = 0; j < 2; j++)
        {
            if (j == 0)
                value = (in[i] >> 4) & 0xF;
            else
                value = (in[i]) & 0xF;

            if (value > 0x9)
                out[2 * i + j] = value + 87;
            else
                out[2 * i + j] = value + 48;
        }
        pos++;
    }
    out[pos << 1] = '\0';
}