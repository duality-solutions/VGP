#include <string.h>
#include "aes256.h"
#include "utils.h"

static uint8_t mult(uint8_t c, uint8_t d)
{
    int32_t i;
    uint8_t f[8];
    uint8_t g[8];
    uint8_t h[15];
    uint8_t result;

    crypto_memzero(h, sizeof(h));
    f[0] = 1 & c;        g[0] = 1 & d;
    f[1] = 1 & (c >> 1); g[1] = 1 & (d >> 1);
    f[2] = 1 & (c >> 2); g[2] = 1 & (d >> 2);
    f[3] = 1 & (c >> 3); g[3] = 1 & (d >> 3);
    f[4] = 1 & (c >> 4); g[4] = 1 & (d >> 4);
    f[5] = 1 & (c >> 5); g[5] = 1 & (d >> 5);
    f[6] = 1 & (c >> 6); g[6] = 1 & (d >> 6);
    f[7] = 1 & (c >> 7); g[7] = 1 & (d >> 7);

    for (i = 0; i < 8; ++i)
    {
        h[i]     ^= f[i] & g[0];
        h[i + 1] ^= f[i] & g[1];
        h[i + 2] ^= f[i] & g[2];
        h[i + 3] ^= f[i] & g[3];
        h[i + 4] ^= f[i] & g[4];
        h[i + 5] ^= f[i] & g[5];
        h[i + 6] ^= f[i] & g[6];
        h[i + 7] ^= f[i] & g[7];
    }

    for (i = 6; i >= 0; --i)
    {
        h[i + 0] ^= h[i + 8];
        h[i + 1] ^= h[i + 8];
        h[i + 3] ^= h[i + 8];
        h[i + 4] ^= h[i + 8];
        h[i + 8] ^= h[i + 8];
    }

    result  = h[0];
    result |= h[1] << 1;
    result |= h[2] << 2;
    result |= h[3] << 3;
    result |= h[4] << 4;
    result |= h[5] << 5;
    result |= h[6] << 6;
    result |= h[7] << 7;

    return result;
}

static uint8_t sqr(uint8_t c)
{
    return mult(c, c);
}

static uint8_t dbl(uint8_t c)
{
    return mult(c, 2);
}

static uint8_t inv(uint8_t c)
{
    /* c^3 = c^2 * c */
    uint8_t c_pow_3 = mult(sqr(c), c);
    /* c^7 = (c^3)^2 * c */
    uint8_t c_pow_7 = mult(sqr(c_pow_3), c);
    /* c^63 = (((c^7)^2)^2)^2 * c^7 */
    uint8_t c_pow_63 = mult(sqr(sqr(sqr(c_pow_7))), c_pow_7);
    /* c^127 = (c^63)^2 * c */
    uint8_t c_pow_127 = mult(sqr(c_pow_63), c);
    /* The inverse of c, c^-1 = c^254 = (c^127)^2 */
    return sqr(c_pow_127);
}

static uint8_t byte_sub(uint8_t c)
{
    uint8_t f[8];
    uint8_t h[8];
    uint8_t result;

    c = inv(c);
    f[0] = 1 & c;
    f[1] = 1 & (c >> 1);
    f[2] = 1 & (c >> 2);
    f[3] = 1 & (c >> 3);
    f[4] = 1 & (c >> 4);
    f[5] = 1 & (c >> 5);
    f[6] = 1 & (c >> 6);
    f[7] = 1 & (c >> 7);

    h[0] = f[0] ^ f[4] ^ f[5] ^ f[6] ^ f[7] ^ 1;
    h[1] = f[1] ^ f[5] ^ f[6] ^ f[7] ^ f[0] ^ 1;
    h[2] = f[2] ^ f[6] ^ f[7] ^ f[0] ^ f[1];
    h[3] = f[3] ^ f[7] ^ f[0] ^ f[1] ^ f[2];
    h[4] = f[4] ^ f[0] ^ f[1] ^ f[2] ^ f[3];
    h[5] = f[5] ^ f[1] ^ f[2] ^ f[3] ^ f[4] ^ 1;
    h[6] = f[6] ^ f[2] ^ f[3] ^ f[4] ^ f[5] ^ 1;
    h[7] = f[7] ^ f[3] ^ f[4] ^ f[5] ^ f[6];

    result  = h[0];
    result |= h[1] << 1;
    result |= h[2] << 2;
    result |= h[3] << 3;
    result |= h[4] << 4;
    result |= h[5] << 5;
    result |= h[6] << 6;
    result |= h[7] << 7;

    return result;
}

static uint8_t inv_byte_sub(uint8_t c)
{
    uint8_t h[8];
    uint8_t f[8];

    h[0] = 1 & c;
    h[1] = 1 & (c >> 1);
    h[2] = 1 & (c >> 2);
    h[3] = 1 & (c >> 3);
    h[4] = 1 & (c >> 4);
    h[5] = 1 & (c >> 5);
    h[6] = 1 & (c >> 6);
    h[7] = 1 & (c >> 7);

    h[0] ^= 1;
    h[1] ^= 1;
    h[5] ^= 1;
    h[6] ^= 1;
    f[0] = h[2] ^ h[5] ^ h[7];
    f[1] = h[3] ^ h[6] ^ h[0];
    f[2] = h[4] ^ h[7] ^ h[1];
    f[3] = h[5] ^ h[0] ^ h[2];
    f[4] = h[6] ^ h[1] ^ h[3];
    f[5] = h[7] ^ h[2] ^ h[4];
    f[6] = h[0] ^ h[3] ^ h[5];
    f[7] = h[1] ^ h[4] ^ h[6];

    c = f[0];
    c |= f[1] << 1;
    c |= f[2] << 2;
    c |= f[3] << 3;
    c |= f[4] << 4;
    c |= f[5] << 5;
    c |= f[6] << 6;
    c |= f[7] << 7;

    return inv(c);
}

void expand_key(uint8_t *expanded, const uint8_t *key)
{
    int32_t idx;
    uint8_t t[4];
    uint8_t round_constant;

    for (idx = 0; idx < 8; ++idx)
    {
        expanded[      idx] = key[4*idx    ];
        expanded[ 60 + idx] = key[4*idx + 1];
        expanded[120 + idx] = key[4*idx + 2];
        expanded[180 + idx] = key[4*idx + 3];
    }

    round_constant = 1;
    for (idx = 8; idx < 60; ++idx)
    {
        if (idx & 3) 
        {
            t[0] = expanded[      (idx - 1)];
            t[1] = expanded[ 60 + (idx - 1)];
            t[2] = expanded[120 + (idx - 1)];
            t[3] = expanded[180 + (idx - 1)];
        }
        else if (idx & 7) 
        {
            t[0] = byte_sub(expanded[      (idx - 1)]);
            t[1] = byte_sub(expanded[ 60 + (idx - 1)]);
            t[2] = byte_sub(expanded[120 + (idx - 1)]);
            t[3] = byte_sub(expanded[180 + (idx - 1)]);
        }
        else
        {
            t[0]  = byte_sub(expanded[ 60 + (idx - 1)]);
            t[1]  = byte_sub(expanded[120 + (idx - 1)]);
            t[2]  = byte_sub(expanded[180 + (idx - 1)]);
            t[3]  = byte_sub(expanded[      (idx - 1)]);
            t[0] ^= round_constant;
            round_constant = dbl(round_constant);
        }
        expanded[      idx] = t[0] ^ expanded[      (idx - 8)];
        expanded[ 60 + idx] = t[1] ^ expanded[ 60 + (idx - 8)];
        expanded[120 + idx] = t[2] ^ expanded[120 + (idx - 8)];
        expanded[180 + idx] = t[3] ^ expanded[180 + (idx - 8)];
    }
}

void aes256_bitslice_encrypt(uint8_t *out,
                             const uint8_t *in,
                             const uint8_t *key)
{
    uint8_t expanded[240];
    uint8_t state[16];
    uint8_t new_state[16];
    uint8_t a[4];
    int32_t idx, round;

    expand_key(expanded, key);

    for (idx = 0; idx < 4; ++idx)
    {
        state[     idx] = in[4*idx]     ^ expanded[      idx];
        state[ 4 + idx] = in[4*idx + 1] ^ expanded[ 60 + idx];
        state[ 8 + idx] = in[4*idx + 2] ^ expanded[120 + idx];
        state[12 + idx] = in[4*idx + 3] ^ expanded[180 + idx];
    }

    for (round = 0; round < 14; ++round)
    {
        for (idx = 0; idx < 4; ++idx) 
        {
            new_state[4*idx    ] = byte_sub(state[4*idx    ]);
            new_state[4*idx + 1] = byte_sub(state[4*idx + 1]);
            new_state[4*idx + 2] = byte_sub(state[4*idx + 2]);
            new_state[4*idx + 3] = byte_sub(state[4*idx + 3]);
        }
        for (idx = 0; idx < 4; ++idx) 
        {
            state[4*idx    ] = new_state[4*idx + idx];
            state[4*idx + 1] = new_state[4*idx + ((1 + idx) & 3)];
            state[4*idx + 2] = new_state[4*idx + ((2 + idx) & 3)];
            state[4*idx + 3] = new_state[4*idx + ((3 + idx) & 3)];
        }
        if (round < 13) 
        {
            for (idx = 0; idx < 4; ++idx)
            {
                a[0] = state[     idx];
                a[1] = state[ 4 + idx];
                a[2] = state[ 8 + idx];
                a[3] = state[12 + idx];
                state[     idx] = dbl(a[0] ^ a[1]) ^ a[1] ^ a[2] ^ a[3];
                state[ 4 + idx] = dbl(a[1] ^ a[2]) ^ a[2] ^ a[3] ^ a[0];
                state[ 8 + idx] = dbl(a[2] ^ a[3]) ^ a[3] ^ a[0] ^ a[1];
                state[12 + idx] = dbl(a[3] ^ a[0]) ^ a[0] ^ a[1] ^ a[2];
            }
        }
        for (idx = 0; idx < 4; ++idx)
        {
            state[4*idx    ] ^= expanded[60*idx + (4 * round + 4)];
            state[4*idx + 1] ^= expanded[60*idx + (4 * round + 5)];
            state[4*idx + 2] ^= expanded[60*idx + (4 * round + 6)];
            state[4*idx + 3] ^= expanded[60*idx + (4 * round + 7)];
        }
    }

    out[ 0] = state[0]; out[ 1] = state[4]; out[ 2] = state[8];  out[ 3] = state[12];
    out[ 4] = state[1]; out[ 5] = state[5]; out[ 6] = state[9];  out[ 7] = state[13];
    out[ 8] = state[2]; out[ 9] = state[6]; out[10] = state[10]; out[11] = state[14];
    out[12] = state[3]; out[13] = state[7]; out[14] = state[11]; out[15] = state[15];
}

void aes256_bitslice_decrypt(uint8_t *out,
                             const uint8_t *in,
                             const uint8_t *key)
{
    uint8_t expanded[240];
    uint8_t state[16];
    uint8_t new_state[16];
    uint8_t a0, a1, a2, a3;
    int32_t idx, round;

    expand_key(expanded, key);

    for (idx = 0; idx < 4; ++idx)
    {
        state[     idx] = in[4*idx];
        state[ 4 + idx] = in[4*idx + 1];
        state[ 8 + idx] = in[4*idx + 2];
        state[12 + idx] = in[4*idx + 3];
    }

    for (round = 13; round >= 0; --round)
    {
        for (idx = 0; idx < 4; ++idx)
        {
            state[4*idx    ] ^= expanded[60*idx + (4*round + 4)];
            state[4*idx + 1] ^= expanded[60*idx + (4*round + 5)];
            state[4*idx + 2] ^= expanded[60*idx + (4*round + 6)];
            state[4*idx + 3] ^= expanded[60*idx + (4*round + 7)];
        }
        if (round < 13) 
        {
            for (idx = 0; idx < 4; ++idx)
            {
                a0 = state[     idx];
                a1 = state[ 4 + idx];
                a2 = state[ 8 + idx];
                a3 = state[12 + idx];
                state[     idx] = mult(a1, 11) ^ mult(a2, 13) ^ mult(a3, 9) ^ mult(a0, 14);
                state[ 4 + idx] = mult(a2, 11) ^ mult(a3, 13) ^ mult(a0, 9) ^ mult(a1, 14);
                state[ 8 + idx] = mult(a3, 11) ^ mult(a0, 13) ^ mult(a1, 9) ^ mult(a2, 14);
                state[12 + idx] = mult(a0, 11) ^ mult(a1, 13) ^ mult(a2, 9) ^ mult(a3, 14);
            }
        }
        for (idx = 0; idx < 4; ++idx) 
        {
            new_state[4*idx    ] = state[4*idx + ((4 - idx) & 3)];             
            new_state[4*idx + 1] = state[4*idx + ((5 - idx) & 3)];             
            new_state[4*idx + 2] = state[4*idx + ((6 - idx) & 3)];             
            new_state[4*idx + 3] = state[4*idx + ((7 - idx) & 3)];             
        }
        for (idx = 0; idx < 4; ++idx) 
        {
            state[4*idx    ] = inv_byte_sub(new_state[4*idx    ]);
            state[4*idx + 1] = inv_byte_sub(new_state[4*idx + 1]);
            state[4*idx + 2] = inv_byte_sub(new_state[4*idx + 2]);
            state[4*idx + 3] = inv_byte_sub(new_state[4*idx + 3]);
        }
    }

    for (idx = 0; idx < 4; ++idx) 
    {
        state[     idx] ^= expanded[      idx];
        state[ 4 + idx] ^= expanded[ 60 + idx];       
        state[ 8 + idx] ^= expanded[120 + idx];
        state[12 + idx] ^= expanded[180 + idx];
    }

    out[ 0] = state[0]; out[ 1] = state[4]; out[ 2] = state[ 8]; out[ 3] = state[12];
    out[ 4] = state[1]; out[ 5] = state[5]; out[ 6] = state[ 9]; out[ 7] = state[13];
    out[ 8] = state[2]; out[ 9] = state[6]; out[10] = state[10]; out[11] = state[14];
    out[12] = state[3]; out[13] = state[7]; out[14] = state[11]; out[15] = state[15];
}
