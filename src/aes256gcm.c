#include "aes256.h"
#include "aes256gcm.h"
#include "utils.h"

static void big_endian_store32(uint8_t *x, uint32_t u)
{
    x[3] = u & 0xFF; u >>= 8;
    x[2] = u & 0xFF; u >>= 8;
    x[1] = u & 0xFF; u >>= 8;
    x[0] = u & 0xFF;
}

static void big_endian_store64(uint8_t *x, uint64_t u)
{
    x[7] = u & 0xFF; u >>= 8;
    x[6] = u & 0xFF; u >>= 8;
    x[5] = u & 0xFF; u >>= 8;
    x[4] = u & 0xFF; u >>= 8;
    x[3] = u & 0xFF; u >>= 8;
    x[2] = u & 0xFF; u >>= 8;
    x[1] = u & 0xFF; u >>= 8;
    x[0] = u & 0xFF;
}

/**
 * @brief Computes (a + x)*y.
 * 
 * @param a The input/output vector a, 16 bytes long
 * @param x The input vector x, x_len bytes long
 * @param x_len The length of vector x (in bytes)
 * @param y The input vector y, 16 bytes long
 */
static void add_mul(uint8_t *a,
                    const uint8_t *x, 
                    size_t x_len,
                    const uint8_t *y)
{
    int32_t i, j;
    uint8_t a_bits[128], y_bits[128];
    uint8_t axy_bits[256];
    
    for (i = 0; i < (int)x_len; ++i)
    {
        a[i] ^= x[i];
    }

    /* Performs reflection on (a + x) and y */
    for (i = 0; i < 128; ++i)
    {
        a_bits[i] = (a[i >> 3] >> (7 - (i & 7))) & 1;
        y_bits[i] = (y[i >> 3] >> (7 - (i & 7))) & 1;
    }

    crypto_memzero(axy_bits, sizeof(axy_bits));
    for (i = 0; i < 128; ++i)
    {
        for (j = 0; j < 128; ++j)
        {
            axy_bits[i + j] ^= a_bits[i] & y_bits[j];
        }
    }

    /**
     * Galois field reduction, GF(2^128) is defined 
     * by polynomial x^128 + x^7 + x^2 + 1
     */
    for (i = 127; i >= 0; --i)
    {
        axy_bits[i]       ^= axy_bits[i + 128];
        axy_bits[i +   1] ^= axy_bits[i + 128];
        axy_bits[i +   2] ^= axy_bits[i + 128];
        axy_bits[i +   7] ^= axy_bits[i + 128];
        axy_bits[i + 128] ^= axy_bits[i + 128];
    }

    /* Undo the reflection on the output */
    crypto_memzero(a, 16);
    for (i = 0; i < 128; ++i)
    {
        a[i >> 3] |= (axy_bits[i] << (7 - (i & 7)));
    }
}

static int32_t diff(const uint8_t *x, const uint8_t *y)
{
    uint32_t result = 0;

    result |= x[0] ^ y[0];
    result |= x[1] ^ y[1];
    result |= x[2] ^ y[2];
    result |= x[3] ^ y[3];
    result |= x[4] ^ y[4];
    result |= x[5] ^ y[5];
    result |= x[6] ^ y[6];
    result |= x[7] ^ y[7];
    result |= x[8] ^ y[8];
    result |= x[9] ^ y[9];
    result |= x[10] ^ y[10];
    result |= x[11] ^ y[11];
    result |= x[12] ^ y[12];
    result |= x[13] ^ y[13];
    result |= x[14] ^ y[14];
    result |= x[15] ^ y[15];

    return (1 & ((result - 1) >> 8)) - 1;
}

int32_t aes256gcm_encrypt(uint8_t* c,
                          size_t *c_len,
                          const uint8_t* msg,
                          size_t msg_len,
                          const uint8_t* aad,
                          size_t aad_len,
                          const uint8_t* nonce,
                          const uint8_t* key)
{
    uint8_t H[16];
    uint8_t J[16];
    uint8_t T[16];
    uint8_t Z[16];
    uint8_t accum[16];
    uint8_t stream[16];
    uint8_t final_block[16];
	uint32_t i, index;
    size_t block_len;

    *c_len = msg_len + 16;
    big_endian_store64(final_block, 8 * aad_len);
    big_endian_store64(final_block + 8, 8 * msg_len);

    crypto_memzero(Z, sizeof(Z));
    aes256_bitslice_encrypt(H, Z, key);

    for (i = 0; i < 12; ++i) 
    {
        J[i] = nonce[i];
    }
    index = 1;
    big_endian_store32(J + 12, index);
    aes256_bitslice_encrypt(T, J, key);

    crypto_memzero(accum, sizeof(accum));

    while (aad_len > 0)
    {
        block_len = 16;
        if (aad_len < block_len) 
        {
            block_len = aad_len;
        }
        add_mul(accum, aad, block_len, H);
        aad += block_len;
        aad_len -= block_len;
    }

    while (msg_len > 0)
    {
        block_len = 16;
        if (msg_len < block_len) 
        {
            block_len = msg_len;
        }
        ++index;
        big_endian_store32(J + 12, index);
        aes256_bitslice_encrypt(stream, J, key);
        for (i = 0; i < block_len; ++i)
        {
            c[i] = msg[i] ^ stream[i];
        }
        add_mul(accum, c, block_len, H);
        c += block_len;
        msg += block_len;
        msg_len -= block_len;
    }

    add_mul(accum, final_block, 16, H);
    for (i = 0; i < 16; ++i)
    {
        c[i] = T[i] ^ accum[i];
    }

    return 0;
}

int32_t aes256gcm_decrypt(uint8_t *msg,
                          size_t *msg_len,
                          const uint8_t *c,
                          size_t c_len,
                          const uint8_t *aad,
                          size_t aad_len,
                          const uint8_t *nonce,
                          const uint8_t *key)
{
    uint8_t H[16];
    uint8_t J[16];
    uint8_t T[16];
    uint8_t Z[16];
    uint8_t accum[16];
    uint8_t stream[16];
    uint8_t final_block[16];
    size_t block_len = 16;
    size_t m_len;
    size_t orig_m_len;
    uint32_t i, index;
    const uint8_t *orig_c;

    if (c_len < 16)
    {
        return -1;
    }
    m_len = c_len - 16;

    big_endian_store64(final_block, 8 * aad_len);
    big_endian_store64(final_block + 8, 8 * m_len);

    crypto_memzero(Z, sizeof(Z));
    aes256_bitslice_encrypt(H, Z, key);

    for (i = 0; i < 12; ++i) 
    {
        J[i] = nonce[i];
    }
    index = 1;
    big_endian_store32(J + 12, index);
    aes256_bitslice_encrypt(T, J, key);

    crypto_memzero(accum, sizeof(accum));

    while (aad_len > 0)
    {
        block_len = 16;
        if (aad_len < block_len) 
        {
            block_len = aad_len;
        }
        add_mul(accum, aad, block_len, H);
        aad += block_len;
        aad_len -= block_len;
    }

    orig_c = c;
    orig_m_len = m_len;
    while (m_len > 0)
    {
        block_len = 16;
        if (m_len < block_len) 
        {
            block_len = m_len;
        }
        add_mul(accum, c, block_len, H);
        c += block_len;
        m_len -= block_len;
    }

    add_mul(accum, final_block, 16, H);
    for (i = 0; i < 16; ++i) 
    {
        accum[i] ^= T[i];
    }
    
    /* Compare GCM tag */
    if (diff(accum, c) != 0) 
    {
        return -1;
    }

    c = orig_c;
    m_len = orig_m_len;
    *msg_len = m_len;

    while (m_len > 0)
    {
        block_len = 16;
        if (m_len < block_len)
        {
            block_len = m_len;
        }
        ++index;
        big_endian_store32(J + 12, index);
        aes256_bitslice_encrypt(stream, J, key);
        for (i = 0; i < block_len; ++i)
        {
            msg[i] = c[i] ^ stream[i];
        }
        c += block_len;
        msg += block_len;
        m_len -= block_len;
    }

    return 0;
}
