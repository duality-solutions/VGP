#include "aes256ctr.h"
#include "aes256.h"
#include "utils.h"

static inline uint8_t ct_eq_ff(uint8_t u)
{
    uint8_t v = u ^ (uint8_t)0xff;
    return ((uint8_t)(v | -v) >> 7) ^ 0x01;
}

/**
 * @brief Increment counter.
 * 
 * The counter wraps around if it exceeds maximum value.
 * 
 * @param ctr a 16-byte array of counter in big-endian
 */
static void increment_counter(uint8_t *ctr)
{
    uint8_t value, carry;

    value   = 0x01;
    carry   = ct_eq_ff(ctr[15]);
    ctr[15] = ctr[15] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[14]);
    ctr[14] = ctr[14] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[13]);
    ctr[13] = ctr[13] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[12]);
    ctr[12] = ctr[12] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[11]);
    ctr[11] = ctr[11] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[10]);
    ctr[10] = ctr[10] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[ 9]);
    ctr[ 9] = ctr[ 9] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[ 8]);
    ctr[ 8] = ctr[ 8] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[ 7]);
    ctr[ 7] = ctr[ 7] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[ 6]);
    ctr[ 6] = ctr[ 6] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[ 5]);
    ctr[ 5] = ctr[ 5] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[ 4]);
    ctr[ 4] = ctr[ 4] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[ 3]);
    ctr[ 3] = ctr[ 3] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[ 2]);
    ctr[ 2] = ctr[ 2] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[ 1]);
    ctr[ 1] = ctr[ 1] + value;

    value   = carry;
    carry  &= ct_eq_ff(ctr[ 0]);
    ctr[ 0] = ctr[ 0] + value;
}

int32_t aes256ctr_encrypt(uint8_t *c,
                          size_t *c_len,
                          const uint8_t *msg,
                          size_t msg_len,
                          const uint8_t *iv,
                          const uint8_t *key)
{
    uint8_t T[AES256CTR_IV_SIZE];
    uint8_t stream[16];
    size_t i, block_len;

    for (i = 0; i < AES256CTR_IV_SIZE; i++)
    {
        T[i] = iv[i];
    }

    *c_len = msg_len;
    while (msg_len > 0)
    {
        block_len = 16;
        if (msg_len < block_len) 
        {
            block_len = msg_len;
        }
        
        aes256_bitslice_encrypt(stream, T, key);

        for (i = 0; i < block_len; ++i)
        {
            c[i] = msg[i] ^ stream[i];
        }

        c += block_len;
        msg += block_len;
        msg_len -= block_len;

        increment_counter(T);
    }

    crypto_memzero(T, AES256CTR_IV_SIZE);
    crypto_memzero(stream, sizeof(stream));

    return 0;
}                      
int32_t aes256ctr_decrypt(uint8_t *msg,
                          size_t *msg_len,
                          const uint8_t *c,
                          size_t c_len,
                          const uint8_t *iv,
                          const uint8_t *key)
{
    return aes256ctr_encrypt(msg, msg_len, c, c_len, iv, key);
}                      
