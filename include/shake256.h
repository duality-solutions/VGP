#ifndef _KECCAK_SHAKE256_H
#define _KECCAK_SHAKE256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief FIPS-202 SHAKE-256 extandable output function (XOF).
 * 
 * @param out the output buffer 
 * @param out_len the expected output length in bytes
 * @param in the input buffer
 * @param in_len the length of input buffer in bytes
 * @return 0 on success, non-zero otherwise
 */
int32_t shake256(uint8_t* out,
                 size_t out_len,
                 const uint8_t *in,
                 size_t in_len);

#ifdef __cplusplus
}
#endif

#endif
