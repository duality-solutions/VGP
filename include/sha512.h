#ifndef _SHA512_H
#define _SHA512_H

#include <stdint.h>
#include <stddef.h>

#define SHA512_DIGEST_SIZE      64

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generates the SHA512 hash of an input block of
 * {@code in_len} bytes.
 * 
 * @param out the pointer to the output hash value 
 * @param in the input for the hash function
 * @param in_len the size of the input block in bytes
 */
void sha512(uint8_t* out,
            const uint8_t* in,
            size_t in_len);

#ifdef __cplusplus
}
#endif

#endif
