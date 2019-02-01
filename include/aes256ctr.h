#ifndef _AES256CTR_H
#define _AES256CTR_H

#include <stdint.h>
#include <stddef.h>

#define AES256CTR_KEY_SIZE      32
#define AES256CTR_IV_SIZE       16

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief AES-256 CTR encrypt method.
 * 
 * @param c The pointer to the output ciphertext
 * @param c_len The pointer to the size of the ciphertext in bytes
 * @param msg The pointer to the input plaintext message
 * @param msg_len The size of the plaintext message in bytes
 * @param iv The initialisation vector, 16 bytes
 * @param key The encryption key, 32 bytes
 * @return 0 on success, non-zero otherwise
 */
int32_t aes256ctr_encrypt(uint8_t *c,
                          size_t *c_len,
                          const uint8_t *msg,
                          size_t msg_len,
                          const uint8_t *iv,
                          const uint8_t *key);

/**
 * @brief AES-256 CTR decrypt method.
 * 
 * @param msg The pointer to the output plaintext message
 * @param msg_len The pointer to the size of the plaintext in bytes
 * @param c The pointer to the input ciphertext
 * @param c_len The size of the ciphertext in bytes
 * @param iv The initialisation vector, 16 bytes
 * @param key The encryption key, 32 bytes
 * @return 0 on success, non-zero otherwise
 */
int32_t aes256ctr_decrypt(uint8_t *msg,
                          size_t *msg_len,
                          const uint8_t *c,
                          size_t c_len,
                          const uint8_t *iv,
                          const uint8_t *key);

#ifdef __cplusplus
}
#endif

#endif
