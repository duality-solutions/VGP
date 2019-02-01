#ifndef _AES256_GCM_H
#define _AES256_GCM_H

#include <stdint.h>
#include <stddef.h>

#define AES256GCM_KEY_SIZE      32
#define AES256GCM_NONCE_SIZE    12
#define AES256GCM_TAG_SIZE      16

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief AES-256 GCM with 16-byte tag encrypt method.
 * 
 * @param c The pointer to the output ciphertext
 * @param c_len The pointer to the ciphertext size in bytes
 * @param msg The pointer to the input plaintext message
 * @param msg_len The size of the plaintext message in bytes
 * @param aad The pointer to the AAD
 * @param aad_len The size of the AAD in bytes
 * @param nonce The pointer to the nonce, 12 bytes
 * @param key The pointer to the encryption key, 32 bytes
 * @return 0 on success, non-zero otherwise
 */
int32_t aes256gcm_encrypt(uint8_t* c,
                          size_t *c_len,
                          const uint8_t* msg,
                          size_t msg_len,
                          const uint8_t* aad,
                          size_t aad_len, 
                          const uint8_t* nonce,
                          const uint8_t* key);

/**
 * @brief AES-256 GCM with 16-byte tag decrypt method.
 * 
 * @param msg The pointer to the output plaintext message
 * @param msg_len The pointer to the plaintext size in bytes
 * @param c The pointer to the input ciphertext
 * @param c_len The size of ciphertext in bytes
 * @param aad The pointer to the AAD
 * @param aad_len The size of the AAD in bytes
 * @param nonce The pointer to the nonce, 12 bytes
 * @param key The pointer to the encryption key, 32 bytes
 * @return 0 on success, non-zero otherwise
 */
int32_t aes256gcm_decrypt(uint8_t *msg,
                          size_t *msg_len,
                          const uint8_t *c,
                          size_t c_len,
                          const uint8_t *aad,
                          size_t aad_len,
                          const uint8_t *nonce,
                          const uint8_t *key);

#ifdef __cplusplus
}
#endif

#endif
