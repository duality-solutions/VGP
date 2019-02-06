// Copyright (c) 2018-2019 Duality Blockchain Solutions Developers
// See LICENSE.md file for license, copying and use information.

#ifndef _ENCRYPTION_CORE_H
#define _ENCRYPTION_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Computes the ciphertext size in bytes for a given
 * number of recipients and plaintext size in bytes.
 * 
 * @param num_recipients the number of recipients
 * @param plaintext_size the plaintext size in bytes
 * @return BDAP ciphertext size
 */
size_t bdap_ciphertext_size(const uint16_t num_recipients,
                            const size_t plaintext_size);

/**
 * @brief Given a ciphertext of a given size, computes the
 * expected decrypted plaintext size.
 * 
 * @param ciphertext the ciphertext
 * @param ciphertext_size the ciphertext size in bytes
 * @return the expected plaintext size in bytes
 */
size_t bdap_decrypted_size(const uint8_t *ciphertext,
                           const size_t ciphertext_size);

/**
 * @brief Performs BDAP end-to-end encryption on a piece of
 * plaintext for a group of recipients.
 * 
 * @note Each recipient provides their Ed25519 public-key,
 * which is 32 bytes in size.
 * 
 * @note The size of the ciphertext can be obtained from
 * bdap_ciphertext_size(const uint16_t, const size_t) function.
 * 
 * @note The caller of this method does not need to allocate
 * and deallocate memory for error messages. This method returns
 * a pointer to a pre-defined string. The parameter {@code
 * error_message} can also be NULL, which means that the caller
 * doesn't want any error messages.
 * 
 * @param ciphertext the output ciphertext pointer
 * @param ciphertext_size the size of the ciphertext in bytes
 * @param num_recipients the number of recipients
 * @param ed25519_public_key the pointer to an array of
 *                           recipient's public-keys
 * @param plaintext the input plaintext pointer
 * @param plaintext_size the plaintext size in bytes
 * @param error_message the pointer to the error message
 *                      in the event of error
 * @return true on success
 * @return false otherwise
 */
bool bdap_encrypt(uint8_t* ciphertext,
                  const uint16_t num_recipients,
                  const uint8_t** ed25519_public_key,
                  const uint8_t* plaintext,
                  const size_t plaintext_size,
                  const char** error_message);

/**
 * @brief Performs BDAP end-to-end decryption on a piece of
 * ciphertext.
 * 
 * @note In order to perform decryption, an Ed25519 private-key
 * is required. The standard Ed25519 private key consists of
 * 32 bytes seed and 32 bytes public-key. This method requires
 * only the first 32 bytes seed of the private-key.
 * 
 * @note The expected size of the plaintext can be obtained from
 * bdap_decrypted_size(const uint8_t*, const size_t) function.
 *
 * @note The caller of this method does not need to allocate
 * and deallocate memory for error messages. This method returns
 * a pointer to a pre-defined string. The parameter {@code
 * error_message} can also be NULL, which means that the caller
 * doesn't want any error messages.
 * 
 * @param plaintext the output plaintext pointer 
 * @param plaintext_size the output plaintext size in bytes
 * @param ed25519_private_key_seed the pointer to the decryption
 *                                 private-key seed
 * @param ciphertext the input ciphertext pointer
 * @param ciphertext_size the ciphertext size in bytes
 * @param error_message the pointer to the error message
 *                      in the event of error
 * @return true on success
 * @return false otherwise
 */
bool bdap_decrypt(uint8_t* plaintext,
                  const uint8_t* ed25519_private_key_seed,
                  const uint8_t* ciphertext,
                  const size_t ciphertext_size,
                  const char** error_message);

#ifdef __cplusplus
}
#endif

#endif // _ENCRYPTION_CORE_H
