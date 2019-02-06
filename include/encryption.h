// Copyright (c) 2018-2019 Duality Blockchain Solutions Developers
// See LICENSE.md file for license, copying and use information.

#ifndef _ENCRYPTION_H
#define _ENCRYPTION_H

#include <string>
#include <vector>

typedef std::vector<uint8_t> CharVector;
typedef std::vector<CharVector> vCharVector;

/**
 * @brief Returns the size of BDAP ciphertext in bytes for given number of recipients
 * and plaintext size in bytes. 
 * 
 * @param numRecipients The number of recipients
 * @param plaintextSize The plaintext size in bytes
 * @return BDAP ciphertext size in bytes
 */
size_t BDAPCiphertextSize(const uint16_t numRecipients, const size_t plaintextSize);

/**
 * @brief Returns the expected size of BDAP decrypted plaintext in bytes for a
 * given BDAP ciphertext.
 * 
 * @param vchCipherText The input BDAP ciphertext
 * @return the expected BDAP decrypted plaintext size in bytes
 */
size_t BDAPExpectedDecryptedSize(const CharVector& vchCipherText);

/**
 * @brief Encrypts a piece of data using BDAP for a set of recipient's public-keys.
 * 
 * @param vchPubKeys The set of recipients Ed25519 public-keys, 32 bytes each
 * @param vchData The input data to be encrypted
 * @param vchCipherText The output ciphertext
 * @param strErrorMessage The string containing error-message in the event of failure
 * @return true on success
 * @return false on failure
 */
bool EncryptBDAPData(const vCharVector& vchPubKeys,
                     const CharVector& vchData,
                     CharVector& vchCipherText,
                     std::string& strErrorMessage);

/**
 * @brief Decrypts a piece of BDAP encrypted ciphertext using a Ed25519 private-key seed.
 * 
 * @param vchPrivKeySeed The Ed25519 private-key seed, 32 bytes
 * @param vchCipherText The input BDAP ciphertext
 * @param vchData The decrypted output
 * @param strErrorMessage The string containing error-message in the event of failure
 * @return true on success
 * @return false on failure
 */
bool DecryptBDAPData(const CharVector& vchPrivKeySeed,
                     const CharVector& vchCipherText,
                     CharVector& vchData,
                     std::string& strErrorMessage);

#endif // _ENCRYPTION_H
