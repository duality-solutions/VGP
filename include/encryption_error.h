// Copyright (c) 2018-2019 Duality Blockchain Solutions Developers
// See LICENSE.md file for license, copying and use information.

#ifndef _ENCRYPTION_ERROR_H
#define _ENCRYPTION_ERROR_H

#define BDAP_SUCCESS                                0
#define BDAP_UNKNOWN_ERROR                          1
#define BDAP_ED25519_TO_X25519_PUBLIC_KEY_FAILED    2
#define BDAP_X25519_PUBLIC_KEY_DERIVATION_FAILED    3
#define BDAP_X25519_KEYPAIR_FAILED                  4
#define BDAP_X25519_DH_FAILED                       5
#define BDAP_AESCTR_KEY_DERIVATION_FAILED           6
#define BDAP_AESGCM_KEY_DERIVATION_FAILED           7
#define BDAP_AESCTR_ENCRYPT_FAILED                  8
#define BDAP_AESCTR_DECRYPT_FAILED                  9
#define BDAP_AESGCM_ENCRYPT_FAILED                  10
#define BDAP_AESGCM_DECRYPT_FAILED                  11
#define BDAP_NO_VALID_RECIPIENT                     12
#define BDAP_MEMORY_PROTECTION_FAILED               13

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief This array contains the actual error messages
 * for the above error codes.
 * 
 * @note For each error-code, there is a corresponding
 * error_message string. If a new error message needs
 * to be added, add a new error code in the above
 * #define macro and add the respective error message
 * in {@code bdap_error_message} array.
 */
extern const char* bdap_error_message[];

#ifdef __cplusplus
}
#endif

#endif // _ENCRYPTION_ERROR_H
