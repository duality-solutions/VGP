#include <string.h>
#include "encryption_core.h"
#include "encryption_error.h"
#include "ed25519.h"
#include "curve25519.h"
#include "aes256ctr.h"
#include "aes256gcm.h"
#include "shake256.h"
#include "rand.h"
#include "utils.h"

#define FINGERPRINT_SIZE    7
#define SECRET_SIZE         32
#define BUF_SIZE            3*CURVE25519_PUBLIC_KEY_SIZE
#define KEY_IV_SIZE         AES256CTR_KEY_SIZE + AES256CTR_IV_SIZE
#define KEY_NONCE_SIZE      AES256GCM_KEY_SIZE + AES256GCM_NONCE_SIZE

static uint16_t bdap_ciphertext_number_of_recipients(
    const uint8_t* ciphertext)
{
    return (uint16_t)(ciphertext[0] + 256 * ciphertext[1]);
}

static size_t bdap_ciphertext_header_size(const uint16_t num_recipients)
{
    return sizeof(num_recipients) + CURVE25519_PUBLIC_KEY_SIZE
        + num_recipients * (FINGERPRINT_SIZE + SECRET_SIZE);
}

static bool bdap_get_ephemeral_public_key_and_encrypted_secret(
    uint8_t* ephemeral_public_key,
    uint8_t* encrypted_secret,
    const uint8_t* ciphertext,
    const uint8_t* ed25519_public_key)
{
    uint16_t i, num_recipients = 0;
    const uint8_t *ptr = ciphertext;
    const uint8_t *fingerprint = ed25519_public_key;

    /* N */
    num_recipients = (uint16_t)(ptr[0] + 256 * ptr[1]);
    ptr += 2;

    /* U */
    memcpy(ephemeral_public_key, ptr, CURVE25519_PUBLIC_KEY_SIZE);
    ptr += CURVE25519_PUBLIC_KEY_SIZE;

    /* | f_i | c_i | */
    for (i = 0; i < num_recipients; ++i)
    {
        if (crypto_is_memequal(fingerprint, ptr, FINGERPRINT_SIZE))
        {
            memcpy(encrypted_secret, ptr + FINGERPRINT_SIZE, SECRET_SIZE);
            return true;
        }

        ptr += (FINGERPRINT_SIZE + SECRET_SIZE);
    }

    crypto_memzero(ephemeral_public_key, CURVE25519_PUBLIC_KEY_SIZE);

    return false;
}

/**
 * @brief Computes the ciphertext size in bytes for a given
 * number of recipients and plaintext size in bytes.
 * 
 * @param num_recipients the number of recipients
 * @param plaintext_size the plaintext size in bytes
 * @return BDAP ciphertext size
 */
size_t bdap_ciphertext_size(const uint16_t num_recipients,
                            const size_t plaintext_size)
{
    return bdap_ciphertext_header_size(num_recipients)
                + plaintext_size + AES256GCM_TAG_SIZE;
}

/**
 * @brief Given a ciphertext of a given size, computes the
 * expected decrypted plaintext size.
 * 
 * @param ciphertext the ciphertext
 * @param ciphertext_size the ciphertext size in bytes
 * @return the expected plaintext size in bytes
 */
size_t bdap_decrypted_size(const uint8_t *ciphertext,
                           const size_t ciphertext_size)
{
    uint16_t num_recipients = 
        bdap_ciphertext_number_of_recipients(ciphertext);
    return ciphertext_size
                - bdap_ciphertext_header_size(num_recipients)
                - AES256GCM_TAG_SIZE;
}

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
                  const char** error_message)
{
    bool result = true;
    uint16_t idx, error_code = BDAP_SUCCESS;
    uint8_t *c_ptr = ciphertext;
    uint8_t ephemeral_pk[CURVE25519_PUBLIC_KEY_SIZE] = {0};
    uint8_t ephemeral_sk[CURVE25519_PRIVATE_KEY_SIZE] = {0};
    uint8_t s[SECRET_SIZE] = {0};
    uint8_t curve25519_pk[CURVE25519_PUBLIC_KEY_SIZE] = {0};
    uint8_t Q[CURVE25519_POINT_SIZE] = {0};
    uint8_t buf[BUF_SIZE] = {0};
    uint8_t key_iv[KEY_IV_SIZE] = {0};
    uint8_t key_nonce[KEY_NONCE_SIZE] = {0};
    uint8_t c[SECRET_SIZE] = {0};
    size_t unused, ciphertext_size;

    ciphertext_size = bdap_ciphertext_size(num_recipients, plaintext_size);

    /* Write N, the number of recipients */
    *c_ptr++ = (uint8_t) num_recipients;
    *c_ptr++ = (uint8_t)(num_recipients >> 8);

    /* 1. Generate an ephemeral Curve25519 keypair */
    if (true != curve25519_random_keypair(ephemeral_pk, ephemeral_sk))
    {
        result = false;
        error_code = BDAP_X25519_KEYPAIR_FAILED;
        goto bdap_e2e_encrypt_bail;
    }
    memcpy(c_ptr, ephemeral_pk, sizeof(ephemeral_pk));
    c_ptr += sizeof(ephemeral_pk);

    /* 2. Generate a random 32-byte secret */
    bdap_randombytes(s, sizeof(s));

    for (idx = 0; idx < num_recipients; ++idx)
    {
        /* 3a. Derive Curve25519 public-key from Ed25519 public-key */
        if (0 != ed25519_to_curve25519_public_key(curve25519_pk,
                                                  ed25519_public_key[idx]))
        {
            result = false;
            error_code = BDAP_ED25519_TO_X25519_PUBLIC_KEY_FAILED;
            crypto_memzero(ciphertext, ciphertext_size);
            goto bdap_e2e_encrypt_bail;
        }                                          

        /* 3b. Curve25519 Diffie-Hellman exchange */
        if (curve25519_dh(Q, ephemeral_sk, curve25519_pk) == false)
        {
            result = false;
            error_code = BDAP_X25519_DH_FAILED;
            crypto_memzero(ciphertext, ciphertext_size);
            goto bdap_e2e_encrypt_bail;
        }

        /* 3c. XOF(Q | curve25519_public_key | ephemeral_pk, 48) */
        memcpy(buf, Q, sizeof(Q));
        memcpy(buf + CURVE25519_PUBLIC_KEY_SIZE,
               curve25519_pk,
               CURVE25519_PUBLIC_KEY_SIZE);
        memcpy(buf + 2*CURVE25519_PUBLIC_KEY_SIZE,
               ephemeral_pk,
               sizeof(ephemeral_pk));
        if (0 != shake256(key_iv, KEY_IV_SIZE, buf, BUF_SIZE))
        {
            result = false;
            error_code = BDAP_AESCTR_KEY_DERIVATION_FAILED;
            crypto_memzero(ciphertext, ciphertext_size);
            goto bdap_e2e_encrypt_bail;
        }

        /* 3d. AESCTR_E(key, iv, s) -> c */
        if (aes256ctr_encrypt(c,
                              &unused,
                              s,
                              sizeof(s),
                              &key_iv[AES256CTR_KEY_SIZE],
                              key_iv) != 0)
        {
            result = false;
            error_code = BDAP_AESCTR_ENCRYPT_FAILED;
            crypto_memzero(ciphertext, ciphertext_size);
            goto bdap_e2e_encrypt_bail;
        }

        /* Write fingerprint and encrypted secret pair */
        memcpy(c_ptr, ed25519_public_key[idx], FINGERPRINT_SIZE);
        c_ptr += FINGERPRINT_SIZE;
        memcpy(c_ptr, c, sizeof(c));
        c_ptr += sizeof(c);
    }

    /* 4. XOF(s, 44) */
    crypto_memzero(buf, sizeof(buf));
    if (0 != shake256(key_nonce, KEY_NONCE_SIZE, s, sizeof(s)))
    {
        result = false;
        error_code = BDAP_AESGCM_KEY_DERIVATION_FAILED;
        crypto_memzero(ciphertext, ciphertext_size);
        goto bdap_e2e_encrypt_bail;
    }

    /* 5. AESGCM_E(key, nonce, plaintext) */
    result = (aes256gcm_encrypt(c_ptr,
                                &unused,
                                plaintext,
                                plaintext_size,
                                NULL,
                                0,
                                &key_nonce[AES256GCM_KEY_SIZE],
                                key_nonce) == 0);
    if (true != result)
    {
        error_code = BDAP_AESGCM_ENCRYPT_FAILED;
        crypto_memzero(ciphertext, ciphertext_size);
    }

bdap_e2e_encrypt_bail:
    crypto_memzero(s, sizeof(s));
    crypto_memzero(key_iv, sizeof(key_iv));
    crypto_memzero(key_nonce, sizeof(key_nonce));
    crypto_memzero(ephemeral_sk, sizeof(ephemeral_sk));
    crypto_memzero(ephemeral_pk, sizeof(ephemeral_pk));
    crypto_memzero(curve25519_pk, CURVE25519_PUBLIC_KEY_SIZE);
    crypto_memzero(c, sizeof(c));
    crypto_memzero(Q, sizeof(Q));
    crypto_memzero(buf, sizeof(buf));
    if (error_message != NULL)
    {
        *error_message = bdap_error_message[error_code];
    }

    return result;
}

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
                  const char** error_message)
{
    bool result = false;
    size_t unused;
    size_t ciphertext_header_size;
    uint16_t num_recipients = 0;
    uint16_t error_code = BDAP_SUCCESS;
    uint8_t curve25519_sk[CURVE25519_PRIVATE_KEY_SIZE] = {0};
    uint8_t curve25519_pk[CURVE25519_PUBLIC_KEY_SIZE] = {0};
    uint8_t curve25519_ephemeral_pk[CURVE25519_PUBLIC_KEY_SIZE] = {0};
    uint8_t ed25519_pk[ED25519_PUBLIC_KEY_SIZE] = {0};
    uint8_t Q[CURVE25519_POINT_SIZE] = {0};
    uint8_t c[SECRET_SIZE] = {0};
    uint8_t s[SECRET_SIZE] = {0};
    uint8_t buf[BUF_SIZE] = {0};
    uint8_t key_iv[KEY_IV_SIZE] = {0};
    uint8_t key_nonce[KEY_NONCE_SIZE] = {0};
    const uint8_t* c_ptr = ciphertext;

    if (!crypto_mlock((void*)ed25519_private_key_seed,
                      ED25519_PRIVATE_KEY_SEED_SIZE) ||
        !crypto_mlock(curve25519_sk, CURVE25519_PRIVATE_KEY_SIZE))
    {
        error_code = BDAP_MEMORY_PROTECTION_FAILED;
        return false;
    }

    /* 2. Compute Ed25519 public-key from private-key seed */
    ed25519_public_key_from_private_key_seed(ed25519_pk, ed25519_private_key_seed);

    /* 1. Parse the input ciphertext */
    /* 3. Search through the fingerprint and encrypted secret pair */
    /*    to obtain one where the fingerprint matches */
    /* 4. Abort if not found */
    result = bdap_get_ephemeral_public_key_and_encrypted_secret(
        curve25519_ephemeral_pk, c, c_ptr, ed25519_pk);
    if (true != result)
    {
        error_code = BDAP_NO_VALID_RECIPIENT;
        goto bdap_e2e_decrypt_bail;
    }

    /* 5. Derive Curve25519 private-key from Ed25519 private-key seed */
    ed25519_to_curve25519_private_key(curve25519_sk,
                                      ed25519_private_key_seed);

    /* 6. Compute Curve25519 public-key from the private-key */
    result = curve25519_public_key_from_private_key(
        curve25519_pk, curve25519_sk);
    if (true != result)
    {
        error_code = BDAP_X25519_PUBLIC_KEY_DERIVATION_FAILED;
        goto bdap_e2e_decrypt_bail;
    }

    /* 7. Curve25519 Diffie-Hellman exchange */
    result = curve25519_dh(Q, curve25519_sk, curve25519_ephemeral_pk);
    if (true != result)
    {
        error_code = BDAP_X25519_DH_FAILED;
        goto bdap_e2e_decrypt_bail;
    }

    /* 8. XOF(Q | curve25519_pk | curve25519_ephemeral_pk, 48) */
    memcpy(buf, Q, sizeof(Q));
    memcpy(buf + CURVE25519_PUBLIC_KEY_SIZE,
            curve25519_pk,
            CURVE25519_PUBLIC_KEY_SIZE);
    memcpy(buf + 2*CURVE25519_PUBLIC_KEY_SIZE,
            curve25519_ephemeral_pk,
            sizeof(curve25519_ephemeral_pk));
    result = (0 == shake256(key_iv, KEY_IV_SIZE, buf, BUF_SIZE));
    if (true != result)
    {
        error_code = BDAP_AESCTR_KEY_DERIVATION_FAILED;
        goto bdap_e2e_decrypt_bail;
    }

    /* 9. AESCTR_D(key, iv, c) -> s */
    if (aes256ctr_decrypt(s,
                          &unused,
                          c,
                          sizeof(c),
                          &key_iv[AES256CTR_KEY_SIZE],
                          key_iv) != 0)
    {
        result = false;
        error_code = BDAP_AESCTR_DECRYPT_FAILED;
        goto bdap_e2e_decrypt_bail;
    }

    /* 10. XOF(s, 44) */
    crypto_memzero(buf, sizeof(buf));
    result = (0 == shake256(key_nonce, KEY_NONCE_SIZE, s, sizeof(s)));
    if (true != result)
    {
        error_code = BDAP_AESGCM_KEY_DERIVATION_FAILED;
        goto bdap_e2e_decrypt_bail;
    }

    /* 11. AESGCM_D(key, nonce, ciphertext) */
    num_recipients = bdap_ciphertext_number_of_recipients(ciphertext);
    ciphertext_header_size = bdap_ciphertext_header_size(num_recipients);
    c_ptr += ciphertext_header_size;

    result = (aes256gcm_decrypt(plaintext,
                                &unused,
                                c_ptr,
                                ciphertext_size - ciphertext_header_size,
                                NULL,
                                0,
                                &key_nonce[AES256GCM_KEY_SIZE],
                                key_nonce) == 0);
    if (true != result)
    {
        error_code = BDAP_AESGCM_DECRYPT_FAILED;
    }
bdap_e2e_decrypt_bail:
    (void)crypto_munlock((void*)ed25519_private_key_seed,
                         ED25519_PRIVATE_KEY_SEED_SIZE);
    (void)crypto_munlock(curve25519_sk, CURVE25519_PRIVATE_KEY_SIZE);
    crypto_memzero(curve25519_sk, sizeof(curve25519_sk));
    crypto_memzero(curve25519_ephemeral_pk, sizeof(curve25519_ephemeral_pk));
    crypto_memzero(ed25519_pk, sizeof(ed25519_pk));
    crypto_memzero(curve25519_pk, sizeof(curve25519_pk));
    crypto_memzero(s, sizeof(s));
    crypto_memzero(c, sizeof(c));
    crypto_memzero(key_iv, sizeof(key_iv));
    crypto_memzero(key_nonce, sizeof(key_nonce));
    crypto_memzero(Q, sizeof(Q));
    crypto_memzero(buf, sizeof(buf));
    if (error_message != NULL)
    {
        *error_message = bdap_error_message[error_code];
    }

    return result;
}
