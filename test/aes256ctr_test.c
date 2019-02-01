/**
 * 256-bit AES-CTR
 * NIST test vectors 
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "rand.h"
#include "aes256ctr.h"
#include "utils.h"

typedef struct
{
    const char *plaintext_hex;
    const char *ciphertext_hex;
    const char *key_hex;
    const char *iv_hex;
} aes256ctr_test_vector;

static aes256ctr_test_vector nist_test_vectors[] = 
{
    {
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    }
};

static uint8_t test_seed[] = {
    0xf5, 0x63, 0x30, 0x61, 0x34, 0x74, 0x68, 0x8c,
    0x88, 0xbc, 0x28, 0x2f, 0x83, 0xc5, 0xca, 0x25,
    0x71, 0xb4, 0xf3, 0xa3, 0x22, 0x7d, 0xaa, 0xa3,
    0x85, 0x2b, 0xad, 0xc0, 0xba, 0x34, 0x06, 0x8a
};

static int32_t prepare_encryption(uint8_t **plaintext, 
                                  size_t *plaintext_hex_size,
                                  uint8_t **ciphertext,
                                  uint8_t *key,
                                  uint8_t *iv,
                                  const aes256ctr_test_vector *test_vector)
{
    *plaintext_hex_size = strlen(test_vector->plaintext_hex);
    *plaintext = calloc(*plaintext_hex_size/2, sizeof(uint8_t));
    if (*plaintext == NULL)
    {
        return -1;
    }        
    if (0 != hex_string_to_byte_array(*plaintext, test_vector->plaintext_hex))
    {
        return -1;
    }

    if (0 != hex_string_to_byte_array(key, test_vector->key_hex))
    {
        return -1;
    }
    if (0 != hex_string_to_byte_array(iv, test_vector->iv_hex))
    {
        return -1;
    }

    *ciphertext = calloc(*plaintext_hex_size / 2, sizeof(uint8_t));
    if (*ciphertext == NULL)
    {
        return -1;
    }
    return 0;
}

static int32_t prepare_decryption(uint8_t **decrypted,
                                  char **ciphertext_hex,
                                  const uint8_t *ciphertext,
                                  const size_t ciphertext_size,
                                  const aes256ctr_test_vector *test_vector)
{
    *ciphertext_hex = calloc(2*ciphertext_size + 1, sizeof(char));
    if (*ciphertext_hex == NULL)
    {
        return -1;
    }
    if (0 != byte_array_to_hex_string(*ciphertext_hex, ciphertext, ciphertext_size))
    {
        return -1;
    }
    if (strcmp(*ciphertext_hex, test_vector->ciphertext_hex) != 0)
    {
        return -2;
    }
    *decrypted = calloc(ciphertext_size,
                        sizeof(uint8_t));
    if (*decrypted == NULL)
    {
        return -1;
    }
    return 0;
}

bool aes256ctr_nist_positive_test()
{
    int32_t count = 0;
    bool result = true;
    size_t plaintext_hex_size;
    size_t decrypted_size;
    size_t ciphertext_size;
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *decrypted = NULL;
    uint8_t key[AES256CTR_KEY_SIZE];
    uint8_t iv[AES256CTR_IV_SIZE];
    char *ciphertext_hex = NULL;
    const aes256ctr_test_vector *ptr = NULL;

    for (count = 0;
         result && 
         count < (int)(sizeof(nist_test_vectors) / sizeof(aes256ctr_test_vector));
         count++)
    {
        result = false;
        ptr = &nist_test_vectors[count];

        if (prepare_encryption(&plaintext,
                               &plaintext_hex_size,
                               &ciphertext,
                               key,
                               iv,
                               ptr) != 0)
        {
            goto bail_test;            
        }

        if (0 != aes256ctr_encrypt(ciphertext,
                                   &ciphertext_size,
                                   plaintext,
                                   plaintext_hex_size / 2,
                                   iv,
                                   key))
        {
            goto bail_test;
        }

        if (prepare_decryption(&decrypted,
                               &ciphertext_hex,
                               ciphertext,
                               ciphertext_size,
                               ptr))
        {
            goto bail_test;
        }

        if (0 != aes256ctr_decrypt(decrypted,
                                   &decrypted_size, 
                                   ciphertext, 
                                   ciphertext_size, 
                                   iv, 
                                   key))
        {
            goto bail_test;
        }

        result = memcmp(decrypted, plaintext, decrypted_size) == 0;
bail_test:
        if (ciphertext_hex != NULL)
        {
            free(ciphertext_hex);
            ciphertext_hex = NULL;
        }
        if (decrypted != NULL)
        {
            free(decrypted);
            decrypted = NULL;
        }
        if (ciphertext != NULL)
        {
            free(ciphertext);
            ciphertext = NULL;
        }
        if (plaintext != NULL)
        {
            free(plaintext);
            plaintext = NULL;
        }
    }

    return result;
}

bool aes256ctr_random_test(int32_t iterations)
{
    int32_t it;
    bool status = true;
    uint16_t plaintext_size = 0;
    size_t ciphertext_size = 0;
    size_t decrypted_size = 0; 
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *decrypted = NULL;
    uint8_t key[AES256CTR_KEY_SIZE];
    uint8_t iv[AES256CTR_IV_SIZE];

    bdap_randominit(test_seed, sizeof(test_seed));

    for (it=0; it<iterations && status; it++)
    {
        status = false;
        bdap_randombytes(key, sizeof(key));
        bdap_randombytes(iv, sizeof(iv));

        bdap_randombytes((uint8_t *)&plaintext_size,
                         sizeof(plaintext_size));
        if (!(plaintext = calloc(plaintext_size, sizeof(uint8_t))))
        {
            goto bail_random_test;
        }
        plaintext_size &= 0x0FFF;
        bdap_randombytes(plaintext, plaintext_size);

        if (!(ciphertext = calloc(plaintext_size, sizeof(uint8_t))))
        {
            goto bail_random_test;
        }

        if (0 != aes256ctr_encrypt(ciphertext,
                                   &ciphertext_size,
                                   plaintext,
                                   (size_t) plaintext_size, 
                                   iv, 
                                   key))
        {
            goto bail_random_test;
        }                          

        if (!(decrypted = calloc(plaintext_size, sizeof(uint8_t))))
        {
            goto bail_random_test;
        }

        if (0 != aes256ctr_decrypt(decrypted,
                                   &decrypted_size,
                                   ciphertext,
                                   ciphertext_size, 
                                   iv, 
                                   key))
        {
            goto bail_random_test;
        }                          

        status = (memcmp(decrypted, plaintext, decrypted_size) == 0);
bail_random_test:
        if (decrypted != NULL)
        {
            free(decrypted);
            decrypted = NULL;
        }
        if (ciphertext != NULL)
        {
            free(ciphertext);
            ciphertext = NULL;
        }
        if (plaintext != NULL)
        {
            free(plaintext);
            plaintext = NULL;
        }
    }

    return status;
}

bool openssl_aes256ctr_random_test(int32_t iterations)
{
    int32_t it;
    bool status = true;
    EVP_CIPHER_CTX *ctx = NULL;
    int32_t openssl_buffer_len;
    int32_t openssl_plaintext_len;
    int32_t openssl_ciphertext_len;
    uint16_t plaintext_size = 0;
    size_t ciphertext_size = 0;
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *openssl_ciphertext = NULL;
    uint8_t key[AES256CTR_KEY_SIZE];
    uint8_t iv[AES256CTR_IV_SIZE];

    bdap_randominit(test_seed, sizeof(test_seed));

    for (it=0; it<iterations && status; it++)
    {
        status = false;
        bdap_randombytes(key, sizeof(key));
        bdap_randombytes(iv, sizeof(iv));

        bdap_randombytes((uint8_t *)&plaintext_size,
                         sizeof(plaintext_size));
        if (!(plaintext = calloc(plaintext_size, sizeof(uint8_t))))
        {
            goto bail_openssl_test;
        }
        plaintext_size &= 0x0FFF;
        bdap_randombytes(plaintext, plaintext_size);

        if (!(ciphertext = calloc(plaintext_size, sizeof(uint8_t))))
        {
            goto bail_openssl_test;
        }

        if (0 != aes256ctr_encrypt(ciphertext,
                                   &ciphertext_size,
                                   plaintext,
                                   (size_t) plaintext_size, 
                                   iv, 
                                   key))
        {
            goto bail_openssl_test;
        }                          

        /* set up to Encrypt AES 256 CTR */
        if (!(ctx = EVP_CIPHER_CTX_new()))
        {
            goto bail_openssl_test;
        }
        
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
        {
            goto bail_openssl_test;
        }
        
        /* perform encryption */
        openssl_plaintext_len = plaintext_size;
        if (!(openssl_ciphertext = calloc(openssl_plaintext_len, sizeof(uint8_t))))
        {
            goto bail_openssl_test;
        }
        if (1 != EVP_EncryptUpdate(ctx,
                                   openssl_ciphertext,
                                   &openssl_buffer_len,
                                   plaintext,
                                   openssl_plaintext_len))
        {
            goto bail_openssl_test;
        }
        openssl_ciphertext_len = openssl_buffer_len;

        /* finalise the encryption, additional ciphertext bytes may be written at this stage */
        if (1 != EVP_EncryptFinal_ex(ctx,
                                     openssl_ciphertext + openssl_buffer_len,
                                     &openssl_buffer_len))
        {
            goto bail_openssl_test;
        }
        openssl_ciphertext_len += openssl_buffer_len;

        status = (openssl_ciphertext_len == (int)ciphertext_size) &&
                 (memcmp(ciphertext, openssl_ciphertext, ciphertext_size) == 0);
bail_openssl_test:
        /* Clean up */
        if (ctx)
        {
            EVP_CIPHER_CTX_free(ctx);
            ctx = NULL;
        }
        if (openssl_ciphertext != NULL)
        {
            free(openssl_ciphertext);
            openssl_ciphertext = NULL;
        }
        if (ciphertext != NULL)
        {
            free(ciphertext);
            ciphertext = NULL;
        }
        if (plaintext != NULL)
        {
            free(plaintext);
            plaintext = NULL;
        }
    }

    return status;
}
