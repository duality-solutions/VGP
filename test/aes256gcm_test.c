/**
 * 256-bit AES-GCM
 * NIST test vectors 
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/evp.h>
#include "aes256gcm.h"
#include "utils.h"

typedef struct
{
    const char *plaintext_hex;
    const char *ciphertext_hex;
    const char *key_hex;
    const char *nonce_hex;
} aes256gcm_test_vector;

/**
 * The following test vectors are from the file gcmEncryptExtIV256.rsp of
 * http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
 * 
 */
static aes256gcm_test_vector nist_test_vectors[] = 
{
    /* Keylen = 256, IVlen = 96, PTlen = 0, AADlen = 0, Taglen = 128 */
    /* Count = 0 */
    {
        "",
        "bdc1ac884d332457a1d2664f168c76f0",
        "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
        "516c33929df5a3284ff463d7"
    },
    /* Count = 1 */
    {
        "",
        "196d691e1047093ca4b3d2ef4baba216",
        "5fe0861cdc2690ce69b3658c7f26f8458eec1c9243c5ba0845305d897e96ca0f",
        "770ac1a5a3d476d5d96944a1"
    },
    /* Count = 2 */
    {
        "",
        "f570c38202d94564bab39f75617bc87a",
        "7620b79b17b21b06d97019aa70e1ca105e1c03d2a0cf8b20b5a0ce5c3903e548",
        "60f56eb7a4b38d4f03395511"
    },
    /* Count = 3 */
    {
        "",
        "db9df5f14f6c9f2ae81fd421412ddbbb",
        "7e2db00321189476d144c5f27e787087302a48b5f7786cd91e93641628c2328b",
        "ea9d525bf01de7b2234b606a"
    },
    /* Keylen = 256, IVlen = 96, PTlen = 128, AADlen = 0, Taglen = 128 */
    /* Count = 0 */
    {
        "2db5168e932556f8089a0622981d017d",
        "fa4362189661d163fcd6a56d8bf0405ad636ac1bbedd5cc3ee727dc2ab4a9489",
        "31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22",
        "0d18e06c7c725ac9e362e1ce"
    },
    /* Count = 1 */
    {
        "99e4e926ffe927f691893fb79a96b067",
        "133fc15751621b5f325c7ff71ce08324ec4e87e0cf74a13618d0b68636ba9fa7",
        "460fc864972261c2560e1eb88761ff1c992b982497bd2ac36c04071cbb8e5d99",
        "8a4a16b9e210eb68bcb6f58d"
    },
    /* Count = 2 */
    {
        "f562509ed139a6bbe7ab545ac616250c",
        "e2f787996e37d3b47294bf7ebba5ee2500f613eee9bdad6c9ee7765db1cb45c0",
        "f78a2ba3c5bd164de134a030ca09e99463ea7e967b92c4b0a0870796480297e5",
        "2bb92fcb726c278a2fa35a88"
    },
    /* Count = 3 */
    {
        "c7afeecec1408ad155b177c2dc7138b0",
        "9432a620e6a22307e06a321d66846fd4e3ea499192f2cd8d3ab3edfc55897415",
        "48e6af212da1386500454c94a201640c2151b28079240e40d72d2a5fd7d54234",
        "ef0ff062220eb817dc2ece94"
    },
    /* Keylen = 256, IVlen = 96, PTlen = 408, AADlen = 0, Taglen = 128 */
    /* Count = 0 */
    {
        "06b2c75853df9aeb17befd33cea81c630b0fc53667ff45199c629c8e15dce41e530aa792f796b8138eeab2e86c7b7bee1d40b0",
        "91fbd061ddc5a7fcc9513fcdfdc9c3a7c5d4d64cedf6a9c24ab8a77c36eefbf1c5dc00bc50121b96456c8cd8b6ff1f8b3e480f30096d340f3d5c42d82a6f475def23eb",
        "1fded32d5999de4a76e0f8082108823aef60417e1896cf4218a2fa90f632ec8a",
        "1f3afa4711e9474f32e70462"
    },
    /* Count = 1 */
    {
        "ab4fd35bef66addfd2856b3881ff2c74fdc09c82abe339f49736d69b2bd0a71a6b4fe8fc53f50f8b7d6d6d6138ab442c7f653f",
        "69a079bca9a6a26707bbfa7fd83d5d091edc88a7f7ff08bd8656d8f2c92144ff23400fcb5c370b596ad6711f386e18f2629e766d2b7861a3c59ba5a3e3a11c92bb2b14",
        "b405ac89724f8b555bfee1eaa369cd854003e9fae415f28c5a199d4d6efc83d6",
        "cec71a13b14c4d9bd024ef29"
    },
    /* Count = 2 */
    {
        "664ea95d511b2cfdb9e5fb87efdd41cbfb88f3ff47a7d2b8830967e39071a89b948754ffb0ed34c357ed6d4b4b2f8a76615c03",
        "ea94dcbf52b22226dda91d9bfc96fb382730b213b66e30960b0d20d2417036cbaa9e359984eea947232526e175f49739095e695ca8905d469fffec6fba7435ebdffdaf",
        "fad40c82264dc9b8d9a42c10a234138344b0133a708d8899da934bfee2bdd6b8",
        "0dade2c95a9b85a8d2bc13ef"
    },
    /* Count = 3 */
    {
        "c691f3b8f3917efb76825108c0e37dc33e7a8342764ce68a62a2dc1a5c940594961fcd5c0df05394a5c0fff66c254c6b26a549",
        "2cd380ebd6b2cf1b80831cff3d6dc2b6770778ad0d0a91d03eb8553696800f84311d337302519d1036feaab8c8eb845882c5f05de4ef67bf8896fbe82c01dca041d590",
        "aa5fca688cc83283ecf39454679948f4d30aa8cb43db7cc4da4eff1669d6c52f",
        "4b2d7b699a5259f9b541fa49"
    }
};

static int32_t prepare_encryption(uint8_t **plaintext, 
                                  size_t *plaintext_hex_size,
                                  uint8_t **ciphertext,
                                  uint8_t *key,
                                  uint8_t *nonce,
                                  const aes256gcm_test_vector *test_vector)
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
    if (0 != hex_string_to_byte_array(nonce, test_vector->nonce_hex))
    {
        return -1;
    }

    *ciphertext = calloc(*plaintext_hex_size / 2 + AES256GCM_TAG_SIZE,
                         sizeof(uint8_t));
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
                                  const aes256gcm_test_vector *test_vector)
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
    *decrypted = calloc(ciphertext_size - AES256GCM_TAG_SIZE,
                        sizeof(uint8_t));
    if (*decrypted == NULL)
    {
        return -1;
    }
    return 0;
}

bool aes256gcm_nist_positive_test()
{
    int32_t count = 0;
    bool result = true;
    size_t plaintext_hex_size;
    size_t decrypted_size;
    size_t ciphertext_size;
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *decrypted = NULL;
    uint8_t key[AES256GCM_KEY_SIZE];
    uint8_t nonce[AES256GCM_NONCE_SIZE];
    char *ciphertext_hex = NULL;
    const aes256gcm_test_vector *ptr = NULL;

    for (count = 0;
         result && 
         count < (int)(sizeof(nist_test_vectors) / sizeof(aes256gcm_test_vector));
         count++)
    {
        result = false;
        ptr = &nist_test_vectors[count];

        if (prepare_encryption(&plaintext,
                               &plaintext_hex_size,
                               &ciphertext,
                               key,
                               nonce,
                               ptr) != 0)
        {
            goto bail_test;            
        }

        if (0 != aes256gcm_encrypt(ciphertext,
                                   &ciphertext_size,
                                   plaintext,
                                   plaintext_hex_size / 2,
                                   NULL,
                                   0,
                                   nonce,
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

        if (0 != aes256gcm_decrypt(decrypted,
                                   &decrypted_size, 
                                   ciphertext, 
                                   ciphertext_size, 
                                   NULL, 
                                   0, 
                                   nonce, 
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

bool openssl_aes256gcm_nist_positive_test()
{
    int32_t count = 0;
    bool result = true;
    int32_t buf_size;
    size_t plaintext_hex_size;
    EVP_CIPHER_CTX *ctx = NULL;
    size_t decrypted_size;
    size_t ciphertext_size;
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *decrypted = NULL;
    uint8_t key[AES256GCM_KEY_SIZE];
    uint8_t nonce[AES256GCM_NONCE_SIZE];
    uint8_t tag[AES256GCM_TAG_SIZE];
    char *ciphertext_hex = NULL;
    const aes256gcm_test_vector *ptr = NULL;

    for (count = 0;
         result && 
         count < (int)(sizeof(nist_test_vectors) / sizeof(aes256gcm_test_vector));
         count++)
    {
        result = false;
        ptr = &nist_test_vectors[count];
        
        if (prepare_encryption(&plaintext,
                               &plaintext_hex_size,
                               &ciphertext,
                               key,
                               nonce,
                               ptr) != 0)
        {
            goto bail_test;            
        }

        /* set up to Encrypt AES 256 GCM */
        if (!(ctx = EVP_CIPHER_CTX_new()))
        {
            goto bail_test;
        }
        
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        {
            goto bail_test;
        }

        /* set the key and ivec */
        if (!EVP_CIPHER_CTX_ctrl(ctx,
                                 EVP_CTRL_GCM_SET_IVLEN,
                                 AES256GCM_NONCE_SIZE,
                                 NULL))
        {
            goto bail_test;
        }
        if (!EVP_EncryptInit_ex (ctx, NULL, NULL, key, nonce))
        {
            goto bail_test;
        }

        /* perform encryption */
        buf_size = 0;
        ciphertext_size = 0;
        if (!EVP_EncryptUpdate(ctx,
                               ciphertext,
                               &buf_size,
                               plaintext,
                               (int32_t)(plaintext_hex_size / 2)))
        {
            goto bail_test;
        }                   
        ciphertext_size += buf_size;
        if (!EVP_EncryptFinal_ex(ctx, 
                                 &ciphertext[buf_size], 
                                 &buf_size))
        {
            goto bail_test;
        }                         
        ciphertext_size += buf_size;

        /* set the GCM tag */
        crypto_memzero(tag, sizeof(tag));
        if (!EVP_CIPHER_CTX_ctrl(ctx, 
                                 EVP_CTRL_GCM_GET_TAG, 
                                 AES256GCM_TAG_SIZE, 
                                 tag))
        {
            goto bail_test;
        }                         

        if (!EVP_CIPHER_CTX_ctrl (ctx, 
                                  EVP_CTRL_GCM_GET_TAG, 
                                  AES256GCM_TAG_SIZE, 
                                  tag))
        {                          
            goto bail_test;
        }
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;

        /* Concatenate ciphertext and tag together */
        memcpy(&ciphertext[ciphertext_size], tag, AES256GCM_TAG_SIZE);
        ciphertext_size += AES256GCM_TAG_SIZE;

        if (prepare_decryption(&decrypted,
                               &ciphertext_hex,
                               ciphertext,
                               ciphertext_size,
                               ptr))
        {
            goto bail_test;
        }

        /* set up to Decrypt AES 256 GCM */
        if (!(ctx = EVP_CIPHER_CTX_new()))
        {
            goto bail_test;
        }
        
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        {
            goto bail_test;
        }

        /* set the key and ivec */
        if (!EVP_CIPHER_CTX_ctrl(ctx,
                                 EVP_CTRL_GCM_SET_IVLEN,
                                 AES256GCM_NONCE_SIZE,
                                 NULL))
        {
            goto bail_test;
        }
        if (!EVP_DecryptInit_ex (ctx, NULL, NULL, key, nonce))
        {
            goto bail_test;
        }

        /* perform decryption */
        buf_size = 0;
        decrypted_size = 0;
        if (!EVP_DecryptUpdate(ctx,
                               decrypted,
                               &buf_size,
                               ciphertext,
                               (int32_t)(ciphertext_size - AES256GCM_TAG_SIZE)))
        {
            goto bail_test;
        }                   
        decrypted_size = buf_size;

        /* set the expected GCM tag value */
        if (!EVP_CIPHER_CTX_ctrl(ctx,
                                 EVP_CTRL_GCM_SET_TAG,
                                 AES256GCM_NONCE_SIZE,
                                 &ciphertext[ciphertext_size - AES256GCM_TAG_SIZE]))
        {
            goto bail_test;
        }

        if (EVP_DecryptFinal_ex(ctx, 
                                &decrypted[buf_size], 
                                &buf_size) <= 0)
        {
            goto bail_test;
        }

        result = memcmp(decrypted, plaintext, decrypted_size) == 0;
bail_test:
        /* Clean up */
        if (ctx)
        {
            EVP_CIPHER_CTX_free(ctx);
            ctx = NULL;
        }
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
