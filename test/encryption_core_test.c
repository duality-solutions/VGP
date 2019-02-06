#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "rand.h"
#include "encryption_core.h"
#include "ed25519.h"
#include "curve25519.h"
#include "utils.h"

const char *seed_pool[] = {
    "41a6a219597a19a90d19515f7c37a848787e111ac6502cd5",
    "408fbdd1c55c80dc6191d8cfe4c26b62511da57dd317370d",
    "d6f7ffef18e151f93b35a465fe074a1f4cd67d7ecb346b10",
    "57b4fca2255d1dd2e487e4c8850ee7e47092a6da2beaf204",
    "8e7c3446b7ee7601f5a70ba94baa233e7e0e8244a127e7d2",
    "8d7addb5b29efd2d69636c70784aa718c2c7008c65766a89",
    "38f4b190670e07b09b5240dd6c1a02e0af912d047ac40f58",
    "fb1b75af55213154836b32a98f45f490cdb217e7e1adaf7c",
    "646a9245f609aa3a72d395678d4a33fb8b5bfb6c6f5408ba",
    "ccba0b41a1845916366851f951035969a446adb3001c4b49",
    "5ee219614ccaa832837b0a3c0d9092abc4a7f4c9dfcd11df",
    "42b2b4e0b8eb18a6f4d5258d0720a87ba9f6bdfbd425ce28",
    "78e7fe060d4c160e652091a6480700a41b823c2899cc0cba",
    "f3973d2f7f52cb4cc5a14218a3e4400d671c12fffecc1ce9",
    "e74a9cc1bf80d2062c35956752bf73793fae6316205b6c4a",
    "4270e50f764634163958a458cea400bf9b5e174812ff6481",
    "f4128b00a612d661c062683793a2a913865277844ab50c90",
    "5534d7071f034dd7018f37c74a1294b82debb77ab5388cb1",
    "97de9d65ad377948d058b658b378fae36cb436a8531e1f44",
    "1bc9234dd0ecb86352cc793cab0af633469677e4fbb5559f",
    "4635bd5964a1f7a7ca5e323af5524a5bddd32148247d19e1",
    "618742be8913bf1242e012fc49d3a14ffccad2097fe34640",
    "e50aee905bd303ff51ff78ee9ac49e0e6733494215acce00",
    "efb1ee7a60923d099a18d08c1f65801eab017d01c022c476",
    "f43886a81774f171765fe58dde989246d09b148d8e9680aa",
    "5f1b9e2183c9d4482dc84c2746e01c1e416e371d8f6fb599",
    "f5868a98c74ca655f981c182068cbc02838146515753ee06",
    "dd5e2a3942d700df0e10bf94d73c63bd64c4cba2ba128cf0",
    "1b4c76d0f7b2c90fc5388bddae5d26cac63534e397b7b96f",
    "65fe85603c5f4c613f659cf48b90f8982c93d58ae31f75e9",
    "6c47ce2bc505a36ad3f57bb7145d20d496afbadd8900d365",
    "78db52392a0e3f54dc5f894f8ea0622f150c68b2703859a1",
    "0bb15a866f9be223bf0e4c4fd467ef8757475caac85f2f25",
    "ea5f5b9ec142d89697d71347d6a6e563aca770a4a89e51b5",
    "9325c477542ca02f1145dba7e63bc643a3ec58bcd324f6fc",
    "54a11dc181897c9907740f3127401851b33a852e8a7c6a68",
    "14980dfaa59ba7f00c959bb20374e6bae20ed1cb5ea56864",
    "987043a418099420397e7057d0c502278bef54d13bf4a1f0",
    "44b6bfa807f92d9ed9d489f8db9989499c05f56490c2377d",
    "74ad76557e4b9cb509a38474f9315d2d5ffb6a994bb53bde",
    "bfb80195daceddf569f495604309f8d73e415e35ce96695d",
    "75b4fd811499a104101fa34c6d8df08f5dc7d5f3e7a6a28c",
    "8838600ddc033497323cafdde0cb09da5f9883486c9619eb",
    "c76e99df7ebe5ea886627b83770f4ad753656ddf7c22f609",
    "fc3d6bda513937105444a03ecb10fe9cc9abdee15459b604",
    "d3bfcc5db168ed417cf6ddce4ea41f8e4f96fbefa2f22f36",
    "9f6e39463177fd989e1987786fc428ef0bf20964143b7238",
    "c90835b1350fe1899a9314f1915520a4bc8d975b61afc8c5",
    "99209ff6db92fbf8e9700dacfe35c7fac1d6b0139156f006",
    "a88bb09af23b37ab7bc5abf599dc54da0bed5890b1b82f50"
};

bool bdap_random_test()
{
    int32_t idx;
    bool result = true;
    uint16_t i, r, num_recipients;
    uint8_t seed[24];
    uint8_t **ed25519_pk;
    uint8_t **ed25519_sk;
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *decrypted = NULL;
    const char *error_message = NULL;
    const uint8_t **ed25519_pk_ptr = NULL;
    size_t plaintext_size = 0;
    size_t decrypted_size = 0;
    size_t ciphertext_size = 0;

    for (idx = 0;
         result && idx < (int)(sizeof(seed_pool)/sizeof(seed_pool[0]));
         idx++)
    {
        result = false;

        hex_string_to_byte_array(seed, seed_pool[idx]);

        bdap_randominit(seed, sizeof(seed));

        bdap_randombytes((uint8_t*)&num_recipients, sizeof(num_recipients));
        num_recipients = 1 + (num_recipients & 0x000f);

        ed25519_pk = (uint8_t **)
            calloc(num_recipients, sizeof(uint8_t *));
        ed25519_sk = (uint8_t **)
            calloc(num_recipients, sizeof(uint8_t *));
        for (i = 0; i < num_recipients; i++)
        {
            ed25519_pk[i] = (uint8_t *)
                calloc(ED25519_PUBLIC_KEY_SIZE, sizeof(uint8_t));
            ed25519_sk[i] = (uint8_t *)
                calloc(ED25519_PRIVATE_KEY_SIZE, sizeof(uint8_t));

            ed25519_keypair(ed25519_pk[i], ed25519_sk[i]);
        }

        bdap_randombytes((uint8_t *)&plaintext_size, sizeof(plaintext_size));
        plaintext_size &= 0x3FFF;

        plaintext = (uint8_t *)calloc(plaintext_size, sizeof(uint8_t));
        bdap_randombytes(plaintext, plaintext_size);

        ciphertext_size = bdap_ciphertext_size(num_recipients, plaintext_size);
        ciphertext = (uint8_t *)
            calloc(ciphertext_size, sizeof(uint8_t));

        ed25519_pk_ptr = (const uint8_t **)ed25519_pk;
        result = bdap_encrypt(ciphertext,
                              num_recipients,
                              ed25519_pk_ptr,
                              plaintext,
                              plaintext_size,
                              &error_message);
        if (result == false)
        {
            free(ciphertext);
            free(plaintext);
            for (i = 0; i < num_recipients; i++)
            {
                free(ed25519_pk[i]);
                free(ed25519_sk[i]);
            }
            free(ed25519_pk);
            free(ed25519_sk);

            return false;
        }

        decrypted_size = bdap_decrypted_size(ciphertext, ciphertext_size);
        decrypted = (uint8_t *)calloc(decrypted_size, sizeof(uint8_t));
        for (r = 0; result && r < num_recipients; r++)
        {
            crypto_memzero(decrypted, decrypted_size);

            result = bdap_decrypt(decrypted,
                                  ed25519_sk[r],
                                  ciphertext,
                                  ciphertext_size,
                                  &error_message);
            if (result == false)
            {
                free(ciphertext);
                free(plaintext);
                free(decrypted);
                for (i = 0; i < num_recipients; i++)
                {
                    free(ed25519_pk[i]);
                    free(ed25519_sk[i]);
                }
                free(ed25519_pk);
                free(ed25519_sk);

                return false;
            }

            result = (plaintext_size == decrypted_size) && 
                    (memcmp(plaintext, decrypted, decrypted_size) == 0);
        }

        free(ciphertext);
        free(plaintext);
        free(decrypted);
        for (i = 0; i < num_recipients; i++)
        {
            free(ed25519_pk[i]);
            free(ed25519_sk[i]);
        }
        free(ed25519_pk);
        free(ed25519_sk);
    }

    return result;
}
