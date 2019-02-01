#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "aes256.h"
#include "rand.h"
#include "utils.h"

bool nist_aes_test_vector() 
{
    const char *hex_plaintext = "00112233445566778899aabbccddeeff";
    const char *hex_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const char *hex_ciphertext = "8ea2b7ca516745bfeafc49904b496089";
    uint8_t plaintext[16];
    uint8_t key[AES256_KEY_SIZE];
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    char hex_output[33];
    bool result;

    hex_string_to_byte_array(plaintext, hex_plaintext);
    hex_string_to_byte_array(key, hex_key);
    crypto_memzero(ciphertext, sizeof(ciphertext));
    aes256_bitslice_encrypt(ciphertext, plaintext, key);

    crypto_memzero(hex_output, sizeof(hex_output));
    byte_array_to_hex_string(hex_output, ciphertext, sizeof(ciphertext));

    result = strcmp(hex_ciphertext, hex_output) == 0;
    if (result != true)
    {
        return false;
    }
    
    aes256_bitslice_decrypt(decrypted, ciphertext, key);

    crypto_memzero(hex_output, sizeof(hex_output));
    byte_array_to_hex_string(hex_output, decrypted, sizeof(decrypted));

    result = strcmp(hex_plaintext, hex_output) == 0;

    return result;
}

bool random_aes_test_vectors(int iterations) 
{
    int32_t it;
    bool status = true;
    uint8_t plaintext[16];
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    uint8_t key[AES256_KEY_SIZE];
    uint8_t seed[] = {
        0x71, 0x6f, 0x17, 0x97, 0xfc, 0xa8, 0xad, 0xed,
        0x8b, 0xd8, 0x1b, 0x05, 0x11, 0xda, 0x64, 0xc7,
        0x9a, 0x2d, 0xea, 0x45, 0x12, 0x24, 0xfc, 0x19
    };

    bdap_randominit(seed, sizeof(seed));

    for (it=0; it<iterations && status; it++)
    {
        bdap_randombytes(plaintext, sizeof(plaintext));
        bdap_randombytes(key, sizeof(key));

        crypto_memzero(ciphertext, sizeof(ciphertext));
        aes256_bitslice_encrypt(ciphertext, plaintext, key);

        crypto_memzero(decrypted, sizeof(decrypted));
        aes256_bitslice_decrypt(decrypted, ciphertext, key);

        status = (memcmp(decrypted, plaintext, sizeof(plaintext)) == 0);
    }

    return status;
}
