#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "shake256_rand.h"
#include "utils.h"

#define SIZE_PER_VECTOR     4

typedef struct
{
    int32_t offset;
    const char *xof_hex;
} xof_offset_pair;

typedef struct
{
    const char *seed_hex;
    xof_offset_pair values[SIZE_PER_VECTOR];
} shake256random_test_vector;

static shake256random_test_vector test_vectors[] = 
{
    {
        "6a25075a543faab09d269c338df80c67a28b735d40c0d84e9347a6915b2026ea",
        {
            {
                0,
                "b082ba639935ba8e0a7c0e48320091add5b9dc33"
            },
            {
                64,
                "59b9ced62a6700836e994638dec8e81c11b1f8bd6be2a765"
            },
            {
                4090,
                "b610af91a6c89313ca5ab7672648141791c9d44e11ff555ef63382206fa4debd5280342a1cd1"
            },
            {
                8180,
                "61e4d1b26749f92b2a52ae822548dc32db071a753b34"
            }
        }
    },
    {
        "39ca273d5dc3aa4bc0b3b2f603052002abb9",
        {
            {
                4092,
                "7eca8d20cf6ab905604f6442d9e9050b5872886ddaa72addb78c6e64d571"
            },
            {
                783,
                "3571333acf0b00ab60866da297b717a3",
            },
            {
                8365,
                "5a3caaf9e5e49783a1d03833f394cbcbaf71c350b22061dada",
            },
            {
                4513,
                "5a693b69868c691714dc87e22f353b0d84b3fe23"
            }
        }
    }
};

uint8_t *hex_to_array(const char* hex, size_t *size)
{
    uint8_t *out = NULL;
    size_t hex_len = strlen(hex);
    
    if (hex_len & 1)
    {
        return NULL;
    }

    if (!(out = calloc(hex_len / 2, sizeof(uint8_t))))
    {
        return NULL;
    }
    hex_string_to_byte_array(out, hex);
    *size = hex_len / 2;
    
    return out;    
}

bool shake256_random_test()
{
    int32_t index, count, offset;
    int32_t bytes_generated;
    bool result = true;
    uint8_t *seed = NULL;
    uint8_t *buffer = NULL;
    uint8_t *rnd_buf = NULL;
    const shake256random_test_vector* ptr;
    size_t size = 0;

    for (count = 0;
         result && 
         count < (int)(sizeof(test_vectors) / sizeof(shake256random_test_vector));
         count++)
    {
        result = false;
        ptr = &test_vectors[count];

        seed = hex_to_array(ptr->seed_hex, &size);
        shake256_randominit(seed, size);
        free(seed);
        bytes_generated = 0;

        for (index=0; index<SIZE_PER_VECTOR; index++)
        {
            offset = ptr->values[index].offset;
            buffer = hex_to_array(ptr->values[index].xof_hex, &size);

            if (offset > 0)
            {
                rnd_buf = calloc(offset, sizeof(uint8_t));
                shake256_randombytes(rnd_buf, offset);
                free(rnd_buf);
            }
            rnd_buf = calloc(size, sizeof(uint8_t));
            shake256_randombytes(rnd_buf, size);

            result = (memcmp(rnd_buf, buffer, size) == 0);

            free(rnd_buf);
            free(buffer);

            bytes_generated += (int32_t)size;
        }
    }

    return true;
}
