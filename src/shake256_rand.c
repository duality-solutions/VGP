#include <stdlib.h>
#include <string.h>
#if !defined(_MSC_VER)
# include <unistd.h>
#endif
#include "shake256.h"
#include "shake256_rand.h"
#include "utils.h"

#define INTERNAL_BUFFER_SIZE        4096

#if defined(_MSC_VER)
typedef long long ssize_t;
#endif

static uint8_t _shake256_buffer[INTERNAL_BUFFER_SIZE];
static uint8_t _buffer[INTERNAL_BUFFER_SIZE];
static ssize_t _bytes_available = 0;

void shake256_randominit(const uint8_t* seed, size_t seed_size)
{
    crypto_memzero(_shake256_buffer, sizeof(_shake256_buffer));
    shake256(_shake256_buffer, INTERNAL_BUFFER_SIZE, seed, seed_size);
    _bytes_available = INTERNAL_BUFFER_SIZE;
}

void shake256_randombytes(uint8_t* buf, size_t buf_size)
{
    uint8_t *ptr = buf;
    ssize_t size;
    ssize_t bytes_left = (ssize_t)buf_size;
    while (bytes_left > 0)
    {
        size = bytes_left;
        if (size > _bytes_available)
        {
            size = _bytes_available;
        }
        memcpy(ptr,
               &_shake256_buffer[INTERNAL_BUFFER_SIZE - _bytes_available],
               (size_t)size);
        ptr += size;
        bytes_left -= size;
        _bytes_available -= size;
        /* Refill SHAKE256 internal buffer if necessary */
        if (_bytes_available <= 0)
        {
            memcpy(_buffer, _shake256_buffer, sizeof(_shake256_buffer));
            shake256(_shake256_buffer,
                     INTERNAL_BUFFER_SIZE,
                     _buffer,
                     INTERNAL_BUFFER_SIZE);
            crypto_memzero(_buffer, sizeof(_buffer));
            _bytes_available = INTERNAL_BUFFER_SIZE;   
        }
    }
}
