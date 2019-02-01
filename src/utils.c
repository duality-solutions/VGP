#include <stdio.h>
#include <string.h>
#if defined(__unix__) || defined(__linux__) || defined(__APPLE__)
# include <sys/mman.h>
#endif
#if defined(_WIN32)
# include <windows.h>
#endif
#include "utils.h"

/**
 * @brief Locks a block of memory at address given by
 * {@code addr}, of {@code size} bytes for storing
 * sensitive data.
 * 
 * @note On Linux system, this method also prevents
 * the block of memory from being included in coredump.
 * 
 * @param addr The address to be locked
 * @param size The number of bytes to lock
 * @return true on success
 * @return false otherwise
 */
bool crypto_mlock(void* const addr, const size_t size)
{
#if defined(__unix__) || defined(__linux__) || defined(__APPLE__)
    return (0 == mlock(addr, size));
#elif defined(_WIN32)
    return VirtualLock(addr, size);
#else
    return false;
#endif
}

/**
 * @brief Unlocks a block of memory at address given by
 * {@code addr}, of {@code size} bytes.
 *
 * @note The block of memory to be unlocked shall be
 * locked by crypto_mlock(void* const, const size_t)
 * in the first place.
 * 
 * @param addr The address to be unlocked
 * @param size The number of bytes to lock
 * @return true on success
 * @return false otherwise
 */
bool crypto_munlock(void* const addr, const size_t size)
{
#if defined(__unix__) || defined(__linux__) || defined(__APPLE__)
    return (0 == munlock(addr, size));
#elif defined(_WIN32)
    return VirtualUnlock(addr, size);
#else
    return false;
#endif
}

/**
 * @brief A constant-time method to zero a block of memory.
 * 
 * @param ptr the pointer of memory location to be zeroed
 * @param size the size of the memory block in bytes
 */
void crypto_memzero(void const* ptr, const size_t size)
{
#if defined(_WIN32)
    SecureZeroMemory((PVOID)ptr, (SIZE_T)size);
#else
    size_t index = 0;
    volatile uint8_t *volatile target_ptr =
        (volatile uint8_t *volatile) ptr;

    for (index=0; index<size; index++)
    {
        target_ptr[index] = 0x00;
    }    
#endif    
}

/**
 * @brief A constant-time method to check whether or not
 * two memory blocks are equal.
 * 
 * @param a the pointer to a memory block
 * @param b the pointer to another memory block
 * @param size the size of the memory block in bytes
 * @return true if both blocks are equal
 * @return false otherwise
 */
bool crypto_is_memequal(void const* a, void const* b, const size_t size)
{
    size_t index = 0;
    uint8_t val = 0;
    volatile uint8_t *volatile a_ptr =
        (volatile uint8_t *volatile) a;
    volatile uint8_t *volatile b_ptr =
        (volatile uint8_t *volatile) b;

    for (index = 0; index < size; index++)
    {
        val |= (a_ptr[index] - b_ptr[index]);
    }

    return (val == 0);
}

/**
 * @brief Converts a byte-array to its hex-string representation.
 * 
 * @param out The output hex-string representation
 * @param in The input byte-array
 * @param in_size The size of the input byte-array in bytes
 * @return 0 on success, non-zero otherwise
 */
int32_t byte_array_to_hex_string(char *out, const uint8_t *in, size_t in_size)
{
    size_t i;
    static const char hex_lookup[] = "0123456789abcdef";

    if (out == NULL)
    {
        fprintf(stderr, "Output buffer is not initialized\n");
        return -1;
    }

    for (i=0; i<in_size; i++)
    {
        out[2*i]     = hex_lookup[((in[i] >> 4) & 0x0f)];
        out[2*i + 1] = hex_lookup[((in[i]     ) & 0x0f)];
    }

    return 0;
}

/**
 * @brief Converts a hex-string to its byte-array value.
 * 
 * @note The length of the hex-string must be even.
 * 
 * @param out The output byte-array value
 * @param in The input hex-string
 * @return 0 on success, non-zero otherwise
 */
int32_t hex_string_to_byte_array(uint8_t *out, const char *in)
{
    int32_t idx = 0, offset = 1;
    size_t hex_string_len;
    
    if (out == NULL)
    {
        fprintf(stderr, "Output buffer is not initialized\n");
        return -1;
    }

    hex_string_len = strlen(in);
    if (hex_string_len & 1)
    {
        fprintf(stderr, "Invalid hex-string\n");
        return -2;
    }

    crypto_memzero(out, hex_string_len >> 1);
    while (idx < (int32_t) hex_string_len)
    {
        if (('0' <= in[idx]) && (in[idx] <= '9'))
        {
            out[(idx >> 1)] |= ((in[idx] - '0') << (4*offset));
        } 
        else if (('a' <= in[idx]) && (in[idx] <= 'f'))
        {
            out[(idx >> 1)] |= ((0x0a + in[idx] - 'a') << (4*offset));
        }
        else if (('A' <= in[idx]) && (in[idx] <= 'F'))
        {
            out[(idx >> 1)] |= ((0x0a + in[idx] - 'A') << (4*offset));
        }
        else
        {
            fprintf(stderr, "Invalid hex-string\n");
            crypto_memzero(out, idx >> 1);
            return -3;
        }
        idx++;
        offset = (offset + 1) & 1;
    }

    return 0;
}
