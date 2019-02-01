#ifndef _UTILS_H
#define _UTILS_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

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
bool crypto_mlock(void* const addr, const size_t size);

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
bool crypto_munlock(void* const addr, const size_t size);

/**
 * @brief A constant-time method to zero a block of memory.
 * 
 * @param ptr the pointer of memory location to be zeroed
 * @param size the size of the memory block in bytes
 */
void crypto_memzero(void const* ptr, const size_t size);

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
bool crypto_is_memequal(void const* a, void const* b, const size_t size);

/**
 * @brief Converts a byte-array to its hex-string representation.
 * 
 * @param out The output hex-string representation
 * @param in The input byte-array
 * @param in_size The size of the input byte-array in bytes
 * @return 0 on success, non-zero otherwise
 */
int32_t byte_array_to_hex_string(char *out, const uint8_t *in, size_t in_size);

/**
 * @brief Converts a hex-string to its byte-array value.
 * 
 * @note The length of the hex-string must be even.
 * 
 * @param out The output byte-array value
 * @param in The input hex-string
 * @return 0 on success, non-zero otherwise
 */
int32_t hex_string_to_byte_array(uint8_t *out, const char *in);

#ifdef __cplusplus
}
#endif

#endif
