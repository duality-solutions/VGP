// Copyright (c) 2018-2019 Duality Blockchain Solutions Developers
// See LICENSE.md file for license, copying and use information.

#ifndef _RAND_H
#define _RAND_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief A function pointer for initialising a random number generator.
 * 
 * @note By default, this function pointer points to
 * os_randominit(const uint8_t, size_t) method, but it can be
 * overwritten with use_shake256_rand() method.
 *
 * @param seed the pointer to the seed
 * @param seed_size the size of the seed in bytes
 */
extern void (*bdap_randominit) (const uint8_t* seed, size_t seed_size);

/**
 * @brief A function pointer for generating a random block of
 * {@code buf_size} bytes.
 * 
 * @note By default, this function pointer points to
 * os_randombytes(uint8_t, size_t) method, but it can be overwritten
 * with use_shake256_rand() method.
 * 
 * @param buf The pointer to the generated random block
 * @param buf_size The length of the random block in bytes
 */
extern void (*bdap_randombytes)(uint8_t *buf, size_t buf_size);

/**
 * @brief Sets up the function pointers above to use SHAKE256-based
 * random number generator.
 * 
 * @note The SHAKE256-based random number generators shall only be
 * used for testing purposes. Don't use it in live/production code,
 * unless you know what you are doing.
 */
void use_shake256_rand();

/**
 * @brief Sets up the function pointers above to use OS random number
 * generator.
 */
void use_os_rand();

#ifdef __cplusplus
}
#endif

#endif
