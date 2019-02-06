// Copyright (c) 2018-2019 Duality Blockchain Solutions Developers
// See LICENSE.md file for license, copying and use information.

#ifndef _ED25519_H
#define _ED25519_H

#include <stdint.h>

#define ED25519_PRIVATE_KEY_SEED_SIZE   32
#define ED25519_PRIVATE_KEY_SIZE        64
#define ED25519_PUBLIC_KEY_SIZE         32

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generates an Ed25519 public/private key-pair from
 * a given {@code seed}.
 * 
 * @note The {@code seed} is 32 bytes in size.
 * 
 * @param pk the pointer to the output public-key, 32 bytes
 * @param sk the pointer to the output private-key, 64 bytes
 * @param seed the pointer to the 32-byte seed
 */
void ed25519_seeded_keypair(uint8_t* pk,
                            uint8_t* sk,
                            const uint8_t* seed);

/**
 * @brief Randomly generates an Ed25519 public/private key-pair.
 *
 * @param pk the pointer to the output public-key, 32 bytes
 * @param sk the pointer to the output private-key, 64 bytes
 */
void ed25519_keypair(uint8_t* pk, uint8_t* sk);

/**
 * @brief Creates a Ed25519 public-key from a private-key seed.
 * 
 * @param p The public-key output, 32 bytes
 * @param s The private-key seed input, 32 bytes
 */
void ed25519_public_key_from_private_key_seed(uint8_t *p,
                                              const uint8_t *s);

/**
 * @brief Converts Ed25519 public-key to Curve25519 public-key.
 * 
 * @param curve25519_pk the output Curve25519 public-key
 * @param ed25519_pk the input Ed25519 public-key
 * @return 0 on success, non-zero otherwise
 */
int32_t ed25519_to_curve25519_public_key(uint8_t *curve25519_pk,
                                         const uint8_t *ed25519_pk);

/**
 * @brief Converts Ed25519 private-key to Curve25519 private-key
 * 
 * @param curve25519_sk the output Curve25519 private-key
 * @param ed25519_sk the input Ed25519 private-key
 */
void ed25519_to_curve25519_private_key(uint8_t *curve25519_sk,
                                       const uint8_t *ed25519_sk);

#ifdef __cplusplus
}
#endif

#endif
