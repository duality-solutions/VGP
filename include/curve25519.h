// Copyright (c) 2018-2019 Duality Blockchain Solutions Developers
// See LICENSE.md file for license, copying and use information.

#ifndef _CURVE25519_H
#define _CURVE25519_H

#include <stdbool.h>
#include <stdint.h>

#define CURVE25519_POINT_SIZE           32
#define CURVE25519_SCALAR_SIZE          32
#define CURVE25519_PRIVATE_KEY_SIZE     32
#define CURVE25519_PUBLIC_KEY_SIZE      32

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Performs curve25519 Diffie-Hellman exchange between point p and scalar n.
 * 
 * @note q = [n].p
 * 
 * @param q The scalar multiplication output
 * @param n The scalar value, 32 bytes
 * @param p The curve25519 point, 32 bytes
 * @return true on success
 * @return false on failure, e.g invalid point
 */
bool curve25519_dh(uint8_t *q, const uint8_t *n, const uint8_t *p);

/**
 * @brief Creates a curve25519 public-key from a private-key.
 * 
 * @param q The public-key output, a point
 * @param n The private-key input, a scalar
 * @return true on success
 * @return false on failure, e.g invalid public-key
 */
bool curve25519_public_key_from_private_key(uint8_t *q, const uint8_t *n);

/**
 * @brief Creates a curve25519 random key-pair.
 * 
 * @param public_key Output public-key array, 32 bytes
 * @param private_key Output private-key array, 32 bytes
 * @return true on success
 * @return false on failure, e.g. invalid key-pair
 */
bool curve25519_random_keypair(uint8_t* public_key, uint8_t* private_key);

#ifdef __cplusplus
}
#endif

#endif
