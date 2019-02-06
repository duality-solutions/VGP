// Copyright (c) 2018-2019 Duality Blockchain Solutions Developers
// See LICENSE.md file for license, copying and use information.

#ifndef _GE_H
#define _GE_H

#include <stdint.h>
#include <stdbool.h>
#include "fe.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief ge represents a group element.
 * 
 * The group is the set of pairs (x, y) where x and y are field-element
 * as defined in fe.h. The pair satisfies the following relationship:
 * -x^2 + y^2 = 1 + d x^2y^2, where d = -121665/121666.
 * 
 * There are a number of representation of ge:
 * - ge_p2 (Projective): (x:y:z) satisfying x=x/z, y=y/z
 * - ge_p3 (Extended): (x:y:z:t) satisfying x=x/z, y=y/z, xy=zt
 * - ge_p1p1 (Completed): ((x:z),(y:t)) satisfying x=x/z, y=y/t
 * 
 * Reference: SUPERCOP reference implementation of ed25519
 */

/**
 * @brief Projective representation of the group element.
 */
typedef struct
{
    fe x;
    fe y;
    fe z;
} ge_p2;

/**
 * @brief Extended representation of the group element.
 */
typedef struct
{
    fe x;
    fe y;
    fe z;
    fe t;
} ge_p3;

/**
 * @brief Completed representation of the group element.
 */
typedef struct
{
    fe x;
    fe y;
    fe z;
    fe t;
} ge_p1p1;

/**
 * @brief Performs group element scalar multiplication.
 *
 * @note The method computes h = [a] * B where
 * a is 32-byte array and B is Ed25519 base-point.
 *
 * @param h the output group element
 * @param a the scalar input, 32 bytes in size
 */
void ge_scalarmult_base(ge_p3* h, const uint8_t* a);

/**
 * @brief Checks whether or not the point P has a small order.
 *
 * @param P byte-array representation of point P 
 * @return true if the point P has a small order
 * @return false otherwise
 */
bool ge_has_small_order(const uint8_t* P);

/**
 * @brief Serialises the group element h to byte-array.
 * 
 * @param s the output byte-array, 32 bytes in size
 * @param h the input group element
 */
void ge_p3_tobytes(uint8_t *s, const ge_p3 *h);

/**
 * @brief Deserialises the point P to a group-element in
 * extended representation.
 * 
 * @param h the deserialised group element
 * @param P byte-array representation of point P 
 * @return 0 on success, non-zero otherwise
 */
int32_t ge_frombytes(ge_p3* h, const uint8_t* P);

/**
 * @brief Checks whether or not the group-element lies on the main subgroup.
 * 
 * @param h the group element
 * @return true if the group element lies on the main subgroup
 * @return false otherwise
 */
bool ge_is_on_main_subgroup(const ge_p3* h);

#ifdef __cplusplus
}
#endif

#endif
