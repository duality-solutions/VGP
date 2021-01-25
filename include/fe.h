// Copyright (c) 2018-2019 Duality Blockchain Solutions Developers
// See LICENSE.md file for license, copying and use information.

#ifndef _FE_H
#define _FE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief fe represents a field element in the field of Z(2^255-19).
 * 
 * A field element h is represented as an array of ten 32-bit integers
 * { h[0], h[1], ..., h[9] } where
 * h[0] + 2^26 h[1] + 2^51 h[2] + 2^77 h[3] + 2^102 h[4] + ... + 2^230 h[9]. 
 * 
 * Reference: SUPERCOP reference implementation of x25519
 */
typedef int32_t fe[10];

/**
 * @brief Zeros a field element h.
 * 
 * @param h The field element to be zero-ed
 */
void fe_zero(fe h);

/**
 * @brief Set the field element h to 1.
 * 
 * @param h The field element to be set
 */
void fe_one(fe h);

/**
 * @brief Copies field element g to f.
 * 
 * @param f The destination field element
 * @param g The source field element
 */
void fe_copy(fe f, const fe g);

/**
 * @brief Sets field element f to g if cond is non-zero.
 * 
 * @note The field element f is unchanged if cond is zero.
 * 
 * @param f The field element f
 * @param g The field element g
 * @param cond The condition
 */
void fe_cmov(fe f, const fe g, uint32_t cond);

/**
 * @brief Add field elements f and g.
 * 
 * @note h = f + g
 * @note It is acceptable to overlap h with f or g.
 * 
 * @param h The output of addition
 * @param f One of the input to addtion
 * @param g The other input to addition
 */
void fe_add(fe h, const fe f, const fe g);

/**
 * @brief Subtracts field element g from field element f.
 * 
 * @param h The subtraction output
 * @param f The input field element
 * @param g Another input field element
 */
void fe_sub(fe h, const fe f, const fe g);

/**
 * @brief Swaps field element f and g if and only if ctrl is true.
 * 
 * @param f An input field element
 * @param g Another input field element
 * @param ctrl Swap control flag
 */
void fe_swap(fe f, fe g, uint32_t ctrl);

/**
 * @brief Multiplies field elements f and g to produce h.
 * 
 * @param h The product of field multiplication
 * @param f The multiplier
 * @param g The multiplicant
 */
void fe_mul(fe h, const fe f, const fe g);

/**
 * @brief Multiplies field element f with 121666.
 * 
 * @param h The product of the multiplication
 * @param f The multiplier
 */
void fe_mul121666(fe h, const fe f);

/**
 * @brief Returns the squared value of field element f.
 * 
 * @param h The squared output
 * @param f The input field element
 */
void fe_sqr(fe h, const fe f);

/**
 * @brief Returns the value of 2 * fe_sqr(f).
 * 
 * @param h The resulting output
 * @param f The input field element
 */
void fe_2sqr(fe h, const fe f);

/**
 * @brief Computes z^(2^252 - 3).
 * 
 * @param x The output field element
 * @param z The input field element
 */
void fe_pow_2e252m3(fe x, const fe z);

/**
 * @brief Inverts a field element.
 * 
 * @param x The output of inversion
 * @param z The field element to be inverted
 */
void fe_inv(fe x, const fe z);

/**
 * @brief Negate a field element v.
 * 
 * @param u The negated field element
 * @param v The input field element
 */
void fe_neg(fe u, const fe v);

/**
 * @brief Returns true if field element v is zero, otherwise false.
 * 
 * @param v The field element to be checked
 * @return boolean value
 */
bool fe_iszero(const fe v);

/**
 * @brief Returns true if field element v is negative, otherwise false.
 * 
 * @param v The field element to be checked
 * @return boolean value
 */
bool fe_isnegative(const fe v);

/**
 * @brief Loads a field element from a byte-array.
 * 
 * @param h The field element loaded
 * @param s The input byte-array
 */
void fe_frombytes(fe h, const uint8_t *s);

/**
 * @brief Stores a field element h to a byte-array.
 * 
 * @param s The output byte-array
 * @param h The input field element
 */
void fe_tobytes(uint8_t *s, const fe h);

/**
 * @brief Checks whether or not the point p has a small order.
 *
 * @param p byte-array representation of point p
 * @return true if the point p has a small order
 * @return false otherwise
 */
bool fe_has_small_order(const uint8_t* p);

// Added to support key exchange
void fe_0(fe h);
void fe_1(fe h);
void fe_invert(fe out, const fe z);
void fe_cswap(fe f, fe g, unsigned int b);
void fe_sq(fe h, const fe f);

#ifdef __cplusplus
}
#endif

#endif


