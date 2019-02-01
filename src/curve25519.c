#include "curve25519.h"
#include "fe.h"
#include "utils.h"
#include "rand.h"

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
bool curve25519_dh(uint8_t *q, const uint8_t *n, const uint8_t *p)
{
    uint8_t e[CURVE25519_SCALAR_SIZE];
    uint32_t i, b, swap;
    fe x1, x2, x3;
    fe z2, z3;
    fe t0, t1;
    int32_t pos;

    if (fe_has_small_order(p))
    {
        return false;
    }

    /**
     * From curve25519 specification, one needs to ensure that:
     * - the bits 0, 1 and 2 of the first byte should be clear
     * - the bit 7 of the last byte should also be clear
     * - the bit 6 of the last byte should be set
     */
    for (i = 0; i < CURVE25519_SCALAR_SIZE; ++i)
    {
        e[i] = n[i];
    }
    e[ 0] &= 0xf8; /* Clear bits 0, 1, and 2 */
    e[31] &= 0x7f; /* Clear bit 7 */
    e[31] |= 0x40; /* Set bit 6 */

    fe_frombytes(x1, p);
    fe_one(x2);
    fe_zero(z2);
    fe_copy(x3, x1);
    fe_one(z3);

    swap = 0;
    for (pos = 254; pos >= 0; --pos)
    {
        b = e[pos >> 3] >> (pos & 7);
        b &= 1;
        swap ^= b;
        fe_swap(x2, x3, swap);
        fe_swap(z2, z3, swap);
        swap = b;
        fe_sub(t0, x3, z3);
        fe_sub(t1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, t0, x2);
        fe_mul(z2, z2, t1);
        fe_sqr(t0, t1);
        fe_sqr(t1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, t1, t0);
        fe_sub(t1, t1, t0);
        fe_sqr(z2, z2);
        fe_mul121666(z3, t1);
        fe_sqr(x3, x3);
        fe_add(t0, t0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, t1, t0);
    }
    fe_swap(x2, x3, swap);
    fe_swap(z2, z3, swap);

    fe_inv(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(q, x2);

    return true;
}

/**
 * @brief Creates a curve25519 public-key from a private-key.
 * 
 * @param q The public-key output, a point
 * @param n The private-key input, a scalar
 * @return true on success
 * @return false on failure, e.g invalid public-key
 */
bool curve25519_public_key_from_private_key(uint8_t *q, const uint8_t *n)
{
    static const uint8_t basepoint[CURVE25519_POINT_SIZE] = {9};
    return curve25519_dh(q, n, basepoint);
}

/**
 * @brief Creates a curve25519 random key-pair.
 * 
 * @param public_key Output public-key array, 32 bytes
 * @param private_key Output private-key array, 32 bytes
 * @return true on success
 * @return false on failure, e.g. invalid key-pair
 */
bool curve25519_random_keypair(uint8_t* public_key, uint8_t* private_key)
{
    bdap_randombytes(private_key, CURVE25519_SCALAR_SIZE);
    return curve25519_public_key_from_private_key(public_key, private_key);
}

