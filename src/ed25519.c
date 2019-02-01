#include <string.h>
#include "ed25519.h"
#include "ge.h"
#include "curve25519.h"
#include "sha512.h"
#include "rand.h"
#include "utils.h"
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
                            const uint8_t* seed)
{
    ed25519_public_key_from_private_key_seed(pk, seed);

    memcpy(sk, seed, ED25519_PRIVATE_KEY_SEED_SIZE);
    memcpy(sk + ED25519_PRIVATE_KEY_SEED_SIZE, pk, ED25519_PUBLIC_KEY_SIZE);
}                            

/**
 * @brief Randomly generates an Ed25519 public/private key-pair.
 *
 * @param pk the pointer to the output public-key, 32 bytes
 * @param sk the pointer to the output private-key, 64 bytes
 */
void ed25519_keypair(uint8_t* pk, uint8_t* sk)
{
    uint8_t seed[ED25519_PRIVATE_KEY_SEED_SIZE];

    bdap_randombytes(seed, sizeof(seed));
    ed25519_seeded_keypair(pk, sk, seed);

    crypto_memzero(seed, sizeof(seed));
}

/**
 * @brief Creates a Ed25519 public-key from a private-key seed.
 * 
 * @param p The public-key output, 32 bytes
 * @param s The private-key seed input, 32 bytes
 */
void ed25519_public_key_from_private_key_seed(uint8_t *p,
                                              const uint8_t *s)
{
    ge_p3 A;
    uint8_t sk[SHA512_DIGEST_SIZE];

    sha512(sk, s, ED25519_PRIVATE_KEY_SEED_SIZE);
    sk[ 0] &= 0xf8; /* Clear bits 0, 1, and 2 */
    sk[31] &= 0x7f; /* Clear bit 7 */
    sk[31] |= 0x40; /* Set bit 6 */

    ge_scalarmult_base(&A, sk);
    ge_p3_tobytes(p, &A);

    crypto_memzero(sk, sizeof(sk));
}

/**
 * The implementation here is based on the code in libsodium v1.0.16.
 * 
 * In converting the private-key from Ed25519 to Curve25519, the
 * first 32-bytes of Ed25519 private-key shall be used as the
 * Curve25519 private-key. Another alternative is to truncate the
 * SHA-512 of Ed25519 private-key to 32-bytes as the Curve25519
 * private-key. The latter approach is implemented here.
 */

/**
 * @brief Converts Ed25519 public-key to Curve25519 public-key.
 * 
 * @param curve25519_pk the output Curve25519 public-key
 * @param ed25519_pk the input Ed25519 public-key
 * @return 0 on success, non-zero otherwise
 */
int32_t ed25519_to_curve25519_public_key(uint8_t *curve25519_pk,
                                         const uint8_t *ed25519_pk)
{
    ge_p3 A;
    fe x;
    fe o_m_y;

    if (ge_has_small_order(ed25519_pk) ||
        ge_frombytes(&A, ed25519_pk) != 0 ||
        ge_is_on_main_subgroup(&A) == false)
    {
        return -1;
    }

    fe_one(o_m_y);
    fe_sub(o_m_y, o_m_y, A.y);
    fe_one(x);
    fe_add(x, x, A.y);
    fe_inv(o_m_y, o_m_y);
    fe_mul(x, x, o_m_y);
    
    fe_tobytes(curve25519_pk, x);

    return 0;
}

/**
 * @brief Converts Ed25519 private-key to Curve25519 private-key
 * 
 * @param curve25519_sk the output Curve25519 private-key
 * @param ed25519_sk the input Ed25519 private-key
 */
void ed25519_to_curve25519_private_key(uint8_t *curve25519_sk,
                                       const uint8_t *ed25519_sk)
{
    uint8_t s[SHA512_DIGEST_SIZE];

    sha512(s, ed25519_sk, 32);
    s[ 0] &= 0xf8; /* Clear bits 0, 1, and 2 */
    s[31] &= 0x7f; /* Clear bit 7 */
    s[31] |= 0x40; /* Set bit 6 */

    memcpy(curve25519_sk, s, CURVE25519_PRIVATE_KEY_SIZE);
    
    crypto_memzero(s, sizeof(s));
}
