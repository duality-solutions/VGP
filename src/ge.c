#include "ge.h"
#include "fe_25_5.h"

typedef struct
{
    fe y_p_x;
    fe y_m_x;
    fe z;
    fe t2d;
} ge_cached;

static fe d = {
    -10913610,  13857413, -15372611,   6949391,    114729,
     -8787816,  -6275908,  -3247719, -18696448, -12055116
};

static fe d2 = {
    -21827239,  -5839606, -30745221,  13898782,    229458,
     15978800, -12551817,  -6495438,  29715968,   9444199
};

static fe sqrt_m_1 = {
    -32595792,  -7943725,   9377950,   3500415,  12389472,
      -272473, -25146209,  -2005654,    326686,  11406482
};

static uint8_t negative(char b)
{
    uint64_t a = b;
    a >>= 63;
    return (a & 0xFF);
}

static uint8_t equal(char a, char b)
{
    uint32_t x = (uint32_t)(a ^ b);
    x  -= 1;
    x >>= 31;
    return x;
}

static void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p)
{
    fe_copy(r->x, p->x);
    fe_copy(r->y, p->y);
    fe_copy(r->z, p->z);
}

static void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p)
{
    fe t0;

    fe_sqr (r->x, p->x);
    fe_sqr (r->z, p->y);
    fe_2sqr(r->t, p->z);
    fe_add (r->y, p->x, p->y);
    fe_sqr (t0, r->y);
    fe_add (r->y, r->z, r->x);
    fe_sub (r->z, r->z, r->x);
    fe_sub (r->x, t0, r->y);
    fe_sub (r->t, r->t, r->z);
}

static void ge_p3_zero(ge_p3* h)
{
    fe_zero(h->x);
    fe_one(h->y);
    fe_one(h->z);
    fe_zero(h->t);
}

static void ge_p3_dbl(ge_p1p1* r, const ge_p3* p)
{
    ge_p2 q;
    ge_p3_to_p2(&q, p);
    ge_p2_dbl(r, &q);
}

static void ge_p1p1_to_p2(ge_p2* r, const ge_p1p1 *p)
{
    fe_mul(r->x, p->x, p->t);
    fe_mul(r->y, p->y, p->z);
    fe_mul(r->z, p->z, p->t);
}

static void ge_p1p1_to_p3(ge_p3* r, const ge_p1p1* p)
{
    fe_mul(r->x, p->x, p->t);
    fe_mul(r->y, p->y, p->z);
    fe_mul(r->z, p->z, p->t);
    fe_mul(r->t, p->x, p->y);
}

static void ge_add(ge_p1p1* r, const ge_p3* p, const ge_cached* q)
{
    fe t0;

    fe_add(r->x, p->y, p->x);
    fe_sub(r->y, p->y, p->x);
    fe_mul(r->z, r->x, q->y_p_x);
    fe_mul(r->y, r->y, q->y_m_x);
    fe_mul(r->t, q->t2d, p->t);
    fe_mul(r->x, p->z, q->z);
    fe_add(t0, r->x, r->x);
    fe_sub(r->x, r->z, r->y);
    fe_add(r->y, r->z, r->y);
    fe_add(r->z, t0, r->t);
    fe_sub(r->t, t0, r->t);
}

static void ge_sub(ge_p1p1* r, const ge_p3* p, const ge_cached* q)
{
    fe t0;

    fe_add(r->x, p->y, p->x);
    fe_sub(r->y, p->y, p->x);
    fe_mul(r->z, r->x, q->y_m_x);
    fe_mul(r->y, r->y, q->y_p_x);
    fe_mul(r->t, q->t2d, p->t);
    fe_mul(r->x, p->z, q->z);
    fe_add(t0, r->x, r->x);
    fe_sub(r->x, r->z, r->y);
    fe_add(r->y, r->z, r->y);
    fe_sub(r->z, t0, r->t);
    fe_add(r->t, t0, r->t);
}

static void ge_p3_to_cached(ge_cached* r, const ge_p3 *p)
{
    fe_add (r->y_p_x, p->y, p->x);
    fe_sub (r->y_m_x, p->y, p->x);
    fe_copy(r->z, p->z);
    fe_mul (r->t2d, p->t, d2);
}

static void ge_mul_l(ge_p3* r, const ge_p3 *A)
{
    static const char aslide[253] = {
         13,   0,   0,   0,   0,  -1,   0,   0,   0,   0, -11,
          0,   0,   0,   0,   0,   0,  -5,   0,   0,   0,   0,
          0,   0,  -3,   0,   0,   0,   0, -13,   0,   0,   0,
          0,   7,   0,   0,   0,   0,   0,   3,   0,   0,   0,
          0, -13,   0,   0,   0,   0,   5,   0,   0,   0,   0,
          0,   0,   0,   0,  11,   0,   0,   0,   0,   0,  11,
          0,   0,   0,   0, -13,   0,   0,   0,   0,   0,   0,
         -3,   0,   0,   0,   0,   0,  -1,   0,   0,   0,   0,
          3,   0,   0,   0,   0, -11,   0,   0,   0,   0,   0,
          0,   0,  15,   0,   0,   0,   0,   0,  -1,   0,   0,
          0,   0,  -1,   0,   0,   0,   0,   7,   0,   0,   0,
          0,   5,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   1
    };
    ge_cached Ai[8];
    ge_p1p1 t;
    ge_p3 u, A2;
    int32_t i;

    ge_p3_to_cached(&Ai[0], A);
    ge_p3_dbl(&t, A);
    ge_p1p1_to_p3(&A2, &t);
    ge_add(&t, &A2, &Ai[0]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[1], &u);
    ge_add(&t, &A2, &Ai[1]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[2], &u);
    ge_add(&t, &A2, &Ai[2]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[3], &u);
    ge_add(&t, &A2, &Ai[3]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[4], &u);
    ge_add(&t, &A2, &Ai[4]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[5], &u);
    ge_add(&t, &A2, &Ai[5]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[6], &u);
    ge_add(&t, &A2, &Ai[6]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[7], &u);

    ge_p3_zero(r);
    for (i = 252; i >= 0; --i)
    {
        ge_p3_dbl(&t, r);

        if (aslide[i] > 0)
        {
            ge_p1p1_to_p3(&u, &t);
            ge_add(&t, &u, &Ai[aslide[i] / 2]);
        }
        else if (aslide[i] < 0)
        {
            ge_p1p1_to_p3(&u, &t);
            ge_sub(&t, &u, &Ai[(-aslide[i]) / 2]);
        }

        ge_p1p1_to_p3(r, &t);
    }
}

static void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q)
{
    fe t;

    fe_add(r->x, p->y,    p->x);
    fe_sub(r->y, p->y,    p->x);
    fe_mul(r->z, r->x,    q->y_p_x);
    fe_mul(r->y, r->y,    q->y_m_x);
    fe_mul(r->t, q->xy2d, p->t);
    fe_add(t,    p->z,    p->z);
    fe_sub(r->x, r->z,    r->y);
    fe_add(r->y, r->z,    r->y);
    fe_add(r->z, t,       r->t);
    fe_sub(r->t, t,       r->t);
}

static void ge_precomp_zero(ge_precomp* h)
{
    fe_one (h->y_p_x);
    fe_one (h->y_m_x);
    fe_zero(h->xy2d);
}

static void ge_cmov(ge_precomp* t, const ge_precomp* u, uint8_t b)
{
    fe_cmov(t->y_p_x, u->y_p_x, b);
    fe_cmov(t->y_m_x, u->y_m_x, b);
    fe_cmov(t->xy2d,  u->xy2d,  b);
}

static void ge_select(ge_precomp* t, const ge_precomp precomp[8], const char b)
{
    ge_precomp mt;
    const uint8_t bnegative = negative(b);
    const uint8_t babs = b - (((-bnegative) & b) * ((char) 1 << 1));

    ge_precomp_zero(t);
    ge_cmov(t, &precomp[0], equal(babs, 1));
    ge_cmov(t, &precomp[1], equal(babs, 2));
    ge_cmov(t, &precomp[2], equal(babs, 3));
    ge_cmov(t, &precomp[3], equal(babs, 4));
    ge_cmov(t, &precomp[4], equal(babs, 5));
    ge_cmov(t, &precomp[5], equal(babs, 6));
    ge_cmov(t, &precomp[6], equal(babs, 7));
    ge_cmov(t, &precomp[7], equal(babs, 8));
    fe_copy(mt.y_p_x, t->y_m_x);
    fe_copy(mt.y_m_x, t->y_p_x);
    fe_neg (mt.xy2d,   t->xy2d);
    ge_cmov(t, &mt, bnegative);
}

static void ge_select_base(ge_precomp* t, const int32_t pos, const char b)
{
    ge_select(t, base[pos], b);
}

/**
 * @brief Performs group element scalar multiplication.
 * 
 * @note The method computes h = [a] * B where
 * a is 32-byte array and B is Ed25519 base-point.
 * 
 * @param h the output group element
 * @param a the scalar input, 32 bytes in size
 */
void ge_scalarmult_base(ge_p3* h, const uint8_t* a)
{
    char e[64], carry;
    ge_p1p1 r;
    ge_p2 s;
    ge_precomp t;
    int32_t i;

    for (i = 0; i < 32; i++)
    {
        e[2 * i]     =  a[i]       & 0x0f;
        e[2 * i + 1] = (a[i] >> 4) & 0x0f;
    }

    for (i = 0, carry = 0; i < 63; i++)
    {
        e[i]   += carry;
        carry   = e[i] + 8;
        carry >>= 4;
        e[i]   -= carry * ((char)1 << 4);
    }
    e[63] += carry;

    ge_p3_zero(h);
    for (i = 1; i < 64; i += 2)
    {
        ge_select_base(&t, i / 2, e[i]);
        ge_madd(&r, h, &t);
        ge_p1p1_to_p3(h, &r);
    }

    ge_p3_dbl(&r, h);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p3(h, &r);

    for (i = 0; i < 64; i += 2)
    {
        ge_select_base(&t, i / 2, e[i]);
        ge_madd(&r, h, &t);
        ge_p1p1_to_p3(h, &r);
    }
}

/**
 * @brief Serialises the group element h to byte-array.
 * 
 * @param s the output byte-array, 32 bytes in size
 * @param h the input group element
 */
void ge_p3_tobytes(uint8_t *s, const ge_p3 *h)
{
    fe r, x, y;

    fe_inv(r, h->z);
    fe_mul(x, h->x, r);
    fe_mul(y, h->y, r);
    
    fe_tobytes(s, y);
    s[31] ^= fe_isnegative(x) << 7;
}

/**
 * @brief Deserialises the point P to a group-element in
 * extended representation.
 * 
 * @param h the deserialised group element
 * @param P byte-array representation of point P 
 * @return 0 on success, non-zero otherwise
 */
int32_t ge_frombytes(ge_p3* h, const uint8_t* P)
{
    fe u, v, v3, x;
    fe m_root_check, p_root_check;
    fe x_sqrt_m_1, neg_x;
    bool has_m_root, has_p_root;

    fe_frombytes(h->y, P);

    fe_one(h->z);
    fe_sqr(u, h->y);
    fe_mul(v, u, d);
    fe_sub(u, u, h->z);
    fe_add(v, v, h->z);

    fe_sqr(v3, v);
    fe_mul(v3, v3, v);
    fe_sqr(h->x, v3);
    fe_mul(h->x, h->x, v);
    fe_mul(h->x, h->x, u);

    fe_pow_2e252m3(h->x, h->x);
    fe_mul(h->x, h->x, v3);
    fe_mul(h->x, h->x, u);

    fe_sqr(x, h->x);
    fe_mul(x, x, v);

    fe_sub(m_root_check, x, u);
    has_m_root = fe_iszero(m_root_check); /* should be false */
    fe_add(p_root_check, x, u);
    has_p_root = fe_iszero(p_root_check); /* should be true */

    fe_mul(x_sqrt_m_1, h->x, sqrt_m_1);
    fe_cmov(h->x, x_sqrt_m_1, 1 - has_m_root);

    fe_neg(neg_x, h->x);
    fe_cmov(h->x, neg_x, fe_isnegative(h->x) ^ (P[31] >> 7));
    fe_mul(h->t, h->x, h->y);

    return (has_m_root | has_p_root) - 1;
}

/**
 * @brief Checks whether or not the group-element lies on the main subgroup.
 * 
 * @param h the group element
 * @return true if the group element lies on the main subgroup
 * @return false otherwise
 */
bool ge_is_on_main_subgroup(const ge_p3* h)
{
    ge_p3 pl;

    ge_mul_l(&pl, h);

    return fe_iszero(pl.x);
}

/**
 * @brief Checks whether or not the point P has a small order.
 * 
 * @param P byte-array representation of point P 
 * @return true if the point P has a small order
 * @return false otherwise
 */
bool ge_has_small_order(const uint8_t* P)
{
#if defined(_MSC_VER)
	__declspec(align(16))
#elif defined(__GNUC__)
	__attribute__((aligned(16)))
#endif
	static const uint8_t blacklist[][32] =
    {
        /* 0 (order 4) */
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        /* 1 (order 1) */
        {
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        /* 2707385501144840649318225287225658788936804 */
        /* 267575313519463743609750303402022 (order 8) */
        {
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
            0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
            0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
            0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05
        },
        /* 55188659117513257062467267217118295137698188 */
        /* 065244968500265048394206261417927 (order 8)  */
        {
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
            0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
            0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
            0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a
        },
        /* p-1 (order 2) */
        {
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
        },
        /* p (=0, order 4) */
        {
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
        },
        /* p+1 (=1, order 1) */
        {
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
        }
    };
    uint8_t c[7] = {0};
    uint32_t k;
    int32_t i, j;

    for (j = 0; j < 31; j++)
    {
        for (i = 0; i < (int)(sizeof(blacklist) / sizeof(blacklist[0])); i++)
        {
            c[i] |= P[j] ^ blacklist[i][j];
        }
    }
    for (i = 0; i < (int)(sizeof(blacklist) / sizeof(blacklist[0])); i++)
    {
        c[i] |= (P[j] & 0x7f) ^ blacklist[i][j];
    }
    k = 0;
    for (i = 0; i < (int)(sizeof(blacklist) / sizeof(blacklist[0])); i++)
    {
        k |= (c[i] - 1);
    }
    return (bool)(1 & (k >> 8));
}
