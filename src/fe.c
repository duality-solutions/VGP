#include "fe.h"
#include "utils.h"

typedef int64_t fe64[10];

#define FE_COPY(u, v) {\
    u[0] = v[0]; \
    u[1] = v[1]; \
    u[2] = v[2]; \
    u[3] = v[3]; \
    u[4] = v[4]; \
    u[5] = v[5]; \
    u[6] = v[6]; \
    u[7] = v[7]; \
    u[8] = v[8]; \
    u[9] = v[9]; \
    }

#define FE_ADD(w, u, v) {\
    w[0] = u[0] + v[0]; \
    w[1] = u[1] + v[1]; \
    w[2] = u[2] + v[2]; \
    w[3] = u[3] + v[3]; \
    w[4] = u[4] + v[4]; \
    w[5] = u[5] + v[5]; \
    w[6] = u[6] + v[6]; \
    w[7] = u[7] + v[7]; \
    w[8] = u[8] + v[8]; \
    w[9] = u[9] + v[9]; \
    }

#define FE_SUB(w, u, v) {\
    w[0] = u[0] - v[0]; \
    w[1] = u[1] - v[1]; \
    w[2] = u[2] - v[2]; \
    w[3] = u[3] - v[3]; \
    w[4] = u[4] - v[4]; \
    w[5] = u[5] - v[5]; \
    w[6] = u[6] - v[6]; \
    w[7] = u[7] - v[7]; \
    w[8] = u[8] - v[8]; \
    w[9] = u[9] - v[9]; \
    }

#define FE_XOR(w, u, v) {\
    w[0] = u[0] ^ v[0]; \
    w[1] = u[1] ^ v[1]; \
    w[2] = u[2] ^ v[2]; \
    w[3] = u[3] ^ v[3]; \
    w[4] = u[4] ^ v[4]; \
    w[5] = u[5] ^ v[5]; \
    w[6] = u[6] ^ v[6]; \
    w[7] = u[7] ^ v[7]; \
    w[8] = u[8] ^ v[8]; \
    w[9] = u[9] ^ v[9]; \
    }

#define FE_AND_CONST(w, u, v) {\
    w[0] = u[0] & v; \
    w[1] = u[1] & v; \
    w[2] = u[2] & v; \
    w[3] = u[3] & v; \
    w[4] = u[4] & v; \
    w[5] = u[5] & v; \
    w[6] = u[6] & v; \
    w[7] = u[7] & v; \
    w[8] = u[8] & v; \
    w[9] = u[9] & v; \
    }

#define FE_MUL_CONST(w, u, v) {\
    w[0] = u[0] * v; \
    w[1] = u[1] * v; \
    w[2] = u[2] * v; \
    w[3] = u[3] * v; \
    w[4] = u[4] * v; \
    w[5] = u[5] * v; \
    w[6] = u[6] * v; \
    w[7] = u[7] * v; \
    w[8] = u[8] * v; \
    w[9] = u[9] * v; \
    }

#define FE_CONST_MUL(w, u, v) {\
    w[0] = u * v[0]; \
    w[1] = u * v[1]; \
    w[2] = u * v[2]; \
    w[3] = u * v[3]; \
    w[4] = u * v[4]; \
    w[5] = u * v[5]; \
    w[6] = u * v[6]; \
    w[7] = u * v[7]; \
    w[8] = u * v[8]; \
    w[9] = u * v[9]; \
    }

static uint64_t big_endian_load_3(const uint8_t *in)
{
    uint64_t result;
    result  =  (uint64_t)in[0];
    result |= ((uint64_t)in[1]) <<  8;
    result |= ((uint64_t)in[2]) << 16;
    return result;
}

static uint64_t big_endian_load_4(const uint8_t *in)
{
    uint64_t result;
    result  =  (uint64_t)in[0];
    result |= ((uint64_t)in[1]) <<  8;
    result |= ((uint64_t)in[2]) << 16;
    result |= ((uint64_t)in[3]) << 24;
    return result;
}

/**
 * @brief Zeros a field element h.
 * 
 * @param h The field element to be zero-ed
 */
void fe_zero(fe h)
{
    crypto_memzero(h, 10*sizeof(int32_t));    
}

/**
 * @brief Set the field element h to 1.
 * 
 * @param h The field element to be set
 */
void fe_one(fe h)
{
    fe_zero(h);
    h[0] = 1;
}

/**
 * @brief Copies field element v to u.
 * 
 * @param u The destination field element
 * @param v The source field element
 */
void fe_copy(fe u, const fe v)
{
    u[0] = v[0];
    u[1] = v[1];
    u[2] = v[2];
    u[3] = v[3];
    u[4] = v[4];
    u[5] = v[5];
    u[6] = v[6];
    u[7] = v[7];
    u[8] = v[8];
    u[9] = v[9];
}

/**
 * @brief Sets field element f to g if cond is non-zero.
 * 
 * @note The field element f is unchanged if cond is zero.
 * 
 * @param f The field element f
 * @param g The field element g
 * @param cond The condition
 */
void fe_cmov(fe f, const fe g, uint32_t cond)
{
    const uint32_t mask = (uint32_t) (-(int32_t) cond);
    fe u, v;

    FE_COPY(u, f);
    FE_XOR(v, u, g);
    FE_AND_CONST(v, v, mask);
    FE_XOR(f, u, v);
}

/**
 * @brief Add field elements f and g
 * 
 * @note h = f + g
 * @note It is acceptable to overlap h with f or g.
 * 
 * @param h The output of addition
 * @param f One of the input to addtion
 * @param g The other input to addition
 */
void fe_add(fe h, const fe f, const fe g)
{
    fe u, v, w;
    FE_COPY(u, f);
    FE_COPY(v, g);
    FE_ADD(w, u, v);
    FE_COPY(h, w);
}

/**
 * @brief Subtracts field element g from field element f.
 * 
 * @param h The subtraction output
 * @param f The input field element
 * @param g Another input field element
 */
void fe_sub(fe h, const fe f, const fe g)
{
    fe u, v, w;
    FE_COPY(u, f);
    FE_COPY(v, g);
    FE_SUB(w, u, v);
    FE_COPY(h, w);
}

/**
 * @brief Swaps field element f and g if and only if ctrl is true.
 * 
 * @param f An input field element
 * @param g Another input field element
 * @param ctrl Swap control flag
 */
void fe_swap(fe f, fe g, uint32_t ctrl)
{
    uint32_t b = ctrl;
    fe u, v, w;
    FE_COPY(u, f);
    FE_COPY(v, g);
    FE_XOR(w, u, v);
#if defined(_MSC_VER)
	b = (uint32_t) (-1) * b;
#else
	b = -b;
#endif
    FE_AND_CONST(w, w, b);
    FE_XOR(f, u, w);
    FE_XOR(g, v, w);
}

/**
 * @brief Multiplies field elements f and g to produce h.
 * 
 * @param h The product of field multiplication
 * @param f The multiplier
 * @param g The multiplicant
 */
void fe_mul(fe h, const fe f, const fe g)
{
    fe u, v;
    fe x19, x2;
    fe64 c, w, w0;
    fe64 w1, w2, w3;
    fe64 w4, w5, w6;
    fe64 w7, w8, w9;
    FE_COPY(u, f);
    FE_COPY(v, g);
    x19[1]= 19 * v[1];
    x19[2]= 19 * v[2];
    x19[3]= 19 * v[3];
    x19[4]= 19 * v[4];
    x19[5]= 19 * v[5];
    x19[6]= 19 * v[6];
    x19[7]= 19 * v[7];
    x19[8]= 19 * v[8];
    x19[9]= 19 * v[9];
    x2[1] =  2 * u[1];
    x2[3] =  2 * u[3];
    x2[5] =  2 * u[5];
    x2[7] =  2 * u[7];
    x2[9] =  2 * u[9];
    FE_CONST_MUL(w0, u[0], (int64_t)v);
    w1[0] =  u[1] * (int64_t)  v[0];
    w1[1] = x2[1] * (int64_t)  v[1];
    w1[2] =  u[1] * (int64_t)  v[2];
    w1[3] = x2[1] * (int64_t)  v[3];
    w1[4] =  u[1] * (int64_t)  v[4];
    w1[5] = x2[1] * (int64_t)  v[5];
    w1[6] =  u[1] * (int64_t)  v[6];
    w1[7] = x2[1] * (int64_t)  v[7];
    w1[8] =  u[1] * (int64_t)  v[8];
    w1[9] = x2[1] * (int64_t)x19[9];
    w2[0] =  u[2] * (int64_t)  v[0];
    w2[1] =  u[2] * (int64_t)  v[1];
    w2[2] =  u[2] * (int64_t)  v[2];
    w2[3] =  u[2] * (int64_t)  v[3];
    w2[4] =  u[2] * (int64_t)  v[4];
    w2[5] =  u[2] * (int64_t)  v[5];
    w2[6] =  u[2] * (int64_t)  v[6];
    w2[7] =  u[2] * (int64_t)  v[7];
    w2[8] =  u[2] * (int64_t)x19[8];
    w2[9] =  u[2] * (int64_t)x19[9];
    w3[0] =  u[3] * (int64_t)  v[0];
    w3[1] = x2[3] * (int64_t)  v[1];
    w3[2] =  u[3] * (int64_t)  v[2];
    w3[3] = x2[3] * (int64_t)  v[3];
    w3[4] =  u[3] * (int64_t)  v[4];
    w3[5] = x2[3] * (int64_t)  v[5];
    w3[6] =  u[3] * (int64_t)  v[6];
    w3[7] = x2[3] * (int64_t)x19[7];
    w3[8] =  u[3] * (int64_t)x19[8];
    w3[9] = x2[3] * (int64_t)x19[9];
    w4[0] =  u[4] * (int64_t)  v[0];
    w4[1] =  u[4] * (int64_t)  v[1];
    w4[2] =  u[4] * (int64_t)  v[2];
    w4[3] =  u[4] * (int64_t)  v[3];
    w4[4] =  u[4] * (int64_t)  v[4];
    w4[5] =  u[4] * (int64_t)  v[5];
    w4[6] =  u[4] * (int64_t)x19[6];
    w4[7] =  u[4] * (int64_t)x19[7];
    w4[8] =  u[4] * (int64_t)x19[8];
    w4[9] =  u[4] * (int64_t)x19[9];
    w5[0] =  u[5] * (int64_t)  v[0];
    w5[1] = x2[5] * (int64_t)  v[1];
    w5[2] =  u[5] * (int64_t)  v[2];
    w5[3] = x2[5] * (int64_t)  v[3];
    w5[4] =  u[5] * (int64_t)  v[4];
    w5[5] = x2[5] * (int64_t)x19[5];
    w5[6] =  u[5] * (int64_t)x19[6];
    w5[7] = x2[5] * (int64_t)x19[7];
    w5[8] =  u[5] * (int64_t)x19[8];
    w5[9] = x2[5] * (int64_t)x19[9];
    w6[0] =  u[6] * (int64_t)  v[0];
    w6[1] =  u[6] * (int64_t)  v[1];
    w6[2] =  u[6] * (int64_t)  v[2];
    w6[3] =  u[6] * (int64_t)  v[3];
    w6[4] =  u[6] * (int64_t)x19[4];
    w6[5] =  u[6] * (int64_t)x19[5];
    w6[6] =  u[6] * (int64_t)x19[6];
    w6[7] =  u[6] * (int64_t)x19[7];
    w6[8] =  u[6] * (int64_t)x19[8];
    w6[9] =  u[6] * (int64_t)x19[9];
    w7[0] =  u[7] * (int64_t)  v[0];
    w7[1] = x2[7] * (int64_t)  v[1];
    w7[2] =  u[7] * (int64_t)  v[2];
    w7[3] = x2[7] * (int64_t)x19[3];
    w7[4] =  u[7] * (int64_t)x19[4];
    w7[5] = x2[7] * (int64_t)x19[5];
    w7[6] =  u[7] * (int64_t)x19[6];
    w7[7] = x2[7] * (int64_t)x19[7];
    w7[8] =  u[7] * (int64_t)x19[8];
    w7[9] = x2[7] * (int64_t)x19[9];
    w8[0] =  u[8] * (int64_t)  v[0];
    w8[1] =  u[8] * (int64_t)  v[1];
    w8[2] =  u[8] * (int64_t)x19[2];
    w8[3] =  u[8] * (int64_t)x19[3];
    w8[4] =  u[8] * (int64_t)x19[4];
    w8[5] =  u[8] * (int64_t)x19[5];
    w8[6] =  u[8] * (int64_t)x19[6];
    w8[7] =  u[8] * (int64_t)x19[7];
    w8[8] =  u[8] * (int64_t)x19[8];
    w8[9] =  u[8] * (int64_t)x19[9];
    w9[0] =  u[9] * (int64_t)  v[0];
    w9[1] = x2[9] * (int64_t)x19[1];
    w9[2] =  u[9] * (int64_t)x19[2];
    w9[3] = x2[9] * (int64_t)x19[3];
    w9[4] =  u[9] * (int64_t)x19[4];
    w9[5] = x2[9] * (int64_t)x19[5];
    w9[6] =  u[9] * (int64_t)x19[6];
    w9[7] = x2[9] * (int64_t)x19[7];
    w9[8] =  u[9] * (int64_t)x19[8];
    w9[9] = x2[9] * (int64_t)x19[9];
    w[0]  = w0[0] + w1[9] + w2[8] + w3[7] + w4[6] + w5[5] + w6[4] + w7[3] + w8[2] + w9[1];
    w[1]  = w0[1] + w1[0] + w2[9] + w3[8] + w4[7] + w5[6] + w6[5] + w7[4] + w8[3] + w9[2];
    w[2]  = w0[2] + w1[1] + w2[0] + w3[9] + w4[8] + w5[7] + w6[6] + w7[5] + w8[4] + w9[3];
    w[3]  = w0[3] + w1[2] + w2[1] + w3[0] + w4[9] + w5[8] + w6[7] + w7[6] + w8[5] + w9[4];
    w[4]  = w0[4] + w1[3] + w2[2] + w3[1] + w4[0] + w5[9] + w6[8] + w7[7] + w8[6] + w9[5];
    w[5]  = w0[5] + w1[4] + w2[3] + w3[2] + w4[1] + w5[0] + w6[9] + w7[8] + w8[7] + w9[6];
    w[6]  = w0[6] + w1[5] + w2[4] + w3[3] + w4[2] + w5[1] + w6[0] + w7[9] + w8[8] + w9[7];
    w[7]  = w0[7] + w1[6] + w2[5] + w3[4] + w4[3] + w5[2] + w6[1] + w7[0] + w8[9] + w9[8];
    w[8]  = w0[8] + w1[7] + w2[6] + w3[5] + w4[4] + w5[3] + w6[2] + w7[1] + w8[0] + w9[9];
    w[9]  = w0[9] + w1[8] + w2[7] + w3[6] + w4[5] + w5[4] + w6[3] + w7[2] + w8[1] + w9[0];

    c[0]  = (w[0] + (int64_t)(1 << 25)) >> 26;
    w[1] += c[0];
    w[0] -= c[0] << 26;
    c[4]  = (w[4] + (int64_t)(1 << 25)) >> 26;
    w[5] += c[4];
    w[4] -= c[4] << 26;

    c[1]  = (w[1] + (int64_t)(1 << 24)) >> 25;
    w[2] += c[1];
    w[1] -= c[1] << 25;
    c[5]  = (w[5] + (int64_t)(1 << 24)) >> 25;
    w[6] += c[5];
    w[5] -= c[5] << 25;

    c[2]  = (w[2] + (int64_t)(1 << 25)) >> 26;
    w[3] += c[2];
    w[2] -= c[2] << 26;
    c[6]  = (w[6] + (int64_t)(1 << 25)) >> 26;
    w[7] += c[6];
    w[6] -= c[6] << 26;

    c[3]  = (w[3] + (int64_t)(1 << 24)) >> 25;
    w[4] += c[3];
    w[3] -= c[3] << 25;
    c[7]  = (w[7] + (int64_t)(1 << 24)) >> 25;
    w[8] += c[7];
    w[7] -= c[7] << 25;

    c[4]  = (w[4] + (int64_t)(1 << 25)) >> 26;
    w[5] += c[4];
    w[4] -= c[4] << 26;
    c[8]  = (w[8] + (int64_t)(1 << 25)) >> 26;
    w[9] += c[8];
    w[8] -= c[8] << 26;

    c[9]  = (w[9] + (int64_t)(1 << 24)) >> 25;
    w[0] += c[9] * 19;
    w[9] -= c[9] << 25;
    c[0]  = (w[0] + (int64_t)(1 << 25)) >> 26;
    w[1] += c[0];
    w[0] -= c[0] << 26;

    FE_COPY(h, (int32_t)w);
}

/**
 * @brief Multiplies field element f with 121666.
 * 
 * @param h The product of the multiplication
 * @param f The multiplier
 */
void fe_mul121666(fe h, const fe f)
{
    fe u;
    fe64 v, c;
    FE_COPY(u, f);
    FE_MUL_CONST(v, u, (int64_t)121666);

    c[9]  = (v[9] + (int64_t)(1 << 24)) >> 25;
    v[0] += c[9] * 19;
    v[9] -= c[9] << 25;
    c[1]  = (v[1] + (int64_t)(1 << 24)) >> 25;
    v[2] += c[1];
    v[1] -= c[1] << 25;
    
    c[3]  = (v[3] + (int64_t)(1 << 24)) >> 25;
    v[4] += c[3];
    v[3] -= c[3] << 25;
    c[5]  = (v[5] + (int64_t)(1 << 24)) >> 25;
    v[6] += c[5];
    v[5] -= c[5] << 25;
    
    c[7]  = (v[7] + (int64_t)(1 << 24)) >> 25;
    v[8] += c[7];
    v[7] -= c[7] << 25;
    c[0]  = (v[0] + (int64_t)(1 << 25)) >> 26;
    v[1] += c[0];
    v[0] -= c[0] << 26;
    
    c[2]  = (v[2] + (int64_t)(1 << 25)) >> 26;
    v[3] += c[2];
    v[2] -= c[2] << 26;
    c[4]  = (v[4] + (int64_t)(1 << 25)) >> 26;
    v[5] += c[4];
    v[4] -= c[4] << 26;
    
    c[6]  = (v[6] + (int64_t)(1 << 25)) >> 26;
    v[7] += c[6];
    v[6] -= c[6] << 26;
    c[8]  = (v[8] + (int64_t)(1 << 25)) >> 26;
    v[9] += c[8];
    v[8] -= c[8] << 26;

    FE_COPY(h, (int32_t)v);
}

/**
 * @brief Returns the squared value of field element f.
 * 
 * @param h The squared output
 * @param f The input field element
 */
void fe_sqr(fe h, const fe f)
{
    fe u, x2, xa;
    fe64 v0, v1, v2;
    fe64 v3, v4, v5;
    fe64 v6, v7, v8;
    fe64 v9, w, c;
    FE_COPY(u, f);
    x2[0] =     2 * u[0];
    x2[1] =     2 * u[1];
    x2[2] =     2 * u[2];
    x2[3] =     2 * u[3];
    x2[4] =     2 * u[4];
    x2[5] =     2 * u[5];
    x2[6] =     2 * u[6];
    x2[7] =     2 * u[7];
    xa[5] =    38 * u[5];
    xa[6] =    19 * u[6];
    xa[7] =    38 * u[7];
    xa[8] =    19 * u[8];
    xa[9] =    38 * u[9];
    v0[0] =  u[0] * (int64_t) u[0];
    v0[1] = x2[0] * (int64_t) u[1];
    v0[2] = x2[0] * (int64_t) u[2];
    v0[3] = x2[0] * (int64_t) u[3];
    v0[4] = x2[0] * (int64_t) u[4];
    v0[5] = x2[0] * (int64_t) u[5];
    v0[6] = x2[0] * (int64_t) u[6];
    v0[7] = x2[0] * (int64_t) u[7];
    v0[8] = x2[0] * (int64_t) u[8];
    v0[9] = x2[0] * (int64_t) u[9];
    v1[1] = x2[1] * (int64_t) u[1];
    v1[2] = x2[1] * (int64_t) u[2];
    v1[3] = x2[1] * (int64_t)x2[3];
    v1[4] = x2[1] * (int64_t) u[4];
    v1[5] = x2[1] * (int64_t)x2[5];
    v1[6] = x2[1] * (int64_t) u[6];
    v1[7] = x2[1] * (int64_t)x2[7];
    v1[8] = x2[1] * (int64_t) u[8];
    v1[9] = x2[1] * (int64_t)xa[9];
    v2[2] =  u[2] * (int64_t) u[2];
    v2[3] = x2[2] * (int64_t) u[3];
    v2[4] = x2[2] * (int64_t) u[4];
    v2[5] = x2[2] * (int64_t) u[5];
    v2[6] = x2[2] * (int64_t) u[6];
    v2[7] = x2[2] * (int64_t) u[7];
    v2[8] = x2[2] * (int64_t)xa[8];
    v2[9] =  u[2] * (int64_t)xa[9];
    v3[3] = x2[3] * (int64_t) u[3];
    v3[4] = x2[3] * (int64_t) u[4];
    v3[5] = x2[3] * (int64_t)x2[5];
    v3[6] = x2[3] * (int64_t) u[6];
    v3[7] = x2[3] * (int64_t)xa[7];
    v3[8] = x2[3] * (int64_t)xa[8];
    v3[9] = x2[3] * (int64_t)xa[9];
    v4[4] =  u[4] * (int64_t) u[4];
    v4[5] = x2[4] * (int64_t) u[5];
    v4[6] = x2[4] * (int64_t)xa[6];
    v4[7] =  u[4] * (int64_t)xa[7];
    v4[8] = x2[4] * (int64_t)xa[8];
    v4[9] =  u[4] * (int64_t)xa[9];
    v5[5] =  u[5] * (int64_t)xa[5];
    v5[6] = x2[5] * (int64_t)xa[6];
    v5[7] = x2[5] * (int64_t)xa[7];
    v5[8] = x2[5] * (int64_t)xa[8];
    v5[9] = x2[5] * (int64_t)xa[9];
    v6[6] =  u[6] * (int64_t)xa[6];
    v6[7] =  u[6] * (int64_t)xa[7];
    v6[8] = x2[6] * (int64_t)xa[8];
    v6[9] =  u[6] * (int64_t)xa[9];
    v7[7] =  u[7] * (int64_t)xa[7];
    v7[8] = x2[7] * (int64_t)xa[8];
    v7[9] = x2[7] * (int64_t)xa[9];
    v8[8] =  u[8] * (int64_t)xa[8];
    v8[9] =  u[8] * (int64_t)xa[9];
    v9[9] =  u[9] * (int64_t)xa[9];
    w[0] = v0[0] + v1[9] + v2[8] + v3[7] + v4[6] + v5[5];
    w[1] = v0[1] + v2[9] + v3[8] + v4[7] + v5[6];
    w[2] = v0[2] + v1[1] + v3[9] + v4[8] + v5[7] + v6[6];
    w[3] = v0[3] + v1[2] + v4[9] + v5[8] + v6[7];
    w[4] = v0[4] + v1[3] + v2[2] + v5[9] + v6[8] + v7[7];
    w[5] = v0[5] + v1[4] + v2[3] + v6[9] + v7[8];
    w[6] = v0[6] + v1[5] + v2[4] + v3[3] + v7[9] + v8[8];
    w[7] = v0[7] + v1[6] + v2[5] + v3[4] + v8[9];
    w[8] = v0[8] + v1[7] + v2[6] + v3[5] + v4[4] + v9[9];
    w[9] = v0[9] + v1[8] + v2[7] + v3[6] + v4[5];

    c[0]  = (w[0] + (int64_t)(1 << 25)) >> 26;
    w[1] += c[0];
    w[0] -= c[0] << 26;
    c[4]  = (w[4] + (int64_t)(1 << 25)) >> 26;
    w[5] += c[4];
    w[4] -= c[4] << 26;

    c[1]  = (w[1] + (int64_t)(1 << 24)) >> 25;
    w[2] += c[1];
    w[1] -= c[1] << 25;
    c[5]  = (w[5] + (int64_t)(1 << 24)) >> 25;
    w[6] += c[5];
    w[5] -= c[5] << 25;

    c[2]  = (w[2] + (int64_t)(1 << 25)) >> 26;
    w[3] += c[2];
    w[2] -= c[2] << 26;
    c[6]  = (w[6] + (int64_t)(1 << 25)) >> 26;
    w[7] += c[6];
    w[6] -= c[6] << 26;

    c[3]  = (w[3] + (int64_t)(1 << 24)) >> 25;
    w[4] += c[3];
    w[3] -= c[3] << 25;
    c[7]  = (w[7] + (int64_t)(1 << 24)) >> 25;
    w[8] += c[7];
    w[7] -= c[7] << 25;

    c[4]  = (w[4] + (int64_t)(1 << 25)) >> 26;
    w[5] += c[4];
    w[4] -= c[4] << 26;
    c[8]  = (w[8] + (int64_t)(1 << 25)) >> 26;
    w[9] += c[8];
    w[8] -= c[8] << 26;

    c[9]  = (w[9] + (int64_t)(1 << 24)) >> 25;
    w[0] += c[9] * 19;
    w[9] -= c[9] << 25;
    c[0]  = (w[0] + (int64_t)(1 << 25)) >> 26;
    w[1] += c[0];
    w[0] -= c[0] << 26;

    FE_COPY(h, (int32_t)w);
}

/**
 * @brief Returns the value of 2 * fe_sqr(f).
 * 
 * @param h The resulting output
 * @param f The input field element
 */
void fe_2sqr(fe h, const fe f)
{
    fe u, x2, xa;
    fe64 v0, v1, v2;
    fe64 v3, v4, v5;
    fe64 v6, v7, v8;
    fe64 v9, w, c;
    FE_COPY(u, f);
    x2[0] =     2 * u[0];
    x2[1] =     2 * u[1];
    x2[2] =     2 * u[2];
    x2[3] =     2 * u[3];
    x2[4] =     2 * u[4];
    x2[5] =     2 * u[5];
    x2[6] =     2 * u[6];
    x2[7] =     2 * u[7];
    xa[5] =    38 * u[5];
    xa[6] =    19 * u[6];
    xa[7] =    38 * u[7];
    xa[8] =    19 * u[8];
    xa[9] =    38 * u[9];
    v0[0] =  u[0] * (int64_t) u[0];
    v0[1] = x2[0] * (int64_t) u[1];
    v0[2] = x2[0] * (int64_t) u[2];
    v0[3] = x2[0] * (int64_t) u[3];
    v0[4] = x2[0] * (int64_t) u[4];
    v0[5] = x2[0] * (int64_t) u[5];
    v0[6] = x2[0] * (int64_t) u[6];
    v0[7] = x2[0] * (int64_t) u[7];
    v0[8] = x2[0] * (int64_t) u[8];
    v0[9] = x2[0] * (int64_t) u[9];
    v1[1] = x2[1] * (int64_t) u[1];
    v1[2] = x2[1] * (int64_t) u[2];
    v1[3] = x2[1] * (int64_t)x2[3];
    v1[4] = x2[1] * (int64_t) u[4];
    v1[5] = x2[1] * (int64_t)x2[5];
    v1[6] = x2[1] * (int64_t) u[6];
    v1[7] = x2[1] * (int64_t)x2[7];
    v1[8] = x2[1] * (int64_t) u[8];
    v1[9] = x2[1] * (int64_t)xa[9];
    v2[2] =  u[2] * (int64_t) u[2];
    v2[3] = x2[2] * (int64_t) u[3];
    v2[4] = x2[2] * (int64_t) u[4];
    v2[5] = x2[2] * (int64_t) u[5];
    v2[6] = x2[2] * (int64_t) u[6];
    v2[7] = x2[2] * (int64_t) u[7];
    v2[8] = x2[2] * (int64_t)xa[8];
    v2[9] =  u[2] * (int64_t)xa[9];
    v3[3] = x2[3] * (int64_t) u[3];
    v3[4] = x2[3] * (int64_t) u[4];
    v3[5] = x2[3] * (int64_t)x2[5];
    v3[6] = x2[3] * (int64_t) u[6];
    v3[7] = x2[3] * (int64_t)xa[7];
    v3[8] = x2[3] * (int64_t)xa[8];
    v3[9] = x2[3] * (int64_t)xa[9];
    v4[4] =  u[4] * (int64_t) u[4];
    v4[5] = x2[4] * (int64_t) u[5];
    v4[6] = x2[4] * (int64_t)xa[6];
    v4[7] =  u[4] * (int64_t)xa[7];
    v4[8] = x2[4] * (int64_t)xa[8];
    v4[9] =  u[4] * (int64_t)xa[9];
    v5[5] =  u[5] * (int64_t)xa[5];
    v5[6] = x2[5] * (int64_t)xa[6];
    v5[7] = x2[5] * (int64_t)xa[7];
    v5[8] = x2[5] * (int64_t)xa[8];
    v5[9] = x2[5] * (int64_t)xa[9];
    v6[6] =  u[6] * (int64_t)xa[6];
    v6[7] =  u[6] * (int64_t)xa[7];
    v6[8] = x2[6] * (int64_t)xa[8];
    v6[9] =  u[6] * (int64_t)xa[9];
    v7[7] =  u[7] * (int64_t)xa[7];
    v7[8] = x2[7] * (int64_t)xa[8];
    v7[9] = x2[7] * (int64_t)xa[9];
    v8[8] =  u[8] * (int64_t)xa[8];
    v8[9] =  u[8] * (int64_t)xa[9];
    v9[9] =  u[9] * (int64_t)xa[9];
    w[0] = 2 * (v0[0] + v1[9] + v2[8] + v3[7] + v4[6] + v5[5]);
    w[1] = 2 * (v0[1] + v2[9] + v3[8] + v4[7] + v5[6]);
    w[2] = 2 * (v0[2] + v1[1] + v3[9] + v4[8] + v5[7] + v6[6]);
    w[3] = 2 * (v0[3] + v1[2] + v4[9] + v5[8] + v6[7]);
    w[4] = 2 * (v0[4] + v1[3] + v2[2] + v5[9] + v6[8] + v7[7]);
    w[5] = 2 * (v0[5] + v1[4] + v2[3] + v6[9] + v7[8]);
    w[6] = 2 * (v0[6] + v1[5] + v2[4] + v3[3] + v7[9] + v8[8]);
    w[7] = 2 * (v0[7] + v1[6] + v2[5] + v3[4] + v8[9]);
    w[8] = 2 * (v0[8] + v1[7] + v2[6] + v3[5] + v4[4] + v9[9]);
    w[9] = 2 * (v0[9] + v1[8] + v2[7] + v3[6] + v4[5]);

    c[0]  = (w[0] + (int64_t)(1 << 25)) >> 26;
    w[1] += c[0];
    w[0] -= c[0] << 26;
    c[4]  = (w[4] + (int64_t)(1 << 25)) >> 26;
    w[5] += c[4];
    w[4] -= c[4] << 26;

    c[1]  = (w[1] + (int64_t)(1 << 24)) >> 25;
    w[2] += c[1];
    w[1] -= c[1] << 25;
    c[5]  = (w[5] + (int64_t)(1 << 24)) >> 25;
    w[6] += c[5];
    w[5] -= c[5] << 25;

    c[2]  = (w[2] + (int64_t)(1 << 25)) >> 26;
    w[3] += c[2];
    w[2] -= c[2] << 26;
    c[6]  = (w[6] + (int64_t)(1 << 25)) >> 26;
    w[7] += c[6];
    w[6] -= c[6] << 26;

    c[3]  = (w[3] + (int64_t)(1 << 24)) >> 25;
    w[4] += c[3];
    w[3] -= c[3] << 25;
    c[7]  = (w[7] + (int64_t)(1 << 24)) >> 25;
    w[8] += c[7];
    w[7] -= c[7] << 25;

    c[4]  = (w[4] + (int64_t)(1 << 25)) >> 26;
    w[5] += c[4];
    w[4] -= c[4] << 26;
    c[8]  = (w[8] + (int64_t)(1 << 25)) >> 26;
    w[9] += c[8];
    w[8] -= c[8] << 26;

    c[9]  = (w[9] + (int64_t)(1 << 24)) >> 25;
    w[0] += c[9] * 19;
    w[9] -= c[9] << 25;
    c[0]  = (w[0] + (int64_t)(1 << 25)) >> 26;
    w[1] += c[0];
    w[0] -= c[0] << 26;

    FE_COPY(h, (int32_t)w);
}

/**
 * @brief Inverts a field element.
 * 
 * @param x The output of inversion
 * @param z The field element to be inverted
 */
void fe_inv(fe x, const fe z)
{
    int32_t i;
    fe t0, t1, t2, t3;

    fe_sqr(t0, z);
    fe_sqr(t1, t0);
    fe_sqr(t1, t1);
    fe_mul(t1,  z, t1);
    fe_mul(t0, t0, t1);
    fe_sqr(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sqr(t2, t1);
    fe_sqr(t2, t2);
    fe_sqr(t2, t2);
    fe_sqr(t2, t2);
    fe_sqr(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sqr(t2, t1);
    for (i = 1; i < 10; ++i)
    {
        fe_sqr(t2, t2);
    }
    fe_mul(t2, t2, t1);
    fe_sqr(t3, t2);
    for (i = 1; i < 20; ++i)
    {
        fe_sqr(t3, t3);
    }
    fe_mul(t2, t3, t2);
    fe_sqr(t2, t2);
    for (i = 1; i < 10; ++i)
    {
        fe_sqr(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sqr(t2, t1);
    for (i = 1; i < 50; ++i)
    {
        fe_sqr(t2, t2);
    }
    fe_mul(t2, t2, t1);
    fe_sqr(t3, t2);
    for (i = 1; i < 100; ++i)
    {
        fe_sqr(t3, t3);
    }
    fe_mul(t2, t3, t2);
    fe_sqr(t2, t2);
    for (i = 1; i < 50; ++i)
    {
        fe_sqr(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sqr(t1, t1);
    fe_sqr(t1, t1);
    fe_sqr(t1, t1);
    fe_sqr(t1, t1);
    fe_sqr(t1, t1);
    fe_mul(x, t1, t0);
}

/**
 * @brief Computes z^(2^252 - 3).
 * 
 * @param x The output field element
 * @param z The input field element
 */
void fe_pow_2e252m3(fe x, const fe z)
{
    fe t0, t1, t2;
    int32_t i;

    fe_sqr(t0, z);
    fe_sqr(t1, t0);
    fe_sqr(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sqr(t0, t0);
    fe_mul(t0, t1, t0);
    fe_sqr(t1, t0);
    for (i = 1; i < 5; ++i)
    {
        fe_sqr(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sqr(t1, t0);
    for (i = 1; i < 10; ++i)
    {
        fe_sqr(t1, t1);
    }
    fe_mul(t1, t1, t0);
    fe_sqr(t2, t1);
    for (i = 1; i < 20; ++i)
    {
        fe_sqr(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sqr(t1, t1);
    for (i = 1; i < 10; ++i)
    {
        fe_sqr(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sqr(t1, t0);
    for (i = 1; i < 50; ++i)
    {
        fe_sqr(t1, t1);
    }
    fe_mul(t1, t1, t0);
    fe_sqr(t2, t1);
    for (i = 1; i < 100; ++i)
    {
        fe_sqr(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sqr(t1, t1);
    for (i = 1; i < 50; ++i)
    {
        fe_sqr(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sqr(t0, t0);
    fe_sqr(t0, t0);
    fe_mul(x, t0, z);
}

/**
 * @brief Negate a field element v.
 * 
 * @param u The negated field element
 * @param v The input field element
 */
void fe_neg(fe u, const fe v)
{
    FE_CONST_MUL(u, -1, v);
}

/**
 * @brief Returns true if field element v is zero, otherwise false.
 * 
 * @param v The field element to be checked
 * @return boolean value
 */
bool fe_iszero(const fe v)
{
    int32_t i;
    volatile uint8_t x = 0U;
    uint8_t u[32];

    fe_tobytes(u, v);

    for (i = 0; i < 32; ++i)
    {
        x |= u[i];
    }

    return (bool)(1 & ((x - 1) >> 8));
}

/**
 * @brief Returns true if field element v is negative, otherwise false.
 * 
 * @param v The field element to be checked
 * @return boolean value
 */
bool fe_isnegative(const fe v)
{
    uint8_t u[32];
    
    fe_tobytes(u, v);
    
    return (bool)(u[0] & 1);
}

/**
 * @brief Loads a field element from a byte-array.
 * 
 * @param h The field element loaded
 * @param s The input byte-array
 */
void fe_frombytes(fe h, const uint8_t *s)
{
    fe64 v, c;
    v[0] = big_endian_load_4(s);
    v[1] = big_endian_load_3(s + 4) << 6;
    v[2] = big_endian_load_3(s + 7) << 5;
    v[3] = big_endian_load_3(s + 10) << 3;
    v[4] = big_endian_load_3(s + 13) << 2;
    v[5] = big_endian_load_4(s + 16);
    v[6] = big_endian_load_3(s + 20) << 7;
    v[7] = big_endian_load_3(s + 23) << 5;
    v[8] = big_endian_load_3(s + 26) << 4;
    v[9] = (big_endian_load_3(s + 29) & 0x7fffff) << 2;

    c[9]  = (v[9] + (int64_t)(1 << 24)) >> 25;
    v[0] += c[9] * 19;
    v[9] -= c[9] << 25;
    c[1]  = (v[1] + (int64_t)(1 << 24)) >> 25;
    v[2] += c[1];
    v[1] -= c[1] << 25;
    c[3]  = (v[3] + (int64_t)(1 << 24)) >> 25;
    v[4] += c[3];
    v[3] -= c[3] << 25;
    c[5]  = (v[5] + (int64_t)(1 << 24)) >> 25;
    v[6] += c[5];
    v[5] -= c[5] << 25;
    c[7]  = (v[7] + (int64_t)(1 << 24)) >> 25;
    v[8] += c[7];
    v[7] -= c[7] << 25;

    c[0]  = (v[0] + (int64_t)(1 << 25)) >> 26;
    v[1] += c[0];
    v[0] -= c[0] << 26;
    c[2]  = (v[2] + (int64_t)(1 << 25)) >> 26;
    v[3] += c[2];
    v[2] -= c[2] << 26;
    c[4]  = (v[4] + (int64_t)(1 << 25)) >> 26;
    v[5] += c[4];
    v[4] -= c[4] << 26;
    c[6]  = (v[6] + (int64_t)(1 << 25)) >> 26;
    v[7] += c[6];
    v[6] -= c[6] << 26;
    c[8]  = (v[8] + (int64_t)(1 << 25)) >> 26;
    v[9] += c[8];
    v[8] -= c[8] << 26;

    FE_COPY(h, (int32_t)v);
}

/**
 * @brief Stores a field element h to a byte-array.
 * 
 * @param s The output byte-array
 * @param h The input field element
 */
void fe_tobytes(uint8_t *s, const fe h)
{
    fe v, c;
    int32_t q;
    
    FE_COPY(v, h);
    q = (19 * v[9] + (((int32_t)1) << 24)) >> 25;
    q = (v[0] + q) >> 26;
    q = (v[1] + q) >> 25;
    q = (v[2] + q) >> 26;
    q = (v[3] + q) >> 25;
    q = (v[4] + q) >> 26;
    q = (v[5] + q) >> 25;
    q = (v[6] + q) >> 26;
    q = (v[7] + q) >> 25;
    q = (v[8] + q) >> 26;
    q = (v[9] + q) >> 25;

    v[0] += 19 * q;

    c[0]  = v[0] >> 26;
    v[1] += c[0];
    v[0] -= c[0] << 26;
    c[1]  = v[1] >> 25;
    v[2] += c[1];
    v[1] -= c[1] << 25;
    c[2]  = v[2] >> 26;
    v[3] += c[2];
    v[2] -= c[2] << 26;
    c[3]  = v[3] >> 25;
    v[4] += c[3];
    v[3] -= c[3] << 25;
    c[4]  = v[4] >> 26;
    v[5] += c[4];
    v[4] -= c[4] << 26;
    c[5]  = v[5] >> 25;
    v[6] += c[5];
    v[5] -= c[5] << 25;
    c[6]  = v[6] >> 26;
    v[7] += c[6];
    v[6] -= c[6] << 26;
    c[7]  = v[7] >> 25;
    v[8] += c[7];
    v[7] -= c[7] << 25;
    c[8]  = v[8] >> 26;
    v[9] += c[8];
    v[8] -= c[8] << 26;
    c[9]  = v[9] >> 25;
    v[9] -= c[9] << 25;

    s[ 0] = v[0] >> 0;
    s[ 1] = v[0] >> 8;
    s[ 2] = v[0] >> 16;
    s[ 3] = (v[0] >> 24) | (v[1] << 2);
    s[ 4] = v[1] >> 6;
    s[ 5] = v[1] >> 14;
    s[ 6] = (v[1] >> 22) | (v[2] << 3);
    s[ 7] = v[2] >> 5;
    s[ 8] = v[2] >> 13;
    s[ 9] = (v[2] >> 21) | (v[3] << 5);
    s[10] = v[3] >> 3;
    s[11] = v[3] >> 11;
    s[12] = (v[3] >> 19) | (v[4] << 6);
    s[13] = v[4] >> 2;
    s[14] = v[4] >> 10;
    s[15] = v[4] >> 18;
    s[16] = v[5] >> 0;
    s[17] = v[5] >> 8;
    s[18] = v[5] >> 16;
    s[19] = (v[5] >> 24) | (v[6] << 1);
    s[20] = v[6] >> 7;
    s[21] = v[6] >> 15;
    s[22] = (v[6] >> 23) | (v[7] << 3);
    s[23] = v[7] >> 5;
    s[24] = v[7] >> 13;
    s[25] = (v[7] >> 21) | (v[8] << 4);
    s[26] = v[8] >> 4;
    s[27] = v[8] >> 12;
    s[28] = (v[8] >> 20) | (v[9] << 6);
    s[29] = v[9] >> 2;
    s[30] = v[9] >> 10;
    s[31] = v[9] >> 18;
}

/**
 * @brief Checks whether or not the point p has a small order.
 * 
 * @param p byte-array representation of point p 
 * @return true if the point p has a small order
 * @return false otherwise
 */
bool fe_has_small_order(const uint8_t* p)
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
        /* 3256062509165574317959836263561106312940081 */
        /* 15727848805560023387167927233504 (order 8)  */
        {
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
            0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
            0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
            0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00
        },
        /* 39382357235489614581723060781553021112529911 */
        /* 719440698176882885853963445705823 (order 8)  */
        {
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
            0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
            0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
            0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57
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
            c[i] |= p[j] ^ blacklist[i][j];
        }
    }
    for (i = 0; i < (int)(sizeof(blacklist) / sizeof(blacklist[0])); i++)
    {
        c[i] |= (p[j] & 0x7f) ^ blacklist[i][j];
    }
    k = 0;
    for (i = 0; i < (int)(sizeof(blacklist) / sizeof(blacklist[0])); i++)
    {
        k |= (c[i] - 1);
    }
    return (bool)(1 & (k >> 8));
}
