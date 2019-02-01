/**
 * @file sha512.c
 * 
 * @brief SUPERCOP implementation of SHA-512
 *
 */

#include "sha512.h"

#define SHR(x,c)    ((x) >> (c))
#define ROTR(x,c)   (((x) >> (c)) | ((x) << (64 - (c))))

#define Ch(x,y,z)   ((x & y) ^ (~x & z))
#define Maj(x,y,z)  ((x & y) ^ (x & z) ^ (y & z))
#define S0(x)       (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define S1(x)       (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define S2(x)       (ROTR(x,  1) ^ ROTR(x,  8) ^ SHR (x,  7))
#define S3(x)       (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR (x,  6))

#define M(w0, w14, w9, w1) \
                    w0 = S3(w14) + w9 + S2(w1) + w0;

#define EXPAND      M( w0, w14,  w9,  w1) \
                    M( w1, w15, w10,  w2) \
                    M( w2,  w0, w11,  w3) \
                    M( w3,  w1, w12,  w4) \
                    M( w4,  w2, w13,  w5) \
                    M( w5,  w3, w14,  w6) \
                    M( w6,  w4, w15,  w7) \
                    M( w7,  w5,  w0,  w8) \
                    M( w8,  w6,  w1,  w9) \
                    M( w9,  w7,  w2, w10) \
                    M(w10,  w8,  w3, w11) \
                    M(w11,  w9,  w4, w12) \
                    M(w12, w10,  w5, w13) \
                    M(w13, w11,  w6, w14) \
                    M(w14, w12,  w7, w15) \
                    M(w15, w13,  w8,  w0)

#define F(w,k)      T1 = h + S1(e) + Ch(e,f,g) + k + w; \
                    T2 = S0(a) + Maj(a,b,c); \
                    h = g; \
                    g = f; \
                    f = e; \
                    e = d + T1; \
                    d = c; \
                    c = b; \
                    b = a; \
                    a = T1 + T2;

static uint64_t big_endian_load(const uint8_t* in)
{
    return ((uint64_t) (in[7]))
        | (((uint64_t) (in[6])) <<  8)
        | (((uint64_t) (in[5])) << 16)
        | (((uint64_t) (in[4])) << 24)
        | (((uint64_t) (in[3])) << 32)
        | (((uint64_t) (in[2])) << 40)
        | (((uint64_t) (in[1])) << 48)
        | (((uint64_t) (in[0])) << 56);
}

static void big_endian_store(uint8_t* out, uint64_t in)
{
    out[7] = in & 0xFF; in >>= 8;
    out[6] = in & 0xFF; in >>= 8;
    out[5] = in & 0xFF; in >>= 8;
    out[4] = in & 0xFF; in >>= 8;
    out[3] = in & 0xFF; in >>= 8;
    out[2] = in & 0xFF; in >>= 8;
    out[1] = in & 0xFF; in >>= 8;
    out[0] = in & 0xFF;
}

static size_t sha512_block(uint8_t *statebytes,
                           const uint8_t *in,
                           size_t in_len)
{
    uint64_t state[8];
    uint64_t a, b, c, d;
    uint64_t e, f, g, h;
    uint64_t w0, w1, w2, w3, w4;
    uint64_t w5, w6, w7, w8, w9;
    uint64_t w10, w11, w12, w13;
    uint64_t w14, w15, T1, T2;

    a = big_endian_load(statebytes + 0);
    state[0] = a;
    b = big_endian_load(statebytes + 8);
    state[1] = b;
    c = big_endian_load(statebytes + 16);
    state[2] = c;
    d = big_endian_load(statebytes + 24);
    state[3] = d;
    e = big_endian_load(statebytes + 32);
    state[4] = e;
    f = big_endian_load(statebytes + 40);
    state[5] = f;
    g = big_endian_load(statebytes + 48);
    state[6] = g;
    h = big_endian_load(statebytes + 56);
    state[7] = h;

    while (in_len >= 128)
    {
        w0  = big_endian_load(in + 0);
        w1  = big_endian_load(in + 8);
        w2  = big_endian_load(in + 16);
        w3  = big_endian_load(in + 24);
        w4  = big_endian_load(in + 32);
        w5  = big_endian_load(in + 40);
        w6  = big_endian_load(in + 48);
        w7  = big_endian_load(in + 56);
        w8  = big_endian_load(in + 64);
        w9  = big_endian_load(in + 72);
        w10 = big_endian_load(in + 80);
        w11 = big_endian_load(in + 88);
        w12 = big_endian_load(in + 96);
        w13 = big_endian_load(in + 104);
        w14 = big_endian_load(in + 112);
        w15 = big_endian_load(in + 120);

        F( w0, 0x428a2f98d728ae22ULL)
        F( w1, 0x7137449123ef65cdULL)
        F( w2, 0xb5c0fbcfec4d3b2fULL)
        F( w3, 0xe9b5dba58189dbbcULL)
        F( w4, 0x3956c25bf348b538ULL)
        F( w5, 0x59f111f1b605d019ULL)
        F( w6, 0x923f82a4af194f9bULL)
        F( w7, 0xab1c5ed5da6d8118ULL)
        F( w8, 0xd807aa98a3030242ULL)
        F( w9, 0x12835b0145706fbeULL)
        F(w10, 0x243185be4ee4b28cULL)
        F(w11, 0x550c7dc3d5ffb4e2ULL)
        F(w12, 0x72be5d74f27b896fULL)
        F(w13, 0x80deb1fe3b1696b1ULL)
        F(w14, 0x9bdc06a725c71235ULL)
        F(w15, 0xc19bf174cf692694ULL)

        EXPAND

        F( w0, 0xe49b69c19ef14ad2ULL)
        F( w1, 0xefbe4786384f25e3ULL)
        F( w2, 0x0fc19dc68b8cd5b5ULL)
        F( w3, 0x240ca1cc77ac9c65ULL)
        F( w4, 0x2de92c6f592b0275ULL)
        F( w5, 0x4a7484aa6ea6e483ULL)
        F( w6, 0x5cb0a9dcbd41fbd4ULL)
        F( w7, 0x76f988da831153b5ULL)
        F( w8, 0x983e5152ee66dfabULL)
        F( w9, 0xa831c66d2db43210ULL)
        F(w10, 0xb00327c898fb213fULL)
        F(w11, 0xbf597fc7beef0ee4ULL)
        F(w12, 0xc6e00bf33da88fc2ULL)
        F(w13, 0xd5a79147930aa725ULL)
        F(w14, 0x06ca6351e003826fULL)
        F(w15, 0x142929670a0e6e70ULL)

        EXPAND

        F( w0, 0x27b70a8546d22ffcULL)
        F( w1, 0x2e1b21385c26c926ULL)
        F( w2, 0x4d2c6dfc5ac42aedULL)
        F( w3, 0x53380d139d95b3dfULL)
        F( w4, 0x650a73548baf63deULL)
        F( w5, 0x766a0abb3c77b2a8ULL)
        F( w6, 0x81c2c92e47edaee6ULL)
        F( w7, 0x92722c851482353bULL)
        F( w8, 0xa2bfe8a14cf10364ULL)
        F( w9, 0xa81a664bbc423001ULL)
        F(w10, 0xc24b8b70d0f89791ULL)
        F(w11, 0xc76c51a30654be30ULL)
        F(w12, 0xd192e819d6ef5218ULL)
        F(w13, 0xd69906245565a910ULL)
        F(w14, 0xf40e35855771202aULL)
        F(w15, 0x106aa07032bbd1b8ULL)

        EXPAND

        F( w0, 0x19a4c116b8d2d0c8ULL)
        F( w1, 0x1e376c085141ab53ULL)
        F( w2, 0x2748774cdf8eeb99ULL)
        F( w3, 0x34b0bcb5e19b48a8ULL)
        F( w4, 0x391c0cb3c5c95a63ULL)
        F( w5, 0x4ed8aa4ae3418acbULL)
        F( w6, 0x5b9cca4f7763e373ULL)
        F( w7, 0x682e6ff3d6b2b8a3ULL)
        F( w8, 0x748f82ee5defb2fcULL)
        F( w9, 0x78a5636f43172f60ULL)
        F(w10, 0x84c87814a1f0ab72ULL)
        F(w11, 0x8cc702081a6439ecULL)
        F(w12, 0x90befffa23631e28ULL)
        F(w13, 0xa4506cebde82bde9ULL)
        F(w14, 0xbef9a3f7b2c67915ULL)
        F(w15, 0xc67178f2e372532bULL)

        EXPAND

        F( w0, 0xca273eceea26619cULL)
        F( w1, 0xd186b8c721c0c207ULL)
        F( w2, 0xeada7dd6cde0eb1eULL)
        F( w3, 0xf57d4f7fee6ed178ULL)
        F( w4, 0x06f067aa72176fbaULL)
        F( w5, 0x0a637dc5a2c898a6ULL)
        F( w6, 0x113f9804bef90daeULL)
        F( w7, 0x1b710b35131c471bULL)
        F( w8, 0x28db77f523047d84ULL)
        F( w9, 0x32caab7b40c72493ULL)
        F(w10, 0x3c9ebe0a15c9bebcULL)
        F(w11, 0x431d67c49c100d4cULL)
        F(w12, 0x4cc5d4becb3e42b6ULL)
        F(w13, 0x597f299cfc657e2aULL)
        F(w14, 0x5fcb6fab3ad6faecULL)
        F(w15, 0x6c44198c4a475817ULL)

        a += state[0];
        b += state[1];
        c += state[2];
        d += state[3];
        e += state[4];
        f += state[5];
        g += state[6];
        h += state[7];

        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;

        in += 128;
        in_len -= 128;
    }

    big_endian_store(statebytes +  0, state[0]);
    big_endian_store(statebytes +  8, state[1]);
    big_endian_store(statebytes + 16, state[2]);
    big_endian_store(statebytes + 24, state[3]);
    big_endian_store(statebytes + 32, state[4]);
    big_endian_store(statebytes + 40, state[5]);
    big_endian_store(statebytes + 48, state[6]);
    big_endian_store(statebytes + 56, state[7]);

    return in_len;
}

void sha512(uint8_t* out,
            const uint8_t* in,
            size_t in_len)
{
    int32_t i;
    uint64_t bytes = (uint64_t)in_len;
    uint8_t padded[256];
    uint8_t h[64] = {
        0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
        0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
        0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b,
        0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1,
        0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1,
        0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
        0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b,
        0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79
    };

    sha512_block(h, in, in_len);
    in += in_len;
    in_len &= 0x7f;
    in -= in_len;

    for (i = 0; i < (int32_t)in_len; ++i)
    {
        padded[i] = in[i];
    }
    padded[in_len] = 0x80;

    if (in_len < 112)
    {
        for (i = (int32_t)in_len + 1; i < 119; ++i)
        {
            padded[i] = 0;
        }
        padded[119] = (bytes >> 61) & 0xFF;
        padded[120] = (bytes >> 53) & 0xFF;
        padded[121] = (bytes >> 45) & 0xFF;
        padded[122] = (bytes >> 37) & 0xFF;
        padded[123] = (bytes >> 29) & 0xFF;
        padded[124] = (bytes >> 21) & 0xFF;
        padded[125] = (bytes >> 13) & 0xFF;
        padded[126] = (bytes >>  5) & 0xFF;
        padded[127] = (bytes <<  3) & 0xFF;
        sha512_block(h, padded, 128);
    }
    else
    {
        for (i = (int32_t)in_len + 1; i < 247; ++i)
        {
            padded[i] = 0;
        }
        padded[247] = (bytes >> 61) & 0xFF;
        padded[248] = (bytes >> 53) & 0xFF;
        padded[249] = (bytes >> 45) & 0xFF;
        padded[250] = (bytes >> 37) & 0xFF;
        padded[251] = (bytes >> 29) & 0xFF;
        padded[252] = (bytes >> 21) & 0xFF;
        padded[253] = (bytes >> 13) & 0xFF;
        padded[254] = (bytes >>  5) & 0xFF;
        padded[255] = (bytes <<  3) & 0xFF;
        sha512_block(h, padded, 256);
    }

    for (i = 0; i < 64; ++i)
    {
        out[i] = h[i];
    }
}
