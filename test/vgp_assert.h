// Copyright (c) 2018-2019 Duality Blockchain Solutions Developers
// See LICENSE.md file for license, copying and use information.

#ifndef _VGP_ASSERT_H
#define _VGP_ASSERT_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#define VGP_ASSERT(expr, msg) \
    vgp_assert(#expr, expr, __FILE__, __LINE__, msg)

#define VGP_ASSERT_WITH_SEED(expr, msg, seed, seed_size) \
    vgp_assert_with_seed(#expr, expr, __FILE__, __LINE__, msg, seed, seed_size)

#ifdef __cplusplus
extern "C" {
#endif

void vgp_assert(const char* expr_str,
                bool expr,
                const char* filename,
                int line,
                const char* message);

void vgp_assert_with_seed(const char* expr_str,
                          bool expr,
                          const char* filename,
                          int line,
                          const char* message,
                          const uint8_t* seed,
                          size_t seed_size);

#ifdef __cplusplus
}
#endif

#endif
