// Copyright (c) 2018-2019 Duality Blockchain Solutions Developers
// See LICENSE.md file for license, copying and use information.

#include <stdio.h>
#include "utils.h"
#include "vgp_assert.h"

void vgp_assert(const char* expr_str,
                bool expr,
                const char* filename,
                int line,
                const char* message)
{
    if (!expr)
    {
        fprintf(stderr, "Assertion failed");
        if (message != NULL)
        {
            fprintf(stderr, ": %s", message);
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "Expected: %s\n", expr_str);
        fprintf(stderr, "Filename: %s, Line: %d\n", filename, line);
        fflush(stderr);
        abort();
    }    
}

void vgp_assert_with_seed(const char* expr_str,
                          bool expr,
                          const char* filename,
                          int line,
                          const char* message,
                          const uint8_t* seed,
                          size_t seed_size)
{
    if (!expr)
    {
        char *seed_str = (char *)calloc(seed_size * 2 + 1, sizeof(char));
        fprintf(stderr, "Assertion failed");
        if (message != NULL)
        {
            fprintf(stderr, ": %s", message);
        }
        fprintf(stderr, "\n");
        if (seed_str != NULL)
        {
            byte_array_to_hex_string(seed_str, seed, seed_size);
            fprintf(stderr, "Seed: %s\n", seed_str);
            free(seed_str);
        }
        fprintf(stderr, "Expected: %s\n", expr_str);
        fprintf(stderr, "Filename: %s, Line: %d\n", filename, line);
        fflush(stderr);
        abort();
    }    
}
