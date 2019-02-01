#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "rand.h"

#define NUM_ITERATIONS      200

#define DO_TEST(name, test_func)    \
    printf(name); fflush(stdout); \
	if (false == test_func) { \
		printf("FAIL\n"); \
		return -1; \
	} else { \
		printf("PASS\n"); fflush(stdout); \
	}

#define DO_ITER_TEST(name, iter, test_func)    \
    printf(name, iter); fflush(stdout); \
	if (false == test_func) { \
		printf("FAIL\n"); \
		return -1; \
	} else { \
		printf("PASS\n"); fflush(stdout); \
	}

extern bool shake256_random_test();
extern bool nist_aes_test_vector();
extern bool random_aes_test_vectors(int iterations);
extern bool aes256ctr_nist_positive_test();
extern bool aes256ctr_random_test(int iterations);
extern bool openssl_aes256ctr_random_test(int iterations);
extern bool aes256gcm_nist_positive_test();
extern bool openssl_aes256gcm_nist_positive_test();
extern bool curve25519_random_keypair_test();
extern bool bdap_random_test();
extern bool ed25519_to_curve25519_conversion_test();
extern bool ed25519_to_curve25519_random_conversion_test(int iterations);

int main(int argc, char *argv[]) 
{
    int32_t num_iterations = NUM_ITERATIONS;
    if (argc > 1) 
    {
        num_iterations = atoi(argv[1]);
    }

    use_shake256_rand();

    DO_TEST("SHAKE256 random test vectors: ",
        shake256_random_test());

    DO_TEST("NIST AES test vectors: ",
        nist_aes_test_vector());

    DO_ITER_TEST("Random AES test (%d iterations): ",
        num_iterations, random_aes_test_vectors(num_iterations));

    DO_TEST("AES256-CTR NIST positive test: ",
        aes256ctr_nist_positive_test());

    DO_ITER_TEST("Random AES256-CTR test (%d iterations): ",
        num_iterations, aes256ctr_random_test(num_iterations));

    DO_ITER_TEST("OpenSSL random AES256-CTR test (%d iterations): ",
        num_iterations, openssl_aes256ctr_random_test(num_iterations));

    DO_TEST("AES256-GCM NIST positive test: ",
        aes256gcm_nist_positive_test());

    DO_TEST("OpenSSL AES256-GCM NIST positive test: ",
        openssl_aes256gcm_nist_positive_test());

    DO_TEST("Curve25519 random keypair test: ",
        curve25519_random_keypair_test());

    DO_TEST("Ed25519 to Curve25519 conversion test: ",
        ed25519_to_curve25519_conversion_test());

    DO_ITER_TEST("Ed25519 to Curve25519 random conversion test (%d iterations): ",
        num_iterations, ed25519_to_curve25519_random_conversion_test(num_iterations));

    DO_TEST("BDAP E2E random test: ",
        bdap_random_test());

    return 0;
}
