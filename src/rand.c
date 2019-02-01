#include "rand.h"
#include "os_rand.h"
#include "shake256_rand.h"

void (*bdap_randominit) 
    (const uint8_t* seed, size_t seed_size) = os_randominit;
void (*bdap_randombytes)
    (uint8_t *buf, size_t buf_size) = os_randombytes;

void use_shake256_rand()
{
    bdap_randominit = shake256_randominit;
    bdap_randombytes = shake256_randombytes;
}
