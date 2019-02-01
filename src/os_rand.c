#if defined(__APPLE__)
# include <stdio.h>
# include <unistd.h>
#elif defined(_MSC_VER)
# include <windows.h>
# include <stdbool.h>
# include <stdio.h>
#elif defined(__linux__)
#  define _GNU_SOURCE
# include <unistd.h>
# include <sys/syscall.h>
# if !defined(SYS_getrandom)
#  include <stdio.h>
# endif /* SYS_getrandom */
#endif
#include "os_rand.h"

#define MAX_BUFFER_SIZE     1048576

#if defined(_MSC_VER)
# define RtlGenRandom SystemFunction036
# if defined(__cplusplus)
extern "C"
# endif
BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
# pragma comment(lib, "advapi32.lib")

typedef long long ssize_t;
#endif

void os_randominit(const uint8_t* seed, size_t seed_size)
{
    /* Dummy placeholder */
    (void) seed; /* avoid warning about unused parameter */
    (void) seed_size; /* avoid warning about unused parameter */
}

void os_randombytes(uint8_t* buf, size_t buf_size)
{
    ssize_t sz, len;
#if defined(__APPLE__) || (defined(__linux__) && !defined(SYS_getrandom))
    FILE *fptr = NULL;

    fptr = fopen("/dev/urandom", "rb");
#endif

	sz = (ssize_t)buf_size;
    while (sz > 0)
    {
        len = MAX_BUFFER_SIZE;
        if (sz < MAX_BUFFER_SIZE)
        {
            len = sz;
        }

#if defined(_MSC_VER)
		if (false == RtlGenRandom((PVOID)buf, (ULONG)len))
		{
			fprintf_s(stderr, "Terminating process, RtlGenRandom failed\n\n");
			exit(-1);
		}
#else
#if defined(__APPLE__) || (defined(__linux__) && !defined(SYS_getrandom))
        len = (ssize_t)fread(buf, sizeof(uint8_t), len, fptr);
#else
        len = syscall(SYS_getrandom, buf, len, 0);
#endif
        if (len < 1)
        {
            sleep(1);
            continue;
        }
#endif

        buf += len;
        sz  -= len;
    }
#if defined(__APPLE__) || (defined(__linux__) && !defined(SYS_getrandom))
    fclose(fptr);
#endif
}
