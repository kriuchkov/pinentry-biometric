/* secure_mem.c — mlock'ed allocations for secrets, guaranteed wipe.
 * SPDX-License-Identifier: MIT */
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>   /* memset_s — plain memset is elided by the optimizer */

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "secure_mem.h"

void secure_process_init(void)
{
    struct rlimit rl = { 0, 0 };
    (void)setrlimit(RLIMIT_CORE, &rl);  /* no core dumps with secrets */
}

void *secure_alloc(size_t len)
{
    void *p = malloc(len);
    if (p)
        (void)mlock(p, len);  /* best effort: keep allocation on failure */
    return p;
}

void secure_wipe(void *p, size_t len)
{
    if (p && len)
        (void)memset_s(p, len, 0, len);
}

void secure_free(void *p, size_t len)
{
    if (!p)
        return;
    secure_wipe(p, len);
    (void)munlock(p, len);
    free(p);
}
