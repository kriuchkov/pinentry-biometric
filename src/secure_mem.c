/* secure_mem.c — mlock'ed allocations for secrets, guaranteed wipe.
 * SPDX-License-Identifier: MIT */
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>   /* memset_s — plain memset is elided by the optimizer */

#include <stdint.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include "secure_mem.h"

void secure_process_init(void)
{
    struct rlimit rl = { 0, 0 };
    (void)setrlimit(RLIMIT_CORE, &rl);  /* no core dumps with secrets */
}

/* Mapping size for a len-byte secret: whole pages, at least one. 0 on
 * overflow. */
static size_t secure_size(size_t len)
{
    size_t pg = (size_t)getpagesize();
    if (len == 0)
        len = 1;
    if (len > SIZE_MAX - (pg - 1))
        return 0;
    return (len + pg - 1) / pg * pg;
}

/* Each secret gets pages of its own from mmap rather than a malloc block:
 * malloc packs small blocks into shared pages, and munlock works on whole
 * pages, so freeing one secret used to unlock the page of any other secret
 * that happened to share it. */
void *secure_alloc(size_t len)
{
    size_t sz = secure_size(len);
    if (sz == 0)
        return NULL;
    void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
                   -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    (void)mlock(p, sz);  /* best effort: keep allocation on failure */
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
    size_t sz = secure_size(len);
    secure_wipe(p, sz);
    (void)munlock(p, sz);
    (void)munmap(p, sz);
}
