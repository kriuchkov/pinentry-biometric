/* secure_mem.h — mlock'ed allocations for secrets, guaranteed wipe.
 * SPDX-License-Identifier: MIT */
#ifndef PE_SECURE_MEM_H
#define PE_SECURE_MEM_H

#include <stddef.h>

/* One-time process hardening: setrlimit(RLIMIT_CORE, 0), and /dev/null on
 * any of fd 0-2 that is closed. Call before anything opens a descriptor. */
void secure_process_init(void);

/* Allocate len bytes (0 is allowed) on whole pages of their own, zeroed and
 * mlock'ed (best effort: allocation succeeds even if mlock fails, e.g.
 * under RLIMIT_MEMLOCK). Returns NULL on OOM. */
void *secure_alloc(size_t len);

/* memset_s-wipe, munlock, unmap. Safe on NULL. len must match secure_alloc. */
void secure_free(void *p, size_t len);

/* memset_s-based wipe of an arbitrary buffer (not necessarily secure_alloc'ed). */
void secure_wipe(void *p, size_t len);

#endif /* PE_SECURE_MEM_H */
