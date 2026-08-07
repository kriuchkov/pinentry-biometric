/* fallback.h — first-entry UI: proxy the prompt to an existing pinentry-mac
 * binary via a child Assuan session (rationale in DESIGN.md).
 * NOTE: allow-external-password-cache is deliberately NOT forwarded to the
 * fallback — otherwise pinentry-mac would store the passphrase under its
 * own code-signing identity; saving is our job (main.c + keychain.m).
 * SPDX-License-Identifier: MIT */
#ifndef PE_FALLBACK_H
#define PE_FALLBACK_H

#include <stddef.h>

#include "state.h"

/* Locate pinentry-mac: next to our own binary (path resolved with realpath),
 * then /opt/homebrew/bin, /usr/local/bin, and GPG Suite's
 * /usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/.
 * NOTE: the result is fully trusted — it receives the typed passphrase — and
 * these prefixes are user-writable on a typical single-admin Mac. Pin the
 * path with --fallback-pinentry if that matters.
 * Returns a malloc'ed path or NULL. */
char *fallback_find(void);

/* Run one GETPIN against the fallback pinentry at `path`, forwarding the
 * relevant SET* fields and tty/locale OPTIONs from `st`.
 * Returns 0 = got passphrase (*out_pw secure_alloc'ed, *out_len bytes,
 * caller secure_frees), 1 = user canceled, -1 = fallback missing/failed.
 * Must not hang: child is reaped on any error path. */
int fallback_getpin(const pe_state *st, const char *path,
                    unsigned char **out_pw, size_t *out_len);

#endif /* PE_FALLBACK_H */
