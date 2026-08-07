/* assuan.h — Assuan/pinentry wire protocol: line IO, percent codec, replies.
 * Reference: GnuPG pinentry (pinentry/pinentry.c), Assuan manual.
 * SPDX-License-Identifier: MIT */
#ifndef PE_ASSUAN_H
#define PE_ASSUAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* Assuan line length limit in bytes, excluding terminating newline/NUL.
 * Longer input lines are a protocol error, never a buffer overflow. */
#define ASSUAN_LINE_MAX 1000

/* libgpg-error codes, source GPG_ERR_SOURCE_PINENTRY (5) in bits 24..30.
 * All values verified against gpg-error.h from libgpg-error 1.61
 * (/opt/homebrew/include/gpg-error.h): GPG_ERR_SOURCE_PINENTRY = 5,
 * GPG_ERR_INTERNAL = 63, GPG_ERR_NO_PIN_ENTRY = 85, GPG_ERR_CANCELED = 99,
 * GPG_ERR_NOT_CONFIRMED = 114, GPG_ERR_ASS_LINE_TOO_LONG = 263,
 * GPG_ERR_ASS_UNKNOWN_CMD = 275. */
#define PE_ERR_SOURCE          (5u << 24)
#define PE_ERR(code)           (PE_ERR_SOURCE | (unsigned int)(code))
#define PE_ERR_CANCELED        PE_ERR(99)  /* GPG_ERR_CANCELED -> 83886179 */
#define PE_ERR_NOT_CONFIRMED   PE_ERR(114) /* GPG_ERR_NOT_CONFIRMED */
#define PE_ERR_NO_PIN_ENTRY    PE_ERR(85)  /* GPG_ERR_NO_PIN_ENTRY */
#define PE_ERR_INTERNAL        PE_ERR(63)  /* GPG_ERR_INTERNAL */
#define PE_ERR_ASS_TOO_LONG    PE_ERR(263) /* GPG_ERR_ASS_LINE_TOO_LONG */
#define PE_ERR_ASS_UNKNOWN_CMD PE_ERR(275) /* GPG_ERR_ASS_UNKNOWN_CMD */

/* Enable protocol debug logging to stderr. Payload of D lines is always
 * masked as "D ***" — secrets must never reach the log. */
void assuan_set_debug(bool on);

/* Read one protocol line from `in` into buf (bufsz >= ASSUAN_LINE_MAX + 1).
 * Strips trailing LF / CRLF. Returns line length >= 0, -1 on EOF,
 * -2 if the line exceeds ASSUAN_LINE_MAX (input is drained to EOL). */
int assuan_read_line(FILE *in, char *buf, size_t bufsz);

/* Split a command line in place: *cmd -> first word (upper/lower preserved),
 * *args -> rest after first run of spaces, or "" if none. */
void assuan_split(char *line, char **cmd, char **args);

/* In-place percent-decoding (%XX). Invalid escapes are kept verbatim.
 * Returns the decoded length; result is NUL-terminated. */
size_t assuan_percent_decode(char *s);

/* All senders write a full line and fflush(out). Return 0 on success. */
int assuan_send_ok(FILE *out, const char *msg);              /* "OK[ msg]" */
int assuan_send_err(FILE *out, unsigned int code, const char *desc);
int assuan_send_status(FILE *out, const char *kw, const char *text); /* "S kw[ text]" */

/* "D <payload>" with '%', CR, LF percent-escaped. Caller sends OK after,
 * but only if this returned 0 — on failure the caller must send ERR, since
 * a bare OK reads as a successful *empty* passphrase. Payload longer than
 * the line limit is split across several D lines. The escape buffer is
 * wiped before return; note that stdio's own buffer is not, so main() puts
 * stdout in unbuffered mode. */
int assuan_send_data(FILE *out, const unsigned char *data, size_t len);

#endif /* PE_ASSUAN_H */
