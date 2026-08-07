/* assuan.c — Assuan/pinentry wire protocol: line IO, percent codec, replies.
 * Reference: GnuPG pinentry (pinentry/pinentry.c), Assuan manual.
 * SPDX-License-Identifier: MIT */
#define __STDC_WANT_LIB_EXT1__ 1
#include "assuan.h"

#include <stdio.h>
#include <string.h>

static bool g_debug = false;

void
assuan_set_debug(bool on)
{
    g_debug = on;
}

/* Read one line, byte by byte. A CR immediately followed by LF is part of
 * the line terminator and dropped; any other CR is ordinary data. Bytes
 * beyond the limit set `over` and are drained (never stored). */
int
assuan_read_line(FILE *in, char *buf, size_t bufsz)
{
    size_t cap, len = 0;
    bool got = false, over = false, cr = false;
    int c;

    if (bufsz == 0)
        return -2;
    cap = (bufsz - 1 < ASSUAN_LINE_MAX) ? bufsz - 1 : ASSUAN_LINE_MAX;

    while ((c = fgetc(in)) != EOF) {
        got = true;
        if (c == '\n')
            break;              /* a pending CR here belongs to CRLF: drop */
        if (cr) {               /* previous CR was not part of CRLF: data */
            cr = false;
            if (len < cap) buf[len++] = '\r'; else over = true;
        }
        if (c == '\r') {
            cr = true;
            continue;
        }
        if (len < cap) buf[len++] = (char)c; else over = true;
    }
    if (c == EOF) {
        if (!got)
            return -1;          /* EOF with no bytes at all */
        if (cr) {               /* lone CR at EOF: keep as data */
            if (len < cap) buf[len++] = '\r'; else over = true;
        }
    }
    buf[len] = '\0';
    return over ? -2 : (int)len;
}

void
assuan_split(char *line, char **cmd, char **args)
{
    *cmd = line;
    while (*line && *line != ' ')
        line++;
    if (*line) {
        *line++ = '\0';
        while (*line == ' ')
            line++;
    }
    *args = line;               /* points at "" when there are no args */
}

static int
hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

size_t
assuan_percent_decode(char *s)
{
    char *w = s;
    const char *r = s;

    while (*r) {
        int hi, lo;
        if (r[0] == '%' && (hi = hexval((unsigned char)r[1])) >= 0
            && (lo = hexval((unsigned char)r[2])) >= 0) {
            *w++ = (char)(hi << 4 | lo);
            r += 3;
        } else {
            *w++ = *r++;        /* invalid escape kept verbatim */
        }
    }
    *w = '\0';
    return (size_t)(w - s);
}

/* Write one complete text line + '\n', flush, and log it when debugging. */
static int
send_line(FILE *out, const char *line)
{
    if (fputs(line, out) == EOF || fputc('\n', out) == EOF || fflush(out) != 0)
        return -1;
    if (g_debug)
        fprintf(stderr, "pinentry-biometric> %s\n", line);
    return 0;
}

int
assuan_send_ok(FILE *out, const char *msg)
{
    char line[ASSUAN_LINE_MAX + 1];

    if (msg && *msg)
        snprintf(line, sizeof line, "OK %s", msg);
    else
        snprintf(line, sizeof line, "OK");
    return send_line(out, line);
}

int
assuan_send_err(FILE *out, unsigned int code, const char *desc)
{
    char line[ASSUAN_LINE_MAX + 1];

    snprintf(line, sizeof line, "ERR %u %s", code, desc ? desc : "");
    return send_line(out, line);
}

int
assuan_send_status(FILE *out, const char *kw, const char *text)
{
    char line[ASSUAN_LINE_MAX + 1];

    if (text && *text)
        snprintf(line, sizeof line, "S %s %s", kw, text);
    else
        snprintf(line, sizeof line, "S %s", kw);
    return send_line(out, line);
}

int
assuan_send_data(FILE *out, const unsigned char *data, size_t len)
{
    static const char hex[] = "0123456789ABCDEF";
    /* "D " plus payload must fit the Assuan line limit. A longer secret is
     * split across several D lines the way reference pinentry does —
     * truncating or refusing would hand gpg-agent a wrong passphrase. */
    enum { PAYLOAD_MAX = ASSUAN_LINE_MAX - 2 };
    char esc[PAYLOAD_MAX];
    size_t i = 0;
    int rc = 0;

    do {
        size_t n = 0;
        while (i < len) {
            unsigned char c = data[i];
            size_t need = (c == '%' || c == '\r' || c == '\n') ? 3 : 1;
            if (n + need > sizeof esc)
                break;                  /* never split an escape sequence */
            if (need == 3) {
                esc[n++] = '%';
                esc[n++] = hex[c >> 4];
                esc[n++] = hex[c & 0x0f];
            } else {
                esc[n++] = (char)c;
            }
            i++;
        }
        if (fwrite("D ", 1, 2, out) != 2
            || (n > 0 && fwrite(esc, 1, n, out) != n)
            || fputc('\n', out) == EOF || fflush(out) != 0)
            rc = -1;
        /* This buffer carried the passphrase: wipe with memset_s so the
         * compiler cannot elide it. */
        (void)memset_s(esc, sizeof esc, 0, sizeof esc);
        if (g_debug)
            fputs("pinentry-biometric> D ***\n", stderr); /* never the payload */
    } while (rc == 0 && i < len);
    return rc;
}
