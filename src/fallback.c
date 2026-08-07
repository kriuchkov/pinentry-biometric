/* fallback.c — first-entry UI: proxy one GETPIN to an existing pinentry-mac
 * binary over a child Assuan session (rationale in DESIGN.md).
 * Deliberately NOT forwarded: OPTION allow-external-password-cache and
 * SETKEYINFO — otherwise pinentry-mac would offer/perform its own Keychain
 * save under its signing identity (see fallback.h).
 * SPDX-License-Identifier: MIT */
#include "fallback.h"

#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "assuan.h"
#include "secure_mem.h"

extern char **environ;

/* Room for a fully percent-escaped Assuan payload plus command word. */
#define FB_LINE_MAX (ASSUAN_LINE_MAX * 3 + 16)

static char *dup_if_exec(const char *p)
{
    return access(p, X_OK) == 0 ? strdup(p) : NULL;
}

char *fallback_find(void)
{
    char exe[PATH_MAX], resolved[PATH_MAX], cand[PATH_MAX];
    uint32_t sz = sizeof(exe);
    /* _NSGetExecutablePath returns the path as exec'd, which may be
     * relative: dirname() of it would then resolve against the caller's
     * cwd, letting whoever started us point the search at a directory they
     * control. realpath() first. */
    if (_NSGetExecutablePath(exe, &sz) == 0 &&
        realpath(exe, resolved) != NULL) {
        snprintf(cand, sizeof(cand), "%s/pinentry-mac", dirname(resolved));
        char *hit = dup_if_exec(cand);
        if (hit) return hit;
    }
    static const char *const prefixes[] = {
        "/opt/homebrew/bin/pinentry-mac",
        "/usr/local/bin/pinentry-mac",
        "/usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/pinentry-mac",
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        char *hit = dup_if_exec(prefixes[i]);
        if (hit) return hit;
    }
    return NULL;
}

static int write_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -1;
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Read one LF-terminated line (byte at a time: traffic is tiny, simplicity
 * beats a buffered reader). Strips CR/LF. -1 on EOF, error or overlong line. */
static int fb_read_line(int fd, char *buf, size_t cap)
{
    size_t n = 0;
    for (;;) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        if (c == '\n') break;
        if (n + 1 >= cap) return -1;
        buf[n++] = c;
    }
    while (n > 0 && buf[n - 1] == '\r') n--;
    buf[n] = '\0';
    return (int)n;
}

/* Percent-encode '%', CR, LF (assuan.h only exposes the decoder). */
static void fb_encode(const char *val, char *out, size_t cap)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)val;
         *p != '\0' && o + 4 < cap; p++) {
        if (*p == '%' || *p == '\r' || *p == '\n') {
            out[o++] = '%';
            out[o++] = hex[*p >> 4];
            out[o++] = hex[*p & 15];
        } else {
            out[o++] = (char)*p;
        }
    }
    out[o] = '\0';
}

/* Send one command line, then read until OK/ERR, skipping S/#/empty lines.
 * 0 on OK, -1 otherwise. No secrets ever pass through here. */
static int fb_command(int wfd, int rfd, const char *cmdline)
{
    char buf[FB_LINE_MAX];
    size_t len = strlen(cmdline);
    if (len + 2 > sizeof(buf)) return -1;
    memcpy(buf, cmdline, len);
    buf[len] = '\n';
    if (write_all(wfd, buf, len + 1) < 0) return -1;
    for (;;) {
        if (fb_read_line(rfd, buf, sizeof(buf)) < 0) return -1;
        if (strncmp(buf, "OK", 2) == 0 && (buf[2] == '\0' || buf[2] == ' '))
            return 0;
        if (strncmp(buf, "S ", 2) == 0 || buf[0] == '#' || buf[0] == '\0')
            continue;
        return -1; /* ERR or garbage */
    }
}

/* SET* forwarding; empty fields are skipped (not an error).
 *
 * The child enforces the same 1000-byte Assuan limit we do, and encoding can
 * triple a value's length, so a long SETDESC would otherwise produce a line
 * the child rejects — aborting the whole session and leaving the user with
 * no passphrase dialog at all. A truncated description is a far better
 * outcome than no prompt, so cap the encoded value to fit. */
static int fb_set(int wfd, int rfd, const char *cmd, const char *val)
{
    if (val == NULL || val[0] == '\0') return 0;
    char enc[FB_LINE_MAX], line[FB_LINE_MAX];
    size_t room = ASSUAN_LINE_MAX - strlen(cmd) - 1; /* command + space */
    if (room > sizeof(enc)) room = sizeof(enc);
    fb_encode(val, enc, room);
    snprintf(line, sizeof(line), "%s %s", cmd, enc);
    return fb_command(wfd, rfd, line);
}

/* Always reap; never block forever: after ~1s of polling, SIGKILL + wait. */
static void fb_reap(pid_t pid)
{
    for (int i = 0; i < 50; i++) {
        pid_t r = waitpid(pid, NULL, WNOHANG);
        if (r == pid || (r < 0 && errno != EINTR)) return;
        struct timespec ts = { 0, 20 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    kill(pid, SIGKILL);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
        ;
}

int fallback_getpin(const pe_state *st, const char *path,
                    unsigned char **out_pw, size_t *out_len)
{
    *out_pw = NULL;
    *out_len = 0;
    if (path == NULL || access(path, X_OK) != 0) return -1;
    signal(SIGPIPE, SIG_IGN); /* a dead child must not kill us on write */

    int to_child[2], from_child[2];
    if (pipe(to_child) < 0) return -1;
    if (pipe(from_child) < 0) {
        close(to_child[0]);
        close(to_child[1]);
        return -1;
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, to_child[0], 0);
    posix_spawn_file_actions_adddup2(&fa, from_child[1], 1);
    posix_spawn_file_actions_addclose(&fa, to_child[1]);
    posix_spawn_file_actions_addclose(&fa, from_child[0]);
    pid_t pid;
    char *cargv[] = { (char *)path, NULL };
    int rc = posix_spawn(&pid, path, &fa, NULL, cargv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(to_child[0]);
    close(from_child[1]);
    int wfd = to_child[1], rfd = from_child[0];
    if (rc != 0) {
        close(wfd);
        close(rfd);
        return -1;
    }

    int ret = -1;
    bool got_data = false;
    size_t acc_len = 0;
    char line[FB_LINE_MAX];
    unsigned char acc[FB_LINE_MAX];

    /* greeting */
    if (fb_read_line(rfd, line, sizeof(line)) < 0 || strncmp(line, "OK", 2) != 0)
        goto done;

    /* tty/locale options. These are not percent-decoded on the way in, and
     * a lone CR survives assuan_read_line as data, so encode them like
     * everything else rather than relying on that accident. */
    static const char *const optname[] = { "ttyname", "ttytype",
                                           "lc-ctype", "lc-messages" };
    const char *const optval[] = { st->ttyname, st->ttytype,
                                   st->lc_ctype, st->lc_messages };
    for (size_t i = 0; i < 4; i++) {
        if (optval[i][0] == '\0') continue;
        char enc[FB_LINE_MAX];
        /* Same line-limit cap as fb_set: ttyname is a full-width field. */
        size_t room = ASSUAN_LINE_MAX - strlen(optname[i]) - 8; /* "OPTION =" */
        if (room > sizeof(enc)) room = sizeof(enc);
        fb_encode(optval[i], enc, room);
        snprintf(line, sizeof(line), "OPTION %s=%s", optname[i], enc);
        if (fb_command(wfd, rfd, line) < 0) goto done;
    }
    if (fb_set(wfd, rfd, "SETTITLE", st->title) < 0 ||
        fb_set(wfd, rfd, "SETDESC", st->desc) < 0 ||
        fb_set(wfd, rfd, "SETPROMPT", st->prompt) < 0 ||
        fb_set(wfd, rfd, "SETOK", st->ok_label) < 0 ||
        fb_set(wfd, rfd, "SETCANCEL", st->cancel_label) < 0 ||
        fb_set(wfd, rfd, "SETERROR", st->error) < 0)
        goto done;

    if (write_all(wfd, "GETPIN\n", 7) < 0) goto done;
    for (;;) {
        if (fb_read_line(rfd, line, sizeof(line)) < 0) goto done;
        if (strncmp(line, "D ", 2) == 0) {
            size_t dlen = assuan_percent_decode(line + 2);
            if (acc_len + dlen > sizeof(acc)) goto done;
            memcpy(acc + acc_len, line + 2, dlen);
            acc_len += dlen;
            got_data = true;
        } else if (strncmp(line, "OK", 2) == 0 &&
                   (line[2] == '\0' || line[2] == ' ')) {
            break;
        } else if (strncmp(line, "ERR ", 4) == 0) {
            /* 83886179 = GPG_ERR_CANCELED with pinentry source bits */
            ret = (strtoul(line + 4, NULL, 10) == 83886179UL) ? 1 : -1;
            goto done;
        } else if (strncmp(line, "S ", 2) == 0 || line[0] == '#' ||
                   line[0] == '\0') {
            continue; /* status/comment lines */
        } else {
            goto done;
        }
    }
    if (!got_data || acc_len == 0) {
        ret = 1; /* bare OK: canceled/empty entry */
        goto done;
    }
    *out_pw = secure_alloc(acc_len);
    if (*out_pw == NULL) goto done;
    memcpy(*out_pw, acc, acc_len);
    *out_len = acc_len;
    ret = 0;

done:
    secure_wipe(line, sizeof(line));
    secure_wipe(acc, sizeof(acc));
    (void)write_all(wfd, "BYE\n", 4);
    close(wfd);
    close(rfd);
    fb_reap(pid);
    return ret;
}
