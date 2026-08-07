/* state.c — per-session pinentry state: OPTION and SET* fields, RESET.
 * Reference: GnuPG pinentry (pinentry/pinentry.c option/cmd handlers).
 * SPDX-License-Identifier: MIT */
#include <string.h>
#include <strings.h>   /* strcasecmp: Assuan verbs are case-insensitive */

#include "state.h"

/* Truncation-safe copy; dst is always NUL-terminated. */
static void field_copy(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void state_init(pe_state *s)
{
    memset(s, 0, sizeof *s);
}

void state_reset(pe_state *s)
{
    /* Clear SET* fields only; OPTION values survive RESET, matching the
     * reference pinentry (pinentry_reset keeps ttyname/locale/cache opts). */
    memset(s->desc, 0, sizeof s->desc);
    memset(s->prompt, 0, sizeof s->prompt);
    memset(s->title, 0, sizeof s->title);
    memset(s->ok_label, 0, sizeof s->ok_label);
    memset(s->cancel_label, 0, sizeof s->cancel_label);
    memset(s->notok_label, 0, sizeof s->notok_label);
    memset(s->error, 0, sizeof s->error);
    memset(s->keygrip, 0, sizeof s->keygrip);
}

int state_handle_option(pe_state *s, const char *args)
{
    if (args[0] == '-' && args[1] == '-')  /* gpg-agent may send "--name" */
        args += 2;

    const char *eq = strchr(args, '=');
    size_t nlen = eq ? (size_t)(eq - args) : strlen(args);
    const char *val = eq ? eq + 1 : NULL;

#define OPT_IS(name) (nlen == sizeof(name) - 1 && memcmp(args, name, nlen) == 0)
    if (OPT_IS("ttyname") && val)
        field_copy(s->ttyname, sizeof s->ttyname, val);
    else if (OPT_IS("ttytype") && val)
        field_copy(s->ttytype, sizeof s->ttytype, val);
    else if (OPT_IS("lc-ctype") && val)
        field_copy(s->lc_ctype, sizeof s->lc_ctype, val);
    else if (OPT_IS("lc-messages") && val)
        field_copy(s->lc_messages, sizeof s->lc_messages, val);
    else if (OPT_IS("allow-external-password-cache"))
        s->allow_external_cache = (!val || !*val || strcmp(val, "1") == 0);
    /* else: unknown option — accepted silently (default-*, touch-file,
     * owner, putenv, constraints-*, ...) */
#undef OPT_IS
    return 0;
}

int state_handle_set(pe_state *s, const char *cmd, char *args)
{
    const struct { const char *cmd; char *dst; size_t cap; } map[] = {
        { "SETDESC",   s->desc,         sizeof s->desc },
        { "SETPROMPT", s->prompt,       sizeof s->prompt },
        { "SETTITLE",  s->title,        sizeof s->title },
        { "SETOK",     s->ok_label,     sizeof s->ok_label },
        { "SETCANCEL", s->cancel_label, sizeof s->cancel_label },
        { "SETNOTOK",  s->notok_label,  sizeof s->notok_label },
        { "SETERROR",  s->error,        sizeof s->error },
    };
    /* Case-insensitive to match the dispatcher in main.c: matching with
     * strcmp there and strcasecmp here meant a lowercase `setkeyinfo` was
     * accepted, dropped, and answered OK — silently disabling the
     * Keychain path for that session. */
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++) {
        if (strcasecmp(cmd, map[i].cmd) == 0) {
            field_copy(map[i].dst, map[i].cap, args);
            return 0;
        }
    }
    if (strcasecmp(cmd, "SETKEYINFO") == 0) {
        /* "n/<KEYGRIP>" or "--" (no caching). Store keygrip sans prefix. */
        if (!*args || strcmp(args, "--") == 0)
            memset(s->keygrip, 0, sizeof s->keygrip);
        else
            field_copy(s->keygrip, sizeof s->keygrip,
                       args[0] && args[1] == '/' ? args + 2 : args);
        return 0;
    }
    return -1;
}
