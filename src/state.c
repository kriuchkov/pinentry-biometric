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

static bool is_hex(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
           (c >= 'a' && c <= 'f');
}

/* A SETKEYINFO value as gpg-agent builds it in agent_askpin and
 * agent_get_passphrase (gnupg agent/call-pinentry.c): "<mode>/<id>".
 * Modes n (normal) and s (ssh) carry a keygrip, 40 hex digits. Mode u
 * carries the client's GET_PASSPHRASE cache ID (agent/command.c) — for
 * gpg's symmetric encryption "S" plus 16 hex digits of salt
 * (g10/passphrase.c) — so it only has to be one printable word. An id too
 * long to store is rejected, not truncated: ids that share a prefix must
 * not share a Keychain item. */
static bool keyinfo_valid(const char *ki)
{
    if ((ki[0] != 'n' && ki[0] != 's' && ki[0] != 'u') || ki[1] != '/')
        return false;
    const char *id = ki + 2;
    size_t n = strlen(id);
    if (n == 0 || n >= PE_KEYGRIP_MAX)
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)id[i];
        if (ki[0] == 'u' ? (c <= ' ' || c >= 0x7f) : !is_hex(c))
            return false;
    }
    return ki[0] == 'u' || n == 40;
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
        /* Store the id of a well-formed "<mode>/<id>" sans prefix (see
         * keyinfo_valid). Anything else clears it — notably "--clear",
         * which gpg-agent sends before every prompt that must not be
         * cached, including new passphrases and their re-entry (gnupg
         * agent/call-pinentry.c, agent_askpin; pinentry/pinentry.c,
         * cmd_setkeyinfo). Storing "--clear" as a keygrip would save a new
         * passphrase under that shared name and answer the re-entry prompt
         * from the Keychain. */
        if (keyinfo_valid(args)) {
            field_copy(s->keygrip, sizeof s->keygrip, args + 2);
            /* gpg-agent sends a keygrip in upper case. Fold a lower-case
             * one onto it, or the same key would get a second Keychain
             * account. A u/ cache ID is the client's own and stays as is. */
            if (args[0] != 'u') {
                for (char *p = s->keygrip; *p != '\0'; p++) {
                    if (*p >= 'a' && *p <= 'f')
                        *p = (char)(*p - 'a' + 'A');
                }
            }
        } else {
            memset(s->keygrip, 0, sizeof s->keygrip);
        }
        return 0;
    }
    return -1;
}

/* Reference: pinentry/pinentry.c cmd_getpin gates both
 * password_cache_lookup and password_cache_save on
 * "pinentry.allow_external_password_cache && pinentry.keyinfo";
 * gpg-agent sends the option from start_pinentry only when
 * opt.allow_external_cache is set (gnupg agent/call-pinentry.c). */
bool state_external_cache_allowed(const pe_state *s)
{
    return s->allow_external_cache && s->keygrip[0] != '\0';
}
