/* main.c — pinentry-biometric: entry point and Assuan command loop.
 * Protocol reference: GnuPG pinentry (pinentry/pinentry.c).
 * stdout carries protocol only; debug goes to stderr; secrets only in D lines.
 * SPDX-License-Identifier: MIT */
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "assuan.h"
#include "biometry.h"
#include "fallback.h"
#include "keychain.h"
#include "secure_mem.h"
#include "state.h"

#define PE_VERSION "0.1.0"

static bool g_debug = false;
static const char *g_fallback_path = NULL;
static pe_access_control g_ac = PE_AC_USER_PRESENCE;
/* Keygrip whose passphrase the Keychain last answered for: if the
 * agent then repeats GETPIN with SETERROR, the stored item is stale. */
static char g_kc_served[PE_KEYGRIP_MAX];

/* Copy printable ASCII only, dropping control characters and anything
 * non-ASCII. The description is attacker-supplied (any process may speak
 * SETDESC to us) and lands verbatim in the Touch ID sheet, so bidi
 * overrides and homoglyphs must not survive into text the user is asked
 * to judge. */
static void sanitize(const char *src, char *dst, size_t cap, size_t max)
{
    size_t n = 0;
    if (cap == 0)
        return;
    if (max > cap - 1)
        max = cap - 1;
    for (const unsigned char *p = (const unsigned char *)src;
         *p != '\0' && n < max; p++) {
        if (*p >= 0x20 && *p < 0x7f)
            dst[n++] = (char)*p;
    }
    dst[n] = '\0';
}

/* Touch ID dialog reason. The fixed first sentence is ours, so an attacker
 * cannot own the whole prompt; the keygrip is the only trustworthy detail
 * and the description that follows is merely a hint (see README threat
 * model). No secrets here. */
static void build_reason(const pe_state *st, char *out, size_t cap)
{
    char grip[17], desc[121];
    sanitize(st->keygrip, grip, sizeof grip, 16);
    sanitize(st->desc, desc, sizeof desc, 120);
    snprintf(out, cap, "release the GPG passphrase for key %s. Requested: %s",
             grip[0] ? grip : "(none)",
             desc[0] ? desc : "(no description)");
}

static void cmd_getpin(FILE *out, pe_state *st)
{
    if (!ui_session_available()) { /* fail fast, never hang */
        assuan_send_err(out, PE_ERR_NO_PIN_ENTRY, "No GUI session available");
        return;
    }
    /* SETERROR means the agent rejected the last passphrase, so never answer
     * this GETPIN from the Keychain — a retry that arrives on a *fresh*
     * connection has an empty g_kc_served, and keying the decision on that
     * alone would hand back the same rejected passphrase until the agent
     * gives up, never offering the prompt.
     *
     * Deleting the item stays gated on having served it from this process,
     * which required passing the user-presence check: otherwise any process
     * could destroy a stored passphrase with SETERROR + GETPIN and no
     * authentication at all. */
    bool first_entry_forced = st->error[0] && st->keygrip[0];
    if (first_entry_forced && strcmp(g_kc_served, st->keygrip) == 0) {
        keychain_delete(st->keygrip);
        g_kc_served[0] = '\0';
    }
    if (!first_entry_forced && st->keygrip[0] && !keychain_disabled()) {
        char reason[PE_FIELD_MAX + 64];
        build_reason(st, reason, sizeof(reason));
        unsigned char *pw = NULL;
        size_t len = 0;
        kc_status ks = keychain_lookup(st->keygrip, reason, g_ac, &pw, &len);
        if (ks == KC_OK) {
            if (st->allow_external_cache)
                assuan_send_status(out, "PASSWORD_FROM_CACHE", "");
            /* A failed send must not be followed by OK: the agent would
             * read that as a successful empty passphrase and then delete
             * this very item as "stale". */
            if (assuan_send_data(out, pw, len) == 0)
                assuan_send_ok(out, NULL);
            else
                assuan_send_err(out, PE_ERR_INTERNAL, "could not send data");
            secure_free(pw, len);
            snprintf(g_kc_served, sizeof(g_kc_served), "%s", st->keygrip);
            st->error[0] = '\0';
            return;
        }
        if (ks == KC_CANCELED) {
            assuan_send_err(out, PE_ERR_CANCELED, "Operation cancelled");
            return;
        }
        /* KC_NOT_FOUND / KC_ERROR: degrade gracefully to first entry */
    }
    /* First entry via fallback pinentry-mac (see DESIGN.md) */
    char *found = NULL;
    const char *path = g_fallback_path;
    if (path == NULL)
        path = found = fallback_find();
    if (path == NULL) {
        assuan_send_err(out, PE_ERR_NO_PIN_ENTRY,
                        "fallback pinentry-mac not found; install pinentry-mac "
                        "or pass --fallback-pinentry");
        return;
    }
    unsigned char *pw = NULL;
    size_t len = 0;
    int rc = fallback_getpin(st, path, &pw, &len);
    free(found);
    if (rc == 1) {
        assuan_send_err(out, PE_ERR_CANCELED, "Operation cancelled");
        return;
    }
    if (rc != 0) {
        assuan_send_err(out, PE_ERR_INTERNAL, "fallback pinentry failed");
        return;
    }
    if (st->keygrip[0] && !keychain_disabled() &&
        ui_confirm("pinentry-biometric",
                   "Save passphrase to Keychain (unlock with Touch ID)?",
                   "Save", "Don't Save") == 0) {
        /* Store failure is not fatal: the passphrase is still returned. */
        if (keychain_store(st->keygrip, pw, len, g_ac) == KC_OK)
            snprintf(g_kc_served, sizeof(g_kc_served), "%s", st->keygrip);
    }
    if (assuan_send_data(out, pw, len) == 0)
        assuan_send_ok(out, NULL);
    else
        assuan_send_err(out, PE_ERR_INTERNAL, "could not send data");
    secure_free(pw, len);
    st->error[0] = '\0';
}

static void cmd_confirm(FILE *out, const pe_state *st, const char *args)
{
    if (!ui_session_available()) { /* fail fast, never hang */
        assuan_send_err(out, PE_ERR_NO_PIN_ENTRY, "No GUI session available");
        return;
    }
    const char *title = st->title[0] ? st->title : st->desc;
    if (args != NULL && strstr(args, "--one-button") != NULL) {
        /* CONFIRM --one-button == MESSAGE. An OK here asserts the user saw
         * the text, so a dialog that never rendered must not report one. */
        if (ui_message(title, st->desc) == 0)
            assuan_send_ok(out, NULL);
        else
            assuan_send_err(out, PE_ERR_INTERNAL, "could not show dialog");
        return;
    }
    const char *cancel =
        st->notok_label[0] ? st->notok_label : st->cancel_label;
    /* Reference pinentry distinguishes these: "no" is NOT_CONFIRMED, a
     * dialog that could not be shown or was dismissed is CANCELED. */
    switch (ui_confirm(title, st->desc, st->ok_label, cancel)) {
    case 0:
        assuan_send_ok(out, NULL);
        break;
    case 1:
        assuan_send_err(out, PE_ERR_NOT_CONFIRMED, "Not confirmed");
        break;
    default:
        assuan_send_err(out, PE_ERR_CANCELED, "Operation cancelled");
    }
}

/* Same contract as CONFIRM --one-button: OK means the user saw the text. */
static void cmd_message(FILE *out, const pe_state *st)
{
    if (!ui_session_available()) {
        assuan_send_err(out, PE_ERR_NO_PIN_ENTRY, "No GUI session available");
        return;
    }
    if (ui_message(st->title[0] ? st->title : st->desc, st->desc) == 0)
        assuan_send_ok(out, NULL);
    else
        assuan_send_err(out, PE_ERR_INTERNAL, "could not show dialog");
}

static void cmd_getinfo(FILE *out, const pe_state *st, const char *what)
{
    char buf[PE_FIELD_MAX + 80];
    if (strcasecmp(what, "pid") == 0) {
        snprintf(buf, sizeof(buf), "%ld", (long)getpid());
    } else if (strcasecmp(what, "version") == 0) {
        snprintf(buf, sizeof(buf), "%s", PE_VERSION);
    } else if (strcasecmp(what, "flavor") == 0) {
        snprintf(buf, sizeof(buf), "%s", "biometric");
    } else if (strcasecmp(what, "ttyinfo") == 0) {
        const char *disp = getenv("DISPLAY");
        snprintf(buf, sizeof(buf), "%s %s %s",
                 st->ttyname[0] ? st->ttyname : "-",
                 st->ttytype[0] ? st->ttytype : "-",
                 (disp != NULL && disp[0]) ? disp : "-");
    } else {
        assuan_send_err(out, PE_ERR_ASS_UNKNOWN_CMD, "Unknown GETINFO item");
        return;
    }
    /* Same invariant as GETPIN (assuan.h): OK only after the data line
     * actually went out, or the peer reads a bare OK as an empty answer. */
    if (assuan_send_data(out, (const unsigned char *)buf, strlen(buf)) == 0)
        assuan_send_ok(out, NULL);
    else
        assuan_send_err(out, PE_ERR_INTERNAL, "could not send data");
}

static bool is_set_cmd(const char *cmd)
{
    static const char *const names[] = { "SETDESC",   "SETPROMPT", "SETTITLE",
                                         "SETOK",     "SETCANCEL", "SETNOTOK",
                                         "SETERROR",  "SETKEYINFO" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (strcasecmp(cmd, names[i]) == 0)
            return true;
    return false;
}

/* Accepted but intentionally inert: behave as plain GETPIN. */
static bool is_ignored_set_cmd(const char *cmd)
{
    static const char *const names[] = { "SETQUALITYBAR", "SETQUALITYBAR_TT",
                                         "SETREPEAT",     "SETREPEATERROR",
                                         "SETREPEATOK",   "SETTIMEOUT" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (strcasecmp(cmd, names[i]) == 0)
            return true;
    return false;
}

static void usage(void)
{
    puts("Usage: pinentry-biometric [OPTIONS]\n"
         "GnuPG pinentry for macOS: Keychain storage unlocked by Touch ID.\n"
         "\n"
         "  --version                 print version and exit\n"
         "  --help                    show this help and exit\n"
         "  --debug                   log protocol to stderr (secrets masked)\n"
         "  --fallback-pinentry <p>   pinentry-mac binary for first entry\n"
         "  --access-control=user-presence|biometry-current-set\n"
         "                            Keychain item ACL (default user-presence)\n"
         "\n"
         "Unknown options are ignored for pinentry-mac CLI compatibility.");
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--version") == 0) {
            puts("pinentry-biometric " PE_VERSION);
            return 0;
        } else if (strcmp(a, "--help") == 0) {
            usage();
            return 0;
        } else if (strcmp(a, "--debug") == 0) {
            g_debug = true;
            assuan_set_debug(true);
        } else if (strcmp(a, "--fallback-pinentry") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "pinentry-biometric: --fallback-pinentry "
                                "needs a path\n");
                return 2;
            }
            g_fallback_path = argv[++i];
        } else if (strncmp(a, "--fallback-pinentry=", 20) == 0) {
            g_fallback_path = a + 20;
        } else if (strncmp(a, "--access-control=", 17) == 0 ||
                   strcmp(a, "--access-control") == 0) {
            /* Both spellings: silently ignoring the space-separated form
             * would downgrade the policy to the weaker default while the
             * user believes they asked for the stricter one. */
            const char *v;
            if (a[16] == '=') {
                v = a + 17;
            } else if (i + 1 < argc) {
                v = argv[++i];
            } else {
                fprintf(stderr, "pinentry-biometric: --access-control needs "
                                "a mode\n");
                return 2;
            }
            if (strcmp(v, "biometry-current-set") == 0) {
                g_ac = PE_AC_BIOMETRY_CURRENT_SET;
            } else if (strcmp(v, "user-presence") == 0) {
                g_ac = PE_AC_USER_PRESENCE;
            } else {
                fprintf(stderr,
                        "pinentry-biometric: invalid --access-control '%s'\n",
                        v);
                return 2;
            }
        }
        /* anything else (e.g. --display <d>) is accepted and ignored */
    }

    secure_process_init();
    signal(SIGPIPE, SIG_IGN);
    /* Unbuffered: stdio would otherwise keep a plaintext copy of the
     * passphrase in a heap buffer that fflush does not clear and that is
     * handed back to the allocator unwiped at exit. */
    setvbuf(stdout, NULL, _IONBF, 0);
    FILE *in = stdin, *out = stdout;
    pe_state st;
    state_init(&st);
    assuan_send_ok(out, "Pleased to meet you");

    char line[ASSUAN_LINE_MAX + 1];
    for (;;) {
        int n = assuan_read_line(in, line, sizeof(line));
        if (n == -1) /* EOF: agent went away */
            return 0;
        if (n == -2) {
            assuan_send_err(out, PE_ERR_ASS_TOO_LONG, "Line too long");
            continue;
        }
        if (g_debug) /* inbound commands carry no secrets */
            fprintf(stderr, "pinentry-biometric< %s\n", line);
        if (line[0] == '\0' || line[0] == '#') { /* comment line */
            assuan_send_ok(out, NULL);
            continue;
        }
        char *cmd, *args;
        assuan_split(line, &cmd, &args);
        if (strcasecmp(cmd, "OPTION") == 0) {
            state_handle_option(&st, args);
            assuan_send_ok(out, NULL);
        } else if (is_set_cmd(cmd)) {
            assuan_percent_decode(args);
            /* Never answer OK for a value we failed to store: a dropped
             * SETKEYINFO silently disables the Keychain path entirely. */
            if (state_handle_set(&st, cmd, args) == 0)
                assuan_send_ok(out, NULL);
            else
                assuan_send_err(out, PE_ERR_INTERNAL, "could not store value");
        } else if (is_ignored_set_cmd(cmd)) {
            assuan_send_ok(out, NULL);
        } else if (strcasecmp(cmd, "GETPIN") == 0) {
            cmd_getpin(out, &st);
        } else if (strcasecmp(cmd, "CONFIRM") == 0) {
            cmd_confirm(out, &st, args);
        } else if (strcasecmp(cmd, "MESSAGE") == 0) {
            cmd_message(out, &st);
        } else if (strcasecmp(cmd, "GETINFO") == 0) {
            cmd_getinfo(out, &st, args);
        } else if (strcasecmp(cmd, "RESET") == 0) {
            state_reset(&st);
            assuan_send_ok(out, NULL);
        } else if (strcasecmp(cmd, "NOP") == 0 ||
                   strcasecmp(cmd, "HELP") == 0) {
            assuan_send_ok(out, NULL);
        } else if (strcasecmp(cmd, "BYE") == 0) {
            assuan_send_ok(out, "closing connection");
            return 0;
        } else {
            assuan_send_err(out, PE_ERR_ASS_UNKNOWN_CMD, "Unknown command");
        }
    }
}
