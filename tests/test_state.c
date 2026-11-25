/* test_state.c — unit tests for state.c and secure_mem.c.
 * Links only state.c + secure_mem.c; no assuan.c dependency.
 * SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../src/secure_mem.h"
#include "../src/state.h"

#define PASS(name) printf("PASS %s\n", name)

static pe_state st;

static void test_option_parsing(void)
{
    state_init(&st);
    assert(state_handle_option(&st, "ttyname=/dev/ttys001") == 0);
    assert(strcmp(st.ttyname, "/dev/ttys001") == 0);
    assert(state_handle_option(&st, "--ttytype=xterm-256color") == 0);
    assert(strcmp(st.ttytype, "xterm-256color") == 0);
    assert(state_handle_option(&st, "lc-ctype=en_US.UTF-8") == 0);
    assert(strcmp(st.lc_ctype, "en_US.UTF-8") == 0);
    assert(state_handle_option(&st, "--lc-messages=C") == 0);
    assert(strcmp(st.lc_messages, "C") == 0);
    /* no value */
    assert(state_handle_option(&st, "no-grab") == 0);
    /* unknown options accepted */
    assert(state_handle_option(&st, "default-ok=_OK") == 0);
    assert(state_handle_option(&st, "touch-file=/tmp/x") == 0);
    assert(state_handle_option(&st, "putenv=DISPLAY=:0") == 0);
    PASS("option_parsing");
}

static void test_option_allow_external_cache(void)
{
    state_init(&st);
    assert(!st.allow_external_cache);
    assert(state_handle_option(&st, "allow-external-password-cache") == 0);
    assert(st.allow_external_cache);
    assert(state_handle_option(&st, "allow-external-password-cache=0") == 0);
    assert(!st.allow_external_cache);
    assert(state_handle_option(&st, "--allow-external-password-cache=1") == 0);
    assert(st.allow_external_cache);
    PASS("option_allow_external_cache");
}

static void test_set_fields(void)
{
    state_init(&st);
    char desc[] = "Please enter the passphrase", prompt[] = "Passphrase:",
         title[] = "pinentry", ok[] = "_OK", cancel[] = "_Cancel",
         notok[] = "_Not OK", err[] = "Bad Passphrase (try 2 of 3)";
    assert(state_handle_set(&st, "SETDESC", desc) == 0);
    assert(state_handle_set(&st, "SETPROMPT", prompt) == 0);
    assert(state_handle_set(&st, "SETTITLE", title) == 0);
    assert(state_handle_set(&st, "SETOK", ok) == 0);
    assert(state_handle_set(&st, "SETCANCEL", cancel) == 0);
    assert(state_handle_set(&st, "SETNOTOK", notok) == 0);
    assert(state_handle_set(&st, "SETERROR", err) == 0);
    assert(strcmp(st.desc, desc) == 0);
    assert(strcmp(st.prompt, prompt) == 0);
    assert(strcmp(st.title, title) == 0);
    assert(strcmp(st.ok_label, ok) == 0);
    assert(strcmp(st.cancel_label, cancel) == 0);
    assert(strcmp(st.notok_label, notok) == 0);
    assert(strcmp(st.error, err) == 0);
    PASS("set_fields");
}

#define GRIP "8CF2B57D48F5D42A6D1B4A6A2C1AC1D6E5F30583"

/* Set a valid keygrip, then send `val`: it must leave the keygrip empty. */
static void assert_keyinfo_clears(const char *val)
{
    char ki[] = "n/" GRIP, buf[PE_FIELD_MAX];
    assert(state_handle_set(&st, "SETKEYINFO", ki) == 0);
    assert(strcmp(st.keygrip, GRIP) == 0);
    snprintf(buf, sizeof buf, "%s", val);
    assert(state_handle_set(&st, "SETKEYINFO", buf) == 0);
    assert(st.keygrip[0] == '\0');
}

static void test_setkeyinfo(void)
{
    state_init(&st);
    /* n/ and s/ carry a keygrip: 40 hex digits, either case. */
    char ki[] = "s/" GRIP;
    assert(state_handle_set(&st, "SETKEYINFO", ki) == 0);
    assert(strcmp(st.keygrip, GRIP) == 0);
    char lower[] = "n/8cf2b57d48f5d42a6d1b4a6a2c1ac1d6e5f30583";
    assert(state_handle_set(&st, "SETKEYINFO", lower) == 0);
    assert(strcmp(st.keygrip, lower + 2) == 0);
    /* u/ carries a GET_PASSPHRASE cache ID, e.g. gpg's symmetric "S<salt>" */
    char sym[] = "u/S0123456789ABCDEF";
    assert(state_handle_set(&st, "SETKEYINFO", sym) == 0);
    assert(strcmp(st.keygrip, "S0123456789ABCDEF") == 0);
    /* What gpg-agent sends before uncacheable prompts (new passphrase and
     * its re-entry): must clear, never become a keygrip. */
    assert_keyinfo_clears("--clear");
    assert_keyinfo_clears("--");
    assert_keyinfo_clears("");
    assert_keyinfo_clears(GRIP);                 /* no "<mode>/" prefix */
    assert_keyinfo_clears("x/" GRIP);            /* unknown mode */
    assert_keyinfo_clears("n/");                 /* empty id */
    assert_keyinfo_clears("n/DEADBEEF");         /* too short for a grip */
    assert_keyinfo_clears("n/" GRIP "00");       /* too long for a grip */
    assert_keyinfo_clears("n/8CF2B57D48F5D42A6D1B4A6A2C1AC1D6E5F3058G");
    assert_keyinfo_clears("u/two words");        /* not one word */
    assert_keyinfo_clears("u/tab\there");
    PASS("setkeyinfo");
}

static void test_reset_preserves_options(void)
{
    state_init(&st);
    assert(state_handle_option(&st, "ttyname=/dev/ttys009") == 0);
    assert(state_handle_option(&st, "allow-external-password-cache") == 0);
    char desc[] = "d", err[] = "e", ki[] = "n/" GRIP;
    assert(state_handle_set(&st, "SETDESC", desc) == 0);
    assert(state_handle_set(&st, "SETERROR", err) == 0);
    assert(state_handle_set(&st, "SETKEYINFO", ki) == 0);
    assert(st.keygrip[0] != '\0');
    state_reset(&st);
    assert(st.desc[0] == '\0' && st.prompt[0] == '\0' && st.title[0] == '\0');
    assert(st.ok_label[0] == '\0' && st.cancel_label[0] == '\0');
    assert(st.notok_label[0] == '\0' && st.error[0] == '\0');
    assert(st.keygrip[0] == '\0');
    assert(strcmp(st.ttyname, "/dev/ttys009") == 0);  /* options survive */
    assert(st.allow_external_cache);
    PASS("reset_preserves_options");
}

static void test_unknown_set_command(void)
{
    state_init(&st);
    char args[] = "x";
    assert(state_handle_set(&st, "SETQUALITYBAR", args) == -1);
    assert(state_handle_set(&st, "SETFOO", args) == -1);
    PASS("unknown_set_command");
}

/* Assuan verbs are case-insensitive, and main.c dispatches with strcasecmp:
 * a lowercase SET* must be stored, not silently dropped. */
static void test_set_command_case_insensitive(void)
{
    state_init(&st);
    char desc[] = "hello";
    assert(state_handle_set(&st, "setdesc", desc) == 0);
    assert(strcmp(st.desc, "hello") == 0);
    char grip[] = "n/" GRIP;
    assert(state_handle_set(&st, "SetKeyInfo", grip) == 0);
    assert(strcmp(st.keygrip, GRIP) == 0);
    PASS("set_command_case_insensitive");
}

static void test_oversized_args_truncated(void)
{
    static char big[PE_FIELD_MAX + 100];
    memset(big, 'A', sizeof big - 1);
    big[sizeof big - 1] = '\0';
    state_init(&st);
    assert(state_handle_set(&st, "SETDESC", big) == 0);
    assert(strlen(st.desc) == PE_FIELD_MAX - 1);  /* truncated, NUL-terminated */
    /* A keyinfo id is rejected, never truncated: two long ids sharing a
     * prefix must not map to one Keychain item. u/ is the mode whose ids
     * have no fixed length; the longest that fits is stored whole. */
    big[0] = 'u';
    big[1] = '/';
    big[2 + PE_KEYGRIP_MAX] = '\0';             /* id one byte too long */
    assert(state_handle_set(&st, "SETKEYINFO", big) == 0);
    assert(st.keygrip[0] == '\0');
    big[2 + PE_KEYGRIP_MAX - 1] = '\0';         /* the longest that fits */
    assert(state_handle_set(&st, "SETKEYINFO", big) == 0);
    assert(strlen(st.keygrip) == PE_KEYGRIP_MAX - 1);
    PASS("oversized_args_truncated");
}

/* Keychain use needs both the agent's allow-external-password-cache and a
 * keyinfo, as in reference pinentry's cmd_getpin. */
static void test_external_cache_gate(void)
{
    state_init(&st);
    char ki[] = "n/8CF2B57D48F5D42A6D1B4A6A2C1AC1D6E5F30583";
    assert(state_handle_set(&st, "SETKEYINFO", ki) == 0);
    assert(!state_external_cache_allowed(&st)); /* no-allow-external-cache */
    assert(state_handle_option(&st, "allow-external-password-cache") == 0);
    assert(state_external_cache_allowed(&st));
    char clear[] = "--clear";
    assert(state_handle_set(&st, "SETKEYINFO", clear) == 0);
    assert(!state_external_cache_allowed(&st)); /* uncacheable prompt */
    PASS("external_cache_gate");
}

static void test_secure_mem(void)
{
    unsigned char *p = secure_alloc(64);
    assert(p != NULL);
    memset(p, 0xAA, 64);
    secure_wipe(p, 64);
    for (int i = 0; i < 64; i++)
        assert(p[i] == 0);
    memset(p, 0x55, 64);  /* dirty again, then wipe+free */
    secure_free(p, 64);
    secure_free(NULL, 16);  /* safe on NULL */
    secure_wipe(NULL, 0);

    /* Two small secrets never share a page: munlock on one must not
     * unlock the other. */
    uintptr_t pg = (uintptr_t)getpagesize();
    unsigned char *a = secure_alloc(16), *b = secure_alloc(16);
    assert(a && b);
    assert((uintptr_t)a % pg == 0 && (uintptr_t)b % pg == 0);
    assert((uintptr_t)a / pg != (uintptr_t)b / pg);
    secure_free(a, 16);
    secure_free(b, 16);

    /* Zero length (keychain_lookup on an empty item) and multi-page. */
    unsigned char *z = secure_alloc(0);
    assert(z != NULL);
    secure_free(z, 0);
    size_t big = (size_t)pg * 2 + 1;
    unsigned char *m = secure_alloc(big);
    assert(m != NULL && m[big - 1] == 0);
    memset(m, 0x5A, big);
    secure_free(m, big);
    PASS("secure_mem");
}

int main(void)
{
    secure_process_init();
    test_option_parsing();
    test_option_allow_external_cache();
    test_set_fields();
    test_setkeyinfo();
    test_reset_preserves_options();
    test_unknown_set_command();
    test_set_command_case_insensitive();
    test_oversized_args_truncated();
    test_external_cache_gate();
    test_secure_mem();
    printf("all tests passed\n");
    return 0;
}
