/* test_state.c — unit tests for state.c and secure_mem.c.
 * Links only state.c + secure_mem.c; no assuan.c dependency.
 * SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>

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

static void test_setkeyinfo(void)
{
    state_init(&st);
    char ki[] = "n/8CF2B57D48F5D42A6D1B4A6A2C1AC1D6E5F30583";
    assert(state_handle_set(&st, "SETKEYINFO", ki) == 0);
    assert(strcmp(st.keygrip, "8CF2B57D48F5D42A6D1B4A6A2C1AC1D6E5F30583") == 0);
    char clear[] = "--";
    assert(state_handle_set(&st, "SETKEYINFO", clear) == 0);
    assert(st.keygrip[0] == '\0');
    char ki2[] = "u/DEADBEEF";  /* any single "<char>/" prefix is stripped */
    assert(state_handle_set(&st, "SETKEYINFO", ki2) == 0);
    assert(strcmp(st.keygrip, "DEADBEEF") == 0);
    char empty[] = "";
    assert(state_handle_set(&st, "SETKEYINFO", empty) == 0);
    assert(st.keygrip[0] == '\0');
    PASS("setkeyinfo");
}

static void test_reset_preserves_options(void)
{
    state_init(&st);
    assert(state_handle_option(&st, "ttyname=/dev/ttys009") == 0);
    assert(state_handle_option(&st, "allow-external-password-cache") == 0);
    char desc[] = "d", err[] = "e", ki[] = "n/ABCD";
    assert(state_handle_set(&st, "SETDESC", desc) == 0);
    assert(state_handle_set(&st, "SETERROR", err) == 0);
    assert(state_handle_set(&st, "SETKEYINFO", ki) == 0);
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
    char grip[] = "n/ABCDEF0123";
    assert(state_handle_set(&st, "SetKeyInfo", grip) == 0);
    assert(strcmp(st.keygrip, "ABCDEF0123") == 0);
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
    assert(state_handle_set(&st, "SETKEYINFO", big) == 0);
    assert(strlen(st.keygrip) == PE_KEYGRIP_MAX - 1);
    PASS("oversized_args_truncated");
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
    test_secure_mem();
    printf("all tests passed\n");
    return 0;
}
