/* test_assuan.c — unit tests for src/assuan.c.
 * Plain C, no frameworks. Prints "PASS <name>" per test; exits non-zero
 * on the first failure. SPDX-License-Identifier: MIT */
#include "../src/assuan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *cur_test = "?";

#define ASSERT(cond) do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s: %s (%s:%d)\n", \
                    cur_test, #cond, __FILE__, __LINE__); \
            exit(1); \
        } \
    } while (0)

#define RUN(fn) do { cur_test = #fn; fn(); printf("PASS %s\n", #fn); } while (0)

/* --- helpers ------------------------------------------------------------ */

static FILE *
input(const char *s)
{
    FILE *f = fmemopen((void *)s, strlen(s), "r");
    ASSERT(f != NULL);
    return f;
}

/* --- percent decode ----------------------------------------------------- */

static void test_decode_normal(void)
{
    char s[] = "Hello%20World%21";
    ASSERT(assuan_percent_decode(s) == 12);
    ASSERT(strcmp(s, "Hello World!") == 0);
}

static void test_decode_percent25(void)
{
    char s[] = "50%25%2b";
    ASSERT(assuan_percent_decode(s) == 4);
    ASSERT(strcmp(s, "50%+") == 0);
}

static void test_decode_invalid_escape(void)
{
    char a[] = "%zz";                    /* bad hex digits */
    ASSERT(assuan_percent_decode(a) == 3);
    ASSERT(strcmp(a, "%zz") == 0);
    char b[] = "abc%2";                  /* truncated escape at end */
    ASSERT(assuan_percent_decode(b) == 5);
    ASSERT(strcmp(b, "abc%2") == 0);
    char c[] = "tail%";                  /* lone % at end */
    ASSERT(assuan_percent_decode(c) == 5);
    ASSERT(strcmp(c, "tail%") == 0);
}

static void test_decode_empty(void)
{
    char s[] = "";
    ASSERT(assuan_percent_decode(s) == 0);
    ASSERT(s[0] == '\0');
}

/* --- data escaping ------------------------------------------------------ */

static void test_send_data_escaping(void)
{
    const unsigned char payload[] = "pw%1\r\n2";     /* has %, CR, LF */
    size_t plen = sizeof payload - 1;
    char *out = NULL;
    size_t outsz = 0;
    FILE *f = open_memstream(&out, &outsz);
    ASSERT(f != NULL);
    ASSERT(assuan_send_data(f, payload, plen) == 0);
    fclose(f);
    ASSERT(strcmp(out, "D pw%251%0D%0A2\n") == 0);

    /* round-trip: strip "D " and "\n", decode, compare to original */
    char dec[64];
    size_t body = outsz - 3;             /* minus "D " and trailing "\n" */
    memcpy(dec, out + 2, body);
    dec[body] = '\0';
    ASSERT(assuan_percent_decode(dec) == plen);
    ASSERT(memcmp(dec, payload, plen) == 0);
    free(out);
}

static void test_send_data_plain(void)
{
    char *out = NULL;
    size_t outsz = 0;
    FILE *f = open_memstream(&out, &outsz);
    ASSERT(f != NULL);
    ASSERT(assuan_send_data(f, (const unsigned char *)"secret", 6) == 0);
    fclose(f);
    ASSERT(strcmp(out, "D secret\n") == 0);
    free(out);
}

/* --- read_line ---------------------------------------------------------- */

static void test_read_line_lf(void)
{
    char buf[ASSUAN_LINE_MAX + 1];
    FILE *f = input("GETPIN\nBYE\n");
    ASSERT(assuan_read_line(f, buf, sizeof buf) == 6);
    ASSERT(strcmp(buf, "GETPIN") == 0);
    ASSERT(assuan_read_line(f, buf, sizeof buf) == 3);
    ASSERT(strcmp(buf, "BYE") == 0);
    ASSERT(assuan_read_line(f, buf, sizeof buf) == -1);   /* clean EOF */
    fclose(f);
}

static void test_read_line_crlf(void)
{
    char buf[ASSUAN_LINE_MAX + 1];
    FILE *f = input("SETDESC hi\r\nNOP\r\n");
    ASSERT(assuan_read_line(f, buf, sizeof buf) == 10);
    ASSERT(strcmp(buf, "SETDESC hi") == 0);
    ASSERT(assuan_read_line(f, buf, sizeof buf) == 3);
    ASSERT(strcmp(buf, "NOP") == 0);
    fclose(f);
}

static void test_read_line_eof_partial(void)
{
    char buf[ASSUAN_LINE_MAX + 1];
    FILE *f = input("BYE");              /* no trailing newline */
    ASSERT(assuan_read_line(f, buf, sizeof buf) == 3);
    ASSERT(strcmp(buf, "BYE") == 0);
    ASSERT(assuan_read_line(f, buf, sizeof buf) == -1);
    fclose(f);
}

static void test_read_line_empty(void)
{
    char buf[ASSUAN_LINE_MAX + 1];
    FILE *f = input("\nX\n");
    ASSERT(assuan_read_line(f, buf, sizeof buf) == 0);
    ASSERT(buf[0] == '\0');
    ASSERT(assuan_read_line(f, buf, sizeof buf) == 1);
    ASSERT(strcmp(buf, "X") == 0);
    fclose(f);
}

static void test_read_line_exact_max(void)
{
    char buf[ASSUAN_LINE_MAX + 1];
    char *in = malloc(ASSUAN_LINE_MAX + 2);
    ASSERT(in != NULL);
    memset(in, 'a', ASSUAN_LINE_MAX);
    in[ASSUAN_LINE_MAX] = '\n';
    in[ASSUAN_LINE_MAX + 1] = '\0';
    FILE *f = input(in);
    ASSERT(assuan_read_line(f, buf, sizeof buf) == ASSUAN_LINE_MAX);
    ASSERT(strlen(buf) == ASSUAN_LINE_MAX);
    ASSERT(buf[0] == 'a' && buf[ASSUAN_LINE_MAX - 1] == 'a');
    fclose(f);
    free(in);
}

static void test_read_line_too_long(void)
{
    char buf[ASSUAN_LINE_MAX + 1];
    size_t n = ASSUAN_LINE_MAX + 1;      /* one byte over the limit */
    char *in = malloc(n + 1 + 5 + 1);    /* + "\n" + "NEXT\n" + NUL */
    ASSERT(in != NULL);
    memset(in, 'b', n);
    memcpy(in + n, "\nNEXT\n", 7);
    FILE *f = input(in);
    ASSERT(assuan_read_line(f, buf, sizeof buf) == -2);
    /* the oversized line was drained: the next line is still readable */
    ASSERT(assuan_read_line(f, buf, sizeof buf) == 4);
    ASSERT(strcmp(buf, "NEXT") == 0);
    fclose(f);
    free(in);
}

/* --- split -------------------------------------------------------------- */

static void test_split_with_args(void)
{
    char line[] = "SETDESC Please enter";
    char *cmd, *args;
    assuan_split(line, &cmd, &args);
    ASSERT(strcmp(cmd, "SETDESC") == 0);
    ASSERT(strcmp(args, "Please enter") == 0);
}

static void test_split_no_args(void)
{
    char line[] = "GETPIN";
    char *cmd, *args;
    assuan_split(line, &cmd, &args);
    ASSERT(strcmp(cmd, "GETPIN") == 0);
    ASSERT(strcmp(args, "") == 0);
}

static void test_split_multi_space(void)
{
    char line[] = "OPTION   ttyname=/dev/ttys0";
    char *cmd, *args;
    assuan_split(line, &cmd, &args);
    ASSERT(strcmp(cmd, "OPTION") == 0);
    ASSERT(strcmp(args, "ttyname=/dev/ttys0") == 0);
}

/* --- reply formatting --------------------------------------------------- */

static void test_err_canceled_exact(void)
{
    ASSERT(PE_ERR_CANCELED == 83886179u);            /* exact wire value, see assuan.h */
    char *out = NULL;
    size_t outsz = 0;
    FILE *f = open_memstream(&out, &outsz);
    ASSERT(f != NULL);
    ASSERT(assuan_send_err(f, PE_ERR_CANCELED, "Operation cancelled") == 0);
    fclose(f);
    ASSERT(strcmp(out, "ERR 83886179 Operation cancelled\n") == 0);
    free(out);
}

static void test_ok_and_status(void)
{
    char *out = NULL;
    size_t outsz = 0;
    FILE *f = open_memstream(&out, &outsz);
    ASSERT(f != NULL);
    ASSERT(assuan_send_ok(f, NULL) == 0);
    ASSERT(assuan_send_ok(f, "Pleased to meet you") == 0);
    ASSERT(assuan_send_status(f, "PASSWORD_FROM_CACHE", NULL) == 0);
    ASSERT(assuan_send_status(f, "PROGRESS", "1 of 2") == 0);
    fclose(f);
    ASSERT(strcmp(out,
                  "OK\n"
                  "OK Pleased to meet you\n"
                  "S PASSWORD_FROM_CACHE\n"
                  "S PROGRESS 1 of 2\n") == 0);
    free(out);
}

int
main(void)
{
    RUN(test_decode_normal);
    RUN(test_decode_percent25);
    RUN(test_decode_invalid_escape);
    RUN(test_decode_empty);
    RUN(test_send_data_escaping);
    RUN(test_send_data_plain);
    RUN(test_read_line_lf);
    RUN(test_read_line_crlf);
    RUN(test_read_line_eof_partial);
    RUN(test_read_line_empty);
    RUN(test_read_line_exact_max);
    RUN(test_read_line_too_long);
    RUN(test_split_with_args);
    RUN(test_split_no_args);
    RUN(test_split_multi_space);
    RUN(test_err_canceled_exact);
    RUN(test_ok_and_status);
    printf("All tests passed\n");
    return 0;
}
