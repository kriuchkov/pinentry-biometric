/* state.h — per-session pinentry state: OPTION and SET* fields, RESET.
 * SPDX-License-Identifier: MIT */
#ifndef PE_STATE_H
#define PE_STATE_H

#include <stdbool.h>

#include "assuan.h"

/* Field buffers sized to hold any percent-decoded Assuan line payload. */
#define PE_FIELD_MAX (ASSUAN_LINE_MAX + 1)
#define PE_KEYGRIP_MAX 128

typedef struct {
    /* SET* fields, stored percent-decoded */
    char desc[PE_FIELD_MAX];
    char prompt[PE_FIELD_MAX];
    char title[PE_FIELD_MAX];
    char ok_label[PE_FIELD_MAX];
    char cancel_label[PE_FIELD_MAX];
    char notok_label[PE_FIELD_MAX];
    char error[PE_FIELD_MAX];   /* SETERROR: non-empty => agent rejected a
                                   previously returned passphrase */
    /* SETKEYINFO: keygrip without the "n/" prefix; "" if none or "--" */
    char keygrip[PE_KEYGRIP_MAX];

    /* OPTIONs we track; unknown options are accepted and ignored */
    bool allow_external_cache;  /* allow-external-password-cache */
    char ttyname[PE_FIELD_MAX];
    char ttytype[64];
    char lc_ctype[64];
    char lc_messages[64];
} pe_state;

void state_init(pe_state *s);

/* RESET: clear SET* fields (desc/prompt/title/labels/error/keygrip).
 * OPTION values survive RESET, matching reference pinentry behaviour. */
void state_reset(pe_state *s);

/* Handle "OPTION name[=value]". Never fails: unknown names return 0 (OK). */
int state_handle_option(pe_state *s, const char *args);

/* Handle SETDESC/SETPROMPT/SETTITLE/SETOK/SETCANCEL/SETNOTOK/SETERROR/
 * SETKEYINFO. `args` must already be percent-decoded by the caller
 * (state.c has no dependency on assuan.c). Returns 0 if the command was
 * recognized and stored, -1 if `cmd` is not a known SET* command. */
int state_handle_set(pe_state *s, const char *cmd, char *args);

#endif /* PE_STATE_H */
