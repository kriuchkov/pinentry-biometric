/* biometry.h — user-facing dialogs without AppKit.
 * CONFIRM/MESSAGE via CFUserNotification; GUI session detection.
 * Implemented in biometry.m (CoreFoundation + Security/AuthSession; no
 * LocalAuthentication here — that lives in keychain.m, and no AppKit).
 * SPDX-License-Identifier: MIT */
#ifndef PE_BIOMETRY_H
#define PE_BIOMETRY_H

#include <stdbool.h>

/* Modal confirmation dialog. Labels fall back to "OK"/"Cancel" when NULL
 * or empty. Returns 0 = confirmed, 1 = canceled, -1 = cannot display. */
int ui_confirm(const char *title, const char *message,
               const char *ok_label, const char *cancel_label);

/* Modal message dialog with a single OK button. 0 on success, -1 on error. */
int ui_message(const char *title, const char *message);

/* True if we can show GUI dialogs (an Aqua session is reachable).
 * False in a bare SSH session — callers must fail fast, not hang. */
bool ui_session_available(void);

#endif /* PE_BIOMETRY_H */
