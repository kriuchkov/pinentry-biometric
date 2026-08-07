/* keychain.h — GnuPG passphrase storage in the macOS Keychain.
 * generic password, service "GnuPG", account = keygrip (pinentry-mac compat).
 * Implemented in keychain.m (Security + LocalAuthentication).
 * SPDX-License-Identifier: MIT */
#ifndef PE_KEYCHAIN_H
#define PE_KEYCHAIN_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    KC_OK = 0,
    KC_NOT_FOUND,   /* no item for this keygrip */
    KC_CANCELED,    /* user canceled the Touch ID / auth dialog */
    KC_ERROR        /* any other Keychain / LAContext failure */
} kc_status;

/* LocalAuthentication policy used to prove user presence before a read.
 * (Not SecAccessControl flags — see the note in keychain.m on why the
 * data-protection keychain is unavailable to this binary.) */
typedef enum {
    PE_AC_USER_PRESENCE = 0,    /* LAPolicyDeviceOwnerAuthentication:
                                   Touch ID or account password (default) */
    PE_AC_BIOMETRY_CURRENT_SET  /* ...WithBiometrics: Touch ID only */
} pe_access_control;

/* Fetch the passphrase for keygrip. `reason` is the localized reason shown
 * in the Touch ID dialog (short keygrip + request description; no secrets).
 * `ac` selects the LocalAuthentication policy: user-presence = Touch ID or
 * account password, biometry-current-set = Touch ID only. User presence is
 * verified via LAContext *before* the item data is read (see keychain.m for
 * why the data-protection keychain + SecAccessControl cannot be used).
 * On KC_OK, *out_pw is a secure_alloc'ed buffer of *out_len bytes (no NUL);
 * caller must secure_free(*out_pw, *out_len). */
kc_status keychain_lookup(const char *keygrip, const char *reason,
                          pe_access_control ac,
                          unsigned char **out_pw, size_t *out_len);

/* Create/replace the login-keychain item for keygrip. `ac` is recorded for
 * API symmetry but enforcement happens at lookup time. */
kc_status keychain_store(const char *keygrip, const unsigned char *pw,
                         size_t len, pe_access_control ac);

/* Delete the item for keygrip. KC_NOT_FOUND if absent. */
kc_status keychain_delete(const char *keygrip);

/* True if saving is disabled via `defaults` domain local.pinentry-biometric,
 * key DisableKeychain (bool). */
bool keychain_disabled(void);

#endif /* PE_KEYCHAIN_H */
