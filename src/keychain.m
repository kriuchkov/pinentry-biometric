/* keychain.m — GnuPG passphrase storage in the macOS Keychain (keychain.h).
 * generic password, service "GnuPG", account = keygrip (pinentry-mac compat).
 * Items live in the login (file-based) keychain: the data-protection
 * keychain requires a keychain-access-groups/application-identifier
 * entitlement, which an ad-hoc signed CLI cannot carry — SecItemAdd fails
 * with errSecMissingEntitlement, and AMFI kills a process that claims the
 * restricted entitlement without a provisioning profile. User presence is
 * therefore enforced in-process: keychain_lookup first checks the item
 * exists (attributes only, no prompt), then runs LAContext evaluatePolicy
 * (Touch ID with account-password fallback), and only then reads the item
 * data. The item itself is bound to our code signature by the classic
 * keychain ACL: we created it, so we are its trusted application.
 * SPDX-License-Identifier: MIT */
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <string.h>
#include "keychain.h"
#include "secure_mem.h"

/* Base query: class + service "GnuPG" + account keygrip. nil on bad UTF-8. */
static NSMutableDictionary *base_query(const char *keygrip)
{
    NSString *account = keygrip ? [NSString stringWithUTF8String:keygrip] : nil;
    if (!account)
        return nil;
    return [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"GnuPG",
        (__bridge id)kSecAttrAccount: account,
        /* Explicit: the file-based keychain is the default for an
         * unsandboxed CLI, but the whole ACL model below depends on it. */
        (__bridge id)kSecUseDataProtectionKeychain: @NO,
    } mutableCopy];
}

/* Map an OSStatus onto kc_status. errSecUserCanceled covers a canceled
 * keychain-ACL confirmation sheet; errSecAuthFailed is what the system
 * reports once it gives up (denied prompt, exhausted retries) — both are
 * "the user said no", not internal errors. */
static kc_status map_status(OSStatus st)
{
    switch (st) {
    case errSecSuccess:      return KC_OK;
    case errSecItemNotFound: return KC_NOT_FOUND;
    case errSecUserCanceled: return KC_CANCELED;
    case errSecAuthFailed:   return KC_CANCELED;
    default:                 return KC_ERROR;
    }
}

/* Blocking user-presence check via LocalAuthentication. user-presence maps
 * to LAPolicyDeviceOwnerAuthentication (Touch ID or account password);
 * biometry-current-set maps to ...WithBiometrics (Touch ID only, no
 * password fallback). NOTE: without the data-protection keychain the
 * "invalidate on enrollment change" property of BiometryCurrentSet cannot
 * be enforced by the Secure Enclave; the mode degrades to "biometry only". */
static kc_status authenticate(const char *reason, pe_access_control ac)
{
    NSString *why = (reason && *reason)
        ? [NSString stringWithUTF8String:reason]
        : nil;
    LAPolicy policy = (ac == PE_AC_BIOMETRY_CURRENT_SET)
        ? LAPolicyDeviceOwnerAuthenticationWithBiometrics
        : LAPolicyDeviceOwnerAuthentication;
    LAContext *ctx = [LAContext new];
    NSError *avail = nil;
    if (![ctx canEvaluatePolicy:policy error:&avail])
        return KC_ERROR;

    __block kc_status result = KC_ERROR;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [ctx evaluatePolicy:policy
        localizedReason:(why ? why : @"unlock the GnuPG passphrase")
                  reply:^(BOOL ok, NSError *err) {
        if (ok) {
            result = KC_OK;
        } else {
            switch (err.code) {
            case LAErrorUserCancel:
            case LAErrorSystemCancel:
            case LAErrorAppCancel:
            case LAErrorAuthenticationFailed:
                result = KC_CANCELED;
                break;
            default:
                result = KC_ERROR;
            }
        }
        dispatch_semaphore_signal(sem);
    }];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    [ctx invalidate];
    return result;
}

kc_status keychain_lookup(const char *keygrip, const char *reason,
                          pe_access_control ac,
                          unsigned char **out_pw, size_t *out_len)
{
    if (!keygrip || !out_pw || !out_len)
        return KC_ERROR;
    *out_pw = NULL;
    *out_len = 0;
    @autoreleasepool {
        /* Existence probe first: attributes are not ACL-protected, so this
         * avoids a pointless Touch ID dialog when nothing is saved yet.
         * kSecUseAuthenticationUI suppresses the keychain-unlock panel that
         * would otherwise appear here if the login keychain is locked —
         * treat that case as "present, needs unlock" and go on to
         * authenticate rather than surprising the user with a password
         * prompt before any user-presence check. */
        NSMutableDictionary *probe = base_query(keygrip);
        if (!probe)
            return KC_ERROR;
        probe[(__bridge id)kSecReturnAttributes] = @YES;
        probe[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
        LAContext *quiet = [LAContext new];
        quiet.interactionNotAllowed = YES;
        probe[(__bridge id)kSecUseAuthenticationContext] = quiet;
        CFTypeRef attrs = NULL;
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)probe,
                                          &attrs);
        if (attrs)
            CFRelease(attrs);
        if (st != errSecSuccess && st != errSecInteractionNotAllowed)
            return map_status(st);

        kc_status auth = authenticate(reason, ac);
        if (auth != KC_OK)
            return auth;

        NSMutableDictionary *q = base_query(keygrip);
        q[(__bridge id)kSecReturnData] = @YES;
        q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
        CFTypeRef res = NULL;
        st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &res);
        if (st != errSecSuccess)
            return map_status(st);

        if (CFGetTypeID(res) != CFDataGetTypeID()) {
            CFRelease(res);
            return KC_ERROR;
        }
        CFDataRef data = (CFDataRef)res;
        size_t len = (size_t)CFDataGetLength(data);
        unsigned char *buf = secure_alloc(len ? len : 1);
        if (!buf) {
            CFRelease(res);
            return KC_ERROR;
        }
        memcpy(buf, CFDataGetBytePtr(data), len);
        /* CFData's backing store is immutable and cannot be wiped; this is
         * the only copy we make, and it is released as soon as possible. */
        CFRelease(res);
        *out_pw = buf;
        *out_len = len;
        return KC_OK;
    }
}

kc_status keychain_store(const char *keygrip, const unsigned char *pw,
                         size_t len, pe_access_control ac)
{
    (void)ac; /* enforced at lookup time by authenticate(), see header note */
    if (!keygrip || (!pw && len > 0))
        return KC_ERROR;
    @autoreleasepool {
        NSMutableDictionary *add = base_query(keygrip);
        if (!add)
            return KC_ERROR;
        /* No-copy wrapper around the caller's buffer: SecItemAdd copies
         * internally, so we avoid a second unwipeable copy in our process. */
        NSData *data = len
            ? [NSData dataWithBytesNoCopy:(void *)pw length:len freeWhenDone:NO]
            : [NSData data];
        add[(__bridge id)kSecValueData] = data;

        OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
        if (st == errSecDuplicateItem) {
            /* Delete, then re-add — do NOT SecItemUpdate. Update preserves
             * the existing item's ACL, and in the migration case that ACL
             * belongs to pinentry-mac, which does not list us as a trusted
             * application: every later read would raise the generic
             * keychain password panel forever. Re-adding creates the item
             * under our own code signature. */
            NSDictionary *del = base_query(keygrip);
            (void)SecItemDelete((__bridge CFDictionaryRef)del);
            st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
        }
        return map_status(st);
    }
}

kc_status keychain_delete(const char *keygrip)
{
    if (!keygrip)
        return KC_ERROR;
    @autoreleasepool {
        NSDictionary *q = base_query(keygrip);
        if (!q)
            return KC_ERROR;
        return map_status(SecItemDelete((__bridge CFDictionaryRef)q));
    }
}

bool keychain_disabled(void)
{
    Boolean exists = false;
    Boolean v = CFPreferencesGetAppBooleanValue(
        CFSTR("DisableKeychain"), CFSTR("local.pinentry-biometric"), &exists);
    return exists && v;
}
