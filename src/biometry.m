/* biometry.m — user-facing dialogs without AppKit (biometry.h).
 * CFUserNotification shows a modal alert from a plain CLI process (no
 * NSApplication, no run loop), which keeps AppKit out of the binary.
 * SPDX-License-Identifier: MIT */
#import <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/AuthSession.h>
#include "biometry.h"

/* Modal CFUserNotification. cancel == NULL → single-button dialog.
 * 0 = default button, 1 = alternate/cancel, -1 = cannot display. */
static int show_note(const char *title, const char *message,
                     const char *ok, const char *cancel)
{
    @autoreleasepool {
        NSMutableDictionary *d = [NSMutableDictionary dictionary];
        d[(__bridge id)kCFUserNotificationAlertHeaderKey] =
            (title && *title) ? @(title) : @"pinentry-biometric";
        if (message && *message)
            d[(__bridge id)kCFUserNotificationAlertMessageKey] = @(message);
        d[(__bridge id)kCFUserNotificationDefaultButtonTitleKey] =
            (ok && *ok) ? @(ok) : @"OK";
        if (cancel)
            d[(__bridge id)kCFUserNotificationAlternateButtonTitleKey] = @(cancel);

        SInt32 err = 0;
        CFUserNotificationRef note = CFUserNotificationCreate(
            kCFAllocatorDefault, 0 /* never auto-dismiss */,
            kCFUserNotificationPlainAlertLevel, &err,
            (__bridge CFDictionaryRef)d);
        if (!note || err != 0) {
            if (note)
                CFRelease(note);
            return -1;
        }
        CFOptionFlags resp = 0;
        int rc;
        if (CFUserNotificationReceiveResponse(note, 0 /* block forever */,
                                              &resp) != 0)
            rc = -1;
        else
            rc = ((resp & 0x3) == kCFUserNotificationDefaultResponse) ? 0 : 1;
        CFRelease(note);
        return rc;
    }
}

int ui_confirm(const char *title, const char *message,
               const char *ok_label, const char *cancel_label)
{
    return show_note(title, message, ok_label,
                     (cancel_label && *cancel_label) ? cancel_label : "Cancel");
}

int ui_message(const char *title, const char *message)
{
    int rc = show_note(title, message, "OK", NULL);
    return rc < 0 ? -1 : 0; /* any dismissal of the single button is success */
}

/* SessionGetInfo (Security) reads the caller's audit-session attributes from
 * the kernel: a synchronous local call that cannot hang, needs no WindowServer
 * connection, and a bare SSH login simply lacks sessionHasGraphicAccess.
 * Chosen over CGSessionCopyCurrentDictionary to avoid linking CoreGraphics. */
bool ui_session_available(void)
{
    SecuritySessionId sid = 0;
    SessionAttributeBits attrs = 0;
    if (SessionGetInfo(callerSecuritySession, &sid, &attrs) != errSessionSuccess)
        return false;
    return (attrs & sessionHasGraphicAccess) != 0;
}
