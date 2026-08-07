# Security

pinentry-biometric holds the key to your GPG secret key. This document states
plainly what it does and does not protect against. It has **not** been
independently audited; version 0.1.0 is a first release.

Report vulnerabilities by opening a GitHub security advisory on this
repository rather than a public issue.

## What actually protects the passphrase

1. **The Keychain ACL.** The item lives in the login keychain and macOS
   releases it without a password panel only to a binary whose code signature
   matches the one that created it. Another process running as you that calls
   `SecItemCopyMatching` — or `security find-generic-password -s GnuPG` — gets
   the "wants to use your confidential information" panel, not the passphrase.

2. **A user-presence check before the read.** `keychain_lookup` runs
   `LAContext evaluatePolicy` (Touch ID, or your account password in the
   default `user-presence` mode) and only then reads the item.

3. **Hardened Runtime.** Point 2 is an in-process check, so it is only as
   trustworthy as the process. Hardened Runtime is what stops
   `DYLD_INSERT_LIBRARIES` from replacing the LocalAuthentication call with one
   that always returns success. The build applies it and
   `tests/security_check.sh` fails if it is missing — **do not distribute or
   install a binary without it**; the biometric requirement would be
   decorative.

The Secure Enclave does *not* enforce any of this. The data-protection
keychain with `SecAccessControl` — which would move enforcement out of our
process entirely — requires a `keychain-access-groups` /
`application-identifier` entitlement, and an ad-hoc-signed command-line tool
cannot carry one (`SecItemAdd` fails with `errSecMissingEntitlement`, and
claiming the entitlement without a provisioning profile gets the process
killed). Consequently `--access-control=biometry-current-set` means "this
program asks for biometry only"; unlike the Secure Enclave flag of the same
name, changing your enrolled fingerprints does not invalidate the item.

## Known limitations

These are real and unfixed in 0.1.0. They are listed here rather than papered
over in the README.

- **The fallback pinentry is fully trusted.** First-time passphrase entry is
  proxied to an external `pinentry-mac`, found next to our binary and then in
  `/opt/homebrew/bin`, `/usr/local/bin`, GPG Suite's prefix. On a typical
  single-admin Mac those directories are writable by your own user, and the
  binary is not signature-verified before being spawned, so a same-uid
  attacker who can write there captures the passphrase as you type it. Pin a
  root-owned path with `--fallback-pinentry` if this is in your threat model.

- **The prompt text is supplied by the requester.** Any process may send
  `SETDESC`, and that text appears in the Touch ID sheet. It is filtered to
  printable ASCII and length-capped, and the first sentence is fixed, but an
  attacker still chooses most of what you read — and, more importantly, *when*
  you are asked. Judge prompts by the keygrip and by whether you just ran gpg.

- **No timeouts.** The Touch ID sheet, the CFUserNotification dialogs and the
  fallback child are all waited on indefinitely, and `SETTIMEOUT` is accepted
  and ignored. A same-uid attacker can stack dialogs on your screen and pin
  processes — a nuisance-grade denial of service and a prompt-fatigue
  amplifier for the point above.

- **Memory locking is best-effort.** Heap buffers holding secrets go through
  `mlock`, but the return value is not checked and `RLIMIT_MEMLOCK` may deny
  it silently; sub-page `munlock` can unlock a page shared with another live
  allocation. Short-lived stack buffers in the protocol and fallback paths are
  wiped with `memset_s` but never locked, so they are pageable until wiped.
  Core dumps are disabled at startup.

- **No automatic migration from pinentry-mac.** An existing `GnuPG` item
  created by pinentry-mac belongs to its signature; we cannot adopt it. Delete
  it and re-save (see README).

- **Nothing verifies the caller.** Any process running as you can speak Assuan
  to this program. That is by design — parent-process checks are spoofable —
  and is why the three defenses above carry the weight.

## Reporting scope

In scope: passphrase disclosure to an unauthenticated caller, bypass of the
user-presence check, memory-safety bugs in the Assuan parser or the fallback
protocol driver, and anything that causes the wrong passphrase to be handed to
gpg-agent. Out of scope: attacks requiring root, physical access to an
unlocked machine, or a compromised gpg-agent.
