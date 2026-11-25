# CLAUDE.md

pinentry-biometric: a macOS pinentry for gpg-agent that keeps GPG passphrases
in the login Keychain behind Touch ID. DESIGN.md has the modules and the
decisions; read it before structural changes or touching GETPIN. Keep
SECURITY.md truthful after any security-relevant change.

## Rules

- Small enough to audit by hand: C11 + Objective-C, system frameworks only
  (Foundation, Security, LocalAuthentication, CoreFoundation). No
  third-party dependencies, no AppKit or CoreGraphics, never a network
  framework (`tests/security_check.sh` checks the link set).
- `-Wall -Wextra -Werror`.
- Framework calls stay in `keychain.m` and `biometry.m`; `assuan.c`,
  `state.c` and `secure_mem.c` have no dependencies and unit-test standalone.
- Every secret goes through `secure_alloc`/`secure_free`; wipe with
  `memset_s`, never `memset`.
- The Keychain item layout is fixed: generic password, service `"GnuPG"`,
  account = keygrip (pinentry-mac compatible).
- The data-protection keychain with `kSecAttrAccessControl` cannot be used:
  an ad-hoc signed CLI has no entitlement for it (`errSecMissingEntitlement`,
  verified).
- Never forward `SETKEYINFO` or `OPTION allow-external-password-cache` to the
  fallback pinentry-mac: it would save the passphrase under its own
  signature.
- Protocol behaviour comes from reference sources (GnuPG pinentry and agent,
  pinentry-mac, libgpg-error); cite them as DESIGN.md does.

## Commands

```sh
make                                # build and sign build/pinentry-biometric
make test                           # unit tests: build/test_assuan, build/test_state
tests/integration.sh                # protocol tests against the built binary
INTERACTIVE=1 tests/integration.sh  # + gpg end-to-end, needs Touch ID
tests/security_check.sh             # link set, Hardened Runtime, log masking
```

An ad-hoc rebuild changes the code signature, so macOS asks to re-authorize
Keychain access during interactive testing. That is expected.
