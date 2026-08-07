# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-06

### Added

- Initial release: minimal Assuan/pinentry implementation for macOS
  (C11 + Objective-C, system frameworks only, no external dependencies).
- Passphrase storage in the macOS login Keychain (generic password, service
  `GnuPG`, account = keygrip — pinentry-mac compatible layout), released
  only to a binary matching the code signature that created the item.
- Touch ID confirmation via `LAContext evaluatePolicy` before the item is
  read and handed to gpg-agent: `--access-control=user-presence` (default,
  Touch ID or account password) or `biometry-current-set` (Touch ID only);
  `S PASSWORD_FROM_CACHE` status when serving from the Keychain.
  **This check runs inside our own process**, so it is only as strong as
  the process integrity that Hardened Runtime provides — see SECURITY.md.
  The data-protection keychain with `SecAccessControl` (Secure Enclave
  enforcement) is unavailable: it requires entitlements that an ad-hoc
  signed command-line tool cannot carry.
- First-entry prompt proxied to an existing pinentry-mac
  (`--fallback-pinentry <path>`, auto-discovery in standard prefixes).
- SETERROR-driven invalidation: a stored passphrase rejected by the agent is
  deleted and re-prompted.
- Security hardening: secret buffers wiped with `memset_s` (best-effort
  `mlock` on heap buffers; transient stack buffers are wiped but not
  locked), core dumps disabled, no network frameworks, `--debug` masks data
  lines as `D ***`, unbuffered stdout so no plaintext lingers in stdio.
  Hardened Runtime is applied by the build itself, not by a separate step.
- Unit tests (pure C: protocol parser and state machine), integration script
  (`tests/integration.sh`) and security check script
  (`tests/security_check.sh`).
- Documentation: README (build, signing, migration from pinentry-mac, threat
  model), DESIGN (architecture and reference points), MIT license.
