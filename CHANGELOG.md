# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Automated tests of the first-entry fallback against a scripted pinentry
  (`tests/fake-pinentry.sh`); skipped where there is no GUI session.

### Fixed

- `no-allow-external-cache` in `gpg-agent.conf` was ignored: the Keychain
  was still read and the save offered. Both now require gpg-agent's
  `allow-external-password-cache`, as in reference pinentry. gpg-agent
  sends it by default, so nothing changes unless you opted out.
- Interrupting gpg left the pinentry-mac first-entry dialog on screen. The
  fallback child is now killed with us.

### Changed

- `SETKEYINFO` is validated: `n/` and `s/` need a 40-hex-digit keygrip,
  `u/` one printable word (a client's cache ID, such as gpg's `S<salt>`).
  An id too long to store is rejected rather than truncated, so two long
  ids can no longer share a Keychain item. Anything rejected is treated
  like `--clear`.
- Each secret buffer gets pages of its own, so freeing one no longer
  unlocks the memory of another.
- The fallback pinentry inherits only stdin, stdout and stderr.
- `--fallback-pinentry` must be an absolute path.

## [0.1.1] - 2026-09-24

### Fixed

- `SETKEYINFO --clear`, which gpg-agent sends before every uncacheable
  prompt (a new passphrase and its re-entry), was stored as the keygrip
  `--clear`. A new passphrase could then be saved to the Keychain under that
  shared name, and the "re-enter" prompt was answered from the Keychain
  instead of by the user — defeating the typo check and silently reusing
  that passphrase for later keys. Only `<mode>/<keygrip>` values now set a
  keygrip; anything else clears it. If you generated or re-protected a key
  with 0.1.0, check for a stale item with
  `security find-generic-password -s GnuPG -a --clear` and delete it.

### Changed

- README and SECURITY.md state plainly that targeted malware running as the
  user is not stopped (a relaying `pinentry-program` wrapper, or an
  unhardened Homebrew gpg-agent), and that the binary must be installed to a
  root-owned directory; the `PREFIX=$HOME/.local` install example is gone.
- README: project logo and a centred header with badges.

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
