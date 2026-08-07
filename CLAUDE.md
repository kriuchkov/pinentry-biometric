# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

pinentry-biometric: a from-scratch macOS pinentry for gpg-agent that stores GPG
passphrases in the Keychain behind Touch ID. Design goals that constrain all
changes: full manual auditability (~1300 lines in `src/`), C11 + Objective-C,
**no third-party build dependencies** — only macOS system frameworks
(Foundation, Security, LocalAuthentication, CoreFoundation; deliberately no
AppKit or CoreGraphics). The binary must never link network frameworks
(`tests/security_check.sh` checks this). An installed `pinentry-mac` *is* a
runtime prerequisite for first passphrase entry.

`DESIGN.md` explains module responsibilities and the key design decisions —
read it before structural changes. `SECURITY.md` states what the tool does
and does not protect against, including known unfixed limitations; keep it
truthful when changing anything security-relevant.

## Commands

```sh
make                                  # build → build/pinentry-biometric
make test                             # pure-C unit tests (no Keychain/Touch ID needed)
build/test_assuan                     # run a single unit test binary
build/test_state
tests/integration.sh                  # automated Assuan protocol tests against the built binary
INTERACTIVE=1 tests/integration.sh    # + gpg end-to-end (requires a live Touch ID finger)
tests/security_check.sh               # verifies no network frameworks linked, log masking
make sign                             # ad-hoc codesign with Hardened Runtime
```

Builds with `-Wall -Wextra -Werror` — new warnings are build failures.

Keychain ACLs bind items to the code signature; after a rebuild with an ad-hoc
signature, macOS treats the binary as a new program (re-authorization prompts
during interactive testing are expected).

## Architecture

The module split is deliberate: protocol and state logic are **pure C with no
framework dependencies** so they unit-test standalone; all macOS API usage is
isolated in the two Objective-C files.

- `src/main.c` — entry point; process hardening first, then the Assuan command
  loop; orchestrates GETPIN: Keychain lookup → fallback prompt → optional store.
- `src/assuan.c` — wire protocol (pure C): line reader with 1000-byte Assuan
  limit, percent en/decoding, reply senders, `--debug` logger that masks every
  data line as `D ***`. Error-code constants live in `assuan.h` (libgpg-error
  values with source `5 << 24` in the high bits — see DESIGN.md table).
- `src/state.c` — per-session state machine (pure C, no dependency on
  assuan.c): stores `SET*` fields and `OPTION`s; `RESET` clears SET\* but keeps
  OPTIONs, matching reference pinentry.
- `src/secure_mem.c` — secret-memory discipline: core dumps disabled,
  `mlock`ed allocations wiped with `memset_s` (never plain `memset`). All
  secret buffers must go through `secure_alloc`/`secure_free`.
- `src/keychain.m` — Keychain layer. Item layout matches pinentry-mac (generic
  password, service `"GnuPG"`, account = keygrip) for migration compatibility —
  do not change it. Items live in the login keychain with an in-process
  `LAContext` user-presence gate before reads; the data-protection keychain +
  `kSecAttrAccessControl` CANNOT be used — it needs entitlements an ad-hoc
  signed CLI can't carry (`errSecMissingEntitlement`; verified empirically).
- `src/biometry.m` — CONFIRM/MESSAGE dialogs via `CFUserNotification` (no
  AppKit) and GUI-session detection so SSH sessions fail fast with `ERR`.
- `src/fallback.c` — first-passphrase-entry UI is *proxied* to an external
  pinentry-mac child process (rationale in DESIGN.md) rather than a native
  window. Deliberate omission: `SETKEYINFO` and
  `OPTION allow-external-password-cache` are NOT forwarded to the child —
  forwarding them would let pinentry-mac save the passphrase under its own
  code signature. Keychain saving belongs solely to `main.c` + `keychain.m`.

Key flow to understand before touching GETPIN (see DESIGN.md): pinentry
cannot validate passphrases, so a wrong stored passphrase is detected via
gpg-agent's retry — `GETPIN` preceded by `SETERROR`, with the previous answer
having come from the Keychain, deletes the item and falls through to the
first-entry prompt.

Behaviour is verified against reference sources (GnuPG pinentry, pinentry-mac,
libgpg-error), not guessed — when changing protocol behaviour, cite the
reference the same way DESIGN.md does.
