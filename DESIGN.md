# DESIGN — pinentry-biometric

Goal: a from-scratch macOS pinentry small enough for full manual audit
(~1400 lines in `src/`), C11 + Objective-C, system frameworks only.

## Code structure

- **`src/main.c`** — entry point and command loop. Hardens the process first
  (`secure_process_init`), parses CLI flags (`--debug`,
  `--fallback-pinentry`, `--access-control`), prints the greeting, then reads
  stdin line by line, dispatches commands, and orchestrates the GETPIN
  scenario (Keychain lookup → fallback prompt → optional store). All secret
  buffers pass through `secure_alloc`/`secure_free`.

- **`src/assuan.c` / `assuan.h`** — the wire protocol, pure C. Line reader
  with the 1000-byte Assuan limit (overlong input is drained and reported as
  a protocol error, never an overflow), command/argument splitting, percent
  decoding, and the reply senders (`OK`, `ERR`, `S`, `D` with percent
  escaping of `%`/CR/LF). Also owns the `--debug` logger, which masks every
  data line as `D ***`. Error-code constants live here (table below).

- **`src/state.c` / `state.h`** — per-session state machine, pure C. Stores
  the percent-decoded `SET*` fields and tracked `OPTION`s. `RESET` clears the
  SET\* fields but keeps OPTION values, matching reference pinentry
  behaviour. Unknown options are accepted with `OK`. Has no
  dependency on `assuan.c` so it unit-tests standalone.

- **`src/secure_mem.c` / `secure_mem.h`** — secret-memory discipline, pure C.
  `secure_process_init` disables core dumps (`setrlimit(RLIMIT_CORE, 0)`);
  `secure_alloc`/`secure_free` provide `mlock`ed allocations (best effort
  under `RLIMIT_MEMLOCK`) that are wiped with `memset_s` — not `memset`,
  which the optimizer may elide — before `munlock`/`free`.

- **`src/keychain.m` / `keychain.h`** — Keychain layer (Security +
  LocalAuthentication). Generic password items, service `"GnuPG"`, account =
  keygrip — the exact layout pinentry-mac uses, for migration compatibility.
  Items live in the **login (file-based) keychain**, not the data-protection
  keychain: `kSecUseDataProtectionKeychain` + `kSecAttrAccessControl` require
  a keychain-access-groups/application-identifier entitlement, which an
  ad-hoc signed CLI cannot carry (`SecItemAdd` fails with
  `errSecMissingEntitlement`, and AMFI kills a process claiming the
  restricted entitlement without a provisioning profile). User presence is
  therefore enforced in-process: lookup probes item existence (attributes
  only, never prompts), runs `LAContext evaluatePolicy` with a localized
  reason (short keygrip + SETDESC, no secrets) — Touch ID with
  account-password fallback for `user-presence`, biometry-only for
  `biometry-current-set` — and only then reads the item data, which the
  classic keychain ACL releases silently to our code signature. Also reads
  the `DisableKeychain` bool from the `local.pinentry-biometric` defaults
  domain.

- **`src/biometry.m` / `biometry.h`** — user-facing dialogs *without AppKit*:
  `CONFIRM`/`MESSAGE` are implemented with `CFUserNotification`, and
  `ui_session_available` detects whether an Aqua/GUI session is reachable
  via `SessionGetInfo` from Security — chosen over
  `CGSessionCopyCurrentDictionary` precisely so that CoreGraphics is *not*
  linked — so SSH sessions fail fast with `ERR` instead of hanging.

- **`src/fallback.c` / `fallback.h`** — first-entry UI, see the decision
  below. Locates pinentry-mac (next to our binary — via `realpath`, so a
  relative `argv[0]` cannot redirect the search to the caller's cwd — then
  `/opt/homebrew/bin`, `/usr/local/bin`, and GPG Suite's
  `/usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/`), spawns it,
  and drives a child Assuan session: forwards the relevant `SET*` fields and
  tty/locale `OPTION`s, runs one `GETPIN`, returns the passphrase in a
  `secure_alloc`ed buffer. The child is reaped on every error path — no
  hangs.

## Decision: proxy first entry to pinentry-mac

We proxy the *first* passphrase entry to an existing `pinentry-mac` binary
instead of building our own AppKit window.

Rationale:

- **Smallest audit surface.** A native secure-input window means AppKit, an
  NSApplication lifecycle, secure input mode handling, focus stealing
  countermeasures — hundreds of lines whose failure modes are UI-security
  bugs. Proxying is a small, testable child-process protocol driver.
- **No AppKit linkage at all**, which keeps the framework list (and
  `otool -L` review) short.
- The fallback runs only in the "no Keychain item yet" path; the steady-state
  hot path (Touch ID → Keychain → agent) never touches it.

**Deliberate omission:** `OPTION allow-external-password-cache` and
`SETKEYINFO` are *not* forwarded to the fallback. If they were, pinentry-mac
would show its own "save in Keychain" checkbox and store the passphrase under
*its* code-signing identity — recreating exactly the split-ownership problem
we are migrating away from. Saving to the Keychain is solely the job of
`main.c` + `keychain.m`, under our signature and our ACL. (See the note in
`src/fallback.h`.)

## SETERROR-driven cache invalidation

pinentry cannot validate the passphrase itself — it does not know the key. So
a mistyped first entry gets saved to the Keychain and is then "successfully"
served to gpg-agent, which rejects it and immediately retries `GETPIN`, this
time preceded by `SETERROR <reason>`. The cycle:

1. `GETPIN` with `state.error` empty → normal path (Keychain, then fallback).
2. `GETPIN` with `state.error` non-empty **and** the previous answer came
   from the Keychain → the stored passphrase is wrong: delete the item
   (`keychain_delete`) and fall through to the first-entry prompt.
3. The freshly entered phrase is returned (and optionally re-saved).

This mirrors how gpg-agent + pinentry-mac recover from a stale Keychain
entry. To exercise it by hand: delete the item with
`security delete-generic-password -s GnuPG -a <keygrip>` and sign again —
the program must fall back to the first-entry prompt without erroring.

## Reference points (behaviour verified against sources, not guessed)

- **GnuPG pinentry, `pinentry/pinentry.c`** — the command table
  (`cmd_setdesc`, `cmd_getinfo`, option handling, `RESET` semantics), the
  greeting string, percent-escaping rules for `D` lines, and the Assuan line
  length limit.
- **pinentry-mac (GPGTools), `KeychainSupport.m` / pinentry-mac sources** —
  the Keychain item layout (service name `"GnuPG"`, account = keygrip) and
  the `S PASSWORD_FROM_CACHE` status line emitted when the passphrase is
  served from the Keychain instead of the user (sent only when the agent
  passed `OPTION allow-external-password-cache` and `SETKEYINFO`).
- **libgpg-error 1.61, `gpg-error.h`** — numeric error codes and the source
  encoding (below).

## Error codes

Wire format: `ERR <code> <description>`. Codes are libgpg-error values with
the error source in bits 24..30: `code = (GPG_ERR_SOURCE_PINENTRY << 24) |
err`, where `GPG_ERR_SOURCE_PINENTRY = 5`, so the base is `5 << 24 =
83886080`. Constants are hardcoded in `src/assuan.h` with the source cited.

| Constant | libgpg-error name | err | wire code |
|---|---|---:|---:|
| `PE_ERR_CANCELED` | `GPG_ERR_CANCELED` | 99 | 83886179 |
| `PE_ERR_NOT_CONFIRMED` | `GPG_ERR_NOT_CONFIRMED` | 114 | 83886194 |
| `PE_ERR_NO_PIN_ENTRY` | `GPG_ERR_NO_PIN_ENTRY` | 85 | 83886165 |
| `PE_ERR_INTERNAL` | `GPG_ERR_INTERNAL` | 63 | 83886143 |
| `PE_ERR_ASS_TOO_LONG` | `GPG_ERR_ASS_LINE_TOO_LONG` | 263 | 83886343 |
| `PE_ERR_ASS_UNKNOWN_CMD` | `GPG_ERR_ASS_UNKNOWN_CMD` | 275 | 83886355 |

Example: user cancel is `ERR 83886179 Operation cancelled`.
