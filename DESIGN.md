# DESIGN — pinentry-biometric

A macOS pinentry small enough to audit by hand: C11 + Objective-C, system
frameworks only. Framework calls live in the two `.m` files; `assuan.c`,
`state.c` and `secure_mem.c` are plain C and unit-tested standalone.

## Modules

- **`main.c`** — hardens the process (`secure_process_init`), parses the
  flags, runs the command loop and GETPIN: Keychain lookup → fallback prompt
  → optional save.
- **`assuan.c`** — the wire protocol: line reader with the 1000-byte limit
  (an overlong line is drained and answered with `ERR`), command splitting,
  percent decoding and encoding (a `D` line never splits an escape), replies,
  and the `--debug` log, which masks every data line as `D ***`.
- **`state.c`** — session state: decoded `SET*` fields and tracked
  `OPTION`s. `RESET` clears the `SET*` fields and keeps the options, as
  reference pinentry does; unknown options get `OK`. `SETKEYINFO` keeps an
  id only in the forms gpg-agent sends (`n/` or `s/` + 40 hex digits, folded
  to upper case; `u/` + one printable word); anything else clears it, like
  `--clear`.
- **`secure_mem.c`** — process hardening at startup: core dumps off
  (`RLIMIT_CORE` 0), and `/dev/null` on any of fd 0–2 that is closed, so no
  pipe or framework file can take the place of stdio. Each secret gets
  pages of its own from `mmap` (on a shared `malloc` page, freeing one
  secret would `munlock` its neighbours), `mlock`ed best effort, wiped with
  `memset_s` before `munlock`/`munmap`.
- **`keychain.m`** — generic password, service `"GnuPG"`, account =
  keygrip: the pinentry-mac layout. Items live in the login keychain,
  because the data-protection keychain with `kSecAttrAccessControl` needs an
  entitlement an ad-hoc signed CLI cannot carry (`errSecMissingEntitlement`;
  claiming it without a provisioning profile gets the process killed). User
  presence is therefore checked in-process: probe the item's attributes
  (never prompts), run `LAContext evaluatePolicy` (Touch ID or account
  password for `user-presence`, Touch ID only for `biometry-current-set`;
  the reason shows the short keygrip and SETDESC), then read the data, which
  the keychain ACL releases silently to our signature. Also reads
  `DisableKeychain` from the `local.pinentry-biometric` defaults domain.
- **`biometry.m`** — `CONFIRM`/`MESSAGE` via `CFUserNotification`, without
  AppKit. GUI-session detection uses `SessionGetInfo` rather than
  `CGSessionCopyCurrentDictionary`, which would link CoreGraphics; an SSH
  session gets `ERR` instead of a hang.
- **`fallback.c`** — the first-entry prompt, proxied to pinentry-mac (see
  below). Search order: next to our binary (via `realpath`, so a relative
  `argv[0]` cannot point into the caller's cwd), `/opt/homebrew/bin`,
  `/usr/local/bin`, GPG Suite's
  `/usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/`; an explicit
  `--fallback-pinentry` must be absolute. The child inherits only stdio
  (`POSIX_SPAWN_CLOEXEC_DEFAULT`) and starts with default signal
  dispositions, receives the relevant `SET*` fields and tty/locale options
  and one `GETPIN`, and the passphrase comes back in a `secure_alloc`
  buffer. The child is reaped on every error path and dies with us:
  gpg-agent cancels a pinentry with SIGINT (libassuan
  `assuan_pipe_kill_server`, called from `watch_sock` in gnupg
  `agent/call-pinentry.c`), so while a child runs, SIGINT, SIGTERM, SIGHUP
  and SIGQUIT kill it before we exit and its dialog does not stay on
  screen. The child leads its own process group and the whole group is
  killed, so the pinentry behind a wrapper script goes too. The handler may run on any thread (a
  signal mask is per thread), so it shares the child's pid with the main
  thread through atomics rather than relying on blocked signals.

## Decision: proxy first entry to pinentry-mac

The first passphrase entry goes to an existing `pinentry-mac` rather than an
AppKit window of our own:

- A secure-input window means AppKit, an `NSApplication` lifecycle, secure
  input mode and focus handling: hundreds of lines whose bugs are UI
  security bugs. A child-process protocol driver is small and testable.
- No AppKit in the link set.
- Only the "no Keychain item yet" path uses it; Touch ID → Keychain → agent
  never does.

`SETKEYINFO` and `OPTION allow-external-password-cache` are deliberately
**not** forwarded: pinentry-mac would offer its own "save in Keychain" and
store the passphrase under its own signature, the split ownership we are
moving away from. Only `main.c` + `keychain.m` save.

## SETERROR-driven cache invalidation

pinentry cannot check a passphrase, so a mistyped first entry is saved and
then served to gpg-agent, which rejects it and asks again with `SETERROR`:

1. `GETPIN` with no error → Keychain, then fallback.
2. `GETPIN` with an error, and the previous answer came from the Keychain →
   delete the item (`keychain_delete`) and fall through to the fallback.
3. The new passphrase is returned and may be saved again.

By hand: `security delete-generic-password -s GnuPG -a <keygrip>`, then sign
again; the first-entry prompt must appear, with no error.

## References

Protocol behaviour is taken from these sources, not guessed:

- **GnuPG pinentry, `pinentry/pinentry.c`** — command table, `RESET`
  semantics, greeting, `D`-line escaping, line limit. `cmd_getpin` uses its
  external cache only when `allow_external_password_cache && keyinfo`; we
  gate the Keychain lookup and the save offer the same way
  (`state_external_cache_allowed`).
- **GnuPG `agent/call-pinentry.c`** — `start_pinentry` sends `OPTION
  allow-external-password-cache` only when `opt.allow_external_cache` is set
  (no `no-allow-external-cache`). `agent_askpin` and `agent_get_passphrase`
  send `SETKEYINFO <n|u|s>/<id>` for cacheable prompts and `SETKEYINFO
  --clear` otherwise; a `u/` id is the client's cache ID
  (`agent/command.c` `cmd_get_passphrase`), such as gpg's `S` + salt
  (`g10/passphrase.c`).
- **pinentry-mac (GPGTools), `KeychainSupport.m`** — item layout (service
  `"GnuPG"`, account = keygrip) and `S PASSWORD_FROM_CACHE` when the
  passphrase comes from the Keychain.
- **libgpg-error 1.61, `gpg-error.h`** — error codes and source encoding.

## Error codes

`ERR <code> <description>` with `code = (5 << 24) | err`, where `5` is
`GPG_ERR_SOURCE_PINENTRY` (base 83886080). Constants are in `src/assuan.h`.

| Constant | libgpg-error name | err | wire code |
|---|---|---:|---:|
| `PE_ERR_CANCELED` | `GPG_ERR_CANCELED` | 99 | 83886179 |
| `PE_ERR_NOT_CONFIRMED` | `GPG_ERR_NOT_CONFIRMED` | 114 | 83886194 |
| `PE_ERR_NO_PIN_ENTRY` | `GPG_ERR_NO_PIN_ENTRY` | 85 | 83886165 |
| `PE_ERR_INTERNAL` | `GPG_ERR_INTERNAL` | 63 | 83886143 |
| `PE_ERR_ASS_TOO_LONG` | `GPG_ERR_ASS_LINE_TOO_LONG` | 263 | 83886343 |
| `PE_ERR_ASS_UNKNOWN_CMD` | `GPG_ERR_ASS_UNKNOWN_CMD` | 275 | 83886355 |
