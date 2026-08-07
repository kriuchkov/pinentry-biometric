# pinentry-biometric

A minimal, auditable pinentry program for macOS. It speaks the Assuan/pinentry
protocol to `gpg-agent`, stores your GPG passphrase in the macOS Keychain, and
requires Touch ID (with the system's account-password fallback) before handing
the passphrase to the agent.

No third-party build dependencies: it links only macOS system frameworks and
the C standard library. Target: macOS 12.0+ (Monterey), builds a universal
binary (Apple Silicon and Intel).

**Runtime prerequisite:** the *first* passphrase entry for a key is proxied to
an existing `pinentry-mac` (see [DESIGN.md](DESIGN.md) for why). Without one
installed, `GETPIN` fails and the Keychain can never be populated — so
pinentry-biometric is not a standalone replacement:

```sh
brew install pinentry-mac        # or install GPG Suite
```

Only the first entry per key needs it; afterwards the passphrase comes from
the Keychain behind Touch ID.

## Build

Requires the Xcode Command Line Tools (`xcode-select --install`).

```sh
make            # builds and signs build/pinentry-biometric
make test       # builds and runs the pure-C unit tests (no Keychain, no Touch ID)
```

Integration and security checks (see `tests/`):

```sh
tests/integration.sh                  # automated protocol tests
INTERACTIVE=1 tests/integration.sh    # + gpg end-to-end (needs a live finger)
tests/security_check.sh               # link set, Hardened Runtime, log masking
```

The integration script needs `gpg`/`gpgconf` for its interactive step; the
automated steps need only the built binary.

## Signing

`make` signs the binary itself — ad-hoc, with Hardened Runtime. That is not
packaging polish: the biometric check runs *inside this process*, so without
Hardened Runtime anyone able to set `DYLD_INSERT_LIBRARIES` could replace the
LocalAuthentication call and take the passphrase with no prompt at all.
`tests/security_check.sh` fails the build if the flag is missing.

**Why a stable signature matters.** The Keychain access-control list binds the
saved passphrase item to the *code signature* of the program that created it.
With an ad-hoc signature, every rebuild produces a different signing identity,
so after each rebuild macOS treats the binary as a new program and asks you to
authorize Keychain access again. If you have a Developer ID certificate, use it
— the identity then survives rebuilds:

```sh
make CODESIGN_ID="Developer ID Application: Your Name (TEAMID)"
```

Verify the signature at any time:

```sh
codesign -dv build/pinentry-biometric
```

## Install

```sh
sudo make install               # installs to /usr/local/bin
make install PREFIX=$HOME/.local  # or anywhere else
```

Then point gpg-agent at it — add to `~/.gnupg/gpg-agent.conf`:

```
pinentry-program /usr/local/bin/pinentry-biometric
```

and restart the agent:

```sh
gpgconf --kill gpg-agent
```

## Migration from pinentry-mac

pinentry-biometric uses the same Keychain item layout as pinentry-mac
(generic password, service `GnuPG`, account = keygrip), so in the best case
your existing saved passphrase is picked up directly.

However, a Keychain item is *owned* by the code signature that created it. If
your existing `GnuPG` item was created by pinentry-mac, our binary cannot read
it silently: macOS raises the classic "wants to use your confidential
information" dialog every time. There is no automatic migration — re-save the
passphrase under our identity:

1. Delete the old item (per keygrip):
   ```sh
   security delete-generic-password -s GnuPG -a <keygrip>
   ```
2. Trigger a signature (`gpg --clearsign`), enter the passphrase in the
   first-entry dialog, and choose Save. The item is recreated under
   pinentry-biometric's code signature, and later reads go through Touch ID.

## Degraded modes

- **No Touch ID available** (desktop Mac, closed lid, external keyboard
  without a sensor): in the default `user-presence` mode the system dialog
  falls back to your account password. Nothing to configure.
- **Biometry unavailable in `biometry-current-set` mode** (no sensor, or
  Touch ID locked out after repeated failures): authentication cannot
  succeed, and the program falls back to the first-entry passphrase prompt
  rather than failing. You are never let in without *some* credential, but
  the mode is not a hard "biometry or nothing".
- **SSH session / no GUI**: there is no Aqua session to show a dialog in, so
  GETPIN fails fast with an `ERR` instead of hanging. Use a
  curses pinentry for remote sessions.

## Threat model

pinentry-biometric does **not** verify who its parent process is — gpg-agent
restarts freely, and parent checks are trivially spoofable anyway. That means
*any process running as your user* can start this program and ask for the
Keychain item. The defenses, in the order they actually matter:

1. the **Keychain ACL** — macOS releases the item without a password panel
   only to a binary whose code signature matches the one that created it.
   A same-uid attacker calling `SecItemCopyMatching` (or `security
   find-generic-password`) directly gets the panel, not the passphrase;
2. the **user-presence check** — before the item is read, this program
   requires Touch ID (or your account password) via LocalAuthentication.
   Note that this check runs *in this process*: it is meaningful only
   because Hardened Runtime prevents code injection into it. See
   [SECURITY.md](SECURITY.md);
3. the **Touch ID prompt** — treat a prompt you did not trigger as the
   signal to press Cancel. Judge it by the keygrip and by timing, **not** by
   the description text: that text is supplied by whoever is asking (any
   process may send `SETDESC`), and is only filtered to printable ASCII.

The binary never opens network connections, and `tests/security_check.sh`
checks the link set for network frameworks. Secrets are wiped with `memset_s`
immediately after use and core dumps are disabled at startup; heap buffers
holding secrets are `mlock`ed on a best-effort basis, while short-lived stack
buffers in the protocol and fallback paths are wiped but not locked.

## Access-control mode

The user-presence policy is selectable via
`--access-control=user-presence|biometry-current-set`:

- `user-presence` (**default**): Touch ID *or* account password. Recommended.
- `biometry-current-set` (stricter): Touch ID only, no password fallback.
  Note: the passphrase item lives in the login keychain (an ad-hoc signed
  CLI cannot use the data-protection keychain — no entitlements), so the
  biometry requirement is enforced by this program rather than the Secure
  Enclave, and enrollment changes do not invalidate the item.

## Options and defaults

CLI flags: `--version`, `--help`, `--debug` (protocol log with `D ***`
payload masking — secrets never reach the log), `--fallback-pinentry <path>`,
`--access-control=<mode>`.

The fallback pinentry is fully trusted: it receives the passphrase you type.
It is located next to our own binary and then in the standard Homebrew and
GPG Suite prefixes — directories that are user-writable on a typical
single-admin Mac. If that matters to you, pin it explicitly to a root-owned
path with `--fallback-pinentry` in `gpg-agent.conf`.

To disable Keychain saving entirely (the save prompt disappears):

```sh
defaults write local.pinentry-biometric DisableKeychain -bool true
```

## Uninstall

```sh
security delete-generic-password -s GnuPG -a <keygrip>   # per saved key
sudo rm /usr/local/bin/pinentry-biometric
```

Remove (or change) the `pinentry-program` line in `~/.gnupg/gpg-agent.conf`
and run `gpgconf --kill gpg-agent`.

## License

MIT — see [LICENSE](LICENSE).
