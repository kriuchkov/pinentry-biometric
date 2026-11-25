<p align="center">
  <img src="assets/logo.svg" width="112" height="112" alt="" />
</p>

<h1 align="center">pinentry-biometric</h1>

<p align="center">
  A minimal, auditable pinentry for <code>gpg-agent</code> on macOS.<br />
  Your GPG passphrase lives in the Keychain and is released only after Touch ID.
</p>

<p align="center">
  <a href="https://github.com/kriuchkov/pinentry-biometric/releases">
    <img src="https://img.shields.io/github/v/release/kriuchkov/pinentry-biometric?style=flat-square" alt="Release" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/kriuchkov/pinentry-biometric?style=flat-square" alt="License" />
  </a>
  <a href="https://github.com/kriuchkov/pinentry-biometric/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/kriuchkov/pinentry-biometric/ci.yml?style=flat-square&label=tests" alt="CI" />
  </a>
  <a href="#build">
    <img src="https://img.shields.io/badge/macOS-12%2B-000000?style=flat-square&logo=apple&logoColor=white" alt="macOS 12 or newer" />
  </a>
  <a href="#build">
    <img src="https://img.shields.io/badge/universal-arm64%20%2B%20x86__64-4A7FB5?style=flat-square" alt="Universal binary" />
  </a>
  <a href="#build">
    <img src="https://img.shields.io/badge/dependencies-none-2EA44F?style=flat-square" alt="No third-party build dependencies" />
  </a>
</p>

<p align="center">
  <a href="#install"><strong>Install</strong></a>
  <span>&nbsp;•&nbsp;</span>
  <a href="#build"><strong>Build</strong></a>
  <span>&nbsp;•&nbsp;</span>
  <a href="#signing"><strong>Signing</strong></a>
  <span>&nbsp;•&nbsp;</span>
  <a href="#threat-model"><strong>Threat Model</strong></a>
  <br />
  <a href="#migration-from-pinentry-mac"><strong>Migration</strong></a>
  <span>&nbsp;•&nbsp;</span>
  <a href="#degraded-modes"><strong>Degraded Modes</strong></a>
  <span>&nbsp;•&nbsp;</span>
  <a href="#options"><strong>Options</strong></a>
  <span>&nbsp;•&nbsp;</span>
  <a href="DESIGN.md"><strong>Design</strong></a>
  <span>&nbsp;•&nbsp;</span>
  <a href="SECURITY.md"><strong>Security</strong></a>
</p>

It speaks the Assuan/pinentry protocol to `gpg-agent`, keeps your GPG passphrase in the macOS Keychain, and hands it to the agent only after Touch ID or your account password. It links only macOS system frameworks and the C library. macOS 12+, universal binary (Apple Silicon and Intel).

**Requires pinentry-mac.** The first passphrase entry for each key is proxied to it (see [DESIGN.md](DESIGN.md) for why); without it, nothing can ever be saved to the Keychain. After that, the passphrase comes from the Keychain.

```sh
brew install pinentry-mac        # or install GPG Suite
```

## Build

Requires the Xcode Command Line Tools (`xcode-select --install`).

```sh
make                                  # build and sign build/pinentry-biometric
make test                             # unit tests (no Keychain, no Touch ID)
tests/integration.sh                  # protocol tests against the built binary
INTERACTIVE=1 tests/integration.sh    # + gpg end-to-end (needs gpg and a finger)
tests/security_check.sh               # link set, Hardened Runtime, log masking
```

## Signing

`make` signs the binary ad-hoc with Hardened Runtime. The Touch ID check runs inside this process, so without Hardened Runtime `DYLD_INSERT_LIBRARIES` could replace it and take the passphrase with no prompt. `tests/security_check.sh` fails if the flag is missing.

The Keychain item trusts the code signature that created it. An ad-hoc signature changes with every rebuild, so after each one macOS asks you to authorize the binary again. A Developer ID keeps the identity across rebuilds:

```sh
make CODESIGN_ID="Developer ID Application: Your Name (TEAMID)"
codesign -dv build/pinentry-biometric    # inspect the signature
```

## Install

```sh
make && sudo make install       # installs to /usr/local/bin
```

Build as yourself first: a bare `sudo make install` builds and signs as root and leaves a root-owned `build/`.

Install into a **root-owned** directory. In one you can write to (`~/.local/bin`, or `/opt/homebrew/bin` on a typical Mac), any process running as you can swap the binary, and the Keychain panel it triggers looks like the one you expect after a rebuild; "Always Allow" then gives it the passphrase without Touch ID. A Keychain panel when you have *not* just rebuilt or upgraded is the signal to press Deny. (`make install PREFIX=…` still works for testing.)

Point gpg-agent at it in `~/.gnupg/gpg-agent.conf`:

```
pinentry-program /usr/local/bin/pinentry-biometric
```

and restart the agent with `gpgconf --kill gpg-agent`.

## Migration from pinentry-mac

The item layout is the same as pinentry-mac's (generic password, service `GnuPG`, account = keygrip), but an item belongs to the signature that created it: reading one made by pinentry-mac raises the "wants to use your confidential information" panel every time. Re-save it under this binary:

1. Delete the old item: `security delete-generic-password -s GnuPG -a <keygrip>`
2. Sign something (`gpg --clearsign`), enter the passphrase in the first-entry dialog and choose Save. Later reads go through Touch ID.

## Degraded modes

- **No Touch ID** (desktop Mac, closed lid): `user-presence` falls back to your account password.
- **`biometry-current-set` without biometry** (no sensor, or Touch ID locked out): you get the first-entry passphrase prompt instead of an error. Some credential is always required, but the mode is not "biometry or nothing".
- **SSH session / no GUI**: GETPIN fails fast with `ERR` instead of hanging. Use a curses pinentry remotely.

## Threat model

Any process running as you can start this program and ask for the passphrase; there is no parent check, because it would be spoofable. What protects the passphrase:

1. the **Keychain ACL**: only a binary with the creating signature reads the item without a password panel;
2. the **user-presence check** before the read, which Hardened Runtime keeps from being patched out;
3. **you**: cancel a Touch ID prompt you did not trigger. Judge it by the keygrip and timing, not by the description, which the requester writes.

This stops *silent* access. It does not stop targeted malware running as you: it can wrap `pinentry-program` and relay the session, or inject into an unhardened Homebrew gpg-agent. No pinentry prevents that, pinentry-mac included. Details and other limitations: [SECURITY.md](SECURITY.md).

No network frameworks are linked. Secrets are wiped with `memset_s` after use and core dumps are off; heap secrets are `mlock`ed best effort, short-lived stack buffers are wiped but not locked.

## Options

- `--access-control=user-presence` (default): Touch ID or account password.
- `--access-control=biometry-current-set`: Touch ID only. This program enforces it, not the Secure Enclave (an ad-hoc signed CLI cannot use the data-protection keychain), so changing enrolled fingerprints does not invalidate the item.
- `--fallback-pinentry <path>`: the pinentry-mac to use; must be absolute. It receives the passphrase you type, and the default search (next to this binary, then the Homebrew and GPG Suite prefixes) covers directories that are often user-writable, so pin a root-owned path if that matters to you.
- `--debug`: protocol log, with data lines masked as `D ***`.
- `--version`, `--help`.

The Keychain is used only when gpg-agent allows an external passphrase cache, which is its default. With `no-allow-external-cache` in `gpg-agent.conf`, every passphrase is typed and nothing is read from or saved to the Keychain.

To turn the Keychain off entirely (items already saved stay until you delete them):

```sh
defaults write local.pinentry-biometric DisableKeychain -bool true
```

## Uninstall

```sh
security delete-generic-password -s GnuPG -a <keygrip>   # per saved key
sudo rm /usr/local/bin/pinentry-biometric
```

Remove the `pinentry-program` line from `~/.gnupg/gpg-agent.conf` and run `gpgconf --kill gpg-agent`.

## License

MIT — see [LICENSE](LICENSE).
