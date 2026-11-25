# Security

pinentry-biometric guards the passphrase to your GPG secret key. It is an
early release and has **not** been independently audited.

Report vulnerabilities through a GitHub security advisory on this
repository, not a public issue.

## What protects the passphrase

1. **The Keychain ACL.** The item is in the login keychain, and macOS
   releases it without a password panel only to a binary with the code
   signature that created it. Any other process running as you
   (`SecItemCopyMatching`, `security find-generic-password -s GnuPG`) gets
   the "wants to use your confidential information" panel, not the
   passphrase.

2. **A user-presence check before the read.** `keychain_lookup` runs
   `LAContext evaluatePolicy` (Touch ID, or your account password in the
   default `user-presence` mode) and only then reads the item.

3. **Hardened Runtime.** Point 2 runs in our process, so it is only as
   trustworthy as the process. Hardened Runtime stops
   `DYLD_INSERT_LIBRARIES` from replacing the LocalAuthentication call with
   one that always succeeds. The build applies it and
   `tests/security_check.sh` fails without it; **never install or
   distribute a binary without it**.

The Secure Enclave enforces none of this. The data-protection keychain with
`SecAccessControl` would move enforcement out of our process, but it needs a
`keychain-access-groups` / `application-identifier` entitlement that an
ad-hoc signed command-line tool cannot carry (`SecItemAdd` fails with
`errSecMissingEntitlement`; claiming it without a provisioning profile gets
the process killed). So `--access-control=biometry-current-set` means "this
program asks for biometry only", and changing enrolled fingerprints does not
invalidate the item.

## Known limitations

- **Targeted malware running as you is not stopped.** The defenses above
  prevent *silent* reads, not an attacker who already runs code as you and
  waits. It can point `pinentry-program` in `~/.gnupg/gpg-agent.conf` at a
  wrapper that runs this program and relays the session; the Touch ID prompt
  then shows the right keygrip exactly when you ran gpg. Or it can restart
  gpg-agent, which a typical Homebrew install ships ad-hoc signed without
  Hardened Runtime, under `DYLD_INSERT_LIBRARIES` and read every passphrase
  you approve. No pinentry closes this; pinentry-mac is exposed the same way.

- **A user-writable install location weakens the Keychain ACL.** Ad-hoc
  rebuilds change the signature, so you get used to approving the Keychain
  panel. If the binary lives where you can write (`~/.local/bin`,
  `/opt/homebrew/bin`), a same-uid attacker can replace it and get the same
  panel; approving it hands over the passphrase without Touch ID. Install to
  a root-owned directory, and deny a panel you did not expect.

- **The fallback pinentry is fully trusted.** The first entry is typed into
  an external `pinentry-mac`, found next to our binary, then in
  `/opt/homebrew/bin`, `/usr/local/bin` and GPG Suite's prefix. Those
  directories are often writable by your own user, and the binary is not
  signature-checked before it is spawned, so an attacker who can write there
  captures the passphrase as you type it. Pin a root-owned path with
  `--fallback-pinentry` if this is in your threat model.

- **The requester writes the prompt text.** Any process may send `SETDESC`,
  and it appears in the Touch ID sheet. It is filtered to printable ASCII
  and length-capped, and the first sentence is fixed, but the attacker
  chooses the rest, and *when* you are asked. Judge a prompt by the keygrip
  and by whether you just ran gpg.

- **No timeouts.** The Touch ID sheet, the `CFUserNotification` dialogs and
  the fallback child are waited on indefinitely; `SETTIMEOUT` is accepted
  and ignored. A same-uid attacker can stack dialogs and pin processes: a
  nuisance-level denial of service that feeds prompt fatigue.

- **Memory locking is best effort.** Heap buffers holding secrets get pages
  of their own and are `mlock`ed, but the result is not checked and
  `RLIMIT_MEMLOCK` may refuse silently. Short-lived stack buffers in the
  protocol and fallback paths are wiped with `memset_s` but never locked.
  Core dumps are disabled at startup.

- **No automatic migration from pinentry-mac.** An item created by
  pinentry-mac belongs to its signature; delete it and re-save (see README).

- **Nothing verifies the caller.** Any process running as you can speak
  Assuan to this program. Parent-process checks are spoofable, so the three
  defenses above carry the weight.

## Reporting scope

In scope: passphrase disclosure to an unauthenticated caller, bypass of the
user-presence check, memory-safety bugs in the Assuan parser or the fallback
protocol driver, and anything that hands gpg-agent the wrong passphrase.

Out of scope: attacks that need root, physical access to an unlocked
machine, or a compromised gpg-agent. A same-uid attacker can usually
compromise gpg-agent, so "any process running as you" is in scope only for
*silent* disclosure, not for the attacks under Known limitations.
