#!/usr/bin/env bash
# tests/security_check.sh — security checks for pinentry-biometric.
# Checks 2 and 3 are best-effort (commented inline); check 1 is authoritative.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/build/pinentry-biometric"

if [ ! -x "$BIN" ]; then
    echo "FATAL: $BIN not found or not executable. Run 'make' first." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
echo "== Check 1: no network frameworks linked (otool -L) =="
LINKS="$(otool -L "$BIN")"
printf '%s\n' "$LINKS"
if printf '%s\n' "$LINKS" | grep -iE 'CFNetwork|Network\.framework|NSURL|curl|ssl'; then
    echo "FAIL: binary links against a network-capable library" >&2
    exit 1
fi
echo "Allowed link set: Foundation, Security, LocalAuthentication,"
echo "CoreFoundation, plus libSystem/libobjc runtime libraries."
echo "PASS: no network frameworks"

# ---------------------------------------------------------------------------
echo "== Check 1b: Hardened Runtime is enabled =="
# Not cosmetic. The Touch ID gate is an in-process LocalAuthentication call,
# so it is only meaningful if the process cannot be tampered with: without
# the runtime flag, DYLD_INSERT_LIBRARIES can replace that call and the
# passphrase is released with no user interaction at all.
# Captured first: piping straight into `grep -q` makes codesign die of
# SIGPIPE, which `set -o pipefail` then reports as a failed check.
SIGINFO="$(codesign -d --verbose=2 "$BIN" 2>&1 || true)"
if printf '%s\n' "$SIGINFO" | grep -qE 'flags=.*runtime'; then
    echo "PASS: binary is signed with Hardened Runtime"
else
    echo "FAIL: binary lacks Hardened Runtime — the biometric gate is" >&2
    echo "      bypassable via DYLD_INSERT_LIBRARIES. Rebuild with 'make'." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
echo "== Check 2: --debug masks D-line payloads (best effort) =="
# We cannot exercise a real GETPIN non-interactively, so this check is
# two-fold and honest about its limits:
#   a) run a scripted --debug session and capture stderr, so the debug code
#      path is at least executed once;
#   b) confirm the "D ***" masking literal is still present in assuan.c.
#      That is a source-level regression guard, not a behavioural proof: it
#      inspects the working tree, not the binary under test.
ERRLOG="$(mktemp)"
printf 'SETDESC secretmarker123\nBYE\n' | "$BIN" --debug > /dev/null 2> "$ERRLOG" || true
echo "-- captured --debug stderr:"
cat "$ERRLOG"
rm -f "$ERRLOG"
if grep -q 'D \*\*\*' "$REPO/src/assuan.c"; then
    echo "PASS: src/assuan.c contains the 'D ***' masking literal"
else
    echo "FAIL: 'D ***' masking literal not found in src/assuan.c" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
echo "== Check 3: no test/marker passphrases baked into the binary (best effort) =="
# strings(1) cannot prove the absence of secret handling bugs; this only
# guards against test fixtures or debug literals leaking into the release
# binary. Checking for memset-vs-memset_s at the binary level is not
# meaningful (inlining), so it is deliberately not attempted here.
if strings "$BIN" | grep -iE 'secretmarker|testpassphrase|hunter2'; then
    echo "FAIL: marker/test passphrase string found in binary" >&2
    exit 1
fi
echo "PASS: no marker passphrase strings in binary"

echo "All security checks passed."
