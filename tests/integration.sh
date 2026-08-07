#!/usr/bin/env bash
# tests/integration.sh — integration tests for pinentry-biometric.
#
# Steps 1 and 2 are fully automated. Step 3 is MANUAL: it drives a real
# gpg-agent session and therefore needs a live finger on the Touch ID
# sensor (or the account-password fallback). Enable it with INTERACTIVE=1.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/build/pinentry-biometric"

if [ ! -x "$BIN" ]; then
    echo "FATAL: $BIN not found or not executable. Run 'make' first." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
echo "== Step 1: protocol smoke test =="
echo "   (GETPIN is deliberately excluded: it triggers Touch ID / a dialog"
echo "    and needs a live finger — see step 3 for the interactive path.)"
OUT="$(printf 'OPTION allow-external-password-cache\nSETKEYINFO n/TESTKEYGRIP000\nSETDESC Test\nGETINFO pid\nGETINFO flavor\nNOP\nRESET\nBYE\n' | "$BIN")"
printf '%s\n' "$OUT"
FIRST="$(printf '%s\n' "$OUT" | head -n 1 | tr -d '\r')"
if [ "$FIRST" != "OK Pleased to meet you" ]; then
    echo "FAIL: unexpected greeting: '$FIRST'" >&2
    exit 1
fi
if printf '%s\n' "$OUT" | grep -q '^ERR '; then
    echo "FAIL: unexpected ERR reply in smoke session" >&2
    exit 1
fi
echo "PASS: smoke test"

# ---------------------------------------------------------------------------
echo "== Step 2: oversized line (>1000 bytes) is a protocol error, not a crash =="
# No python3 dependency: awk is in every base macOS install.
BIG="SETDESC $(awk 'BEGIN{while(i++<1100)printf "x"}')"
OUT2="$(printf '%s\nNOP\nBYE\n' "$BIG" | "$BIN")"
printf '%s\n' "$OUT2"
# 83886343 = (5 << 24) | 263 = GPG_ERR_SOURCE_PINENTRY | GPG_ERR_ASS_LINE_TOO_LONG
if ! printf '%s\n' "$OUT2" | grep -q '^ERR 83886343'; then
    echo "FAIL: expected 'ERR 83886343 ...' (line too long)" >&2
    exit 1
fi
# The session must survive the error: the NOP after it must be answered OK.
if ! printf '%s\n' "$OUT2" | sed -n '/^ERR 83886343/,$p' | tail -n +2 | grep -q '^OK'; then
    echo "FAIL: session did not survive the oversized line (no OK after ERR)" >&2
    exit 1
fi
echo "PASS: oversized line rejected, session survived"

# ---------------------------------------------------------------------------
echo "== Step 3: gpg end-to-end (MANUAL — requires a live finger) =="
if [ "${INTERACTIVE:-0}" = 1 ]; then
    GNUPGHOME="$(mktemp -d)"
    export GNUPGHOME
    chmod 700 "$GNUPGHOME"
    cleanup() {
        gpgconf --kill gpg-agent 2>/dev/null || true
        rm -rf "$GNUPGHOME"
    }
    trap cleanup EXIT

    cat > "$GNUPGHOME/gpg-agent.conf" <<EOF
pinentry-program $BIN
default-cache-ttl 1
max-cache-ttl 1
EOF

    UID_STR="pinentry-biometric-test@example.invalid"
    echo "-- Generating test key (first passphrase prompt goes through our pinentry)"
    gpg --batch --quick-gen-key "$UID_STR" default default never
    echo "-- First clearsign (expect passphrase prompt or Keychain/Touch ID)"
    echo "integration test" | gpg --clearsign -u "$UID_STR" > /dev/null
    sleep 2   # let the 1-second agent cache expire
    echo "-- Second clearsign (expect a Touch ID prompt if the phrase was saved)"
    echo "integration test" | gpg --clearsign -u "$UID_STR" > /dev/null
    echo "PASS: end-to-end signing worked twice"
else
    echo "SKIPPED. Run 'INTERACTIVE=1 tests/integration.sh' to execute the"
    echo "gpg end-to-end test. It creates a throwaway GNUPGHOME, generates a"
    echo "key and clearsigns twice; you must touch the sensor when prompted."
fi

echo "All automated steps passed."
