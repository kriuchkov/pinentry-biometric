#!/usr/bin/env bash
# tests/integration.sh — integration tests for pinentry-biometric.
#
# Steps 1-3 are automated. Step 3 drives the first-entry fallback against a
# scripted pinentry (tests/fake-pinentry.sh); GETPIN refuses to run without a
# GUI session, so where there is none the step reports SKIPPED. Step 4 is
# MANUAL: it drives a real gpg-agent session and therefore needs a live
# finger on the Touch ID sensor (or the account-password fallback). Enable it
# with INTERACTIVE=1.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/build/pinentry-biometric"
FAKE="$REPO/tests/fake-pinentry.sh"

if [ ! -x "$BIN" ]; then
    echo "FATAL: $BIN not found or not executable. Run 'make' first." >&2
    exit 1
fi

TMPD="$(mktemp -d)"
TEST_GNUPGHOME=""
cleanup() {
    if [ -n "$TEST_GNUPGHOME" ]; then
        gpgconf --kill gpg-agent 2>/dev/null || true
        rm -rf "$TEST_GNUPGHOME"
    fi
    rm -rf "$TMPD"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# ---------------------------------------------------------------------------
echo "== Step 1: protocol smoke test =="
echo "   (GETPIN is deliberately excluded: it triggers Touch ID / a dialog"
echo "    and needs a live finger — see step 4 for the interactive path.)"
OUT="$(printf 'OPTION allow-external-password-cache\nSETKEYINFO n/0123456789ABCDEF0123456789ABCDEF01234567\nSETDESC Test\nGETINFO pid\nGETINFO flavor\nNOP\nRESET\nBYE\n' | "$BIN")"
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

# SET* commands are case-insensitive; an unknown one is an unknown command
# (83886355 = GPG_ERR_ASS_UNKNOWN_CMD), never a silent OK.
OUT1B="$(printf 'setdesc lower\nSETFOO x\nBYE\n' | "$BIN")"
if [ "$(printf '%s\n' "$OUT1B" | sed -n 2p)" != "OK" ] ||
   ! printf '%s\n' "$OUT1B" | sed -n 3p | grep -q '^ERR 83886355 '; then
    printf '%s\n' "$OUT1B" >&2
    echo "FAIL: SET* dispatch (lowercase accepted, unknown rejected)" >&2
    exit 1
fi
echo "PASS: SET* dispatch"

# The fallback receives the passphrase, so its path must not depend on
# gpg-agent's working directory.
if "$BIN" --fallback-pinentry tests/fake-pinentry.sh < /dev/null > /dev/null 2>&1 ||
   "$BIN" --fallback-pinentry=fake-pinentry.sh < /dev/null > /dev/null 2>&1; then
    echo "FAIL: a relative --fallback-pinentry path was accepted" >&2
    exit 1
fi
echo "PASS: relative --fallback-pinentry rejected"

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
echo "== Step 3: first-entry fallback against a scripted pinentry =="
# run_fb <mode> <input> [-]: one session with tests/fake-pinentry.sh as the
# fallback; <input> is expanded with printf %b. Our replies land in
# $TMPD/out, every line the fake was sent in $TMPD/fake.log. A hard 10 s
# deadline: a regression that raises a real dialog (Touch ID, "Save to
# Keychain?") has to fail the test, not hang it. The binary gets an extra
# fd 3, which must not leak into the fallback child. A third argument of
# "-" starts the binary with its stderr closed.
run_fb() {
    : > "$TMPD/fake.log"
    printf '%b' "$2" > "$TMPD/in"
    FAKE_PIN_MODE="$1" FAKE_PIN_LOG="$TMPD/fake.log" \
        "$BIN" --fallback-pinentry "$FAKE" < "$TMPD/in" > "$TMPD/out" \
        3< /dev/null 2>&"${3:-2}" &
    local pid=$! tick=0
    while kill -0 "$pid" 2>/dev/null; do
        tick=$((tick + 1))
        if [ "$tick" -gt 100 ]; then
            kill -9 "$pid" 2>/dev/null || true
            fail "session (mode $1) did not finish within 10 s — a dialog?"
        fi
        sleep 0.1
    done
    wait "$pid" || true
}

# expect <line> <what>: <line> must appear verbatim in our replies.
expect() {
    if ! grep -qxF -- "$1" "$TMPD/out"; then
        cat "$TMPD/out" >&2
        fail "$2: expected the reply line '$1'"
    fi
}

# "pass%word" LF "tail", sent by the fake as two D lines, must come out as
# one D line, re-escaped, followed by OK.
PIN_LINE='D pass%25word%0Atail'
expect_pin() {
    expect "$PIN_LINE" "$1"
    if ! awk -v d="$PIN_LINE" 'p == d && $0 == "OK" { f = 1 } { p = $0 }
                               END { exit !f }' "$TMPD/out"; then
        fail "$1: the data line was not followed by OK"
    fi
}

run_fb ok 'GETPIN\nBYE\n'
# 83886165 = GPG_ERR_NO_PIN_ENTRY: GETPIN fails fast without a GUI session.
if grep -q '^ERR 83886165' "$TMPD/out"; then
    # CI sets REQUIRE_GUI=1: its runners have a GUI session, and losing it
    # must fail the job rather than quietly skip everything below.
    if [ "${REQUIRE_GUI:-0}" = 1 ]; then
        fail "no GUI session, so the fallback tests cannot run (REQUIRE_GUI=1)"
    fi
    echo "SKIPPED: no GUI session here, and GETPIN refuses to run without one."
else
    expect_pin "passphrase relay"
    if grep -qxF 'FD3 open' "$TMPD/fake.log"; then
        fail "a file descriptor beyond stdio leaked into the fallback child"
    fi
    # run_fb starts us in the background, i.e. with SIGINT ignored, and we
    # ignore SIGPIPE ourselves: neither may reach the child.
    if grep -q '^SIGIGN' "$TMPD/fake.log"; then
        fail "the fallback child inherited ignored signals: $(grep '^SIGIGN' "$TMPD/fake.log")"
    fi

    # Started with stderr closed, we must not let a pipe or any other
    # descriptor stand in for it: the child gets /dev/null as stderr.
    run_fb ok 'GETPIN\nBYE\n' -
    expect_pin "relay with our stderr closed"
    grep -qxF 'FD2 devnull' "$TMPD/fake.log" ||
        fail "with our stderr closed, the fallback child's stderr was not /dev/null"

    run_fb ok 'OPTION allow-external-password-cache\nOPTION ttyname=/dev/ttys000\nSETKEYINFO --clear\nSETDESC 100%25 sure\nGETPIN\nBYE\n'
    expect_pin "relay with options set"
    grep -qxF 'SETDESC 100%25 sure' "$TMPD/fake.log" ||
        fail "SETDESC was not forwarded (re-escaped) to the fallback"
    grep -qxF 'OPTION ttyname=/dev/ttys000' "$TMPD/fake.log" ||
        fail "OPTION ttyname was not forwarded to the fallback"
    # The deliberate omission (DESIGN.md): forwarded, these would let
    # pinentry-mac save the passphrase under its own code signature.
    if grep -qE 'allow-external-password-cache|^SETKEYINFO' "$TMPD/fake.log"; then
        fail "allow-external-password-cache or SETKEYINFO reached the fallback"
    fi

    # No allow-external-password-cache (gpg-agent's no-allow-external-cache):
    # a cacheable SETKEYINFO must not lead to a "Save to Keychain?" dialog
    # after the prompt, which would trip the deadline. The lookup half of
    # the gate is not visible here (there is no item for this keygrip, so a
    # lookup would not prompt either); test_state.c covers the gate itself.
    run_fb ok 'SETKEYINFO n/0000000000000000000000000000000000000000\nGETPIN\nBYE\n'
    expect_pin "keyinfo without allow-external-password-cache"

    # 83886179 = GPG_ERR_CANCELED
    run_fb cancel 'GETPIN\nBYE\n'
    grep -q '^ERR 83886179 ' "$TMPD/out" || fail "fallback cancel was not reported as CANCELED"

    # 83886143 = GPG_ERR_INTERNAL; the session must outlive the child.
    run_fb die 'GETPIN\nBYE\n'
    grep -q '^ERR 83886143 ' "$TMPD/out" || fail "a dying fallback was not reported as an error"
    expect 'OK closing connection' "session after the fallback died"

    # gpg-agent cancels a pinentry with SIGINT (libassuan's
    # assuan_pipe_kill_server, e.g. when gpg is interrupted). We have to
    # exit, and the fallback's dialog has to go with us; the hanging fake
    # stands in for that dialog.
    #
    # cancel_case <signal> <mode> <pidfile>: send <signal> to a session that
    # is waiting on the fake. Within 3 s — long before the fake's own 30 s
    # run out — we must be gone, and so must the process whose pid the fake
    # left in <pidfile>. Job control is switched on for the spawn because a
    # non-interactive shell starts background jobs with SIGINT and SIGQUIT
    # ignored, and gpg-agent does not.
    cancel_case() {
        local pe victim tick=0
        rm -f "$TMPD/fake.pid" "$TMPD/fake.pid.child"
        printf 'GETPIN\n' > "$TMPD/in"
        set -m
        FAKE_PIN_MODE="$2" FAKE_PIN_PIDFILE="$TMPD/fake.pid" \
            "$BIN" --fallback-pinentry "$FAKE" < "$TMPD/in" > "$TMPD/out" &
        pe=$!
        set +m
        while [ ! -s "$3" ]; do
            tick=$((tick + 1))
            if [ "$tick" -gt 50 ]; then
                kill -9 "$pe" 2>/dev/null || true
                fail "SIG$1, mode $2: the fake pinentry never received GETPIN"
            fi
            sleep 0.1
        done
        victim="$(cat "$3")"
        kill "-$1" "$pe"
        tick=0
        while kill -0 "$pe" 2>/dev/null; do
            tick=$((tick + 1))
            if [ "$tick" -gt 30 ]; then
                kill -9 "$pe" "$victim" 2>/dev/null || true
                fail "SIG$1, mode $2: still running 3 s after the signal"
            fi
            sleep 0.1
        done
        wait "$pe" 2>/dev/null || true
        tick=0
        while kill -0 "$victim" 2>/dev/null; do
            tick=$((tick + 1))
            if [ "$tick" -gt 10 ]; then
                kill -9 "$victim" 2>/dev/null || true
                fail "SIG$1, mode $2: the fallback's dialog process outlived us"
            fi
            sleep 0.1
        done
    }
    cancel_case INT hang "$TMPD/fake.pid"
    # A wrapper script that runs pinentry-mac without exec: the dialog is a
    # grandchild holding our pipes.
    cancel_case INT hang-child "$TMPD/fake.pid.child"
    # The child runs in its own process group, so a terminal's or a service
    # manager's signal reaches only us; each has to take the child along.
    for sig in TERM HUP QUIT; do
        cancel_case "$sig" hang "$TMPD/fake.pid"
    done

    echo "PASS: fallback relay, forwarding, cancel, child failure and signals"
fi

# ---------------------------------------------------------------------------
echo "== Step 4: gpg end-to-end (MANUAL — requires a live finger) =="
if [ "${INTERACTIVE:-0}" = 1 ]; then
    GNUPGHOME="$(mktemp -d)"
    export GNUPGHOME
    TEST_GNUPGHOME="$GNUPGHOME"
    chmod 700 "$GNUPGHOME"

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
