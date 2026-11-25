#!/usr/bin/env bash
# tests/fake-pinentry.sh — scripted stand-in for pinentry-mac, passed to the
# binary with --fallback-pinentry so tests/integration.sh can drive
# src/fallback.c without any dialog. Configured through the environment,
# which reaches us through the binary under test:
#   FAKE_PIN_MODE     ok (default) | cancel | die | hang
#   FAKE_PIN_LOG      file that receives every command line we are sent
#   FAKE_PIN_PIDFILE  file that receives our pid once GETPIN arrives
set -u

log() {
    if [ -n "${FAKE_PIN_LOG:-}" ]; then
        printf '%s\n' "$1" >> "$FAKE_PIN_LOG"
    fi
}

printf 'OK Pleased to meet you\n'
while IFS= read -r line; do
    log "$line"
    case "$line" in
        GETPIN)
            if [ -n "${FAKE_PIN_PIDFILE:-}" ]; then
                printf '%s\n' "$$" > "$FAKE_PIN_PIDFILE"
            fi
            # integration.sh starts the binary with fd 3 open; only stdio
            # may reach us.
            if { : >&3; } 2> /dev/null; then
                log "FD3 open"
            fi
            case "${FAKE_PIN_MODE:-ok}" in
                ok)
                    # A status line to skip, then the passphrase "pass%word",
                    # LF, "tail" split over two D lines: the driver has to
                    # decode each line and join them.
                    printf 'S SOMESTATUS ignored\n'
                    printf 'D pass%%25word\n'
                    printf 'D %%0Atail\n'
                    printf 'OK\n'
                    ;;
                cancel)
                    printf 'ERR 83886179 Operation cancelled\n'
                    ;;
                die)
                    exit 3
                    ;;
                hang)
                    # Like a modal dialog: blocked on something other than
                    # stdin, so EOF from a dead parent does not end us.
                    exec sleep 30
                    ;;
            esac
            ;;
        BYE)
            # The driver closes its end right after sending BYE, without
            # reading this reply: a write error here is expected.
            printf 'OK closing connection\n' 2> /dev/null || true
            exit 0
            ;;
        *)
            printf 'OK\n'
            ;;
    esac
done
