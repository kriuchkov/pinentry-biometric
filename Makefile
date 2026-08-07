# pinentry-biometric — GNU make (works with Apple's make 3.81).
# SPDX-License-Identifier: MIT
CC         = clang
# Hardened Runtime is a security requirement, not a packaging nicety: without
# it DYLD_INSERT_LIBRARIES can replace the LocalAuthentication call that gates
# the passphrase, so the binary is signed as part of the link rule and never
# exists unhardened. macOS floor and archs must be pinned or the build silently
# targets the host only (README promises macOS 12+, Intel and Apple Silicon).
DEPLOY     = -mmacosx-version-min=12.0
ARCHS     ?= -arch arm64 -arch x86_64
CFLAGS     = -std=c11 -Wall -Wextra -Werror -O2 -fstack-protector-strong \
             $(DEPLOY) $(ARCHS)
OBJCFLAGS  = $(CFLAGS) -fobjc-arc
# Session detection in biometry.m uses SessionGetInfo from Security,
# so no CoreGraphics/AppKit link is needed.
FRAMEWORKS = -framework Foundation -framework Security \
             -framework LocalAuthentication -framework CoreFoundation
PREFIX    ?= /usr/local
# Override to sign with a Developer ID so the keychain identity survives
# rebuilds: make CODESIGN_ID="Developer ID Application: You (TEAMID)"
CODESIGN_ID ?= -

BUILD  = build
BIN    = $(BUILD)/pinentry-biometric
C_SRCS = src/main.c src/assuan.c src/state.c src/secure_mem.c src/fallback.c
M_SRCS = src/keychain.m src/biometry.m
OBJS   = $(patsubst src/%.c,$(BUILD)/%.o,$(C_SRCS)) \
         $(patsubst src/%.m,$(BUILD)/%.o,$(M_SRCS))

.PHONY: all test install clean sign

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(FRAMEWORKS)
	codesign --force --options runtime --sign $(CODESIGN_ID) $@

# Coarse but safe header deps: any header change rebuilds everything.
$(BUILD)/%.o: src/%.c src/*.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/%.o: src/%.m src/*.h | $(BUILD)
	$(CC) $(OBJCFLAGS) -c -o $@ $<

$(BUILD):
	mkdir -p $(BUILD)

# Unit tests are pure C: no frameworks, no Keychain, no biometry.
test: $(BUILD)/test_assuan $(BUILD)/test_state
	$(BUILD)/test_assuan
	$(BUILD)/test_state

$(BUILD)/test_assuan: tests/test_assuan.c src/assuan.c src/*.h | $(BUILD)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_assuan.c src/assuan.c

$(BUILD)/test_state: tests/test_state.c src/state.c src/secure_mem.c src/*.h | $(BUILD)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_state.c src/state.c src/secure_mem.c

install: all
	install -d $(PREFIX)/bin
	install -m 755 $(BIN) $(PREFIX)/bin/pinentry-biometric

# Kept for compatibility and for re-signing an existing build with a
# Developer ID; the normal build already signs.
sign: all
	codesign --force --options runtime --sign $(CODESIGN_ID) $(BIN)

clean:
	rm -rf $(BUILD)
