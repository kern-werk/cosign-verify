# SPDX-License-Identifier: BSD-2-Clause
# cosign-verify — verify-only Cosign blob signatures in freestanding C.
# Builds the host reference verifier; the library itself is cosign_verify.h
# plus the vendored third_party sources (no build artifact of its own).
CC     ?= cc
CFLAGS ?= -Wall -Wextra -O2
CFLAGS += -I. -Ithird_party/p256 -Ithird_party/sha256

SRC = cv.c \
      third_party/sha256/sha256.c \
      third_party/p256/p256.c third_party/p256/p256_ec.c \
      third_party/p256/p256_ecdsa.c third_party/p256/dsa_sig.c

cv: $(SRC) cosign_verify.h
	$(CC) $(CFLAGS) -o $@ $(SRC)

test: cv
	test/test.sh

clean:
	rm -f cv

.PHONY: test clean
