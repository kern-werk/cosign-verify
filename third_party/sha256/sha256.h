/* sha256.h
**
** Copyright 2007, The Android Open Source Project
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of Google Inc. nor the names of its contributors may
**       be used to endorse or promote products derived from this software
**       without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY Google Inc. ``AS IS'' AND ANY EXPRESS OR
** IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
** EVENT SHALL Google Inc. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
** PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
** OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
** WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
** OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
** ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
 * Companion header for the Android Open Source Project (libmincrypt) SHA-256.
 * Source:
 *   https://android.googlesource.com/platform/system/core/+/669ecc2f5e80ff924fa20ce7445354a7c5bcfd98/libmincrypt/sha256.c
 *   (sha256.h alongside it in libmincrypt/include/mincrypt/)
 */

#ifndef _CRYPTO_SHA256_H
#define _CRYPTO_SHA256_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration so the vtab's function-pointer parameters reference the
 * file-scope tag (not a prototype-scoped one), matching SHA256_CTX below. */
struct HASH_CTX;

typedef struct HASH_VTAB {
  void (* const init)(struct HASH_CTX*);
  void (* const update)(struct HASH_CTX*, const void*, int);
  const uint8_t* (* const final)(struct HASH_CTX*);
  const uint8_t* (* const hash)(const void*, int, uint8_t*);
  int size;
} HASH_VTAB;

typedef struct HASH_CTX {
  const HASH_VTAB * f;
  uint64_t count;
  uint8_t buf[64];
  uint32_t state[8];
} HASH_CTX;

typedef HASH_CTX SHA256_CTX;

void SHA256_init(SHA256_CTX* ctx);
void SHA256_update(SHA256_CTX* ctx, const void* data, int len);
const uint8_t* SHA256_final(SHA256_CTX* ctx);

#define SHA256_DIGEST_SIZE 32

/* Convenience method. Returns digest address. */
/* NOTE: *digest needs to hold SHA256_DIGEST_SIZE bytes. */
const uint8_t* SHA256_hash(const void* data, int len, uint8_t* digest);

#ifdef __cplusplus
}
#endif

#endif
