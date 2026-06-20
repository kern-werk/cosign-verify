/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * cosign_verify.h — verify-only adapter for Cosign-format signatures, on top of
 * the vendored Android libmincrypt P-256 code (third_party/p256).
 *
 * Compatibility contract (the supported subset of sigstore/cosign):
 *
 *   key-pair blob signatures only — what these commands produce/accept:
 *     cosign sign-blob   --key <priv|kms-uri> --tlog-upload=false \
 *                        --output-signature <blob>.sig <blob>
 *                        (cosign >= 3.x also needs --use-signing-config=false)
 *     cosign verify-blob --key <pub.pem> --signature <blob>.sig \
 *                        --insecure-ignore-tlog=true <blob>
 *
 *   No keyless/Fulcio, no Rekor transparency log, no bundles, no OCI.
 *
 * Wire format: the .sig file is base64(DER ECDSA-Sig-Value{r,s}) of an
 * ECDSA-P256 signature over SHA-256(blob). The caller computes the digest
 * (stream it — see secasset_sha256()) and hands it here together with the raw
 * signature file contents; we trim a trailing newline, base64-decode, DER-
 * unpack via the vendored dsa_sig_unpack(), and verify. The public key is the
 * raw 64-byte uncompressed point X||Y (the last 64 bytes of the PKIX DER in
 * cosign's pub PEM — extracted at build time, see tools/embed-pubkey.sh).
 *
 * Verification only: no RNG, no allocation (a few hundred bytes of stack),
 * identical code in-kernel, in the OP-TEE TA, and in userland.
 *
 * Include requirements (provided by each environment before including this):
 *   - third_party/p256 headers on the include path (p256.h, p256_ecdsa.h,
 *     dsa_sig.h) and their .c files linked into the image;
 *   - a definition of uint8_t (kernel: linux headers via the compat_libc
 *     shim; user/TA: <stdint.h>).
 */
#ifndef COSIGN_VERIFY_H
#define COSIGN_VERIFY_H

#include "p256.h"
#include "p256_ecdsa.h"
#include "dsa_sig.h"

#define COSIGNVERIFY_DIGEST_BYTES 32u  /* SHA-256                            */
#define COSIGNVERIFY_PK_BYTES     64u  /* raw P-256 point, X || Y            */
#define COSIGNVERIFY_DER_MAX      72u  /* SEQ(2) + 2*INT(2+33)               */
#define COSIGNVERIFY_SIG_MAX     128u  /* base64(DER_MAX)=96 + newline + pad */

/* Map one base64 character to its 6-bit value, or -1. */
static inline int cosignverify_b64_val(uint8_t c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

/*
 * Strict base64 decode: standard alphabet, length a non-zero multiple of 4,
 * '=' padding only at the very end, padded bits required to be zero (so every
 * signature has exactly one valid encoding). Returns the decoded length, or
 * -1 on any malformation or if the output exceeds `cap`.
 */
static inline int cosignverify_b64_decode(const uint8_t *in, unsigned long len,
					uint8_t *out, unsigned long cap)
{
	unsigned long i, o = 0;
	unsigned pad = 0;

	if (len == 0 || (len & 3) != 0)
		return -1;
	if (in[len - 1] == '=') pad++;
	if (in[len - 2] == '=') pad++;

	for (i = 0; i < len; i += 4) {
		int v0 = cosignverify_b64_val(in[i]);
		int v1 = cosignverify_b64_val(in[i + 1]);
		int v2 = cosignverify_b64_val(in[i + 2]);
		int v3 = cosignverify_b64_val(in[i + 3]);
		unsigned last = (i + 4 == len);
		unsigned n = last ? 3 - pad : 3, k;
		uint8_t b[3];

		if (v0 < 0 || v1 < 0)
			return -1;
		if (last && pad >= 2) v2 = 0; else if (v2 < 0) return -1;
		if (last && pad >= 1) v3 = 0; else if (v3 < 0) return -1;
		/* Non-canonical padding bits make the same bytes encode two
		 * ways — reject. */
		if (last && pad == 2 && (v1 & 0x0f))
			return -1;
		if (last && pad == 1 && (v2 & 0x03))
			return -1;

		b[0] = (uint8_t)(v0 << 2 | v1 >> 4);
		b[1] = (uint8_t)((v1 & 0x0f) << 4 | v2 >> 2);
		b[2] = (uint8_t)((v2 & 0x03) << 6 | v3);
		if (o + n > cap)
			return -1;
		for (k = 0; k < n; k++)
			out[o++] = b[k];
	}
	return (int)o;
}

/*
 * Verify a cosign .sig (raw file contents, base64 DER) over a 32-byte SHA-256
 * digest under a raw 64-byte P-256 public key. Returns 0 on success, -1 on
 * any failure (malformed base64/DER, bad point, bad signature).
 */
static inline int cosignverify_verify_digest(const uint8_t *sig, unsigned long sig_len,
					   const uint8_t digest[COSIGNVERIFY_DIGEST_BYTES],
					   const uint8_t pk[COSIGNVERIFY_PK_BYTES])
{
	uint8_t der[COSIGNVERIFY_DER_MAX];
	p256_int kx, ky, m, r, s;
	int der_len;

	/* Tolerate (only) trailing newline/CR — pipelines add one. */
	while (sig_len && (sig[sig_len - 1] == '\n' || sig[sig_len - 1] == '\r'))
		sig_len--;
	if (sig_len == 0 || sig_len > COSIGNVERIFY_SIG_MAX)
		return -1;

	der_len = cosignverify_b64_decode(sig, sig_len, der, sizeof(der));
	if (der_len < 8)
		return -1;
	if (!dsa_sig_unpack(der, der_len, &r, &s))
		return -1;

	p256_from_bin(pk, &kx);
	p256_from_bin(pk + P256_NBYTES, &ky);
	p256_from_bin(digest, &m);

	return p256_ecdsa_verify(&kx, &ky, &m, &r, &s) ? 0 : -1;
}

#endif /* COSIGN_VERIFY_H */
