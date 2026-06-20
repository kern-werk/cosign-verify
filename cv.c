// SPDX-License-Identifier: BSD-2-Clause
/*
 * cv — host-side reference verifier for cosign_verify.h.
 *
 *   cv verify <file> <pub.raw64> <sig>
 *       Verify a cosign-format signature (base64 DER ECDSA-P256 over
 *       SHA-256(file)) — exit 0 ok, 1 bad. Bit-for-bit the same check the
 *       kernel module (and later the TA) performs: stream-hash the file,
 *       then cosignverify_verify_digest() on the raw .sig contents.
 *
 *   cv selftest
 *       Run compiled-in vectors for the strict base64 decoder edge cases
 *       that real signatures rarely exercise.
 *
 * <pub.raw64> is the raw 64-byte P-256 point X||Y — the embedded-key format.
 * Extract it from a cosign PEM with:
 *   openssl pkey -pubin -in cosign.pub -outform DER | tail -c 64
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha256.h"
#include "cosign_verify.h"

static int read_file(const char *path, uint8_t **buf, size_t *len)
{
	FILE *f = fopen(path, "rb");
	if (!f) { perror(path); return -1; }
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (sz < 0) { fclose(f); return -1; }
	uint8_t *b = malloc(sz ? sz : 1);
	if (!b) { fclose(f); return -1; }
	if (sz && fread(b, 1, sz, f) != (size_t)sz) { perror("fread"); free(b); fclose(f); return -1; }
	fclose(f);
	*buf = b; *len = sz;
	return 0;
}

static int read_exact(const char *path, uint8_t *buf, size_t want)
{
	FILE *f = fopen(path, "rb");
	if (!f) { perror(path); return -1; }
	size_t n = fread(buf, 1, want, f);
	int extra = getc(f);   /* EOF expected: the key file must be exactly `want` */
	fclose(f);
	if (n != want || extra != EOF) {
		fprintf(stderr, "%s: expected exactly %zu bytes\n", path, want);
		return -1;
	}
	return 0;
}

/* SHA-256 the file by streaming (mirrors the kmod's hash_file()). */
static int hash_file(const char *path, uint8_t digest[COSIGNVERIFY_DIGEST_BYTES])
{
	uint8_t buf[65536];
	SHA256_CTX ctx;
	size_t n;
	FILE *f = fopen(path, "rb");
	if (!f) { perror(path); return -1; }

	SHA256_init(&ctx);
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
		SHA256_update(&ctx, buf, (int)n);
	int err = ferror(f);
	fclose(f);
	if (err) { fprintf(stderr, "%s: read error\n", path); return -1; }
	memcpy(digest, SHA256_final(&ctx), COSIGNVERIFY_DIGEST_BYTES);
	return 0;
}

static int cmd_verify(const char *file, const char *pk_path, const char *sig_path)
{
	uint8_t pk[COSIGNVERIFY_PK_BYTES], digest[COSIGNVERIFY_DIGEST_BYTES];
	uint8_t *sig; size_t sig_len;

	if (read_exact(pk_path, pk, sizeof(pk))) return 2;
	if (read_file(sig_path, &sig, &sig_len)) return 2;
	if (hash_file(file, digest)) { free(sig); return 2; }

	int rc = cosignverify_verify_digest(sig, sig_len, digest, pk);
	free(sig);
	if (rc != 0) {
		fprintf(stderr, "[!] signature INVALID\n");
		return 1;
	}
	fprintf(stderr, "[*] signature OK\n");
	return 0;
}

/* --- base64 decoder vectors (the strictness real sigs rarely exercise) --- */

struct b64_vec {
	const char *in;
	int out_len;          /* -1 = must be rejected */
	const char *out;      /* expected bytes when out_len >= 0 */
	const char *why;
};

static const struct b64_vec vecs[] = {
	{ "TWFu",     3, "Man",  "plain block" },
	{ "TWE=",     2, "Ma",   "one pad" },
	{ "TQ==",     1, "M",    "two pad" },
	{ "TWFuTWFu", 6, "ManMan", "two blocks" },
	{ "",        -1, 0, "empty" },
	{ "TWF",     -1, 0, "length not multiple of 4" },
	{ "TWFu\n",  -1, 0, "embedded whitespace (caller trims, decoder rejects)" },
	{ "TW=u",    -1, 0, "pad not at end" },
	{ "T===",    -1, 0, "three pads" },
	{ "====",    -1, 0, "all pads" },
	{ "TW!u",    -1, 0, "bad alphabet" },
	{ "TR==",    -1, 0, "non-canonical pad bits (2-pad)" },
	{ "TWF=",    -1, 0, "non-canonical pad bits (1-pad)" },
	{ "TQ==TQ==",-1, 0, "pad mid-stream" },
};

static int cmd_selftest(void)
{
	uint8_t out[16];
	int fail = 0;

	for (size_t i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
		const struct b64_vec *v = &vecs[i];
		int n = cosignverify_b64_decode((const uint8_t *)v->in, strlen(v->in),
					      out, sizeof(out));
		int ok = (v->out_len < 0)
			? (n < 0)
			: (n == v->out_len && memcmp(out, v->out, n) == 0);
		fprintf(stderr, "  %-50s %s\n", v->why, ok ? "ok" : "FAIL");
		fail |= !ok;
	}
	/* Output-capacity guard: "TWFu" needs 3 bytes, give it 2. */
	{
		int n = cosignverify_b64_decode((const uint8_t *)"TWFu", 4, out, 2);
		fprintf(stderr, "  %-50s %s\n", "output cap enforced", n < 0 ? "ok" : "FAIL");
		fail |= !(n < 0);
	}
	fprintf(stderr, fail ? "[!] selftest FAILED\n" : "[*] selftest OK\n");
	return fail;
}

int main(int argc, char **argv)
{
	if (argc == 5 && !strcmp(argv[1], "verify"))
		return cmd_verify(argv[2], argv[3], argv[4]);
	if (argc == 2 && !strcmp(argv[1], "selftest"))
		return cmd_selftest();

	fprintf(stderr,
		"usage:\n"
		"  %s verify <file> <pub.raw64> <sig>\n"
		"  %s selftest\n", argv[0], argv[0]);
	return 2;
}
