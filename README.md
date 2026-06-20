# cosign-verify

Verify [Cosign](https://github.com/sigstore/cosign) blob signatures in ~150 lines of freestanding C — no libc required, no allocation, no RNG, no dependencies beyond the vendored sources in this folder. Small enough to run inside a kernel module.

## Compatibility contract

The supported subset of cosign is exactly **key-pair blob signatures**:

```sh
cosign sign-blob --key <priv|kms-uri> --tlog-upload=false \
                 --output-signature blob.sig blob
# cosign >= 3.x additionally needs: --use-signing-config=false

# what this library verifies is bit-for-bit what this accepts:
cosign verify-blob --key pub.pem --signature blob.sig \
                   --insecure-ignore-tlog=true blob
```

Wire format: `blob.sig` is `base64(DER ECDSA-Sig-Value{r,s})` — an ECDSA-P256 signature over `SHA-256(blob)`. Cosign only generates ECDSA-P256/SHA-256 keys, so this is the only algorithm pair implemented.

## API

Everything is in [`cosign_verify.h`](cosign_verify.h) (header-only, static inline), on top of the vendored sources:

```c
/* digest: SHA-256 of the blob. sig: raw .sig file contents.
 * pk: raw 64-byte P-256 point X||Y.
 * Returns 0 on a good signature, -1 on anything else. */
int cosignverify_verify_digest(const uint8_t *sig, unsigned long sig_len,
                             const uint8_t digest[32],
                             const uint8_t pk[64]);
```

Extract the raw 64-byte public key from cosign's PEM:

```sh
openssl pkey -pubin -in cosign.pub -outform DER | tail -c 64 > pub.raw64
```

Stack use is a few hundred bytes; the base64 decoder is strict (canonical encodings only) and the DER unpacking is mincrypt's `dsa_sig_unpack`.

## Testing

```sh
make test
```

## Dependencies sources

| what | source |
|---|---|
| `third_party/p256/` | AOSP libmincrypt @ [`669ecc2f`](https://android.googlesource.com/platform/system/core/+/669ecc2f5e80ff924fa20ce7445354a7c5bcfd98/libmincrypt/) |
| `third_party/sha256/` | AOSP libmincrypt @ same commit |

The vendored files carry minimal, documented local changes (flattened include paths, unused libc includes dropped) so they compile freestanding. Everything else is byte-identical to upstream. The mincrypt P-256 code is the verifier Android used for verified boot: integer-only, constant time, no heap.
