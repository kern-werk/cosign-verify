#!/usr/bin/env bash
#
# gen-vectors.sh — (re)generate the test vectors in test/vectors/.
#
# Vectors are not committed: test.sh runs this automatically when the folder
# is empty. The signing keys are created fresh in a tmpdir and thrown away, so
# regenerating REPLACES the vectors wholesale (the old signatures can never be
# reproduced). Run it by hand only to deliberately refresh the vectors.
#
# Requires openssl and cosign.
#
# Produces:
#   blob.dat            the signed payload (fixed text)
#   pub.pem             P-256 public key, PKIX PEM (what cosign hands out)
#   pub.raw64           raw 64-byte X||Y (the embedded-key format)
#   otherpub.raw64      a second key's public half (wrong-key negative test)
#   blob.sig            base64(DER) signature over SHA-256(blob.dat)
#   blob.cosign.sig     a signature produced by stock `cosign sign-blob`
#   cosignpub.raw64     the cosign key's public half
#
set -euo pipefail

command -v cosign >/dev/null || { echo "cosign is required" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VEC="$HERE/vectors"
TMP="$(mktemp -d /tmp/cosign-verify-vectors.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$VEC"

printf 'cosign-verify test vector: ECDSA-P256 over SHA-256, cosign blob format.\n' \
	> "$VEC/blob.dat"

openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/ec.key" 2>/dev/null
openssl ec -in "$TMP/ec.key" -pubout -out "$VEC/pub.pem" 2>/dev/null
openssl pkey -pubin -in "$VEC/pub.pem" -outform DER | tail -c 64 > "$VEC/pub.raw64"

openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/other.key" 2>/dev/null
openssl ec -in "$TMP/other.key" -pubout -outform DER 2>/dev/null | tail -c 64 \
	> "$VEC/otherpub.raw64"

openssl dgst -sha256 -sign "$TMP/ec.key" "$VEC/blob.dat" | base64 -w0 > "$VEC/blob.sig"

export COSIGN_PASSWORD=""
(cd "$TMP" && cosign generate-key-pair >/dev/null 2>&1)
# --use-signing-config exists only on cosign >= 3.x; pass it only if supported.
scfg=()
if cosign sign-blob --help 2>&1 | grep -q -- --use-signing-config; then
	scfg=(--use-signing-config=false)
fi
cosign sign-blob --key "$TMP/cosign.key" "${scfg[@]}" \
	--tlog-upload=false --output-signature "$VEC/blob.cosign.sig" \
	"$VEC/blob.dat" >/dev/null 2>&1
openssl pkey -pubin -in "$TMP/cosign.pub" -outform DER | tail -c 64 \
	> "$VEC/cosignpub.raw64"

echo "[*] vectors written to $VEC:"
ls -la "$VEC"
