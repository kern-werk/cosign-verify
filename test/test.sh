#!/usr/bin/env bash
#
# test.sh — cosign-verify test suite.
#
# Three tiers:
#   1. compiled-in selftest      — strict-base64 decoder edge vectors;
#   2. generated vectors         — a known-good signature (openssl + one
#      produced by stock cosign) plus negative variants derived from them
#      (tampered blob, flipped/truncated sig, wrong key);
#   3. live interop              — fresh keys/signatures both ways:
#      cosign-produced sigs must verify here, and an openssl-produced sig
#      accepted here must also be accepted by stock `cosign verify-blob`.
#
# openssl and cosign are assumed installed.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
VEC="$HERE/vectors"
CV="$ROOT/cv"

make -C "$ROOT" cv >/dev/null

TMP="$(mktemp -d /tmp/cosign-verify-test.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

pass=0
ok()   { pass=$((pass+1)); echo "  ok: $1"; }
fail() { echo "  FAIL: $1" >&2; exit 1; }

raw_pub() { openssl pkey -pubin -in "$1" -outform DER | tail -c 64 > "$2"; }

# Vectors are generated, not committed. Build them if the folder is empty.
ensure_vectors() {
	[[ -n "$(ls -A "$VEC" 2>/dev/null)" ]] || "$HERE/gen-vectors.sh" >/dev/null
}

echo "[*] tier 1: base64 decoder selftest"
"$CV" selftest >/dev/null || fail "decoder selftest"
ok "decoder vectors"

echo "[*] tier 2: generated vectors"
ensure_vectors
for sig in "$VEC"/blob.sig "$VEC"/blob.cosign.sig; do
	pub="$VEC/pub.raw64"
	[[ "$sig" == *cosign.sig ]] && pub="$VEC/cosignpub.raw64"
	"$CV" verify "$VEC/blob.dat" "$pub" "$sig" >/dev/null 2>&1 \
		|| fail "vector $(basename "$sig") rejected"
	ok "vector $(basename "$sig") verifies"
done

cat "$VEC/blob.dat" > "$TMP/tampered.dat"; printf 'X' >> "$TMP/tampered.dat"
"$CV" verify "$TMP/tampered.dat" "$VEC/pub.raw64" "$VEC/blob.sig" >/dev/null 2>&1 \
	&& fail "tampered blob accepted"
ok "tampered blob rejected"

sig="$(cat "$VEC/blob.sig")"
c="${sig:10:1}"; r=A; [[ "$c" == A ]] && r=B
printf '%s' "${sig:0:10}$r${sig:11}" > "$TMP/flipped.sig"
"$CV" verify "$VEC/blob.dat" "$VEC/pub.raw64" "$TMP/flipped.sig" >/dev/null 2>&1 \
	&& fail "bit-flipped signature accepted"
ok "bit-flipped signature rejected"

printf '%s' "${sig:0:40}" > "$TMP/truncated.sig"
"$CV" verify "$VEC/blob.dat" "$VEC/pub.raw64" "$TMP/truncated.sig" >/dev/null 2>&1 \
	&& fail "truncated signature accepted"
ok "truncated signature rejected"

"$CV" verify "$VEC/blob.dat" "$VEC/otherpub.raw64" "$VEC/blob.sig" >/dev/null 2>&1 \
	&& fail "wrong key accepted"
ok "wrong public key rejected"

printf 'not base64 at all!!\n' > "$TMP/garbage.sig"
"$CV" verify "$VEC/blob.dat" "$VEC/pub.raw64" "$TMP/garbage.sig" >/dev/null 2>&1 \
	&& fail "garbage signature accepted"
ok "garbage signature rejected"

: > "$TMP/empty.sig"
"$CV" verify "$VEC/blob.dat" "$VEC/pub.raw64" "$TMP/empty.sig" >/dev/null 2>&1 \
	&& fail "empty signature accepted"
ok "empty signature rejected"

# Valid base64, valid DER framing, but not a signature: must die at the
# curve check, not earlier.
printf 'MAYCAQECAQE=' > "$TMP/bogus.sig"   # base64 of DER SEQ{INT 1, INT 1}
"$CV" verify "$VEC/blob.dat" "$VEC/pub.raw64" "$TMP/bogus.sig" >/dev/null 2>&1 \
	&& fail "bogus r=s=1 signature accepted"
ok "well-formed-but-bogus DER rejected"

echo "[*] tier 3: live interop with cosign $(cosign version 2>/dev/null | sed -n 's/GitVersion: *//p')"
cd "$TMP"
head -c 1048576 /dev/urandom > blob.bin
export COSIGN_PASSWORD=""
cosign generate-key-pair >/dev/null 2>&1
raw_pub cosign.pub cosign.raw
# --use-signing-config exists only on cosign >= 3.x; pass it only if supported.
scfg=()
if cosign sign-blob --help 2>&1 | grep -q -- --use-signing-config; then
	scfg=(--use-signing-config=false)
fi
for i in 1 2 3 4; do
	cosign sign-blob --key cosign.key "${scfg[@]}" \
		--tlog-upload=false --output-signature blob.sig blob.bin >/dev/null 2>&1
	"$CV" verify blob.bin cosign.raw blob.sig >/dev/null 2>&1 \
		|| fail "fresh cosign-produced sig #$i rejected"
done
ok "fresh cosign-produced signatures verify"

openssl ecparam -name prime256v1 -genkey -noout -out ec.key 2>/dev/null
openssl ec -in ec.key -pubout -out ec.pub 2>/dev/null
raw_pub ec.pub ec.raw
openssl dgst -sha256 -sign ec.key blob.bin | base64 -w0 > blob.osig
"$CV" verify blob.bin ec.raw blob.osig >/dev/null 2>&1 \
	|| fail "openssl-produced sig rejected"
cosign verify-blob --key ec.pub --signature blob.osig \
	--insecure-ignore-tlog=true blob.bin >/dev/null 2>&1 \
	|| fail "stock cosign rejected the sig our verifier accepts"
ok "contract holds both ways (cosign-verify == cosign verify-blob)"

echo
echo "[*] all $pass checks passed"
