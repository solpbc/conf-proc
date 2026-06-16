#!/usr/bin/env bash
#
# test/verifier-selftest.sh — off-hardware tests for verify.sh.
#
# The AMD-chain re-check and the quote verification need snpguest + a TPM, so
# those run only inside the container on a CVM. The parts that DON'T need
# hardware — the toy policy parser and the X25519 key-release round-trip — are
# exercised here against synthetic inputs.
#
#   ./test/verifier-selftest.sh   (needs only bash + openssl + xxd)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=../verify.sh
source "$ROOT/verify.sh"   # guarded main: sourcing only loads functions

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

pass=0; fail=0
good() { echo "  ok   - $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL - $1"; fail=$((fail+1)); }

le32() {
  local v="$1"
  printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
    $((v & 0xff)) $(((v>>8)&0xff)) $(((v>>16)&0xff)) $(((v>>24)&0xff)))"
}

# synthetic 1184-byte AMD report with a chosen guest-policy low word
make_report() {  # args: outfile, policy_lo_hex, vmpl
  local out="$1" policy_lo="$2" vmpl="$3"
  head -c 1184 /dev/zero > "$out"
  le32 3            | dd of="$out" bs=1 seek=0  conv=notrunc status=none   # version
  le32 "$policy_lo" | dd of="$out" bs=1 seek=8  conv=notrunc status=none   # guest policy (low 32)
  le32 "$vmpl"      | dd of="$out" bs=1 seek=48 conv=notrunc status=none   # vmpl
}

echo "== toy policy =="
# debug bit (19) clear -> allowed
make_report ok_report.bin $((0x00030000)) 0
if v_check_policy ok_report.bin >/dev/null 2>&1; then good "debug-disabled report passes policy"; else bad "debug-disabled should pass"; fi
# debug bit set -> denied
make_report dbg_report.bin $((0x00080000)) 0
if v_check_policy dbg_report.bin >/dev/null 2>&1; then bad "debug-enabled should be denied"; else good "debug-enabled report denied"; fi

echo
echo "== X25519 key release round-trip =="
openssl genpkey -algorithm X25519 -out guest.key 2>/dev/null
openssl pkey -in guest.key -pubout -outform DER -out guest.pub.der 2>/dev/null
head -c 32 /dev/urandom > secret.bin
v_release_key guest.pub.der secret.bin rel >/dev/null
if [[ -f rel/wrapped.bin && -f rel/verifier_pub.der ]]; then good "verifier wrapped secret to guest pubkey"; else bad "release produced no ciphertext"; fi
v_unwrap_key guest.key rel/verifier_pub.der rel/wrapped.bin recovered.bin
if cmp -s secret.bin recovered.bin; then good "guest recovered the exact secret (round-trip)"; else bad "round-trip mismatch"; fi
# a different guest key must NOT recover the secret
openssl genpkey -algorithm X25519 -out other.key 2>/dev/null
if v_unwrap_key other.key rel/verifier_pub.der rel/wrapped.bin wrong.bin 2>/dev/null && cmp -s secret.bin wrong.bin; then
  bad "wrong guest key should not recover the secret"
else
  good "wrong guest key cannot recover the secret"
fi

echo
echo "== summary: ${pass} passed, ${fail} failed =="
[[ "$fail" -eq 0 ]]
