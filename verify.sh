#!/usr/bin/env bash
#
# verify.sh — a TOY, in-container verifier for the solpbc evidence bundle.
#
# This is a teaching aid, NOT the real thing. A production verifier runs on
# customer-controlled hardware that is NOT the CVM being attested, pins the AMD
# roots offline, owns the nonce, and never sees the guest private key. This
# script runs inside the same container as the attester and even unwraps the
# released key locally to prove the round-trip — purely so the whole flow is
# visible in one place. The point is to show the *verifier's role* and which
# checks it independently re-runs, with run.sh kept as the attester.
#
# Bundle (produced by run.sh into OUT_DIR / -v $PWD:/out):
#   hcl_report.bin            full HCLA blob
#   report.bin                AMD SEV-SNP report (also embedded in the blob)
#   certs/{ark,ask,vcek}.pem  AMD cert chain (verifier re-checks to pinned roots)
#   akpub.pem                 vTPM AK public key (NOT trusted as a root)
#   guest_x25519.pub.der      guest ephemeral public key (key-release target)
#   nonce.hex                 the nonce the verifier issued
#   quote.{msg,sig,pcrs}      AK-signed TPM quote
#
# Usage:
#   verify.sh challenge [bundle_dir]   # issue a fresh nonce into the bundle
#   verify.sh appraise  [bundle_dir]   # re-verify everything + toy key release
#
# Env knobs mirror run.sh: BINDING_DOMAIN, CTX_FILE, PCR list comes from the
# quote itself. PINNED_ARK_SHA256 pins the AMD root (else trust-on-first-use,
# clearly flagged).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/hcl.sh
source "${SCRIPT_DIR}/lib/hcl.sh"

BINDING_DOMAIN="${BINDING_DOMAIN:-sol-key-release-v1}"
CTX_FILE="${CTX_FILE:-}"
KDF_LABEL="sol-key-release-kdf-v1"

# SNP report field offsets (bytes) used by the toy policy.
SNP_OFF_VERSION=0
SNP_OFF_POLICY=8     # 8-byte guest policy; DEBUG is bit 19
SNP_OFF_VMPL=48
SNP_POLICY_DEBUG_BIT=19

# pretty output
_pass=0; _fail=0
say()  { printf '%s\n' "$*"; }
ok()   { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; _pass=$((_pass+1)); }
no()   { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*" >&2; _fail=$((_fail+1)); }
note() { printf '  ----  %s\n' "$*"; }

# --- verifier issues a fresh nonce ------------------------------------------

v_challenge() {
  local bundle="$1"
  mkdir -p "$bundle"
  local nonce; nonce="$(openssl rand -hex 32)"
  printf '%s\n' "$nonce" > "${bundle}/nonce.hex"
  say "Issued nonce -> ${bundle}/nonce.hex"
  say "$nonce"
  # In the orchestrated demo the next stages run automatically; only print the
  # manual follow-up when invoked standalone.
  if [[ -z "${DEMO:-}" ]]; then
    say
    say "Now have the attester bind it, e.g.:"
    say "  NONCE_HEX=${nonce} ./run.sh"
    say "then: ./verify.sh appraise ${bundle}"
  fi
}

# --- individual checks (sourceable for tests) -------------------------------

# Toy policy over the AMD report. Args: report file. Returns non-zero on deny.
v_check_policy() {
  local report="$1" policy_lo vmpl version debug
  version=$(_le32 "$report" "$SNP_OFF_VERSION")
  policy_lo=$(_le32 "$report" "$SNP_OFF_POLICY")  # low 32 bits hold the DEBUG bit
  vmpl=$(_le32 "$report" "$SNP_OFF_VMPL")
  debug=$(( (policy_lo >> SNP_POLICY_DEBUG_BIT) & 1 ))
  note "report version=${version} vmpl=${vmpl} guest_policy_lo=$(printf '0x%08x' "$policy_lo")"
  if [[ "$debug" -ne 0 ]]; then
    no "SNP guest policy allows DEBUG — refusing to release"
    return 1
  fi
  ok "SNP debug disabled (policy DEBUG bit clear)"
  # VMPL 0 is the paravisor-fetched report on Azure; surface it, don't gate.
  note "VMPL=${vmpl} (informational; Azure HCLA report is VMPL 0)"
  return 0
}

# Toy key release: wrap SECRET to the guest's X25519 pubkey.
# Args: guest_pubkey_der, secret_file, out_dir. Writes out_dir/{verifier_pub.der,wrapped.bin}.
v_release_key() {
  local guest_pub_der="$1" secret="$2" out="$3"
  mkdir -p "$out"
  local vkey="${out}/verifier_eph.key" vpub="${out}/verifier_pub.der"
  local gpem="${out}/guest_pub.pem" shared="${out}/shared.bin"
  openssl genpkey -algorithm X25519 -out "$vkey" 2>/dev/null
  openssl pkey -in "$vkey" -pubout -outform DER -out "$vpub" 2>/dev/null
  openssl pkey -pubin -inform DER -in "$guest_pub_der" -out "$gpem" 2>/dev/null
  openssl pkeyutl -derive -inkey "$vkey" -peerkey "$gpem" -out "$shared"
  # toy KDF: SHA-256(shared || label) -> 32-byte key; IV from a second hash.
  local key iv
  key=$( { cat "$shared"; printf '%s' "$KDF_LABEL"; } | openssl dgst -sha256 -binary | xxd -p -c32 | tr -d '\n')
  iv=$( { cat "$shared"; printf '%s' "${KDF_LABEL}:iv"; } | openssl dgst -sha256 -binary | head -c16 | xxd -p -c16 | tr -d '\n')
  openssl enc -aes-256-ctr -K "$key" -iv "$iv" -in "$secret" -out "${out}/wrapped.bin"
  rm -f "$shared" "$gpem"
  printf '%s' "$key"   # return the symmetric key (for the round-trip check)
}

# Guest-side unwrap (TOY: proves the round-trip; the real guest does this in
# confidential memory and the verifier never holds the guest private key).
# Args: guest_priv_key, verifier_pub_der, wrapped_file, out_plaintext.
v_unwrap_key() {
  local guest_key="$1" verifier_pub_der="$2" wrapped="$3" out="$4"
  local tmp; tmp="$(mktemp -d)"
  openssl pkey -pubin -inform DER -in "$verifier_pub_der" -out "${tmp}/v.pem" 2>/dev/null
  openssl pkeyutl -derive -inkey "$guest_key" -peerkey "${tmp}/v.pem" -out "${tmp}/shared.bin"
  local key iv
  key=$( { cat "${tmp}/shared.bin"; printf '%s' "$KDF_LABEL"; } | openssl dgst -sha256 -binary | xxd -p -c32 | tr -d '\n')
  iv=$( { cat "${tmp}/shared.bin"; printf '%s' "${KDF_LABEL}:iv"; } | openssl dgst -sha256 -binary | head -c16 | xxd -p -c16 | tr -d '\n')
  openssl enc -d -aes-256-ctr -K "$key" -iv "$iv" -in "$wrapped" -out "$out"
  rm -rf "$tmp"
}

# --- full appraisal ----------------------------------------------------------

v_appraise() {
  local bundle="$1"
  local hcl="${bundle}/hcl_report.bin"
  local report="${bundle}/report.bin"
  local certs="${bundle}/certs"
  local akpub="${bundle}/akpub.pem"
  local guest_pub="${bundle}/guest_x25519.pub.der"
  local nonce_file="${bundle}/nonce.hex"
  local qmsg="${bundle}/quote.msg" qsig="${bundle}/quote.sig" qpcrs="${bundle}/quote.pcrs"
  local work; work="$(mktemp -d)"
  # clean up on return and clear the trap so it doesn't re-fire for the caller
  trap 'rm -rf "${work:-}" 2>/dev/null; trap - RETURN' RETURN

  say "== solpbc toy verifier :: appraising ${bundle} =="
  say

  # 0. presence
  local missing=0 f
  for f in "$hcl" "$akpub" "$guest_pub" "$nonce_file" "$qmsg" "$qsig" "$qpcrs"; do
    [[ -f "$f" ]] || { no "missing bundle file: $f"; missing=1; }
  done
  if [[ "$missing" -ne 0 ]]; then
    no "incomplete bundle — run ./run.sh on the CVM first (writes to OUT_DIR/-v \$PWD:/out)"
    return 1
  fi
  # derive the AMD report from the blob if the standalone copy is absent
  [[ -f "$report" ]] || { hcl_amd_report "$hcl" > "${work}/report.bin"; report="${work}/report.bin"; }

  # 1. HCLA header + runtime data
  if hcl_verify_header "$hcl" >/dev/null; then ok "HCLA header well-formed ($(hcl_verify_header "$hcl"))"; else no "HCLA header"; fi
  hcl_runtime_json "$hcl" > "${work}/runtime.json" \
    && ok "extracted HCL runtime data ($(wc -c < "${work}/runtime.json") bytes)" \
    || no "could not extract runtime data"

  # 2. AMD chain to (ideally pinned) roots
  if command -v snpguest >/dev/null 2>&1 && [[ -d "$certs" ]]; then
    if snpguest verify certs "$certs" >/dev/null 2>&1; then ok "AMD cert chain verifies (ARK -> ASK -> VCEK)"; else no "AMD cert chain"; fi
    if snpguest verify attestation "$certs" "$report" >/dev/null 2>&1; then ok "AMD report signature valid (VCEK)"; else no "AMD report signature"; fi
    if [[ -n "${PINNED_ARK_SHA256:-}" && -f "${certs}/ark.pem" ]]; then
      local fp; fp=$(openssl x509 -in "${certs}/ark.pem" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')
      if [[ "$fp" == "$(printf '%s' "$PINNED_ARK_SHA256" | tr 'A-F' 'a-f' | tr -d ':')" ]]; then ok "ARK matches pinned root"; else no "ARK does NOT match PINNED_ARK_SHA256"; fi
    else
      note "ARK not pinned (set PINNED_ARK_SHA256 to enforce) — trusting fetched root [TOY GAP]"
    fi
  else
    note "snpguest/certs unavailable — skipping AMD-chain re-check (run inside the container) [TOY GAP]"
  fi

  # 3. report_data == H(runtime data)
  if hcl_verify_runtime_binding "$report" "${work}/runtime.json" >/dev/null; then
    ok "runtime-data binding: report_data == H(runtime data)"
  else no "runtime-data binding"; fi

  # 4. live AK is the AMD-bound HCLAkPub
  if hcl_verify_ak_binding "${work}/runtime.json" "$akpub" >/dev/null; then
    ok "AK binding: vTPM AK == AMD-bound HCLAkPub"
  else no "AK binding"; fi

  # 5. freshness: recompute the binding from OUR nonce + the guest key, then
  #    verify the quote under the AK (extraData must equal the binding).
  local nonce binding
  nonce="$(tr -d '[:space:]' < "$nonce_file")"
  binding="$(hcl_binding_hash "$BINDING_DOMAIN" "$nonce" "$guest_pub" "$CTX_FILE")"
  note "recomputed qualifying data = ${binding}"
  if command -v tpm2_checkquote >/dev/null 2>&1; then
    if tpm2_checkquote -u "$akpub" -m "$qmsg" -s "$qsig" -f "$qpcrs" -g sha256 -q "$binding" >/dev/null 2>&1; then
      ok "quote valid under AK AND extraData == binding (fresh + guest-bound)"
    else
      no "quote verification / freshness binding"
    fi
  else
    note "tpm2_checkquote unavailable — skipping quote signature check [run in container]"
  fi

  # 6. toy policy
  v_check_policy "$report" || true
  note "measured-boot PCR fingerprint = $(openssl dgst -sha256 "$qpcrs" | sed 's/.*= *//')  [record-then-pin; no MS reference values]"

  say
  if [[ "$_fail" -ne 0 ]]; then
    no "APPRAISAL FAILED (${_fail} failing checks) — NOT releasing the key"
    return 1
  fi
  ok "ALL CHECKS PASSED"

  # 7. toy key release + local round-trip proof
  say
  say "-- releasing secret to the guest public key --"
  head -c 32 /dev/urandom > "${work}/luks.key"          # stand-in for a LUKS key
  v_release_key "$guest_pub" "${work}/luks.key" "${bundle}/release" >/dev/null
  note "wrapped secret -> ${bundle}/release/wrapped.bin (+ verifier_pub.der)"
  if [[ -f "${bundle}/guest_x25519.key" ]]; then
    v_unwrap_key "${bundle}/guest_x25519.key" "${bundle}/release/verifier_pub.der" \
                 "${bundle}/release/wrapped.bin" "${work}/unwrapped.key"
    if cmp -s "${work}/luks.key" "${work}/unwrapped.key"; then
      ok "guest unwrapped the released key (round-trip verified) [TOY: real guest does this in CVM memory]"
    else
      no "key-release round-trip mismatch"
    fi
  else
    note "guest private key not in bundle — skipping local unwrap (as a real verifier would)"
  fi
  return 0
}

# --- main --------------------------------------------------------------------

_main() {
  local cmd="${1:-help}"
  local bundle="${2:-${OUT_DIR:-/out}}"
  [[ -d "$bundle" || "$cmd" == "challenge" ]] || bundle="${2:-.}"
  case "$cmd" in
    challenge) v_challenge "$bundle" ;;
    appraise)  v_appraise  "$bundle" ;;
    help|-h|--help)
      sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
    *) echo "unknown command '$cmd' (use: challenge | appraise | help)" >&2; exit 2 ;;
  esac
}

# Only run main when executed directly (so tests can source the functions).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  _main "$@"
fi
