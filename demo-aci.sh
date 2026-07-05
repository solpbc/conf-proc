#!/usr/bin/env bash
#
# demo-aci.sh — the whole solpbc story in a single ACI container run.
#
# The ACI counterpart of demo.sh, and the default entrypoint of
# Containerfile.aci. Same three roles, same toy arrangement — verifier and
# attester share the container so the demo is self-contained, and the whole
# staged story lands in `az container logs`:
#   STAGE 1  [verifier] takes the challenge nonce (the NONCE_HEX deployment
#            parameter if supplied — i.e. an outside verifier's nonce — else
#            a locally generated one)
#   STAGE 2  [attester] binds the nonce into REPORT_DATA via /dev/sev-guest
#            (raw path: no vTPM, no HCL — the UVM runs unparavisored at VMPL0)
#   STAGE 3  [verifier] fetches the VCEK from AMD KDS (certs are NOT
#            available in-TEE on ACI) and appraises: chain -> report
#            signature -> freshness -> policy
#
# Provisioning (az/podman: ACR, CCE policy, deployment) happens OUTSIDE the
# container — see the README's "Running on ACI Confidential Containers".
#
# NOTE: as in demo.sh, the verifier here runs in the same TEE as the attester
# purely so the demo is self-contained; a real verifier runs owner-side
# (verifier.py appraise-raw on your own machine, per the README).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OUT_DIR="${OUT_DIR:-/tmp/demo}"
mkdir -p "$OUT_DIR"

cat <<'BANNER'
#####################################################################
#  solpbc — end-to-end ACI Confidential Containers attestation demo
#
#    [verifier] take nonce
#        -> [attester] bind nonce into a raw SNP report (/dev/sev-guest)
#            -> [verifier] AMD KDS cert chain + freshness + policy
#
#  AMD silicon is the only root of trust. No MAA, no vTPM, no HCL.
#####################################################################
BANNER

if [[ ! -e /dev/sev-guest ]]; then
  cat <<'EOF'

No /dev/sev-guest. This demo must run INSIDE an ACI confidential container
group (sku Confidential) — see the README's "Running on ACI Confidential
Containers" for the build/policy/deploy steps.

To exercise the raw-report verifier logic off-hardware (no TEE needed), run
the self-test instead:

  ./test/python-verifier-selftest.py
EOF
  exit 0
fi

echo
echo "============================================================"
echo " STAGE 1/3 — [verifier] take the challenge nonce"
echo "============================================================"
if [[ -n "${NONCE_HEX:-}" ]]; then
  NONCE="$NONCE_HEX"
  echo "using deployment-supplied verifier nonce (nonceHex parameter)"
else
  NONCE="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  echo "no NONCE_HEX in environment; generated a local nonce"
fi
echo "nonce: $NONCE"

echo
echo "============================================================"
echo " STAGE 2/3 — [attester] bind the nonce, produce the raw report"
echo "============================================================"
python3 "${SCRIPT_DIR}/fetch-report.py" --nonce-hex "$NONCE" --out "$OUT_DIR/report.bin"

echo
echo "============================================================"
echo " STAGE 3/3 — [verifier] fetch VCEK + appraise the evidence"
echo "============================================================"
python3 "${SCRIPT_DIR}/verifier.py" fetch-vcek "$OUT_DIR" || {
  echo "AMD KDS fetch failed; trying Microsoft's acccache mirror (same AMD-signed certs)"
  python3 "${SCRIPT_DIR}/verifier.py" fetch-vcek "$OUT_DIR" --source acccache
}
python3 "${SCRIPT_DIR}/verifier.py" appraise-raw "$OUT_DIR" \
  --roots "${SCRIPT_DIR}/roots/amd" --nonce-hex "$NONCE"

cat <<'EOF'

[TOY GAP] the verifier above ran inside the TEE it was verifying, and
[TOY GAP] HOST_DATA was recorded, not checked — this container cannot know
[TOY GAP] its own expected policy hash. The real verifier runs owner-side:
[TOY GAP] grab the report base64 from these logs (or redeploy with your own
[TOY GAP] nonceHex) and run verifier.py appraise-raw with --cce-policy-file
[TOY GAP] from your template, per the README.

#####################################################################
#  demo complete: raw SNP report, nonce-fresh, AMD-rooted, appraised
#  in-container — with no MAA anywhere in the path.
#####################################################################
EOF
