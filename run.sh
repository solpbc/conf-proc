#!/usr/bin/env bash
#
# solpbc demo entry point.
#
# Fetches the AMD SEV-SNP attestation report from the Azure Confidential VM's
# vTPM and decodes it. On Azure the paravisor pre-fetches the report at VMPL 0
# and stores it in the vTPM, so snpguest reads it via `--platform` (the hyperv
# build feature) rather than the absent /dev/sev-guest interface.
#
# Verifying the report against the AMD cert chain (ARK -> ASK -> VCEK) is the
# next milestone and is intentionally NOT done here yet.
#
# Run on the CVM with the raw vTPM device passed through, e.g.:
#   podman run --rm --device /dev/tpm0 --device /dev/tpmrm0 \
#     --group-add keep-groups -v "$PWD:/out" -w /out solpbc

set -euo pipefail

# Where to write artifacts. Defaults to a mounted /out volume if present,
# otherwise an ephemeral /tmp (override with OUT_DIR=...).
OUT_DIR="${OUT_DIR:-/out}"
[[ -d "$OUT_DIR" && -w "$OUT_DIR" ]] || OUT_DIR="/tmp"

REPORT="${OUT_DIR}/report.bin"
REQUEST="${OUT_DIR}/request.txt"
TPM_DEV="/dev/tpm0"

echo "== solpbc :: AMD SEV-SNP attestation demo =="

# The vTPM report path needs the raw TPM device. If it isn't here, we're not
# on a CVM (or it wasn't passed through) — explain and exit cleanly.
if [[ ! -e "$TPM_DEV" ]]; then
  cat <<EOF

No vTPM device found at ${TPM_DEV}.

This demo must run ON an Azure SEV-SNP Confidential VM with the TPM passed
through. From a checkout on the CVM:

  podman build -t solpbc .
  podman run --rm --device /dev/tpm0 --device /dev/tpmrm0 \\
    --group-add keep-groups -v "\$PWD:/out" -w /out solpbc

(See the README for provisioning the CVM and granting tss-group access to
/dev/tpm0.)
EOF
  exit 0
fi

echo
echo "[1/2] Fetching attestation report from vTPM (VMPL 0, --platform)..."
snpguest report --platform "$REPORT" "$REQUEST"
size="$(wc -c < "$REPORT" | tr -d ' ')"
echo "      wrote ${REPORT} (${size} bytes)"

echo
echo "[2/2] Decoding attestation report:"
echo
snpguest display report "$REPORT"

cat <<'EOF'

-- demo complete --
Got a genuine, AMD-signed SEV-SNP report straight from the vTPM, with no
Microsoft Azure Attestation (MAA) in the loop.

Next milestone: verify it against the AMD cert chain --
  snpguest fetch ca   ...   # ARK + ASK for this CPU (Milan)
  snpguest fetch vcek ...   # chip- and TCB-specific endorsement key
  snpguest verify certs ...
  snpguest verify attestation ...
EOF
