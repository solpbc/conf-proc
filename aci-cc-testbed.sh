#!/usr/bin/env bash
# aci-cc-testbed.sh — Layer-1 attestation-shape probe on ACI Confidential
# Containers (GA), replacing the sunset AKS kata-cc path (see journal/2026-07-04).
#
# Question under test: can a tenant verify a policy-bound SEV-SNP child report
# AMD-rooted, with no MAA in the loop? Checks: raw /dev/sev(-guest) vs HCL/vTPM
# mediation, HOST_DATA == CCE policy hash, CHIP_ID real vs zeroed, THIM vs AMD KDS
# for the VCEK chain, then verifier.py appraisal.
#
# Run sections interactively; don't blind-execute.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE_SRC="$DIR/arm/aci-snp-probe.json"

RG=solpbc-acicc-rg
LOC=eastus            # confidential ACI is GA in most major regions

# ---------------------------------------------------------------- 0. setup
az extension add --upgrade --name confcom

# work on a copy: acipolicygen writes the policy into the template in place,
# and the policy is CLI-generated only (manual policies unsupported):
TEMPLATE=/tmp/aci-snp-probe.deploy.json
cp "$TEMPLATE_SRC" "$TEMPLATE"

# generate a *debug* CCE policy (allows exec — test only) and inject it:
az confcom acipolicygen -a "$TEMPLATE" --debug-mode

# record the expected HOST_DATA value (sha256 of the decoded policy):
python3 - "$TEMPLATE" <<'EOF'
import base64, hashlib, json, sys
t = json.load(open(sys.argv[1]))
pol = t["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"]
print("expected HOST_DATA:", hashlib.sha256(base64.b64decode(pol)).hexdigest())
EOF

# ---------------------------------------------------------------- 1. deploy
az group create -n "$RG" -l "$LOC"
az deployment group create -g "$RG" --template-file "$TEMPLATE"
az container show -g "$RG" -n snp-probe --query 'instanceView.state' -o tsv

# ---------------------------------------------------------------- 2. probe
az container exec -g "$RG" -n snp-probe --container-name probe \
  --exec-command "/bin/bash"
# --- inside the TEE, the decisive checks: ---
#   ls -l /dev/sev /dev/sev-guest /dev/tpm0 /dev/tpmrm0    # raw vs vTPM path?
#   dmesg | grep -i -e sev -e snp -e hcl -e tpm 2>/dev/null || cat /proc/version
#   apt-get update && apt-get install -y curl jq
#   # THIM: VCEK chain without touching AMD KDS or any MS auth endpoint?
#   curl -s -H Metadata:true \
#     http://169.254.169.254/metadata/THIM/amd/certification | head -c 400
#   # fetch a raw SNP report via the guest device (snpguest, or the sev-guest
#   # ioctl; older UVM kernels expose SEV_SNP_GUEST_MSG_REPORT on /dev/sev):
#   #   - REPORT_DATA: bind a fresh nonce
#   #   - HOST_DATA: must equal the sha256 printed in step 0
#   #   - CHIP_ID / TCB: real values? does AMD KDS accept them for VCEK fetch?
#   # then run verifier.py against report + VCEK chain — no MAA anywhere.
#
# NOTE: the microsoft/confidential-sidecar-containers SKR sidecar can also emit
# the raw report over a localhost REST API — useful later for the bridge design,
# unnecessary for this probe.

# ---------------------------------------------------------------- 3. teardown
# az group delete -n "$RG" --yes --no-wait
