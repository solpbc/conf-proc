# conf-proc

`conf-proc` is sol pbc's operated confidential-processing engine. It serves
the same model used by the local-default path over a two-phase RA-TLS channel
bound to fresh AMD SEV-SNP and NVIDIA confidential-GPU evidence.

The production deployment at `processing.solstone.app` runs these components:

- `ratls_gateway.py` — fail-closed TLS 1.3 admission and loopback routing
- `ratls_collector.py` — live CPU/GPU evidence collection
- `ratls_contract.py` + `ratls-contract.json` — the versioned wire-contract
  source and generated consumer artifact
- `verifier.py` + `roots/amd/` — the AMD CPU-leg appraisal reference from
  which the journal's owner-side verifier is derived
- `asr_shim.py` + `strict_wav.py` — the bounded hosted-transcription sidecar
- `spp_health.py` — content-free on-box readiness and health

SGLang, the model weights and NVIDIA's local GPU verifier are deployment
dependencies rather than vendored source. The collector takes the AMD report
from the vTPM's HCL report and checks it against the AMD roots pinned in
`roots/amd/` before returning it, fetching only the VCEK from AMD's KDS.

## Trust boundary

The gateway admits no credential or inference bytes until both attestation
phases verify. Before the first post-attestation request reaches a serving
upstream, the gateway validates its portal-issued bearer against the live SPP
binding and entitlement state. Invalid/inactive credentials fail 401;
authorizer failure fails 503; neither path opens an upstream connection. The
raw bearer is stripped before forwarding, and the gateway replaces any
client-asserted `x-sol-device` value with a SHA-256-derived opaque id. Inference
and audio upstreams bind only to loopback. The engine does not log request or
response content, write owner content to durable storage, or send content to a
third-party telemetry service. The audio path accepts only canonical PCM16
WAV, 16 kHz, mono input and rejects rather than transcodes every other format.

The engine produces the composite attestation evidence. The checked-in
`verifier.py` preserves the independently testable CPU-leg reference, but the
production owner-side appraisal and verify-before-egress decision execute in
the journal client, not on the engine.

## Development

Python 3.10 or newer is required for the gateway and hardware-free tests.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
make PYTHON=.venv/bin/python ci
```

`make ci` compiles every shipped Python module, compiles and runs the native
SPP diagnostic-trace C codec tests (ordinary and address/undefined-behavior
sanitizers), checks that `ratls-contract.json` matches the code source, and
runs the CPU verifier, gateway, health, and ASR self-tests. It does not
require confidential-compute hardware or model weights.

The ASR serving environment is intentionally separate and pinned in
`requirements-asr.txt`. Any NeMo bump, change to `strict_wav.py` or
`parse_multipart`, or change to gateway relay framing requires security
re-qualification before production rollout.

Production rebuilds install `requirements-lock.txt` and
`requirements-asr-lock.txt`, the complete environments resolved on the qualified
Ubuntu 22.04 / CPython 3.10 / CUDA 13 pool. The shorter requirement files remain
the human-maintained direct-dependency intent. Refresh a lock only from an A–H
qualified candidate and commit it with the source revision that advances the
deployment recipe.

## Sealed appliance recipe

`appliance/` holds the public recipe for the sealed confidential-processing appliance
(`python3 appliance/spp_appliance.py --help`). `--stage prod` is the image that serves; stages
`1a`, `1b` and `2h` are the earlier qualification images, kept for reference and not reproducible
(inputs they baked are no longer published).

1. **Acquire.** `appliance/acquire_boot_inputs.py --workspace DIR` fetches the kernel, driver,
   boot-tool, nftables and TLS-library inputs, each pinned by SHA-256. The serving stack's upstream
   identities (OCI digest, Hugging Face revisions, the ASR dependency closure) are recorded in the
   input manifest's `url` fields; its acquisition is not yet scripted in this repository.
2. **Verify.** The build refuses unless every input matches `--manifest` exactly: each file by
   SHA-256 and size, each directory by its full file list, symlink targets included.
3. **Build.** `python3 appliance/spp_appliance.py --stage prod --workspace DIR --manifest M
   --signer-dir SIGNER [--work OUT]` runs every step after input verification with no network
   (`bwrap --unshare-net`) and refuses a dirty checkout of this repository. It emits the build
   manifest, the verified input manifest and a generated SBOM of the assembled root.
4. **Egress.** `appliance/check_egress_ruleset.sh NFT_PACKAGE_ROOT` loads the prod egress ruleset
   with the image's own `nft` in a throwaway network namespace and checks that the content
   services send nothing beyond loopback and the gateway reaches only TCP 443.

## Deployment

The checked-in systemd units under `deploy/systemd/` describe the live service
layout. `deploy/spp-health` is the stable `/usr/local/bin/spp-health` entrypoint
and deliberately runs the checker in the pinned gateway venv; do not symlink the
Python module directly to a system interpreter. `run-collector.sh` is the narrow
bridge into the independently installed NVIDIA verifier environment. A deployment
is ready only when:

```sh
spp-health --json
```

returns `"state":"healthy"` after a real two-phase admission, a portal-backed
rejection of a fixed synthetic invalid entitlement, and independent loopback
readiness/model identity checks. No owner credential is used. A process merely
listening on its port is not ready.

The current production environment is one persistent Azure
`Standard_NCC40ads_H100_v5` confidential VM. This repository does not provision
or destroy that standing infrastructure.

## History

The engine graduated from [`solpbc/devops-lab`](https://github.com/solpbc/devops-lab)
on 2026-07-21. This repository preserves that Git ancestry, so historical
security-review pins remain independently inspectable. `devops-lab` remains the
home for the exploratory Azure CVM, ACI, and AKS work; its verifier copy remains
part of those historical lab flows, while this repo carries the production
trust-chain reference forward.

## Security

Please report vulnerabilities through the process in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 sol pbc. Licensed under the GNU Affero General Public License,
version 3 only. See [LICENSE](LICENSE).
