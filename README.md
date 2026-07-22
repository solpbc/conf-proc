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

SGLang, the model weights, NVIDIA's local GPU verifier, and `snpguest` are
deployment dependencies rather than vendored source.

## Trust boundary

The gateway admits no credential or inference bytes until both attestation
phases verify. Inference and audio upstreams bind only to loopback. The engine
does not log request or response content, write owner content to durable
storage, or send content to a third-party telemetry service. The audio path
accepts only canonical PCM16 WAV, 16 kHz, mono input and rejects rather than
transcodes every other format.

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

`make ci` compiles every shipped module, checks that `ratls-contract.json`
matches the code source, and runs the CPU verifier, gateway, health, and ASR
self-tests. It does not require confidential-compute hardware or model weights.

The ASR serving environment is intentionally separate and pinned in
`requirements-asr.txt`. Any NeMo bump, change to `strict_wav.py` or
`parse_multipart`, or change to gateway relay framing requires security
re-qualification before production rollout.

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

returns `"state":"healthy"` after a real two-phase admission and both served
model identities match. A process merely listening on its port is not ready.

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
