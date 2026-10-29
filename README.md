# conf-proc

`conf-proc` is sol pbc's operated confidential-processing engine. it serves
the same model used by the local-default path over a two-phase RA-TLS channel
bound to fresh AMD SEV-SNP and NVIDIA confidential-GPU evidence.

the sealed production recipe runs these components:

- `ratls_gateway.py`: fail-closed TLS 1.3 admission and loopback routing
- `ratls_collector.py`: live CPU/GPU evidence collection
- `ratls_contract.py` + `ratls-contract.json`: the versioned wire-contract
  source and generated consumer artifact
- `verifier.py` + `roots/amd/`: the AMD CPU-leg appraisal reference from
  which the journal's owner-side verifier is derived
- `asr_shim.py` + `strict_wav.py`: the bounded hosted-transcription sidecar
- `spp_health_push.py` + `health-push-contract.json`: independent, fixed-schema
  health reports to sol pbc's monitoring on Cloudflare
- `usage_tally.py` + `fleet_usage.py`: in-memory usage accounting and bounded
  service-wide operational figures
- `allowance.py`: allowance enforcement, disabled unless portal authorization
  supplies an allowance

SGLang, the model weights and NVIDIA's local GPU verifier are deployment
dependencies rather than vendored source. the collector takes the AMD report
from the vTPM's HCL report and checks it against the AMD roots pinned in
`roots/amd/` before returning it, fetching only the VCEK from AMD's KDS.

## trust boundary

the gateway admits no credential or inference bytes until both attestation
phases verify. before the first post-attestation request reaches a serving
upstream, the gateway validates its portal-issued bearer against the live SPP
binding and entitlement state. invalid/inactive credentials fail 401;
authorizer failure fails 503; neither path opens an upstream connection. the
raw bearer is stripped before forwarding, and the gateway replaces any
client-asserted `x-sol-device` value with a process-randomized label derived from
the portal-authorized journal binding (not stable across restart of the gateway process). inference
and audio upstreams bind only to loopback. the engine does not log request or
response content, write owner content to durable storage, or send content to a
third-party telemetry service. the audio path accepts only canonical PCM16
WAV, 16 kHz, mono input and rejects rather than transcodes every other format.

the serving stack uses that journal label to partition its prefix cache. a
caller cannot choose the label or a shared cache namespace. the partition is
enforced by software, not by separate hardware for each journal.

a separate unprivileged reporter pushes health over HTTPS without adding a
listener or waiting for admission. its schema permits fixed system, model,
GPU and collector states and bounded operational figures. it carries no
request or response content, journal or sign-in identifiers, credentials or
owner challenges. prompt and cached-prompt totals freeze at UTC midnight;
load bands cover only a closed month and suppress populations below the
in-container floor. the reporter reads only the bounded HTTP status line,
not response headers or bodies, and follows no redirects. the receiver admits
only explicitly allowed source IPs before storing a report.

the engine produces the composite attestation evidence. the checked-in
`verifier.py` preserves the independently testable CPU-leg reference, but the
production owner-side appraisal and verify-before-egress decision execute in
the journal client, not on the engine.

## development

Python 3.10 or newer is required for the gateway and hardware-free tests.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
make PYTHON=.venv/bin/python ci
```

`make ci` compiles every shipped Python module, compiles and runs the native
SPP diagnostic-trace C codec tests (ordinary and address/undefined-behavior
sanitizers), checks that `ratls-contract.json` matches the code source, and
runs the CPU verifier, gateway, health, and ASR self-tests. it does not
require confidential-compute hardware or model weights.

the ASR serving environment is intentionally separate and pinned in
`requirements-asr.txt`. any NeMo bump, change to `strict_wav.py` or
`parse_multipart`, or change to gateway relay framing requires security
re-qualification before production rollout.

production rebuilds install `requirements-lock.txt` and
`requirements-asr-lock.txt`, the complete environments resolved on the qualified
Ubuntu 22.04 / CPython 3.10 / CUDA 13 pool. the shorter requirement files remain
the human-maintained direct-dependency intent. refresh a lock only from a
qualified candidate and commit it with the source revision that advances the
deployment recipe.

## sealed appliance recipe

`appliance/` holds the public recipe for the sealed confidential-processing appliance
(`python3 appliance/spp_appliance.py --help`). `--stage prod` is the image that serves; stages
`1a`, `1b` and `2h` are the earlier qualification images, kept for reference and not reproducible
(inputs they baked are no longer published).

1. **acquire.** follow the [input acquisition and build instructions](appliance/BUILD.md).
   the scripts fetch the serving stack, models, kernel, driver and build inputs by pinned identities.
2. **verify.** the build refuses unless every input matches `--manifest` exactly: each file by
   SHA-256 and size, each directory by its full file list, symlink targets included.
3. **build.** `appliance/toolchain.py` assembles the pinned Debian-package toolchain root and
   runs the recipe inside it without network access. the recipe refuses a dirty checkout.
   it emits the build
   manifest, the verified input manifest and a generated SBOM of the assembled root.
4. **egress.** `appliance/check_egress_ruleset.sh NFT_PACKAGE_ROOT` loads the prod egress ruleset
   with the image's own `nft` in a throwaway network namespace and checks that the content
   services cannot initiate traffic beyond loopback or reach the gateway's
   loopback listeners. the gateway and health reporter can initiate HTTPS
   traffic on TCP 443; their code fixes the permitted endpoints.

## deployment

the sealed recipe generates its own systemd units inside the measured root.
it exposes the attested gateway on TCP 9443 and has no operator shell or guest
agent. qualification checks attestation, serving, reboot-stable measurements
and the pushed health report. a listening port alone does not establish
readiness.

`deploy/systemd/`, `deploy/spp-health` and the on-box `spp_health.py` checker
remain tools for the earlier unsealed deployment layout. they are not an
operator path into the sealed image. `run-collector.sh` bridges the gateway to
the NVIDIA verifier environment included by the recipe.

the current production environment is one persistent Azure
`Standard_NCC40ads_H100_v5` confidential VM. this repository does not provision
or destroy that standing infrastructure.

## history

[confidential processing: image #5](RELEASE-NOTES.md)

the engine graduated from [`solpbc/devops-lab`](https://github.com/solpbc/devops-lab)
on 2026-07-21. this repository preserves that Git ancestry, so historical
security-review pins remain independently inspectable. `devops-lab` remains the
home for the exploratory Azure CVM, ACI, and AKS work; its verifier copy remains
part of those historical lab flows, while this repo carries the production
trust-chain reference forward.

## security

please report vulnerabilities through the process in [SECURITY.md](SECURITY.md).

## license

copyright 2026 sol pbc. licensed under the GNU Affero General Public License,
version 3 only. see [LICENSE](LICENSE).
