# Off-CVM Python verifier

`verifier.py` is the first owner-side verifier spike for the Azure SEV-SNP
bundle emitted by `run.sh`. It runs off the CVM, owns the challenge nonce, uses
local pinned AMD CA roots from `roots/amd/`, appraises the file bundle, and
releases a secret to the guest X25519 public key only after every check passes.

## Bundle contract

The verifier consumes the same file bundle the current attester writes under
`OUT_DIR` / `/out`:

- `hcl_report.bin` — Azure HCLA blob containing the AMD report and runtime JSON.
- `certs/vcek.pem` — chip/TCB VCEK certificate. Bundled `ark.pem` / `ask.pem`
  are optional, but if present they must byte-match the pinned roots.
- `akpub.pem` — vTPM AK public key.
- `guest_x25519.pub.der` — guest ephemeral X25519 public key.
- `nonce.hex` — nonce issued by the verifier.
- `quote.msg`, `quote.sig`, `quote.pcrs` — AK quote artifacts.

## Commands

Issue a verifier nonce:

```bash
./verifier.py challenge /path/to/bundle
```

After the CVM attester binds that nonce and writes the bundle, appraise it:

```bash
./verifier.py appraise /path/to/bundle \
  --roots roots/amd \
  --release-secret journal-key.bin \
  --release-out /path/to/bundle/release-py
```

If `--release-secret` is omitted, the verifier releases a random 32-byte test
secret. For local demo proof only, a bundle that still contains the guest private
key can unwrap the AEAD release:

```bash
./verifier.py unwrap-for-test /path/to/bundle/release-py/release.json \
  /path/to/bundle/guest_x25519.key recovered-key.bin
```

## Checks

The verifier currently gates:

- HCLA header: signature `HCLA`, version 1 or 2, `request_type == 2`.
- AMD report signature: VCEK signs bytes `0..0x29f` with ECDSA P-384/SHA-384.
- AMD certificate chain: VCEK chains to local pinned ASK/ARK. No AMD or Azure
  network fetch occurs during verification.
- Runtime binding: `report_data[0..32] == SHA-256(runtime JSON)` and the
  trailing `report_data[32..64]` bytes are zero.
- TCB/security policy: report version, VMPL, debug bit, and optional per-field
  TCB floors loaded from JSON.
- AK binding: bundle `akpub.pem` RSA modulus matches runtime `HCLAkPub`.
- Freshness/key target: `tpm2_checkquote` must verify the AK quote with
  `extraData == SHA-256(domain || verifier nonce || guest pubkey || ctx)`.
- PCR policy: record-then-pin v1 by default, or explicit pin match.
- Key release: X25519 ECDH -> HKDF-SHA256 -> AES-256-GCM release JSON.

## Policy JSON

The default policy is intentionally narrow but portable across the observed
DC2as_v5 and DC2as_v6 data shapes. Earlier captures used AMD report version 3;
the live DC2as_v5 replay on 2026-06-18 returned report version 5, with the same
structural offsets used by this verifier.

```json
{
  "allowed_report_versions": [3, 5],
  "allowed_hcla_versions": [1, 2],
  "allowed_vmpl": [0],
  "require_debug_disabled": true,
  "min_tcb": {
    "reported": {"boot_loader": 4, "snp": 23}
  },
  "pcr_policy": {
    "mode": "pin",
    "pins": ["<sha256 of quote.pcrs>"]
  }
}
```

`min_tcb` labels can be `current`, `reported`, `committed`, or `launch`.
Recognized fields are `boot_loader`, `tee`, `snp`, `microcode`, and `fmc`
(`fmc` exists only on Turin-style TCB layouts).

## Reference-values gap

PCR policy is deliberately v1:

- `record` mode accepts the bundle and prints the `SHA-256(quote.pcrs)`
  fingerprint to pin later.
- `pin` mode accepts only an explicit fingerprint in policy JSON.

This does **not** solve the reference-values problem. The open production
question is which HCL/UEFI/vTPM/PCR measurements are acceptable for each
substrate. The v5/v6 validation showed measurements, TCB values, and HCL version
are per-substrate, so the pin ledger must be per-substrate. That ledger and its
transparency process belong to the follow-on pin-transparency workstream.
