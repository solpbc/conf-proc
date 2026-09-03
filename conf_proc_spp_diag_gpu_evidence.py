#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fixed local GPU-evidence helper: source for the staged spp-diag-gpu-evidence.py.

Invocation is fixed and caller-declared-flag-free: python3.10 -I -B -S
spp-diag-gpu-evidence.py <32-byte-hex-nonce>. Spawns the fixed native
/usr/local/libexec/solstone/spp-diag-cuda-driver child, builds a seven-field TLV
evidence record, and derives output_oracle_address / gpu_witness_policy_address via
the shared domain-address protocol (conf_proc_spp_diagbundle_protocol). Imports only
that shared protocol module and conf_proc_json -- both staged alongside this file for
its isolated `-I -B -S` import root -- and never any production-appraiser module.
"""

from __future__ import annotations

import hashlib
import struct
import subprocess
import sys
from typing import Final

from conf_proc_spp_diagbundle_protocol import domain_address


CUDA_DRIVER_PATH: Final = "/usr/local/libexec/solstone/spp-diag-cuda-driver"

DOMAIN_OUTPUT_ORACLE: Final = b"sol-spp-diag-output-oracle-v1\x00"
DOMAIN_GPU_WITNESS_POLICY: Final = b"sol-spp-diag-gpu-witness-policy-v1\x00"
DOMAIN_GPU_NONCE: Final = b"sol-spp-diag-gpu-nonce-v1\x00"

TLV_SCHEMA: Final = b"SPPGPU1\x00"
_WITNESS_MODULE_TEXT: Final = (
    b".version 8.0\n.target spp_diag_witness_v1\n.address_size 64\n"
    b".visible .entry spp_diag_witness(.param .u64 in, .param .u64 out) { ret; }\n"
)
WITNESS_MODULE_SHA256: Final = hashlib.sha256(_WITNESS_MODULE_TEXT).digest()
WITNESS_FUNCTION_SHA256: Final = hashlib.sha256(b"spp_diag_witness").digest()
WITNESS_GEOMETRY: Final = struct.pack(">HHI", 1, 32, 0)  # grid_x, block_x, reserved


class GpuEvidenceError(RuntimeError):
    pass


def _tlv_field(type_id: int, value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise GpuEvidenceError("TLV field too large")
    return bytes([type_id]) + struct.pack(">H", len(value)) + value


def build_tlv(nonce: bytes, driver_result: int, witness_output: bytes) -> bytes:
    if len(nonce) != 32 or len(witness_output) != 32:
        raise GpuEvidenceError("nonce/witness_output must each be 32 bytes")
    return b"".join(
        [
            _tlv_field(1, TLV_SCHEMA),
            _tlv_field(2, nonce),
            _tlv_field(3, WITNESS_MODULE_SHA256),
            _tlv_field(4, WITNESS_FUNCTION_SHA256),
            _tlv_field(5, WITNESS_GEOMETRY),
            _tlv_field(6, struct.pack(">I", driver_result)),
            _tlv_field(7, witness_output),
        ]
    )


def output_oracle_address(*, model_path_hex: str, model_sha256: str, nonce: bytes, witness_output: bytes) -> str:
    return domain_address(
        DOMAIN_OUTPUT_ORACLE,
        {
            "model_path_hex": model_path_hex,
            "model_sha256": model_sha256,
            "nonce": nonce.hex(),
            "witness_output": witness_output.hex(),
        },
    )


def gpu_witness_policy_address(*, challenge: bytes, run_identity: bytes, control_plan_address: bytes) -> str:
    return domain_address(
        DOMAIN_GPU_WITNESS_POLICY,
        {
            "challenge": challenge.hex(),
            "run_identity": run_identity.hex(),
            "control_plan_address": control_plan_address.hex(),
        },
    )


def derive_gpu_nonce(
    *, challenge: bytes, run_identity: bytes, image_binding_address: str, control_plan_address: str, output_oracle_address_hex: str
) -> bytes:
    """Domain-separated 32-byte nonce binding a run's identity/image/plan/oracle before the GPU child runs."""

    preimage = DOMAIN_GPU_NONCE + challenge + run_identity + bytes.fromhex(image_binding_address) + bytes.fromhex(
        control_plan_address
    ) + bytes.fromhex(output_oracle_address_hex)
    return hashlib.sha256(preimage).digest()


def run_cuda_driver(nonce_hex: str, *, driver_path: str = CUDA_DRIVER_PATH) -> tuple[int, bytes]:
    result = subprocess.run([driver_path, nonce_hex], capture_output=True, timeout=10)
    output = b""
    if result.returncode == 0:
        stdout_text = result.stdout.decode("ascii").strip()
        if len(stdout_text) != 64:
            raise GpuEvidenceError("cuda driver produced malformed witness output")
        output = bytes.fromhex(stdout_text)
    return result.returncode, output


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: spp-diag-gpu-evidence.py <32-byte-hex-nonce>\n")
        return 2
    nonce_hex = argv[1]
    try:
        nonce = bytes.fromhex(nonce_hex)
    except ValueError:
        sys.stderr.write("spp-diag-gpu-evidence: malformed nonce\n")
        return 2
    if len(nonce) != 32:
        sys.stderr.write("spp-diag-gpu-evidence: nonce must be 32 bytes\n")
        return 2
    driver_result, witness_output = run_cuda_driver(nonce_hex)
    if driver_result != 0 or len(witness_output) != 32:
        sys.stderr.write("spp-diag-gpu-evidence: cuda driver failed\n")
        return 3
    tlv = build_tlv(nonce, driver_result, witness_output)
    sys.stdout.write(tlv.hex() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
