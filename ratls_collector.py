#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Live CVM evidence collector for ``ratls_gateway.py``.

Reads one gateway collector request from stdin and writes one JSON response to
stdout.  It must run inside the Azure H100 CVM with the vTPM, ``tpm2-tools``,
``nvidia-smi``, and NVIDIA's local GPU verifier.  Set
``SPP_NVIDIA_VERIFIER_SRC`` to the directory containing that ``verifier``
Python package.  The AMD report is the one the vTPM's HCL report embeds, and
its ARK/ASK are this repository's pinned roots; only the VCEK is fetched.

Diagnostics go to stderr.  Evidence goes only to the gateway over stdout and
is held in an ephemeral temporary directory.
"""

from __future__ import annotations

import base64
import contextlib
import functools
import hashlib
import importlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from ratls_contract import (
    CERTIFICATE_BINDING_DOMAIN,
    EXPORTER_BINDING_DOMAIN,
    OWNER_NONCE_BYTES,
)


GPU_ENVELOPE_MAGIC = b"SPPGPU1\x00"
AK_HANDLE = os.environ.get("SPP_AK_HANDLE", "0x81000003")
HCL_NV_INDEX = os.environ.get("SPP_HCL_NV_INDEX", "0x01400001")
PCR_LIST = os.environ.get("SPP_PCR_LIST", "sha256:0,2,4,7,8,9,15,16,22,23")
COMMAND_TIMEOUT = int(os.environ.get("SPP_COLLECT_COMMAND_TIMEOUT", "120"))
# AMD KDS rate-limits aggressively (HTTP 429); the VCEK is per-chip/TCB-stable,
# so fetch once and reuse. Verification still runs on every collection; a stale
# cached VCEK (TCB bump) falls back to one refetch.
VCEK_CACHE_DIR = os.environ.get("SPP_VCEK_CACHE_DIR", "/var/tmp/spp-vcek-cache")
AMD_ROOTS_DIR = Path(__file__).resolve().parent / "roots" / "amd"


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be base64 text")
    return base64.b64decode(value, validate=True)


def _run(*command: str) -> bytes:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=COMMAND_TIMEOUT,
        check=False,
    )
    if completed.returncode != 0:
        cause = completed.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"{' '.join(command)} failed ({completed.returncode}): {cause}")
    return completed.stdout


def _require_cc_production() -> None:
    state = _run("nvidia-smi", "conf-compute", "-f").decode("utf-8", "replace")
    environment = _run("nvidia-smi", "conf-compute", "-e").decode(
        "utf-8", "replace"
    )
    if "CC status: ON" not in state or "CC Environment: PRODUCTION" not in environment:
        raise RuntimeError("GPU is not in CC ON / PRODUCTION mode")


def _vendor_import() -> tuple[Any, Any]:
    vendor_src = os.environ.get("SPP_NVIDIA_VERIFIER_SRC")
    if not vendor_src:
        raise RuntimeError("SPP_NVIDIA_VERIFIER_SRC is required")
    # The vendor tree ships `verifier/` WITHOUT __init__.py (namespace-style),
    # so a regular module named verifier.py later on sys.path — this repo's
    # own off-CVM verifier.py next to this script — would win the import
    # scan. Drop the script directory from the path (ratls_contract is
    # already imported) and purge any shadow before importing.
    script_dir = str(Path(__file__).resolve().parent)
    sys.path = [
        entry for entry in sys.path
        if os.path.abspath(entry or os.getcwd()) != script_dir
    ]
    sys.path.insert(0, vendor_src)
    for name in [m for m in sys.modules if m == "verifier" or m.startswith("verifier.")]:
        del sys.modules[name]
    cc_admin = importlib.import_module("verifier.cc_admin")
    chains = importlib.import_module("verifier.nvml.gpu_cert_chains")
    return cc_admin, chains.GpuCertificateChains


def _gpu_tlv(owner_nonce: bytes) -> bytes:
    cc_admin, certificate_chains = _vendor_import()
    with contextlib.redirect_stdout(sys.stderr):
        evidence = cc_admin.collect_gpu_evidence(owner_nonce.hex(), no_gpu_mode=False)
    if len(evidence) != 1:
        raise RuntimeError(f"expected exactly one local GPU, found {len(evidence)}")
    gpu = evidence[0]
    fields = (
        (1, owner_nonce),
        (2, gpu.get_attestation_report()),
        (
            3,
            base64.b64decode(
                certificate_chains.extract_gpu_cert_chain_base64(
                    gpu.get_attestation_cert_chain()
                )
            ),
        ),
        (4, gpu.get_driver_version().encode("utf-8")),
        (5, gpu.get_vbios_version().encode("utf-8")),
        (6, str(gpu.get_uuid()).encode("utf-8")),
        (7, gpu.get_gpu_architecture().encode("utf-8")),
    )
    return GPU_ENVELOPE_MAGIC + struct.pack(">H", len(fields)) + b"".join(
        struct.pack(">HI", field_id, len(value)) + value
        for field_id, value in fields
    )


def _quote(directory: Path, qualifying_data: bytes) -> dict[str, str]:
    ak_public = directory / "akpub.pem"
    quote_message = directory / "quote.msg"
    quote_signature = directory / "quote.sig"
    quote_pcrs = directory / "quote.pcrs"
    _run("tpm2_readpublic", "-c", AK_HANDLE, "-f", "pem", "-o", str(ak_public))
    _run(
        "tpm2_quote",
        "-c",
        AK_HANDLE,
        "-l",
        PCR_LIST,
        "-q",
        qualifying_data.hex(),
        "-m",
        str(quote_message),
        "-s",
        str(quote_signature),
        "-o",
        str(quote_pcrs),
        "-g",
        "sha256",
    )
    _run(
        "tpm2_checkquote",
        "-u",
        str(ak_public),
        "-m",
        str(quote_message),
        "-s",
        str(quote_signature),
        "-f",
        str(quote_pcrs),
        "-g",
        "sha256",
        "-q",
        qualifying_data.hex(),
    )
    return {
        "ak_public_key_pem_b64": _b64(ak_public.read_bytes()),
        "quote_message_b64": _b64(quote_message.read_bytes()),
        "quote_signature_b64": _b64(quote_signature.read_bytes()),
        "quote_pcrs_b64": _b64(quote_pcrs.read_bytes()),
        "qualifying_data_hex": qualifying_data.hex(),
    }


@functools.cache
def _amd_verifier() -> Any:
    # This repo's off-CVM verifier.py, loaded under its own name: the vendor GPU
    # package is also called `verifier`, and the two must not shadow each other.
    spec = importlib.util.spec_from_file_location(
        "spp_amd_verifier", Path(__file__).resolve().parent / "verifier.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("verifier.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # its dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return module


def _amd_chain(certs: Path, report_raw: bytes) -> None:
    """Materialize + verify the ARK/ASK/VCEK chain, KDS-fetching the VCEK at most once."""
    amd = _amd_verifier()
    report = amd.SnpReport.parse(report_raw)
    product = amd.kds_product_for_cpuid(report.cpuid_family, report.cpuid_model)
    if product is None:
        raise RuntimeError("AMD report CPUID maps to no known KDS product")
    for name in ("ark.pem", "ask.pem"):
        (certs / name).write_bytes((AMD_ROOTS_DIR / product / name).read_bytes())
    cached = Path(VCEK_CACHE_DIR) / "vcek.pem"
    for source in ("cache", "fetch"):
        if source == "cache":
            if not cached.is_file():
                continue
            pem = cached.read_bytes()
        else:
            url = amd.vcek_url(report, amd.VCEK_SOURCES["kds"], product)
            with urllib.request.urlopen(url, timeout=COMMAND_TIMEOUT) as response:
                der = response.read()
            pem = amd.x509.load_der_x509_certificate(der).public_bytes(
                amd.serialization.Encoding.PEM
            )
        (certs / "vcek.pem").write_bytes(pem)
        try:
            amd.verify_amd_chain_and_report(report, certs, AMD_ROOTS_DIR)
        except (amd.VerificationError, ValueError):
            if source == "fetch":
                raise
            continue  # cached VCEK went stale (TCB bump); refetch once
        if source == "fetch":
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(pem)
        return
    raise RuntimeError("AMD certificate chain could not be materialized")


def _certificate_evidence(request: dict[str, Any]) -> dict[str, str]:
    if request.get("binding_domain") != CERTIFICATE_BINDING_DOMAIN.decode("ascii"):
        raise ValueError("wrong certificate binding domain")
    owner_nonce = _decode(request.get("owner_nonce_b64"), "owner_nonce_b64")
    if len(owner_nonce) != OWNER_NONCE_BYTES:
        raise ValueError("owner nonce must be exactly 32 bytes")
    spki_der = _decode(request.get("tls_spki_der_b64"), "tls_spki_der_b64")
    _require_cc_production()
    gpu_envelope = _gpu_tlv(owner_nonce)
    qualifying_data = hashlib.sha256(
        CERTIFICATE_BINDING_DOMAIN
        + owner_nonce
        + hashlib.sha256(spki_der).digest()
        + hashlib.sha256(gpu_envelope).digest()
    ).digest()

    with tempfile.TemporaryDirectory(prefix="spp-ratls-") as temp:
        directory = Path(temp)
        hcl_report = directory / "hcl_report.bin"
        certs = directory / "certs"
        certs.mkdir()
        _run("tpm2_nvread", "-C", "o", HCL_NV_INDEX, "-o", str(hcl_report))
        hcl = hcl_report.read_bytes()
        report = _amd_verifier().parse_hcla(hcl).report
        _amd_chain(certs, report)
        quote = _quote(directory, qualifying_data)
        return {
            "owner_nonce_b64": _b64(owner_nonce),
            "tls_spki_der_b64": _b64(spki_der),
            "amd_report_b64": _b64(report),
            "hcl_report_b64": _b64(hcl),
            "amd_ark_pem_b64": _b64((certs / "ark.pem").read_bytes()),
            "amd_ask_pem_b64": _b64((certs / "ask.pem").read_bytes()),
            "amd_vcek_pem_b64": _b64((certs / "vcek.pem").read_bytes()),
            "gpu_envelope_b64": _b64(gpu_envelope),
            **quote,
        }


def _exporter_proof(request: dict[str, Any]) -> dict[str, str]:
    if request.get("binding_domain") != EXPORTER_BINDING_DOMAIN.decode("ascii"):
        raise ValueError("wrong exporter binding domain")
    qualifying_hex = request.get("qualifying_data_hex")
    if not isinstance(qualifying_hex, str):
        raise ValueError("qualifying_data_hex is required")
    qualifying_data = bytes.fromhex(qualifying_hex)
    if len(qualifying_data) != 32:
        raise ValueError("exporter qualifying data must be exactly 32 bytes")
    with tempfile.TemporaryDirectory(prefix="spp-ratls-exporter-") as temp:
        quote = _quote(Path(temp), qualifying_data)
    return {
        "quote_message_b64": quote["quote_message_b64"],
        "quote_signature_b64": quote["quote_signature_b64"],
        "quote_pcrs_b64": quote["quote_pcrs_b64"],
        "qualifying_data_hex": quote["qualifying_data_hex"],
    }


def main() -> int:
    # The vendor GPU verifier prints progress to stdout in ways Python-level
    # redirect_stdout cannot always intercept (streams bound at import, fd-1
    # writes). The gateway consumes stdout as one JSON object, so park the
    # real stdout fd, point fd 1 (and sys.stdout) at stderr for the whole
    # collection, and write only the final JSON to the parked fd.
    real_stdout_fd = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise ValueError("collector request must be an object")
        operation = request.get("operation")
        if operation == "certificate-evidence-v1":
            response = _certificate_evidence(request)
        elif operation == "exporter-proof-v1":
            response = _exporter_proof(request)
        else:
            raise ValueError(f"unsupported collector operation {operation!r}")
        payload = json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n"
        os.write(real_stdout_fd, payload.encode("ascii"))
        return 0
    except Exception as exc:
        print(f"collector failed: {exc}", file=sys.stderr)
        return 1
    finally:
        os.close(real_stdout_fd)


if __name__ == "__main__":
    raise SystemExit(main())
