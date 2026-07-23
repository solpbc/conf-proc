#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Content-free health check for the persistent SPP engine pool.

The check is intentionally on-box: it verifies the confidential-compute mode,
required processes, a real two-phase RA-TLS admission, both served-model
identities, and the single expected H100.  Structured output contains only
fixed health fields and capacity counters; it never includes evidence,
request/response bodies, prompts, frames, audio, or transcripts.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import socket
import subprocess
from datetime import datetime, timezone
from typing import Any, Callable, Final

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from OpenSSL import SSL

from ratls_contract import (
    COMPOSITE_EVIDENCE_OID,
    EXPORTER_BYTES,
    EXPORTER_CONTEXT_DOMAIN,
    EXPORTER_LABEL,
    EXPORTER_PROOF_MEDIA_TYPE,
    EXPORTER_PROOF_PATH,
    OWNER_NONCE_BYTES,
    PREFACE_MAGIC,
    CompositeEvidence,
    ExporterProof,
)


SCHEMA_VERSION: Final = 1
EXPECTED_INFERENCE_MODEL: Final = "Qwen/Qwen3.5-4B"
EXPECTED_ASR_MODEL: Final = "nvidia/parakeet-tdt-0.6b-v3"
EXPECTED_GPU: Final = "NVIDIA H100 NVL"
GATEWAY_HOST: Final = "127.0.0.1"
GATEWAY_PORT: Final = 9443
COMMAND_TIMEOUT_SECONDS: Final = 15
GATEWAY_TIMEOUT_SECONDS: Final = 45
MAX_HTTP_HEAD_BYTES: Final = 32 * 1024
MAX_HTTP_BODY_BYTES: Final = 1024 * 1024

RunCommand = Callable[[list[str], int], subprocess.CompletedProcess[str]]
GatewayProbe = Callable[[str, int, int], dict[str, object]]
ModelsProbe = Callable[[int], dict[str, str]]


class HealthProbeError(RuntimeError):
    """A bounded health probe failed; details must not enter structured output."""


def _run(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _command_text(
    argv: list[str],
    *,
    runner: RunCommand,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> str:
    try:
        completed = runner(argv, timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HealthProbeError("command unavailable") from exc
    if completed.returncode != 0 or not isinstance(completed.stdout, str):
        raise HealthProbeError("command failed")
    return completed.stdout.strip()


def _read_cc_field(flag: str, label: str, runner: RunCommand) -> str:
    output = _command_text(
        ["nvidia-smi", "conf-compute", flag],
        runner=runner,
    )
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == label:
            return value.strip()
    raise HealthProbeError("unexpected confidential-compute output")


def _read_service(name: str, runner: RunCommand) -> str:
    value = _command_text(["systemctl", "is-active", name], runner=runner)
    return value if value else "unknown"


def _read_container(runner: RunCommand) -> str:
    value = _command_text(
        [
            "sudo",
            "-n",
            "docker",
            "inspect",
            "--format={{.State.Status}}",
            "spp-sglang",
        ],
        runner=runner,
    )
    return value if value else "unknown"


def _read_gpu(runner: RunCommand) -> dict[str, object]:
    output = _command_text(
        [
            "nvidia-smi",
            "--query-gpu=name,memory.total,memory.used,memory.free",
            "--format=csv,noheader,nounits",
        ],
        runner=runner,
    )
    rows = [line.strip() for line in output.splitlines() if line.strip()]
    if len(rows) != 1:
        raise HealthProbeError("unexpected GPU count")
    fields = [field.strip() for field in rows[0].split(",")]
    if len(fields) != 4:
        raise HealthProbeError("unexpected GPU output")
    try:
        total, used, free = (int(value) for value in fields[1:])
    except ValueError as exc:
        raise HealthProbeError("unexpected GPU memory output") from exc
    if min(total, used, free) < 0 or used > total or free > total:
        raise HealthProbeError("invalid GPU memory counters")
    return {
        "count": 1,
        "name": fields[0],
        "memory_total_mib": total,
        "memory_used_mib": used,
        "memory_free_mib": free,
    }


class _TlsHttp:
    """Small bounded HTTP/1.1 reader over a pyOpenSSL connection."""

    def __init__(self, connection: SSL.Connection) -> None:
        self.connection = connection
        self.buffer = bytearray()

    def _receive(self) -> bytes:
        try:
            chunk = self.connection.recv(65536)
        except (SSL.Error, OSError) as exc:
            raise HealthProbeError("gateway response failed") from exc
        if not chunk:
            raise HealthProbeError("gateway closed response")
        return chunk

    def _read_until(self, marker: bytes, limit: int) -> bytes:
        while marker not in self.buffer:
            if len(self.buffer) >= limit:
                raise HealthProbeError("gateway response head exceeds limit")
            self.buffer.extend(self._receive())
        end = self.buffer.index(marker) + len(marker)
        if end > limit:
            raise HealthProbeError("gateway response head exceeds limit")
        value = bytes(self.buffer[:end])
        del self.buffer[:end]
        return value

    def _read_exact(self, length: int) -> bytes:
        if length < 0 or length > MAX_HTTP_BODY_BYTES:
            raise HealthProbeError("gateway response body exceeds limit")
        while len(self.buffer) < length:
            self.buffer.extend(self._receive())
            if len(self.buffer) > MAX_HTTP_BODY_BYTES:
                raise HealthProbeError("gateway response body exceeds limit")
        value = bytes(self.buffer[:length])
        del self.buffer[:length]
        return value

    def _read_chunked(self) -> bytes:
        body = bytearray()
        while True:
            size_line = self._read_until(b"\r\n", 1024)[:-2]
            try:
                size = int(size_line.split(b";", 1)[0], 16)
            except ValueError as exc:
                raise HealthProbeError("invalid gateway chunk") from exc
            if size < 0 or len(body) + size > MAX_HTTP_BODY_BYTES:
                raise HealthProbeError("gateway response body exceeds limit")
            if size == 0:
                while self._read_until(b"\r\n", MAX_HTTP_HEAD_BYTES) != b"\r\n":
                    pass
                return bytes(body)
            body.extend(self._read_exact(size))
            if self._read_exact(2) != b"\r\n":
                raise HealthProbeError("invalid gateway chunk framing")

    def get(self, path: str) -> tuple[int, dict[bytes, bytes], bytes]:
        try:
            self.connection.sendall(
                f"GET {path} HTTP/1.1\r\nHost: spp-engine\r\n"
                "Accept: application/json\r\nContent-Length: 0\r\n\r\n".encode(
                    "ascii"
                )
            )
        except (SSL.Error, OSError) as exc:
            raise HealthProbeError("gateway request failed") from exc
        head = self._read_until(b"\r\n\r\n", MAX_HTTP_HEAD_BYTES)[:-4]
        lines = head.split(b"\r\n")
        parts = lines[0].split(b" ", 2) if lines else []
        if len(parts) != 3 or parts[0] != b"HTTP/1.1" or not parts[1].isdigit():
            raise HealthProbeError("invalid gateway status line")
        headers: dict[bytes, bytes] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            key = name.strip().lower()
            if not separator or not key or key in headers:
                raise HealthProbeError("invalid gateway response headers")
            headers[key] = value.strip()
        transfer = headers.get(b"transfer-encoding", b"").lower().replace(b" ", b"")
        if transfer:
            if transfer != b"chunked" or b"content-length" in headers:
                raise HealthProbeError("unsupported gateway response framing")
            body = self._read_chunked()
        else:
            length_text = headers.get(b"content-length")
            if length_text is None or not length_text.isdigit():
                raise HealthProbeError("gateway response lacks content length")
            body = self._read_exact(int(length_text))
        return int(parts[1]), headers, body


def _require_nonempty_evidence(evidence: CompositeEvidence) -> None:
    if any(not value for value in evidence.__dict__.values()):
        raise HealthProbeError("certificate evidence is incomplete")


def admit_gateway(
    host: str = GATEWAY_HOST,
    port: int = GATEWAY_PORT,
    timeout: int = GATEWAY_TIMEOUT_SECONDS,
) -> tuple[SSL.Connection, socket.socket, _TlsHttp]:
    """Complete the two-phase SPP admission and return the admitted channel."""

    nonce = os.urandom(OWNER_NONCE_BYTES)
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        raw.sendall(PREFACE_MAGIC + nonce)
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_min_proto_version(SSL.TLS1_3_VERSION)
        context.set_max_proto_version(SSL.TLS1_3_VERSION)
        context.set_verify(SSL.VERIFY_NONE, lambda *_args: True)
        connection = SSL.Connection(context, raw)
        connection.setblocking(1)
        connection.set_connect_state()
        connection.set_tlsext_host_name(b"spp-engine")
        connection.do_handshake()
    except (OSError, SSL.Error) as exc:
        try:
            raw.close()
        except (NameError, OSError):
            pass
        raise HealthProbeError("RA-TLS handshake failed") from exc

    try:
        if connection.get_protocol_version_name() != "TLSv1.3":
            raise HealthProbeError("gateway did not negotiate TLS 1.3")
        peer = connection.get_peer_certificate().to_cryptography()
        extension = peer.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(COMPOSITE_EVIDENCE_OID)
        )
        if not extension.critical:
            raise HealthProbeError("certificate evidence is not critical")
        evidence = CompositeEvidence.from_der(extension.value.value)
        _require_nonempty_evidence(evidence)
        peer_spki = peer.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if evidence.owner_nonce != nonce or evidence.tls_spki_der != peer_spki:
            raise HealthProbeError("certificate evidence binding mismatch")
        exporter_context = hashlib.sha256(
            EXPORTER_CONTEXT_DOMAIN + nonce + hashlib.sha256(peer_spki).digest()
        ).digest()
        exporter = connection.export_keying_material(
            EXPORTER_LABEL,
            EXPORTER_BYTES,
            exporter_context,
        )
        http = _TlsHttp(connection)
        status, headers, body = http.get(EXPORTER_PROOF_PATH)
        if status != 200 or headers.get(b"content-type") != EXPORTER_PROOF_MEDIA_TYPE.encode():
            raise HealthProbeError("exporter proof endpoint rejected")
        proof = ExporterProof.from_der(body)
        if (
            proof.owner_nonce != nonce
            or proof.tls_spki_der != peer_spki
            or proof.tls_exporter != exporter
            or not proof.quote_message
            or not proof.quote_signature
            or not proof.quote_pcrs
        ):
            raise HealthProbeError("exporter proof binding mismatch")
        return connection, raw, http
    except (HealthProbeError, ValueError, x509.ExtensionNotFound, SSL.Error) as exc:
        connection.close()
        raw.close()
        if isinstance(exc, HealthProbeError):
            raise
        raise HealthProbeError("RA-TLS evidence rejected") from exc


def _json_object(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HealthProbeError("health endpoint returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise HealthProbeError("health endpoint returned invalid object")
    return value


def _model_id(body: bytes) -> str:
    value = _json_object(body)
    data = value.get("data")
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise HealthProbeError("model endpoint returned invalid list")
    model_id = data[0].get("id")
    if (
        not isinstance(model_id, str)
        or not model_id
        or len(model_id) > 256
        or any(not char.isprintable() for char in model_id)
    ):
        raise HealthProbeError("model endpoint omitted model id")
    return model_id


def probe_gateway(
    host: str = GATEWAY_HOST,
    port: int = GATEWAY_PORT,
    timeout: int = GATEWAY_TIMEOUT_SECONDS,
) -> dict[str, object]:
    connection, raw, http = admit_gateway(host, port, timeout)
    try:
        status, headers, body = http.get("/health")
        if (
            status != 401
            or headers.get(b"cache-control") != b"no-store"
            or not headers.get(b"www-authenticate", b"").lower().startswith(b"bearer")
            or body != b'{"error":"invalid entitlement credential"}'
        ):
            raise HealthProbeError("gateway did not enforce entitlement admission")
        return {"admitted": True}
    finally:
        try:
            connection.shutdown()
        except (SSL.Error, OSError):
            pass
        connection.close()
        raw.close()


def _loopback_get(port: int, path: str, timeout: int) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        body = response.read(MAX_HTTP_BODY_BYTES + 1)
        if len(body) > MAX_HTTP_BODY_BYTES:
            raise HealthProbeError("loopback response body exceeds limit")
        return response.status, body
    except (OSError, http.client.HTTPException) as exc:
        raise HealthProbeError("loopback serving probe failed") from exc
    finally:
        connection.close()


def probe_loopback_models(timeout: int = COMMAND_TIMEOUT_SECONDS) -> dict[str, str]:
    inference_health, _ = _loopback_get(8000, "/health", timeout)
    inference_models, inference_body = _loopback_get(8000, "/v1/models", timeout)
    asr_health, asr_health_body = _loopback_get(8100, "/v1/audio/health", timeout)
    asr_models, asr_body = _loopback_get(8100, "/v1/audio/models", timeout)
    asr_ready = _json_object(asr_health_body)
    if (
        inference_health != 200
        or inference_models != 200
        or asr_health != 200
        or asr_models != 200
        or asr_ready.get("ok") is not True
        or asr_ready.get("ready") is not True
    ):
        raise HealthProbeError("loopback serving endpoint is not ready")
    return {
        "inference_model": _model_id(inference_body),
        "asr_model": _model_id(asr_body),
    }


def collect_health(
    *,
    runner: RunCommand = _run,
    gateway_probe: GatewayProbe = probe_gateway,
    models_probe: ModelsProbe = probe_loopback_models,
    now: Callable[[], datetime] | None = None,
) -> dict[str, object]:
    """Return the complete bounded health document without raising probe details."""

    reasons: list[str] = []
    cc = {"status": "unknown", "environment": "unknown"}
    services = {
        "spp-asr.service": "unknown",
        "spp-gateway.service": "unknown",
        "docker.service": "unknown",
        "spp-sglang": "unknown",
    }
    gateway = {"admitted": False}
    models = {"inference": "unknown", "asr": "unknown"}
    gpu: dict[str, object] = {
        "count": 0,
        "name": "unknown",
        "memory_total_mib": 0,
        "memory_used_mib": 0,
        "memory_free_mib": 0,
    }

    try:
        cc["status"] = _read_cc_field("-f", "CC status", runner)
    except Exception:  # noqa: BLE001 - health boundary converts all failures to UNKNOWN
        reasons.append("cc_status_probe")
    else:
        if cc["status"] != "ON":
            reasons.append("cc_status")

    try:
        cc["environment"] = _read_cc_field("-e", "CC Environment", runner)
    except Exception:  # noqa: BLE001 - health boundary converts all failures to UNKNOWN
        reasons.append("cc_environment_probe")
    else:
        if cc["environment"] != "PRODUCTION":
            reasons.append("cc_environment")

    for service in ("spp-asr.service", "spp-gateway.service", "docker.service"):
        try:
            services[service] = _read_service(service, runner)
        except Exception:  # noqa: BLE001 - health boundary converts all failures to UNKNOWN
            reasons.append(f"service_{service.removesuffix('.service').replace('-', '_')}_probe")
        else:
            if services[service] != "active":
                reasons.append(f"service_{service.removesuffix('.service').replace('-', '_')}")

    try:
        services["spp-sglang"] = _read_container(runner)
    except Exception:  # noqa: BLE001 - health boundary converts all failures to UNKNOWN
        reasons.append("container_spp_sglang_probe")
    else:
        if services["spp-sglang"] != "running":
            reasons.append("container_spp_sglang")

    try:
        gateway_result = gateway_probe(
            GATEWAY_HOST,
            GATEWAY_PORT,
            GATEWAY_TIMEOUT_SECONDS,
        )
    except Exception:  # noqa: BLE001 - never leak evidence/body diagnostics
        reasons.append("gateway_admission")
    else:
        if gateway_result.get("admitted") is True:
            gateway["admitted"] = True
        else:
            reasons.append("gateway_admission")
    try:
        model_result = models_probe(COMMAND_TIMEOUT_SECONDS)
    except Exception:  # noqa: BLE001 - never leak loopback response diagnostics
        reasons.extend(["inference_model", "asr_model"])
    else:
        inference_model = model_result.get("inference_model")
        asr_model = model_result.get("asr_model")
        if isinstance(inference_model, str):
            models["inference"] = (
                inference_model
                if inference_model == EXPECTED_INFERENCE_MODEL
                else "unexpected"
            )
        if isinstance(asr_model, str):
            models["asr"] = (
                asr_model if asr_model == EXPECTED_ASR_MODEL else "unexpected"
            )
        if models["inference"] != EXPECTED_INFERENCE_MODEL:
            reasons.append("inference_model")
        if models["asr"] != EXPECTED_ASR_MODEL:
            reasons.append("asr_model")

    try:
        gpu = _read_gpu(runner)
    except Exception:  # noqa: BLE001 - health boundary converts all failures to UNKNOWN
        reasons.append("gpu_probe")
    else:
        if gpu["count"] != 1:
            reasons.append("gpu_count")
        if gpu["name"] != EXPECTED_GPU:
            reasons.append("gpu_model")

    checked = (now or (lambda: datetime.now(timezone.utc)))()
    return {
        "schema_version": SCHEMA_VERSION,
        "checked_at": checked.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "state": "healthy" if not reasons else "unhealthy",
        "reasons": reasons,
        "cc": cc,
        "services": services,
        "gateway": gateway,
        "models": models,
        "gpu": gpu,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the bounded machine-readable health document",
    )
    args = parser.parse_args(argv)
    result = collect_health()
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        reasons = ",".join(result["reasons"]) if result["reasons"] else "none"
        print(f"SPP engine: {result['state']} (reasons: {reasons})")
    return 0 if result["state"] == "healthy" else 1


if __name__ == "__main__":
    raise SystemExit(main())
