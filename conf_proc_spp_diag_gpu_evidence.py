#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Nonce-bound raw NVIDIA GPU evidence collector for the diagnostic appliance."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import selectors
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Callable, Final


GPU_ENVELOPE_MAGIC: Final = b"SPPGPU1\0"
NVATTEST_PATH: Final = "/usr/bin/nvattest"
NVIDIA_SMI_PATH: Final = "/usr/bin/nvidia-smi"
OUTPUT_PATH: Final = "/run/spp-diag/gpu-evidence.tlv"
FIXED_ENVIRONMENT: Final = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
HELPER_TIMEOUT_SECONDS: Final = 120.0
MAX_TOOL_OUTPUT_BYTES: Final = 8 * 1024 * 1024
MAX_FIELD_BYTES: Final = 8 * 1024 * 1024
EXPECTED_GPU_NAME: Final = "NVIDIA H100 NVL"
_LOWER_HEX_32 = re.compile(r"[0-9a-f]{64}\Z")


class GpuEvidenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolResult:
    returncode: int
    stdout: bytes
    stderr: bytes


RunTool = Callable[[tuple[str, ...], dict[str, str], float, int], ToolResult]
Clock = Callable[[], float]


def _run_tool(argv: tuple[str, ...], env: dict[str, str], timeout: float, output_cap: int) -> ToolResult:
    if timeout < 0 or output_cap < 1:
        raise GpuEvidenceError("fixed GPU evidence tool limits are invalid")
    try:
        process = subprocess.Popen(
            argv,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
    except OSError as exc:
        raise GpuEvidenceError("fixed GPU evidence tool failed") from exc

    def stop_child() -> None:
        try:
            process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait()
            except OSError:
                pass

    assert process.stdout is not None and process.stderr is not None
    streams = (process.stdout, process.stderr)
    buffers: dict[int, bytearray] = {stream.fileno(): bytearray() for stream in streams}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream.fileno(), selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining < 0:
                raise GpuEvidenceError("fixed GPU evidence tool timed out")
            events = selector.select(remaining)
            if not events:
                raise GpuEvidenceError("fixed GPU evidence tool timed out")
            for key, _ in events:
                descriptor = key.fd
                while True:
                    try:
                        chunk = os.read(descriptor, min(65536, output_cap - len(buffers[descriptor]) + 1))
                    except BlockingIOError:
                        break
                    if not chunk:
                        selector.unregister(descriptor)
                        break
                    buffers[descriptor].extend(chunk)
                    if len(buffers[descriptor]) > output_cap:
                        raise GpuEvidenceError("fixed GPU evidence tool exceeded output cap")
        remaining = deadline - time.monotonic()
        if process.poll() is None:
            if remaining <= 0:
                raise GpuEvidenceError("fixed GPU evidence tool timed out")
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise GpuEvidenceError("fixed GPU evidence tool timed out") from exc
        if time.monotonic() > deadline:
            raise GpuEvidenceError("fixed GPU evidence tool timed out")
        return ToolResult(process.returncode, bytes(buffers[streams[0].fileno()]), bytes(buffers[streams[1].fileno()]))
    except Exception:
        # Deliberately do not create or signal a nested process group: PID 1 owns
        # this helper and every descendant in one group, so its deadline/cleanup
        # reaches collectors or grandchildren even if this direct child exits.
        stop_child()
        raise
    finally:
        selector.close()
        for stream in streams:
            stream.close()


def _remaining_budget(deadline: float, monotonic: Clock) -> float:
    remaining = deadline - monotonic()
    if remaining < 0:
        raise GpuEvidenceError("GPU evidence helper timed out")
    return remaining


def _decode_base64(value: object, name: str) -> bytes:
    if type(value) is not str or not value:
        raise GpuEvidenceError(f"{name} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise GpuEvidenceError(f"{name} is invalid") from exc
    if not decoded or len(decoded) > MAX_FIELD_BYTES:
        raise GpuEvidenceError(f"{name} is invalid")
    return decoded


def _text_field(value: str, name: str) -> bytes:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise GpuEvidenceError(f"{name} is invalid") from exc
    if not encoded or len(encoded) > 1024 or any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise GpuEvidenceError(f"{name} is invalid")
    return encoded


def encode_gpu_envelope(fields: tuple[bytes, ...]) -> bytes:
    if type(fields) is not tuple or len(fields) != 7:
        raise GpuEvidenceError("GPU evidence field inventory is invalid")
    encoded = [GPU_ENVELOPE_MAGIC, len(fields).to_bytes(2, "big")]
    for field_id, value in enumerate(fields, start=1):
        if type(value) is not bytes or not value or len(value) > MAX_FIELD_BYTES:
            raise GpuEvidenceError("GPU evidence field is invalid")
        encoded.extend((field_id.to_bytes(2, "big"), len(value).to_bytes(4, "big"), value))
    envelope = b"".join(encoded)
    if len(envelope) > MAX_TOOL_OUTPUT_BYTES:
        raise GpuEvidenceError("GPU evidence envelope is too large")
    return envelope


def collect_gpu_evidence(
    nonce: bytes,
    *,
    run_tool: RunTool = _run_tool,
    monotonic: Clock = time.monotonic,
    deadline: float | None = None,
) -> bytes:
    if type(nonce) is not bytes or len(nonce) != 32:
        raise GpuEvidenceError("GPU evidence nonce is invalid")
    if deadline is None:
        deadline = monotonic() + HELPER_TIMEOUT_SECONDS
    nonce_hex = nonce.hex()
    collect_argv = (
        NVATTEST_PATH,
        "--format=json",
        "collect-evidence",
        "--device=gpu",
        "--gpu-evidence-source=nvml",
        f"--nonce={nonce_hex}",
    )
    collected = run_tool(
        collect_argv,
        dict(FIXED_ENVIRONMENT),
        _remaining_budget(deadline, monotonic),
        MAX_TOOL_OUTPUT_BYTES,
    )
    _remaining_budget(deadline, monotonic)
    if collected.returncode != 0 or len(collected.stdout) > MAX_TOOL_OUTPUT_BYTES:
        raise GpuEvidenceError("nvattest evidence collection failed")
    try:
        document = json.loads(collected.stdout.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GpuEvidenceError("nvattest output is invalid") from exc
    if type(document) is not dict or set(document) != {"evidences", "result_code", "result_message"}:
        raise GpuEvidenceError("nvattest output schema is invalid")
    evidences = document["evidences"]
    if (
        document["result_code"] != 0
        or type(document["result_message"]) is not str
        or type(evidences) is not list
        or len(evidences) != 1
    ):
        raise GpuEvidenceError("nvattest did not return exactly one GPU")
    evidence = evidences[0]
    if type(evidence) is not dict or set(evidence) != {"arch", "nonce", "evidence", "certificate"}:
        raise GpuEvidenceError("nvattest evidence schema is invalid")
    evidence_nonce = evidence["nonce"]
    if (
        type(evidence_nonce) is not str
        or re.fullmatch(r"[0-9A-Fa-f]{64}", evidence_nonce) is None
        or evidence_nonce.lower() != nonce_hex
    ):
        raise GpuEvidenceError("nvattest evidence nonce is invalid")
    architecture = _text_field(evidence["arch"], "GPU architecture") if type(evidence["arch"]) is str else b""
    if architecture != b"HOPPER":
        raise GpuEvidenceError("GPU architecture is not HOPPER")
    report = _decode_base64(evidence["evidence"], "GPU attestation report")
    certificate_chain = _decode_base64(evidence["certificate"], "GPU certificate chain")

    metadata_argv = (
        NVIDIA_SMI_PATH,
        "--query-gpu=name,driver_version,vbios_version,uuid,compute_cap",
        "--format=csv,noheader,nounits",
    )
    metadata = run_tool(metadata_argv, dict(FIXED_ENVIRONMENT), _remaining_budget(deadline, monotonic), 4096)
    _remaining_budget(deadline, monotonic)
    if metadata.returncode != 0 or len(metadata.stdout) > 4096:
        raise GpuEvidenceError("nvidia-smi metadata collection failed")
    try:
        lines = metadata.stdout.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as exc:
        raise GpuEvidenceError("nvidia-smi metadata is invalid") from exc
    if len(lines) != 1:
        raise GpuEvidenceError("nvidia-smi did not return exactly one GPU")
    columns = [column.strip() for column in lines[0].split(",")]
    if (
        len(columns) != 5
        or columns[0] != EXPECTED_GPU_NAME
        or columns[4] != "9.0"
        or not columns[3].startswith("GPU-")
    ):
        raise GpuEvidenceError("nvidia-smi metadata is invalid")

    return encode_gpu_envelope(
        (
            nonce,
            report,
            certificate_chain,
            _text_field(columns[1], "driver version"),
            _text_field(columns[2], "VBIOS version"),
            _text_field(columns[3], "GPU UUID"),
            architecture,
        )
    )


def _publish_no_replace(
    data: bytes,
    output_path: str,
    *,
    deadline: float | None = None,
    monotonic: Clock = time.monotonic,
) -> None:
    if deadline is not None:
        _remaining_budget(deadline, monotonic)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC
    try:
        descriptor = os.open(output_path, flags, 0o600)
    except OSError as exc:
        raise GpuEvidenceError("GPU evidence output creation failed") from exc
    try:
        offset = 0
        while offset < len(data):
            if deadline is not None:
                _remaining_budget(deadline, monotonic)
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise GpuEvidenceError("GPU evidence output write failed")
            offset += written
        os.fsync(descriptor)
        if deadline is not None:
            _remaining_budget(deadline, monotonic)
        os.close(descriptor)
        if deadline is not None:
            _remaining_budget(deadline, monotonic)
    except Exception as exc:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(output_path)
        except OSError:
            pass
        if isinstance(exc, GpuEvidenceError):
            raise
        raise GpuEvidenceError("GPU evidence output write failed") from exc


def main(
    argv: list[str],
    *,
    run_tool: RunTool = _run_tool,
    output_path_override: str | None = None,
    monotonic: Clock = time.monotonic,
) -> int:
    if len(argv) != 5 or argv[1] != "--nonce-hex" or argv[3] != "--output":
        return 2
    nonce_hex = argv[2]
    output_path = argv[4]
    if _LOWER_HEX_32.fullmatch(nonce_hex) is None or (
        output_path_override is None and output_path != OUTPUT_PATH
    ):
        return 2
    try:
        deadline = monotonic() + HELPER_TIMEOUT_SECONDS
        evidence = collect_gpu_evidence(
            bytes.fromhex(nonce_hex), run_tool=run_tool, monotonic=monotonic, deadline=deadline
        )
        _publish_no_replace(
            evidence,
            output_path_override if output_path_override is not None else output_path,
            deadline=deadline,
            monotonic=monotonic,
        )
    except GpuEvidenceError:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
