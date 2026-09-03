#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent wire and invocation tests for the diagnostic GPU helper."""

from __future__ import annotations

import ast
import base64
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import conf_proc_spp_diag_gpu_evidence as gpu


NONCE = bytes(range(32))
REPORT = b"raw-spdm-attestation-report"
CHAIN = b"decoded-nvidia-certificate-chain"
METADATA = b"NVIDIA H100 NVL, 595.71.05, 96.00.9F.00.04, GPU-11111111-2222-3333-4444-555555555555, 9.0\n"


def evidence_document(*, nonce: str = NONCE.hex(), arch: str = "HOPPER") -> dict:
    return {
        "evidences": [
            {
                "arch": arch,
                "nonce": nonce,
                "evidence": base64.b64encode(REPORT).decode("ascii"),
                "certificate": base64.b64encode(CHAIN).decode("ascii"),
            }
        ],
        "result_code": 0,
        "result_message": "Ok",
    }


class FakeClock:
    def __init__(self, value: float = 1000.0):
        self.value = value

    def __call__(self) -> float:
        return self.value


class Recorder:
    def __init__(
        self,
        *,
        document: dict | None = None,
        metadata: bytes = METADATA,
        fail_call: int | None = None,
        clock: FakeClock | None = None,
        durations: tuple[float, ...] = (),
    ):
        self.document = evidence_document() if document is None else document
        self.metadata = metadata
        self.fail_call = fail_call
        self.clock = clock
        self.durations = durations
        self.calls: list[tuple[tuple[str, ...], dict[str, str], float, int]] = []

    def __call__(self, argv: tuple[str, ...], env: dict[str, str], timeout: float, cap: int) -> gpu.ToolResult:
        self.calls.append((argv, env, timeout, cap))
        if self.clock is not None and len(self.calls) <= len(self.durations):
            self.clock.value += self.durations[len(self.calls) - 1]
        if self.fail_call == len(self.calls):
            return gpu.ToolResult(1, b"", b"forced failure")
        if argv[0] == gpu.NVATTEST_PATH:
            return gpu.ToolResult(0, json.dumps(self.document, separators=(",", ":")).encode("utf-8"), b"")
        if argv[0] == gpu.NVIDIA_SMI_PATH:
            return gpu.ToolResult(0, self.metadata, b"")
        raise AssertionError(argv)


def parse_envelope(data: bytes) -> list[tuple[int, bytes]]:
    assert data[:8] == b"SPPGPU1\0"
    count = int.from_bytes(data[8:10], "big")
    offset = 10
    fields: list[tuple[int, bytes]] = []
    for _ in range(count):
        field_id, length = struct.unpack(">HI", data[offset : offset + 6])
        offset += 6
        value = data[offset : offset + length]
        assert len(value) == length
        offset += length
        fields.append((field_id, value))
    assert offset == len(data)
    return fields


def test_exact_invocations_and_wire() -> None:
    recorder = Recorder()
    clock = FakeClock()
    envelope = gpu.collect_gpu_evidence(NONCE, run_tool=recorder, monotonic=clock)
    assert recorder.calls == [
        (
            (
                "/usr/bin/nvattest",
                "--format=json",
                "collect-evidence",
                "--device=gpu",
                "--gpu-evidence-source=nvml",
                f"--nonce={NONCE.hex()}",
            ),
            {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
            120.0,
            8 * 1024 * 1024,
        ),
        (
            (
                "/usr/bin/nvidia-smi",
                "--query-gpu=name,driver_version,vbios_version,uuid,compute_cap",
                "--format=csv,noheader,nounits",
            ),
            {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
            120.0,
            4096,
        ),
    ]
    fields = parse_envelope(envelope)
    assert [field_id for field_id, _ in fields] == list(range(1, 8))
    assert [value for _, value in fields] == [
        NONCE,
        REPORT,
        CHAIN,
        b"595.71.05",
        b"96.00.9F.00.04",
        b"GPU-11111111-2222-3333-4444-555555555555",
        b"HOPPER",
    ]


def test_schema_nonce_and_target_mutations_reject() -> None:
    mutations: list[tuple[str, dict, bytes]] = []
    wrong_nonce = evidence_document(nonce="ff" * 32)
    mutations.append(("wrong_nonce", wrong_nonce, METADATA))
    wrong_arch = evidence_document(arch="BLACKWELL")
    mutations.append(("wrong_arch", wrong_arch, METADATA))
    two_gpus = evidence_document()
    two_gpus["evidences"].append(dict(two_gpus["evidences"][0]))
    mutations.append(("two_gpus", two_gpus, METADATA))
    bad_base64 = evidence_document()
    bad_base64["evidences"][0]["evidence"] = "***"
    mutations.append(("bad_base64", bad_base64, METADATA))
    extra_key = evidence_document()
    extra_key["unexpected"] = 1
    mutations.append(("extra_key", extra_key, METADATA))
    mutations.append(("wrong_compute_cap", evidence_document(), METADATA.replace(b"9.0", b"8.0")))
    for wrong_name in (b"NVIDIA H200", b"NVIDIA GH200 120GB", b"NVIDIA H20"):
        mutations.append(
            (wrong_name.decode("ascii"), evidence_document(), METADATA.replace(b"NVIDIA H100 NVL", wrong_name))
        )
    mutations.append(("two_metadata_rows", evidence_document(), METADATA + METADATA))
    for name, document, metadata in mutations:
        try:
            gpu.collect_gpu_evidence(NONCE, run_tool=Recorder(document=document, metadata=metadata))
            raise AssertionError(f"{name} unexpectedly passed")
        except gpu.GpuEvidenceError:
            pass


def test_tool_failures_reject() -> None:
    for failed_call in (1, 2):
        try:
            gpu.collect_gpu_evidence(NONCE, run_tool=Recorder(fail_call=failed_call))
            raise AssertionError(f"tool call {failed_call} unexpectedly passed")
        except gpu.GpuEvidenceError:
            pass


def test_bounded_capture_and_shared_deadline() -> None:
    environment = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    for channel in ("stdout", "stderr"):
        script = "import os;os.write(%d,b'x'*33)" % (1 if channel == "stdout" else 2)
        try:
            gpu._run_tool((sys.executable, "-c", script), environment, 2.0, 32)
            raise AssertionError(f"over-cap {channel} unexpectedly passed")
        except gpu.GpuEvidenceError:
            pass

    group_probe = gpu._run_tool(
        (sys.executable, "-c", "import os;print(os.getpgrp())"), environment, 2.0, 32
    )
    assert group_probe.returncode == 0
    assert group_probe.stdout.strip() == str(os.getpgrp()).encode("ascii")

    exact_clock = FakeClock()
    exact = Recorder(clock=exact_clock, durations=(70.0, 50.0))
    gpu.collect_gpu_evidence(NONCE, run_tool=exact, monotonic=exact_clock)
    assert [call[2] for call in exact.calls] == [120.0, 50.0]

    late_clock = FakeClock()
    late = Recorder(clock=late_clock, durations=(70.0, 50.000001))
    try:
        gpu.collect_gpu_evidence(NONCE, run_tool=late, monotonic=late_clock)
        raise AssertionError("one-tick deadline overrun unexpectedly passed")
    except gpu.GpuEvidenceError:
        pass


def test_deadline_includes_completed_publication() -> None:
    argv = [
        "/usr/lib/spp/spp-diag-gpu-evidence.py",
        "--nonce-hex",
        NONCE.hex(),
        "--output",
        gpu.OUTPUT_PATH,
    ]
    real_close = gpu.os.close
    with tempfile.TemporaryDirectory() as work_dir:
        for suffix, close_duration, expected in (("exact", 1.0, 0), ("late", 1.000001, 3)):
            destination = os.path.join(work_dir, f"{suffix}.tlv")
            clock = FakeClock()
            recorder = Recorder(clock=clock, durations=(70.0, 49.0))

            def timed_close(descriptor: int, *, duration: float = close_duration) -> None:
                real_close(descriptor)
                clock.value += duration

            gpu.os.close = timed_close
            try:
                assert (
                    gpu.main(
                        argv,
                        run_tool=recorder,
                        output_path_override=destination,
                        monotonic=clock,
                    )
                    == expected
                )
            finally:
                gpu.os.close = real_close
            assert os.path.exists(destination) is (expected == 0)


def test_exact_cli_and_no_replace_output() -> None:
    with tempfile.TemporaryDirectory() as work_dir:
        destination = os.path.join(work_dir, "gpu-evidence.tlv")
        argv = [
            "/usr/lib/spp/spp-diag-gpu-evidence.py",
            "--nonce-hex",
            NONCE.hex(),
            "--output",
            gpu.OUTPUT_PATH,
        ]
        assert gpu.main(argv, run_tool=Recorder(), output_path_override=destination) == 0
        with open(destination, "rb") as handle:
            fields = parse_envelope(handle.read())
        assert fields[0] == (1, NONCE)
        assert stat.S_IMODE(os.stat(destination).st_mode) == 0o600
        original = open(destination, "rb").read()
        assert gpu.main(argv, run_tool=Recorder(), output_path_override=destination) == 3
        assert open(destination, "rb").read() == original

    malformed = [
        argv[:1],
        [argv[0], "--nonce-hex", "AA" * 32, "--output", gpu.OUTPUT_PATH],
        [argv[0], "--nonce-hex", NONCE.hex(), "--output", "/tmp/elsewhere"],
        [argv[0], "--output", gpu.OUTPUT_PATH, "--nonce-hex", NONCE.hex()],
        argv + ["extra"],
    ]
    for candidate in malformed:
        assert gpu.main(candidate, run_tool=Recorder()) == 2


def test_no_appraiser_import_or_deprecated_verifier() -> None:
    source_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "conf_proc_spp_diag_gpu_evidence.py")
    with open(source_path, "r", encoding="utf-8") as handle:
        source = handle.read()
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert not any(name.startswith("conf_proc_spp_diag") for name in imported)
    assert "verifier.cc_admin" not in source and "local_gpu_verifier" not in source


def main() -> int:
    tests = [
        test_exact_invocations_and_wire,
        test_schema_nonce_and_target_mutations_reject,
        test_tool_failures_reject,
        test_bounded_capture_and_shared_deadline,
        test_deadline_includes_completed_publication,
        test_exact_cli_and_no_replace_output,
        test_no_appraiser_import_or_deprecated_verifier,
    ]
    for test in tests:
        test()
        print(f"ok   {test.__name__}")
    print(f"SPP diagnostic GPU evidence helper: ok ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
