#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Off-hardware tests for the content-free SPP engine health check."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import spp_health  # noqa: E402


class FakeRunner:
    def __init__(self, overrides: dict[tuple[str, ...], subprocess.CompletedProcess[str]] | None = None) -> None:
        self.overrides = overrides or {}
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def __call__(self, argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        key = tuple(argv)
        self.calls.append((key, timeout))
        if key in self.overrides:
            return self.overrides[key]
        if key == ("nvidia-smi", "conf-compute", "-f"):
            stdout = "CC status: ON\n"
        elif key == ("nvidia-smi", "conf-compute", "-e"):
            stdout = "CC Environment: PRODUCTION\n"
        elif key[:2] == ("systemctl", "is-active"):
            stdout = "active\n"
        elif key[:4] == ("sudo", "-n", "docker", "inspect"):
            stdout = "running\n"
        elif key[0:2] == ("nvidia-smi", "--query-gpu=name,memory.total,memory.used,memory.free"):
            stdout = "NVIDIA H100 NVL, 95830, 80840, 14010\n"
        else:
            raise AssertionError(f"unexpected command: {argv}")
        return subprocess.CompletedProcess(argv, 0, stdout, "")


def healthy_gateway(_host: str, _port: int, _timeout: int) -> dict[str, object]:
    return {
        "admitted": True,
        "inference_model": spp_health.EXPECTED_INFERENCE_MODEL,
        "asr_model": spp_health.EXPECTED_ASR_MODEL,
    }


class SppHealthTest(unittest.TestCase):
    def test_happy_document_is_bounded_and_healthy(self) -> None:
        result = spp_health.collect_health(
            runner=FakeRunner(),
            gateway_probe=healthy_gateway,
            now=lambda: datetime(2026, 7, 21, 1, 2, 3, tzinfo=timezone.utc),
        )

        self.assertEqual(
            result,
            {
                "schema_version": 1,
                "checked_at": "2026-07-21T01:02:03+00:00",
                "state": "healthy",
                "reasons": [],
                "cc": {"status": "ON", "environment": "PRODUCTION"},
                "services": {
                    "spp-asr.service": "active",
                    "spp-gateway.service": "active",
                    "docker.service": "active",
                    "spp-sglang": "running",
                },
                "gateway": {"admitted": True},
                "models": {
                    "inference": "Qwen/Qwen3.5-4B",
                    "asr": "nvidia/parakeet-tdt-0.6b-v3",
                },
                "gpu": {
                    "count": 1,
                    "name": "NVIDIA H100 NVL",
                    "memory_total_mib": 95830,
                    "memory_used_mib": 80840,
                    "memory_free_mib": 14010,
                },
            },
        )

    def test_failures_use_fixed_codes_without_command_or_body_details(self) -> None:
        failing = subprocess.CompletedProcess([], 7, "", "device-secret-evidence")
        runner = FakeRunner(
            {
                ("nvidia-smi", "conf-compute", "-f"): failing,
                ("systemctl", "is-active", "spp-asr.service"): failing,
            }
        )

        def failed_gateway(_host: str, _port: int, _timeout: int) -> dict[str, object]:
            raise RuntimeError("prompt-and-audio-material")

        result = spp_health.collect_health(
            runner=runner,
            gateway_probe=failed_gateway,
            now=lambda: datetime(2026, 7, 21, tzinfo=timezone.utc),
        )
        rendered = json.dumps(result)

        self.assertEqual(result["state"], "unhealthy")
        self.assertIn("cc_status_probe", result["reasons"])
        self.assertIn("service_spp_asr_probe", result["reasons"])
        self.assertIn("gateway_admission", result["reasons"])
        self.assertNotIn("secret", rendered)
        self.assertNotIn("prompt", rendered)
        self.assertNotIn("audio-material", rendered)

    def test_model_drift_is_unhealthy_context_not_raw_response(self) -> None:
        def drifted(_host: str, _port: int, _timeout: int) -> dict[str, object]:
            return {
                "admitted": True,
                "inference_model": "wrong/inference",
                "asr_model": "wrong/asr",
                "future": "untrusted-body",
            }

        result = spp_health.collect_health(runner=FakeRunner(), gateway_probe=drifted)

        self.assertEqual(result["state"], "unhealthy")
        self.assertIn("inference_model", result["reasons"])
        self.assertIn("asr_model", result["reasons"])
        self.assertEqual(
            result["models"],
            {"inference": "unexpected", "asr": "unexpected"},
        )
        self.assertNotIn("future", result)

    def test_http_reader_rejects_header_terminator_beyond_limit(self) -> None:
        class OneChunk:
            def recv(self, _size: int) -> bytes:
                return b"x" * 1025 + b"\r\n\r\n"

        reader = spp_health._TlsHttp(OneChunk())

        with self.assertRaisesRegex(
            spp_health.HealthProbeError,
            "response head exceeds limit",
        ):
            reader._read_until(b"\r\n\r\n", 1024)

    def test_gpu_parser_rejects_multiple_devices(self) -> None:
        command = (
            "nvidia-smi",
            "--query-gpu=name,memory.total,memory.used,memory.free",
            "--format=csv,noheader,nounits",
        )
        runner = FakeRunner(
            {
                command: subprocess.CompletedProcess(
                    command,
                    0,
                    "NVIDIA H100 NVL, 1, 1, 0\nNVIDIA H100 NVL, 1, 1, 0\n",
                    "",
                )
            }
        )

        result = spp_health.collect_health(runner=runner, gateway_probe=healthy_gateway)

        self.assertEqual(result["gpu"]["count"], 0)
        self.assertIn("gpu_probe", result["reasons"])


if __name__ == "__main__":
    unittest.main()
