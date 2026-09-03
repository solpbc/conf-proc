#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Compiles the real spp-diag-cuda-driver and a fake libcuda.so.1, and proves the
witness transform, fault-injection matrix, and cleanup behavior end to end."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER_SOURCE = os.path.join(ROOT, "spp-diag-runtime-src", "spp_diag_cuda_driver.c")
FAKE_SOURCE = os.path.join(ROOT, "test", "spp-diag-runtime-shim", "fake_libcuda.c")

FIXED_KEY = bytes(
    [
        0x53, 0x50, 0x50, 0x2D, 0x44, 0x49, 0x41, 0x47, 0x2D, 0x57, 0x49, 0x54, 0x4E, 0x45, 0x53, 0x53,
        0x2D, 0x56, 0x31, 0x2D, 0x4B, 0x45, 0x59, 0x2D, 0x30, 0x31, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ]
)


def expected_witness(nonce: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(nonce, FIXED_KEY))


def build(build_dir: str) -> tuple[str, str]:
    driver = os.path.join(build_dir, "spp-diag-cuda-driver")
    result = subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-o", driver, DRIVER_SOURCE, "-ldl"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or result.stdout.strip() or result.stderr.strip():
        raise SystemExit(f"driver compile failed/warned:\n{result.stdout}\n{result.stderr}")

    fake = os.path.join(build_dir, "libcuda.so.1")
    result = subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-fPIC", "-shared", "-o", fake, FAKE_SOURCE],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(f"fake compile failed:\n{result.stdout}\n{result.stderr}")
    return driver, fake


def run_driver(driver: str, lib_dir: str, nonce_hex: str, extra_env: dict | None = None, timeout: float = 3.0):
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = lib_dir
    if extra_env:
        env.update(extra_env)
    return subprocess.run([driver, nonce_hex], env=env, capture_output=True, text=True, timeout=timeout)


def main() -> int:
    with tempfile.TemporaryDirectory() as build_dir:
        driver, fake = build(build_dir)
        lib_dir = os.path.dirname(fake)
        tests = 0

        nonce_a = "11" * 32
        nonce_b = "22" * 32
        result_a = run_driver(driver, lib_dir, nonce_a)
        result_b = run_driver(driver, lib_dir, nonce_b)
        assert result_a.returncode == 0, result_a.stderr
        assert result_b.returncode == 0, result_b.stderr
        assert result_a.stdout.strip() == expected_witness(bytes.fromhex(nonce_a)).hex(), result_a.stdout
        assert result_b.stdout.strip() == expected_witness(bytes.fromhex(nonce_b)).hex(), result_b.stdout
        assert result_a.stdout != result_b.stdout
        print("ok   witness_transform_two_distinct_vectors")
        tests += 1

        result_const = run_driver(driver, lib_dir, nonce_a, {"SPP_DIAG_CUDA_FAKE_FORCE_CONSTANT_OUTPUT": "1"})
        assert result_const.returncode == 0
        assert result_const.stdout.strip() != expected_witness(bytes.fromhex(nonce_a)).hex()
        print("ok   constant_stale_output_detected_as_wrong_by_independent_expectation")
        tests += 1

        for fault_env, expect_nonzero in [
            ({"SPP_DIAG_CUDA_FAKE_FORCE_MODULE_MISMATCH": "1"}, True),
            ({"SPP_DIAG_CUDA_FAKE_FORCE_FUNCTION_MISMATCH": "1"}, True),
            ({"SPP_DIAG_CUDA_FAKE_FORCE_GEOMETRY_MISMATCH": "1"}, True),
            ({"SPP_DIAG_CUDA_FAKE_FORCE_DRIVER_RESULT": "719"}, True),
            ({"SPP_DIAG_CUDA_FAKE_FORCE_CLEANUP_FAIL": "1"}, True),
        ]:
            result = run_driver(driver, lib_dir, nonce_a, fault_env)
            assert (result.returncode != 0) == expect_nonzero, (fault_env, result.returncode, result.stdout, result.stderr)
            if fault_env.get("SPP_DIAG_CUDA_FAKE_FORCE_CLEANUP_FAIL"):
                # cleanup failure happens after a correct result was already computed;
                # the driver must still report failure via its exit code.
                assert result.returncode != 0
            else:
                assert result.stdout.strip() == "", f"{fault_env}: unexpected stdout on failure: {result.stdout!r}"
            print(f"ok   fault_{list(fault_env)[0]}")
            tests += 1

        try:
            run_driver(driver, lib_dir, nonce_a, {"SPP_DIAG_CUDA_FAKE_FORCE_TIMEOUT": "1"}, timeout=1.0)
            raise AssertionError("expected timeout")
        except subprocess.TimeoutExpired:
            pass
        print("ok   timeout_detected_by_caller_deadline")
        tests += 1

        result_bad_nonce = run_driver(driver, lib_dir, "not-hex")
        assert result_bad_nonce.returncode != 0
        assert result_bad_nonce.stdout.strip() == ""
        print("ok   malformed_nonce_rejects")
        tests += 1

        print(f"SPP diagnostic CUDA driver: ok ({tests} tests)")
        return 0


if __name__ == "__main__":
    sys.exit(main())
