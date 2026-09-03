#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent literal oracle for AC2 full-stream trace scenario."""

from __future__ import annotations

import hashlib
import struct
import subprocess
import sys

from conf_proc_spp_diag_trace_semantic_fixture import (
    CONTROL_PLAN_HEX,
    EXPECTED_LEDGER_HEX,
    STREAM_HEX,
)

PID_TGID_OFFSETS = (296, 300, 462, 466, 3846, 3850, 4061, 4065, 4280, 4284)


def transform_stream(raw: bytes) -> bytes:
    """Transform mock root PID/TGID 1001 (0x03e9) to real root PID/TGID 1 (0x0001)."""
    buf = bytearray(raw)
    for offset in PID_TGID_OFFSETS:
        val = int.from_bytes(buf[offset : offset + 4], "big")
        if val != 1001:
            raise ValueError(f"Offset {offset} expected 1001 (0x03e9), found {val}")
        buf[offset : offset + 4] = struct.pack(">I", 1)
    return bytes(buf)


def transform_ledger(raw: bytes) -> bytes:
    """Transform mock root PID/TGID in ledger JSON text to 1."""
    target_pid = b'"pid_hex":"000003e9"'
    target_tgid = b'"tgid_hex":"000003e9"'

    if raw.count(target_pid) != 1:
        raise ValueError(
            f"Expected exactly 1 occurrence of {target_pid!r}, found {raw.count(target_pid)}"
        )
    if raw.count(target_tgid) != 1:
        raise ValueError(
            f"Expected exactly 1 occurrence of {target_tgid!r}, found {raw.count(target_tgid)}"
        )

    modified = raw.replace(target_pid, b'"pid_hex":"00000001"', 1)
    modified = modified.replace(target_tgid, b'"tgid_hex":"00000001"', 1)
    return modified


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <fixture_binary>", file=sys.stderr)
        sys.exit(1)

    fixture_bin = sys.argv[1]

    # 1. Baseline verification against transformed STREAM_HEX
    expected_stream = transform_stream(bytes.fromhex(STREAM_HEX))
    actual_stream = subprocess.check_output([fixture_bin])

    if len(actual_stream) != len(expected_stream):
        print(
            f"FAIL: Stream length mismatch: actual {len(actual_stream)}, expected {len(expected_stream)}",
            file=sys.stderr,
        )
        sys.exit(1)

    if actual_stream != expected_stream:
        for i in range(min(len(actual_stream), len(expected_stream))):
            if actual_stream[i] != expected_stream[i]:
                print(
                    f"FAIL: First mismatch at byte {i} (0x{i:04x}): "
                    f"actual=0x{actual_stream[i]:02x}, expected=0x{expected_stream[i]:02x}",
                    file=sys.stderr,
                )
                break
        sys.exit(1)

    expected_sha = hashlib.sha256(expected_stream).hexdigest()
    actual_sha = hashlib.sha256(actual_stream).hexdigest()
    print(f"PASS: AC2 stream byte-for-byte exact match (sha256: {actual_sha})")

    # Transform ledger to verify transform validity
    _ = transform_ledger(bytes.fromhex(EXPECTED_LEDGER_HEX))

    # 2. Mutation tests (confirm rejection and restoration)
    mutations = [
        ("--mutate-task-correlation", 42, "task correlation"),
        ("--mutate-op-close", 43, "operation close"),
        ("--mutate-phase-order", 44, "phase order"),
        ("--mutate-terminal", 45, "terminal"),
    ]

    for flag, expected_code, name in mutations:
        proc = subprocess.run([fixture_bin, flag], capture_output=True)
        if proc.returncode != expected_code:
            print(
                f"FAIL: Mutation {name} expected exit code {expected_code}, got {proc.returncode}",
                file=sys.stderr,
            )
            print(f"Stderr: {proc.stderr.decode('utf-8', errors='replace')}", file=sys.stderr)
            sys.exit(1)
        print(f"PASS: Mutation {name} rejected as expected (exit code {proc.returncode})")

    # Verify baseline is fully functional after mutations
    restored_stream = subprocess.check_output([fixture_bin])
    if restored_stream != expected_stream:
        print("FAIL: Baseline restoration mismatch after mutations", file=sys.stderr)
        sys.exit(1)
    print("PASS: Baseline restoration confirmed")


if __name__ == "__main__":
    main()
