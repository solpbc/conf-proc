#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent AC2 parser for adapter reservation and task-lifecycle frames."""

from __future__ import annotations

import struct
import subprocess
import sys


def frames(raw: bytes):
    length = int.from_bytes(raw[:4], "big")
    stream = raw[4:]
    if len(stream) != length:
        raise AssertionError("fixture length prefix mismatch")
    offset = 4 + 4 + 192
    found = []
    while offset < len(raw):
        frame_len = int.from_bytes(raw[offset:offset + 4], "big")
        data = raw[offset + 4:offset + 4 + frame_len]
        if len(data) != frame_len or frame_len < 44:
            raise AssertionError("malformed frame")
        event, _flags, payload_len, sequence, task, parent, op, phase, _ = struct.unpack(
            ">HHIQQQQHH", data[:44]
        )
        if payload_len != len(data) - 44:
            raise AssertionError("payload length mismatch")
        found.append((event, sequence, task, parent, op, phase, data[44:]))
        offset += 4 + frame_len
    return found


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: runtime-exec-lifecycle-oracle-selftest.py FIXTURE")
    fixture = sys.argv[1]
    items = frames(subprocess.check_output([fixture]))
    events = [item[0] for item in items]
    if events.count(7) != 1 or events.count(8) != 1 or events.count(0x105) != 1:
        print(f"FAIL lifecycle event counts {events}")
        return 1
    attempts = [item for item in items if item[0] == 5]
    paths = [item[6][16:] for item in attempts]
    if paths.count(b"/sbin/init") != 2 or paths.count(b"/usr/bin/env") != 1:
        print(f"FAIL frozen-path/pass counts {paths}")
        return 1
    kernel = [item for item in attempts if item[6][16:] == b"/sbin/init"]
    if [int.from_bytes(item[6][:4], "big") for item in kernel] != [1, 2]:
        print("FAIL recursive bprm pass count did not increment")
        return 1
    if sum(1 for item in items if item[0] == 6) != 2 or sum(1 for item in items if item[0] == 0x104) != 3:
        print("FAIL commit/return lifecycle count")
        return 1
    file_attempt = next(item for item in items if item[0] == 0x100)
    if kernel[0][4] != file_attempt[4] + 1:
        print("FAIL exec reservation consumed an operation ordinal before promotion")
        return 1
    for mode in ("--wrong-token", "--unsupported", "--pre-bprm-failure"):
        mutation = subprocess.run([fixture, mode], check=False)
        if mutation.returncode != 42:
            print(f"FAIL {mode} mutation exit={mutation.returncode}, want 42")
            return 1
    print("ok   adapter exec/lifecycle interleaving, frozen-path, denial, and kthread cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
