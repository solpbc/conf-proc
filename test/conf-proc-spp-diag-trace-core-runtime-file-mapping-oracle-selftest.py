#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""AC4 parser for adapter-derived file and executable-mapping facts."""

from __future__ import annotations

import struct
import subprocess
import sys


def payloads(raw: bytes, event: int) -> list[bytes]:
    length = int.from_bytes(raw[:4], "big")
    if length != len(raw) - 4:
        raise AssertionError("fixture length mismatch")
    offset, result = 4 + 4 + 192, []
    while offset < len(raw):
        frame_len = int.from_bytes(raw[offset:offset + 4], "big")
        frame = raw[offset + 4:offset + 4 + frame_len]
        kind, _flags, payload_len = struct.unpack(">HHI", frame[:8])
        if payload_len != len(frame) - 44:
            raise AssertionError("bad frame payload")
        if kind == event:
            result.append(frame[44:])
        offset += 4 + frame_len
    return result


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: runtime-file-mapping-oracle-selftest.py FIXTURE")
    fixture = sys.argv[1]
    raw = subprocess.check_output([fixture])
    files = payloads(raw, 0x101)
    maps = payloads(raw, 0x102)
    if len(files) != 1 or len(maps) != 2:
        print(f"FAIL file/mapping event counts file={len(files)} map={len(maps)}")
        return 1
    if int.from_bytes(files[0][8:12], "big") != 0:
        print("FAIL file fact did not preserve allow result")
        return 1
    # Mapping payload result is the eighth u32 after four u16 fields.
    results = [int.from_bytes(item[20:24], "big") for item in maps]
    if results != [0x80000001, 0x80000001]:
        print(f"FAIL signed kernel results were not wire-normalized: {results!r}")
        return 1
    for mode in ("--fmode-red", "--mapping-red", "--shm-red"):
        red = subprocess.run([fixture, mode], check=False)
        if red.returncode != 42:
            print(f"FAIL {mode} did not sticky-red: exit={red.returncode}")
            return 1
    print("ok   adapter file/mapping facts, FMODE_EXEC twin, and unsupported red paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
