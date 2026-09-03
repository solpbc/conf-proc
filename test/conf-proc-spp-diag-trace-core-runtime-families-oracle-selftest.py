#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent literal oracle for K3 runtime families (exec, file_open, mmap, mprotect)."""

from __future__ import annotations

import hashlib
import struct
import subprocess
import sys


SOURCE_COMMIT = bytes.fromhex("91a8e826012fbb1c7f5cb2a326c08b13e390f469")
HEADER_DOMAIN = b"sol-spp-diag-trace-header/v1"
FRAME_DOMAIN = b"sol-spp-diag-trace-frame/v1"
CANARY = b"/usr/local/libexec/solstone/pre-release-denied"
COMMAND_LINE = (
    b"ima_policy=critical_data "
    b"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
    b"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
    b"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
)


def frame(
    event: int, sequence: int, task: int, parent: int, operation: int, phase: int, payload: bytes
) -> bytes:
    return struct.pack(
        ">HHIQQQQHH", event, 0, len(payload), sequence, task, parent, operation, phase, 0
    ) + payload


def expected() -> bytes:
    challenge = bytes(range(32))
    run = bytes(range(32, 64))
    control = bytes(range(64, 96))
    command_hash = hashlib.sha256(COMMAND_LINE).digest()
    header = b"".join(
        (
            b"SPPTRC1\0",
            struct.pack(">HHHHIQI", 1, 192, 2, 1, 524288, 268435456, 1088),
            SOURCE_COMMIT,
            challenge,
            run,
            control,
            command_hash,
            struct.pack(">QI", 0xFFFF, 0),
        )
    )
    assert len(header) == 192

    exec_path = b"/usr/bin/python3"
    file_path = b"/etc/ld.so.cache"

    frames = (
        # 1-4: Bootstrap prefix
        frame(1, 0, 0, 0, 0, 0, b""),
        frame(2, 1, 0, 0, 1, 0, struct.pack(">HHIIQ", 13, len(CANARY), 1, 1, 0) + CANARY),
        frame(3, 2, 0, 0, 0, 0, struct.pack(">Q", 1)),
        frame(4, 3, 1, 0, 0, 0, struct.pack(">IIQ", 1, 1, 1)),
        # 5-8: Exec family (op 2)
        frame(5, 4, 1, 0, 2, 1, struct.pack(">IHHII", 1, len(exec_path), 0, 1, 1) + exec_path),
        frame(5, 5, 1, 0, 2, 1, struct.pack(">IHHII", 2, len(exec_path), 0, 1, 1) + exec_path),
        frame(6, 6, 1, 0, 2, 1, struct.pack(">IIII", 2, 1, 1, 0)),
        frame(0x0104, 7, 1, 0, 2, 1, struct.pack(">HHIQ", 6, 0, 0, 0)),
        # 9-11: File open family (op 3)
        frame(
            0x0100,
            8,
            1,
            0,
            3,
            1,
            struct.pack(">HHHHII", 1, len(file_path), 1, 8, 0xFFFFFF9C, 0) + file_path,
        ),
        frame(
            0x0101,
            9,
            1,
            0,
            3,
            1,
            struct.pack(">HHHHIIIIQQQ", 1, 8, 1, 1, 0, 0xEF53, 8, 1, 12345, 67890, 4096),
        ),
        frame(0x0104, 10, 1, 0, 3, 1, struct.pack(">HHIQ", 1, 0, 0, 0)),
        # 12-13: MMAP family (op 4)
        frame(
            0x0102,
            11,
            1,
            0,
            4,
            1,
            struct.pack(
                ">HHHHIIIIIIIIQQQ", 1, 1, 2, 2, 5, 5, 0, 0, 0xEF53, 8, 1, 0, 2000, 3000, 8192
            ),
        ),
        frame(0x0104, 12, 1, 0, 4, 1, struct.pack(">HHIQ", 2, 0, 0, 0)),
        # 14-16: MPROTECT family (op 5)
        frame(
            0x0102,
            13,
            1,
            0,
            5,
            1,
            struct.pack(
                ">HHHHIIIIIIIIQQQ", 2, 1, 2, 2, 7, 7, 1, 0, 0xEF53, 8, 1, 0, 2000, 3000, 8192
            ),
        ),
        frame(
            0x0102,
            14,
            1,
            0,
            5,
            1,
            struct.pack(
                ">HHHHIIIIIIIIQQQ",
                2,
                2,
                2,
                2,
                7,
                7,
                1,
                0x80000001,
                0xEF53,
                8,
                1,
                0,
                2000,
                3000,
                8192,
            ),
        ),
        frame(0x0104, 15, 1, 0, 5, 1, struct.pack(">HHIQ", 3, 0, 0, 0xFFFFFFFFFFFFFFFF)),
        # 17-18: CONNECT family (op 6)
        frame(
            0x0103,
            16,
            1,
            0,
            6,
            1,
            struct.pack(
                ">HHHHHHHHIIIQHHII16s",
                1,
                1,
                1,
                1,
                1,
                6,
                2,
                16,
                0,
                0,
                0,
                0x1122334455667788,
                443,
                0,
                0,
                0,
                bytes([0] * 12 + [10, 0, 0, 1]),
            ),
        ),
        frame(0x0104, 17, 1, 0, 6, 1, struct.pack(">HHIQ", 4, 0, 0, 0)),
        # 19-20: SENDMSG family (op 7)
        frame(
            0x0103,
            18,
            1,
            0,
            7,
            1,
            struct.pack(
                ">HHHHHHHHIIIQHHII16s",
                2,
                2,
                2,
                2,
                2,
                17,
                10,
                0,
                0x8000000D,
                0,
                512,
                0x99AABBCCDDEEFF00,
                53,
                0,
                1,
                2,
                bytes([0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            ),
        ),
        frame(0x0104, 19, 1, 0, 7, 1, struct.pack(">HHIQ", 5, 0, 0, 0xFFFFFFFFFFFFFFF3)),
    )

    stream = struct.pack(">I", len(header)) + header
    for raw_frame in frames:
        stream += struct.pack(">I", len(raw_frame)) + raw_frame
    return stream


def decode_blob(raw: bytes) -> bytes:
    if len(raw) < 4:
        raise AssertionError("truncated fixture length")
    length = int.from_bytes(raw[:4], "big")
    blob = raw[4 : 4 + length]
    if len(blob) != length or len(raw) != 4 + length:
        raise AssertionError(f"fixture framing mismatch: len(blob)={len(blob)}, expected={length}")
    return blob


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: runtime-families-oracle-selftest.py FIXTURE")
    actual = decode_blob(subprocess.check_output([sys.argv[1]]))
    wanted = expected()
    label = "20-frame runtime families stream"
    if actual != wanted:
        print(f"FAIL {label}: got len={len(actual)}, expected len={len(wanted)}")
        # Print first byte diff
        for i in range(min(len(actual), len(wanted))):
            if actual[i] != wanted[i]:
                print(f"  First mismatch at byte {i}: got 0x{actual[i]:02x}, want 0x{wanted[i]:02x}")
                break
        return 1
    mutated = bytearray(wanted)
    mutated[-1] ^= 1
    if actual == bytes(mutated):
        print(f"FAIL {label}: mutation control did not turn red")
        return 1
    print(f"ok   {label} bytes={len(actual)} sha256={hashlib.sha256(actual).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
