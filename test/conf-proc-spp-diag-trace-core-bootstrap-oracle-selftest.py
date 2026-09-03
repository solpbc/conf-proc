#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent literal oracle for the four-frame K2 bootstrap prefix."""

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


def frame(event: int, sequence: int, task: int, operation: int, payload: bytes) -> bytes:
    return struct.pack(
        ">HHIQQQQHH", event, 0, len(payload), sequence, task, 0, operation, 0, 0
    ) + payload


def expected() -> tuple[bytes, bytes, bytes]:
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
    denial_payload = struct.pack(">HHIIQ", 13, len(CANARY), 1, 1, 0) + CANARY
    frames = (
        frame(1, 0, 0, 0, b""),
        frame(2, 1, 0, 1, denial_payload),
        frame(3, 2, 0, 0, struct.pack(">Q", 1)),
        frame(4, 3, 1, 0, struct.pack(">IIQ", 1, 1, 1)),
    )
    chain = hashlib.sha256(HEADER_DOMAIN + struct.pack(">I", len(header)) + header).digest()
    stream = struct.pack(">I", len(header)) + header
    records: list[bytes] = []
    for index, raw_frame in enumerate(frames):
        chain = hashlib.sha256(
            FRAME_DOMAIN + chain + struct.pack(">I", len(raw_frame)) + raw_frame
        ).digest()
        stream += struct.pack(">I", len(raw_frame)) + raw_frame
        if index in (2, 3):
            kind = 1 if index == 2 else 2
            record = b"".join(
                (
                    b"SPPIMA1\0",
                    struct.pack(">HHIHHH", 1, kind, 256, 2, 1, kind),
                    bytes(2),
                    SOURCE_COMMIT,
                    challenge,
                    run,
                    control,
                    command_hash,
                    struct.pack(">QQ", index + 1, len(stream)),
                    chain,
                    bytes(8),
                    struct.pack(">QQ", 0xFFFF, 1),
                    bytes(12),
                )
            )
            assert len(record) == 256
            records.append(record)
    return stream, records[0], records[1]


def decode_blobs(raw: bytes) -> tuple[bytes, bytes, bytes]:
    blobs: list[bytes] = []
    offset = 0
    for _ in range(3):
        if offset + 4 > len(raw):
            raise AssertionError("truncated fixture length")
        length = int.from_bytes(raw[offset : offset + 4], "big")
        offset += 4
        blobs.append(raw[offset : offset + length])
        offset += length
    if offset != len(raw) or len(blobs) != 3:
        raise AssertionError("fixture framing mismatch")
    return blobs[0], blobs[1], blobs[2]


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: bootstrap-oracle-selftest.py FIXTURE")
    actual = decode_blobs(subprocess.check_output([sys.argv[1]]))
    wanted = expected()
    labels = ("four-frame stream", "READY record", "RELEASE record")
    for label, got, want in zip(labels, actual, wanted):
        if got != want:
            print(f"FAIL {label}: got={got.hex()} expected={want.hex()}")
            return 1
        mutated = bytearray(want)
        mutated[-1] ^= 1
        if got == bytes(mutated):
            print(f"FAIL {label}: mutation control did not turn red")
            return 1
        print(f"ok   {label} bytes={len(got)} sha256={hashlib.sha256(got).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
