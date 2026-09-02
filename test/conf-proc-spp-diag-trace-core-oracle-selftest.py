#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent field-tuple oracle for the SPP diagnostic kernel trace core."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


SOURCE_COMMIT = bytes.fromhex("91a8e826012fbb1c7f5cb2a326c08b13e390f469")
HEADER_DOMAIN = b"sol-spp-diag-trace-header/v1"
FRAME_DOMAIN = b"sol-spp-diag-trace-frame/v1"
WIRE_EVENT = 10


def be(value: int, width: int) -> bytes:
    if value < 0 or value >= 1 << (8 * width):
        raise AssertionError(f"integer {value} does not fit {width} bytes")
    return value.to_bytes(width, "big")


def header(challenge: bytes, run: bytes, control: bytes, cmdline: bytes) -> bytes:
    for value in (challenge, run, control, cmdline):
        if len(value) != 32:
            raise AssertionError("identity fields must be 32 bytes")
    raw = b"".join(
        (
            b"SPPTRC1\x00",
            be(1, 2),
            be(192, 2),
            be(2, 2),
            be(1, 2),
            be(524288, 4),
            be(268435456, 8),
            be(1088, 4),
            SOURCE_COMMIT,
            challenge,
            run,
            control,
            cmdline,
            be(0xFFFF, 8),
            bytes(4),
        )
    )
    if len(raw) != 192:
        raise AssertionError(f"oracle header is {len(raw)} bytes")
    return raw


def frame(
    event: int,
    flags: int,
    sequence: int,
    task: int,
    parent: int,
    operation: int,
    phase: int,
    payload: bytes,
) -> bytes:
    raw = b"".join(
        (
            be(event, 2),
            be(flags, 2),
            be(len(payload), 4),
            be(sequence, 8),
            be(task, 8),
            be(parent, 8),
            be(operation, 8),
            be(phase, 2),
            bytes(2),
            payload,
        )
    )
    if len(raw) != 44 + len(payload):
        raise AssertionError(f"oracle frame is {len(raw)} bytes")
    return raw


def frame_tuple(
    event: int,
    flags: int,
    task: int,
    parent: int,
    operation: int,
    phase: int,
    payload: bytes,
) -> str:
    return (
        be(event, 2)
        + be(flags, 2)
        + be(task, 8)
        + be(parent, 8)
        + be(operation, 8)
        + be(phase, 2)
        + payload
    ).hex()


def header_chain_of(encoded_header: bytes) -> bytes:
    return hashlib.sha256(HEADER_DOMAIN + be(192, 4) + encoded_header).digest()


def roll_frame(previous: bytes, encoded_frame: bytes) -> bytes:
    return hashlib.sha256(
        FRAME_DOMAIN + previous + be(len(encoded_frame), 4) + encoded_frame
    ).digest()


def invoke(harness: Path, *args: object) -> list[str]:
    result = subprocess.run(
        [str(harness), *(str(value) for value in args)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"harness exit {result.returncode}: {result.stderr.strip()}"
        )
    if result.stderr:
        raise AssertionError(f"harness wrote stderr: {result.stderr.strip()}")
    return result.stdout.rstrip("\n").split("\t")


def expect_init(
    harness: Path,
    challenge: bytes,
    run: bytes,
    control: bytes,
    cmdline: bytes,
) -> None:
    encoded_header = header(challenge, run, control, cmdline)
    core_init = frame(1, 0, 0, 0, 0, 0, 0, b"")
    header_chain = header_chain_of(encoded_header)
    chain = roll_frame(header_chain, core_init)
    actual = invoke(
        harness, "init", challenge.hex(), run.hex(), control.hex(), cmdline.hex()
    )
    wanted = [
        "0",
        "0",
        "0",
        "1",
        "1",
        "244",
        "1",
        encoded_header.hex(),
        core_init.hex(),
        header_chain.hex(),
        chain.hex(),
        core_init.hex(),
    ]
    if actual != wanted:
        raise AssertionError(f"init: expected {wanted}, got {actual}")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: conf-proc-spp-diag-trace-core-oracle-selftest.py HARNESS"
        )
    harness = Path(sys.argv[1]).resolve()
    zero = bytes(32)
    challenge = bytes(range(0, 32))
    run = bytes(range(32, 64))
    control = bytes(range(64, 96))
    cmdline = bytes(range(96, 128))

    expect_init(harness, zero, zero, zero, zero)
    expect_init(harness, challenge, run, control, cmdline)

    encoded_header = header(challenge, run, control, cmdline)
    core_init = frame(1, 0, 0, 0, 0, 0, 0, b"")
    header_chain = header_chain_of(encoded_header)
    chain = roll_frame(header_chain, core_init)
    terminal = frame(10, 0, 1, 0, 0, 0, 15, b"")
    chain_after = roll_frame(chain, terminal)
    terminal_tuple = frame_tuple(10, 0, 0, 0, 0, 15, b"")
    actual = invoke(
        harness,
        "run",
        challenge.hex(),
        run.hex(),
        control.hex(),
        cmdline.hex(),
        terminal_tuple,
    )
    wanted = [
        "0",
        "0",
        "0",
        "1",
        "2",
        str(244 + 4 + 44),
        "2",
        encoded_header.hex(),
        core_init.hex(),
        header_chain.hex(),
        chain_after.hex(),
        core_init.hex(),
        terminal.hex(),
    ]
    if actual != wanted:
        raise AssertionError(f"run-terminal: expected {wanted}, got {actual}")

    ima_payload = be((1 << 64) - 1, 8)
    ima = frame(3, 0, 1, 0, 0, 0, 0, ima_payload)
    chain_ima = roll_frame(chain, ima)
    actual = invoke(
        harness,
        "run",
        challenge.hex(),
        run.hex(),
        control.hex(),
        cmdline.hex(),
        frame_tuple(3, 0, 0, 0, 0, 0, ima_payload),
    )
    wanted = [
        "0",
        "0",
        "0",
        "1",
        "2",
        str(244 + 4 + 52),
        "2",
        encoded_header.hex(),
        core_init.hex(),
        header_chain.hex(),
        chain_ima.hex(),
        core_init.hex(),
        ima.hex(),
    ]
    if actual != wanted:
        raise AssertionError(f"run-ima-ready: expected {wanted}, got {actual}")

    actual = invoke(
        harness,
        "run",
        challenge.hex(),
        run.hex(),
        control.hex(),
        cmdline.hex(),
        frame_tuple(1, 0, 0, 0, 0, 0, b""),
    )
    if actual[0] != str(WIRE_EVENT) or actual[1] != "1":
        raise AssertionError(f"caller CORE_INIT: {actual}")
    if actual[4] != "1":
        raise AssertionError("caller CORE_INIT published a frame")

    actual = invoke(
        harness,
        "mark",
        challenge.hex(),
        run.hex(),
        control.hex(),
        cmdline.hex(),
        "8",
        terminal_tuple,
    )
    if actual[0] != "8" or actual[1] != "1" or actual[4] != "1":
        raise AssertionError(f"mark-then-append: {actual}")

    other = invoke(
        harness, "init", bytes(32).hex(), bytes(32).hex(), bytes([1] + [0] * 31).hex(),
        bytes(32).hex(),
    )
    first = invoke(
        harness, "init", bytes(32).hex(), bytes(32).hex(), bytes(32).hex(), bytes(32).hex()
    )
    if other[7] == first[7] or other[9] == first[9] or other[10] == first[10]:
        raise AssertionError("distinct identities did not produce distinct captures")
    if other[8] != first[8]:
        raise AssertionError("CORE_INIT wire bytes must not depend on identity")

    print("ok   spp-diag-trace-core-oracle-selftest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
