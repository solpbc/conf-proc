#!/usr/bin/env python3
"""Independent literal oracle for the SPP diagnostic structural C ABI.

This file is derived only from the reviewed wire prose.  It does not import,
parse, or generate values from the production C header, implementation, or
same-lode native tests.  Its sole production-facing input is a thin executable
that returns raw tab-separated numeric results, decoded fields, and bytes.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


SOURCE_COMMIT = bytes.fromhex("91a8e826012fbb1c7f5cb2a326c08b13e390f469")
HEADER_DOMAIN = b"sol-spp-diag-trace-header/v1"
FRAME_DOMAIN = b"sol-spp-diag-trace-frame/v1"
IMA_LABEL = b"sol_spp_diag_trace"


def be(value: int, width: int) -> bytes:
    if value < 0 or value >= 1 << (8 * width):
        raise AssertionError(f"integer {value} does not fit {width} bytes")
    return value.to_bytes(width, "big")


def header(challenge: bytes, run: bytes, control: bytes, cmdline: bytes) -> bytes:
    for value in (challenge, run, control, cmdline):
        if len(value) != 32:
            raise AssertionError("header opaque fields must be 32 bytes")
    raw = b"".join(
        (
            b"SPPTRC1\x00",
            be(1, 2),
            be(192, 2),
            be(1, 2),
            be(1, 2),
            be(524288, 4),
            be(268435456, 8),
            be(1088, 4),
            SOURCE_COMMIT,
            challenge,
            run,
            control,
            cmdline,
            be(15, 8),
            bytes(4),
        )
    )
    if len(raw) != 192:
        raise AssertionError(f"oracle header is {len(raw)} bytes")
    return raw


def command(kind: int, phase: int, challenge: bytes, run: bytes, control: bytes) -> bytes:
    raw = b"".join(
        (
            b"SPPCMD1\x00",
            be(1, 2),
            be(kind, 2),
            be(128, 4),
            challenge,
            run,
            control,
            be(phase, 2),
            bytes(14),
        )
    )
    if len(raw) != 128:
        raise AssertionError(f"oracle command is {len(raw)} bytes")
    return raw


def ima(
    kind: int,
    state: int,
    challenge: bytes,
    run: bytes,
    control: bytes,
    cmdline: bytes,
    frame_count: int,
    stream_bytes: int,
    chain: bytes,
    denied: int,
    committed: int,
) -> bytes:
    if len(chain) != 32:
        raise AssertionError("chain must be 32 bytes")
    raw = b"".join(
        (
            b"SPPIMA1\x00",
            be(1, 2),
            be(kind, 2),
            be(256, 4),
            be(1, 2),
            be(1, 2),
            be(state, 2),
            bytes(2),
            SOURCE_COMMIT,
            challenge,
            run,
            control,
            cmdline,
            be(frame_count, 8),
            be(stream_bytes, 8),
            chain,
            be(15, 8),
            be(denied, 8),
            be(committed, 8),
            bytes(4),
            bytes(4),
            bytes(4),
        )
    )
    if len(raw) != 256:
        raise AssertionError(f"oracle IMA record is {len(raw)} bytes")
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
    if len(raw) != 44 + len(payload) or len(raw) > 1088:
        raise AssertionError(f"oracle frame is {len(raw)} bytes")
    return raw


def denied_payload(path: bytes, pid: int, tgid: int, task_flags: int) -> bytes:
    return b"".join((be(13, 2), be(len(path), 2), be(pid, 4), be(tgid, 4), be(task_flags, 8), path))


def release_payload(pid: int, tgid: int, denied: int) -> bytes:
    return be(pid, 4) + be(tgid, 4) + be(denied, 8)


def attempt_payload(pass_index: int, path: bytes, pid: int, tgid: int) -> bytes:
    return b"".join((be(pass_index, 4), be(len(path), 2), bytes(2), be(pid, 4), be(tgid, 4), path))


def commit_payload(pass_count: int, pid: int, tgid: int) -> bytes:
    return be(pass_count, 4) + be(pid, 4) + be(tgid, 4) + bytes(4)


def created_payload(pid: int, tgid: int, clone_flags: int) -> bytes:
    return be(pid, 4) + be(tgid, 4) + be(clone_flags, 8)


def marker_payload(previous: int, following: int) -> bytes:
    return be(previous, 2) + be(following, 2) + bytes(4)


def invoke(harness: Path, operation: str, *args: object) -> list[str]:
    command_line = [str(harness), operation, *(str(value) for value in args)]
    result = subprocess.run(
        command_line, check=False, capture_output=True, text=True, timeout=5
    )
    if result.returncode != 0:
        raise AssertionError(
            f"{operation} harness exit {result.returncode}: {result.stderr.strip()}"
        )
    if result.stderr:
        raise AssertionError(f"{operation} wrote stderr: {result.stderr.strip()}")
    return result.stdout.rstrip("\n").split("\t")


def expect_encode(
    harness: Path, operation: str, expected: bytes, *args: object
) -> None:
    actual = invoke(harness, operation, *args)
    wanted = ["0", str(len(expected)), str(len(expected)), expected.hex()]
    if actual != wanted:
        raise AssertionError(f"{operation}: expected {wanted}, got {actual}")


def expect_decode(
    harness: Path, operation: str, encoded: bytes, fields: list[str]
) -> None:
    actual = invoke(harness, operation, encoded.hex())
    wanted = ["0", str(len(encoded)), *fields]
    if actual != wanted:
        raise AssertionError(f"{operation}: expected {wanted}, got {actual}")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: conf-proc-spp-diag-trace-oracle-selftest.py HARNESS")
    harness = Path(sys.argv[1]).resolve()

    zero = bytes(32)
    challenge = bytes(range(0, 32))
    run = bytes(range(32, 64))
    control = bytes(range(64, 96))
    cmdline = bytes(range(96, 128))
    chain_a = bytes(range(128, 160))
    chain_b = bytes(range(160, 192))

    headers = (
        (zero, zero, zero, zero),
        (challenge, run, control, cmdline),
    )
    for fields in headers:
        encoded = header(*fields)
        hex_fields = [field.hex() for field in fields]
        expect_encode(harness, "header-encode", encoded, encoded.hex())
        expect_decode(harness, "header-decode", encoded, hex_fields)

    dense_header = header(challenge, run, control, cmdline)
    preimage = HEADER_DOMAIN + be(192, 4) + dense_header
    if len(HEADER_DOMAIN) != 28 or len(preimage) != 224:
        raise AssertionError("header domain/preimage length drift")
    expect_encode(harness, "header-preimage", preimage, dense_header.hex())

    commands = (
        (1, 2, challenge, run, control),
        (1, 9, zero, zero, zero),
        (1, 14, challenge, run, control),
        (2, 15, challenge, run, control),
    )
    for kind, phase, cmd_challenge, cmd_run, cmd_control in commands:
        encoded = command(kind, phase, cmd_challenge, cmd_run, cmd_control)
        args = (
            kind,
            phase,
            cmd_challenge.hex(),
            cmd_run.hex(),
            cmd_control.hex(),
        )
        expect_encode(harness, "command-encode", encoded, encoded.hex())
        expect_decode(
            harness,
            "command-decode",
            encoded,
            [
                str(kind),
                str(phase),
                cmd_challenge.hex(),
                cmd_run.hex(),
                cmd_control.hex(),
            ],
        )

    ima_vectors = (
        (1, 1, zero, zero, zero, zero, 1, 244, zero, 0, 0, b"sol-spp-diag-ready-v1"),
        (2, 2, challenge, run, control, cmdline, 7, 500, chain_a, 3, 2, b"sol-spp-diag-release-v1"),
        (
            3,
            3,
            challenge,
            run,
            control,
            cmdline,
            524288,
            268435456,
            chain_b,
            524288,
            123,
            b"sol-spp-diag-terminal-v1",
        ),
    )
    for (
        kind,
        state,
        ima_challenge,
        ima_run,
        ima_control,
        ima_cmdline,
        frame_count,
        stream_bytes,
        chain,
        denied,
        committed,
        event_name,
    ) in ima_vectors:
        encoded = ima(
            kind,
            state,
            ima_challenge,
            ima_run,
            ima_control,
            ima_cmdline,
            frame_count,
            stream_bytes,
            chain,
            denied,
            committed,
        )
        args = (
            kind,
            state,
            ima_challenge.hex(),
            ima_run.hex(),
            ima_control.hex(),
            ima_cmdline.hex(),
            frame_count,
            stream_bytes,
            chain.hex(),
            denied,
            committed,
        )
        expect_encode(harness, "ima-encode", encoded, encoded.hex())
        expect_decode(
            harness,
            "ima-decode",
            encoded,
            [str(value) for value in args],
        )
        vocabulary = invoke(
            harness, "ima-vocabulary", encoded.hex(), event_name.hex()
        )
        if vocabulary != ["0"]:
            raise AssertionError(
                f"IMA vocabulary {kind}: expected result 0, got {vocabulary}"
            )

    label = invoke(harness, "ima-label")
    if label != ["0", "18", IMA_LABEL.hex()]:
        raise AssertionError(f"IMA label mismatch: {label}")

    path_one = b"/"
    path_inner = b"/usr/lib/sol/diagnostic"
    path_max = b"P" * 1024
    maximum32 = (1 << 32) - 1
    maximum64 = (1 << 64) - 1
    frame_vectors = (
        ("core-init", frame(1, 0, 0, 0, 0, 0, 0, b"")),
        (
            "denied-min",
            frame(2, 0, 1, 0, 0, 1, 0, denied_payload(path_one, 1, 1, 0)),
        ),
        (
            "denied-max",
            frame(
                2,
                0,
                maximum64,
                maximum64,
                0,
                maximum64,
                0,
                denied_payload(path_max, maximum32, maximum32, maximum64),
            ),
        ),
        ("ima-ready-zero", frame(3, 0, 2, 0, 0, 0, 0, be(0, 8))),
        ("ima-ready-max", frame(3, 0, 3, 0, 0, 0, 0, be(maximum64, 8))),
        (
            "userspace-release-min",
            frame(4, 0, 4, 1, 0, 0, 0, release_payload(1, 1, 0)),
        ),
        (
            "userspace-release-max",
            frame(
                4,
                0,
                5,
                maximum64,
                0,
                0,
                0,
                release_payload(maximum32, maximum32, maximum64),
            ),
        ),
        (
            "exec-attempt-prerelease",
            frame(5, 1, 6, 1, 0, 1, 0, attempt_payload(1, path_one, 1, 1)),
        ),
        (
            "exec-attempt-init",
            frame(
                5,
                0,
                7,
                2,
                0,
                2,
                1,
                attempt_payload(2, path_inner, 2, 3),
            ),
        ),
        (
            "exec-attempt-finalize",
            frame(
                5,
                0,
                8,
                maximum64,
                0,
                maximum64,
                14,
                attempt_payload(maximum32, path_max, maximum32, maximum32),
            ),
        ),
        ("exec-commit-min", frame(6, 0, 9, 1, 0, 1, 1, commit_payload(1, 1, 1))),
        (
            "exec-commit-max",
            frame(
                6,
                0,
                10,
                maximum64,
                0,
                maximum64,
                14,
                commit_payload(maximum32, maximum32, maximum32),
            ),
        ),
        ("task-alloc-zero", frame(7, 0, 11, 2, 1, 1, 1, be(0, 8))),
        (
            "task-alloc-max",
            frame(7, 0, 12, maximum64, maximum64 - 1, maximum64, 14, be(maximum64, 8)),
        ),
        (
            "task-created-zero",
            frame(8, 0, 13, 2, 1, 1, 1, created_payload(1, 1, 0)),
        ),
        (
            "task-created-max",
            frame(
                8,
                0,
                14,
                maximum64,
                maximum64 - 1,
                maximum64,
                14,
                created_payload(maximum32, maximum32, maximum64),
            ),
        ),
        ("phase-marker-min", frame(9, 0, 15, 1, 0, 0, 2, marker_payload(1, 2))),
        ("phase-marker-mid", frame(9, 0, 16, 2, 0, 0, 8, marker_payload(7, 8))),
        (
            "phase-marker-max",
            frame(9, 0, 17, maximum64, 0, 0, 14, marker_payload(13, 14)),
        ),
        ("terminal", frame(10, 0, maximum64, 0, 0, 0, 15, b"")),
    )
    if len(FRAME_DOMAIN) != 27:
        raise AssertionError("frame domain length drift")
    frame_digests: list[bytes] = []
    for name, encoded in frame_vectors:
        payload = encoded[44:]
        fields = [
            str(int.from_bytes(encoded[0:2], "big")),
            str(int.from_bytes(encoded[2:4], "big")),
            str(len(payload)),
            str(int.from_bytes(encoded[8:16], "big")),
            str(int.from_bytes(encoded[16:24], "big")),
            str(int.from_bytes(encoded[24:32], "big")),
            str(int.from_bytes(encoded[32:40], "big")),
            str(int.from_bytes(encoded[40:42], "big")),
            payload.hex(),
        ]
        expect_encode(harness, "frame-encode", encoded, encoded.hex())
        expect_decode(harness, "frame-decode", encoded, fields)
        for previous in (zero, chain_a):
            preimage = FRAME_DOMAIN + previous + be(len(encoded), 4) + encoded
            expect_encode(
                harness,
                "frame-preimage",
                preimage,
                encoded.hex(),
                previous.hex(),
            )
            frame_digests.append(hashlib.sha256(preimage).digest())
        if frame_digests[-1] == frame_digests[-2]:
            raise AssertionError(f"{name}: previous chain did not change digest")

    digest_set = hashlib.sha256(b"".join(frame_digests)).hexdigest()

    print(
        "ok   independent fixed-object/frame oracle "
        f"header_preimage_sha256={hashlib.sha256(HEADER_DOMAIN + be(192, 4) + dense_header).hexdigest()} "
        f"frame_vectors={len(frame_vectors)} frame_preimages={len(frame_digests)} "
        f"frame_digest_set_sha256={digest_set}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
