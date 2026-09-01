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
STREAM_FAILURE_COUNT = 0x1122334455667788
STREAM_FAILURE_BYTES = 0x99AABBCCDDEEFF00
WIRE_LENGTH = 5
WIRE_VALUE = 6
WIRE_RESERVED = 7
WIRE_CAP = 8
WIRE_EVENT = 10
WIRE_FLAGS = 11
WIRE_STATE = 12


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


def with_sequence(encoded: bytes, sequence: int) -> bytes:
    if len(encoded) < 44:
        raise AssertionError("frame too short for sequence replacement")
    return encoded[:8] + be(sequence, 8) + encoded[16:]


def wire_stream(encoded_header: bytes, frames: tuple[bytes, ...]) -> bytes:
    if len(encoded_header) != 192:
        raise AssertionError("stream header must be 192 bytes")
    return be(192, 4) + encoded_header + b"".join(
        be(len(encoded), 4) + encoded for encoded in frames
    )


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


def expect_stream(
    harness: Path,
    encoded: bytes,
    result: int,
    frame_count: int | None = None,
) -> None:
    actual = invoke(harness, "stream-validate", encoded.hex())
    if result == 0:
        if frame_count is None:
            raise AssertionError("successful stream expectation needs frame count")
        wanted = ["0", str(len(encoded)), str(frame_count), str(len(encoded))]
    else:
        wanted = [
            str(result),
            "0",
            str(STREAM_FAILURE_COUNT),
            str(STREAM_FAILURE_BYTES),
        ]
    if actual != wanted:
        raise AssertionError(f"stream-validate: expected {wanted}, got {actual}")


def provenance_payload(path: bytes, access: int, modifiers: int, dirfd_bits: int) -> bytes:
    return b"".join(
        (
            b"\x00\x01",
            be(len(path), 2),
            be(access, 2),
            be(modifiers, 2),
            be(dirfd_bits, 4),
            bytes(4),
            path,
        )
    )


def file_policy_payload(
    access: int,
    modifiers: int,
    decision: int,
    object_kind: int,
    raw_result: int,
    filesystem_magic: int,
    device_major: int,
    device_minor: int,
    inode: int,
    mount_identity: int,
    observed_size: int,
) -> bytes:
    raw = b"".join(
        (
            be(access, 2),
            be(modifiers, 2),
            be(decision, 2),
            be(object_kind, 2),
            be(raw_result, 4),
            be(filesystem_magic, 4),
            be(device_major, 4),
            be(device_minor, 4),
            be(inode, 8),
            be(mount_identity, 8),
            be(observed_size, 8),
        )
    )
    if len(raw) != 48:
        raise AssertionError(f"file-policy payload is {len(raw)} bytes")
    return raw


def mapping_policy_payload(
    operation: int,
    decision: int,
    backing: int,
    mode: int,
    requested: int,
    effective: int,
    prior: int,
    raw_result: int,
    filesystem_magic: int,
    device_major: int,
    device_minor: int,
    seals: int,
    inode: int,
    mount_identity: int,
    observed_size: int,
) -> bytes:
    raw = b"".join(
        (
            be(operation, 2),
            be(decision, 2),
            be(backing, 2),
            be(mode, 2),
            be(requested, 4),
            be(effective, 4),
            be(prior, 4),
            be(raw_result, 4),
            be(filesystem_magic, 4),
            be(device_major, 4),
            be(device_minor, 4),
            be(seals, 4),
            be(inode, 8),
            be(mount_identity, 8),
            be(observed_size, 8),
        )
    )
    if len(raw) != 64:
        raise AssertionError(f"mapping-policy payload is {len(raw)} bytes")
    return raw


def network_policy_payload(
    operation: int,
    decision: int,
    endpoint_kind: int,
    endpoint_source: int,
    socket_kind: int,
    protocol: int,
    observed_family: int,
    address_length: int,
    raw_result: int,
    message_flags: int,
    message_size: int,
    socket_cookie: int,
    port: int,
    reserved: int,
    scope_id: int,
    flow_information: int,
    address: bytes,
) -> bytes:
    if len(address) != 16:
        raise AssertionError("network-policy address must be 16 bytes")
    raw = b"".join(
        (
            be(operation, 2),
            be(decision, 2),
            be(endpoint_kind, 2),
            be(endpoint_source, 2),
            be(socket_kind, 2),
            be(protocol, 2),
            be(observed_family, 2),
            be(address_length, 2),
            be(raw_result, 4),
            be(message_flags, 4),
            be(message_size, 4),
            be(socket_cookie, 8),
            be(port, 2),
            be(reserved, 2),
            be(scope_id, 4),
            be(flow_information, 4),
            address,
        )
    )
    if len(raw) != 64:
        raise AssertionError(f"network-policy payload is {len(raw)} bytes")
    return raw


def operation_return_payload(operation: int, raw_return: int) -> bytes:
    raw = b"".join((be(operation, 2), bytes(2), bytes(4), be(raw_return, 8)))
    if len(raw) != 16:
        raise AssertionError(f"operation-return payload is {len(raw)} bytes")
    return raw


def expect_provenance_encode(
    harness: Path, encoded: bytes, result: int = 0, capacity: int | None = None
) -> None:
    actual_capacity = 1088 if capacity is None else capacity
    actual = invoke(harness, "provenance-encode", encoded.hex(), actual_capacity)
    if result == 0:
        wanted = ["0", str(len(encoded)), str(len(encoded)), "0", encoded.hex()]
    elif result == 2:
        wanted = ["2", "0", str(len(encoded)), "1", ""]
    else:
        wanted = [str(result), "0", "0", "1", ""]
    if actual != wanted:
        raise AssertionError(f"provenance-encode: expected {wanted}, got {actual}")


def expect_provenance_decode(
    harness: Path, encoded: bytes, result: int = 0
) -> None:
    actual = invoke(harness, "provenance-decode", encoded.hex())
    if result == 0:
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
            bytes(1044 - len(payload)).hex(),
        ]
        wanted = ["0", str(len(encoded)), "0", *fields]
    else:
        wanted = [str(result), "0", "1"]
    if actual != wanted:
        raise AssertionError(f"provenance-decode: expected {wanted}, got {actual}")


def expect_provenance_preimage(
    harness: Path,
    encoded: bytes,
    chain: bytes,
    result: int = 0,
    capacity: int | None = None,
) -> bytes:
    expected = FRAME_DOMAIN + chain + be(len(encoded), 4) + encoded
    actual_capacity = 1151 if capacity is None else capacity
    actual = invoke(
        harness,
        "provenance-preimage",
        encoded.hex(),
        chain.hex(),
        actual_capacity,
    )
    if result == 0:
        wanted = ["0", str(len(expected)), str(len(expected)), "0", expected.hex()]
    elif result == 2:
        wanted = ["2", "0", str(len(expected)), "1", ""]
    else:
        wanted = [str(result), "0", "0", "1", ""]
    if actual != wanted:
        raise AssertionError(f"provenance-preimage: expected {wanted}, got {actual}")
    return expected


def replace(encoded: bytes, offset: int, replacement: bytes) -> bytes:
    return encoded[:offset] + replacement + encoded[offset + len(replacement) :]


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

    by_event = (
        frame_vectors[0][1],
        frame_vectors[1][1],
        frame_vectors[3][1],
        frame_vectors[5][1],
        frame_vectors[7][1],
        frame_vectors[10][1],
        frame_vectors[12][1],
        frame_vectors[14][1],
        frame_vectors[16][1],
        frame_vectors[19][1],
    )
    sequential = tuple(
        with_sequence(encoded, sequence)
        for sequence, encoded in enumerate(by_event)
    )
    positive_streams: list[tuple[str, bytes, int]] = [
        ("header-only", wire_stream(dense_header, ()), 0),
    ]
    for event, encoded in enumerate(by_event, start=1):
        positive_streams.append(
            (f"one-event-{event}", wire_stream(dense_header, (with_sequence(encoded, 0),)), 1)
        )
    positive_streams.extend(
        (
            ("all-events", wire_stream(dense_header, sequential), 10),
            (
                "nonsensical-order",
                wire_stream(
                    dense_header,
                    (with_sequence(by_event[9], 0), with_sequence(by_event[0], 1)),
                ),
                2,
            ),
            (
                "maximum-path",
                wire_stream(dense_header, (with_sequence(frame_vectors[2][1], 0),)),
                1,
            ),
        )
    )
    for name, encoded, count in positive_streams:
        expect_stream(harness, encoded, 0, count)
        if count and int.from_bytes(encoded[208:216], "big") != 0:
            raise AssertionError(f"{name}: first sequence is not zero")

    stream_prefix = be(192, 4) + dense_header
    negative_streams: list[tuple[str, bytes, int]] = []
    for short_len in range(4):
        negative_streams.append((f"short-{short_len}", bytes(short_len), 5))
    for prefix in (0, 1, 191, 193, 65536, maximum32):
        negative_streams.append(
            (f"header-prefix-{prefix}", be(prefix, 4) + dense_header, 5)
        )
    for length in (4, 5, 64, 127, 195):
        negative_streams.append(
            (f"header-truncated-{length}", stream_prefix[:length], 5)
        )
    bad_header = bytearray(stream_prefix)
    bad_header[4] ^= 0x01
    negative_streams.append(("header-magic", bytes(bad_header), 3))
    for suffix_len in (1, 2, 3):
        negative_streams.append(
            (f"trailing-prefix-{suffix_len}", stream_prefix + bytes(suffix_len), 5)
        )
    for declared, expected_result in ((0, 5), (43, 5), (44, 5), (1088, 5), (1089, 8)):
        negative_streams.append(
            (f"frame-prefix-{declared}", stream_prefix + be(declared, 4), expected_result)
        )

    core_zero = sequential[0]
    core_one = with_sequence(core_zero, 1)
    core_two = with_sequence(core_zero, 2)
    core_max = with_sequence(core_zero, maximum64)
    local_bad_event = bytearray(core_one)
    local_bad_event[0:2] = be(0, 2)
    local_bad_reserved = bytearray(core_one)
    local_bad_reserved[42:44] = be(1, 2)
    negative_streams.extend(
        (
            ("first-sequence-one", wire_stream(dense_header, (core_one,)), 13),
            ("first-sequence-max", wire_stream(dense_header, (core_max,)), 13),
            ("duplicate", wire_stream(dense_header, (core_zero, core_zero)), 13),
            ("gap", wire_stream(dense_header, (core_zero, core_two)), 13),
            (
                "backward",
                wire_stream(dense_header, (core_zero, core_one, core_zero)),
                13,
            ),
            (
                "local-before-sequence-event",
                wire_stream(dense_header, (bytes(local_bad_event),)),
                10,
            ),
            (
                "local-before-sequence-reserved",
                wire_stream(dense_header, (bytes(local_bad_reserved),)),
                7,
            ),
            ("late-prefix", wire_stream(dense_header, (core_zero,)) + b"\x00", 5),
            (
                "late-local",
                wire_stream(dense_header, (core_zero, bytes(local_bad_reserved))),
                7,
            ),
            ("late-sequence", wire_stream(dense_header, (core_zero, core_two)), 13),
        )
    )
    for _name, encoded, result in negative_streams:
        expect_stream(harness, encoded, result)

    stream_vector_digest = hashlib.sha256(
        b"".join(be(len(encoded), 4) + encoded for _, encoded, _ in positive_streams)
    ).hexdigest()

    provenance_min_literal = bytes.fromhex(
        "0100000000000011"
        "0000000000000000"
        "0000000000000001"
        "0000000000000000"
        "0000000000000001"
        "00010000"
        "0001000100010000ffffff9c000000002f"
    )
    provenance_interior_literal = bytes.fromhex(
        "010000000000001f"
        "1122334455667788"
        "0000000000000002"
        "0000000000000000"
        "0000000000000003"
        "00060000"
        "0001000f000300180000000500000000"
        "72656c61746976652f6c69622e736f"
    )
    if provenance_min_literal != frame(
        0x0100, 0, 0, 1, 0, 1, 1, provenance_payload(b"/", 1, 0, 0xFFFFFF9C)
    ):
        raise AssertionError("minimum provenance literal disagrees with prose builder")
    if provenance_interior_literal != frame(
        0x0100,
        0,
        0x1122334455667788,
        2,
        0,
        3,
        6,
        provenance_payload(b"relative/lib.so", 3, 0x0018, 5),
    ):
        raise AssertionError("interior provenance literal disagrees with prose builder")
    provenance_max = frame(
        0x0100,
        0,
        maximum64,
        maximum64,
        0,
        maximum64,
        14,
        provenance_payload(b"P" * 1024, 4, 0x003F, 0x80000000),
    )
    provenance_write = frame(
        0x0100,
        0,
        9,
        7,
        0,
        11,
        10,
        provenance_payload(b"/tmp/output", 2, 0x0007, 0),
    )
    provenance_vectors = (
        provenance_min_literal,
        provenance_interior_literal,
        provenance_write,
        provenance_max,
    )
    provenance_preimages: list[bytes] = []
    for encoded in provenance_vectors:
        expect_provenance_encode(harness, encoded)
        expect_provenance_decode(harness, encoded)
        for previous in (zero, chain_a):
            provenance_preimages.append(
                expect_provenance_preimage(harness, encoded, previous)
            )

    expect_provenance_encode(
        harness, provenance_min_literal, result=2, capacity=len(provenance_min_literal) - 1
    )
    expect_provenance_preimage(
        harness,
        provenance_max,
        chain_a,
        result=2,
        capacity=27 + 32 + 4 + len(provenance_max) - 1,
    )

    for short_len in range(44):
        expect_provenance_decode(harness, provenance_min_literal[:short_len], WIRE_LENGTH)

    envelope_negatives: list[tuple[bytes, int]] = []
    for payload_len in (1041, 1042, 1043, 1044):
        envelope_negatives.append(
            (
                frame(
                    0x0100,
                    0,
                    0,
                    1,
                    0,
                    1,
                    1,
                    provenance_payload(
                        b"P" * (payload_len - 16), 1, 0, 0xFFFFFF9C
                    ),
                ),
                WIRE_LENGTH,
            )
        )
    envelope_negatives.append(
        (replace(provenance_min_literal, 4, be(1045, 4)), WIRE_CAP)
    )
    embedded_cap = replace(provenance_max, 46, be(1025, 2))
    envelope_negatives.append((embedded_cap, WIRE_CAP))
    for encoded, result in envelope_negatives:
        expect_provenance_decode(harness, encoded, result)

    adjacent_negatives: tuple[tuple[bytes, int, int | None], ...] = (
        (
            replace(replace(provenance_min_literal, 0, be(0x0106, 2)), 2, be(1, 2)),
            WIRE_EVENT,
            WIRE_EVENT,
        ),
        (
            replace(replace(provenance_min_literal, 2, be(1, 2)), 4, be(16, 4)),
            WIRE_FLAGS,
            WIRE_FLAGS,
        ),
        (replace(provenance_min_literal, 4, be(16, 4)), WIRE_LENGTH, WIRE_LENGTH),
        (
            replace(provenance_min_literal, 16, bytes(8)) + b"\x00",
            WIRE_LENGTH,
            None,
        ),
        (
            replace(replace(provenance_min_literal, 16, bytes(8)), 24, be(1, 8)),
            WIRE_VALUE,
            WIRE_VALUE,
        ),
        (
            replace(replace(provenance_min_literal, 24, be(1, 8)), 32, bytes(8)),
            WIRE_VALUE,
            WIRE_VALUE,
        ),
        (
            replace(replace(provenance_min_literal, 32, bytes(8)), 40, bytes(2)),
            WIRE_VALUE,
            WIRE_VALUE,
        ),
        (
            replace(replace(provenance_min_literal, 40, bytes(2)), 42, be(1, 2)),
            WIRE_STATE,
            WIRE_STATE,
        ),
        (
            replace(replace(provenance_min_literal, 42, be(1, 2)), 44, be(2, 2)),
            WIRE_RESERVED,
            WIRE_RESERVED,
        ),
        (
            replace(replace(provenance_min_literal, 44, be(2, 2)), 46, bytes(2)),
            WIRE_STATE,
            WIRE_STATE,
        ),
        (
            replace(replace(provenance_max, 46, be(1025, 2)), 48, bytes(2)),
            WIRE_CAP,
            WIRE_CAP,
        ),
        (
            replace(replace(provenance_min_literal, 48, bytes(2)), 50, be(0x40, 2)),
            WIRE_STATE,
            WIRE_STATE,
        ),
        (
            replace(replace(provenance_min_literal, 50, be(0x40, 2)), 56, be(1, 4)),
            WIRE_FLAGS,
            WIRE_FLAGS,
        ),
        (
            replace(replace(provenance_min_literal, 56, be(1, 4)), 60, b"\x00"),
            WIRE_RESERVED,
            WIRE_RESERVED,
        ),
    )
    for encoded, decode_result, encode_result in adjacent_negatives:
        expect_provenance_decode(harness, encoded, decode_result)
        if encode_result is not None:
            expect_provenance_encode(harness, encoded, encode_result)

    boundary_negatives = (
        (replace(provenance_min_literal, 40, be(15, 2)), WIRE_STATE),
        (replace(provenance_min_literal, 44, bytes(2)), WIRE_STATE),
        (replace(provenance_min_literal, 44, be(2, 2)), WIRE_STATE),
        (replace(provenance_min_literal, 46, bytes(2)), WIRE_LENGTH),
        (replace(provenance_min_literal, 46, be(0xFFFF, 2)), WIRE_CAP),
        (replace(provenance_min_literal, 48, be(5, 2)), WIRE_STATE),
        (replace(provenance_min_literal, 46, be(2, 2)), WIRE_LENGTH),
        (replace(provenance_min_literal, 60, b"\x00"), WIRE_VALUE),
    )
    for encoded, result in boundary_negatives:
        expect_provenance_decode(harness, encoded, result)
        expect_provenance_encode(harness, encoded, result)

    for event in (0x0001, 0x00FF, 0x0106, 0x01FF, 0x0200, 0xFFFF):
        encoded = replace(provenance_min_literal, 0, be(event, 2))
        expect_provenance_decode(harness, encoded, WIRE_EVENT)
        expect_provenance_encode(harness, encoded, WIRE_EVENT)
        expect_provenance_preimage(harness, encoded, zero, WIRE_EVENT)

    policy_dense_literal = bytes.fromhex(
        "0101000000000030"
        "0fedcba987654321"
        "0102030405060708"
        "0000000000000000"
        "8877665544332211"
        "00060000"
        "0004003500020003"
        "fffffffb10203040"
        "5060708090a0b0c0"
        "1122334455667788"
        "99aabbccddeeff00"
        "0123456789abcdef"
    )
    if policy_dense_literal != frame(
        0x0101,
        0,
        0x0FEDCBA987654321,
        0x0102030405060708,
        0,
        0x8877665544332211,
        6,
        file_policy_payload(
            4,
            0x0035,
            2,
            3,
            0xFFFFFFFB,
            0x10203040,
            0x50607080,
            0x90A0B0C0,
            0x1122334455667788,
            0x99AABBCCDDEEFF00,
            0x0123456789ABCDEF,
        ),
    ):
        raise AssertionError("dense file-policy literal disagrees with prose builder")

    policy_allow_regular = frame(
        0x0101,
        0,
        0,
        1,
        0,
        1,
        1,
        file_policy_payload(1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0),
    )
    policy_allow_directory = frame(
        0x0101,
        0,
        maximum64,
        maximum64,
        0,
        maximum64,
        14,
        file_policy_payload(
            2,
            0x003F,
            1,
            2,
            0,
            maximum32,
            maximum32,
            maximum32,
            maximum64,
            maximum64,
            maximum64,
        ),
    )
    policy_deny_other = frame(
        0x0101,
        0,
        7,
        11,
        0,
        13,
        9,
        file_policy_payload(
            3,
            1,
            2,
            4,
            0x80000001,
            0xA1B2C3D4,
            0x01020304,
            0xF0E0D0C0,
            0x1020304050607080,
            0xFFEEDDCCBBAA9988,
            0x8877665544332211,
        ),
    )
    policy_vectors = (
        policy_allow_regular,
        policy_allow_directory,
        policy_dense_literal,
        policy_deny_other,
    )
    policy_preimages: list[bytes] = []
    for encoded in policy_vectors:
        expect_provenance_encode(harness, encoded)
        expect_provenance_decode(harness, encoded)
        for previous in (zero, chain_b):
            policy_preimages.append(
                expect_provenance_preimage(harness, encoded, previous)
            )

    for raw_result in (0x80000000, 0x80000001, 0xFFFFFFFB, 0xFFFFFFFF):
        encoded = replace(policy_dense_literal, 52, be(raw_result, 4))
        expect_provenance_encode(harness, encoded)
        expect_provenance_decode(harness, encoded)
        expect_provenance_preimage(harness, encoded, chain_b)

    for phase in (1, 7, 14):
        encoded = replace(policy_dense_literal, 40, be(phase, 2))
        expect_provenance_encode(harness, encoded)
        expect_provenance_decode(harness, encoded)
        expect_provenance_preimage(harness, encoded, zero)

    expect_provenance_encode(
        harness, policy_dense_literal, result=2, capacity=91
    )
    expect_provenance_preimage(
        harness, policy_dense_literal, chain_b, result=2, capacity=154
    )

    policy_invalid_structs: list[tuple[bytes, int]] = [
        (replace(policy_dense_literal, 0, be(0x0106, 2)), WIRE_EVENT),
        (replace(policy_dense_literal, 2, be(1, 2)), WIRE_FLAGS),
        (replace(policy_dense_literal, 4, be(1045, 4)), WIRE_CAP),
        (replace(policy_dense_literal, 4, be(47, 4)), WIRE_LENGTH),
        (replace(policy_dense_literal, 16, bytes(8)), WIRE_VALUE),
        (replace(policy_dense_literal, 24, be(1, 8)), WIRE_VALUE),
        (replace(policy_dense_literal, 32, bytes(8)), WIRE_VALUE),
        (replace(policy_dense_literal, 40, bytes(2)), WIRE_STATE),
        (replace(policy_dense_literal, 42, be(1, 2)), WIRE_RESERVED),
        (replace(policy_dense_literal, 44, bytes(2)), WIRE_STATE),
        (replace(policy_dense_literal, 46, be(0x0040, 2)), WIRE_FLAGS),
        (replace(policy_dense_literal, 48, bytes(2)), WIRE_STATE),
        (replace(policy_dense_literal, 50, bytes(2)), WIRE_STATE),
        (replace(policy_dense_literal, 52, bytes(4)), WIRE_VALUE),
        (replace(policy_dense_literal, 68, bytes(8)), WIRE_VALUE),
        (replace(policy_dense_literal, 76, bytes(8)), WIRE_VALUE),
    ]
    for encoded, result in policy_invalid_structs:
        expect_provenance_decode(harness, encoded, result)
        for capacity in (0, 91):
            expect_provenance_encode(harness, encoded, result, capacity)
        for capacity in (0, 154):
            expect_provenance_preimage(harness, encoded, zero, result, capacity)

    for short_len in range(44):
        expect_provenance_decode(harness, policy_dense_literal[:short_len], WIRE_LENGTH)
    for short_len in range(44, 92):
        expect_provenance_decode(harness, policy_dense_literal[:short_len], WIRE_LENGTH)
    expect_provenance_decode(harness, policy_dense_literal + b"\x00", WIRE_LENGTH)

    policy_envelope_negatives: list[tuple[bytes, int]] = []
    for payload_len in (0, 47, 49, 1044):
        policy_envelope_negatives.append(
            (replace(policy_dense_literal, 4, be(payload_len, 4)), WIRE_LENGTH)
        )
    for payload_len in (1045, maximum32):
        policy_envelope_negatives.append(
            (replace(policy_dense_literal, 4, be(payload_len, 4)), WIRE_CAP)
        )
    for encoded, result in policy_envelope_negatives:
        expect_provenance_decode(harness, encoded, result)
        expect_provenance_encode(harness, encoded, result)
        expect_provenance_preimage(harness, encoded, zero, result)

    policy_adjacent_negatives: tuple[tuple[bytes, int, int], ...] = (
        (
            replace(replace(policy_dense_literal, 0, be(0x0106, 2)), 2, be(1, 2)),
            WIRE_EVENT,
            WIRE_EVENT,
        ),
        (
            replace(replace(policy_dense_literal, 2, be(1, 2)), 4, be(47, 4)),
            WIRE_FLAGS,
            WIRE_FLAGS,
        ),
        (
            replace(policy_dense_literal, 4, be(47, 4)) + b"\x00",
            WIRE_LENGTH,
            WIRE_LENGTH,
        ),
        (
            replace(policy_dense_literal, 16, bytes(8)) + b"\x00",
            WIRE_LENGTH,
            WIRE_VALUE,
        ),
        (
            replace(replace(policy_dense_literal, 16, bytes(8)), 24, be(1, 8)),
            WIRE_VALUE,
            WIRE_VALUE,
        ),
        (
            replace(replace(policy_dense_literal, 24, be(1, 8)), 32, bytes(8)),
            WIRE_VALUE,
            WIRE_VALUE,
        ),
        (
            replace(replace(policy_dense_literal, 32, bytes(8)), 40, bytes(2)),
            WIRE_VALUE,
            WIRE_VALUE,
        ),
        (
            replace(replace(policy_dense_literal, 40, bytes(2)), 42, be(1, 2)),
            WIRE_STATE,
            WIRE_STATE,
        ),
        (
            replace(replace(policy_dense_literal, 42, be(1, 2)), 44, bytes(2)),
            WIRE_RESERVED,
            WIRE_RESERVED,
        ),
        (
            replace(replace(policy_dense_literal, 44, bytes(2)), 46, be(0x40, 2)),
            WIRE_STATE,
            WIRE_STATE,
        ),
        (
            replace(replace(policy_dense_literal, 46, be(0x40, 2)), 48, bytes(2)),
            WIRE_FLAGS,
            WIRE_FLAGS,
        ),
        (
            replace(replace(policy_dense_literal, 48, bytes(2)), 50, bytes(2)),
            WIRE_STATE,
            WIRE_STATE,
        ),
        (
            replace(replace(policy_dense_literal, 50, bytes(2)), 52, bytes(4)),
            WIRE_STATE,
            WIRE_STATE,
        ),
        (
            replace(replace(policy_dense_literal, 52, bytes(4)), 68, bytes(8)),
            WIRE_VALUE,
            WIRE_VALUE,
        ),
        (
            replace(replace(policy_dense_literal, 68, bytes(8)), 76, bytes(8)),
            WIRE_VALUE,
            WIRE_VALUE,
        ),
    )
    for encoded, decode_result, struct_result in policy_adjacent_negatives:
        expect_provenance_decode(harness, encoded, decode_result)
        expect_provenance_encode(harness, encoded, struct_result)
        expect_provenance_preimage(harness, encoded, zero, struct_result)

    policy_boundary_negatives: list[tuple[bytes, int]] = []
    for phase in (0, 15, 16, 0xFFFF):
        policy_boundary_negatives.append(
            (replace(policy_dense_literal, 40, be(phase, 2)), WIRE_STATE)
        )
    for access in (0, 5, 0xFFFF):
        policy_boundary_negatives.append(
            (replace(policy_dense_literal, 44, be(access, 2)), WIRE_STATE)
        )
    for modifiers in (0x0040, 0x8000, 0xFFFF):
        policy_boundary_negatives.append(
            (replace(policy_dense_literal, 46, be(modifiers, 2)), WIRE_FLAGS)
        )
    for decision in (0, 3, 0xFFFF):
        policy_boundary_negatives.append(
            (replace(policy_dense_literal, 48, be(decision, 2)), WIRE_STATE)
        )
    for object_kind in (0, 5, 0xFFFF):
        policy_boundary_negatives.append(
            (replace(policy_dense_literal, 50, be(object_kind, 2)), WIRE_STATE)
        )
    allow_dense = replace(policy_dense_literal, 48, be(1, 2))
    for raw_result in (0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFB, 0xFFFFFFFF):
        policy_boundary_negatives.append(
            (replace(allow_dense, 52, be(raw_result, 4)), WIRE_VALUE)
        )
    for raw_result in (0, 0x7FFFFFFF):
        policy_boundary_negatives.append(
            (replace(policy_dense_literal, 52, be(raw_result, 4)), WIRE_VALUE)
        )
    for encoded, result in policy_boundary_negatives:
        expect_provenance_decode(harness, encoded, result)
        expect_provenance_encode(harness, encoded, result)
        expect_provenance_preimage(harness, encoded, zero, result)

    for event in (0x0000, 0x0001, 0x00FF, 0x0106, 0x01FF, 0x0200, 0xFFFF):
        encoded = replace(policy_dense_literal, 0, be(event, 2))
        expect_provenance_decode(harness, encoded, WIRE_EVENT)
        expect_provenance_encode(harness, encoded, WIRE_EVENT)
        expect_provenance_preimage(harness, encoded, zero, WIRE_EVENT)

    mapping_dense_literal = bytes.fromhex(
        "0102000000000040"
        "0fedcba987654321"
        "0102030405060708"
        "0000000000000000"
        "8877665544332211"
        "00060000"
        "0001000200030002"
        "0000000500000007"
        "00000000fffffffb"
        "1020304050607080"
        "90a0b0c00000000f"
        "1122334455667788"
        "99aabbccddeeff00"
        "0123456789abcdef"
    )
    if mapping_dense_literal != frame(
        0x0102,
        0,
        0x0FEDCBA987654321,
        0x0102030405060708,
        0,
        0x8877665544332211,
        6,
        mapping_policy_payload(
            1,
            2,
            3,
            2,
            0x00000005,
            0x00000007,
            0,
            0xFFFFFFFB,
            0x10203040,
            0x50607080,
            0x90A0B0C0,
            0x0000000F,
            0x1122334455667788,
            0x99AABBCCDDEEFF00,
            0x0123456789ABCDEF,
        ),
    ):
        raise AssertionError("dense mapping-policy literal disagrees with prose builder")

    mapping_complement_literal = bytes.fromhex(
        "0102000000000040"
        "0000000000000000"
        "0000000000000001"
        "0000000000000000"
        "0000000000000001"
        "00010000"
        "0002000100040001"
        "0000000400000005"
        "0000000300000000"
        "a1b2c3d400000000"
        "f0e0d0c000000000"
        "0000000000000001"
        "ffffffffffffffff"
        "0000000000000000"
    )
    if mapping_complement_literal != frame(
        0x0102,
        0,
        0,
        1,
        0,
        1,
        1,
        mapping_policy_payload(
            2,
            1,
            4,
            1,
            0x00000004,
            0x00000005,
            0x00000003,
            0,
            0xA1B2C3D4,
            0,
            0xF0E0D0C0,
            0,
            1,
            0xFFFFFFFFFFFFFFFF,
            0,
        ),
    ):
        raise AssertionError(
            "complement mapping-policy literal disagrees with prose builder"
        )

    mapping_anonymous = frame(
        0x0102,
        0,
        maximum64,
        maximum64,
        0,
        maximum64,
        14,
        mapping_policy_payload(1, 1, 1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )
    mapping_regular = frame(
        0x0102,
        0,
        7,
        11,
        0,
        13,
        9,
        mapping_policy_payload(
            2,
            2,
            2,
            1,
            7,
            4,
            7,
            0x80000001,
            maximum32,
            maximum32,
            maximum32,
            0,
            maximum64,
            1,
            maximum64,
        ),
    )
    mapping_vectors = (
        mapping_dense_literal,
        mapping_complement_literal,
        mapping_anonymous,
        mapping_regular,
    )
    mapping_preimages: list[bytes] = []
    for encoded in mapping_vectors:
        expect_provenance_encode(harness, encoded)
        expect_provenance_decode(harness, encoded)
        for previous in (zero, chain_b):
            mapping_preimages.append(
                expect_provenance_preimage(harness, encoded, previous)
            )

    mapping_negative_frames: set[bytes] = set()

    for decision in (1, 2):
        for raw_result in (
            0x00000000,
            0x7FFFFFFF,
            0x80000000,
            0x80000001,
            0xFFFFFFFB,
            0xFFFFFFFF,
        ):
            encoded = replace(
                replace(mapping_dense_literal, 46, be(decision, 2)),
                64,
                be(raw_result, 4),
            )
            result = (
                0
                if (decision == 1 and raw_result == 0)
                or (decision == 2 and raw_result & 0x80000000)
                else WIRE_VALUE
            )
            expect_provenance_encode(harness, encoded, result)
            expect_provenance_decode(harness, encoded, result)
            expect_provenance_preimage(harness, encoded, zero, result)
            if result != 0:
                mapping_negative_frames.add(encoded)

    expect_provenance_encode(harness, mapping_dense_literal, result=2, capacity=107)
    expect_provenance_preimage(
        harness, mapping_dense_literal, chain_b, result=2, capacity=170
    )

    mapping_invalid_structs: list[tuple[bytes, int]] = [
        (replace(mapping_dense_literal, 0, be(0x0106, 2)), WIRE_EVENT),
        (replace(mapping_dense_literal, 2, be(1, 2)), WIRE_FLAGS),
        (replace(mapping_dense_literal, 4, be(1045, 4)), WIRE_CAP),
        (replace(mapping_dense_literal, 4, be(63, 4)), WIRE_LENGTH),
        (replace(mapping_dense_literal, 16, bytes(8)), WIRE_VALUE),
        (replace(mapping_dense_literal, 24, be(1, 8)), WIRE_VALUE),
        (replace(mapping_dense_literal, 32, bytes(8)), WIRE_VALUE),
        (replace(mapping_dense_literal, 40, bytes(2)), WIRE_STATE),
        (replace(mapping_dense_literal, 42, be(1, 2)), WIRE_RESERVED),
        (replace(mapping_dense_literal, 44, bytes(2)), WIRE_STATE),
        (replace(mapping_dense_literal, 46, bytes(2)), WIRE_STATE),
        (replace(mapping_dense_literal, 48, bytes(2)), WIRE_STATE),
        (replace(mapping_dense_literal, 50, bytes(2)), WIRE_STATE),
        (replace(mapping_dense_literal, 52, be(8, 4)), WIRE_FLAGS),
        (replace(mapping_dense_literal, 56, be(8, 4)), WIRE_FLAGS),
        (replace(mapping_dense_literal, 60, be(8, 4)), WIRE_FLAGS),
        (replace(mapping_dense_literal, 56, be(3, 4)), WIRE_STATE),
        (replace(mapping_dense_literal, 60, be(1, 4)), WIRE_STATE),
        (replace(mapping_dense_literal, 64, bytes(4)), WIRE_VALUE),
        (replace(mapping_dense_literal, 48, be(4, 2)), WIRE_FLAGS),
        (replace(mapping_anonymous, 68, be(1, 4)), WIRE_VALUE),
        (replace(mapping_anonymous, 72, be(1, 4)), WIRE_VALUE),
        (replace(mapping_anonymous, 76, be(1, 4)), WIRE_VALUE),
        (replace(mapping_anonymous, 80, be(1, 4)), WIRE_FLAGS),
        (replace(mapping_anonymous, 84, be(1, 8)), WIRE_VALUE),
        (replace(mapping_anonymous, 92, be(1, 8)), WIRE_VALUE),
        (replace(mapping_anonymous, 100, be(1, 8)), WIRE_VALUE),
        (replace(mapping_regular, 84, bytes(8)), WIRE_VALUE),
        (replace(mapping_regular, 92, bytes(8)), WIRE_VALUE),
    ]
    for encoded, result in mapping_invalid_structs:
        mapping_negative_frames.add(encoded)
        expect_provenance_decode(harness, encoded, result)
        for capacity in (0, 107):
            expect_provenance_encode(harness, encoded, result, capacity)
        for capacity in (0, 170):
            expect_provenance_preimage(harness, encoded, zero, result, capacity)

    for short_len in range(108):
        encoded = mapping_dense_literal[:short_len]
        mapping_negative_frames.add(encoded)
        expect_provenance_decode(harness, encoded, WIRE_LENGTH)

    mapping_suffix = mapping_dense_literal + b"\x00"
    mapping_negative_frames.add(mapping_suffix)
    expect_provenance_decode(harness, mapping_suffix, WIRE_LENGTH)

    mapping_envelope_negatives: list[tuple[bytes, int]] = []
    for payload_len in (0, 63, 65, 1044):
        mapping_envelope_negatives.append(
            (replace(mapping_dense_literal, 4, be(payload_len, 4)), WIRE_LENGTH)
        )
    for payload_len in (1045, maximum32):
        mapping_envelope_negatives.append(
            (replace(mapping_dense_literal, 4, be(payload_len, 4)), WIRE_CAP)
        )
    for encoded, result in mapping_envelope_negatives:
        mapping_negative_frames.add(encoded)
        expect_provenance_decode(harness, encoded, result)
        expect_provenance_encode(harness, encoded, result)
        expect_provenance_preimage(harness, encoded, zero, result)

    mapping_precedence_negatives: tuple[tuple[bytes, int], ...] = (
        (
            replace(replace(mapping_dense_literal, 0, be(0x0106, 2)), 2, be(1, 2)),
            WIRE_EVENT,
        ),
        (
            replace(replace(mapping_dense_literal, 2, be(1, 2)), 4, be(63, 4)),
            WIRE_FLAGS,
        ),
        (
            replace(replace(mapping_dense_literal, 4, be(63, 4)), 16, bytes(8)),
            WIRE_LENGTH,
        ),
        (
            replace(replace(mapping_dense_literal, 16, bytes(8)), 24, be(1, 8)),
            WIRE_VALUE,
        ),
        (
            replace(replace(mapping_dense_literal, 24, be(1, 8)), 32, bytes(8)),
            WIRE_VALUE,
        ),
        (
            replace(replace(mapping_dense_literal, 32, bytes(8)), 40, bytes(2)),
            WIRE_VALUE,
        ),
        (
            replace(replace(mapping_dense_literal, 40, bytes(2)), 42, be(1, 2)),
            WIRE_STATE,
        ),
        (
            replace(replace(mapping_dense_literal, 42, be(1, 2)), 44, bytes(2)),
            WIRE_RESERVED,
        ),
        (
            replace(replace(mapping_dense_literal, 44, bytes(2)), 46, bytes(2)),
            WIRE_STATE,
        ),
        (
            replace(replace(mapping_dense_literal, 46, bytes(2)), 48, bytes(2)),
            WIRE_STATE,
        ),
        (
            replace(replace(mapping_dense_literal, 48, bytes(2)), 50, bytes(2)),
            WIRE_STATE,
        ),
        (
            replace(replace(mapping_dense_literal, 50, bytes(2)), 52, be(8, 4)),
            WIRE_STATE,
        ),
        (
            replace(replace(mapping_dense_literal, 52, be(8, 4)), 56, be(8, 4)),
            WIRE_FLAGS,
        ),
        (
            replace(replace(mapping_dense_literal, 56, be(8, 4)), 60, be(8, 4)),
            WIRE_FLAGS,
        ),
        (
            replace(replace(mapping_dense_literal, 60, be(8, 4)), 56, be(3, 4)),
            WIRE_FLAGS,
        ),
        (
            replace(replace(mapping_dense_literal, 56, be(3, 4)), 60, be(1, 4)),
            WIRE_STATE,
        ),
        (
            replace(replace(mapping_dense_literal, 60, be(1, 4)), 64, bytes(4)),
            WIRE_STATE,
        ),
        (
            replace(
                replace(replace(mapping_dense_literal, 64, bytes(4)), 48, be(4, 2)),
                80,
                be(1, 4),
            ),
            WIRE_VALUE,
        ),
        (
            replace(replace(mapping_anonymous, 80, be(1, 4)), 68, be(1, 4)),
            WIRE_FLAGS,
        ),
        (
            replace(replace(mapping_regular, 84, bytes(8)), 92, bytes(8)),
            WIRE_VALUE,
        ),
    )
    for precedence_index, (encoded, result) in enumerate(
        mapping_precedence_negatives, start=1
    ):
        mapping_negative_frames.add(encoded)
        try:
            expect_provenance_decode(harness, encoded, result)
            expect_provenance_encode(harness, encoded, result)
            expect_provenance_preimage(harness, encoded, zero, result)
        except AssertionError as error:
            raise AssertionError(
                f"mapping precedence vector {precedence_index}: {error}"
            ) from error

    for event in (0x0000, 0x0001, 0x00FF, 0x0106, 0x01FF, 0x0200, 0xFFFF):
        encoded = replace(mapping_dense_literal, 0, be(event, 2))
        mapping_negative_frames.add(encoded)
        expect_provenance_decode(harness, encoded, WIRE_EVENT)
        expect_provenance_encode(harness, encoded, WIRE_EVENT)
        expect_provenance_preimage(harness, encoded, zero, WIRE_EVENT)

    network_ipv4_literal = bytes.fromhex(
        "0103000000000040"
        "0fedcba987654321"
        "0102030405060708"
        "0000000000000000"
        "8877665544332211"
        "00030000"
        "0001000200010001"
        "0001000600020010"
        "fffffffb00000000"
        "00000000"
        "1122334455667788"
        "01bb0000"
        "0000000000000000"
        "000000000000000000000000cb007107"
    )
    if network_ipv4_literal != frame(
        0x0103,
        0,
        0x0FEDCBA987654321,
        0x0102030405060708,
        0,
        0x8877665544332211,
        3,
        network_policy_payload(
            1,
            2,
            1,
            1,
            1,
            6,
            2,
            16,
            0xFFFFFFFB,
            0,
            0,
            0x1122334455667788,
            443,
            0,
            0,
            0,
            bytes(12) + bytes.fromhex("cb007107"),
        ),
    ):
        raise AssertionError("IPv4 network-policy literal disagrees with prose builder")

    network_ipv6_literal = bytes.fromhex(
        "0103000000000040"
        "ffffffffffffffff"
        "ffffffffffffffff"
        "0000000000000000"
        "ffffffffffffffff"
        "000e0000"
        "0002000100020002"
        "00020011000a0000"
        "0000000010203040"
        "7fffffff"
        "ffffffffffffffff"
        "00350000"
        "89abcdef01234567"
        "20010db8000000000000000000000001"
    )
    if network_ipv6_literal != frame(
        0x0103,
        0,
        maximum64,
        maximum64,
        0,
        maximum64,
        14,
        network_policy_payload(
            2,
            1,
            2,
            2,
            2,
            17,
            10,
            0,
            0,
            0x10203040,
            0x7FFFFFFF,
            maximum64,
            53,
            0,
            0x89ABCDEF,
            0x01234567,
            bytes.fromhex("20010db8000000000000000000000001"),
        ),
    ):
        raise AssertionError("IPv6 network-policy literal disagrees with prose builder")

    network_unsupported_literal = bytes.fromhex(
        "0103000000000040"
        "0000000000000001"
        "0000000000000001"
        "0000000000000000"
        "0000000000000001"
        "00010000"
        "0002000200030001"
        "0005ffff0001006e"
        "80000001ffffffff"
        "12345678"
        "0102030405060708"
        "00000000"
        "0000000000000000"
        "00000000000000000000000000000000"
    )
    if network_unsupported_literal != frame(
        0x0103,
        0,
        1,
        1,
        0,
        1,
        1,
        network_policy_payload(
            2,
            2,
            3,
            1,
            5,
            0xFFFF,
            1,
            110,
            0x80000001,
            maximum32,
            0x12345678,
            0x0102030405060708,
            0,
            0,
            0,
            0,
            bytes(16),
        ),
    ):
        raise AssertionError(
            "unsupported network-policy literal disagrees with prose builder"
        )

    network_unresolved_literal = bytes.fromhex(
        "0103000000000040"
        "0000000000000000"
        "0000000000000001"
        "0000000000000000"
        "0000000000000001"
        "00010000"
        "0002000100050002"
        "0003000000000000"
        "0000000000000000"
        "00000000"
        "0000000000000001"
        "00000000"
        "0000000000000000"
        "00000000000000000000000000000000"
    )
    if network_unresolved_literal != frame(
        0x0103,
        0,
        0,
        1,
        0,
        1,
        1,
        network_policy_payload(
            2, 1, 5, 2, 3, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, bytes(16)
        ),
    ):
        raise AssertionError(
            "unresolved network-policy literal disagrees with prose builder"
        )

    network_malformed = frame(
        0x0103,
        0,
        7,
        11,
        0,
        13,
        9,
        network_policy_payload(
            1,
            1,
            4,
            1,
            4,
            0x1234,
            0,
            1,
            0,
            0,
            0,
            0x8877665544332211,
            0,
            0,
            0,
            0,
            bytes(16),
        ),
    )
    network_cross_axis = frame(
        0x0103,
        0,
        42,
        42,
        0,
        42,
        8,
        network_policy_payload(
            2, 1, 3, 1, 1, 6, 42, 37, 0, 1, 1, 42, 0, 0, 0, 0, bytes(16)
        ),
    )
    network_vectors = (
        network_ipv4_literal,
        network_ipv6_literal,
        network_unsupported_literal,
        network_unresolved_literal,
        network_malformed,
        network_cross_axis,
    )
    network_preimages: list[bytes] = []
    for encoded in network_vectors:
        expect_provenance_encode(harness, encoded)
        expect_provenance_decode(harness, encoded)
        for previous in (zero, chain_b):
            network_preimages.append(
                expect_provenance_preimage(harness, encoded, previous)
            )

    def relation_fixture(operation: int, source: int, kind: int, sequence: int) -> bytes:
        family = 0
        address_length = 0
        port = 0
        scope = 0
        flow = 0
        address = bytes(16)
        if kind == 1:
            family = 2
            address_length = 16 if source == 1 else 0
            port = 1
            address = bytes(12) + b"\x01\x02\x03\x04"
        elif kind == 2:
            family = 10
            address_length = 28 if source == 1 else 0
            port = 2
            scope = 3
            flow = 4
            address = bytes(range(16))
        elif kind == 3:
            family = 1
            address_length = 2 if source == 1 else 0
        elif kind == 4:
            if source != 1:
                raise AssertionError("malformed fixture requires explicit source")
            address_length = 1
        elif kind == 5:
            if operation != 2 or source != 2:
                raise AssertionError("unresolved fixture requires connected sendmsg")
        else:
            raise AssertionError("unknown relation fixture kind")
        return frame(
            0x0103,
            0,
            sequence,
            1,
            0,
            1,
            1,
            network_policy_payload(
                operation,
                1,
                kind,
                source,
                1,
                6,
                family,
                address_length,
                0,
                0 if operation == 1 else 1,
                0 if operation == 1 else 1,
                sequence + 1,
                port,
                0,
                scope,
                flow,
                address,
            ),
        )

    connect_class_frames = tuple(
        relation_fixture(1, 1, kind, kind) for kind in (1, 2, 3, 4)
    )
    all_class_frames = connect_class_frames + tuple(
        relation_fixture(2, 1, kind, 10 + kind) for kind in (1, 2, 3, 4)
    ) + tuple(
        relation_fixture(2, 2, kind, 20 + kind) for kind in (1, 2, 3, 5)
    )
    if len(all_class_frames) != 12:
        raise AssertionError("network relation fixture class count drift")

    network_negative_frames: set[bytes] = set()

    for decision in (1, 2):
        for raw_result in (
            0x00000000,
            0x7FFFFFFF,
            0x80000000,
            0x80000001,
            0xFFFFFFFB,
            0xFFFFFFFF,
        ):
            encoded = replace(
                replace(network_ipv4_literal, 46, be(decision, 2)),
                60,
                be(raw_result, 4),
            )
            result = (
                0
                if (decision == 1 and raw_result == 0)
                or (decision == 2 and raw_result & 0x80000000)
                else WIRE_VALUE
            )
            expect_provenance_encode(harness, encoded, result)
            expect_provenance_decode(harness, encoded, result)
            expect_provenance_preimage(harness, encoded, zero, result)
            if result != 0:
                network_negative_frames.add(encoded)

    for base in connect_class_frames:
        for bit in range(32):
            for offset in (64, 68):
                encoded = replace(base, offset, be(1 << bit, 4))
                network_negative_frames.add(encoded)
                expect_provenance_encode(harness, encoded, WIRE_STATE)
                expect_provenance_decode(harness, encoded, WIRE_STATE)
                expect_provenance_preimage(harness, encoded, zero, WIRE_STATE)

    for base in all_class_frames:
        for bit in range(16):
            encoded = replace(base, 82, be(1 << bit, 2))
            network_negative_frames.add(encoded)
            expect_provenance_encode(harness, encoded, WIRE_RESERVED)
            expect_provenance_decode(harness, encoded, WIRE_RESERVED)
            expect_provenance_preimage(harness, encoded, zero, WIRE_RESERVED)

    for low_bits in (
        0,
        0x3FFFFFFF,
        0x7FFFFFFF,
        *(1 << bit for bit in range(31)),
        *(0x7FFFFFFF ^ (1 << bit) for bit in range(31)),
    ):
        encoded = replace(network_ipv6_literal, 68, be(0x80000000 | low_bits, 4))
        network_negative_frames.add(encoded)
        expect_provenance_encode(harness, encoded, WIRE_VALUE)
        expect_provenance_decode(harness, encoded, WIRE_VALUE)
        expect_provenance_preimage(harness, encoded, zero, WIRE_VALUE)

    expect_provenance_encode(harness, network_ipv4_literal, result=2, capacity=107)
    expect_provenance_preimage(
        harness, network_ipv4_literal, chain_b, result=2, capacity=170
    )

    network_invalid_structs: list[tuple[bytes, int]] = [
        (replace(network_ipv4_literal, 0, be(0x0106, 2)), WIRE_EVENT),
        (replace(network_ipv4_literal, 2, be(1, 2)), WIRE_FLAGS),
        (replace(network_ipv4_literal, 4, be(1045, 4)), WIRE_CAP),
        (replace(network_ipv4_literal, 4, be(63, 4)), WIRE_LENGTH),
        (replace(network_ipv4_literal, 16, bytes(8)), WIRE_VALUE),
        (replace(network_ipv4_literal, 24, be(1, 8)), WIRE_VALUE),
        (replace(network_ipv4_literal, 32, bytes(8)), WIRE_VALUE),
        (replace(network_ipv4_literal, 40, bytes(2)), WIRE_STATE),
        (replace(network_ipv4_literal, 42, be(1, 2)), WIRE_RESERVED),
        (replace(network_ipv4_literal, 44, bytes(2)), WIRE_STATE),
        (replace(network_ipv4_literal, 46, bytes(2)), WIRE_STATE),
        (replace(network_ipv4_literal, 48, bytes(2)), WIRE_STATE),
        (replace(network_ipv4_literal, 50, bytes(2)), WIRE_STATE),
        (replace(network_ipv4_literal, 52, bytes(2)), WIRE_STATE),
        (replace(network_ipv4_literal, 58, be(129, 2)), WIRE_LENGTH),
        (replace(network_ipv4_literal, 72, bytes(8)), WIRE_VALUE),
        (replace(network_ipv4_literal, 50, be(2, 2)), WIRE_STATE),
        (replace(network_ipv4_literal, 64, be(1, 4)), WIRE_STATE),
        (replace(network_ipv4_literal, 68, be(1, 4)), WIRE_STATE),
        (replace(network_ipv6_literal, 68, be(0x80000000, 4)), WIRE_VALUE),
        (
            replace(replace(network_ipv4_literal, 46, be(1, 2)), 60, be(0x7FFFFFFF, 4)),
            WIRE_VALUE,
        ),
        (replace(network_ipv4_literal, 60, bytes(4)), WIRE_VALUE),
        (replace(network_ipv4_literal, 56, be(10, 2)), WIRE_STATE),
        (replace(network_ipv4_literal, 58, be(28, 2)), WIRE_STATE),
        (replace(network_ipv4_literal, 84, be(1, 4)), WIRE_VALUE),
        (replace(network_ipv4_literal, 88, be(1, 4)), WIRE_VALUE),
        (replace(network_ipv4_literal, 92, b"\x01"), WIRE_VALUE),
        (replace(network_unsupported_literal, 80, be(1, 2)), WIRE_VALUE),
        (replace(network_unsupported_literal, 84, be(1, 4)), WIRE_VALUE),
        (replace(network_unsupported_literal, 88, be(1, 4)), WIRE_VALUE),
        (replace(network_unsupported_literal, 107, b"\x01"), WIRE_VALUE),
        (replace(network_unresolved_literal, 56, be(1, 2)), WIRE_STATE),
        (replace(network_unresolved_literal, 50, be(1, 2)), WIRE_STATE),
        (replace(network_unresolved_literal, 48, be(3, 2)), WIRE_STATE),
        (replace(network_malformed, 50, be(2, 2)), WIRE_STATE),
    ]
    for encoded, result in network_invalid_structs:
        network_negative_frames.add(encoded)
        expect_provenance_decode(harness, encoded, result)
        for capacity in (0, 107):
            expect_provenance_encode(harness, encoded, result, capacity)
        for capacity in (0, 170):
            expect_provenance_preimage(harness, encoded, zero, result, capacity)

    for short_len in range(108):
        encoded = network_ipv4_literal[:short_len]
        network_negative_frames.add(encoded)
        expect_provenance_decode(harness, encoded, WIRE_LENGTH)

    network_suffix = network_ipv4_literal + b"\x00"
    network_negative_frames.add(network_suffix)
    expect_provenance_decode(harness, network_suffix, WIRE_LENGTH)

    network_envelope_negatives: list[tuple[bytes, int]] = []
    for payload_len in (0, 63, 65, 1044):
        network_envelope_negatives.append(
            (replace(network_ipv4_literal, 4, be(payload_len, 4)), WIRE_LENGTH)
        )
    for payload_len in (1045, maximum32):
        network_envelope_negatives.append(
            (replace(network_ipv4_literal, 4, be(payload_len, 4)), WIRE_CAP)
        )
    for encoded, result in network_envelope_negatives:
        network_negative_frames.add(encoded)
        expect_provenance_decode(harness, encoded, result)
        expect_provenance_encode(harness, encoded, result)
        expect_provenance_preimage(harness, encoded, zero, result)

    network_precedence_negatives: tuple[tuple[bytes, int], ...] = (
        (replace(replace(network_ipv4_literal, 0, be(0x0106, 2)), 2, be(1, 2)), WIRE_EVENT),
        (replace(replace(network_ipv4_literal, 2, be(1, 2)), 4, be(63, 4)), WIRE_FLAGS),
        (replace(replace(network_ipv4_literal, 4, be(63, 4)), 16, bytes(8)), WIRE_LENGTH),
        (replace(replace(network_ipv4_literal, 16, bytes(8)), 24, be(1, 8)), WIRE_VALUE),
        (replace(replace(network_ipv4_literal, 24, be(1, 8)), 32, bytes(8)), WIRE_VALUE),
        (replace(replace(network_ipv4_literal, 32, bytes(8)), 40, bytes(2)), WIRE_VALUE),
        (replace(replace(network_ipv4_literal, 40, bytes(2)), 42, be(1, 2)), WIRE_STATE),
        (replace(replace(network_ipv4_literal, 42, be(1, 2)), 44, bytes(2)), WIRE_RESERVED),
        (replace(replace(network_ipv4_literal, 44, bytes(2)), 46, bytes(2)), WIRE_STATE),
        (replace(replace(network_ipv4_literal, 46, bytes(2)), 48, bytes(2)), WIRE_STATE),
        (replace(replace(network_ipv4_literal, 48, bytes(2)), 50, bytes(2)), WIRE_STATE),
        (replace(replace(network_ipv4_literal, 50, bytes(2)), 52, bytes(2)), WIRE_STATE),
        (replace(replace(network_ipv4_literal, 52, bytes(2)), 58, be(129, 2)), WIRE_STATE),
        (replace(replace(network_ipv4_literal, 58, be(129, 2)), 72, bytes(8)), WIRE_LENGTH),
        (replace(replace(network_ipv4_literal, 72, bytes(8)), 82, be(1, 2)), WIRE_VALUE),
        (replace(replace(network_ipv4_literal, 82, be(1, 2)), 50, be(2, 2)), WIRE_RESERVED),
        (replace(replace(network_ipv4_literal, 50, be(2, 2)), 60, bytes(4)), WIRE_STATE),
        (replace(replace(network_ipv4_literal, 60, bytes(4)), 56, be(10, 2)), WIRE_VALUE),
        (replace(replace(network_ipv4_literal, 56, be(10, 2)), 84, be(1, 4)), WIRE_STATE),
    )
    for precedence_index, (encoded, result) in enumerate(
        network_precedence_negatives, start=1
    ):
        network_negative_frames.add(encoded)
        try:
            expect_provenance_decode(harness, encoded, result)
            expect_provenance_encode(harness, encoded, result)
            expect_provenance_preimage(harness, encoded, zero, result)
        except AssertionError as error:
            raise AssertionError(
                f"network precedence vector {precedence_index}: {error}"
            ) from error

    for event in (0x0000, 0x0001, 0x00FF, 0x0106, 0x01FF, 0x0200, 0xFFFF):
        encoded = replace(network_ipv4_literal, 0, be(event, 2))
        network_negative_frames.add(encoded)
        expect_provenance_decode(harness, encoded, WIRE_EVENT)
        expect_provenance_encode(harness, encoded, WIRE_EVENT)
        expect_provenance_preimage(harness, encoded, zero, WIRE_EVENT)

    operation_return_file_open = bytes.fromhex(
        "0104000000000010"
        "0000000000000000"
        "0000000000000001"
        "0000000000000000"
        "0000000000000001"
        "00010000"
        "00010000"
        "00000000"
        "0000000000000000"
    )
    if operation_return_file_open != frame(
        0x0104, 0, 0, 1, 0, 1, 1, operation_return_payload(1, 0)
    ):
        raise AssertionError("FILE_OPEN operation-return literal disagrees with prose")

    operation_return_mmap = bytes.fromhex(
        "0104000000000010"
        "ffffffffffffffff"
        "ffffffffffffffff"
        "0000000000000000"
        "ffffffffffffffff"
        "000e0000"
        "00020000"
        "00000000"
        "0000000000000001"
    )
    if operation_return_mmap != frame(
        0x0104,
        0,
        maximum64,
        maximum64,
        0,
        maximum64,
        14,
        operation_return_payload(2, 1),
    ):
        raise AssertionError("MMAP operation-return literal disagrees with prose")

    operation_return_mprotect = bytes.fromhex(
        "0104000000000010"
        "0102030405060708"
        "0000000000000002"
        "0000000000000000"
        "0000000000000003"
        "00070000"
        "00030000"
        "00000000"
        "0123456789abcdef"
    )
    if operation_return_mprotect != frame(
        0x0104,
        0,
        0x0102030405060708,
        2,
        0,
        3,
        7,
        operation_return_payload(3, 0x0123456789ABCDEF),
    ):
        raise AssertionError("MPROTECT operation-return literal disagrees with prose")

    operation_return_connect = bytes.fromhex(
        "0104000000000010"
        "1111111111111111"
        "2222222222222222"
        "0000000000000000"
        "4444444444444444"
        "00040000"
        "00040000"
        "00000000"
        "7fffffffffffffff"
    )
    if operation_return_connect != frame(
        0x0104,
        0,
        0x1111111111111111,
        0x2222222222222222,
        0,
        0x4444444444444444,
        4,
        operation_return_payload(4, 0x7FFFFFFFFFFFFFFF),
    ):
        raise AssertionError("CONNECT operation-return literal disagrees with prose")

    operation_return_sendmsg = bytes.fromhex(
        "0104000000000010"
        "aabbccddeeff0011"
        "0000000000000005"
        "0000000000000000"
        "0000000000000005"
        "000d0000"
        "00050000"
        "00000000"
        "ffffffff80000000"
    )
    if operation_return_sendmsg != frame(
        0x0104,
        0,
        0xAABBCCDDEEFF0011,
        5,
        0,
        5,
        13,
        operation_return_payload(5, 0xFFFFFFFF80000000),
    ):
        raise AssertionError("SENDMSG operation-return literal disagrees with prose")

    operation_return_vectors = (
        operation_return_file_open,
        operation_return_mmap,
        operation_return_mprotect,
        operation_return_connect,
        operation_return_sendmsg,
    )
    operation_return_preimages: list[bytes] = []
    for encoded in operation_return_vectors:
        expect_provenance_encode(harness, encoded)
        expect_provenance_decode(harness, encoded)
        for previous in (zero, chain_b):
            operation_return_preimages.append(
                expect_provenance_preimage(harness, encoded, previous)
            )

    operation_return_negative_frames: set[bytes] = set()

    for operation in range(1 << 16):
        encoded = replace(operation_return_file_open, 44, be(operation, 2))
        result = 0 if 1 <= operation <= 5 else WIRE_STATE
        if result != 0:
            operation_return_negative_frames.add(encoded)
        expect_provenance_encode(harness, encoded, result)
        expect_provenance_decode(harness, encoded, result)
        expect_provenance_preimage(harness, encoded, zero, result)

    for phase in range(1 << 16):
        encoded = replace(operation_return_file_open, 40, be(phase, 2))
        result = 0 if 1 <= phase <= 14 else WIRE_STATE
        if result != 0:
            operation_return_negative_frames.add(encoded)
        expect_provenance_encode(harness, encoded, result)
        expect_provenance_decode(harness, encoded, result)
        expect_provenance_preimage(harness, encoded, zero, result)

    for operation in range(1, 6):
        base = replace(operation_return_file_open, 44, be(operation, 2))
        for raw_return in (0, maximum64):
            encoded = replace(base, 52, be(raw_return, 8))
            expect_provenance_encode(harness, encoded)
            expect_provenance_decode(harness, encoded)
            expect_provenance_preimage(harness, encoded, zero)
        for bit in range(64):
            for raw_return in (1 << bit, maximum64 ^ (1 << bit)):
                encoded = replace(base, 52, be(raw_return, 8))
                expect_provenance_encode(harness, encoded)
                expect_provenance_decode(harness, encoded)
                expect_provenance_preimage(harness, encoded, zero)

    for bit in range(16):
        encoded = replace(operation_return_file_open, 2, be(1 << bit, 2))
        operation_return_negative_frames.add(encoded)
        expect_provenance_encode(harness, encoded, WIRE_FLAGS)
        expect_provenance_decode(harness, encoded, WIRE_FLAGS)
        expect_provenance_preimage(harness, encoded, zero, WIRE_FLAGS)
    for bit in range(16):
        encoded = replace(operation_return_file_open, 42, be(1 << bit, 2))
        operation_return_negative_frames.add(encoded)
        expect_provenance_encode(harness, encoded, WIRE_RESERVED)
        expect_provenance_decode(harness, encoded, WIRE_RESERVED)
        expect_provenance_preimage(harness, encoded, zero, WIRE_RESERVED)
    for bit in range(16):
        encoded = replace(operation_return_file_open, 46, be(1 << bit, 2))
        operation_return_negative_frames.add(encoded)
        expect_provenance_encode(harness, encoded, WIRE_RESERVED)
        expect_provenance_decode(harness, encoded, WIRE_RESERVED)
        expect_provenance_preimage(harness, encoded, zero, WIRE_RESERVED)
    for bit in range(32):
        encoded = replace(operation_return_file_open, 48, be(1 << bit, 4))
        operation_return_negative_frames.add(encoded)
        expect_provenance_encode(harness, encoded, WIRE_RESERVED)
        expect_provenance_decode(harness, encoded, WIRE_RESERVED)
        expect_provenance_preimage(harness, encoded, zero, WIRE_RESERVED)

    sequence_task_crossfeed = replace(
        replace(operation_return_mprotect, 8, operation_return_mprotect[16:24]),
        16,
        operation_return_mprotect[8:16],
    )
    expect_provenance_encode(harness, sequence_task_crossfeed)
    expect_provenance_decode(harness, sequence_task_crossfeed)
    expect_provenance_preimage(harness, sequence_task_crossfeed, zero)

    operation_return_crossfeed_invalids: tuple[tuple[bytes, int], ...] = (
        (
            replace(
                replace(operation_return_file_open, 0, operation_return_file_open[2:4]),
                2,
                operation_return_file_open[0:2],
            ),
            WIRE_EVENT,
        ),
        (
            replace(
                replace(operation_return_file_open, 16, operation_return_file_open[24:32]),
                24,
                operation_return_file_open[16:24],
            ),
            WIRE_VALUE,
        ),
        (
            replace(
                replace(operation_return_file_open, 24, operation_return_file_open[32:40]),
                32,
                operation_return_file_open[24:32],
            ),
            WIRE_VALUE,
        ),
        (
            replace(
                replace(operation_return_file_open, 32, operation_return_file_open[52:60]),
                52,
                operation_return_file_open[32:40],
            ),
            WIRE_VALUE,
        ),
        (
            replace(
                replace(operation_return_file_open, 40, operation_return_file_open[42:44]),
                42,
                operation_return_file_open[40:42],
            ),
            WIRE_STATE,
        ),
        (
            replace(
                replace(operation_return_file_open, 44, operation_return_file_open[46:48]),
                46,
                operation_return_file_open[44:46],
            ),
            WIRE_STATE,
        ),
        (
            replace(
                replace(operation_return_file_open, 4, operation_return_file_open[48:52]),
                48,
                operation_return_file_open[4:8],
            ),
            WIRE_LENGTH,
        ),
    )
    for encoded, result in operation_return_crossfeed_invalids:
        operation_return_negative_frames.add(encoded)
        expect_provenance_encode(harness, encoded, result)
        expect_provenance_decode(harness, encoded, result)
        expect_provenance_preimage(harness, encoded, zero, result)

    operation_return_invalids: tuple[tuple[bytes, int], ...] = (
        (replace(operation_return_file_open, 0, be(0x0106, 2)), WIRE_EVENT),
        (replace(operation_return_file_open, 2, be(1, 2)), WIRE_FLAGS),
        (replace(operation_return_file_open, 4, be(1045, 4)), WIRE_CAP),
        (replace(operation_return_file_open, 4, be(15, 4)), WIRE_LENGTH),
        (replace(operation_return_file_open, 16, bytes(8)), WIRE_VALUE),
        (replace(operation_return_file_open, 24, be(1, 8)), WIRE_VALUE),
        (replace(operation_return_file_open, 32, bytes(8)), WIRE_VALUE),
        (replace(operation_return_file_open, 40, bytes(2)), WIRE_STATE),
        (replace(operation_return_file_open, 42, be(1, 2)), WIRE_RESERVED),
        (replace(operation_return_file_open, 44, bytes(2)), WIRE_STATE),
        (replace(operation_return_file_open, 44, be(6, 2)), WIRE_STATE),
        (replace(operation_return_file_open, 44, be(0xFFFF, 2)), WIRE_STATE),
        (replace(operation_return_file_open, 46, be(1, 2)), WIRE_RESERVED),
        (replace(operation_return_file_open, 48, be(1, 4)), WIRE_RESERVED),
    )
    for encoded, result in operation_return_invalids:
        operation_return_negative_frames.add(encoded)
        expect_provenance_decode(harness, encoded, result)
        for capacity in (0, 59):
            expect_provenance_encode(harness, encoded, result, capacity)
        for capacity in (0, 122):
            expect_provenance_preimage(harness, encoded, zero, result, capacity)

    for payload_length, result in (
        (0, WIRE_LENGTH),
        (15, WIRE_LENGTH),
        (17, WIRE_LENGTH),
        (1044, WIRE_LENGTH),
        (1045, WIRE_CAP),
        (maximum32, WIRE_CAP),
    ):
        encoded = replace(operation_return_file_open, 4, be(payload_length, 4))
        operation_return_negative_frames.add(encoded)
        expect_provenance_decode(harness, encoded, result)
        expect_provenance_encode(harness, encoded, result)
        expect_provenance_preimage(harness, encoded, zero, result)

    for short_length in range(60):
        encoded = operation_return_file_open[:short_length]
        operation_return_negative_frames.add(encoded)
        expect_provenance_decode(harness, encoded, WIRE_LENGTH)
    operation_return_suffix = operation_return_file_open + b"\x00"
    operation_return_negative_frames.add(operation_return_suffix)
    expect_provenance_decode(harness, operation_return_suffix, WIRE_LENGTH)

    operation_return_precedence: tuple[tuple[bytes, int], ...] = (
        (
            replace(
                replace(operation_return_file_open, 0, be(0x0106, 2)),
                2,
                be(1, 2),
            ),
            WIRE_EVENT,
        ),
        (
            replace(replace(operation_return_file_open, 2, be(1, 2)), 4, be(15, 4)),
            WIRE_FLAGS,
        ),
        (
            replace(operation_return_file_open, 4, be(15, 4)),
            WIRE_LENGTH,
        ),
        (
            replace(replace(operation_return_file_open, 16, bytes(8)), 24, be(1, 8)),
            WIRE_VALUE,
        ),
        (
            replace(replace(operation_return_file_open, 24, be(1, 8)), 32, bytes(8)),
            WIRE_VALUE,
        ),
        (
            replace(replace(operation_return_file_open, 32, bytes(8)), 40, bytes(2)),
            WIRE_VALUE,
        ),
        (
            replace(replace(operation_return_file_open, 40, bytes(2)), 42, be(1, 2)),
            WIRE_STATE,
        ),
        (
            replace(replace(operation_return_file_open, 42, be(1, 2)), 44, bytes(2)),
            WIRE_RESERVED,
        ),
        (
            replace(replace(operation_return_file_open, 44, bytes(2)), 46, be(1, 2)),
            WIRE_STATE,
        ),
        (
            replace(replace(operation_return_file_open, 46, be(1, 2)), 48, be(1, 4)),
            WIRE_RESERVED,
        ),
    )
    for index, (encoded, result) in enumerate(operation_return_precedence, start=1):
        operation_return_negative_frames.add(encoded)
        try:
            expect_provenance_decode(harness, encoded, result)
            expect_provenance_encode(harness, encoded, result)
            expect_provenance_preimage(harness, encoded, zero, result)
        except AssertionError as error:
            raise AssertionError(
                f"operation-return precedence vector {index}: {error}"
            ) from error

    operation_return_decode_only_precedence = replace(
        operation_return_suffix, 16, bytes(8)
    )
    operation_return_negative_frames.add(operation_return_decode_only_precedence)
    expect_provenance_decode(
        harness, operation_return_decode_only_precedence, WIRE_LENGTH
    )

    expect_provenance_encode(
        harness, operation_return_file_open, result=2, capacity=59
    )
    expect_provenance_preimage(
        harness, operation_return_file_open, chain_b, result=2, capacity=122
    )

    provenance_digest = hashlib.sha256(b"".join(provenance_vectors)).hexdigest()
    provenance_preimage_digest = hashlib.sha256(
        b"".join(provenance_preimages)
    ).hexdigest()
    policy_digest = hashlib.sha256(b"".join(policy_vectors)).hexdigest()
    policy_preimage_digest = hashlib.sha256(b"".join(policy_preimages)).hexdigest()
    mapping_digest = hashlib.sha256(b"".join(mapping_vectors)).hexdigest()
    mapping_preimage_digest = hashlib.sha256(
        b"".join(mapping_preimages)
    ).hexdigest()
    network_digest = hashlib.sha256(b"".join(network_vectors)).hexdigest()
    network_preimage_digest = hashlib.sha256(
        b"".join(network_preimages)
    ).hexdigest()
    operation_return_digest = hashlib.sha256(
        b"".join(operation_return_vectors)
    ).hexdigest()
    operation_return_preimage_digest = hashlib.sha256(
        b"".join(operation_return_preimages)
    ).hexdigest()

    print(
        "ok   independent fixed-object/frame oracle "
        f"header_preimage_sha256={hashlib.sha256(HEADER_DOMAIN + be(192, 4) + dense_header).hexdigest()} "
        f"frame_vectors={len(frame_vectors)} frame_preimages={len(frame_digests)} "
        f"frame_digest_set_sha256={digest_set} "
        f"stream_vectors={len(positive_streams)} stream_negatives={len(negative_streams)} "
        f"stream_vector_set_sha256={stream_vector_digest} "
        f"provenance_vectors={len(provenance_vectors)} "
        f"provenance_vector_set_sha256={provenance_digest} "
        f"provenance_preimage_set_sha256={provenance_preimage_digest} "
        f"provenance_negatives={44 + len(envelope_negatives) + len(adjacent_negatives) + len(boundary_negatives) + 6} "
        f"policy_vectors={len(policy_vectors)} "
        f"policy_vector_set_sha256={policy_digest} "
        f"policy_preimage_set_sha256={policy_preimage_digest} "
        f"policy_negatives={93 + len(policy_invalid_structs) + len(policy_envelope_negatives) + len(policy_adjacent_negatives) + len(policy_boundary_negatives) + 7} "
        f"mapping_vectors={len(mapping_vectors)} "
        f"mapping_vector_set_sha256={mapping_digest} "
        f"mapping_preimages={len(mapping_preimages)} "
        f"mapping_preimage_set_sha256={mapping_preimage_digest} "
        f"mapping_negative_frames={len(mapping_negative_frames)} "
        f"network_vectors={len(network_vectors)} "
        f"network_vector_set_sha256={network_digest} "
        f"network_preimages={len(network_preimages)} "
        f"network_preimage_set_sha256={network_preimage_digest} "
        f"network_negative_frames={len(network_negative_frames)} "
        f"operation_return_vectors={len(operation_return_vectors)} "
        f"operation_return_vector_set_sha256={operation_return_digest} "
        f"operation_return_preimages={len(operation_return_preimages)} "
        f"operation_return_preimage_set_sha256={operation_return_preimage_digest} "
        f"operation_return_negative_frames={len(operation_return_negative_frames)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
