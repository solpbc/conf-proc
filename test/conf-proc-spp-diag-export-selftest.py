#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent literal checks for the canonical SPPDBN1 producer."""

from __future__ import annotations

import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conf_proc_spp_diag_export import (
    ExportOps,
    PoweroffInvalidationFailed,
    PoweroffReturned,
    build_export_stream,
    export_and_poweroff,
    parse_export_stream,
)
from conf_proc_spp_diag_export_reasons import SppDiagExportError
from conf_proc_spp_diag_uart import FramedUartWriter, decode_uart_record


LITERAL_MEMBER_NAMES = (
    "ak-public.pem",
    "firmware-event-log.bin",
    "gpu-evidence.tlv",
    "hcla.bin",
    "ima-measurements.bin",
    "inner-receipt/ak-tpmt-public.bin",
    "inner-receipt/firmware-event-log.sha256",
    "inner-receipt/gpu-evidence.sha256",
    "inner-receipt/ima-measurements.sha256",
    "inner-receipt/manifest.json",
    "inner-receipt/synthetic-output.bin",
    "inner-receipt/terminal-frame.bin",
    "inner-receipt/trace.bin",
    "quote.msg",
    "quote.pcrs",
    "quote.sig",
    "zz-capture-terminal.bin",
)
LITERAL_PAYLOAD_NAMES = LITERAL_MEMBER_NAMES[:-1]
CHALLENGE = bytes(range(32))
RUN = bytes(range(32, 64))
MAX_STREAM_BYTES = 16_777_216
MAX_MEMBER_BYTES = 8_388_608


def make_members(size: int = 16) -> dict[str, bytes]:
    return {name: bytes([len(name) % 251]) * size for name in LITERAL_PAYLOAD_NAMES}


def literal_stream(members: dict[str, bytes]) -> bytes:
    prefix = struct.pack(">8sII", b"SPPDBN1\0", 1, 17)
    for name in LITERAL_PAYLOAD_NAMES:
        path = name.encode("utf-8")
        payload = members[name]
        prefix += struct.pack(">HQ32s", len(path), len(payload), hashlib.sha256(payload).digest()) + path + payload
    terminal = struct.pack(
        ">8sHH32s32s32s",
        b"SPPCAP1\0",
        1,
        1,
        CHALLENGE,
        RUN,
        hashlib.sha256(prefix).digest(),
    )
    path = b"zz-capture-terminal.bin"
    return prefix + struct.pack(">HQ32s", len(path), len(terminal), hashlib.sha256(terminal).digest()) + path + terminal


def test_exact_literal_stream_and_terminal() -> None:
    members = make_members()
    stream = build_export_stream(members=members, challenge=CHALLENGE, run_identity=RUN)
    assert stream == literal_stream(members)
    parsed = parse_export_stream(stream, expected_challenge=CHALLENGE, expected_run_identity=RUN)
    assert tuple(member.name for member in parsed.members) == LITERAL_MEMBER_NAMES
    terminal = parsed.members[-1].payload
    assert len(terminal) == 108
    assert struct.unpack(">8sHH", terminal[:12]) == (b"SPPCAP1\0", 1, 1)


def test_every_truncation_trailing_and_identity_mismatch_reject() -> None:
    stream = literal_stream(make_members(size=1))
    for cut in range(len(stream)):
        try:
            parse_export_stream(stream[:cut])
        except SppDiagExportError:
            pass
        else:
            raise AssertionError(f"truncation at {cut} accepted")
    try:
        parse_export_stream(stream + b"\0")
    except SppDiagExportError:
        pass
    else:
        raise AssertionError("trailing byte accepted")
    for kwargs in (
        {"expected_challenge": b"x" * 32},
        {"expected_run_identity": b"y" * 32},
    ):
        try:
            parse_export_stream(stream, **kwargs)
        except SppDiagExportError:
            pass
        else:
            raise AssertionError("wrong identity accepted")


def test_duplicate_unknown_and_rehashed_prefix_mutation_reject() -> None:
    members = make_members()
    stream = bytearray(literal_stream(members))
    record_offset = 16
    path_size, payload_size, _digest = struct.unpack(">HQ32s", stream[record_offset : record_offset + 42])
    payload_offset = record_offset + 42 + path_size
    stream[payload_offset] ^= 1
    mutated_payload = bytes(stream[payload_offset : payload_offset + payload_size])
    stream[record_offset + 10 : record_offset + 42] = hashlib.sha256(mutated_payload).digest()
    try:
        parse_export_stream(bytes(stream))
    except SppDiagExportError:
        pass
    else:
        raise AssertionError("rehashed prefix mutation accepted")

    def malformed_names(names: tuple[str, ...]) -> bytes:
        wire = struct.pack(">8sII", b"SPPDBN1\0", 1, len(names))
        for name in names:
            path = name.encode()
            wire += struct.pack(">HQ32s", len(path), 0, hashlib.sha256(b"").digest()) + path
        return wire

    for names in (
        (LITERAL_MEMBER_NAMES[0], LITERAL_MEMBER_NAMES[0]) + LITERAL_MEMBER_NAMES[2:],
        ("aaa-unknown",) + LITERAL_MEMBER_NAMES[1:],
    ):
        try:
            parse_export_stream(malformed_names(names))
        except SppDiagExportError:
            pass
        else:
            raise AssertionError("wrong wire member set accepted")


def _fixed_framing_bytes() -> int:
    return (
        16
        + sum(42 + len(name.encode()) for name in LITERAL_PAYLOAD_NAMES)
        + 42
        + len(b"zz-capture-terminal.bin")
        + 108
    )


def test_exact_member_and_stream_cap_boundaries() -> None:
    members = {name: b"" for name in LITERAL_PAYLOAD_NAMES}
    members[LITERAL_PAYLOAD_NAMES[0]] = b"x" * MAX_MEMBER_BYTES
    assert len(build_export_stream(members=members, challenge=CHALLENGE, run_identity=RUN)) < MAX_STREAM_BYTES
    members[LITERAL_PAYLOAD_NAMES[0]] += b"x"
    try:
        build_export_stream(members=members, challenge=CHALLENGE, run_identity=RUN)
    except SppDiagExportError:
        pass
    else:
        raise AssertionError("member cap +1 accepted")

    payload_budget = MAX_STREAM_BYTES - _fixed_framing_bytes()
    members = {name: b"" for name in LITERAL_PAYLOAD_NAMES}
    members[LITERAL_PAYLOAD_NAMES[0]] = b"x" * MAX_MEMBER_BYTES
    members[LITERAL_PAYLOAD_NAMES[1]] = b"y" * (payload_budget - MAX_MEMBER_BYTES)
    exact = build_export_stream(members=members, challenge=CHALLENGE, run_identity=RUN)
    assert len(exact) == MAX_STREAM_BYTES
    members[LITERAL_PAYLOAD_NAMES[1]] += b"y"
    try:
        build_export_stream(members=members, challenge=CHALLENGE, run_identity=RUN)
    except SppDiagExportError:
        pass
    else:
        raise AssertionError("stream cap +1 accepted")


def test_framed_poweroff_boundary_uses_one_absolute_2400_second_deadline() -> None:
    writes: list[bytes] = []
    clock = [0.0]
    writer = FramedUartWriter(CHALLENGE, RUN)
    writer.load_success(b"valid-stream")

    def write(data: bytes) -> int:
        writes.append(data)
        return len(data)

    ops = ExportOps(write, lambda _deadline: True, lambda: 0, lambda: clock[0], lambda: None)
    try:
        export_and_poweroff(ops, writer)
    except PoweroffReturned as exc:
        assert exc.writer is writer
    else:
        raise AssertionError("returned poweroff did not fail-stop")
    assert len(writes) == 2
    assert decode_uart_record(writes[0], expected_challenge=CHALLENGE, expected_run_identity=RUN).payload == b"valid-stream"
    invalidator = decode_uart_record(writes[1], expected_challenge=CHALLENGE, expected_run_identity=RUN)
    assert invalidator.kind == "I" and invalidator.payload == b"\0" and invalidator.sequence == 1

    writer = FramedUartWriter(CHALLENGE, RUN)
    writer.load_success(b"deadline")

    def late_write(data: bytes) -> int:
        clock[0] = 2400.000001
        return len(data)

    clock[0] = 0.0
    try:
        export_and_poweroff(ExportOps(late_write, lambda _deadline: True, lambda: 0, lambda: clock[0], lambda: None), writer)
    except PoweroffReturned:
        pass
    else:
        raise AssertionError("expired export deadline did not fail-stop")
    assert writer.poisoned


TESTS = (
    test_exact_literal_stream_and_terminal,
    test_every_truncation_trailing_and_identity_mismatch_reject,
    test_duplicate_unknown_and_rehashed_prefix_mutation_reject,
    test_exact_member_and_stream_cap_boundaries,
    test_framed_poweroff_boundary_uses_one_absolute_2400_second_deadline,
)


if __name__ == "__main__":
    for test in TESTS:
        test()
        print(f"ok   {test.__name__}")
    print(f"SPP diagnostic UART export: ok ({len(TESTS)} tests)")
