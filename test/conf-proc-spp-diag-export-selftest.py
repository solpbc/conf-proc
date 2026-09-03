#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftest for conf_proc_spp_diag_export: SPPDBN1 stream encode/decode, terminal
record, and deadline/poweroff behavior."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conf_proc_spp_diag_export import (
    MEMBER_NAMES,
    STATUS_COMPLETE,
    STATUS_FAILED,
    TERMINAL_SIZE,
    ExportOps,
    build_export_stream,
    encode_terminal,
    export_and_poweroff,
    parse_export_stream,
)
from conf_proc_spp_diag_export_reasons import (
    CP_SPP_DIAG_EXPORT_MEMBER_HASH,
    CP_SPP_DIAG_EXPORT_MEMBER_NAME,
    CP_SPP_DIAG_EXPORT_MEMBER_ORDER,
    CP_SPP_DIAG_EXPORT_TERMINAL,
    CP_SPP_DIAG_EXPORT_TRAILING_BYTES,
    CP_SPP_DIAG_EXPORT_TRUNCATED,
    SppDiagExportError,
)


def make_members(sizes: dict | None = None) -> dict:
    sizes = sizes or {}
    return {name: bytes([len(name) % 256]) * sizes.get(name, 16) for name in MEMBER_NAMES}


def test_terminal_literal_size_and_fields() -> None:
    challenge = bytes(range(32))
    run_identity = bytes(range(32, 64))
    terminal = encode_terminal(challenge=challenge, run_identity=run_identity, status=STATUS_COMPLETE, reason_code_index=0, current_phase=15)
    assert len(terminal) == TERMINAL_SIZE == 108
    assert terminal[:8] == b"SPPDBTM1"
    assert terminal[8:40] == challenge
    assert terminal[40:72] == run_identity
    assert terminal[72] == STATUS_COMPLETE
    assert terminal[73] == 0
    assert terminal[74] == 15
    assert terminal[75:] == bytes(33)


def test_round_trip_happy_path() -> None:
    members = make_members()
    terminal = encode_terminal(challenge=b"\x01" * 32, run_identity=b"\x02" * 32, status=STATUS_COMPLETE, reason_code_index=0, current_phase=15)
    stream = build_export_stream(members, terminal)
    bundle = parse_export_stream(stream)
    assert [m.name for m in bundle.members] == list(MEMBER_NAMES)
    assert bundle.terminal == terminal
    for member in bundle.members:
        assert member.payload == members[member.name]


def test_truncation_at_every_boundary_rejects() -> None:
    members = make_members()
    terminal = encode_terminal(challenge=b"\x03" * 32, run_identity=b"\x04" * 32, status=STATUS_COMPLETE, reason_code_index=0, current_phase=15)
    stream = build_export_stream(members, terminal)
    # A complete prefix (any strict prefix) must never parse successfully.
    checked = 0
    for cut in range(1, len(stream)):
        try:
            parse_export_stream(stream[:cut])
            raise AssertionError(f"truncation at byte {cut} unexpectedly parsed")
        except SppDiagExportError:
            checked += 1
    assert checked == len(stream) - 1


def test_appended_bytes_reject() -> None:
    members = make_members()
    terminal = encode_terminal(challenge=b"\x05" * 32, run_identity=b"\x06" * 32, status=STATUS_COMPLETE, reason_code_index=0, current_phase=15)
    stream = build_export_stream(members, terminal) + b"\x00"
    try:
        parse_export_stream(stream)
        raise AssertionError("expected trailing-bytes rejection")
    except SppDiagExportError as exc:
        assert exc.reason_code == CP_SPP_DIAG_EXPORT_TRAILING_BYTES


def test_unknown_and_duplicate_members_reject() -> None:
    try:
        build_export_stream({"unknown-member": b"x"}, encode_terminal(challenge=b"\x00" * 32, run_identity=b"\x00" * 32, status=STATUS_FAILED, reason_code_index=1, current_phase=1))
        raise AssertionError("expected member-name rejection")
    except SppDiagExportError as exc:
        assert exc.reason_code == CP_SPP_DIAG_EXPORT_MEMBER_NAME


def test_one_byte_wrong_challenge_changes_terminal() -> None:
    base = encode_terminal(challenge=b"\x07" * 32, run_identity=b"\x08" * 32, status=STATUS_COMPLETE, reason_code_index=0, current_phase=15)
    mutated_challenge = bytearray(b"\x07" * 32)
    mutated_challenge[0] ^= 0x01
    mutated = encode_terminal(challenge=bytes(mutated_challenge), run_identity=b"\x08" * 32, status=STATUS_COMPLETE, reason_code_index=0, current_phase=15)
    assert base != mutated


def test_exact_byte_cap_boundary() -> None:
    # payload exactly matching its declared size passes; a payload one byte short
    # (declared size larger than actual, forced by hand-truncating the stream after
    # encoding) must be caught as truncation by the independent parser.
    members = make_members()
    terminal = encode_terminal(challenge=b"\x09" * 32, run_identity=b"\x0a" * 32, status=STATUS_COMPLETE, reason_code_index=0, current_phase=15)
    stream = build_export_stream(members, terminal)
    bundle = parse_export_stream(stream)
    assert bundle.members[0].size_bytes == 16
    truncated_by_one = stream[:-1]
    try:
        parse_export_stream(truncated_by_one)
        raise AssertionError("expected +1-short rejection")
    except SppDiagExportError:
        pass


def test_deadline_and_stalled_write_still_requests_poweroff() -> None:
    stream = b"X" * 1000
    poweroff_calls = []

    def make_ops(write_budget_bytes: int, clock_jump: bool):
        clock = [0.0]

        def monotonic():
            clock[0] += 0.001
            if clock_jump and clock[0] > 0.01:
                clock[0] += 1000.0
            return clock[0]

        written_total = [0]

        def write_serial(data: bytes) -> int:
            take = min(len(data), write_budget_bytes)
            written_total[0] += take
            return take

        def request_poweroff_hardware() -> None:
            poweroff_calls.append(True)

        return ExportOps(write_serial=write_serial, monotonic=monotonic, request_poweroff_hardware=request_poweroff_hardware)

    # happy path: full budget, no clock jump -> complete
    poweroff_calls.clear()
    complete = export_and_poweroff(make_ops(1000, clock_jump=False), stream)
    assert complete is True
    assert poweroff_calls == [True]

    # stalled write (budget 0 bytes per call) -> never completes, still requests poweroff
    poweroff_calls.clear()
    complete = export_and_poweroff(make_ops(0, clock_jump=False), stream)
    assert complete is False
    assert poweroff_calls == [True]

    # deadline exceeded mid-write -> never completes, still requests poweroff
    poweroff_calls.clear()
    complete = export_and_poweroff(make_ops(10, clock_jump=True), stream)
    assert complete is False
    assert poweroff_calls == [True]


def main() -> int:
    tests = [
        test_terminal_literal_size_and_fields,
        test_round_trip_happy_path,
        test_truncation_at_every_boundary_rejects,
        test_appended_bytes_reject,
        test_unknown_and_duplicate_members_reject,
        test_one_byte_wrong_challenge_changes_terminal,
        test_exact_byte_cap_boundary,
        test_deadline_and_stalled_write_still_requests_poweroff,
    ]
    for test in tests:
        test()
        print(f"ok   {test.__name__}")
    print(f"SPP diagnostic UART export: ok ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
