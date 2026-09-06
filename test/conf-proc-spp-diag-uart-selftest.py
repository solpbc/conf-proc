#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent literal and state checks for the SPPUART/1 framing profile."""

from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from conf_proc_spp_diag_export import ExportOps, PoweroffInvalidationFailed, PoweroffReturned, export_and_poweroff
from conf_proc_spp_diag_failure_terminal_reasons import SPPFLR1_EXPORT, encode_failure_terminal
from conf_proc_spp_diag_uart import (
    KIND_FAILURE,
    KIND_INVALIDATE,
    KIND_SUCCESS,
    MAX_FRAMES,
    MAX_NON_PAYLOAD_OVERHEAD,
    MAX_RECORD_WIRE_BYTES,
    MAX_SNAPSHOT_BYTES,
    MAX_WIRE_BYTES,
    MAX_S_PAYLOAD_BYTES,
    FramedUartWriter,
    decode_uart_record,
    encode_uart_record,
)
from conf_proc_spp_diag_uart_observation import (
    MAX_PREAMBLE_BYTES,
    STATUS_COMPLETE_RESULT,
    STATUS_INCOMPLETE,
    STATUS_INVALID,
    STATUS_INVALIDATED_RESULT,
    STATUS_STANDALONE_FAILURE,
    observe_uart_blob,
)
from conf_proc_spp_diag_uart_reasons import SppDiagUartError
from conf_proc_spp_diag_export import MEMBER_NAMES, build_export_stream


CHALLENGE = b"\0" * 32
RUN = b"\x11" * 32
FIXTURE = ROOT / "test/fixtures/spp-diag-uart-v1/literal-invalidator-line.uart"


def literal_frame(kind: str, sequence: int, payload: bytes, *, challenge: bytes = CHALLENGE, run: bytes = RUN) -> bytes:
    """Independent spelling of the frozen outer grammar, not the production encoder."""

    return (
        b"SPPUART/1|k=" + kind.encode() + b"|c=" + challenge.hex().encode() + b"|r=" + run.hex().encode()
        + b"|n=" + str(sequence).encode() + b"|l=" + str(len(payload)).encode()
        + b"|h=" + hashlib.sha256(payload).hexdigest().encode() + b"|b=" + base64.b64encode(payload) + b"\n"
    )


def inner_stream(*, challenge: bytes = CHALLENGE, run: bytes = RUN) -> bytes:
    return build_export_stream(members={name: b"" for name in MEMBER_NAMES[:-1]}, challenge=challenge, run_identity=run)


def split_success(stream: bytes, count: int) -> tuple[bytes, ...]:
    """Split a valid inner stream into exactly ``count`` nonempty outer chunks."""

    assert 1 <= count <= len(stream)
    return tuple(stream[index : index + 1] for index in range(count - 1)) + (stream[count - 1 :],)


class Clock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _writer(stream: bytes) -> FramedUartWriter:
    writer = FramedUartWriter(CHALLENGE, RUN)
    writer.load_success(stream)
    return writer


def test_literal_fixture_grammar_overhead_and_canonicality() -> None:
    literal = FIXTURE.read_bytes()
    parsed = decode_uart_record(literal, expected_challenge=CHALLENGE, expected_run_identity=RUN)
    assert parsed.kind == KIND_INVALIDATE and parsed.payload == b"\0" and parsed.sequence == 0
    assert literal == literal_frame(KIND_INVALIDATE, 0, b"\0")

    record = encode_uart_record(
        kind=KIND_SUCCESS,
        challenge=CHALLENGE,
        run_identity=RUN,
        sequence=257,
        payload=b"x" * MAX_S_PAYLOAD_BYTES,
    )
    assert len(record) == MAX_RECORD_WIRE_BYTES
    assert len(record) - len(base64.b64encode(b"x" * MAX_S_PAYLOAD_BYTES)) == MAX_NON_PAYLOAD_OVERHEAD == 232
    assert decode_uart_record(record, expected_challenge=CHALLENGE, expected_run_identity=RUN).payload == b"x" * MAX_S_PAYLOAD_BYTES
    for malformed in (
        record.replace(b"|n=257|", b"|n=0257|"),
        record.replace(b"|b=", b"|b=A"),
        record.replace(b"|h=", b"|h=F"),
        record[:-1],
    ):
        try:
            decode_uart_record(malformed, expected_challenge=CHALLENGE, expected_run_identity=RUN)
        except SppDiagUartError:
            pass
        else:
            raise AssertionError("noncanonical record accepted")
    for kind, payload in ((KIND_SUCCESS, b""), (KIND_SUCCESS, b"x" * (MAX_S_PAYLOAD_BYTES + 1)), (KIND_INVALIDATE, b"x")):
        try:
            encode_uart_record(kind=kind, challenge=CHALLENGE, run_identity=RUN, sequence=0, payload=payload)
        except SppDiagUartError:
            pass
        else:
            raise AssertionError("one-over payload bound accepted")


def test_writer_short_eagain_eintr_pending_and_poisoning() -> None:
    writer = _writer(b"A" * (MAX_S_PAYLOAD_BYTES + 1))
    physical: list[bytes] = []
    attempts = [0]

    def write(data: bytes) -> int:
        attempts[0] += 1
        if attempts[0] == 2:
            raise BlockingIOError()
        if attempts[0] == 3:
            raise InterruptedError()
        count = min(19, len(data))
        physical.append(data[:count])
        return count

    writer.write_success(
        write_serial=write, wait_writable=lambda _deadline: True, serial_queue_bytes=lambda: 0,
        monotonic=Clock(), deadline=2400.0,
    )
    expected = literal_frame(KIND_SUCCESS, 0, b"A" * MAX_S_PAYLOAD_BYTES) + literal_frame(KIND_SUCCESS, 1, b"A")
    assert b"".join(physical) == expected and writer.success_complete and writer.next_sequence == 2

    writer = _writer(b"B")
    writes: list[bytes] = []
    waits = [0]

    def wait(_deadline: float) -> bool:
        waits[0] += 1
        return waits[0] == 1

    def short(data: bytes) -> int:
        writes.append(data[:7])
        return 7

    try:
        writer.write_success(
            write_serial=short, wait_writable=wait, serial_queue_bytes=lambda: 0, monotonic=Clock(), deadline=2400.0
        )
    except SppDiagUartError:
        pass
    else:
        raise AssertionError("failed S record accepted")
    assert writer.poisoned and writer.pending_record is not None and writer.pending_offset == 7
    pending = writer.pending_record
    try:
        writer.emit_invalidator(
            write_serial=short, wait_writable=wait, serial_queue_bytes=lambda: 0, monotonic=Clock(), deadline=1.0
        )
    except SppDiagUartError:
        pass
    else:
        raise AssertionError("poisoned writer appended invalidator")
    assert writer.pending_record == pending and b"".join(writes) == pending[:7]

    writer = _writer(b"C")
    clock = Clock(2400.1)
    try:
        writer.write_success(
            write_serial=lambda _data: 1, wait_writable=lambda _deadline: True, serial_queue_bytes=lambda: 0,
            monotonic=clock, deadline=2400.0,
        )
    except SppDiagUartError:
        pass
    else:
        raise AssertionError("zero-offset deadline did not poison")
    assert writer.poisoned and writer.pending_offset == 0

    writer = _writer(b"D")
    drain_waits = [0]

    def drain_wait(_deadline: float) -> bool:
        drain_waits[0] += 1
        return drain_waits[0] == 1

    try:
        writer.write_success(
            write_serial=lambda data: len(data), wait_writable=drain_wait, serial_queue_bytes=lambda: 1,
            monotonic=Clock(), deadline=2400.0,
        )
    except SppDiagUartError:
        pass
    else:
        raise AssertionError("drain failure did not poison")
    assert writer.poisoned and writer.pending_record is not None and writer.pending_offset == len(writer.pending_record)


def test_export_state_deadlines_and_terminal_order() -> None:
    clock = Clock()
    writes: list[bytes] = []
    writer = _writer(b"Z")
    ops = ExportOps(
        write_serial=lambda data: writes.append(data) or len(data),
        wait_writable=lambda _deadline: True,
        serial_queue_bytes=lambda: 0,
        monotonic=clock,
        request_poweroff_hardware=lambda: None,
    )
    try:
        export_and_poweroff(ops, writer)
    except PoweroffReturned as exc:
        assert exc.writer is writer
    else:
        raise AssertionError("returned primary poweroff accepted")
    assert b"".join(writes) == literal_frame(KIND_SUCCESS, 0, b"Z") + literal_frame(KIND_INVALIDATE, 1, b"\0")
    writer.emit_failure(
        SPPFLR1_EXPORT, 15,
        write_serial=lambda data: writes.append(data) or len(data), wait_writable=lambda _deadline: True,
        serial_queue_bytes=lambda: 0, monotonic=clock, deadline=clock() + 5.0,
    )
    late = decode_uart_record(writes[-1], expected_challenge=CHALLENGE, expected_run_identity=RUN)
    assert late.kind == KIND_FAILURE and late.sequence == 2 and len(late.payload) == 112

    writer = _writer(b"Q")
    try:
        export_and_poweroff(
            ExportOps(lambda _data: 0, lambda _deadline: True, lambda: 0, Clock(), lambda: None), writer
        )
    except PoweroffReturned:
        pass
    else:
        raise AssertionError("failed S did not fail-stop")
    assert writer.poisoned and not writer.can_emit_failure

    writer = _writer(b"Q")
    calls = [0]

    def invalidator_short(data: bytes) -> int:
        calls[0] += 1
        return len(data) if calls[0] == 1 else 0

    try:
        export_and_poweroff(
            ExportOps(invalidator_short, lambda _deadline: True, lambda: 0, Clock(), lambda: None), writer
        )
    except PoweroffInvalidationFailed:
        pass
    else:
        raise AssertionError("failed I did not surface")
    assert writer.poisoned and not writer.can_emit_failure


def test_observation_statuses_padding_resync_limits_and_identity_binding() -> None:
    stream = inner_stream()
    success = literal_frame(KIND_SUCCESS, 0, stream)
    observed = observe_uart_blob(b"serial noise\n" + success + b"\0" * 3, expected_challenge=CHALLENGE, expected_run_identity=RUN)
    assert observed.status == STATUS_COMPLETE_RESULT and observed.padding is not None and observed.padding.length == 3
    assert observed.records[0].decoded.length == len(stream) and observed.snapshot == stream
    assert observed.profile_identifier == "SPPUART" and observed.profile_version == 1
    assert observed.expected_challenge == CHALLENGE and observed.expected_run_identity == RUN
    assert observed.raw.offset == 0 and observed.preamble is not None and observed.preamble.offset == 0
    assert observed.wire is not None and observed.wire.offset == len(b"serial noise\n")
    assert not hasattr(observed.records[0].decoded, "offset")

    failure = encode_failure_terminal(SPPFLR1_EXPORT, 15, CHALLENGE, RUN)
    standalone = observe_uart_blob(literal_frame(KIND_FAILURE, 0, failure), expected_challenge=CHALLENGE, expected_run_identity=RUN)
    assert standalone.status == STATUS_STANDALONE_FAILURE and standalone.failure is not None
    invalidated = observe_uart_blob(
        success + literal_frame(KIND_INVALIDATE, 1, b"\0") + literal_frame(KIND_FAILURE, 2, failure),
        expected_challenge=CHALLENGE,
        expected_run_identity=RUN,
    )
    assert invalidated.status == STATUS_INVALIDATED_RESULT and invalidated.failure is not None
    assert invalidated.records[1].decoded.length == 1 and invalidated.padding is None

    cases = (
        success + b"\0x",  # nonzero suffix after raw NUL fill
        success + literal_frame(KIND_FAILURE, 1, failure),  # F without I
        success + success,  # second result / bad sequence
        success + b"SPPUART/1|k=S",  # no resynchronization of partial candidate
        success[:-1] + b"\0" * 5,  # partial outer line is not raw padding
        success + b"\0" + literal_frame(KIND_INVALIDATE, 1, b"\0"),
        success[:20] + b"\0" + success[21:],  # NUL inside a complete outer line
        success + literal_frame(KIND_SUCCESS, 1, stream),  # sequence-correct second SPPDBN1 result
    )
    for blob in cases:
        assert observe_uart_blob(blob, expected_challenge=CHALLENGE, expected_run_identity=RUN).status != STATUS_COMPLETE_RESULT
    assert observe_uart_blob(success[:-1], expected_challenge=CHALLENGE, expected_run_identity=RUN).status == STATUS_INCOMPLETE
    assert observe_uart_blob(b"x" * (MAX_PREAMBLE_BYTES + 1) + success, expected_challenge=CHALLENGE, expected_run_identity=RUN).status == STATUS_INVALID

    outer_wrong = literal_frame(KIND_SUCCESS, 0, stream, challenge=b"\x22" * 32)
    assert observe_uart_blob(outer_wrong, expected_challenge=CHALLENGE, expected_run_identity=RUN).status == STATUS_INVALID
    outer_wrong_run = literal_frame(KIND_SUCCESS, 0, stream, run=b"\x33" * 32)
    assert observe_uart_blob(outer_wrong_run, expected_challenge=CHALLENGE, expected_run_identity=RUN).status == STATUS_INVALID
    inner_wrong = literal_frame(KIND_SUCCESS, 0, inner_stream(challenge=b"\x22" * 32))
    assert observe_uart_blob(inner_wrong, expected_challenge=CHALLENGE, expected_run_identity=RUN).status == STATUS_INVALID
    assert observe_uart_blob(success + literal_frame(KIND_INVALIDATE, 1, b"\0") + b"x", expected_challenge=CHALLENGE, expected_run_identity=RUN).status == STATUS_INVALID


def test_observation_frame_wire_and_raw_one_over_limits() -> None:
    stream = inner_stream()
    success_258 = b"".join(
        literal_frame(KIND_SUCCESS, index, payload) for index, payload in enumerate(split_success(stream, MAX_FRAMES))
    )
    complete = observe_uart_blob(success_258, expected_challenge=CHALLENGE, expected_run_identity=RUN)
    assert complete.status == STATUS_COMPLETE_RESULT and len(complete.records) == MAX_FRAMES

    success_257_then_i = b"".join(
        literal_frame(KIND_SUCCESS, index, payload) for index, payload in enumerate(split_success(stream, MAX_FRAMES - 1))
    ) + literal_frame(KIND_INVALIDATE, MAX_FRAMES - 1, b"\0")
    invalidated = observe_uart_blob(
        success_257_then_i, expected_challenge=CHALLENGE, expected_run_identity=RUN
    )
    assert invalidated.status == STATUS_INVALIDATED_RESULT and len(invalidated.records) == MAX_FRAMES

    over_frames = observe_uart_blob(
        success_258 + literal_frame(KIND_SUCCESS, 0, b"x"),
        expected_challenge=CHALLENGE,
        expected_run_identity=RUN,
    )
    assert over_frames.status == STATUS_INVALID and over_frames.reason == "SPPUART/1 frame limit"

    over_success = bytearray()
    for index in range(MAX_SNAPSHOT_BYTES // MAX_S_PAYLOAD_BYTES):
        over_success.extend(literal_frame(KIND_SUCCESS, index, b"x" * MAX_S_PAYLOAD_BYTES))
    over_success.extend(literal_frame(KIND_SUCCESS, MAX_SNAPSHOT_BYTES // MAX_S_PAYLOAD_BYTES, b"x"))
    over_decoded = observe_uart_blob(bytes(over_success), expected_challenge=CHALLENGE, expected_run_identity=RUN)
    assert over_decoded.status == STATUS_INVALID and over_decoded.reason == "SPPUART/1 success decoded limit"

    over_wire = b"SPPUART/1|k=" + b"x" * MAX_WIRE_BYTES + b"\n"
    assert observe_uart_blob(over_wire, expected_challenge=CHALLENGE, expected_run_identity=RUN).status == STATUS_INVALID
    try:
        observe_uart_blob(b"x" * (32 * 1024 * 1024 + 1), expected_challenge=CHALLENGE, expected_run_identity=RUN)
    except SppDiagUartError:
        pass
    else:
        raise AssertionError("raw snapshot cap +1 accepted")


TESTS = (
    test_literal_fixture_grammar_overhead_and_canonicality,
    test_writer_short_eagain_eintr_pending_and_poisoning,
    test_export_state_deadlines_and_terminal_order,
    test_observation_statuses_padding_resync_limits_and_identity_binding,
    test_observation_frame_wire_and_raw_one_over_limits,
)


if __name__ == "__main__":
    for test in TESTS:
        test()
        print(f"ok   {test.__name__}")
    print(f"SPPUART/1: ok ({len(TESTS)} tests)")
