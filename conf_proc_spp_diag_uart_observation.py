#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Host-only, finite-blob observation of one SPPUART/1 transport result.

This is intentionally not a capture reader and not a mapper input.  It accepts
one already-supplied byte string and records what that byte string proves, with
snapshot-relative extents for independent off-box audit.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from conf_proc_spp_diag_export import ExportedBundle, parse_export_stream
from conf_proc_spp_diag_export_reasons import CP_SPP_DIAG_EXPORT_TRUNCATED
from conf_proc_spp_diag_failure_terminal_reasons import FailureTerminal, parse_failure_terminal
from conf_proc_spp_diag_uart import (
    KIND_FAILURE,
    KIND_INVALIDATE,
    KIND_SUCCESS,
    MARKER,
    MAX_DECODED_BYTES,
    MAX_FRAMES,
    MAX_RECORD_WIRE_BYTES,
    MAX_SNAPSHOT_BYTES,
    MAX_WIRE_BYTES,
    UartFrame,
    decode_uart_record,
    inspect_uart_record,
)
from conf_proc_spp_diag_uart_reasons import (
    CP_SPP_DIAG_UART_IDENTITY,
    CP_SPP_DIAG_UART_LIMIT,
    CP_SPP_DIAG_UART_SEQUENCE,
    SppDiagUartError,
)


MAX_RAW_SNAPSHOT_BYTES: Final = 32 * 1024 * 1024
MAX_PREAMBLE_BYTES: Final = 1 * 1024 * 1024

STATUS_COMPLETE_RESULT: Final = "complete_result"
STATUS_STANDALONE_FAILURE: Final = "standalone_failure"
STATUS_INVALIDATED_RESULT: Final = "invalidated_result"
STATUS_INVALID: Final = "invalid"
STATUS_INCOMPLETE: Final = "incomplete"


@dataclass(frozen=True)
class SnapshotExtent:
    """A byte range in the supplied raw snapshot, including an immutable hash."""

    offset: int
    length: int
    sha256: bytes


@dataclass(frozen=True)
class DecodedExtent:
    """A byte range in the logical concatenated outer decoded payload stream."""

    offset: int
    length: int
    sha256: bytes


@dataclass(frozen=True)
class UartRecordObservation:
    kind: str
    sequence: int
    wire: SnapshotExtent
    decoded: DecodedExtent


@dataclass(frozen=True)
class UartObservation:
    """An immutable description, never a ``CapturedDiagnostic`` or mapper value."""

    status: str
    reason: str | None
    raw: SnapshotExtent
    preamble: SnapshotExtent | None
    wire: SnapshotExtent | None
    padding: SnapshotExtent | None
    records: tuple[UartRecordObservation, ...]
    decoded: DecodedExtent | None
    snapshot: bytes | None
    exported: ExportedBundle | None
    failure: FailureTerminal | None


def _extent(data: bytes, offset: int, length: int) -> SnapshotExtent:
    return SnapshotExtent(offset, length, hashlib.sha256(memoryview(data)[offset : offset + length]).digest())


def _decoded_extent(offset: int, payload: bytes) -> DecodedExtent:
    return DecodedExtent(offset, len(payload), hashlib.sha256(payload).digest())


def _observation(
    *,
    status: str,
    reason: str | None,
    data: bytes,
    marker: int | None,
    wire_end: int | None,
    padding_start: int | None,
    records: list[UartRecordObservation],
    decoded_size: int,
    decoded_sha256: bytes | None,
    snapshot: bytes | None = None,
    exported: ExportedBundle | None = None,
    failure: FailureTerminal | None = None,
) -> UartObservation:
    preamble = _extent(data, 0, marker) if marker is not None else _extent(data, 0, len(data))
    wire = _extent(data, marker, wire_end - marker) if marker is not None and wire_end is not None else None
    padding = _extent(data, padding_start, len(data) - padding_start) if padding_start is not None else None
    decoded = None
    if decoded_size:
        # The logical decoded stream has no snapshot byte address. Offset zero is
        # explicit; its digest is maintained while validated payloads are read.
        assert decoded_sha256 is not None
        decoded = DecodedExtent(0, decoded_size, decoded_sha256)
    return UartObservation(
        status,
        reason,
        _extent(data, 0, len(data)),
        preamble,
        wire,
        padding,
        tuple(records),
        decoded,
        snapshot,
        exported,
        failure,
    )


def _inner_success(snapshot: bytes, challenge: bytes, run_identity: bytes) -> tuple[ExportedBundle | None, str | None, str]:
    try:
        return parse_export_stream(
            snapshot, expected_challenge=challenge, expected_run_identity=run_identity
        ), None, STATUS_COMPLETE_RESULT
    except Exception as exc:
        reason = getattr(exc, "reason_code", str(exc))
        status = STATUS_INCOMPLETE if reason == CP_SPP_DIAG_EXPORT_TRUNCATED else STATUS_INVALID
        return None, reason, status


def observe_uart_blob(
    data: bytes,
    *,
    expected_challenge: bytes,
    expected_run_identity: bytes,
) -> UartObservation:
    """Observe one finite raw snapshot without reader, capture, or mapper semantics.

    A NUL run is terminal storage fill only once a semantic outer result has
    completed. A decoded invalidator is instead represented by a normal ``I``
    record with its own wire and decoded extents.
    """

    if type(data) is not bytes or len(data) > MAX_RAW_SNAPSHOT_BYTES:
        raise SppDiagUartError(CP_SPP_DIAG_UART_LIMIT)
    if any(type(value) is not bytes or len(value) != 32 for value in (expected_challenge, expected_run_identity)):
        raise SppDiagUartError(CP_SPP_DIAG_UART_IDENTITY)

    marker = data.find(MARKER)
    if marker < 0:
        return _observation(
            status=STATUS_INCOMPLETE,
            reason="SPPUART/1 marker absent",
            data=data,
            marker=None,
            wire_end=None,
            padding_start=None,
            records=[],
            decoded_size=0,
            decoded_sha256=None,
        )
    if marker > MAX_PREAMBLE_BYTES:
        return _observation(
            status=STATUS_INVALID,
            reason="SPPUART/1 preamble exceeds 1048576 bytes",
            data=data,
            marker=marker,
            wire_end=None,
            padding_start=None,
            records=[],
            decoded_size=0,
            decoded_sha256=None,
        )

    records: list[UartRecordObservation] = []
    payloads: list[bytes] = []
    offset = marker
    wire_end = marker
    decoded_size = 0
    decoded_hash = hashlib.sha256()
    expected_sequence = 0
    state = "start"
    late_failure: FailureTerminal | None = None

    def result(
        status: str,
        reason: str | None,
        *,
        padding_start: int | None = None,
        snapshot: bytes | None = None,
        exported: ExportedBundle | None = None,
        failure: FailureTerminal | None = None,
    ) -> UartObservation:
        return _observation(
            status=status,
            reason=reason,
            data=data,
            marker=marker,
            wire_end=wire_end,
            padding_start=padding_start,
            records=records,
            decoded_size=decoded_size,
            decoded_sha256=decoded_hash.digest() if decoded_size else None,
            snapshot=snapshot,
            exported=exported,
            failure=failure,
        )

    def semantic_result(*, padding_start: int | None) -> UartObservation:
        if state == "success":
            snapshot = b"".join(payloads)
            exported, reason, status = _inner_success(snapshot, expected_challenge, expected_run_identity)
            return result(status, reason, padding_start=padding_start, snapshot=snapshot if exported else None, exported=exported)
        if state == "invalidated":
            return result(
                STATUS_INVALIDATED_RESULT,
                None,
                padding_start=padding_start,
                snapshot=b"".join(payloads),
                failure=late_failure,
            )
        if state == "standalone_failure":
            return result(STATUS_STANDALONE_FAILURE, None, padding_start=padding_start, failure=late_failure)
        return result(STATUS_INCOMPLETE, "SPPUART/1 sequence has no terminal result", padding_start=padding_start)

    while offset < len(data):
        if data[offset] == 0:
            tail = memoryview(data)[offset:]
            if all(byte == 0 for byte in tail):
                semantic = semantic_result(padding_start=offset)
                # Padding is valid only after a semantically complete outer record.
                if semantic.status in (STATUS_COMPLETE_RESULT, STATUS_STANDALONE_FAILURE, STATUS_INVALIDATED_RESULT):
                    return semantic
                return result(STATUS_INVALID if semantic.status == STATUS_INVALID else STATUS_INCOMPLETE, semantic.reason)
            return result(STATUS_INVALID, "nonzero suffix after outer record")
        if not data.startswith(MARKER, offset):
            return result(STATUS_INVALID, "nonzero suffix outside an outer record")
        line_end = data.find(b"\n", offset)
        if line_end < 0:
            return result(STATUS_INCOMPLETE, "unterminated SPPUART/1 record")
        line_size = line_end + 1 - offset
        if line_size > MAX_RECORD_WIRE_BYTES or line_end + 1 - marker > MAX_WIRE_BYTES:
            return result(STATUS_INVALID, "SPPUART/1 wire limit")
        record_wire = data[offset : line_end + 1]
        if len(records) >= MAX_FRAMES:
            return result(STATUS_INVALID, "SPPUART/1 frame limit")
        try:
            header = inspect_uart_record(
                record_wire,
                expected_challenge=expected_challenge,
                expected_run_identity=expected_run_identity,
            )
        except SppDiagUartError as exc:
            return result(STATUS_INVALID, exc.reason_code)
        if header.sequence != expected_sequence:
            return result(STATUS_INVALID, CP_SPP_DIAG_UART_SEQUENCE)
        if decoded_size + header.length > MAX_DECODED_BYTES:
            return result(STATUS_INVALID, "SPPUART/1 decoded limit")
        if header.kind == KIND_SUCCESS:
            if state != "start" and state != "success":
                return result(STATUS_INVALID, "SPPUART/1 success after terminal record")
            if len(payloads) >= MAX_SNAPSHOT_BYTES // 65_536:
                return result(STATUS_INVALID, "SPPUART/1 success frame limit")
        elif header.kind == KIND_INVALIDATE:
            if state != "success":
                return result(STATUS_INVALID, "SPPUART/1 invalidator without complete success")
            snapshot = b"".join(payloads)
            exported, reason, status = _inner_success(snapshot, expected_challenge, expected_run_identity)
            if status != STATUS_COMPLETE_RESULT:
                return result(status, reason)
        elif header.kind == KIND_FAILURE and state not in ("start", "invalidated"):
            return result(STATUS_INVALID, "SPPUART/1 failure is not standalone or late")
        if header.kind == KIND_FAILURE and late_failure is not None:
            return result(STATUS_INVALID, "SPPUART/1 second failure record")
        try:
            frame: UartFrame = decode_uart_record(
                record_wire,
                expected_challenge=expected_challenge,
                expected_run_identity=expected_run_identity,
            )
        except SppDiagUartError as exc:
            return result(STATUS_INVALID, exc.reason_code)
        logical_offset = decoded_size
        decoded_size += len(frame.payload)
        decoded_hash.update(frame.payload)
        records.append(
            UartRecordObservation(
                frame.kind,
                frame.sequence,
                _extent(data, offset, len(record_wire)),
                _decoded_extent(logical_offset, frame.payload),
            )
        )
        expected_sequence += 1
        wire_end = line_end + 1
        offset = wire_end
        if frame.kind == KIND_SUCCESS:
            payloads.append(frame.payload)
            state = "success"
        elif frame.kind == KIND_INVALIDATE:
            state = "invalidated"
        else:
            try:
                parsed_failure = parse_failure_terminal(
                    frame.payload,
                    expected_challenge=expected_challenge,
                    expected_run_identity=expected_run_identity,
                )
            except Exception as exc:
                return result(STATUS_INVALID, getattr(exc, "reason_code", str(exc)))
            late_failure = parsed_failure
            if state == "start":
                state = "standalone_failure"
            else:
                # An F after I is allowed once and makes the invalidated result
                # more descriptive; it never changes it into a failure-only result.
                state = "invalidated"

    return semantic_result(padding_start=None)
