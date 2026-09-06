#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Shared, staged SPPUART/1 codec and fail-closed serial writer.

This module deliberately knows nothing about capture, mapper, appliances, or
poweroff.  The controller owns those policy decisions; this boundary only
formats, validates, and serializes one canonical printable-ASCII record at a
time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Callable, Final

from conf_proc_spp_diag_failure_terminal_reasons import (
    FAILURE_TERMINAL_SIZE,
    encode_failure_terminal,
)
from conf_proc_spp_diag_uart_reasons import (
    CP_SPP_DIAG_UART_ASCII,
    CP_SPP_DIAG_UART_BASE64,
    CP_SPP_DIAG_UART_DEADLINE,
    CP_SPP_DIAG_UART_HASH,
    CP_SPP_DIAG_UART_IDENTITY,
    CP_SPP_DIAG_UART_KIND,
    CP_SPP_DIAG_UART_LIMIT,
    CP_SPP_DIAG_UART_SEQUENCE,
    CP_SPP_DIAG_UART_STATE,
    CP_SPP_DIAG_UART_WRITE,
    SppDiagUartError,
)


MAGIC: Final = b"SPPUART/1"
MARKER: Final = MAGIC + b"|k="
MAX_S_PAYLOAD_BYTES: Final = 65_536
MAX_SNAPSHOT_BYTES: Final = 16 * 1024 * 1024
MAX_FRAMES: Final = 258
MAX_WIRE_BYTES: Final = 22_500_000
MAX_DECODED_BYTES: Final = MAX_SNAPSHOT_BYTES + 1 + FAILURE_TERMINAL_SIZE
MAX_NON_PAYLOAD_OVERHEAD: Final = 232
MAX_RECORD_WIRE_BYTES: Final = MAX_NON_PAYLOAD_OVERHEAD + 4 * ((MAX_S_PAYLOAD_BYTES + 2) // 3)

KIND_SUCCESS: Final = "S"
KIND_INVALIDATE: Final = "I"
KIND_FAILURE: Final = "F"
_KINDS: Final = frozenset((KIND_SUCCESS, KIND_INVALIDATE, KIND_FAILURE))


def _require_identity(value: bytes) -> None:
    if type(value) is not bytes or len(value) != 32:
        raise SppDiagUartError(CP_SPP_DIAG_UART_IDENTITY)


def _decimal(field: bytes, maximum: int) -> int:
    if not field or (field != b"0" and (field[0] == ord("0") or not field.isdigit())):
        raise SppDiagUartError(CP_SPP_DIAG_UART_ASCII)
    if field == b"0":
        return 0
    if not field.isdigit() or len(field) > len(str(maximum)):
        raise SppDiagUartError(CP_SPP_DIAG_UART_LIMIT)
    value = int(field)
    if value > maximum:
        raise SppDiagUartError(CP_SPP_DIAG_UART_LIMIT)
    return value


def _hex(field: bytes) -> bytes:
    if len(field) != 64 or any(byte not in b"0123456789abcdef" for byte in field):
        raise SppDiagUartError(CP_SPP_DIAG_UART_ASCII)
    return bytes.fromhex(field.decode("ascii"))


def _validate_kind_length(kind: str, length: int) -> None:
    if kind == KIND_SUCCESS:
        if not 1 <= length <= MAX_S_PAYLOAD_BYTES:
            raise SppDiagUartError(CP_SPP_DIAG_UART_LIMIT)
    elif kind == KIND_INVALIDATE:
        if length != 1:
            raise SppDiagUartError(CP_SPP_DIAG_UART_LIMIT)
    elif kind == KIND_FAILURE:
        if length != FAILURE_TERMINAL_SIZE:
            raise SppDiagUartError(CP_SPP_DIAG_UART_LIMIT)
    else:
        raise SppDiagUartError(CP_SPP_DIAG_UART_KIND)


@dataclass(frozen=True)
class UartFrame:
    """One decoded and authenticated SPPUART/1 record."""

    kind: str
    challenge: bytes
    run_identity: bytes
    sequence: int
    payload: bytes
    wire: bytes


@dataclass(frozen=True)
class UartRecordHeader:
    """Bounded, unauthenticated-payload fields available before Base64 decoding."""

    kind: str
    challenge: bytes
    run_identity: bytes
    sequence: int
    length: int
    digest: bytes
    encoded: bytes


def encode_uart_record(
    *, kind: str, challenge: bytes, run_identity: bytes, sequence: int, payload: bytes
) -> bytes:
    """Encode exactly one canonical LF-terminated printable ASCII record."""

    _require_identity(challenge)
    _require_identity(run_identity)
    if kind not in _KINDS:
        raise SppDiagUartError(CP_SPP_DIAG_UART_KIND)
    if type(sequence) is not int or not 0 <= sequence < MAX_FRAMES:
        raise SppDiagUartError(CP_SPP_DIAG_UART_SEQUENCE)
    if type(payload) is not bytes:
        raise SppDiagUartError(CP_SPP_DIAG_UART_LIMIT)
    _validate_kind_length(kind, len(payload))
    if kind == KIND_INVALIDATE and payload != b"\0":
        raise SppDiagUartError(CP_SPP_DIAG_UART_STATE)
    encoded = base64.b64encode(payload)
    record = (
        MAGIC
        + b"|k="
        + kind.encode("ascii")
        + b"|c="
        + challenge.hex().encode("ascii")
        + b"|r="
        + run_identity.hex().encode("ascii")
        + b"|n="
        + str(sequence).encode("ascii")
        + b"|l="
        + str(len(payload)).encode("ascii")
        + b"|h="
        + hashlib.sha256(payload).hexdigest().encode("ascii")
        + b"|b="
        + encoded
        + b"\n"
    )
    if len(record) - len(encoded) > MAX_NON_PAYLOAD_OVERHEAD or len(record) > MAX_RECORD_WIRE_BYTES:
        raise AssertionError("SPPUART/1 overhead bound")
    return record


def inspect_uart_record(
    record: bytes,
    *,
    expected_challenge: bytes,
    expected_run_identity: bytes,
) -> UartRecordHeader:
    """Bound every field that controls a later payload allocation or decode."""

    _require_identity(expected_challenge)
    _require_identity(expected_run_identity)
    if type(record) is not bytes or not record.endswith(b"\n") or len(record) > MAX_RECORD_WIRE_BYTES:
        raise SppDiagUartError(CP_SPP_DIAG_UART_ASCII)
    if any(byte < 0x20 or byte > 0x7E for byte in record[:-1]):
        raise SppDiagUartError(CP_SPP_DIAG_UART_ASCII)
    fields = record[:-1].split(b"|")
    if len(fields) != 8 or fields[0] != MAGIC:
        raise SppDiagUartError(CP_SPP_DIAG_UART_ASCII)
    prefixes = (b"k=", b"c=", b"r=", b"n=", b"l=", b"h=", b"b=")
    if any(not field.startswith(prefix) for field, prefix in zip(fields[1:], prefixes)):
        raise SppDiagUartError(CP_SPP_DIAG_UART_ASCII)
    kind_field = fields[1][2:]
    if len(kind_field) != 1 or kind_field not in (b"S", b"I", b"F"):
        raise SppDiagUartError(CP_SPP_DIAG_UART_KIND)
    kind = kind_field.decode("ascii")
    challenge = _hex(fields[2][2:])
    run_identity = _hex(fields[3][2:])
    if not hmac.compare_digest(challenge, expected_challenge) or not hmac.compare_digest(run_identity, expected_run_identity):
        raise SppDiagUartError(CP_SPP_DIAG_UART_IDENTITY)
    sequence = _decimal(fields[4][2:], MAX_FRAMES - 1)
    length = _decimal(fields[5][2:], MAX_S_PAYLOAD_BYTES)
    _validate_kind_length(kind, length)
    digest = _hex(fields[6][2:])
    encoded = fields[7][2:]
    if len(encoded) != 4 * ((length + 2) // 3):
        raise SppDiagUartError(CP_SPP_DIAG_UART_BASE64)
    return UartRecordHeader(kind, challenge, run_identity, sequence, length, digest, encoded)


def decode_uart_record(
    record: bytes,
    *,
    expected_challenge: bytes,
    expected_run_identity: bytes,
) -> UartFrame:
    """Decode a pre-bounded canonical record and authenticate its payload."""

    header = inspect_uart_record(
        record, expected_challenge=expected_challenge, expected_run_identity=expected_run_identity
    )
    try:
        payload = base64.b64decode(header.encoded, validate=True)
    except Exception as exc:
        raise SppDiagUartError(CP_SPP_DIAG_UART_BASE64) from exc
    if len(payload) != header.length or base64.b64encode(payload) != header.encoded:
        raise SppDiagUartError(CP_SPP_DIAG_UART_BASE64)
    if not hmac.compare_digest(hashlib.sha256(payload).digest(), header.digest):
        raise SppDiagUartError(CP_SPP_DIAG_UART_HASH)
    if header.kind == KIND_INVALIDATE and payload != b"\0":
        raise SppDiagUartError(CP_SPP_DIAG_UART_STATE)
    return UartFrame(header.kind, header.challenge, header.run_identity, header.sequence, payload, record)


class FramedUartWriter:
    """One-way record writer; any attempted-record failure permanently poisons it."""

    def __init__(self, challenge: bytes, run_identity: bytes) -> None:
        _require_identity(challenge)
        _require_identity(run_identity)
        self.challenge = challenge
        self.run_identity = run_identity
        self.next_sequence = 0
        self.pending_record: bytes | None = None
        self.pending_offset = 0
        self.pending_kind: str | None = None
        self.poisoned = False
        self._success: bytes | None = None
        self._success_offset = 0
        self._success_complete = False
        self._invalidated = False
        self._terminal = False

    @property
    def empty(self) -> bool:
        return self.pending_record is None

    @property
    def success_complete(self) -> bool:
        return self._success_complete and not self.poisoned and self.empty

    @property
    def can_emit_failure(self) -> bool:
        return not self.poisoned and self.empty and (self._success is None or self._invalidated) and not self._terminal

    def load_success(self, stream: bytes) -> None:
        if self.poisoned or self._success is not None or self._terminal or self.pending_record is not None:
            raise SppDiagUartError(CP_SPP_DIAG_UART_STATE)
        if type(stream) is not bytes or not 1 <= len(stream) <= MAX_SNAPSHOT_BYTES:
            raise SppDiagUartError(CP_SPP_DIAG_UART_LIMIT)
        self._success = stream

    def _poison(self, reason: str) -> None:
        self.poisoned = True
        raise SppDiagUartError(reason)

    def _start(self, kind: str, payload: bytes) -> None:
        if self.poisoned or self.pending_record is not None or self.next_sequence >= MAX_FRAMES:
            raise SppDiagUartError(CP_SPP_DIAG_UART_STATE)
        self.pending_record = encode_uart_record(
            kind=kind,
            challenge=self.challenge,
            run_identity=self.run_identity,
            sequence=self.next_sequence,
            payload=payload,
        )
        self.pending_offset = 0
        self.pending_kind = kind

    def _write_pending(
        self,
        *,
        write_serial: Callable[[bytes], int],
        wait_writable: Callable[[float], bool],
        monotonic: Callable[[], float],
        deadline: float,
    ) -> None:
        assert self.pending_record is not None
        while self.pending_offset < len(self.pending_record):
            if monotonic() > deadline:
                self._poison(CP_SPP_DIAG_UART_DEADLINE)
            try:
                if not wait_writable(deadline) or monotonic() > deadline:
                    self._poison(CP_SPP_DIAG_UART_DEADLINE)
                written = write_serial(self.pending_record[self.pending_offset :])
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                self._poison(CP_SPP_DIAG_UART_WRITE)
            remaining = len(self.pending_record) - self.pending_offset
            if type(written) is not int or written <= 0 or written > remaining:
                self._poison(CP_SPP_DIAG_UART_WRITE)
            self.pending_offset += written
        # The LF is now physically handed to the serial driver.  It is never
        # reused, even if the following drain reveals an indeterminate queue.
        self.next_sequence += 1

    def _drain(
        self,
        *,
        wait_writable: Callable[[float], bool],
        serial_queue_bytes: Callable[[], int],
        monotonic: Callable[[], float],
        deadline: float,
    ) -> None:
        assert self.pending_record is not None
        while True:
            if monotonic() > deadline:
                self._poison(CP_SPP_DIAG_UART_DEADLINE)
            try:
                queued = serial_queue_bytes()
                if type(queued) is not int or queued < 0:
                    self._poison(CP_SPP_DIAG_UART_WRITE)
                if queued == 0:
                    self.pending_record = None
                    self.pending_offset = 0
                    self.pending_kind = None
                    return
                if not wait_writable(deadline) or monotonic() > deadline:
                    self._poison(CP_SPP_DIAG_UART_DEADLINE)
            except SppDiagUartError:
                raise
            except OSError:
                self._poison(CP_SPP_DIAG_UART_WRITE)

    def _send_record(
        self,
        kind: str,
        payload: bytes,
        *,
        write_serial: Callable[[bytes], int],
        wait_writable: Callable[[float], bool],
        serial_queue_bytes: Callable[[], int],
        monotonic: Callable[[], float],
        deadline: float,
    ) -> None:
        self._start(kind, payload)
        self._write_pending(
            write_serial=write_serial, wait_writable=wait_writable, monotonic=monotonic, deadline=deadline
        )
        self._drain(
            wait_writable=wait_writable,
            serial_queue_bytes=serial_queue_bytes,
            monotonic=monotonic,
            deadline=deadline,
        )

    def write_success(
        self,
        *,
        write_serial: Callable[[bytes], int],
        wait_writable: Callable[[float], bool],
        serial_queue_bytes: Callable[[], int],
        monotonic: Callable[[], float],
        deadline: float,
    ) -> None:
        if self.poisoned or self._success is None or self._success_complete or self._invalidated or self._terminal:
            raise SppDiagUartError(CP_SPP_DIAG_UART_STATE)
        while self._success_offset < len(self._success):
            end = min(self._success_offset + MAX_S_PAYLOAD_BYTES, len(self._success))
            self._send_record(
                KIND_SUCCESS,
                self._success[self._success_offset : end],
                write_serial=write_serial,
                wait_writable=wait_writable,
                serial_queue_bytes=serial_queue_bytes,
                monotonic=monotonic,
                deadline=deadline,
            )
            self._success_offset = end
        self._success_complete = True

    def emit_invalidator(
        self,
        *,
        write_serial: Callable[[bytes], int],
        wait_writable: Callable[[float], bool],
        serial_queue_bytes: Callable[[], int],
        monotonic: Callable[[], float],
        deadline: float,
    ) -> None:
        if not self.success_complete or self._invalidated or self._terminal:
            raise SppDiagUartError(CP_SPP_DIAG_UART_STATE)
        self._send_record(
            KIND_INVALIDATE,
            b"\0",
            write_serial=write_serial,
            wait_writable=wait_writable,
            serial_queue_bytes=serial_queue_bytes,
            monotonic=monotonic,
            deadline=deadline,
        )
        self._invalidated = True

    def emit_failure(
        self,
        reason: str,
        phase: int,
        *,
        write_serial: Callable[[bytes], int],
        wait_writable: Callable[[float], bool],
        serial_queue_bytes: Callable[[], int],
        monotonic: Callable[[], float],
        deadline: float,
    ) -> None:
        if not self.can_emit_failure:
            raise SppDiagUartError(CP_SPP_DIAG_UART_STATE)
        payload = encode_failure_terminal(reason, phase, self.challenge, self.run_identity)
        self._send_record(
            KIND_FAILURE,
            payload,
            write_serial=write_serial,
            wait_writable=wait_writable,
            serial_queue_bytes=serial_queue_bytes,
            monotonic=monotonic,
            deadline=deadline,
        )
        self._terminal = True
