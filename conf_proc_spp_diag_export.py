#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Canonical SPPDBN1 UART evidence-stream producer."""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
import struct
import unicodedata
from dataclasses import dataclass
from typing import Callable, Final

from conf_proc_spp_diag_export_reasons import (
    CP_SPP_DIAG_EXPORT_MEMBER_HASH,
    CP_SPP_DIAG_EXPORT_MEMBER_NAME,
    CP_SPP_DIAG_EXPORT_MEMBER_ORDER,
    CP_SPP_DIAG_EXPORT_MEMBER_SIZE,
    CP_SPP_DIAG_EXPORT_TERMINAL,
    CP_SPP_DIAG_EXPORT_TRAILING_BYTES,
    CP_SPP_DIAG_EXPORT_TRUNCATED,
    SppDiagExportError,
)
from conf_proc_spp_diag_uart import FramedUartWriter
from conf_proc_spp_diag_uart_reasons import SppDiagUartError


MAGIC: Final = b"SPPDBN1\0"
VERSION: Final = 1
TERMINAL_MAGIC: Final = b"SPPCAP1\0"
TERMINAL_VERSION: Final = 1
STATUS_COMPLETE: Final = 1
TERMINAL_SIZE: Final = 108
MAX_STREAM_BYTES: Final = 16_777_216
MAX_MEMBER_BYTES: Final = 8_388_608
_HEADER = struct.Struct(">8sII")
_RECORD = struct.Struct(">HQ32s")
_TERMINAL = struct.Struct(">8sHH32s32s32s")

MEMBER_NAMES: Final = (
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
PAYLOAD_MEMBER_NAMES: Final = MEMBER_NAMES[:-1]

UART_MAJOR: Final = 4
UART_MINOR: Final = 64


def _encode_record(name: str, payload: bytes) -> bytes:
    try:
        normalized = unicodedata.normalize("NFC", name)
        name_bytes = normalized.encode("utf-8", errors="strict")
    except (TypeError, UnicodeError) as exc:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_NAME) from exc
    if normalized != name or not name_bytes or len(name_bytes) > 255:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_NAME)
    if type(payload) is not bytes or len(payload) > MAX_MEMBER_BYTES:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_SIZE)
    return _RECORD.pack(len(name_bytes), len(payload), hashlib.sha256(payload).digest()) + name_bytes + payload


def encode_terminal(*, challenge: bytes, run_identity: bytes, prefix_digest: bytes) -> bytes:
    """Encode the exact successful-capture terminal payload."""

    if any(type(value) is not bytes or len(value) != 32 for value in (challenge, run_identity, prefix_digest)):
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TERMINAL)
    return _TERMINAL.pack(
        TERMINAL_MAGIC,
        TERMINAL_VERSION,
        STATUS_COMPLETE,
        challenge,
        run_identity,
        prefix_digest,
    )


def build_export_stream(*, members: dict[str, bytes], challenge: bytes, run_identity: bytes) -> bytes:
    """Build the closed 17-member canonical stream, binding its terminal to the prefix."""

    if type(members) is not dict or tuple(sorted(members)) != PAYLOAD_MEMBER_NAMES:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_NAME)
    prefix_parts = [_HEADER.pack(MAGIC, VERSION, len(MEMBER_NAMES))]
    prefix_size = _HEADER.size
    terminal_record_size = _RECORD.size + len(MEMBER_NAMES[-1].encode("utf-8")) + TERMINAL_SIZE
    for name in PAYLOAD_MEMBER_NAMES:
        record = _encode_record(name, members[name])
        if len(record) > MAX_STREAM_BYTES - prefix_size - terminal_record_size:
            raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_SIZE)
        prefix_parts.append(record)
        prefix_size += len(record)
    prefix = b"".join(prefix_parts)
    terminal = encode_terminal(
        challenge=challenge,
        run_identity=run_identity,
        prefix_digest=hashlib.sha256(prefix).digest(),
    )
    stream = prefix + _encode_record(MEMBER_NAMES[-1], terminal)
    if len(stream) > MAX_STREAM_BYTES:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_SIZE)
    return stream


@dataclass(frozen=True)
class ExportedMember:
    name: str
    size_bytes: int
    sha256: bytes
    payload: bytes


@dataclass(frozen=True)
class ExportedBundle:
    members: tuple[ExportedMember, ...]
    challenge: bytes
    run_identity: bytes


def parse_export_stream(
    data: bytes,
    *,
    expected_challenge: bytes | None = None,
    expected_run_identity: bytes | None = None,
) -> ExportedBundle:
    """Strict diagnostic parser used by producer-side tests and capture integration."""

    if type(data) is not bytes or len(data) > MAX_STREAM_BYTES:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_SIZE)
    offset = 0

    def take(size: int) -> bytes:
        nonlocal offset
        if size < 0 or size > len(data) - offset:
            raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TRUNCATED)
        chunk = data[offset : offset + size]
        offset += size
        return chunk

    magic, version, count = _HEADER.unpack(take(_HEADER.size))
    if magic != MAGIC or version != VERSION:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_NAME)
    if count != len(MEMBER_NAMES):
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_ORDER)

    members: list[ExportedMember] = []
    terminal_prefix_end = 0
    for expected_name in MEMBER_NAMES:
        record_offset = offset
        name_size, payload_size, digest = _RECORD.unpack(take(_RECORD.size))
        if payload_size > MAX_MEMBER_BYTES:
            raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_SIZE)
        try:
            name_bytes = take(name_size)
            name = name_bytes.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_NAME) from exc
        if unicodedata.normalize("NFC", name) != name:
            raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_NAME)
        if name != expected_name:
            raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_ORDER)
        if name == MEMBER_NAMES[-1]:
            terminal_prefix_end = record_offset
        payload = take(payload_size)
        if not hmac.compare_digest(hashlib.sha256(payload).digest(), digest):
            raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_HASH)
        members.append(ExportedMember(name, payload_size, digest, payload))

    if offset != len(data):
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TRAILING_BYTES)
    terminal = members[-1].payload
    if len(terminal) != TERMINAL_SIZE:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TERMINAL)
    terminal_magic, terminal_version, status, challenge, run_identity, prefix_digest = _TERMINAL.unpack(terminal)
    if terminal_magic != TERMINAL_MAGIC or terminal_version != TERMINAL_VERSION or status != STATUS_COMPLETE:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TERMINAL)
    if not hmac.compare_digest(prefix_digest, hashlib.sha256(data[:terminal_prefix_end]).digest()):
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TERMINAL)
    if expected_challenge is not None and not hmac.compare_digest(challenge, expected_challenge):
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TERMINAL)
    if expected_run_identity is not None and not hmac.compare_digest(run_identity, expected_run_identity):
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TERMINAL)
    return ExportedBundle(tuple(members), challenge, run_identity)


def uart_node_is_valid(path: str) -> bool:
    try:
        node = os.stat(path)
    except OSError:
        return False
    return stat.S_ISCHR(node.st_mode) and os.major(node.st_rdev) == UART_MAJOR and os.minor(node.st_rdev) == UART_MINOR


@dataclass
class ExportOps:
    write_serial: Callable[[bytes], int]
    wait_writable: Callable[[float], bool]
    serial_queue_bytes: Callable[[], int]
    monotonic: Callable[[], float]
    request_poweroff_hardware: Callable[[], None]


EXPORT_DEADLINE_SECONDS: Final = 2400.0


class PoweroffReturned(RuntimeError):
    """The poweroff request returned instead of stopping the appliance."""

    def __init__(self, writer: FramedUartWriter) -> None:
        self.writer = writer
        super().__init__("hardware poweroff returned")


class PoweroffInvalidationFailed(RuntimeError):
    """The appliance could not invalidate a completed stream after poweroff failed."""

    def __init__(self, writer: FramedUartWriter) -> None:
        self.writer = writer
        super().__init__("could not write framed stream invalidator")


_INVALIDATION_DEADLINE_SECONDS: Final = 1.0


def export_and_poweroff(ops: ExportOps, writer: FramedUartWriter) -> None:
    """Frame, write, and drain success under one 2,400-second deadline.

    The primary poweroff is attempted only after every success frame is fully
    drained. A returning (or errored) primary poweroff gets exactly one framed
    invalidator; the controller decides whether the now-valid late-failure path
    should follow. Any attempted record failure poisons ``writer``.
    """

    deadline = ops.monotonic() + EXPORT_DEADLINE_SECONDS
    try:
        writer.write_success(
            write_serial=ops.write_serial,
            wait_writable=ops.wait_writable,
            serial_queue_bytes=ops.serial_queue_bytes,
            monotonic=ops.monotonic,
            deadline=deadline,
        )
    except SppDiagUartError as exc:
        try:
            ops.request_poweroff_hardware()
        except Exception:
            pass
        raise PoweroffReturned(writer) from exc
    if not writer.success_complete:
        raise AssertionError("framed writer returned without a drained success stream")
    poweroff_error: BaseException | None = None
    try:
        ops.request_poweroff_hardware()
    except BaseException as exc:
        poweroff_error = exc
    try:
        writer.emit_invalidator(
            write_serial=ops.write_serial,
            wait_writable=ops.wait_writable,
            serial_queue_bytes=ops.serial_queue_bytes,
            monotonic=ops.monotonic,
            deadline=ops.monotonic() + _INVALIDATION_DEADLINE_SECONDS,
        )
    except SppDiagUartError as exc:
        raise PoweroffInvalidationFailed(writer) from exc
    raise PoweroffReturned(writer) from poweroff_error
