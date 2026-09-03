#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""SPPDBN1 UART evidence export and the 108-byte completion/failure terminal.

Producer side (build_export_stream/encode_terminal) writes the fixed-order member
allowlist and terminal record that the controller sends out over the fixed serial
fd (5). This module never imports conf_proc_spp_diagbundle or any other appraiser
module; the OUTER_MEMBER_NAMES tuple below is an intentional literal mirror of that
module's fixed member-name list plus "inner-receipt", not an import.
"""

from __future__ import annotations

import hashlib
import os
import stat
import struct
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


MAGIC: Final = b"SPPDBN1\x00"
TERMINAL_MAGIC: Final = b"SPPDBTM1"
TERMINAL_SIZE: Final = 108

MEMBER_NAMES: Final = (
    "ak-public.pem",
    "quote.msg",
    "quote.sig",
    "quote.pcrs",
    "hcla.bin",
    "snp-vcek.pem",
    "snp-cert-chain.pem",
    "firmware-event-log.bin",
    "ima-measurements.bin",
    "gpu-evidence.tlv",
    "inner-receipt",
)

UART_MAJOR: Final = 4
UART_MINOR: Final = 64

STATUS_COMPLETE: Final = 1
STATUS_FAILED: Final = 0


def encode_terminal(*, challenge: bytes, run_identity: bytes, status: int, reason_code_index: int, current_phase: int) -> bytes:
    if len(challenge) != 32 or len(run_identity) != 32:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TERMINAL)
    if status not in (STATUS_COMPLETE, STATUS_FAILED):
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TERMINAL)
    if not 0 <= reason_code_index <= 255 or not 0 <= current_phase <= 255:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TERMINAL)
    record = (
        TERMINAL_MAGIC
        + challenge
        + run_identity
        + bytes([status, reason_code_index, current_phase])
        + bytes(33)
    )
    assert len(record) == TERMINAL_SIZE
    return record


def build_export_stream(members: dict, terminal: bytes) -> bytes:
    """members: dict[name -> bytes], name set must equal MEMBER_NAMES exactly."""

    if frozenset(members) != frozenset(MEMBER_NAMES):
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_NAME)
    if len(terminal) != TERMINAL_SIZE:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TERMINAL)
    chunks = [MAGIC, struct.pack(">H", len(MEMBER_NAMES))]
    for name in MEMBER_NAMES:
        payload = members[name]
        name_bytes = name.encode("ascii")
        digest = hashlib.sha256(payload).digest()
        chunks.append(struct.pack(">H", len(name_bytes)))
        chunks.append(name_bytes)
        chunks.append(struct.pack(">Q", len(payload)))
        chunks.append(digest)
        chunks.append(payload)
    chunks.append(terminal)
    return b"".join(chunks)


@dataclass(frozen=True)
class ExportedMember:
    name: str
    size_bytes: int
    sha256: bytes
    payload: bytes


@dataclass(frozen=True)
class ExportedBundle:
    members: tuple[ExportedMember, ...]
    terminal: bytes


def parse_export_stream(data: bytes) -> ExportedBundle:
    """Independent oracle: does not call build_export_stream, re-derives the layout
    from the fixed wire prose only."""

    offset = 0

    def take(n: int) -> bytes:
        nonlocal offset
        if offset + n > len(data):
            raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TRUNCATED)
        chunk = data[offset : offset + n]
        offset += n
        return chunk

    if take(len(MAGIC)) != MAGIC:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_NAME)
    (count,) = struct.unpack(">H", take(2))
    if count != len(MEMBER_NAMES):
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_ORDER)

    members = []
    seen_names: set[str] = set()
    for expected_name in MEMBER_NAMES:
        (name_len,) = struct.unpack(">H", take(2))
        name = take(name_len).decode("ascii", errors="strict")
        if name != expected_name:
            raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_ORDER)
        if name in seen_names:
            raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_ORDER)
        seen_names.add(name)
        (size,) = struct.unpack(">Q", take(8))
        digest = take(32)
        payload = take(size)
        if hashlib.sha256(payload).digest() != digest:
            raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_HASH)
        if len(payload) != size:
            raise SppDiagExportError(CP_SPP_DIAG_EXPORT_MEMBER_SIZE)
        members.append(ExportedMember(name=name, size_bytes=size, sha256=digest, payload=payload))

    terminal = take(TERMINAL_SIZE)
    if terminal[:8] != TERMINAL_MAGIC:
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TERMINAL)

    if offset != len(data):
        raise SppDiagExportError(CP_SPP_DIAG_EXPORT_TRAILING_BYTES)

    return ExportedBundle(members=tuple(members), terminal=terminal)


def uart_node_is_valid(path: str) -> bool:
    """Confirms the serial path is a character device with the fixed major/minor
    (4/64, the traditional ttyS0 node) before any export write is attempted."""

    try:
        st = os.stat(path)
    except OSError:
        return False
    if not stat.S_ISCHR(st.st_mode):
        return False
    return os.major(st.st_rdev) == UART_MAJOR and os.minor(st.st_rdev) == UART_MINOR


@dataclass
class ExportOps:
    write_serial: Callable[[bytes], int]
    monotonic: Callable[[], float]
    request_poweroff_hardware: Callable[[], None]


_EXPORT_DEADLINE_SECONDS: Final = 15.0


def export_and_poweroff(ops: ExportOps, stream: bytes) -> bool:
    """Writes the full export stream within the fixed deadline, then always requests
    poweroff regardless of whether the write completed -- a short/stalled write still
    requests poweroff, it just never reaches the success oracle's complete terminal."""

    deadline = ops.monotonic() + _EXPORT_DEADLINE_SECONDS
    offset = 0
    while offset < len(stream):
        if ops.monotonic() > deadline:
            break
        written = ops.write_serial(stream[offset:])
        if written <= 0:
            break
        offset += written
    complete = offset == len(stream)
    ops.request_poweroff_hardware()
    return complete
