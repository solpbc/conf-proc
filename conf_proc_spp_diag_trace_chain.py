# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Independent constant-memory reduction of framed SPP diagnostic traces."""

from dataclasses import dataclass
import hashlib
from typing import BinaryIO


CP_SPP_TRACE_CHAIN_TYPE = "CP_SPP_TRACE_CHAIN_TYPE"
CP_SPP_TRACE_CHAIN_CAP = "CP_SPP_TRACE_CHAIN_CAP"
CP_SPP_TRACE_CHAIN_LENGTH = "CP_SPP_TRACE_CHAIN_LENGTH"
CP_SPP_TRACE_CHAIN_IO = "CP_SPP_TRACE_CHAIN_IO"

_HEADER_DOMAIN = b"sol-spp-diag-trace-header/v1"
_FRAME_DOMAIN = b"sol-spp-diag-trace-frame/v1"
_HEADER_LENGTH = 192
_HEADER_ENTRY_SIZE = 196
_MIN_FRAME_LENGTH = 44
_MAX_FRAME_LENGTH = 1088
_MAX_STREAM_BYTES = 268435456
_MAX_FRAMES = 524288


class SppDiagTraceChainError(ValueError):
    """A stable failure reason for trace-chain reduction."""

    reason: str

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class SppDiagTraceChainReduction:
    """The chain value and counts derived from one complete trace stream."""

    status: str
    chain: bytes
    frame_count: int
    stream_byte_count: int


def _fail(reason: str):
    raise SppDiagTraceChainError(reason)


def _read_exact(reader, amount: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < amount:
        needed = amount - len(chunks)
        failure = None
        try:
            chunk = reader(needed)
        except Exception:
            failure = CP_SPP_TRACE_CHAIN_IO
            chunk = b""
        if failure is not None:
            _fail(failure)
        if type(chunk) is not bytes or len(chunk) > needed:
            chunk = b""
            _fail(CP_SPP_TRACE_CHAIN_TYPE)
        if not chunk:
            _fail(CP_SPP_TRACE_CHAIN_LENGTH)
        chunks.extend(chunk)
    return bytes(chunks)


def reduce_spp_diag_trace_chain(
    source: BinaryIO, stream_byte_count: int
) -> SppDiagTraceChainReduction:
    """Reduce exactly ``stream_byte_count`` framed bytes from ``source``."""

    failure = None
    try:
        reader = source.read
    except AttributeError:
        failure = CP_SPP_TRACE_CHAIN_TYPE
        reader = None
    except Exception:
        failure = CP_SPP_TRACE_CHAIN_IO
        reader = None
    if failure is not None:
        _fail(failure)
    if not callable(reader):
        _fail(CP_SPP_TRACE_CHAIN_TYPE)
    if type(stream_byte_count) is not int:
        _fail(CP_SPP_TRACE_CHAIN_TYPE)
    if stream_byte_count < _HEADER_ENTRY_SIZE:
        _fail(CP_SPP_TRACE_CHAIN_LENGTH)
    if stream_byte_count > _MAX_STREAM_BYTES:
        _fail(CP_SPP_TRACE_CHAIN_CAP)

    header_prefix = _read_exact(reader, 4)
    if header_prefix != _HEADER_LENGTH.to_bytes(4, "big"):
        _fail(CP_SPP_TRACE_CHAIN_LENGTH)
    raw_header = _read_exact(reader, _HEADER_LENGTH)
    chain = hashlib.sha256(_HEADER_DOMAIN + header_prefix + raw_header).digest()
    header_prefix = b""
    raw_header = b""
    remaining = stream_byte_count - _HEADER_ENTRY_SIZE
    frame_count = 0

    while remaining:
        if remaining < 4:
            _fail(CP_SPP_TRACE_CHAIN_LENGTH)
        prefix = _read_exact(reader, 4)
        remaining -= 4
        frame_length = int.from_bytes(prefix, "big")
        if frame_length < _MIN_FRAME_LENGTH:
            _fail(CP_SPP_TRACE_CHAIN_LENGTH)
        if frame_length > _MAX_FRAME_LENGTH:
            _fail(CP_SPP_TRACE_CHAIN_CAP)
        if frame_length > remaining:
            _fail(CP_SPP_TRACE_CHAIN_LENGTH)
        if frame_count >= _MAX_FRAMES:
            _fail(CP_SPP_TRACE_CHAIN_CAP)
        frame = _read_exact(reader, frame_length)
        remaining -= frame_length
        chain = hashlib.sha256(_FRAME_DOMAIN + chain + prefix + frame).digest()
        prefix = b""
        frame = b""
        frame_count += 1

    return SppDiagTraceChainReduction(
        status="chain_reduced",
        chain=chain,
        frame_count=frame_count,
        stream_byte_count=stream_byte_count,
    )
