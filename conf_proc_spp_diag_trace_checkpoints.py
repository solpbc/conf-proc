# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Independent binding of supplied checkpoints to raw SPP trace prefixes."""

from dataclasses import dataclass
import hashlib
from typing import BinaryIO


CP_SPP_TRACE_CHECKPOINT_TYPE = "CP_SPP_TRACE_CHECKPOINT_TYPE"
CP_SPP_TRACE_CHECKPOINT_IO = "CP_SPP_TRACE_CHECKPOINT_IO"
CP_SPP_TRACE_CHECKPOINT_LENGTH = "CP_SPP_TRACE_CHECKPOINT_LENGTH"
CP_SPP_TRACE_CHECKPOINT_CAP = "CP_SPP_TRACE_CHECKPOINT_CAP"
CP_SPP_TRACE_CHECKPOINT_HEADER = "CP_SPP_TRACE_CHECKPOINT_HEADER"
CP_SPP_TRACE_CHECKPOINT_EXPECTATION = "CP_SPP_TRACE_CHECKPOINT_EXPECTATION"
CP_SPP_TRACE_CHECKPOINT_FRAME = "CP_SPP_TRACE_CHECKPOINT_FRAME"
CP_SPP_TRACE_CHECKPOINT_SEQUENCE = "CP_SPP_TRACE_CHECKPOINT_SEQUENCE"
CP_SPP_TRACE_CHECKPOINT_ANCHOR = "CP_SPP_TRACE_CHECKPOINT_ANCHOR"
CP_SPP_TRACE_CHECKPOINT_RECORD = "CP_SPP_TRACE_CHECKPOINT_RECORD"
CP_SPP_TRACE_CHECKPOINT_BINDING = "CP_SPP_TRACE_CHECKPOINT_BINDING"

_HEADER_DOMAIN = b"sol-spp-diag-trace-header/v1"
_FRAME_DOMAIN = b"sol-spp-diag-trace-frame/v1"
_HEADER_MAGIC = int.from_bytes(b"SPPTRC1\0", "big")
_RECORD_MAGIC = int.from_bytes(b"SPPIMA1\0", "big")
_SOURCE_COMMIT = int.from_bytes(
    bytes.fromhex("91a8e826012fbb1c7f5cb2a326c08b13e390f469"), "big"
)
_EVENT_NAMES = (
    int.from_bytes(b"sol-spp-diag-ready-v1", "big"),
    int.from_bytes(b"sol-spp-diag-release-v1", "big"),
    int.from_bytes(b"sol-spp-diag-terminal-v1", "big"),
)
_EVENT_NAME_LENGTHS = (21, 23, 24)
_ANCHOR_EVENTS = (3, 4, 10)
_ANCHOR_KINDS = ("ready", "release", "terminal")
_HEADER_LENGTH = 192
_HEADER_ENTRY_SIZE = 196
_RECORD_LENGTH = 256
_MIN_FRAME_LENGTH = 44
_MAX_FRAME_LENGTH = 1088
_MAX_STREAM_BYTES = 268435456
_MAX_FRAMES = 524288


class SppDiagTraceCheckpointError(ValueError):
    reason: str

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class SppDiagTraceCheckpointExpectations:
    source_commit: bytes
    challenge: bytes
    run_identity: bytes
    control_plan_address: bytes
    command_line_sha256: bytes


@dataclass(frozen=True)
class SppDiagTraceCheckpointInput:
    event_name: bytes
    record: bytes


@dataclass(frozen=True)
class SppDiagTraceCheckpoint:
    kind: str
    frame_count: int
    stream_byte_count: int
    chain: bytes
    raw_denied_exec_event_count: int
    raw_committed_exec_event_count: int


@dataclass(frozen=True)
class SppDiagTraceCheckpointBinding:
    status: str
    ready: SppDiagTraceCheckpoint
    release: SppDiagTraceCheckpoint
    terminal: SppDiagTraceCheckpoint
    frame_count: int
    stream_byte_count: int
    chain: bytes


def _fail(reason: str):
    raise SppDiagTraceCheckpointError(reason)


def _read_exact(reader, amount: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < amount:
        needed = amount - len(chunks)
        failure = None
        try:
            chunk = reader(needed)
        except Exception:
            failure = CP_SPP_TRACE_CHECKPOINT_IO
            chunk = b""
        if failure is not None:
            chunks.clear()
            _fail(failure)
        if type(chunk) is not bytes or len(chunk) > needed:
            chunk = b""
            chunks.clear()
            _fail(CP_SPP_TRACE_CHECKPOINT_TYPE)
        if not chunk:
            chunks.clear()
            _fail(CP_SPP_TRACE_CHECKPOINT_LENGTH)
        chunks.extend(chunk)
        chunk = b""
    result = bytes(chunks)
    chunks.clear()
    return result


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 8], "big")


def _bytes_int(data: bytes, start: int, end: int) -> int:
    return int.from_bytes(data[start:end], "big")


def _normalize_inputs(checkpoints, expectations):
    failure = None
    expected = None
    records = None
    if type(expectations) is not SppDiagTraceCheckpointExpectations:
        failure = CP_SPP_TRACE_CHECKPOINT_TYPE
    else:
        fields = (
            expectations.source_commit,
            expectations.challenge,
            expectations.run_identity,
            expectations.control_plan_address,
            expectations.command_line_sha256,
        )
        if any(type(value) is not bytes for value in fields):
            failure = CP_SPP_TRACE_CHECKPOINT_TYPE
        elif tuple(len(value) for value in fields) != (20, 32, 32, 32, 32):
            failure = CP_SPP_TRACE_CHECKPOINT_TYPE
        else:
            expected = tuple(int.from_bytes(value, "big") for value in fields)
    if failure is None:
        if type(checkpoints) is not tuple or len(checkpoints) != 3:
            failure = CP_SPP_TRACE_CHECKPOINT_TYPE
        else:
            parsed = []
            for item in checkpoints:
                if type(item) is not SppDiagTraceCheckpointInput:
                    failure = CP_SPP_TRACE_CHECKPOINT_TYPE
                    break
                if type(item.event_name) is not bytes or type(item.record) is not bytes:
                    failure = CP_SPP_TRACE_CHECKPOINT_TYPE
                    break
                if len(item.record) != _RECORD_LENGTH:
                    failure = CP_SPP_TRACE_CHECKPOINT_LENGTH
                    break
                raw = item.record
                parsed.append(
                    (
                        len(item.event_name),
                        int.from_bytes(item.event_name, "big"),
                        _bytes_int(raw, 0, 8),
                        _u16(raw, 8),
                        _u16(raw, 10),
                        _u32(raw, 12),
                        _u16(raw, 16),
                        _u16(raw, 18),
                        _u16(raw, 20),
                        _u16(raw, 22),
                        _bytes_int(raw, 24, 44),
                        _bytes_int(raw, 44, 76),
                        _bytes_int(raw, 76, 108),
                        _bytes_int(raw, 108, 140),
                        _bytes_int(raw, 140, 172),
                        _u64(raw, 172),
                        _u64(raw, 180),
                        _bytes_int(raw, 188, 220),
                        _u64(raw, 220),
                        _u64(raw, 228),
                        _u64(raw, 236),
                        _u32(raw, 244),
                        _u32(raw, 248),
                        _u32(raw, 252),
                    )
                )
                raw = b""
            if failure is None:
                records = tuple(parsed)
            parsed.clear()
    return failure, expected, records


def _parse_header(raw: bytes):
    return (
        _bytes_int(raw, 0, 8),
        _u16(raw, 8),
        _u16(raw, 10),
        _u16(raw, 12),
        _u16(raw, 14),
        _u32(raw, 16),
        _u64(raw, 20),
        _u32(raw, 28),
        _bytes_int(raw, 32, 52),
        _bytes_int(raw, 52, 84),
        _bytes_int(raw, 84, 116),
        _bytes_int(raw, 116, 148),
        _bytes_int(raw, 148, 180),
        _u64(raw, 180),
        _u32(raw, 188),
    )


def _header_reason(header) -> str | None:
    if header[:8] != (
        _HEADER_MAGIC,
        1,
        192,
        2,
        1,
        524288,
        268435456,
        1088,
    ):
        return CP_SPP_TRACE_CHECKPOINT_HEADER
    if header[8] != _SOURCE_COMMIT or header[13] != 0xFFFF or header[14] != 0:
        return CP_SPP_TRACE_CHECKPOINT_HEADER
    return None


def _record_reason(record, index: int) -> str | None:
    event_len, event_name = record[:2]
    fixed = record[2:10]
    if fixed != (
        _RECORD_MAGIC,
        1,
        index + 1,
        256,
        2,
        1,
        index + 1,
        0,
    ):
        return CP_SPP_TRACE_CHECKPOINT_RECORD
    if event_len != _EVENT_NAME_LENGTHS[index] or event_name != _EVENT_NAMES[index]:
        return CP_SPP_TRACE_CHECKPOINT_RECORD
    source_commit = record[10]
    frame_count, stream_bytes = record[15:17]
    hook_mask, denied, committed, loss, overflow, reserved = record[18:24]
    if source_commit != _SOURCE_COMMIT:
        return CP_SPP_TRACE_CHECKPOINT_RECORD
    if frame_count < 1 or frame_count > _MAX_FRAMES:
        return CP_SPP_TRACE_CHECKPOINT_RECORD
    if stream_bytes < 244 or stream_bytes > _MAX_STREAM_BYTES:
        return CP_SPP_TRACE_CHECKPOINT_RECORD
    if hook_mask != 0xFFFF or denied > frame_count or committed > frame_count:
        return CP_SPP_TRACE_CHECKPOINT_RECORD
    if loss != 0 or overflow != 0 or reserved != 0:
        return CP_SPP_TRACE_CHECKPOINT_RECORD
    return None


def _bind_spp_diag_trace_checkpoints(
    source: BinaryIO,
    stream_byte_count: int,
    checkpoints: tuple[SppDiagTraceCheckpointInput, ...],
    expectations: SppDiagTraceCheckpointExpectations,
) -> SppDiagTraceCheckpointBinding:
    """Bind three supplied records to exact prefixes of one complete stream."""

    if type(stream_byte_count) is not int:
        source = None
        checkpoints = None
        expectations = None
        _fail(CP_SPP_TRACE_CHECKPOINT_TYPE)
    failure, expected, records = _normalize_inputs(checkpoints, expectations)
    checkpoints = None
    expectations = None
    if failure is not None:
        source = None
        _fail(failure)

    failure = None
    try:
        reader = source.read
    except AttributeError:
        failure = CP_SPP_TRACE_CHECKPOINT_TYPE
        reader = None
    except Exception:
        failure = CP_SPP_TRACE_CHECKPOINT_IO
        reader = None
    source = None
    if failure is not None:
        _fail(failure)
    if not callable(reader):
        reader = None
        _fail(CP_SPP_TRACE_CHECKPOINT_TYPE)
    if stream_byte_count < _HEADER_ENTRY_SIZE:
        _fail(CP_SPP_TRACE_CHECKPOINT_LENGTH)
    if stream_byte_count > _MAX_STREAM_BYTES:
        _fail(CP_SPP_TRACE_CHECKPOINT_CAP)

    header_prefix = _read_exact(reader, 4)
    if header_prefix != _HEADER_LENGTH.to_bytes(4, "big"):
        header_prefix = b""
        _fail(CP_SPP_TRACE_CHECKPOINT_LENGTH)
    raw_header = _read_exact(reader, _HEADER_LENGTH)
    chain = hashlib.sha256(_HEADER_DOMAIN + header_prefix + raw_header).digest()
    header = _parse_header(raw_header)
    header_prefix = b""
    raw_header = b""
    failure = _header_reason(header)
    if failure is not None:
        _fail(failure)
    header_identities = header[8:13]
    if header_identities != expected:
        _fail(CP_SPP_TRACE_CHECKPOINT_EXPECTATION)

    remaining = stream_byte_count - _HEADER_ENTRY_SIZE
    stream_offset = _HEADER_ENTRY_SIZE
    frame_count = 0
    raw_denied = 0
    raw_committed = 0
    anchor_index = 0
    ready = None
    release = None
    terminal = None

    while remaining:
        if remaining < 4:
            _fail(CP_SPP_TRACE_CHECKPOINT_LENGTH)
        prefix = _read_exact(reader, 4)
        remaining -= 4
        frame_length = int.from_bytes(prefix, "big")
        if frame_length < _MIN_FRAME_LENGTH:
            prefix = b""
            _fail(CP_SPP_TRACE_CHECKPOINT_LENGTH)
        if frame_length > _MAX_FRAME_LENGTH:
            prefix = b""
            _fail(CP_SPP_TRACE_CHECKPOINT_CAP)
        if frame_length > remaining:
            prefix = b""
            _fail(CP_SPP_TRACE_CHECKPOINT_LENGTH)
        if frame_count >= _MAX_FRAMES:
            prefix = b""
            _fail(CP_SPP_TRACE_CHECKPOINT_CAP)
        frame = _read_exact(reader, frame_length)
        remaining -= frame_length
        stream_offset += 4 + frame_length
        chain = hashlib.sha256(_FRAME_DOMAIN + chain + prefix + frame).digest()
        event = _u16(frame, 0)
        flags = _u16(frame, 2)
        payload_length = _u32(frame, 4)
        sequence = _u64(frame, 8)
        task = _u64(frame, 16)
        parent = _u64(frame, 24)
        operation = _u64(frame, 32)
        phase = _u16(frame, 40)
        reserved = _u16(frame, 42)
        payload_first = _u64(frame, 44) if payload_length >= 8 else 0
        release_pid = _u32(frame, 44) if payload_length >= 4 else 0
        release_tgid = _u32(frame, 48) if payload_length >= 8 else 0
        release_count = _u64(frame, 52) if payload_length >= 16 else 0
        prefix = b""
        frame = b""
        frame_count += 1

        if payload_length != frame_length - 44:
            _fail(CP_SPP_TRACE_CHECKPOINT_LENGTH)
        if sequence != frame_count - 1:
            _fail(CP_SPP_TRACE_CHECKPOINT_SEQUENCE)
        if event == 2:
            raw_denied += 1
        elif event == 6:
            raw_committed += 1

        if event not in _ANCHOR_EVENTS:
            continue
        if event == 3:
            if (
                flags != 0
                or payload_length != 8
                or task != 0
                or parent != 0
                or operation != 0
                or phase != 0
                or reserved != 0
            ):
                _fail(CP_SPP_TRACE_CHECKPOINT_FRAME)
            if payload_first != raw_denied:
                _fail(CP_SPP_TRACE_CHECKPOINT_ANCHOR)
        elif event == 4:
            if (
                flags != 0
                or payload_length != 16
                or task == 0
                or parent != 0
                or operation != 0
                or phase != 0
                or reserved != 0
                or release_pid == 0
                or release_tgid == 0
            ):
                _fail(CP_SPP_TRACE_CHECKPOINT_FRAME)
            if release_count != raw_denied:
                _fail(CP_SPP_TRACE_CHECKPOINT_ANCHOR)
        else:
            if (
                flags != 0
                or payload_length != 0
                or task != 0
                or parent != 0
                or operation != 0
                or phase != 15
                or reserved != 0
            ):
                _fail(CP_SPP_TRACE_CHECKPOINT_FRAME)
            if remaining != 0:
                _fail(CP_SPP_TRACE_CHECKPOINT_LENGTH)

        if anchor_index >= 3 or event != _ANCHOR_EVENTS[anchor_index]:
            _fail(CP_SPP_TRACE_CHECKPOINT_ANCHOR)
        checkpoint = SppDiagTraceCheckpoint(
            kind=_ANCHOR_KINDS[anchor_index],
            frame_count=frame_count,
            stream_byte_count=stream_offset,
            chain=chain,
            raw_denied_exec_event_count=raw_denied,
            raw_committed_exec_event_count=raw_committed,
        )
        if anchor_index == 0:
            ready = checkpoint
        elif anchor_index == 1:
            release = checkpoint
        else:
            terminal = checkpoint
        anchor_index += 1

    if anchor_index != 3 or ready is None or release is None or terminal is None:
        _fail(CP_SPP_TRACE_CHECKPOINT_ANCHOR)

    failure = None
    try:
        trailing = reader(1)
    except Exception:
        failure = CP_SPP_TRACE_CHECKPOINT_IO
        trailing = b""
    if failure is not None:
        _fail(failure)
    if type(trailing) is not bytes or len(trailing) > 1:
        trailing = b""
        _fail(CP_SPP_TRACE_CHECKPOINT_TYPE)
    if trailing:
        trailing = b""
        _fail(CP_SPP_TRACE_CHECKPOINT_LENGTH)
    trailing = b""

    snapshots = (ready, release, terminal)
    for index, (record, checkpoint) in enumerate(zip(records, snapshots)):
        failure = _record_reason(record, index)
        if failure is not None:
            _fail(failure)
        record_identities = record[10:15]
        if record_identities != header_identities or record_identities != expected:
            _fail(CP_SPP_TRACE_CHECKPOINT_BINDING)
        if (
            record[15] != checkpoint.frame_count
            or record[16] != checkpoint.stream_byte_count
            or record[17] != int.from_bytes(checkpoint.chain, "big")
            or record[19] != checkpoint.raw_denied_exec_event_count
            or record[20] != checkpoint.raw_committed_exec_event_count
        ):
            _fail(CP_SPP_TRACE_CHECKPOINT_BINDING)

    return SppDiagTraceCheckpointBinding(
        status="checkpoints_bound",
        ready=ready,
        release=release,
        terminal=terminal,
        frame_count=frame_count,
        stream_byte_count=stream_byte_count,
        chain=chain,
    )


def bind_spp_diag_trace_checkpoints(
    source: BinaryIO,
    stream_byte_count: int,
    checkpoints: tuple[SppDiagTraceCheckpointInput, ...],
    expectations: SppDiagTraceCheckpointExpectations,
) -> SppDiagTraceCheckpointBinding:
    """Bind checkpoints while keeping sensitive worker frames private."""

    failure = None
    result = None
    try:
        result = _bind_spp_diag_trace_checkpoints(
            source, stream_byte_count, checkpoints, expectations
        )
    except SppDiagTraceCheckpointError as error:
        failure = error.reason
        error.__traceback__ = None
    if failure is None:
        return result
    source = None
    checkpoints = None
    expectations = None
    result = None
    _fail(failure)
