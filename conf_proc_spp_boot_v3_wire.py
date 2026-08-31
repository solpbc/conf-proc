#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Typed, closed binary codec for the SPP boot authority v3 wire protocol."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from math import ceil
from typing import Callable, Final

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_spp_boot_v3_tables import ServingWireMessageTypeV3
from conf_proc_spp_reasons_v3 import ApplianceErrorV3, CP_BOOT_V3_WIRE_PROTOCOL


HEADER_MAGIC_V3: Final = b"SPPIPC3\x00"
HEADER_SIZE_V3: Final = 72
HEADER_VERSION_V3: Final = 3
MAX_CHUNK_PAYLOAD_BYTES_V3: Final = 16384
FLAG_START_V3: Final = 1
FLAG_END_V3: Final = 2
FLAG_HAS_FD_V3: Final = 4

_HEADER_FORMAT: Final = ">8sHHHHIIIIQ32s"
_HEADER_FLAGS_MASK: Final = FLAG_START_V3 | FLAG_END_V3 | FLAG_HAS_FD_V3
_ZERO_TOKEN: Final = b"\0" * 32
_STREAM_BUFFER_BYTES_V3: Final = 2097152
_COLLECTOR_RESPONSE_MAX_TAIL_BYTES_V3: Final = 8388608
_COLLECTOR_RESPONSE_MAX_PAYLOAD_BYTES_V3: Final = 44 + _COLLECTOR_RESPONSE_MAX_TAIL_BYTES_V3
STANDALONE_READINESS_PROBE_BYTES_V3: Final = 32
STANDALONE_READINESS_RESULT_BYTES_V3: Final = 80
STANDALONE_READINESS_PROBE_MAGIC_V3: Final = b"SPPRDQ3\0"
STANDALONE_READINESS_RESULT_MAGIC_V3: Final = b"SPPRDR3\0"
_STANDALONE_READINESS_PROBE_FORMAT_V3: Final = ">8sHHIQQ"
_STANDALONE_READINESS_RESULT_FORMAT_V3: Final = ">8sHHIQQIIII32s"

assert struct.calcsize(_HEADER_FORMAT) == HEADER_SIZE_V3
assert struct.calcsize(_STANDALONE_READINESS_PROBE_FORMAT_V3) == STANDALONE_READINESS_PROBE_BYTES_V3
assert struct.calcsize(_STANDALONE_READINESS_RESULT_FORMAT_V3) == STANDALONE_READINESS_RESULT_BYTES_V3


class RouteV3(IntEnum):
    INFERENCE = 1
    ASR = 2


class CollectorGenerationV3(IntEnum):
    CERTIFICATE = 1
    EXPORTER = 2


class CollectorResultV3(IntEnum):
    SUCCESS = 1
    ACQUIRE_REJECTED = 2
    ABORTED = 3


class CollectorAbortReasonV3(IntEnum):
    NONZERO_EXIT = 1
    TIMEOUT = 2
    STDOUT_OVERFLOW = 3
    STDERR_OVERFLOW = 4
    MALFORMED = 5
    IDENTITY = 6
    CLIENT_CLOSE = 7
    CANCELLED = 8


class CollectorAckInvalidReasonV3(IntEnum):
    SHAPE = 1
    BINDING = 2
    ENCODING = 3
    IDENTITY = 4


class CollectorCancelReasonV3(IntEnum):
    TIMEOUT = 1
    CLIENT_CLOSE = 2
    SHUTDOWN = 3


class RequestRejectReasonV3(IntEnum):
    ROUTE_SLOT_SATURATED = 1
    DUPLICATE_REQUEST = 2


class WorkFinishOutcomeV3(IntEnum):
    ORDINARY = 1
    UPSTREAM_RETURN = 2
    UPSTREAM_THROW = 3
    UPSTREAM_TIMEOUT = 4
    CLIENT_CLOSE = 5


class RequestReleaseStateV3(IntEnum):
    WORK_FINISHED = 1
    AUDIO_413 = 2


class SessionReleaseReasonV3(IntEnum):
    NORMAL_CLIENT_CLOSE = 1
    PREFACE_FAILED = 2
    CERTIFICATE_FAILED = 3
    TLS_FAILED = 4
    EXPORTER_REQUEST_FAILED = 5
    EXPORTER_COLLECTOR_FAILED = 6
    PROOF_WRITE_FAILED = 7
    PARSER_REJECTED = 8
    SATURATION = 9
    CREDENTIAL_FAILED = 10
    DNS_FAILED = 11
    ENTITLEMENT_TLS_FAILED = 12
    AUTHORIZATION_DENIED = 13
    UPSTREAM_FAILED = 14
    HARD_AUDIO = 15


@dataclass(frozen=True)
class StandaloneReadinessProbeV3:
    role_id: int
    census_generation: int
    absolute_monotonic_deadline_ns: int


def encode_standalone_readiness_probe_v3(probe: StandaloneReadinessProbeV3) -> bytes:
    if type(probe) is not StandaloneReadinessProbeV3:
        _reject("standalone readiness probe is invalid")
    if type(probe.role_id) is not int or not 1 <= probe.role_id <= 3:
        _reject("standalone readiness role is invalid")
    generation = _uint(probe.census_generation, 64, "standalone readiness generation")
    if generation != 1:
        _reject("standalone readiness generation is invalid")
    if type(probe.absolute_monotonic_deadline_ns) is not int or not 0 < probe.absolute_monotonic_deadline_ns < 1 << 64:
        _reject("standalone readiness deadline is invalid")
    return struct.pack(
        _STANDALONE_READINESS_PROBE_FORMAT_V3,
        STANDALONE_READINESS_PROBE_MAGIC_V3,
        3,
        probe.role_id,
        0,
        generation,
        probe.absolute_monotonic_deadline_ns,
    )


def decode_standalone_readiness_probe_v3(data: bytes) -> StandaloneReadinessProbeV3:
    if type(data) is not bytes or len(data) != STANDALONE_READINESS_PROBE_BYTES_V3:
        _reject("standalone readiness probe length is invalid")
    magic, version, role_id, flags, generation, deadline = struct.unpack(
        _STANDALONE_READINESS_PROBE_FORMAT_V3, data
    )
    if magic != STANDALONE_READINESS_PROBE_MAGIC_V3 or version != 3 or flags != 0:
        _reject("standalone readiness probe framing is invalid")
    probe = StandaloneReadinessProbeV3(role_id, generation, deadline)
    if encode_standalone_readiness_probe_v3(probe) != data:
        _reject("standalone readiness probe is not canonical")
    return probe


@dataclass(frozen=True)
class StandaloneReadinessResultV3:
    role_id: int
    flags: int
    census_generation: int
    absolute_monotonic_deadline_ns: int
    supervised_child_pid: int
    role_uid: int
    role_gid: int
    executable_sha256: bytes


def encode_standalone_readiness_result_v3(result: StandaloneReadinessResultV3) -> bytes:
    if type(result) is not StandaloneReadinessResultV3:
        _reject("standalone readiness result is invalid")
    if type(result.role_id) is not int or not 1 <= result.role_id <= 3:
        _reject("standalone readiness role is invalid")
    flags = _uint(result.flags, 32, "standalone readiness flags")
    if flags != 1:
        _reject("standalone readiness flags are invalid")
    generation = _uint(result.census_generation, 64, "standalone readiness generation")
    if generation != 1:
        _reject("standalone readiness generation is invalid")
    if type(result.absolute_monotonic_deadline_ns) is not int or not 0 < result.absolute_monotonic_deadline_ns < 1 << 64:
        _reject("standalone readiness deadline is invalid")
    return struct.pack(
        _STANDALONE_READINESS_RESULT_FORMAT_V3,
        STANDALONE_READINESS_RESULT_MAGIC_V3,
        3,
        result.role_id,
        flags,
        generation,
        result.absolute_monotonic_deadline_ns,
        _uint(result.supervised_child_pid, 32, "supervised child PID"),
        _uint(result.role_uid, 32, "readiness role UID"),
        _uint(result.role_gid, 32, "readiness role GID"),
        0,
        _exact_bytes(result.executable_sha256, 32, "readiness executable digest"),
    )


def decode_standalone_readiness_result_v3(data: bytes) -> StandaloneReadinessResultV3:
    if type(data) is not bytes or len(data) != STANDALONE_READINESS_RESULT_BYTES_V3:
        _reject("standalone readiness result length is invalid")
    (
        magic, version, role_id, flags, generation, deadline, child_pid,
        role_uid, role_gid, reserved, executable_sha256,
    ) = struct.unpack(_STANDALONE_READINESS_RESULT_FORMAT_V3, data)
    if magic != STANDALONE_READINESS_RESULT_MAGIC_V3 or version != 3 or reserved != 0:
        _reject("standalone readiness result framing is invalid")
    result = StandaloneReadinessResultV3(
        role_id, flags, generation, deadline, child_pid, role_uid, role_gid,
        executable_sha256,
    )
    if encode_standalone_readiness_result_v3(result) != data:
        _reject("standalone readiness result is not canonical")
    return result


class PreRequestRejectedReasonV3(IntEnum):
    MALFORMED = 1
    HEAD_OVERSIZE = 2
    CHUNKED = 3
    FIRST_BYTE_IDLE = 4
    HEAD_DEADLINE = 5
    CLIENT_CLOSE = 6
    RETURN = 7
    THROW = 8


class GlobalFaultReasonV3(IntEnum):
    REDUCER_IDENTITY = 1
    PROCESS_IDENTITY = 2
    SOCKET_IDENTITY = 3
    READINESS = 4
    POLICY_READBACK = 5
    CONTROL_PROTOCOL = 6


COLLECTOR_ACK_INVALID_TO_ABORT_REASON_V3: Final[dict[CollectorAckInvalidReasonV3, CollectorAbortReasonV3]] = {
    CollectorAckInvalidReasonV3.SHAPE: CollectorAbortReasonV3.MALFORMED,
    CollectorAckInvalidReasonV3.BINDING: CollectorAbortReasonV3.IDENTITY,
    CollectorAckInvalidReasonV3.ENCODING: CollectorAbortReasonV3.MALFORMED,
    CollectorAckInvalidReasonV3.IDENTITY: CollectorAbortReasonV3.IDENTITY,
}


def _reject(message: str) -> None:
    raise ApplianceErrorV3(CP_BOOT_V3_WIRE_PROTOCOL, message) from None


def _uint(value: object, bits: int, label: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        _reject(f"{label} is invalid")
    return value


def _exact_bytes(value: object, length: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != length:
        _reject(f"{label} is invalid")
    return value


def _nonzero_bytes(value: object, length: int, label: str) -> bytes:
    result = _exact_bytes(value, length, label)
    if result == b"\0" * length:
        _reject(f"{label} must be nonzero")
    return result


def _enum(enum_type: type[IntEnum], value: object, label: str) -> IntEnum:
    _uint(value, 16, label)
    try:
        return enum_type(value)
    except ValueError:
        _reject(f"{label} is invalid")


def _canonical_json(value: object, *, maximum_length: int, required: bool) -> bytes:
    if type(value) is not bytes or len(value) > maximum_length or (required and not value):
        _reject("canonical JSON payload is invalid")
    try:
        parsed = canonical_loads(value)
    except Exception:
        _reject("canonical JSON payload is invalid")
    if canonical_dumps(parsed) != value:
        _reject("canonical JSON payload is invalid")
    return value


@dataclass(frozen=True)
class ServingWireHeaderV3:
    version: int
    message_type: ServingWireMessageTypeV3
    flags: int
    sequence: int
    chunk_index: int
    chunk_count: int
    chunk_length: int
    total_length: int
    session_token: bytes


def _validate_header(header: object) -> ServingWireHeaderV3:
    if type(header) is not ServingWireHeaderV3:
        _reject("wire header is invalid")
    if header.version != HEADER_VERSION_V3:
        _reject("wire version is invalid")
    if type(header.message_type) is not ServingWireMessageTypeV3:
        _reject("wire message type is invalid")
    _uint(header.flags, 16, "wire flags")
    if header.flags & ~_HEADER_FLAGS_MASK:
        _reject("wire flags are invalid")
    _uint(header.sequence, 32, "wire sequence")
    _uint(header.chunk_index, 32, "wire chunk index")
    _uint(header.chunk_count, 32, "wire chunk count")
    _uint(header.chunk_length, 32, "wire chunk length")
    _uint(header.total_length, 64, "wire total length")
    _exact_bytes(header.session_token, 32, "wire session token")
    return header


def encode_serving_wire_header_v3(header: ServingWireHeaderV3) -> bytes:
    """Encode one fully validated fixed-size v3 wire header."""

    header = _validate_header(header)
    return struct.pack(
        _HEADER_FORMAT,
        HEADER_MAGIC_V3,
        header.version,
        header.message_type.value,
        header.flags,
        0,
        header.sequence,
        header.chunk_index,
        header.chunk_count,
        header.chunk_length,
        header.total_length,
        header.session_token,
    )


def decode_serving_wire_header_v3(data: bytes) -> ServingWireHeaderV3:
    """Decode only the fixed header; token scope is checked at frame level."""

    if type(data) is not bytes or len(data) != HEADER_SIZE_V3:
        _reject("wire header length is invalid")
    (
        magic,
        version,
        message_type,
        flags,
        reserved,
        sequence,
        chunk_index,
        chunk_count,
        chunk_length,
        total_length,
        session_token,
    ) = struct.unpack(_HEADER_FORMAT, data)
    if magic != HEADER_MAGIC_V3:
        _reject("wire header magic is invalid")
    if version != HEADER_VERSION_V3:
        _reject("wire header version is invalid")
    if reserved != 0:
        _reject("wire header reserved field is invalid")
    if flags & ~_HEADER_FLAGS_MASK:
        _reject("wire header flags are invalid")
    try:
        parsed_type = ServingWireMessageTypeV3(message_type)
    except ValueError:
        _reject("wire header message type is invalid")
    return _validate_header(ServingWireHeaderV3(
        version, parsed_type, flags, sequence, chunk_index, chunk_count,
        chunk_length, total_length, session_token,
    ))


@dataclass(frozen=True)
class SessionFdPayloadV3:
    session_epoch: int
    af_family: int
    local_ipv4: bytes
    local_port: int
    peer_ipv4: bytes
    peer_port: int
    so_cookie: int


def encode_session_fd_payload_v3(payload: SessionFdPayloadV3) -> bytes:
    if type(payload) is not SessionFdPayloadV3 or payload.af_family != 2:
        _reject("session FD payload is invalid")
    return struct.pack(
        ">QH4sH4sHQ", _uint(payload.session_epoch, 64, "session epoch"), payload.af_family,
        _exact_bytes(payload.local_ipv4, 4, "local IPv4"), _uint(payload.local_port, 16, "local port"),
        _exact_bytes(payload.peer_ipv4, 4, "peer IPv4"), _uint(payload.peer_port, 16, "peer port"),
        _uint(payload.so_cookie, 64, "socket cookie"),
    )


def decode_session_fd_payload_v3(data: bytes) -> SessionFdPayloadV3:
    if type(data) is not bytes or len(data) != 30:
        _reject("session FD payload length is invalid")
    return _decode_with(encode_session_fd_payload_v3, SessionFdPayloadV3(*struct.unpack(">QH4sH4sHQ", data)))


@dataclass(frozen=True)
class CollectorRequestPayloadV3:
    generation: CollectorGenerationV3
    json_bytes: bytes


def encode_collector_request_payload_v3(payload: CollectorRequestPayloadV3) -> bytes:
    if type(payload) is not CollectorRequestPayloadV3 or type(payload.generation) is not CollectorGenerationV3:
        _reject("collector request payload is invalid")
    return struct.pack(">B3s", payload.generation.value, b"\0" * 3) + _canonical_json(
        payload.json_bytes, maximum_length=4096, required=True,
    )


def decode_collector_request_payload_v3(data: bytes) -> CollectorRequestPayloadV3:
    if type(data) is not bytes or not 5 <= len(data) <= 4100:
        _reject("collector request payload length is invalid")
    generation, reserved = struct.unpack(">B3s", data[:4])
    if reserved != b"\0" * 3:
        _reject("collector request reserved field is invalid")
    return _decode_with(
        encode_collector_request_payload_v3,
        CollectorRequestPayloadV3(_enum(CollectorGenerationV3, generation, "collector generation"), data[4:]),
    )


@dataclass(frozen=True)
class CollectorResponsePayloadV3:
    generation: CollectorGenerationV3
    result: CollectorResultV3
    reason: int
    child_pid: int
    wait_status: int
    stdout_sha256: bytes
    json_bytes: bytes


def encode_collector_response_payload_v3(payload: CollectorResponsePayloadV3) -> bytes:
    if (
        type(payload) is not CollectorResponsePayloadV3
        or type(payload.generation) is not CollectorGenerationV3
        or type(payload.result) is not CollectorResultV3
    ):
        _reject("collector response payload is invalid")
    reason = _uint(payload.reason, 16, "collector response reason")
    child_pid = _uint(payload.child_pid, 32, "collector child PID")
    wait_status = _uint(payload.wait_status, 32, "collector wait status")
    digest = _exact_bytes(payload.stdout_sha256, 32, "collector stdout digest")
    tail = payload.json_bytes
    if payload.result is CollectorResultV3.SUCCESS:
        if reason != 0 or child_pid == 0 or wait_status != 0 or digest == _ZERO_TOKEN:
            _reject("successful collector response is invalid")
        tail = _canonical_json(tail, maximum_length=_COLLECTOR_RESPONSE_MAX_TAIL_BYTES_V3, required=True)
    elif payload.result is CollectorResultV3.ACQUIRE_REJECTED:
        if reason != 1 or child_pid != 0 or wait_status != 0 or digest != _ZERO_TOKEN or tail != b"":
            _reject("rejected collector response is invalid")
    else:
        _enum(CollectorAbortReasonV3, reason, "collector abort reason")
        if tail != b"":
            _reject("aborted collector response is invalid")
    return struct.pack(
        ">BBHII32s", payload.generation.value, payload.result.value, reason, child_pid,
        wait_status, digest,
    ) + tail


def decode_collector_response_payload_v3(data: bytes) -> CollectorResponsePayloadV3:
    if type(data) is not bytes or not 44 <= len(data) <= _COLLECTOR_RESPONSE_MAX_PAYLOAD_BYTES_V3:
        _reject("collector response payload length is invalid")
    generation, result, reason, child_pid, wait_status, digest = struct.unpack(">BBHII32s", data[:44])
    return _decode_with(
        encode_collector_response_payload_v3,
        CollectorResponsePayloadV3(
            _enum(CollectorGenerationV3, generation, "collector generation"),
            _enum(CollectorResultV3, result, "collector result"), reason, child_pid,
            wait_status, digest, data[44:],
        ),
    )


@dataclass(frozen=True)
class CollectorAckValidPayloadV3:
    generation: CollectorGenerationV3
    child_pid: int
    wait_status: int
    stdout_sha256: bytes


def encode_collector_ack_valid_payload_v3(payload: CollectorAckValidPayloadV3) -> bytes:
    if type(payload) is not CollectorAckValidPayloadV3 or type(payload.generation) is not CollectorGenerationV3:
        _reject("collector valid acknowledgement is invalid")
    return struct.pack(
        ">B3sII32s", payload.generation.value, b"\0" * 3,
        _uint(payload.child_pid, 32, "collector child PID"),
        _uint(payload.wait_status, 32, "collector wait status"),
        _exact_bytes(payload.stdout_sha256, 32, "collector stdout digest"),
    )


def decode_collector_ack_valid_payload_v3(data: bytes) -> CollectorAckValidPayloadV3:
    if type(data) is not bytes or len(data) != 44:
        _reject("collector valid acknowledgement length is invalid")
    generation, reserved, child_pid, wait_status, digest = struct.unpack(">B3sII32s", data)
    if reserved != b"\0" * 3:
        _reject("collector valid acknowledgement reserved field is invalid")
    return _decode_with(
        encode_collector_ack_valid_payload_v3,
        CollectorAckValidPayloadV3(_enum(CollectorGenerationV3, generation, "collector generation"), child_pid, wait_status, digest),
    )


@dataclass(frozen=True)
class CollectorAckInvalidPayloadV3:
    generation: CollectorGenerationV3
    child_pid: int
    wait_status: int
    stdout_sha256: bytes
    reason: CollectorAckInvalidReasonV3


def encode_collector_ack_invalid_payload_v3(payload: CollectorAckInvalidPayloadV3) -> bytes:
    if (
        type(payload) is not CollectorAckInvalidPayloadV3
        or type(payload.generation) is not CollectorGenerationV3
        or type(payload.reason) is not CollectorAckInvalidReasonV3
    ):
        _reject("collector invalid acknowledgement is invalid")
    return struct.pack(
        ">B3sII32sH", payload.generation.value, b"\0" * 3,
        _uint(payload.child_pid, 32, "collector child PID"),
        _uint(payload.wait_status, 32, "collector wait status"),
        _exact_bytes(payload.stdout_sha256, 32, "collector stdout digest"), payload.reason.value,
    )


def decode_collector_ack_invalid_payload_v3(data: bytes) -> CollectorAckInvalidPayloadV3:
    if type(data) is not bytes or len(data) != 46:
        _reject("collector invalid acknowledgement length is invalid")
    generation, reserved, child_pid, wait_status, digest, reason = struct.unpack(">B3sII32sH", data)
    if reserved != b"\0" * 3:
        _reject("collector invalid acknowledgement reserved field is invalid")
    return _decode_with(
        encode_collector_ack_invalid_payload_v3,
        CollectorAckInvalidPayloadV3(
            _enum(CollectorGenerationV3, generation, "collector generation"), child_pid,
            wait_status, digest, _enum(CollectorAckInvalidReasonV3, reason, "collector invalid reason"),
        ),
    )


@dataclass(frozen=True)
class CollectorCancelPayloadV3:
    generation: CollectorGenerationV3
    reason: CollectorCancelReasonV3


def encode_collector_cancel_payload_v3(payload: CollectorCancelPayloadV3) -> bytes:
    if (
        type(payload) is not CollectorCancelPayloadV3
        or type(payload.generation) is not CollectorGenerationV3
        or type(payload.reason) is not CollectorCancelReasonV3
    ):
        _reject("collector cancellation is invalid")
    return struct.pack(">BB2s", payload.generation.value, payload.reason.value, b"\0" * 2)


def decode_collector_cancel_payload_v3(data: bytes) -> CollectorCancelPayloadV3:
    if type(data) is not bytes or len(data) != 4:
        _reject("collector cancellation length is invalid")
    generation, reason, reserved = struct.unpack(">BB2s", data)
    if reserved != b"\0" * 2:
        _reject("collector cancellation reserved field is invalid")
    return _decode_with(
        encode_collector_cancel_payload_v3,
        CollectorCancelPayloadV3(
            _enum(CollectorGenerationV3, generation, "collector generation"),
            _enum(CollectorCancelReasonV3, reason, "collector cancel reason"),
        ),
    )


@dataclass(frozen=True)
class RequestAcquirePayloadV3:
    request_cycle: int
    route: RouteV3
    gateway_reducer_instance_token: bytes


def encode_request_acquire_payload_v3(payload: RequestAcquirePayloadV3) -> bytes:
    if type(payload) is not RequestAcquirePayloadV3 or type(payload.route) is not RouteV3:
        _reject("request acquire payload is invalid")
    return struct.pack(
        ">QB7s32s", _uint(payload.request_cycle, 64, "request cycle"), payload.route.value,
        b"\0" * 7, _exact_bytes(payload.gateway_reducer_instance_token, 32, "gateway reducer token"),
    )


def decode_request_acquire_payload_v3(data: bytes) -> RequestAcquirePayloadV3:
    if type(data) is not bytes or len(data) != 48:
        _reject("request acquire payload length is invalid")
    cycle, route, reserved, token = struct.unpack(">QB7s32s", data)
    if reserved != b"\0" * 7:
        _reject("request acquire reserved field is invalid")
    return _decode_with(
        encode_request_acquire_payload_v3,
        RequestAcquirePayloadV3(cycle, _enum(RouteV3, route, "route"), token),
    )


@dataclass(frozen=True)
class RequestAdmitPayloadV3:
    cycle: int
    route: RouteV3
    buffer_capacity: int
    request_permit_token: bytes
    route_work_permit_token: bytes
    buffer_permit_token: bytes


def encode_request_admit_payload_v3(payload: RequestAdmitPayloadV3) -> bytes:
    if type(payload) is not RequestAdmitPayloadV3 or type(payload.route) is not RouteV3:
        _reject("request admit payload is invalid")
    if payload.buffer_capacity != _STREAM_BUFFER_BYTES_V3:
        _reject("request admit buffer capacity is invalid")
    return struct.pack(
        ">QB3sI32s32s32s", _uint(payload.cycle, 64, "request cycle"), payload.route.value,
        b"\0" * 3, payload.buffer_capacity,
        _nonzero_bytes(payload.request_permit_token, 32, "request permit token"),
        _nonzero_bytes(payload.route_work_permit_token, 32, "route work permit token"),
        _nonzero_bytes(payload.buffer_permit_token, 32, "buffer permit token"),
    )


def decode_request_admit_payload_v3(data: bytes) -> RequestAdmitPayloadV3:
    if type(data) is not bytes or len(data) != 112:
        _reject("request admit payload length is invalid")
    cycle, route, reserved, capacity, request, route_work, buffer = struct.unpack(">QB3sI32s32s32s", data)
    if reserved != b"\0" * 3:
        _reject("request admit reserved field is invalid")
    return _decode_with(
        encode_request_admit_payload_v3,
        RequestAdmitPayloadV3(cycle, _enum(RouteV3, route, "route"), capacity, request, route_work, buffer),
    )


@dataclass(frozen=True)
class RequestRejectPayloadV3:
    cycle: int
    route: RouteV3
    reason: RequestRejectReasonV3


def encode_request_reject_payload_v3(payload: RequestRejectPayloadV3) -> bytes:
    if (
        type(payload) is not RequestRejectPayloadV3
        or type(payload.route) is not RouteV3
        or type(payload.reason) is not RequestRejectReasonV3
    ):
        _reject("request reject payload is invalid")
    return struct.pack(">QBB6s", _uint(payload.cycle, 64, "request cycle"), payload.route.value, payload.reason.value, b"\0" * 6)


def decode_request_reject_payload_v3(data: bytes) -> RequestRejectPayloadV3:
    if type(data) is not bytes or len(data) != 16:
        _reject("request reject payload length is invalid")
    cycle, route, reason, reserved = struct.unpack(">QBB6s", data)
    if reserved != b"\0" * 6:
        _reject("request reject reserved field is invalid")
    return _decode_with(
        encode_request_reject_payload_v3,
        RequestRejectPayloadV3(cycle, _enum(RouteV3, route, "route"), _enum(RequestRejectReasonV3, reason, "request reject reason")),
    )


@dataclass(frozen=True)
class WorkBeginPayloadV3:
    cycle: int
    route: RouteV3
    request_permit_token: bytes
    route_work_permit_token: bytes


def encode_work_begin_payload_v3(payload: WorkBeginPayloadV3) -> bytes:
    if type(payload) is not WorkBeginPayloadV3 or type(payload.route) is not RouteV3:
        _reject("work begin payload is invalid")
    return struct.pack(
        ">QB7s32s32s", _uint(payload.cycle, 64, "request cycle"), payload.route.value, b"\0" * 7,
        _nonzero_bytes(payload.request_permit_token, 32, "request permit token"),
        _nonzero_bytes(payload.route_work_permit_token, 32, "route work permit token"),
    )


def decode_work_begin_payload_v3(data: bytes) -> WorkBeginPayloadV3:
    if type(data) is not bytes or len(data) != 80:
        _reject("work begin payload length is invalid")
    cycle, route, reserved, request, route_work = struct.unpack(">QB7s32s32s", data)
    if reserved != b"\0" * 7:
        _reject("work begin reserved field is invalid")
    return _decode_with(
        encode_work_begin_payload_v3,
        WorkBeginPayloadV3(cycle, _enum(RouteV3, route, "route"), request, route_work),
    )


@dataclass(frozen=True)
class WorkFinishPayloadV3:
    cycle: int
    route: RouteV3
    outcome: WorkFinishOutcomeV3
    request_permit_token: bytes
    route_work_permit_token: bytes


def encode_work_finish_payload_v3(payload: WorkFinishPayloadV3) -> bytes:
    if (
        type(payload) is not WorkFinishPayloadV3
        or type(payload.route) is not RouteV3
        or type(payload.outcome) is not WorkFinishOutcomeV3
    ):
        _reject("work finish payload is invalid")
    return struct.pack(
        ">QBB6s32s32s", _uint(payload.cycle, 64, "request cycle"), payload.route.value,
        payload.outcome.value, b"\0" * 6,
        _nonzero_bytes(payload.request_permit_token, 32, "request permit token"),
        _nonzero_bytes(payload.route_work_permit_token, 32, "route work permit token"),
    )


def decode_work_finish_payload_v3(data: bytes) -> WorkFinishPayloadV3:
    if type(data) is not bytes or len(data) != 80:
        _reject("work finish payload length is invalid")
    cycle, route, outcome, reserved, request, route_work = struct.unpack(">QBB6s32s32s", data)
    if reserved != b"\0" * 6:
        _reject("work finish reserved field is invalid")
    return _decode_with(
        encode_work_finish_payload_v3,
        WorkFinishPayloadV3(
            cycle, _enum(RouteV3, route, "route"), _enum(WorkFinishOutcomeV3, outcome, "work finish outcome"),
            request, route_work,
        ),
    )


@dataclass(frozen=True)
class RequestReleasePayloadV3:
    cycle: int
    route: RouteV3
    state: RequestReleaseStateV3
    request_permit_token: bytes
    route_work_permit_token: bytes
    buffer_permit_token: bytes


def encode_request_release_payload_v3(payload: RequestReleasePayloadV3) -> bytes:
    if (
        type(payload) is not RequestReleasePayloadV3
        or type(payload.route) is not RouteV3
        or type(payload.state) is not RequestReleaseStateV3
    ):
        _reject("request release payload is invalid")
    return struct.pack(
        ">QBB6s32s32s32s", _uint(payload.cycle, 64, "request cycle"), payload.route.value,
        payload.state.value, b"\0" * 6,
        _nonzero_bytes(payload.request_permit_token, 32, "request permit token"),
        _nonzero_bytes(payload.route_work_permit_token, 32, "route work permit token"),
        _nonzero_bytes(payload.buffer_permit_token, 32, "buffer permit token"),
    )


def decode_request_release_payload_v3(data: bytes) -> RequestReleasePayloadV3:
    if type(data) is not bytes or len(data) != 112:
        _reject("request release payload length is invalid")
    cycle, route, state, reserved, request, route_work, buffer = struct.unpack(">QBB6s32s32s32s", data)
    if reserved != b"\0" * 6:
        _reject("request release reserved field is invalid")
    return _decode_with(
        encode_request_release_payload_v3,
        RequestReleasePayloadV3(
            cycle, _enum(RouteV3, route, "route"), _enum(RequestReleaseStateV3, state, "request release state"),
            request, route_work, buffer,
        ),
    )


@dataclass(frozen=True)
class RequestReleasedPayloadV3:
    cycle: int
    route: RouteV3
    request_permit_token: bytes


def encode_request_released_payload_v3(payload: RequestReleasedPayloadV3) -> bytes:
    if type(payload) is not RequestReleasedPayloadV3 or type(payload.route) is not RouteV3:
        _reject("request released payload is invalid")
    return struct.pack(
        ">QB7s32s", _uint(payload.cycle, 64, "request cycle"), payload.route.value,
        b"\0" * 7, _exact_bytes(payload.request_permit_token, 32, "request permit token"),
    )


def decode_request_released_payload_v3(data: bytes) -> RequestReleasedPayloadV3:
    if type(data) is not bytes or len(data) != 48:
        _reject("request released payload length is invalid")
    cycle, route, reserved, request = struct.unpack(">QB7s32s", data)
    if reserved != b"\0" * 7:
        _reject("request released reserved field is invalid")
    return _decode_with(
        encode_request_released_payload_v3,
        RequestReleasedPayloadV3(cycle, _enum(RouteV3, route, "route"), request),
    )


@dataclass(frozen=True)
class SessionReleasePayloadV3:
    cycle: int
    held_permit_bitmap: int
    closed_reason: SessionReleaseReasonV3
    request_permit_slot: bytes
    route_work_permit_slot: bytes
    buffer_permit_slot: bytes


def encode_session_release_payload_v3(payload: SessionReleasePayloadV3) -> bytes:
    if type(payload) is not SessionReleasePayloadV3 or type(payload.closed_reason) is not SessionReleaseReasonV3:
        _reject("session release payload is invalid")
    bitmap = _uint(payload.held_permit_bitmap, 16, "held permit bitmap")
    if bitmap & ~0b111:
        _reject("held permit bitmap is invalid")
    slots = (
        _exact_bytes(payload.request_permit_slot, 32, "request permit slot"),
        _exact_bytes(payload.route_work_permit_slot, 32, "route work permit slot"),
        _exact_bytes(payload.buffer_permit_slot, 32, "buffer permit slot"),
    )
    if any((bool(bitmap & (1 << index))) != (slot != _ZERO_TOKEN) for index, slot in enumerate(slots)):
        _reject("held permit slots disagree with bitmap")
    return struct.pack(
        ">QHH4s32s32s32s", _uint(payload.cycle, 64, "request cycle"), bitmap,
        payload.closed_reason.value, b"\0" * 4, *slots,
    )


def decode_session_release_payload_v3(data: bytes) -> SessionReleasePayloadV3:
    if type(data) is not bytes or len(data) != 112:
        _reject("session release payload length is invalid")
    cycle, bitmap, reason, reserved, request, route_work, buffer = struct.unpack(">QHH4s32s32s32s", data)
    if reserved != b"\0" * 4:
        _reject("session release reserved field is invalid")
    return _decode_with(
        encode_session_release_payload_v3,
        SessionReleasePayloadV3(
            cycle, bitmap, _enum(SessionReleaseReasonV3, reason, "session release reason"),
            request, route_work, buffer,
        ),
    )


@dataclass(frozen=True)
class SessionReleasedPayloadV3:
    cycle: int
    prior_held_bitmap: int
    prior_reason: SessionReleaseReasonV3


def encode_session_released_payload_v3(payload: SessionReleasedPayloadV3) -> bytes:
    if type(payload) is not SessionReleasedPayloadV3 or type(payload.prior_reason) is not SessionReleaseReasonV3:
        _reject("session released payload is invalid")
    bitmap = _uint(payload.prior_held_bitmap, 16, "prior held bitmap")
    if bitmap & ~0b111:
        _reject("prior held bitmap is invalid")
    return struct.pack(
        ">QHH4s", _uint(payload.cycle, 64, "request cycle"), bitmap, payload.prior_reason.value, b"\0" * 4,
    )


def decode_session_released_payload_v3(data: bytes) -> SessionReleasedPayloadV3:
    if type(data) is not bytes or len(data) != 16:
        _reject("session released payload length is invalid")
    cycle, bitmap, reason, reserved = struct.unpack(">QHH4s", data)
    if reserved != b"\0" * 4:
        _reject("session released reserved field is invalid")
    return _decode_with(
        encode_session_released_payload_v3,
        SessionReleasedPayloadV3(cycle, bitmap, _enum(SessionReleaseReasonV3, reason, "session release reason")),
    )


@dataclass(frozen=True)
class PreRequestRejectedPayloadV3:
    next_cycle: int
    reason: PreRequestRejectedReasonV3


def encode_pre_request_rejected_payload_v3(payload: PreRequestRejectedPayloadV3) -> bytes:
    if type(payload) is not PreRequestRejectedPayloadV3 or type(payload.reason) is not PreRequestRejectedReasonV3:
        _reject("pre-request rejection payload is invalid")
    return struct.pack(">QH6s", _uint(payload.next_cycle, 64, "next cycle"), payload.reason.value, b"\0" * 6)


def decode_pre_request_rejected_payload_v3(data: bytes) -> PreRequestRejectedPayloadV3:
    if type(data) is not bytes or len(data) != 16:
        _reject("pre-request rejection payload length is invalid")
    cycle, reason, reserved = struct.unpack(">QH6s", data)
    if reserved != b"\0" * 6:
        _reject("pre-request rejection reserved field is invalid")
    return _decode_with(
        encode_pre_request_rejected_payload_v3,
        PreRequestRejectedPayloadV3(cycle, _enum(PreRequestRejectedReasonV3, reason, "pre-request rejection reason")),
    )


@dataclass(frozen=True)
class GlobalFaultPayloadV3:
    cycle: int
    reason: GlobalFaultReasonV3
    gateway_reducer_instance_token: bytes


def encode_global_fault_payload_v3(payload: GlobalFaultPayloadV3) -> bytes:
    if type(payload) is not GlobalFaultPayloadV3 or type(payload.reason) is not GlobalFaultReasonV3:
        _reject("global fault payload is invalid")
    return struct.pack(
        ">QH6s32s", _uint(payload.cycle, 64, "global fault cycle"), payload.reason.value,
        b"\0" * 6, _exact_bytes(payload.gateway_reducer_instance_token, 32, "gateway reducer token"),
    )


def decode_global_fault_payload_v3(data: bytes) -> GlobalFaultPayloadV3:
    if type(data) is not bytes or len(data) != 48:
        _reject("global fault payload length is invalid")
    cycle, reason, reserved, token = struct.unpack(">QH6s32s", data)
    if reserved != b"\0" * 6:
        _reject("global fault reserved field is invalid")
    return _decode_with(
        encode_global_fault_payload_v3,
        GlobalFaultPayloadV3(cycle, _enum(GlobalFaultReasonV3, reason, "global fault reason"), token),
    )


@dataclass(frozen=True)
class ChunkAckPayloadV3:
    acknowledged_message_sequence: int
    chunk_index: int
    cumulative_payload_bytes: int
    rolling_sha256: bytes


def encode_chunk_ack_payload_v3(payload: ChunkAckPayloadV3) -> bytes:
    if type(payload) is not ChunkAckPayloadV3:
        _reject("chunk acknowledgement payload is invalid")
    return struct.pack(
        ">IIQ32s", _uint(payload.acknowledged_message_sequence, 32, "acknowledged sequence"),
        _uint(payload.chunk_index, 32, "acknowledged chunk index"),
        _uint(payload.cumulative_payload_bytes, 64, "cumulative payload bytes"),
        _exact_bytes(payload.rolling_sha256, 32, "rolling digest"),
    )


def decode_chunk_ack_payload_v3(data: bytes) -> ChunkAckPayloadV3:
    if type(data) is not bytes or len(data) != 48:
        _reject("chunk acknowledgement payload length is invalid")
    return _decode_with(encode_chunk_ack_payload_v3, ChunkAckPayloadV3(*struct.unpack(">IIQ32s", data)))


@dataclass(frozen=True)
class SessionFdAckPayloadV3:
    session_epoch: int
    so_cookie: int
    gateway_reducer_instance_token: bytes


def encode_session_fd_ack_payload_v3(payload: SessionFdAckPayloadV3) -> bytes:
    if type(payload) is not SessionFdAckPayloadV3:
        _reject("session FD acknowledgement payload is invalid")
    return struct.pack(
        ">QQ32s", _uint(payload.session_epoch, 64, "session epoch"),
        _uint(payload.so_cookie, 64, "socket cookie"),
        _exact_bytes(payload.gateway_reducer_instance_token, 32, "gateway reducer token"),
    )


def decode_session_fd_ack_payload_v3(data: bytes) -> SessionFdAckPayloadV3:
    if type(data) is not bytes or len(data) != 48:
        _reject("session FD acknowledgement length is invalid")
    return _decode_with(encode_session_fd_ack_payload_v3, SessionFdAckPayloadV3(*struct.unpack(">QQ32s", data)))


@dataclass(frozen=True)
class GatewayReadinessProbePayloadV3:
    census_generation: int
    absolute_monotonic_deadline_ns: int


def encode_gateway_readiness_probe_payload_v3(payload: GatewayReadinessProbePayloadV3) -> bytes:
    if type(payload) is not GatewayReadinessProbePayloadV3:
        _reject("gateway readiness probe payload is invalid")
    generation = _uint(payload.census_generation, 64, "census generation")
    if generation != 1:
        _reject("gateway readiness generation is invalid")
    if type(payload.absolute_monotonic_deadline_ns) is not int or not 0 < payload.absolute_monotonic_deadline_ns < 1 << 64:
        _reject("gateway readiness deadline is invalid")
    return struct.pack(
        ">QQ", generation,
        _uint(payload.absolute_monotonic_deadline_ns, 64, "readiness deadline"),
    )


def decode_gateway_readiness_probe_payload_v3(data: bytes) -> GatewayReadinessProbePayloadV3:
    if type(data) is not bytes or len(data) != 16:
        _reject("gateway readiness probe payload length is invalid")
    return _decode_with(encode_gateway_readiness_probe_payload_v3, GatewayReadinessProbePayloadV3(*struct.unpack(">QQ", data)))


@dataclass(frozen=True)
class GatewayReadinessResultPayloadV3:
    census_generation: int
    gateway_pid: int
    session_worker_count: int
    flags: int
    executable_sha256: bytes
    control_endpoint_so_cookie: int


def encode_gateway_readiness_result_payload_v3(payload: GatewayReadinessResultPayloadV3) -> bytes:
    if type(payload) is not GatewayReadinessResultPayloadV3:
        _reject("gateway readiness result payload is invalid")
    generation = _uint(payload.census_generation, 64, "census generation")
    if generation != 1:
        _reject("gateway readiness generation is invalid")
    if type(payload.gateway_pid) is not int or not 0 < payload.gateway_pid < 1 << 32:
        _reject("gateway readiness PID is invalid")
    if type(payload.session_worker_count) is not int or not 0 <= payload.session_worker_count <= 4:
        _reject("gateway readiness worker count is invalid")
    flags = _uint(payload.flags, 16, "gateway readiness flags")
    if flags != 1:
        _reject("gateway readiness flags are invalid")
    if type(payload.control_endpoint_so_cookie) is not int or not 0 < payload.control_endpoint_so_cookie < 1 << 64:
        _reject("gateway readiness control endpoint cookie is invalid")
    return struct.pack(
        ">QIHH32sQ", generation,
        _uint(payload.gateway_pid, 32, "gateway PID"),
        _uint(payload.session_worker_count, 16, "session worker count"), flags,
        _exact_bytes(payload.executable_sha256, 32, "gateway executable digest"),
        _uint(payload.control_endpoint_so_cookie, 64, "control endpoint socket cookie"),
    )


def decode_gateway_readiness_result_payload_v3(data: bytes) -> GatewayReadinessResultPayloadV3:
    if type(data) is not bytes or len(data) != 56:
        _reject("gateway readiness result payload length is invalid")
    return _decode_with(
        encode_gateway_readiness_result_payload_v3,
        GatewayReadinessResultPayloadV3(*struct.unpack(">QIHH32sQ", data)),
    )


def _decode_with(encoder: Callable[[object], bytes], payload: object) -> object:
    """Reapply encoder validation to decoded values before returning them."""

    encoder(payload)
    return payload


WIRE_PAYLOAD_DECODERS_V3: Final[dict[ServingWireMessageTypeV3, Callable[[bytes], object]]] = {
    ServingWireMessageTypeV3.SESSION_FD: decode_session_fd_payload_v3,
    ServingWireMessageTypeV3.COLLECTOR_REQUEST: decode_collector_request_payload_v3,
    ServingWireMessageTypeV3.COLLECTOR_RESPONSE: decode_collector_response_payload_v3,
    ServingWireMessageTypeV3.COLLECTOR_ACK_VALID: decode_collector_ack_valid_payload_v3,
    ServingWireMessageTypeV3.COLLECTOR_ACK_INVALID: decode_collector_ack_invalid_payload_v3,
    ServingWireMessageTypeV3.COLLECTOR_CANCEL: decode_collector_cancel_payload_v3,
    ServingWireMessageTypeV3.REQUEST_ACQUIRE: decode_request_acquire_payload_v3,
    ServingWireMessageTypeV3.REQUEST_ADMIT: decode_request_admit_payload_v3,
    ServingWireMessageTypeV3.REQUEST_REJECT: decode_request_reject_payload_v3,
    ServingWireMessageTypeV3.WORK_BEGIN: decode_work_begin_payload_v3,
    ServingWireMessageTypeV3.WORK_BEGUN: decode_work_begin_payload_v3,
    ServingWireMessageTypeV3.WORK_FINISH: decode_work_finish_payload_v3,
    ServingWireMessageTypeV3.WORK_FINISHED: decode_work_finish_payload_v3,
    ServingWireMessageTypeV3.REQUEST_RELEASE: decode_request_release_payload_v3,
    ServingWireMessageTypeV3.REQUEST_RELEASED: decode_request_released_payload_v3,
    ServingWireMessageTypeV3.SESSION_RELEASE: decode_session_release_payload_v3,
    ServingWireMessageTypeV3.SESSION_RELEASED: decode_session_released_payload_v3,
    ServingWireMessageTypeV3.PRE_REQUEST_REJECTED: decode_pre_request_rejected_payload_v3,
    ServingWireMessageTypeV3.GLOBAL_FAULT: decode_global_fault_payload_v3,
    ServingWireMessageTypeV3.CHUNK_ACK: decode_chunk_ack_payload_v3,
    ServingWireMessageTypeV3.SESSION_FD_ACK: decode_session_fd_ack_payload_v3,
    ServingWireMessageTypeV3.GATEWAY_READINESS_PROBE: decode_gateway_readiness_probe_payload_v3,
    ServingWireMessageTypeV3.GATEWAY_READINESS_RESULT: decode_gateway_readiness_result_payload_v3,
}


@dataclass(frozen=True)
class ServingWireFrameV3:
    header: ServingWireHeaderV3
    payload: object


def _validate_session_token(header: ServingWireHeaderV3) -> None:
    message_type = header.message_type
    token_is_zero = header.session_token == _ZERO_TOKEN
    if (
        ServingWireMessageTypeV3.SESSION_FD <= message_type <= ServingWireMessageTypeV3.PRE_REQUEST_REJECTED
        or message_type is ServingWireMessageTypeV3.SESSION_FD_ACK
    ) and token_is_zero:
        _reject("session-scoped message has a zero session token")
    if message_type in (
        ServingWireMessageTypeV3.GATEWAY_READINESS_PROBE,
        ServingWireMessageTypeV3.GATEWAY_READINESS_RESULT,
    ) and not token_is_zero:
        _reject("readiness message has a nonzero session token")


def encode_serving_wire_frame_v3(
    message_type: ServingWireMessageTypeV3,
    *,
    session_token: bytes,
    sequence: int,
    chunk_index: int,
    chunk_count: int,
    chunk_length: int,
    total_length: int,
    flags: int,
    payload_bytes: bytes,
) -> bytes:
    """Encode one frame from a caller-validated typed payload byte sequence."""

    if type(message_type) is not ServingWireMessageTypeV3 or type(payload_bytes) is not bytes:
        _reject("wire frame is invalid")
    if chunk_length != len(payload_bytes) or not payload_bytes or chunk_length > MAX_CHUNK_PAYLOAD_BYTES_V3:
        _reject("wire frame chunk length is invalid")
    header = ServingWireHeaderV3(
        HEADER_VERSION_V3, message_type, flags, sequence, chunk_index, chunk_count,
        chunk_length, total_length, session_token,
    )
    return encode_serving_wire_header_v3(header) + payload_bytes


def decode_serving_wire_frame_v3(data: bytes) -> ServingWireFrameV3:
    """Decode a wire frame, deferring multi-chunk collector payloads to reassembly."""

    if type(data) is not bytes or len(data) < HEADER_SIZE_V3:
        _reject("wire frame length is invalid")
    header = decode_serving_wire_header_v3(data[:HEADER_SIZE_V3])
    payload_bytes = data[HEADER_SIZE_V3:]
    if not payload_bytes or len(payload_bytes) != header.chunk_length or len(payload_bytes) > MAX_CHUNK_PAYLOAD_BYTES_V3:
        _reject("wire frame payload length is invalid")
    _validate_session_token(header)
    has_fd = bool(header.flags & FLAG_HAS_FD_V3)
    if (header.message_type is ServingWireMessageTypeV3.SESSION_FD) != has_fd:
        _reject("wire frame FD flag is invalid")
    if header.chunk_count > 1:
        if header.message_type is not ServingWireMessageTypeV3.COLLECTOR_RESPONSE:
            _reject("only collector responses may be chunked")
        return ServingWireFrameV3(header, payload_bytes)
    payload = WIRE_PAYLOAD_DECODERS_V3[header.message_type](payload_bytes)
    if header.message_type is ServingWireMessageTypeV3.GLOBAL_FAULT:
        assert type(payload) is GlobalFaultPayloadV3
        if (header.session_token == _ZERO_TOKEN) != (payload.cycle == 0):
            _reject("global fault token and cycle disagree")
    return ServingWireFrameV3(header, payload)


def reassemble_chunked_payload_v3(frames: list[ServingWireFrameV3]) -> bytes:
    """Validate and concatenate one complete chunked collector-response payload."""

    if type(frames) is not list or not frames or any(type(frame) is not ServingWireFrameV3 for frame in frames):
        _reject("chunk train is invalid")
    first = frames[0].header
    if (
        first.message_type is not ServingWireMessageTypeV3.COLLECTOR_RESPONSE
        or first.chunk_count < 2
        or first.total_length <= MAX_CHUNK_PAYLOAD_BYTES_V3
    ):
        _reject("chunk train is not a multi-frame collector response")
    expected_count = ceil(first.total_length / MAX_CHUNK_PAYLOAD_BYTES_V3)
    if first.chunk_count != expected_count or expected_count > 513 or len(frames) != expected_count:
        _reject("chunk train count is invalid")
    chunks: list[bytes] = []
    for index, frame in enumerate(frames):
        header = frame.header
        if (
            header.message_type is not first.message_type
            or header.sequence != first.sequence
            or header.total_length != first.total_length
            or header.session_token != first.session_token
            or header.chunk_count != expected_count
            or header.chunk_index != index
            or header.flags & FLAG_HAS_FD_V3
            or bool(header.flags & FLAG_START_V3) != (index == 0)
            or bool(header.flags & FLAG_END_V3) != (index == expected_count - 1)
            or type(frame.payload) is not bytes
            or len(frame.payload) != header.chunk_length
            or header.chunk_length > MAX_CHUNK_PAYLOAD_BYTES_V3
        ):
            _reject("chunk train ordering or flags are invalid")
        chunks.append(frame.payload)
    result = b"".join(chunks)
    if len(result) != first.total_length:
        _reject("chunk train total length is invalid")
    decode_collector_response_payload_v3(result)
    return result
