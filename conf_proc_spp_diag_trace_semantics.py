#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent policy-2 SPP trace semantic appraisal.

This module parses the raw wire directly. It intentionally does not import the
C codec, trace-chain reducer, checkpoint binder, or the frozen test fixture.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Final, NoReturn

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_spp_diag_trace_semantic_reasons import (
    CP_SPP_TRACE_SEMANTICS_CAP,
    CP_SPP_TRACE_SEMANTICS_CONTROL,
    CP_SPP_TRACE_SEMANTICS_FRAME,
    CP_SPP_TRACE_SEMANTICS_HEADER,
    CP_SPP_TRACE_SEMANTICS_LEDGER,
    CP_SPP_TRACE_SEMANTICS_LIFECYCLE,
    CP_SPP_TRACE_SEMANTICS_OPERATION,
    CP_SPP_TRACE_SEMANTICS_PHASE,
    CP_SPP_TRACE_SEMANTICS_PLAN,
    CP_SPP_TRACE_SEMANTICS_PRIVACY,
    CP_SPP_TRACE_SEMANTICS_RESULT,
    CP_SPP_TRACE_SEMANTICS_SEQUENCE,
    CP_SPP_TRACE_SEMANTICS_TASK,
    CP_SPP_TRACE_SEMANTICS_TYPE,
    TraceSemanticsError,
)


MAX_STREAM_BYTES: Final = 268_435_456
MAX_PLAN_BYTES: Final = 131_072
MAX_FRAMES: Final = 524_288
MAX_FRAME_BYTES: Final = 1_088
HEADER_BYTES: Final = 192
SOURCE_COMMIT: Final = bytes.fromhex("91a8e826012fbb1c7f5cb2a326c08b13e390f469")
PLAN_DOMAIN: Final = b"sol-spp-diagbundle-control-plan-v1\0"
AT_FDCWD_BITS: Final = 0xFFFFFF9C

CORE_INIT: Final = 1
PRE_RELEASE_EXEC_DENIED: Final = 2
IMA_READY: Final = 3
USERSPACE_RELEASE: Final = 4
EXEC_ATTEMPT: Final = 5
EXEC_COMMIT: Final = 6
TASK_ALLOC_ATTEMPT: Final = 7
TASK_CREATED: Final = 8
PHASE_MARKER: Final = 9
TERMINAL: Final = 10
FILE_OPEN_ATTEMPT: Final = 0x0100
FILE_POLICY_DECISION: Final = 0x0101
EXEC_MAPPING_POLICY_DECISION: Final = 0x0102
NETWORK_POLICY_DECISION: Final = 0x0103
OPERATION_RETURN: Final = 0x0104
TASK_EXIT: Final = 0x0105

READ: Final = 1
NOFOLLOW: Final = 0x0008
CLOEXEC: Final = 0x0010
ALLOW: Final = 1
DENY: Final = 2
MMAP: Final = 1
MPROTECT: Final = 2
ANONYMOUS: Final = 1
PROT_EXEC: Final = 4
CONNECT: Final = 1
SENDMSG: Final = 2
IPV4: Final = 1
IPV6: Final = 2
EXPLICIT: Final = 1
STREAM: Final = 1
DGRAM: Final = 2

RETURN_KIND: Final = {
    1: "file_open",
    2: "mmap",
    3: "mprotect",
    4: "connect",
    5: "sendmsg",
    6: "exec",
}
INT_RETURN_KINDS: Final = frozenset({"mprotect", "connect", "sendmsg", "exec"})

PHASE_NAMES: Final = (
    "init",
    "cold_start",
    "synthetic_inference",
    "poison_import",
    "poison_module",
    "poison_library",
    "remote_package",
    "remote_model",
    "remote_plugin",
    "writable_exec",
    "attached_disk_exec",
    "remote_code",
    "jit_cache",
    "evidence_finalize",
)

PLAN_KEYS: Final = frozenset(
    {
        "attached_disk_exec",
        "cold_start",
        "jit_cache",
        "phase_order",
        "poison_import",
        "poison_library",
        "poison_module",
        "pre_release",
        "remote_code",
        "remote_model",
        "remote_package",
        "remote_plugin",
        "schema",
        "synthetic_inference",
        "writable_exec",
    }
)


def _fail(reason: str) -> None:
    raise TraceSemanticsError(reason) from None


def _exact_dict(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    return value


def _lower_hex(value: object, byte_length: int | None = None) -> bytes:
    if type(value) is not str or len(value) == 0 or len(value) % 2 != 0:
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    if byte_length is not None and len(value) != byte_length * 2:
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    if any(character not in "0123456789abcdef" for character in value):
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    try:
        result = bytes.fromhex(value)
    except ValueError:
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    if byte_length is not None and len(result) != byte_length:
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    return result


def _plan_path(value: object) -> bytes:
    raw = _lower_hex(value)
    if len(raw) > 1_024 or raw[:1] != b"/" or b"\0" in raw:
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    return raw


def _plan_endpoint(value: object) -> dict[str, object]:
    row = _exact_dict(value, frozenset({"address_hex", "family", "operation", "port"}))
    family = row["family"]
    operation = row["operation"]
    port = row["port"]
    if type(family) is not int or family not in (2, 10):
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    if type(operation) is not str or operation not in ("connect", "sendmsg"):
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    if type(port) is not int or not 1 <= port <= 65_535:
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    address = _lower_hex(row["address_hex"], 4 if family == 2 else 16)
    return {"address": address, "family": family, "operation": operation, "port": port}


def _one_path(value: object, key: str) -> bytes:
    row = _exact_dict(value, frozenset({key}))
    return _plan_path(row[key])


@dataclass(frozen=True)
class _Plan:
    address: bytes
    pre_release: bytes
    cold_start: bytes
    model_path: bytes
    model_sha256: str
    jit_path: bytes
    jit_sha256: str
    poison_paths: dict[int, bytes]
    remote_endpoints: dict[int, dict[str, object]]
    exec_denials: dict[int, bytes]


def _parse_plan(data: bytes) -> _Plan:
    try:
        value = canonical_loads(data)
    except Exception:
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    root = _exact_dict(value, PLAN_KEYS)
    if root["schema"] != "sol-spp-diag-trace-control-plan-v1":
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    phase_order = root["phase_order"]
    if type(phase_order) is not list or tuple(phase_order) != PHASE_NAMES:
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)

    synthetic = _exact_dict(
        root["synthetic_inference"],
        frozenset(
            {"gpu_witness_policy_address", "model_path_hex", "model_sha256", "output_oracle_address"}
        ),
    )
    model_sha256 = synthetic["model_sha256"]
    if type(model_sha256) is not str:
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    _lower_hex(model_sha256, 32)
    _lower_hex(synthetic["gpu_witness_policy_address"], 32)
    _lower_hex(synthetic["output_oracle_address"], 32)

    jit = _exact_dict(root["jit_cache"], frozenset({"object_sha256", "path_hex"}))
    jit_sha256 = jit["object_sha256"]
    if type(jit_sha256) is not str:
        _fail(CP_SPP_TRACE_SEMANTICS_PLAN)
    _lower_hex(jit_sha256, 32)

    address = hashlib.sha256(PLAN_DOMAIN + data).digest()
    return _Plan(
        address=address,
        pre_release=_one_path(root["pre_release"], "denied_exec_path_hex"),
        cold_start=_one_path(root["cold_start"], "exec_path_hex"),
        model_path=_plan_path(synthetic["model_path_hex"]),
        model_sha256=model_sha256,
        jit_path=_plan_path(jit["path_hex"]),
        jit_sha256=jit_sha256,
        poison_paths={
            4: _one_path(root["poison_import"], "path_hex"),
            5: _one_path(root["poison_module"], "path_hex"),
            6: _one_path(root["poison_library"], "path_hex"),
        },
        remote_endpoints={
            7: _plan_endpoint(root["remote_package"]),
            8: _plan_endpoint(root["remote_model"]),
            9: _plan_endpoint(root["remote_plugin"]),
        },
        exec_denials={
            10: _one_path(root["writable_exec"], "path_hex"),
            11: _one_path(root["attached_disk_exec"], "path_hex"),
            12: _one_path(root["remote_code"], "exec_path_hex"),
        },
    )


@dataclass(frozen=True)
class _Frame:
    event: int
    sequence: int
    task: int
    parent: int
    operation: int
    phase: int
    payload: dict[str, object]


def _path_payload(payload: bytes, prefix: int, path_length_offset: int) -> bytes:
    path_length = struct.unpack_from(">H", payload, path_length_offset)[0]
    if path_length == 0 or path_length > 1_024 or len(payload) != prefix + path_length:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    path = payload[prefix:]
    if b"\0" in path:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    return path


def _core_payload(event: int, payload: bytes, frame_phase: int) -> dict[str, object]:
    if event in (CORE_INIT, TERMINAL):
        if payload:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        return {}
    if event == PRE_RELEASE_EXEC_DENIED:
        if not 21 <= len(payload) <= 1_044:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        path = _path_payload(payload, 20, 2)
        errno_value, _path_length, pid, tgid, task_flags = struct.unpack_from(">HHIIQ", payload)
        if errno_value != 13 or pid == 0 or tgid == 0 or task_flags != 0:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        return {"path": path, "pid": pid, "tgid": tgid}
    if event == IMA_READY:
        if len(payload) != 8:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        return {"denied_count": struct.unpack(">Q", payload)[0]}
    if event == USERSPACE_RELEASE:
        if len(payload) != 16:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        pid, tgid, denied_count = struct.unpack(">IIQ", payload)
        if pid == 0 or tgid == 0:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        return {"pid": pid, "tgid": tgid, "denied_count": denied_count}
    if event == EXEC_ATTEMPT:
        if not 17 <= len(payload) <= 1_040:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        path = _path_payload(payload, 16, 4)
        pass_index, _path_length, reserved, pid, tgid = struct.unpack_from(">IHHII", payload)
        if pass_index == 0 or reserved != 0 or pid == 0 or tgid == 0:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        return {"pass_index": pass_index, "path": path, "pid": pid, "tgid": tgid}
    if event == EXEC_COMMIT:
        if len(payload) != 16:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        pass_count, pid, tgid, reserved = struct.unpack(">IIII", payload)
        if pass_count == 0 or pid == 0 or tgid == 0 or reserved != 0:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        return {"pass_count": pass_count, "pid": pid, "tgid": tgid}
    if event == TASK_ALLOC_ATTEMPT:
        if len(payload) != 8:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        return {"clone_flags": struct.unpack(">Q", payload)[0]}
    if event == TASK_CREATED:
        if len(payload) != 16:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        pid, tgid, clone_flags = struct.unpack(">IIQ", payload)
        if pid == 0 or tgid == 0:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        return {"pid": pid, "tgid": tgid, "clone_flags": clone_flags}
    if event == PHASE_MARKER:
        if len(payload) != 8:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        previous, next_phase, reserved = struct.unpack(">HHI", payload)
        if reserved != 0 or not 1 <= previous <= 13 or next_phase != previous + 1 or frame_phase != next_phase:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        return {"previous": previous, "next": next_phase}
    _fail(CP_SPP_TRACE_SEMANTICS_FRAME)


def _file_attempt_payload(payload: bytes) -> dict[str, object]:
    if not 17 <= len(payload) <= 1_040:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    path = _path_payload(payload, 16, 2)
    action, _path_length, access, modifiers, dirfd, reserved = struct.unpack_from(">HHHHII", payload)
    if action != 1 or access not in (1, 2, 3, 4) or modifiers & ~0x003F or reserved != 0:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    return {"path": path, "access": access, "modifiers": modifiers, "dirfd": dirfd}


def _file_policy_payload(payload: bytes) -> dict[str, object]:
    if len(payload) != 48:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    values = struct.unpack(">HHHHIIIIQQQ", payload)
    access, modifiers, decision, object_kind, result, fs_magic, dev_major, dev_minor, inode, mount, size = values
    if access not in (1, 2, 3, 4) or modifiers & ~0x003F:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if decision not in (ALLOW, DENY) or object_kind not in (1, 2, 3, 4):
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if (decision == ALLOW and result != 0) or (decision == DENY and result < 0x80000000):
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if inode == 0 or mount == 0:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    return {
        "access": access,
        "modifiers": modifiers,
        "decision": decision,
        "result": result,
        "object_kind": object_kind,
        "object": (fs_magic, dev_major, dev_minor, inode, mount, size),
    }


def _mapping_payload(payload: bytes) -> dict[str, object]:
    if len(payload) != 64:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    values = struct.unpack(">HHHHIIIIIIIIQQQ", payload)
    operation, decision, backing, mode = values[:4]
    requested, effective, prior, result, fs_magic, dev_major, dev_minor, seals = values[4:12]
    inode, mount, size = values[12:]
    if operation not in (MMAP, MPROTECT) or decision not in (ALLOW, DENY):
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if backing not in (1, 2, 3, 4) or mode not in (1, 2):
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if requested & ~7 or effective & ~7 or prior & ~7 or not effective & PROT_EXEC:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if operation == MMAP and prior != 0:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if (decision == ALLOW and result != 0) or (decision == DENY and result < 0x80000000):
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if backing == ANONYMOUS:
        if any((fs_magic, dev_major, dev_minor, seals, inode, mount, size)):
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    else:
        if inode == 0 or mount == 0 or (backing != 3 and seals != 0):
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    return {
        "mapping_operation": operation,
        "decision": decision,
        "result": result,
        "backing": backing,
        "mode": mode,
        "requested": requested,
        "effective": effective,
        "prior": prior,
        "seals": seals,
        "object": (fs_magic, dev_major, dev_minor, inode, mount, size),
    }


def _network_payload(payload: bytes) -> dict[str, object]:
    if len(payload) != 64:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    values = struct.unpack(">HHHHHHHHIIIQHHII16s", payload)
    operation, decision, kind, source, socket_kind, protocol, family, addrlen = values[:8]
    result, flags, size, cookie, port, reserved, scope, flow, address_field = values[8:]
    if operation not in (CONNECT, SENDMSG) or decision not in (ALLOW, DENY):
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if kind not in range(1, 6) or source not in (1, 2) or socket_kind not in range(1, 6):
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if cookie == 0 or reserved != 0 or addrlen > 128:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if (decision == ALLOW and result != 0) or (decision == DENY and result < 0x80000000):
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if operation == CONNECT and (source != EXPLICIT or flags != 0 or size != 0):
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if operation == SENDMSG and size >= 0x80000000:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    if kind == IPV4:
        if family != 2 or ((source == EXPLICIT) != (addrlen == 16)):
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        if source != EXPLICIT and addrlen != 0:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        if scope != 0 or flow != 0 or any(address_field[:12]):
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        address = address_field[12:]
    elif kind == IPV6:
        if family != 10 or ((source == EXPLICIT) != (addrlen == 28)):
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        if source != EXPLICIT and addrlen != 0:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        address = address_field
    else:
        if port != 0 or scope != 0 or flow != 0 or any(address_field):
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        address = b""
        if kind == 3:
            if source == EXPLICIT:
                if family in (0, 2, 10) or not 2 <= addrlen <= 128:
                    _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
            elif family in (0, 2, 10) or addrlen != 0:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        elif kind == 4:
            malformed = source == EXPLICIT and (
                (family == 0 and addrlen in (0, 1))
                or (family == 2 and 2 <= addrlen <= 128 and addrlen != 16)
                or (family == 10 and 2 <= addrlen <= 128 and addrlen != 28)
            )
            if not malformed:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        elif kind == 5 and not (
            operation == SENDMSG and source == 2 and family == 0 and addrlen == 0
        ):
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    return {
        "network_operation": operation,
        "decision": decision,
        "result": result,
        "kind": kind,
        "source": source,
        "socket_kind": socket_kind,
        "protocol": protocol,
        "family": family,
        "addrlen": addrlen,
        "flags": flags,
        "size": size,
        "cookie": cookie,
        "port": port,
        "scope": scope,
        "flow": flow,
        "address": address,
    }


def _decode_frame(entry: bytes, expected_sequence: int) -> _Frame:
    if not 44 <= len(entry) <= MAX_FRAME_BYTES:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    event, flags, payload_length, sequence, task, parent, operation, phase, reserved = struct.unpack_from(
        ">HHIQQQQHH", entry
    )
    if sequence != expected_sequence:
        _fail(CP_SPP_TRACE_SEMANTICS_SEQUENCE)
    if flags != 0 or reserved != 0 or len(entry) != 44 + payload_length:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    payload_bytes = entry[44:]

    if 1 <= event <= 10:
        if event in (CORE_INIT, IMA_READY, TERMINAL) and task != 0:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        if event == PRE_RELEASE_EXEC_DENIED:
            if task != 0 or parent != 0 or operation == 0 or phase != 0:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        elif event in (CORE_INIT, IMA_READY):
            if parent != 0 or operation != 0 or phase != 0:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        elif event == USERSPACE_RELEASE:
            if task == 0 or parent != 0 or operation != 0 or phase != 0:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        elif event in (EXEC_ATTEMPT, EXEC_COMMIT):
            if task == 0 or parent != 0 or operation == 0 or not 1 <= phase <= 14:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        elif event in (TASK_ALLOC_ATTEMPT, TASK_CREATED):
            if task == 0 or parent == 0 or task == parent or operation == 0 or not 1 <= phase <= 14:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        elif event == PHASE_MARKER:
            if task == 0 or parent != 0 or operation != 0 or not 2 <= phase <= 14:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        elif event == TERMINAL:
            if parent != 0 or operation != 0 or phase != 15:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        payload = _core_payload(event, payload_bytes, phase)
    elif 0x0100 <= event <= 0x0105:
        if task == 0 or not 1 <= phase <= 14:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        if event == TASK_EXIT:
            if parent == 0 or parent == task or operation != 0:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
            if len(payload_bytes) != 8:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
            exit_code, reserved32 = struct.unpack(">II", payload_bytes)
            if reserved32 != 0:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
            payload = {"exit_code": exit_code}
        else:
            if parent != 0 or operation == 0:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
            if event == FILE_OPEN_ATTEMPT:
                payload = _file_attempt_payload(payload_bytes)
            elif event == FILE_POLICY_DECISION:
                payload = _file_policy_payload(payload_bytes)
            elif event == EXEC_MAPPING_POLICY_DECISION:
                payload = _mapping_payload(payload_bytes)
            elif event == NETWORK_POLICY_DECISION:
                payload = _network_payload(payload_bytes)
            elif event == OPERATION_RETURN:
                if len(payload_bytes) != 16:
                    _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
                kind, reserved16, reserved32, raw = struct.unpack(">HHIQ", payload_bytes)
                if kind not in RETURN_KIND or reserved16 != 0 or reserved32 != 0:
                    _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
                payload = {"kind": RETURN_KIND[kind], "raw": raw}
            else:
                _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    else:
        _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
    return _Frame(event, sequence, task, parent, operation, phase, payload)


@dataclass
class _TaskState:
    ordinal: int
    parent: int | None
    pid: int
    tgid: int
    mint_phase: int | None
    creation_sequence: int | None
    exit_sequence: int | None = None
    exit_code: int | None = None
    live: bool = True
    doomed: bool = False


@dataclass
class _OperationState:
    ordinal: int
    kind: str
    task: int
    phase: int
    first_sequence: int
    path: bytes | None = None
    access: int | None = None
    modifiers: int | None = None
    dirfd: int | None = None
    parent: int | None = None
    clone_flags: int | None = None
    pid: int | None = None
    tgid: int | None = None
    exec_passes: int = 0
    committed: bool | None = None
    policy_rows: list[dict[str, object]] = field(default_factory=list)


def _hex16(value: int) -> str:
    return f"{value:016x}"


def _signed64(raw: int) -> int:
    return raw - (1 << 64) if raw & (1 << 63) else raw


def _signed32(raw: int) -> int:
    low = raw & 0xFFFFFFFF
    return low - (1 << 32) if low & (1 << 31) else low


def _canonical_int(raw: int) -> bool:
    low = raw & 0xFFFFFFFF
    widened = low | 0xFFFFFFFF00000000 if low & 0x80000000 else low
    return raw == widened


def _object_row(
    sequence: int,
    operation: int,
    phase: int,
    role: str,
    expected_sha256: str | None,
    object_tuple: tuple[int, int, int, int, int, int],
) -> dict[str, object]:
    fs_magic, dev_major, dev_minor, inode, mount, size = object_tuple
    return {
        "dev_major_hex": f"{dev_major:08x}",
        "dev_minor_hex": f"{dev_minor:08x}",
        "expected_sha256": expected_sha256,
        "fs_magic_hex": f"{fs_magic:08x}",
        "inode_hex": f"{inode:016x}",
        "mount_identity_hex": f"{mount:016x}",
        "observed_size_hex": f"{size:016x}",
        "operation_ordinal": _hex16(operation),
        "phase": phase,
        "role": role,
        "sequence": sequence,
    }


class _Reducer:
    def __init__(self, plan: _Plan, header: dict[str, object], stream_length: int) -> None:
        self.plan = plan
        self.header = header
        self.stream_length = stream_length
        self.stage = 0
        self.current_phase: int | None = None
        self.phase_start: int | None = None
        self.root: int | None = None
        self.tasks: dict[int, _TaskState] = {}
        self.task_order: list[int] = []
        self.used_tasks: set[int] = set()
        self.live_identities: dict[tuple[int, int], int] = {}
        self.open_operations: dict[int, _OperationState] = {}
        self.open_by_task: dict[int, int] = {}
        self.used_operations: set[int] = set()
        self.closed_operations: list[dict[str, object]] = []
        self.object_bindings: list[dict[str, object]] = []
        self.phases: list[dict[str, object]] = []
        self.control_hits: dict[int, int] = {phase: 0 for phase in range(2, 14)}
        self.cold_success_tasks: set[int] = set()
        self.model_object: tuple[int, int, int, int, int, int] | None = None
        self.jit_object: tuple[int, int, int, int, int, int] | None = None
        self.jit_stage = 0
        self.terminal_seen = False

    def _live_task(self, ordinal: int, *, allow_doomed: bool = False) -> _TaskState:
        task = self.tasks.get(ordinal)
        if task is None or not task.live or (task.doomed and not allow_doomed):
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        return task

    def _mint_operation(self, frame: _Frame, kind: str) -> _OperationState:
        if frame.operation in self.used_operations:
            _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
        self.used_operations.add(frame.operation)
        operation = _OperationState(frame.operation, kind, frame.task, frame.phase, frame.sequence)
        self.open_operations[frame.operation] = operation
        self.open_by_task[frame.task] = self.open_by_task.get(frame.task, 0) + 1
        return operation

    def _operation(self, frame: _Frame, kind: str) -> _OperationState:
        operation = self.open_operations.get(frame.operation)
        if operation is None or operation.kind != kind or operation.task != frame.task or operation.phase != frame.phase:
            _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
        return operation

    def _close_operation(
        self,
        operation: _OperationState,
        last_sequence: int,
        final_raw: int | None,
        committed: bool | None,
    ) -> None:
        self.closed_operations.append(
            {
                "committed": committed,
                "final_raw_hex": None if final_raw is None else f"{final_raw:016x}",
                "first_sequence": operation.first_sequence,
                "kind": operation.kind,
                "last_sequence": last_sequence,
                "operation_ordinal": _hex16(operation.ordinal),
                "phase": operation.phase,
                "policy_count": len(operation.policy_rows),
                "task_ordinal": _hex16(operation.task),
            }
        )
        del self.open_operations[operation.ordinal]
        remaining = self.open_by_task[operation.task] - 1
        if remaining == 0:
            del self.open_by_task[operation.task]
        else:
            self.open_by_task[operation.task] = remaining

    def _policy_role(
        self, phase: int, object_tuple: tuple[int, int, int, int, int, int]
    ) -> tuple[str, str | None]:
        if phase == 3 and self.model_object == object_tuple:
            return "synthetic_model", self.plan.model_sha256
        if phase == 13 and self.jit_object == object_tuple:
            return "jit_cache", self.plan.jit_sha256
        return "ordinary_measured_object", None

    def _add_object_binding(self, frame: _Frame, object_tuple: tuple[int, int, int, int, int, int]) -> None:
        role, expected = self._policy_role(frame.phase, object_tuple)
        self.object_bindings.append(
            _object_row(frame.sequence, frame.operation, frame.phase, role, expected, object_tuple)
        )

    def _runtime_frame(self, frame: _Frame) -> None:
        if self.current_phase is None:
            _fail(CP_SPP_TRACE_SEMANTICS_LIFECYCLE)
        if frame.event == PHASE_MARKER:
            self._marker(frame)
            return
        if frame.event == TERMINAL:
            self._terminal(frame)
            return
        if frame.phase != self.current_phase:
            _fail(CP_SPP_TRACE_SEMANTICS_PHASE)
        if self.current_phase == 14:
            _fail(CP_SPP_TRACE_SEMANTICS_PHASE)

        if frame.event == TASK_ALLOC_ATTEMPT:
            self._task_alloc(frame)
        elif frame.event == TASK_CREATED:
            self._task_created(frame)
        elif frame.event == EXEC_ATTEMPT:
            self._exec_attempt(frame)
        elif frame.event == EXEC_COMMIT:
            self._exec_commit(frame)
        elif frame.event == FILE_OPEN_ATTEMPT:
            self._file_attempt(frame)
        elif frame.event == FILE_POLICY_DECISION:
            self._file_policy(frame)
        elif frame.event == EXEC_MAPPING_POLICY_DECISION:
            self._mapping_policy(frame)
        elif frame.event == NETWORK_POLICY_DECISION:
            self._network_policy(frame)
        elif frame.event == OPERATION_RETURN:
            self._operation_return(frame)
        elif frame.event == TASK_EXIT:
            self._task_exit(frame)
        else:
            _fail(CP_SPP_TRACE_SEMANTICS_LIFECYCLE)

    def consume(self, frame: _Frame, is_last: bool) -> None:
        if self.terminal_seen:
            _fail(CP_SPP_TRACE_SEMANTICS_LIFECYCLE)
        if self.stage == 0:
            if frame.event != CORE_INIT or frame.sequence != 0:
                _fail(CP_SPP_TRACE_SEMANTICS_LIFECYCLE)
            self.stage = 1
        elif self.stage == 1:
            if frame.event != PRE_RELEASE_EXEC_DENIED or frame.payload["path"] != self.plan.pre_release:
                _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
            if frame.operation in self.used_operations:
                _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
            self.used_operations.add(frame.operation)
            self.closed_operations.append(
                {
                    "committed": None,
                    "final_raw_hex": None,
                    "first_sequence": frame.sequence,
                    "kind": "pre_release_denied",
                    "last_sequence": frame.sequence,
                    "operation_ordinal": _hex16(frame.operation),
                    "phase": 0,
                    "policy_count": 0,
                    "task_ordinal": None,
                }
            )
            self.stage = 2
        elif self.stage == 2:
            if frame.event != IMA_READY or frame.payload["denied_count"] != 1:
                _fail(CP_SPP_TRACE_SEMANTICS_LIFECYCLE)
            self.stage = 3
        elif self.stage == 3:
            if frame.event != USERSPACE_RELEASE or frame.payload["denied_count"] != 1:
                _fail(CP_SPP_TRACE_SEMANTICS_LIFECYCLE)
            if frame.task in self.used_tasks:
                _fail(CP_SPP_TRACE_SEMANTICS_TASK)
            self.root = frame.task
            self.used_tasks.add(frame.task)
            self.tasks[frame.task] = _TaskState(
                frame.task,
                None,
                int(frame.payload["pid"]),
                int(frame.payload["tgid"]),
                None,
                None,
            )
            self.live_identities[(int(frame.payload["pid"]), int(frame.payload["tgid"]))] = frame.task
            self.task_order.append(frame.task)
            self.current_phase = 1
            self.phase_start = frame.sequence + 1
            self.stage = 4
        else:
            self._runtime_frame(frame)
        if is_last and not self.terminal_seen:
            _fail(CP_SPP_TRACE_SEMANTICS_LIFECYCLE)

    def _control_only(self, allowed: frozenset[int], event: int) -> None:
        if self.current_phase is not None and 4 <= self.current_phase <= 12 and event not in allowed:
            _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)

    def _task_alloc(self, frame: _Frame) -> None:
        self._control_only(frozenset(), frame.event)
        self._live_task(frame.parent)
        if frame.task in self.used_tasks or frame.task in self.tasks:
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        operation = self._mint_operation(frame, "task_alloc")
        operation.parent = frame.parent
        operation.clone_flags = int(frame.payload["clone_flags"])

    def _task_created(self, frame: _Frame) -> None:
        self._control_only(frozenset(), frame.event)
        operation = self._operation(frame, "task_alloc")
        if operation.parent != frame.parent or operation.clone_flags != frame.payload["clone_flags"]:
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        self._live_task(frame.parent)
        if frame.task in self.used_tasks:
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        pid, tgid = int(frame.payload["pid"]), int(frame.payload["tgid"])
        if (pid, tgid) in self.live_identities:
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        self.used_tasks.add(frame.task)
        self.tasks[frame.task] = _TaskState(
            frame.task, frame.parent, pid, tgid, frame.phase, frame.sequence
        )
        self.live_identities[(pid, tgid)] = frame.task
        self.task_order.append(frame.task)
        self._close_operation(operation, frame.sequence, None, None)

    def _exec_attempt(self, frame: _Frame) -> None:
        if self.current_phase in (4, 5, 6, 7, 8, 9):
            _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
        task = self._live_task(frame.task)
        if (frame.payload["pid"], frame.payload["tgid"]) != (task.pid, task.tgid):
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        operation = self.open_operations.get(frame.operation)
        if operation is None:
            operation = self._mint_operation(frame, "exec")
            operation.path = frame.payload["path"]
            operation.pid = task.pid
            operation.tgid = task.tgid
            operation.committed = False
        elif operation.kind != "exec" or operation.task != frame.task or operation.phase != frame.phase:
            _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
        if operation.committed or frame.payload["path"] != operation.path:
            _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
        if frame.payload["pass_index"] != operation.exec_passes + 1:
            _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
        operation.exec_passes += 1
        if self.current_phase in (10, 11, 12) and operation.path != self.plan.exec_denials[self.current_phase]:
            _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)

    def _exec_commit(self, frame: _Frame) -> None:
        self._control_only(frozenset(), frame.event)
        task = self._live_task(frame.task)
        operation = self._operation(frame, "exec")
        if operation.committed or frame.payload["pass_count"] != operation.exec_passes:
            _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
        if (frame.payload["pid"], frame.payload["tgid"]) != (task.pid, task.tgid):
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        operation.committed = True

    def _file_attempt(self, frame: _Frame) -> None:
        if self.current_phase in (7, 8, 9, 10, 11, 12):
            _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
        self._live_task(frame.task)
        operation = self._mint_operation(frame, "file_open")
        operation.path = frame.payload["path"]
        operation.access = int(frame.payload["access"])
        operation.modifiers = int(frame.payload["modifiers"])
        operation.dirfd = int(frame.payload["dirfd"])
        if operation.dirfd != AT_FDCWD_BITS:
            _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
        if self.current_phase in self.plan.poison_paths:
            if (
                operation.path != self.plan.poison_paths[self.current_phase]
                or operation.access != READ
                or operation.modifiers != NOFOLLOW | CLOEXEC
            ):
                _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
        elif self.current_phase == 3 and operation.path == self.plan.model_path:
            if operation.access != READ or operation.modifiers != CLOEXEC:
                _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
        elif self.current_phase == 13 and operation.path == self.plan.jit_path:
            if operation.access != READ or operation.modifiers != CLOEXEC:
                _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)

    def _file_policy(self, frame: _Frame) -> None:
        self._control_only(frozenset(), frame.event)
        self._live_task(frame.task)
        operation = self._operation(frame, "file_open")
        if operation.policy_rows or (
            frame.payload["access"], frame.payload["modifiers"]
        ) != (operation.access, operation.modifiers):
            _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
        operation.policy_rows.append(frame.payload)
        object_tuple = frame.payload["object"]
        if not isinstance(object_tuple, tuple):
            _fail(CP_SPP_TRACE_SEMANTICS_LEDGER)
        if frame.phase == 3 and operation.path == self.plan.model_path:
            self.model_object = object_tuple
        elif frame.phase == 13 and operation.path == self.plan.jit_path:
            self.jit_object = object_tuple
        self._add_object_binding(frame, object_tuple)

    def _mapping_policy(self, frame: _Frame) -> None:
        self._control_only(frozenset(), frame.event)
        self._live_task(frame.task)
        mapping_operation = int(frame.payload["mapping_operation"])
        kind = "mmap" if mapping_operation == MMAP else "mprotect"
        operation = self.open_operations.get(frame.operation)
        if operation is None:
            operation = self._mint_operation(frame, kind)
        elif operation.kind != kind or operation.task != frame.task or operation.phase != frame.phase:
            _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
        if kind == "mmap" and operation.policy_rows:
            _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
        if operation.policy_rows and operation.policy_rows[-1]["decision"] == DENY:
            _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
        if frame.payload["backing"] == ANONYMOUS:
            _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
        operation.policy_rows.append(frame.payload)
        object_tuple = frame.payload["object"]
        if not isinstance(object_tuple, tuple):
            _fail(CP_SPP_TRACE_SEMANTICS_LEDGER)
        self._add_object_binding(frame, object_tuple)

    def _endpoint_matches(self, payload: dict[str, object], endpoint: dict[str, object]) -> bool:
        expected_operation = CONNECT if endpoint["operation"] == "connect" else SENDMSG
        if payload["network_operation"] != expected_operation:
            return False
        if expected_operation == CONNECT:
            fixed = payload["socket_kind"] == STREAM and payload["protocol"] == 6 and payload["size"] == 0
        else:
            fixed = payload["socket_kind"] == DGRAM and payload["protocol"] == 17 and payload["size"] == 1
        return bool(
            fixed
            and payload["decision"] == DENY
            and payload["kind"] == (IPV4 if endpoint["family"] == 2 else IPV6)
            and payload["source"] == EXPLICIT
            and payload["family"] == endpoint["family"]
            and payload["port"] == endpoint["port"]
            and payload["scope"] == 0
            and payload["flow"] == 0
            and payload["flags"] == 0
            and payload["address"] == endpoint["address"]
        )

    def _network_policy(self, frame: _Frame) -> None:
        if self.current_phase in (4, 5, 6, 10, 11, 12):
            _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
        self._live_task(frame.task)
        if frame.payload["kind"] in (4, 5):
            _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
        kind = "connect" if frame.payload["network_operation"] == CONNECT else "sendmsg"
        operation = self._mint_operation(frame, kind)
        operation.policy_rows.append(frame.payload)
        if self.current_phase in self.plan.remote_endpoints and not self._endpoint_matches(
            frame.payload, self.plan.remote_endpoints[self.current_phase]
        ):
            _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)

    def _policy_result(self, operation: _OperationState, raw: int) -> None:
        if not operation.policy_rows:
            return
        denied = [row for row in operation.policy_rows if row["decision"] == DENY]
        if denied:
            if operation.policy_rows[-1]["decision"] != DENY or len(denied) != 1:
                _fail(CP_SPP_TRACE_SEMANTICS_RESULT)
            policy_result = int(denied[0]["result"])
            expected = policy_result | 0xFFFFFFFF00000000
            if raw != expected:
                _fail(CP_SPP_TRACE_SEMANTICS_RESULT)

    def _operation_return(self, frame: _Frame) -> None:
        self._live_task(frame.task)
        kind = str(frame.payload["kind"])
        operation = self._operation(frame, kind)
        raw = int(frame.payload["raw"])
        if kind in INT_RETURN_KINDS and not _canonical_int(raw):
            _fail(CP_SPP_TRACE_SEMANTICS_RESULT)
        signed = _signed32(raw) if kind in INT_RETURN_KINDS else _signed64(raw)

        if kind == "exec":
            if signed > 0 or (signed == 0 and not operation.committed):
                _fail(CP_SPP_TRACE_SEMANTICS_RESULT)
            if operation.phase in (10, 11, 12):
                if (
                    operation.committed
                    or operation.exec_passes != 1
                    or signed >= 0
                    or operation.path != self.plan.exec_denials[operation.phase]
                ):
                    _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
                self.control_hits[operation.phase] += 1
            elif operation.phase == 2 and operation.path == self.plan.cold_start and signed == 0:
                if operation.task in self.cold_success_tasks:
                    _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
                self.cold_success_tasks.add(operation.task)
            if signed < 0 and operation.committed:
                task = self._live_task(operation.task)
                if operation.task == self.root:
                    _fail(CP_SPP_TRACE_SEMANTICS_TASK)
                task.doomed = True
            self._close_operation(operation, frame.sequence, raw, bool(operation.committed))
            return

        if kind == "file_open":
            if not operation.policy_rows:
                if not (
                    operation.phase in self.plan.poison_paths
                    and operation.path == self.plan.poison_paths[operation.phase]
                    and signed == -2
                ):
                    _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
                self.control_hits[operation.phase] += 1
            else:
                self._policy_result(operation, raw)
                if operation.phase == 3 and operation.path == self.plan.model_path and signed >= 0:
                    if operation.policy_rows[0]["decision"] != ALLOW:
                        _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
                    self.control_hits[3] += 1
                if operation.phase == 13 and operation.path == self.plan.jit_path and signed >= 0:
                    if operation.policy_rows[0]["decision"] != ALLOW:
                        _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
                    self.control_hits[13] += 1
                    self.jit_stage = 1
            self._close_operation(operation, frame.sequence, raw, None)
            return

        if kind in ("mmap", "mprotect"):
            if not operation.policy_rows or (kind == "mmap" and len(operation.policy_rows) != 1):
                _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
            self._policy_result(operation, raw)
            if operation.phase == 13 and self.jit_object is not None:
                tuples = {row["object"] for row in operation.policy_rows}
                all_allow = all(row["decision"] == ALLOW for row in operation.policy_rows)
                if tuples == {self.jit_object} and signed >= 0 and all_allow:
                    if kind == "mmap" and self.jit_stage == 1:
                        self.jit_stage = 2
                    elif kind == "mprotect" and self.jit_stage == 2:
                        self.jit_stage = 3
                    elif kind in ("mmap", "mprotect"):
                        _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
            self._close_operation(operation, frame.sequence, raw, None)
            return

        if kind in ("connect", "sendmsg"):
            if len(operation.policy_rows) != 1:
                _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)
            if signed >= 0 or (kind == "connect" and signed in (-115, -114)):
                _fail(CP_SPP_TRACE_SEMANTICS_RESULT)
            self._policy_result(operation, raw)
            if operation.phase in self.plan.remote_endpoints:
                self.control_hits[operation.phase] += 1
            self._close_operation(operation, frame.sequence, raw, None)
            return
        _fail(CP_SPP_TRACE_SEMANTICS_OPERATION)

    def _task_exit(self, frame: _Frame) -> None:
        self._control_only(frozenset(), frame.event)
        task = self._live_task(frame.task, allow_doomed=True)
        if frame.task == self.root or task.parent != frame.parent or task.mint_phase != frame.phase:
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        if self.open_by_task.get(frame.task, 0) != 0:
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        exit_code = int(frame.payload["exit_code"])
        if task.doomed and exit_code != 11:
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        task.exit_sequence = frame.sequence
        task.exit_code = exit_code
        task.live = False
        identity = (task.pid, task.tgid)
        if self.live_identities.get(identity) != frame.task:
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        del self.live_identities[identity]
        if frame.task in self.cold_success_tasks:
            if frame.phase != 2 or exit_code != 0:
                _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
            self.control_hits[2] += 1

    def _phase_control_closed(self, phase: int) -> None:
        if phase == 1:
            return
        if phase == 13:
            if self.control_hits[13] != 1 or self.jit_stage != 3:
                _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)
            return
        if self.control_hits.get(phase) != 1:
            _fail(CP_SPP_TRACE_SEMANTICS_CONTROL)

    def _marker(self, frame: _Frame) -> None:
        if self.root is None or frame.task != self.root or self.current_phase is None:
            _fail(CP_SPP_TRACE_SEMANTICS_PHASE)
        if frame.payload != {"previous": self.current_phase, "next": self.current_phase + 1}:
            _fail(CP_SPP_TRACE_SEMANTICS_PHASE)
        if self.current_phase > 13 or self.open_operations:
            _fail(CP_SPP_TRACE_SEMANTICS_PHASE)
        if any(task.live and ordinal != self.root for ordinal, task in self.tasks.items()):
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        self._phase_control_closed(self.current_phase)
        if self.phase_start is None:
            _fail(CP_SPP_TRACE_SEMANTICS_PHASE)
        self.phases.append(
            {
                "control": "closed",
                "first_sequence": self.phase_start,
                "frame_count": frame.sequence - self.phase_start + 1,
                "last_sequence": frame.sequence,
                "name": PHASE_NAMES[self.current_phase - 1],
                "phase": self.current_phase,
            }
        )
        self.current_phase += 1
        self.phase_start = frame.sequence + 1

    def _terminal(self, frame: _Frame) -> None:
        if self.current_phase != 14 or self.root is None or self.open_operations:
            _fail(CP_SPP_TRACE_SEMANTICS_PHASE)
        if any(task.live and ordinal != self.root for ordinal, task in self.tasks.items()):
            _fail(CP_SPP_TRACE_SEMANTICS_TASK)
        if self.phase_start is None or frame.sequence != self.phase_start:
            _fail(CP_SPP_TRACE_SEMANTICS_PHASE)
        self.phases.append(
            {
                "control": "closed",
                "first_sequence": frame.sequence,
                "frame_count": 1,
                "last_sequence": frame.sequence,
                "name": PHASE_NAMES[13],
                "phase": 14,
            }
        )
        self.terminal_seen = True

    def ledger(self, frame_count: int) -> bytes:
        if not self.terminal_seen or self.root is None or len(self.phases) != 14:
            _fail(CP_SPP_TRACE_SEMANTICS_LEDGER)
        tasks = []
        for ordinal in self.task_order:
            task = self.tasks[ordinal]
            if ordinal != self.root and (task.exit_sequence is None or task.exit_code is None):
                _fail(CP_SPP_TRACE_SEMANTICS_TASK)
            tasks.append(
                {
                    "creation_sequence": task.creation_sequence,
                    "exit_code_hex": None if task.exit_code is None else f"{task.exit_code:08x}",
                    "exit_sequence": task.exit_sequence,
                    "mint_phase": task.mint_phase,
                    "parent_task_ordinal": None if task.parent is None else _hex16(task.parent),
                    "pid_hex": f"{task.pid:08x}",
                    "task_ordinal": _hex16(task.ordinal),
                    "tgid_hex": f"{task.tgid:08x}",
                }
            )
        ledger = {
            "external_requirements": [
                "gpu_hardware_witness",
                "measured_object_bindings",
                "synthetic_output_oracle",
            ],
            "frame_count": frame_count,
            "header": self.header,
            "object_bindings": sorted(self.object_bindings, key=lambda row: int(row["sequence"])),
            "operations": sorted(self.closed_operations, key=lambda row: int(row["first_sequence"])),
            "phases": self.phases,
            "root_task_ordinal": _hex16(self.root),
            "schema": "sol-spp-diag-trace-semantic-ledger-v1",
            "status": "trace_semantics_valid",
            "stream_byte_count": self.stream_length,
            "tasks": tasks,
        }
        return canonical_dumps(ledger)


def _header(stream: bytes, plan: _Plan) -> tuple[dict[str, object], int]:
    if len(stream) < 196 or struct.unpack_from(">I", stream)[0] != HEADER_BYTES:
        _fail(CP_SPP_TRACE_SEMANTICS_HEADER)
    header = stream[4:196]
    if header[:8] != b"SPPTRC1\0":
        _fail(CP_SPP_TRACE_SEMANTICS_HEADER)
    wire, length, policy, hash_algorithm = struct.unpack_from(">HHHH", header, 8)
    max_frames = struct.unpack_from(">I", header, 16)[0]
    max_stream = struct.unpack_from(">Q", header, 20)[0]
    max_frame = struct.unpack_from(">I", header, 28)[0]
    required_hook_mask = struct.unpack_from(">Q", header, 180)[0]
    reserved = struct.unpack_from(">I", header, 188)[0]
    if (
        wire != 1
        or length != HEADER_BYTES
        or policy != 2
        or hash_algorithm != 1
        or max_frames != MAX_FRAMES
        or max_stream != MAX_STREAM_BYTES
        or max_frame != MAX_FRAME_BYTES
        or header[32:52] != SOURCE_COMMIT
        or header[116:148] != plan.address
        or required_hook_mask != 0xFFFF
        or reserved != 0
    ):
        _fail(CP_SPP_TRACE_SEMANTICS_HEADER)
    row = {
        "challenge": header[52:84].hex(),
        "command_line_sha256": header[148:180].hex(),
        "control_plan_address": header[116:148].hex(),
        "policy_version": policy,
        "required_hook_mask": f"{required_hook_mask:016x}",
        "run_identity": header[84:116].hex(),
        "source_commit": header[32:52].hex(),
        "wire_version": wire,
    }
    return row, 196


def _appraise(control_plan_bytes: bytes, stream_bytes: bytes) -> bytes:
    if len(control_plan_bytes) > MAX_PLAN_BYTES or len(stream_bytes) > MAX_STREAM_BYTES:
        _fail(CP_SPP_TRACE_SEMANTICS_CAP)
    plan = _parse_plan(control_plan_bytes)
    header, offset = _header(stream_bytes, plan)
    reducer = _Reducer(plan, header, len(stream_bytes))
    frame_count = 0
    while offset < len(stream_bytes):
        if frame_count == MAX_FRAMES:
            _fail(CP_SPP_TRACE_SEMANTICS_CAP)
        if len(stream_bytes) - offset < 4:
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        frame_length = struct.unpack_from(">I", stream_bytes, offset)[0]
        if frame_length > MAX_FRAME_BYTES:
            _fail(CP_SPP_TRACE_SEMANTICS_CAP)
        end = offset + 4 + frame_length
        if end > len(stream_bytes):
            _fail(CP_SPP_TRACE_SEMANTICS_FRAME)
        frame = _decode_frame(stream_bytes[offset + 4 : end], frame_count)
        reducer.consume(frame, end == len(stream_bytes))
        frame_count += 1
        offset = end
    if frame_count == 0:
        _fail(CP_SPP_TRACE_SEMANTICS_LIFECYCLE)
    return reducer.ledger(frame_count)


def _raise_public(reason: str) -> NoReturn:
    raise TraceSemanticsError(reason) from None


def appraise_spp_diag_trace_semantics(control_plan_bytes: bytes, stream_bytes: bytes) -> bytes:
    """Return a canonical trace-semantic ledger or one stable public reason."""

    reason: str | None = None
    result: bytes | None = None
    if type(control_plan_bytes) is not bytes or type(stream_bytes) is not bytes:
        reason = CP_SPP_TRACE_SEMANTICS_TYPE
    else:
        try:
            result = _appraise(control_plan_bytes, stream_bytes)
        except TraceSemanticsError as internal_error:
            reason = internal_error.reason_code
            internal_error.__traceback__ = None
            internal_error.__context__ = None
            internal_error.__cause__ = None
        except Exception as internal_error:
            reason = CP_SPP_TRACE_SEMANTICS_PRIVACY
            internal_error.__traceback__ = None
            internal_error.__context__ = None
            internal_error.__cause__ = None
    if reason is None and result is None:
        reason = CP_SPP_TRACE_SEMANTICS_PRIVACY
    if reason is not None:
        del control_plan_bytes
        del stream_bytes
        _raise_public(reason)
    assert result is not None
    return result
