#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent metamorphic positives for SPP trace semantics.

This oracle imports only the caller-frozen literal fixture. It never imports
the production semantic appraiser or any product wire codec.
"""

from __future__ import annotations

import copy
import json
import struct
from dataclasses import dataclass

from conf_proc_spp_diag_trace_semantic_fixture import (
    CONTROL_PLAN_HEX,
    EXPECTED_LEDGER_HEX,
    STREAM_HEX,
)


FILE_OPEN_ATTEMPT = 0x0100
FILE_POLICY_DECISION = 0x0101
EXEC_MAPPING_POLICY_DECISION = 0x0102
NETWORK_POLICY_DECISION = 0x0103
OPERATION_RETURN = 0x0104
TASK_EXIT = 0x0105
EXEC_ATTEMPT = 5
EXEC_COMMIT = 6
TASK_ALLOC_ATTEMPT = 7
TASK_CREATED = 8


@dataclass(frozen=True)
class PositiveVector:
    name: str
    control_plan: bytes
    stream: bytes
    expected_ledger: bytes


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entries(stream: bytes) -> list[bytes]:
    assert struct.unpack_from(">I", stream)[0] == 192
    offset = 196
    result = []
    while offset < len(stream):
        length = struct.unpack_from(">I", stream, offset)[0]
        end = offset + 4 + length
        assert end <= len(stream)
        result.append(stream[offset:end])
        offset = end
    assert offset == len(stream)
    return result


BASE_PLAN = bytes.fromhex(CONTROL_PLAN_HEX)
BASE_STREAM = bytes.fromhex(STREAM_HEX)
BASE_HEADER = BASE_STREAM[:196]
BASE_ENTRIES = _entries(BASE_STREAM)
BASE_LEDGER = json.loads(bytes.fromhex(EXPECTED_LEDGER_HEX))


def _event(entry: bytes) -> int:
    return struct.unpack_from(">H", entry, 4)[0]


def _set(entry: bytes, fmt: str, offset: int, value: int) -> bytes:
    mutable = bytearray(entry)
    struct.pack_into(fmt, mutable, offset, value)
    return bytes(mutable)


def _resequence(entries: list[bytes]) -> list[bytes]:
    return [_set(entry, ">Q", 12, sequence) for sequence, entry in enumerate(entries)]


def _stream(entries: list[bytes]) -> bytes:
    return BASE_HEADER + b"".join(_resequence(entries))


def _shift_value(value: object, pivot: int, delta: int, inclusive: bool) -> object:
    if type(value) is not int:
        return value
    if value > pivot or (inclusive and value == pivot):
        return value + delta
    return value


def _shift_ledger(ledger: dict[str, object], pivot: int, delta: int, *, inclusive: bool) -> None:
    for operation in ledger["operations"]:
        operation["first_sequence"] = _shift_value(operation["first_sequence"], pivot, delta, inclusive)
        operation["last_sequence"] = _shift_value(operation["last_sequence"], pivot, delta, inclusive)
    for task in ledger["tasks"]:
        task["creation_sequence"] = _shift_value(task["creation_sequence"], pivot, delta, inclusive)
        task["exit_sequence"] = _shift_value(task["exit_sequence"], pivot, delta, inclusive)
    for phase in ledger["phases"]:
        phase["first_sequence"] = _shift_value(phase["first_sequence"], pivot, delta, inclusive)
        phase["last_sequence"] = _shift_value(phase["last_sequence"], pivot, delta, inclusive)
    for row in ledger["object_bindings"]:
        row["sequence"] = _shift_value(row["sequence"], pivot, delta, inclusive)


def _finish(name: str, entries: list[bytes], ledger: dict[str, object]) -> PositiveVector:
    stream = _stream(entries)
    ledger["frame_count"] = len(entries)
    ledger["stream_byte_count"] = len(stream)
    expected = _canonical(ledger)
    assert stream != BASE_STREAM
    assert expected != bytes.fromhex(EXPECTED_LEDGER_HEX)
    return PositiveVector(name, BASE_PLAN, stream, expected)


def _renumbered() -> PositiveVector:
    task_map = {1: 0x101, 2: 0x202, 3: 0x303, 4: 0x404}
    operation_map = {value: 0x1000 + value for value in range(1, 22)}
    pid_map = {1001: 11001, 2002: 12002, 3003: 13003, 4004: 14004}
    entries = []
    for entry in BASE_ENTRIES:
        mutable = bytearray(entry)
        for offset in (20, 28):
            value = struct.unpack_from(">Q", mutable, offset)[0]
            if value:
                struct.pack_into(">Q", mutable, offset, task_map[value])
        operation = struct.unpack_from(">Q", mutable, 36)[0]
        if operation:
            struct.pack_into(">Q", mutable, 36, operation_map[operation])
        event = _event(entry)
        pid_offsets: tuple[int, ...] = ()
        if event == 2:
            pid_offsets = (52, 56)
        elif event == 4:
            pid_offsets = (48, 52)
        elif event == EXEC_ATTEMPT:
            pid_offsets = (56, 60)
        elif event == EXEC_COMMIT:
            pid_offsets = (52, 56)
        elif event == TASK_CREATED:
            pid_offsets = (48, 52)
        for offset in pid_offsets:
            value = struct.unpack_from(">I", mutable, offset)[0]
            struct.pack_into(">I", mutable, offset, pid_map[value])
        entries.append(bytes(mutable))

    ledger = copy.deepcopy(BASE_LEDGER)
    ledger["root_task_ordinal"] = f"{task_map[1]:016x}"
    for operation in ledger["operations"]:
        old_operation = int(operation["operation_ordinal"], 16)
        operation["operation_ordinal"] = f"{operation_map[old_operation]:016x}"
        if operation["task_ordinal"] is not None:
            old_task = int(operation["task_ordinal"], 16)
            operation["task_ordinal"] = f"{task_map[old_task]:016x}"
    for task in ledger["tasks"]:
        old_task = int(task["task_ordinal"], 16)
        task["task_ordinal"] = f"{task_map[old_task]:016x}"
        task["pid_hex"] = f"{pid_map[int(task['pid_hex'], 16)]:08x}"
        task["tgid_hex"] = f"{pid_map[int(task['tgid_hex'], 16)]:08x}"
        if task["parent_task_ordinal"] is not None:
            old_parent = int(task["parent_task_ordinal"], 16)
            task["parent_task_ordinal"] = f"{task_map[old_parent]:016x}"
    for row in ledger["object_bindings"]:
        old_operation = int(row["operation_ordinal"], 16)
        row["operation_ordinal"] = f"{operation_map[old_operation]:016x}"
    return _finish("coherent_identifier_renumbering", entries, ledger)


def _exec_pass_count(count: int) -> PositiveVector:
    entries = list(BASE_ENTRIES)
    ledger = copy.deepcopy(BASE_LEDGER)
    operation = next(row for row in ledger["operations"] if row["operation_ordinal"] == "0000000000000003")
    phase = ledger["phases"][1]
    if count == 1:
        del entries[8]
        entries[8] = _set(entries[8], ">I", 48, 1)
        _shift_ledger(ledger, 8, -1, inclusive=False)
        phase["frame_count"] -= 1
    elif count == 2:
        raise AssertionError("base vector is already the two-pass case")
    elif count == 3:
        third = _set(entries[8], ">I", 48, 3)
        entries.insert(9, third)
        entries[10] = _set(entries[10], ">I", 48, 3)
        _shift_ledger(ledger, 9, 1, inclusive=True)
        phase["frame_count"] += 1
    else:
        raise AssertionError(count)
    operation["last_sequence"] = 8 + count
    return _finish(f"cold_exec_pass_count_{count}", entries, ledger)


def _mprotect_policy_count(count: int) -> PositiveVector:
    entries = list(BASE_ENTRIES)
    ledger = copy.deepcopy(BASE_LEDGER)
    operation = next(row for row in ledger["operations"] if row["operation_ordinal"] == "0000000000000015")
    phase = ledger["phases"][12]
    if count == 1:
        del entries[64]
        ledger["object_bindings"] = [row for row in ledger["object_bindings"] if row["sequence"] != 64]
        _shift_ledger(ledger, 64, -1, inclusive=False)
        phase["frame_count"] -= 1
    elif count == 2:
        raise AssertionError("base vector is already the two-policy case")
    elif count == 3:
        entries.insert(65, entries[64])
        _shift_ledger(ledger, 65, 1, inclusive=True)
        extra = copy.deepcopy(next(row for row in ledger["object_bindings"] if row["sequence"] == 64))
        extra["sequence"] = 65
        ledger["object_bindings"].append(extra)
        ledger["object_bindings"].sort(key=lambda row: row["sequence"])
        phase["frame_count"] += 1
    else:
        raise AssertionError(count)
    operation["policy_count"] = count
    operation["last_sequence"] = 63 + count
    return _finish(f"mprotect_policy_count_{count}", entries, ledger)


def _later_failure_becomes_success() -> PositiveVector:
    entries = list(BASE_ENTRIES)
    entries[22] = _set(entries[22], ">Q", 56, 9)
    ledger = copy.deepcopy(BASE_LEDGER)
    operation = next(row for row in ledger["operations"] if row["operation_ordinal"] == "0000000000000007")
    operation["final_raw_hex"] = "0000000000000009"
    return _finish("allow_then_later_success", entries, ledger)


def _frame(event: int, task: int, parent: int, operation: int, phase: int, payload: bytes) -> bytes:
    body = struct.pack(">HHIQQQQHH", event, 0, len(payload), 0, task, parent, operation, phase, 0) + payload
    return struct.pack(">I", len(body)) + body


def _file_attempt(path: bytes) -> bytes:
    return struct.pack(">HHHHII", 1, len(path), 1, 0x10, 0xFFFFFF9C, 0) + path


def _file_policy(object_tuple: tuple[int, int, int, int, int, int]) -> bytes:
    return struct.pack(">HHHHIIIIQQQ", 1, 0x10, 1, 1, 0, *object_tuple)


def _mapping_policy(object_tuple: tuple[int, int, int, int, int, int]) -> bytes:
    fs_magic, dev_major, dev_minor, inode, mount, size = object_tuple
    return struct.pack(
        ">HHHHIIIIIIIIQQQ", 1, 1, 2, 2, 5, 5, 0, 0, fs_magic, dev_major, dev_minor, 0, inode, mount, size
    )


def _network_policy(*, operation: int = 1, result: int = -13) -> bytes:
    socket_kind = 1 if operation == 1 else 2
    protocol = 6 if operation == 1 else 17
    size = 0 if operation == 1 else 1
    return struct.pack(
        ">HHHHHHHHIIIQHHII16s",
        operation,
        2,
        1,
        1,
        socket_kind,
        protocol,
        2,
        16,
        result & 0xFFFFFFFF,
        0,
        size,
        0xD00D,
        443,
        0,
        0,
        0,
        bytes(12) + bytes([192, 0, 2, 44]),
    )


def _return(kind: int, raw: int) -> bytes:
    return struct.pack(">HHIQ", kind, 0, 0, raw & 0xFFFFFFFFFFFFFFFF)


def _operation_row(
    operation: int,
    kind: str,
    phase: int,
    task: int,
    first: int,
    last: int,
    final: int | None,
    policy_count: int,
    committed: bool | None = None,
) -> dict[str, object]:
    return {
        "committed": committed,
        "final_raw_hex": None if final is None else f"{final & 0xffffffffffffffff:016x}",
        "first_sequence": first,
        "kind": kind,
        "last_sequence": last,
        "operation_ordinal": f"{operation:016x}",
        "phase": phase,
        "policy_count": policy_count,
        "task_ordinal": f"{task:016x}",
    }


def _object_row(
    sequence: int,
    operation: int,
    phase: int,
    object_tuple: tuple[int, int, int, int, int, int],
) -> dict[str, object]:
    fs_magic, dev_major, dev_minor, inode, mount, size = object_tuple
    return {
        "dev_major_hex": f"{dev_major:08x}",
        "dev_minor_hex": f"{dev_minor:08x}",
        "expected_sha256": None,
        "fs_magic_hex": f"{fs_magic:08x}",
        "inode_hex": f"{inode:016x}",
        "mount_identity_hex": f"{mount:016x}",
        "observed_size_hex": f"{size:016x}",
        "operation_ordinal": f"{operation:016x}",
        "phase": phase,
        "role": "ordinary_measured_object",
        "sequence": sequence,
    }


def _added_operation(phase: int, family: str) -> PositiveVector:
    ledger = copy.deepcopy(BASE_LEDGER)
    entries = list(BASE_ENTRIES)
    insertion = int(ledger["phases"][phase - 1]["last_sequence"])
    original_phase_first = int(ledger["phases"][phase - 1]["first_sequence"])
    operation = 0x5000 + phase * 0x10 + {"file": 1, "mapping": 2, "network": 3, "postcommit_exec": 4}[family]
    task = 1
    object_tuple = (0xEF53, 0x101, phase, 0x9000 + operation, 0xE0 + phase, 0x4000 + phase)
    added_entries: list[bytes]
    added_operations: list[dict[str, object]]
    added_objects: list[dict[str, object]] = []
    added_task: dict[str, object] | None = None
    if family == "file":
        path = f"/tmp/spp-extra-file-{phase}".encode("ascii")
        added_entries = [
            _frame(FILE_OPEN_ATTEMPT, task, 0, operation, phase, _file_attempt(path)),
            _frame(FILE_POLICY_DECISION, task, 0, operation, phase, _file_policy(object_tuple)),
            _frame(OPERATION_RETURN, task, 0, operation, phase, _return(1, 9)),
        ]
        added_operations = [_operation_row(operation, "file_open", phase, task, insertion, insertion + 2, 9, 1)]
        added_objects = [_object_row(insertion + 1, operation, phase, object_tuple)]
    elif family == "mapping":
        added_entries = [
            _frame(EXEC_MAPPING_POLICY_DECISION, task, 0, operation, phase, _mapping_policy(object_tuple)),
            _frame(OPERATION_RETURN, task, 0, operation, phase, _return(2, 0x73000000 + phase * 0x1000)),
        ]
        added_operations = [
            _operation_row(operation, "mmap", phase, task, insertion, insertion + 1, 0x73000000 + phase * 0x1000, 1)
        ]
        added_objects = [_object_row(insertion, operation, phase, object_tuple)]
    elif family == "network":
        added_entries = [
            _frame(NETWORK_POLICY_DECISION, task, 0, operation, phase, _network_policy()),
            _frame(OPERATION_RETURN, task, 0, operation, phase, _return(4, -13)),
        ]
        added_operations = [_operation_row(operation, "connect", phase, task, insertion, insertion + 1, -13, 1)]
    elif family == "postcommit_exec":
        child = 0x6000 + phase
        child_pid = 20_000 + phase
        alloc_operation = operation
        exec_operation = operation + 0x100
        path = f"/tmp/spp-extra-postcommit-{phase}".encode("ascii")
        added_entries = [
            _frame(TASK_ALLOC_ATTEMPT, child, task, alloc_operation, phase, struct.pack(">Q", 0x11)),
            _frame(TASK_CREATED, child, task, alloc_operation, phase, struct.pack(">IIQ", child_pid, child_pid, 0x11)),
            _frame(
                EXEC_ATTEMPT,
                child,
                0,
                exec_operation,
                phase,
                struct.pack(">IHHII", 1, len(path), 0, child_pid, child_pid) + path,
            ),
            _frame(EXEC_COMMIT, child, 0, exec_operation, phase, struct.pack(">IIII", 1, child_pid, child_pid, 0)),
            _frame(OPERATION_RETURN, child, 0, exec_operation, phase, _return(6, -8)),
            _frame(TASK_EXIT, child, task, 0, phase, struct.pack(">II", 11, 0)),
        ]
        added_operations = [
            _operation_row(alloc_operation, "task_alloc", phase, child, insertion, insertion + 1, None, 0),
            _operation_row(exec_operation, "exec", phase, child, insertion + 2, insertion + 4, -8, 0, True),
        ]
        added_task = {
            "creation_sequence": insertion + 1,
            "exit_code_hex": "0000000b",
            "exit_sequence": insertion + 5,
            "mint_phase": phase,
            "parent_task_ordinal": "0000000000000001",
            "pid_hex": f"{child_pid:08x}",
            "task_ordinal": f"{child:016x}",
            "tgid_hex": f"{child_pid:08x}",
        }
    else:
        raise AssertionError(family)

    delta = len(added_entries)
    _shift_ledger(ledger, insertion, delta, inclusive=True)
    ledger["phases"][phase - 1]["first_sequence"] = min(original_phase_first, insertion)
    ledger["phases"][phase - 1]["frame_count"] += delta
    ledger["operations"].extend(added_operations)
    ledger["operations"].sort(key=lambda row: row["first_sequence"])
    ledger["object_bindings"].extend(added_objects)
    ledger["object_bindings"].sort(key=lambda row: row["sequence"])
    if added_task is not None:
        ledger["tasks"].append(added_task)
        ledger["tasks"] = [ledger["tasks"][0]] + sorted(
            ledger["tasks"][1:], key=lambda row: row["creation_sequence"]
        )
    entries[insertion:insertion] = added_entries
    return _finish(f"ordinary_{family}_phase_{phase}", entries, ledger)


def _sendmsg_async_result() -> PositiveVector:
    ledger = copy.deepcopy(BASE_LEDGER)
    entries = list(BASE_ENTRIES)
    phase = 1
    insertion = int(ledger["phases"][0]["last_sequence"])
    original_phase_first = int(ledger["phases"][0]["first_sequence"])
    operation = 0x5A01
    added_entries = [
        _frame(
            NETWORK_POLICY_DECISION,
            1,
            0,
            operation,
            phase,
            _network_policy(operation=2, result=-115),
        ),
        _frame(OPERATION_RETURN, 1, 0, operation, phase, _return(5, -115)),
    ]
    _shift_ledger(ledger, insertion, len(added_entries), inclusive=True)
    ledger["phases"][0]["first_sequence"] = min(original_phase_first, insertion)
    ledger["phases"][0]["frame_count"] += len(added_entries)
    ledger["operations"].append(
        _operation_row(operation, "sendmsg", phase, 1, insertion, insertion + 1, -115, 1)
    )
    ledger["operations"].sort(key=lambda row: row["first_sequence"])
    entries[insertion:insertion] = added_entries
    return _finish("sendmsg_async_result_phase_1", entries, ledger)


def accepted_vectors() -> tuple[PositiveVector, ...]:
    vectors = [
        _renumbered(),
        _exec_pass_count(1),
        _exec_pass_count(3),
        _mprotect_policy_count(1),
        _mprotect_policy_count(3),
        _later_failure_becomes_success(),
        _sendmsg_async_result(),
    ]
    for phase in (1, 2, 3, 13):
        for family in ("file", "mapping", "network", "postcommit_exec"):
            vectors.append(_added_operation(phase, family))
    return tuple(vectors)
