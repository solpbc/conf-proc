#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Production tests for independent SPP trace-semantic appraisal."""

from __future__ import annotations

import ast
import copy
import json
import struct
from pathlib import Path

import conf_proc_spp_diag_trace_semantics as production
from conf_proc_spp_diag_trace_semantic_fixture import (
    CONTROL_PLAN_HEX,
    EXPECTED_LEDGER_HEX,
    STREAM_HEX,
)
from conf_proc_spp_diag_trace_semantic_reasons import (
    ALL_SPP_TRACE_SEMANTIC_REASONS,
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
from conf_proc_spp_diag_trace_semantics_oracle import (
    BASE_ENTRIES,
    BASE_HEADER,
    accepted_vectors,
)


PLAN = bytes.fromhex(CONTROL_PLAN_HEX)
STREAM = bytes.fromhex(STREAM_HEX)
LEDGER = bytes.fromhex(EXPECTED_LEDGER_HEX)


def make_stream(entries: list[bytes], *, resequence: bool = True) -> bytes:
    result = []
    for sequence, entry in enumerate(entries):
        mutable = bytearray(entry)
        if resequence:
            struct.pack_into(">Q", mutable, 12, sequence)
        result.append(bytes(mutable))
    return BASE_HEADER + b"".join(result)


def set_field(entry: bytes, fmt: str, offset: int, value: int) -> bytes:
    mutable = bytearray(entry)
    struct.pack_into(fmt, mutable, offset, value)
    return bytes(mutable)


def flip(entry: bytes, offset: int) -> bytes:
    mutable = bytearray(entry)
    mutable[offset] ^= 1
    return bytes(mutable)


def expect_reason(
    name: str,
    reason: str,
    *,
    plan: object = PLAN,
    stream: object = STREAM,
) -> None:
    try:
        production.appraise_spp_diag_trace_semantics(plan, stream)  # type: ignore[arg-type]
    except TraceSemanticsError as error:
        assert error.reason_code == reason, (name, error.reason_code, reason)
        assert str(error) == reason and repr(error).find(reason) >= 0
        assert error.__cause__ is None
        return
    raise AssertionError(f"{name}: accepted")


def expect_red(name: str, entries: list[bytes]) -> None:
    try:
        production.appraise_spp_diag_trace_semantics(PLAN, make_stream(entries))
    except TraceSemanticsError as error:
        assert error.reason_code in ALL_SPP_TRACE_SEMANTIC_REASONS, name
        return
    raise AssertionError(f"{name}: accepted")


def test_frozen_and_accepted_positives() -> None:
    plan_before = bytes(PLAN)
    stream_before = bytes(STREAM)
    first = production.appraise_spp_diag_trace_semantics(PLAN, STREAM)
    second = production.appraise_spp_diag_trace_semantics(PLAN, STREAM)
    assert first == LEDGER == second
    assert PLAN == plan_before and STREAM == stream_before
    for vector in accepted_vectors():
        vector_plan = bytes(vector.control_plan)
        vector_stream = bytes(vector.stream)
        assert production.appraise_spp_diag_trace_semantics(
            vector.control_plan, vector.stream
        ) == vector.expected_ledger, vector.name
        assert vector.control_plan == vector_plan and vector.stream == vector_stream


def test_independence_and_types() -> None:
    source = Path("conf_proc_spp_diag_trace_semantics.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert "conf_proc_spp_diag_trace_chain" not in imported
    assert "conf_proc_spp_diag_trace_checkpoints" not in imported
    assert "conf_proc_spp_diag_trace_semantic_fixture" not in imported
    expect_reason("null_plan", CP_SPP_TRACE_SEMANTICS_TYPE, plan=None)
    expect_reason("null_stream", CP_SPP_TRACE_SEMANTICS_TYPE, stream=None)
    expect_reason("bytearray_plan", CP_SPP_TRACE_SEMANTICS_TYPE, plan=bytearray(PLAN))
    expect_reason("memoryview_stream", CP_SPP_TRACE_SEMANTICS_TYPE, stream=memoryview(STREAM))


def test_plan_header_frame_and_sequence() -> None:
    expect_reason("invalid_plan", CP_SPP_TRACE_SEMANTICS_PLAN, plan=b"secret-not-json")
    plan = json.loads(PLAN)
    plan["schema"] = "sol-spp-diag-trace-control-plan-v2"
    bad_plan = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    expect_reason("wrong_plan_schema", CP_SPP_TRACE_SEMANTICS_PLAN, plan=bad_plan)
    plan = json.loads(PLAN)
    plan["extra"] = 1
    bad_plan = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    expect_reason("extra_plan_key", CP_SPP_TRACE_SEMANTICS_PLAN, plan=bad_plan)
    expect_reason("short_stream", CP_SPP_TRACE_SEMANTICS_HEADER, stream=STREAM[:195])
    expect_reason("plan_cap", CP_SPP_TRACE_SEMANTICS_CAP, plan=b"x" * 131_073)
    header = bytearray(STREAM)
    header[120] ^= 1
    expect_reason("plan_address_mismatch", CP_SPP_TRACE_SEMANTICS_HEADER, stream=bytes(header))
    entries = list(BASE_ENTRIES)
    entries[0] = set_field(entries[0], ">H", 4, 0)
    expect_reason("unknown_event", CP_SPP_TRACE_SEMANTICS_FRAME, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    entries[10] = set_field(entries[10], ">Q", 12, 99)
    expect_reason(
        "sequence_gap",
        CP_SPP_TRACE_SEMANTICS_SEQUENCE,
        stream=make_stream(entries, resequence=False),
    )
    oversized = bytearray(STREAM)
    struct.pack_into(">I", oversized, 196, 1089)
    expect_reason("frame_cap", CP_SPP_TRACE_SEMANTICS_CAP, stream=bytes(oversized))


def test_lifecycle_task_and_operation_rejections() -> None:
    expect_reason(
        "missing_core",
        CP_SPP_TRACE_SEMANTICS_LIFECYCLE,
        stream=make_stream(list(BASE_ENTRIES[1:])),
    )
    entries = list(BASE_ENTRIES)
    entries[2], entries[3] = entries[3], entries[2]
    expect_reason("release_before_ima", CP_SPP_TRACE_SEMANTICS_LIFECYCLE, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    entries.append(entries[0])
    expect_reason("event_after_terminal", CP_SPP_TRACE_SEMANTICS_LIFECYCLE, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    entries[5], entries[6] = entries[6], entries[5]
    expect_reason("creation_before_alloc", CP_SPP_TRACE_SEMANTICS_OPERATION, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    entries.insert(11, entries[10])
    expect_reason("return_after_close", CP_SPP_TRACE_SEMANTICS_OPERATION, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    del entries[11]
    expect_reason("missing_child_exit", CP_SPP_TRACE_SEMANTICS_TASK, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    exit_frame = entries.pop(11)
    entries.insert(12, exit_frame)
    expect_reason("child_crosses_marker", CP_SPP_TRACE_SEMANTICS_TASK, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    entries[12] = set_field(entries[12], ">Q", 20, 2)
    expect_reason("nonroot_marker", CP_SPP_TRACE_SEMANTICS_PHASE, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    entries[34] = set_field(entries[34], ">Q", 36, 10)
    expect_reason("operation_reuse", CP_SPP_TRACE_SEMANTICS_OPERATION, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    entries[8] = set_field(entries[8], ">I", 48, 3)
    expect_reason("exec_pass_gap", CP_SPP_TRACE_SEMANTICS_OPERATION, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    entries[9] = set_field(entries[9], ">I", 48, 1)
    expect_reason("commit_count", CP_SPP_TRACE_SEMANTICS_OPERATION, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    second_attempt = set_field(entries[7], ">Q", 36, 0x1000)
    second_commit = set_field(entries[9], ">Q", 36, 0x1000)
    second_commit = set_field(second_commit, ">I", 48, 1)
    second_return = set_field(entries[10], ">Q", 36, 0x1000)
    entries[11:11] = [second_attempt, second_commit, second_return]
    expect_reason(
        "second_cold_success_same_task",
        CP_SPP_TRACE_SEMANTICS_CONTROL,
        stream=make_stream(entries),
    )
    entries = list(BASE_ENTRIES)
    del entries[9]
    expect_reason("zero_exec_without_commit", CP_SPP_TRACE_SEMANTICS_RESULT, stream=make_stream(entries))
    first_by_event: dict[int, int] = {}
    for index, entry in enumerate(BASE_ENTRIES):
        first_by_event.setdefault(struct.unpack_from(">H", entry, 4)[0], index)
    assert len(first_by_event) == 16
    for event, index in first_by_event.items():
        entries = list(BASE_ENTRIES)
        entries.insert(index + 1, entries[index])
        expect_red(f"duplicate_event_family_{event:04x}", entries)


def test_fatal_child_rejections() -> None:
    base = next(vector for vector in accepted_vectors() if vector.name == "ordinary_postcommit_exec_phase_1")
    entries = []
    offset = 196
    while offset < len(base.stream):
        length = struct.unpack_from(">I", base.stream, offset)[0]
        entries.append(base.stream[offset : offset + 4 + length])
        offset += 4 + length
    # Inserted phase-1 frames occupy 4..9: alloc/create/attempt/commit/return/exit.
    wrong_exit = list(entries)
    wrong_exit[9] = set_field(wrong_exit[9], ">I", 48, 0)
    expect_red("doomed_zero_exit", wrong_exit)
    missing_exit = list(entries)
    del missing_exit[9]
    expect_red("doomed_missing_exit", missing_exit)
    marker_before_exit = list(entries)
    marker_before_exit[9], marker_before_exit[10] = marker_before_exit[10], marker_before_exit[9]
    expect_red("marker_before_fatal_exit", marker_before_exit)
    continuation = list(entries)
    continued = bytearray(BASE_ENTRIES[31])
    struct.pack_into(">Q", continued, 20, 0x6001)
    struct.pack_into(">Q", continued, 36, 0x7FFF)
    struct.pack_into(">H", continued, 44, 1)
    continuation.insert(9, bytes(continued))
    expect_red("doomed_task_continues", continuation)
    root_owned = list(entries)
    for index in (6, 7, 8):
        root_owned[index] = set_field(root_owned[index], ">Q", 20, 1)
    root_owned[6] = set_field(root_owned[6], ">I", 56, 1001)
    root_owned[6] = set_field(root_owned[6], ">I", 60, 1001)
    root_owned[7] = set_field(root_owned[7], ">I", 52, 1001)
    root_owned[7] = set_field(root_owned[7], ">I", 56, 1001)
    expect_reason(
        "root_committed_negative",
        CP_SPP_TRACE_SEMANTICS_TASK,
        stream=make_stream(root_owned),
    )


def test_reducer_and_control_rejections() -> None:
    ranges = {
        2: range(7, 11),
        3: range(15, 18),
        4: range(31, 33),
        5: range(34, 36),
        6: range(37, 39),
        7: range(40, 42),
        8: range(43, 45),
        9: range(46, 48),
        10: range(49, 51),
        11: range(52, 54),
        12: range(55, 57),
        13: range(58, 66),
    }
    for phase, removed in ranges.items():
        entries = [entry for index, entry in enumerate(BASE_ENTRIES) if index not in removed]
        expect_reason(
            f"missing_phase_{phase}_control",
            CP_SPP_TRACE_SEMANTICS_CONTROL,
            stream=make_stream(entries),
        )

    entries = list(BASE_ENTRIES)
    del entries[16]
    expect_reason("model_policy_missing", CP_SPP_TRACE_SEMANTICS_OPERATION, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    entries.insert(19, entries[18])
    expect_reason("mmap_second_policy", CP_SPP_TRACE_SEMANTICS_OPERATION, stream=make_stream(entries))
    entries = [entry for index, entry in enumerate(BASE_ENTRIES) if index not in (63, 64)]
    expect_reason("mprotect_no_policy", CP_SPP_TRACE_SEMANTICS_OPERATION, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    first = bytearray(entries[63])
    struct.pack_into(">H", first, 50, 2)
    struct.pack_into(">I", first, 68, 0xFFFFFFF3)
    entries[63] = bytes(first)
    expect_reason("mprotect_row_after_deny", CP_SPP_TRACE_SEMANTICS_OPERATION, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    entries[41] = set_field(entries[41], ">Q", 56, -1 & 0xFFFFFFFFFFFFFFFF)
    expect_reason("deny_not_propagated", CP_SPP_TRACE_SEMANTICS_RESULT, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    entries[40] = set_field(entries[40], ">I", 64, 0xFFFFFF8D)
    entries[41] = set_field(entries[41], ">Q", 56, -115 & 0xFFFFFFFFFFFFFFFF)
    expect_reason("connect_in_progress", CP_SPP_TRACE_SEMANTICS_RESULT, stream=make_stream(entries))
    entries = list(BASE_ENTRIES)
    second_pass = set_field(entries[49], ">I", 48, 2)
    entries.insert(50, second_pass)
    expect_reason(
        "denial_exec_second_pass",
        CP_SPP_TRACE_SEMANTICS_CONTROL,
        stream=make_stream(entries),
    )
    entries = list(BASE_ENTRIES)
    entries[50] = set_field(entries[50], ">Q", 56, 0x00000000FFFFFFF3)
    expect_reason("exec_noncanonical_int", CP_SPP_TRACE_SEMANTICS_RESULT, stream=make_stream(entries))


def test_context_and_object_near_misses() -> None:
    for name, index, offset, fmt, value in (
        ("relative_path", 15, 64, ">B", ord("x")),
        ("wrong_dirfd", 15, 56, ">I", 0xFFFFFF9B),
        ("wrong_access", 15, 52, ">H", 2),
        ("wrong_modifier", 15, 54, ">H", 0),
        ("wrong_socket_kind", 40, 56, ">H", 2),
        ("wrong_protocol", 40, 58, ">H", 17),
        ("wrong_source", 40, 54, ">H", 2),
        ("wrong_family", 40, 60, ">H", 10),
        ("wrong_port", 40, 84, ">H", 444),
        ("wrong_scope", 40, 88, ">I", 1),
        ("wrong_flow", 40, 92, ">I", 1),
        ("wrong_flags", 40, 68, ">I", 1),
        ("wrong_size", 40, 72, ">I", 1),
    ):
        entries = list(BASE_ENTRIES)
        entries[index] = set_field(entries[index], fmt, offset, value)
        expect_red(name, entries)
    entries = list(BASE_ENTRIES)
    entries[61] = set_field(entries[61], ">Q", 88, 0x3333)
    expect_red("jit_object_relation", entries)


def test_privacy_translation() -> None:
    secret = "CALLER_SECRET_MUST_NOT_ESCAPE"
    original = production.canonical_dumps

    def assert_sanitized(error: TraceSemanticsError) -> None:
        assert error.__cause__ is None
        assert error.__context__ is None
        assert error.__suppress_context__
        traceback = error.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if frame.f_globals.get("__name__") == production.__name__:
                assert frame.f_code.co_name not in {"_appraise", "canonical_dumps"}
                assert all(value is not PLAN and value is not STREAM for value in frame.f_locals.values())
                assert all(secret not in repr(value) for value in frame.f_locals.values())
            traceback = traceback.tb_next

    def explode(_value: object) -> bytes:
        raise RuntimeError(secret)

    production.canonical_dumps = explode
    try:
        try:
            production.appraise_spp_diag_trace_semantics(PLAN, STREAM)
        except TraceSemanticsError as error:
            assert error.reason_code == CP_SPP_TRACE_SEMANTICS_PRIVACY
            assert_sanitized(error)
        else:
            raise AssertionError("unexpected internal failure accepted")
    finally:
        production.canonical_dumps = original
    try:
        production.appraise_spp_diag_trace_semantics(b"{\"secret\":\"CALLER_SECRET_MUST_NOT_ESCAPE\"}", STREAM)
    except TraceSemanticsError as error:
        assert secret not in str(error) and secret not in repr(error)
        assert_sanitized(error)
    else:
        raise AssertionError("secret plan accepted")


def main() -> int:
    assert len(ALL_SPP_TRACE_SEMANTIC_REASONS) == 14
    test_frozen_and_accepted_positives()
    test_independence_and_types()
    test_plan_header_frame_and_sequence()
    test_lifecycle_task_and_operation_rejections()
    test_fatal_child_rejections()
    test_reducer_and_control_rejections()
    test_context_and_object_near_misses()
    test_privacy_translation()
    print("spp_diag_trace_semantics_tests=pass")
    print(f"spp_diag_trace_semantics_positive_vectors={1 + len(accepted_vectors())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
