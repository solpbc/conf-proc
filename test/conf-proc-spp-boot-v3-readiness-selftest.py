#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent A3.1b launch literal, codec, barrier, and deletion KATs."""

from __future__ import annotations

import dataclasses
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

import conf_proc_spp_boot_v3 as boot
import conf_proc_spp_boot_v3_tables as tables
import conf_proc_spp_boot_v3_wire as wire
import conf_proc_spp_boot_v3_readiness_oracle as oracle
from conf_proc_spp_boot_v3_fixture import build_v3_fixture
from conf_proc_spp_reasons_v3 import ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION


ROLE_PIDS = (
    ("attestation-broker", 7101),
    ("inference", 7102),
    ("asr", 7103),
    ("gateway", 7104),
)
EPOCH = 41
START_NS = 9_000_000_000
DEADLINE_NS = START_NS + 4_000_000_000
COOKIE = 0x0102030405060708
WORKERS = 2
STATIC_DIGESTS = (b"a" * 32, b"b" * 32, b"c" * 32, b"d" * 32)


class EqualityForgingEpoch:
    def __eq__(self, _other: object) -> bool:
        return True


class RolePropertyTrap:
    @property
    def role(self) -> object:
        raise AssertionError("non-identity role property was evaluated")


def _assert_exact_literal_types(actual: object, expected: object, path: str) -> None:
    if type(actual) is not type(expected):
        raise AssertionError(f"{path} concrete type")
    if type(expected) is tuple:
        if len(actual) != len(expected):
            raise AssertionError(f"{path} tuple length")
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected, strict=True)):
            _assert_exact_literal_types(actual_item, expected_item, f"{path}[{index}]")
    elif type(expected) is dict:
        if tuple(actual) != tuple(expected):
            raise AssertionError(f"{path} dictionary denominator")
        for key in expected:
            _assert_exact_literal_types(actual[key], expected[key], f"{path}.{key}")


def _readiness_tuple(value: object) -> object:
    if value is None:
        return None
    return (
        value.transport, value.request_magic, value.result_magic,
        value.request_bytes, value.result_bytes, value.role_id, value.clock,
        value.deadline_unit, value.credentials, value.ancillary_fd_rule,
        value.aggregate_deadline_seconds,
    )


def _launch_row_dict(row: object) -> dict[str, object]:
    if type(row) is not tables.LaunchRoleRowV3:
        raise AssertionError("launch row concrete type")
    if tuple(field.name for field in dataclasses.fields(row)) != oracle.LAUNCH_FIELD_NAMES:
        raise AssertionError("launch field denominator")
    result = {name: getattr(row, name) for name in oracle.LAUNCH_FIELD_NAMES}
    if type(row.fd_surface) is not tuple:
        raise AssertionError("launch fd container type")
    result["fd_surface"] = tuple(
        (item.fd, item.purpose, item.owner, item.inheritance, item.limit)
        for item in row.fd_surface
        if type(item) is tables.LaunchFdRowV3
    )
    if len(result["fd_surface"]) != len(row.fd_surface):
        raise AssertionError("launch fd concrete type")
    if type(row.pipe_census) is not tuple:
        raise AssertionError("launch pipe container type")
    result["pipe_census"] = tuple(
        (
            item.fd, item.stream, item.requested_capacity_bytes,
            item.minimum_readback_capacity_bytes, item.census_budget_bytes,
            item.detection_bytes, item.disposition,
        )
        for item in row.pipe_census
        if type(item) is tables.PipeCensusRowV3
    )
    if len(result["pipe_census"]) != len(row.pipe_census):
        raise AssertionError("launch pipe concrete type")
    if row.readiness is not None and type(row.readiness) is not tables.ReadinessProtocolRowV3:
        raise AssertionError("launch readiness concrete type")
    result["readiness"] = _readiness_tuple(row.readiness)
    return result


def _validate_launch_rows(rows: object) -> None:
    if type(rows) is not tuple or len(rows) != 5:
        raise AssertionError("launch five-row denominator")
    reached = []
    for actual, expected in zip(rows, oracle.LAUNCH_ROWS, strict=True):
        normalized = _launch_row_dict(actual)
        _assert_exact_literal_types(normalized, expected, f"launch.{expected['role']}")
        if tuple(normalized) != oracle.LAUNCH_FIELD_NAMES or normalized != expected:
            raise AssertionError("launch literal mismatch")
        reached.append(normalized["role"])
    if tuple(reached) != tuple(row["role"] for row in oracle.LAUNCH_ROWS):
        raise AssertionError("launch oracle reachability")


def _readiness_layout_tuple(row: object) -> tuple[object, ...]:
    if type(row) is not tables.ReadinessLayoutRowV3:
        raise AssertionError("readiness layout row concrete type")
    if tuple(field.name for field in dataclasses.fields(row)) != oracle.READINESS_LAYOUT_ROW_FIELD_NAMES:
        raise AssertionError("readiness layout row denominator")
    if type(row.fields) is not tuple:
        raise AssertionError("readiness layout field container type")
    fields = []
    for field in row.fields:
        if type(field) is not tables.ReadinessLayoutFieldV3:
            raise AssertionError("readiness layout field concrete type")
        if tuple(item.name for item in dataclasses.fields(field)) != oracle.READINESS_LAYOUT_FIELD_NAMES:
            raise AssertionError("readiness layout field denominator")
        fields.append((field.offset, field.width, field.name, field.encoding, field.constraint))
    return (
        row.row_id, row.transport, row.total_bytes, tuple(fields), row.credential_rule,
        row.fd_rule, row.trailing_rule,
    )


def _readiness_barrier_dict(row: object) -> dict[str, object]:
    if type(row) is not tables.ReadinessBarrierRowV3:
        raise AssertionError("readiness barrier concrete type")
    if tuple(field.name for field in dataclasses.fields(row)) != oracle.READINESS_BARRIER_FIELD_NAMES:
        raise AssertionError("readiness barrier denominator")
    return {name: getattr(row, name) for name in oracle.READINESS_BARRIER_FIELD_NAMES}


def _validate_readiness_declarations(layouts: object, barriers: object) -> None:
    if type(layouts) is not tuple or len(layouts) != 4:
        raise AssertionError("readiness layout denominator")
    actual_layouts = tuple(_readiness_layout_tuple(row) for row in layouts)
    _assert_exact_literal_types(actual_layouts, oracle.READINESS_LAYOUTS, "readiness.layouts")
    if actual_layouts != oracle.READINESS_LAYOUTS:
        raise AssertionError("readiness layout literal mismatch")
    if type(barriers) is not tuple or len(barriers) != 1:
        raise AssertionError("readiness barrier denominator")
    actual_barrier = _readiness_barrier_dict(barriers[0])
    _assert_exact_literal_types(actual_barrier, oracle.BARRIER, "readiness.barrier")
    if actual_barrier != oracle.BARRIER:
        raise AssertionError("readiness barrier literal mismatch")


def _changed(value: object) -> object:
    if value is None:
        return "not-none"
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if type(value) is str:
        return value + "-mutated"
    if type(value) is bytes:
        return bytes([value[0] ^ 1]) + value[1:]
    if type(value) is tuple:
        return tuple(reversed(value)) if len(value) > 1 else value + ("mutated",)
    return object()


def _identities() -> tuple[boot.ReadinessRoleIdentityV3, ...]:
    return tuple(
        boot.ReadinessRoleIdentityV3(
            role, index + 1 if index < 3 else None, pid, 61100 + index,
            61100 + index, STATIC_DIGESTS[index],
            WORKERS if index == 3 else None, COOKIE if index == 3 else None,
        )
        for index, (role, pid) in enumerate(ROLE_PIDS)
    )


def _barrier(controller_epoch: int = EPOCH) -> boot.LaunchReadinessBarrierV3:
    return boot.LaunchReadinessBarrierV3(
        controller_epoch=controller_epoch,
        census_start_ns=START_NS,
        expected_identities=_identities(),
    )


def _standalone_result(index: int, *, generation: int = 1, deadline: int = DEADLINE_NS) -> bytes:
    identity = _identities()[index]
    return struct.pack(
        ">8sHHIQQIIII32s", b"SPPRDR3\0", 3, index + 1, 1,
        generation, deadline, identity.pid, identity.uid, identity.gid, 0,
        identity.executable_sha256,
    )


def _gateway_frame(
    *, generation: int = 1, pid: int = ROLE_PIDS[3][1], workers: int = WORKERS,
    flags: int = 1, digest: bytes = STATIC_DIGESTS[3], cookie: int = COOKIE,
    message_type: int = 23, sequence: int = 1, session: bytes = b"\0" * 32,
    header_flags: int = 3,
) -> bytes:
    payload = struct.pack(">QIHH32sQ", generation, pid, workers, flags, digest, cookie)
    header = struct.pack(
        ">8sHHHHIIIIQ32s", b"SPPIPC3\0", 3, message_type, header_flags, 0,
        sequence, 0, 1, 56, 56, session,
    )
    return header + payload


def _datagram(index: int, data: bytes, *, credentials: object = None, fds: tuple[int, ...] = ()) -> boot.ReadinessDatagramV3:
    identity = _identities()[index]
    if credentials is None:
        credentials = (boot.ReadinessProcessCredentialsV3(identity.pid, identity.uid, identity.gid),)
    return boot.ReadinessDatagramV3(data, credentials, fds)


def _feed_one(
    barrier: boot.LaunchReadinessBarrierV3,
    index: int,
    *,
    terminal: bool = False,
    controller_epoch: int = EPOCH,
) -> None:
    probe = barrier.next_probe(
        controller_epoch=controller_epoch, controller_terminal=False, now_ns=START_NS + index,
    )
    expected_probe_role = ROLE_PIDS[index][0]
    if probe.role != expected_probe_role:
        raise AssertionError("probe order")
    data = _standalone_result(index) if index < 3 else _gateway_frame()
    barrier.accept_result(
        role=expected_probe_role,
        datagram=_datagram(index, data),
        controller_epoch=controller_epoch,
        controller_terminal=terminal,
        now_ns=START_NS + 100 + index,
    )


def _feed_all(
    barrier: boot.LaunchReadinessBarrierV3, *, controller_epoch: int = EPOCH
) -> boot.ReadinessCompletionV3:
    for index in range(4):
        _feed_one(barrier, index, controller_epoch=controller_epoch)
    return barrier.complete(controller_epoch=controller_epoch, controller_terminal=False)


def _engine_at_serving() -> boot.BootTransitionEngineV3:
    docs, contract = build_v3_fixture()
    engine = boot.BootTransitionEngineV3(boot.bind_boot_inputs_v3(contract=contract, **docs))
    engine._state = boot.BootTransitionStateV3.SERVING_AVAILABLE
    engine._serving_effect_completed = True
    return engine


def _consume_production_readiness(
    engine: boot.BootTransitionEngineV3,
) -> boot.LaunchReadinessBarrierV3:
    barrier = engine.begin_launch_readiness_census_v3(
        controller_epoch=EPOCH, census_start_ns=START_NS, role_pids=ROLE_PIDS,
        gateway_live_session_worker_count=WORKERS,
        gateway_control_endpoint_so_cookie=COOKIE,
    )
    for index, identity in enumerate(barrier._identities):
        barrier.next_probe(
            controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS + index,
        )
        if index < 3:
            data = struct.pack(
                ">8sHHIQQIIII32s", b"SPPRDR3\0", 3, index + 1, 1, 1,
                DEADLINE_NS, identity.pid, identity.uid, identity.gid, 0,
                identity.executable_sha256,
            )
        else:
            data = _gateway_frame(digest=identity.executable_sha256)
        barrier.accept_result(
            role=identity.role,
            datagram=boot.ReadinessDatagramV3(
                data,
                (boot.ReadinessProcessCredentialsV3(identity.pid, identity.uid, identity.gid),),
            ),
            controller_epoch=EPOCH, controller_terminal=False,
            now_ns=START_NS + 100 + index,
        )
    completion = barrier.complete(controller_epoch=EPOCH, controller_terminal=False)
    engine.consume_launch_readiness_completion_v3(
        completion, controller_epoch=EPOCH, controller_terminal=False,
    )
    return barrier


class LaunchLiteralOracleTests(unittest.TestCase):
    def test_a_exact_five_by_twenty_six_literal_oracle(self) -> None:
        _validate_launch_rows(tables.LAUNCH_ROLE_ROWS_V3)
        self.assertEqual(len(oracle.LAUNCH_FIELD_NAMES), 26)
        self.assertEqual(tuple(row.role for row in tables.LAUNCH_ROLE_ROWS_V3), (
            "attestation-broker", "inference", "asr", "gateway", "collector",
        ))

    def test_b_each_field_member_type_and_order_mutation_fails(self) -> None:
        baseline = tables.LAUNCH_ROLE_ROWS_V3
        for row_index, row in enumerate(baseline):
            for field in dataclasses.fields(row):
                changed = list(baseline)
                changed[row_index] = dataclasses.replace(
                    row, **{field.name: _changed(getattr(row, field.name))}
                )
                with self.subTest(row=row.role, field=field.name):
                    with self.assertRaises(AssertionError):
                        _validate_launch_rows(tuple(changed))
                wrong_type = list(baseline)
                wrong_type[row_index] = dataclasses.replace(row, **{field.name: object()})
                with self.subTest(row=row.role, concrete_type=field.name):
                    with self.assertRaises(AssertionError):
                        _validate_launch_rows(tuple(wrong_type))
            for container_name in ("fd_surface", "pipe_census"):
                for member_index, member in enumerate(getattr(row, container_name)):
                    for field in dataclasses.fields(member):
                        members = list(getattr(row, container_name))
                        members[member_index] = dataclasses.replace(
                            member, **{field.name: _changed(getattr(member, field.name))}
                        )
                        changed = list(baseline)
                        changed[row_index] = dataclasses.replace(
                            row, **{container_name: tuple(members)}
                        )
                        with self.subTest(row=row.role, nested=container_name, field=field.name):
                            with self.assertRaises(AssertionError):
                                _validate_launch_rows(tuple(changed))
            if row.readiness is not None:
                for field in dataclasses.fields(row.readiness):
                    changed = list(baseline)
                    changed[row_index] = dataclasses.replace(
                        row,
                        readiness=dataclasses.replace(
                            row.readiness,
                            **{field.name: _changed(getattr(row.readiness, field.name))},
                        ),
                    )
                    with self.subTest(row=row.role, readiness=field.name):
                        with self.assertRaises(AssertionError):
                            _validate_launch_rows(tuple(changed))
        for changed in (baseline[:-1], tuple(reversed(baseline)), baseline + (baseline[0],)):
            with self.assertRaises(AssertionError):
                _validate_launch_rows(changed)

    def test_c_layout_and_barrier_declarations_match_independent_oracle(self) -> None:
        layouts = tables.READINESS_LAYOUT_ROWS_V3
        barriers = tables.READINESS_BARRIER_ROWS_V3
        _validate_readiness_declarations(layouts, barriers)

        for row_index, row in enumerate(layouts):
            for field_name in oracle.READINESS_LAYOUT_ROW_FIELD_NAMES:
                changed = list(layouts)
                changed[row_index] = dataclasses.replace(
                    row, **{field_name: _changed(getattr(row, field_name))}
                )
                with self.subTest(layout=row.row_id, row_field=field_name):
                    with self.assertRaises(AssertionError):
                        _validate_readiness_declarations(tuple(changed), barriers)
            for layout_field_index, layout_field in enumerate(row.fields):
                for field_name in oracle.READINESS_LAYOUT_FIELD_NAMES:
                    changed_fields = list(row.fields)
                    changed_fields[layout_field_index] = dataclasses.replace(
                        layout_field, **{field_name: _changed(getattr(layout_field, field_name))}
                    )
                    changed = list(layouts)
                    changed[row_index] = dataclasses.replace(row, fields=tuple(changed_fields))
                    with self.subTest(
                        layout=row.row_id, layout_field=layout_field.name, field=field_name,
                    ):
                        with self.assertRaises(AssertionError):
                            _validate_readiness_declarations(tuple(changed), barriers)

        for changed in (layouts[:-1], tuple(reversed(layouts)), layouts + (layouts[0],)):
            with self.assertRaises(AssertionError):
                _validate_readiness_declarations(changed, barriers)

        barrier = barriers[0]
        for field_name in oracle.READINESS_BARRIER_FIELD_NAMES:
            changed = dataclasses.replace(
                barrier, **{field_name: _changed(getattr(barrier, field_name))}
            )
            with self.subTest(barrier_field=field_name):
                with self.assertRaises(AssertionError):
                    _validate_readiness_declarations(layouts, (changed,))
        for changed in ((), barriers + barriers):
            with self.assertRaises(AssertionError):
                _validate_readiness_declarations(layouts, changed)

        self.assertEqual(tables.LAUNCH_DELETE_WITNESS_ROWS_V3, ("independent_coherent_delete",))

    def test_d_wrong_concrete_types_fail_every_nested_oracle_denominator(self) -> None:
        launch_rows = tables.LAUNCH_ROLE_ROWS_V3
        with self.assertRaises(AssertionError):
            _validate_launch_rows(list(launch_rows))
        for row_index, row in enumerate(launch_rows):
            changed = list(launch_rows)
            changed[row_index] = dataclasses.astuple(row)
            with self.subTest(launch_row=row.role, concrete_type="row"):
                with self.assertRaises(AssertionError):
                    _validate_launch_rows(tuple(changed))
            for container_name in ("fd_surface", "pipe_census"):
                container = getattr(row, container_name)
                for nested_index, nested in enumerate(container):
                    changed_container = list(container)
                    changed_container[nested_index] = dataclasses.astuple(nested)
                    changed = list(launch_rows)
                    changed[row_index] = dataclasses.replace(
                        row, **{container_name: tuple(changed_container)}
                    )
                    with self.subTest(
                        launch_row=row.role, concrete_type=container_name,
                        nested_index=nested_index,
                    ):
                        with self.assertRaises(AssertionError):
                            _validate_launch_rows(tuple(changed))
                    for field in dataclasses.fields(nested):
                        changed_container = list(container)
                        changed_container[nested_index] = dataclasses.replace(
                            nested, **{field.name: EqualityForgingEpoch()}
                        )
                        changed = list(launch_rows)
                        changed[row_index] = dataclasses.replace(
                            row, **{container_name: tuple(changed_container)}
                        )
                        with self.subTest(
                            launch_row=row.role, concrete_type=container_name,
                            nested_index=nested_index, field=field.name,
                        ):
                            with self.assertRaises(AssertionError):
                                _validate_launch_rows(tuple(changed))
            if row.readiness is not None:
                changed = list(launch_rows)
                changed[row_index] = dataclasses.replace(
                    row, readiness=dataclasses.astuple(row.readiness),
                )
                with self.subTest(launch_row=row.role, concrete_type="readiness"):
                    with self.assertRaises(AssertionError):
                        _validate_launch_rows(tuple(changed))
                for field in dataclasses.fields(row.readiness):
                    changed = list(launch_rows)
                    changed[row_index] = dataclasses.replace(
                        row,
                        readiness=dataclasses.replace(
                            row.readiness, **{field.name: EqualityForgingEpoch()}
                        ),
                    )
                    with self.subTest(
                        launch_row=row.role, concrete_type="readiness",
                        field=field.name,
                    ):
                        with self.assertRaises(AssertionError):
                            _validate_launch_rows(tuple(changed))

        layouts = tables.READINESS_LAYOUT_ROWS_V3
        barriers = tables.READINESS_BARRIER_ROWS_V3
        for bad_layouts in (list(layouts), layouts[:-1] + (dataclasses.astuple(layouts[-1]),)):
            with self.assertRaises(AssertionError):
                _validate_readiness_declarations(bad_layouts, barriers)
        for row_index, row in enumerate(layouts):
            with self.subTest(layout=row.row_id, concrete_type="field_container"):
                changed = list(layouts)
                changed[row_index] = dataclasses.replace(row, fields=list(row.fields))
                with self.assertRaises(AssertionError):
                    _validate_readiness_declarations(tuple(changed), barriers)
            for field_name in oracle.READINESS_LAYOUT_ROW_FIELD_NAMES:
                changed = list(layouts)
                changed[row_index] = dataclasses.replace(
                    row, **{field_name: EqualityForgingEpoch()}
                )
                with self.subTest(
                    layout=row.row_id, concrete_type="layout_row", field=field_name,
                ):
                    with self.assertRaises(AssertionError):
                        _validate_readiness_declarations(tuple(changed), barriers)
            for field_index, field in enumerate(row.fields):
                changed_fields = list(row.fields)
                changed_fields[field_index] = dataclasses.astuple(field)
                changed = list(layouts)
                changed[row_index] = dataclasses.replace(row, fields=tuple(changed_fields))
                with self.subTest(
                    layout=row.row_id, concrete_type="field", field=field.name,
                ):
                    with self.assertRaises(AssertionError):
                        _validate_readiness_declarations(tuple(changed), barriers)
                for field_name in oracle.READINESS_LAYOUT_FIELD_NAMES:
                    changed_fields = list(row.fields)
                    changed_fields[field_index] = dataclasses.replace(
                        field, **{field_name: EqualityForgingEpoch()}
                    )
                    changed = list(layouts)
                    changed[row_index] = dataclasses.replace(
                        row, fields=tuple(changed_fields)
                    )
                    with self.subTest(
                        layout=row.row_id, concrete_type="layout_field",
                        layout_field=field.name, field=field_name,
                    ):
                        with self.assertRaises(AssertionError):
                            _validate_readiness_declarations(tuple(changed), barriers)

        with self.assertRaises(AssertionError):
            _validate_readiness_declarations(layouts, list(barriers))
        with self.assertRaises(AssertionError):
            _validate_readiness_declarations(layouts, (dataclasses.astuple(barriers[0]),))
        for field_name in oracle.READINESS_BARRIER_FIELD_NAMES:
            changed = dataclasses.replace(
                barriers[0], **{field_name: EqualityForgingEpoch()}
            )
            with self.subTest(barrier_concrete_type=field_name):
                with self.assertRaises(AssertionError):
                    _validate_readiness_declarations(layouts, (changed,))
        for field_name in ("role_order", "states"):
            changed = dataclasses.replace(
                barriers[0], **{field_name: list(getattr(barriers[0], field_name))}
            )
            with self.subTest(barrier_nested_type=field_name):
                with self.assertRaises(AssertionError):
                    _validate_readiness_declarations(layouts, (changed,))


class ReadinessCodecKatTests(unittest.TestCase):
    def test_a_standalone_exact_offsets_and_cross_feed(self) -> None:
        probe = struct.pack(">8sHHIQQ", b"SPPRDQ3\0", 3, 2, 0, 1, DEADLINE_NS)
        self.assertEqual(len(probe), 32)
        self.assertEqual(
            wire.encode_standalone_readiness_probe_v3(
                wire.StandaloneReadinessProbeV3(2, 1, DEADLINE_NS)
            ),
            probe,
        )
        self.assertEqual(
            wire.decode_standalone_readiness_probe_v3(probe),
            wire.StandaloneReadinessProbeV3(2, 1, DEADLINE_NS),
        )
        result = _standalone_result(1)
        self.assertEqual(len(result), 80)
        self.assertEqual(
            wire.decode_standalone_readiness_result_v3(result),
            wire.StandaloneReadinessResultV3(
                2, 1, 1, DEADLINE_NS, 7102, 61101, 61101, b"b" * 32,
            ),
        )
        for value, decoder in (
            (result, wire.decode_standalone_readiness_probe_v3),
            (probe, wire.decode_standalone_readiness_result_v3),
            (probe + b"x", wire.decode_standalone_readiness_probe_v3),
            (result + b"x", wire.decode_standalone_readiness_result_v3),
        ):
            with self.assertRaises(ApplianceErrorV3):
                decoder(value)

    def test_b_standalone_one_field_negatives(self) -> None:
        probe_fields = ((0, b"BADRDQ3\0"), (8, 4), (10, 0), (12, 1), (16, 0), (24, 0))
        for offset, value in probe_fields:
            data = bytearray(struct.pack(">8sHHIQQ", b"SPPRDQ3\0", 3, 1, 0, 1, DEADLINE_NS))
            if type(value) is bytes:
                data[offset:offset + len(value)] = value
            else:
                width = {8: 2, 10: 2, 12: 4, 16: 8, 24: 8}[offset]
                data[offset:offset + width] = value.to_bytes(width, "big")
            with self.subTest(probe_offset=offset):
                with self.assertRaises(ApplianceErrorV3):
                    wire.decode_standalone_readiness_probe_v3(bytes(data))
        result = bytearray(_standalone_result(0))
        mutations = ((0, b"BADRDR3\0"), (8, 4), (10, 0), (12, 0), (16, 0), (24, 0), (44, 1))
        for offset, value in mutations:
            changed = bytearray(result)
            if type(value) is bytes:
                changed[offset:offset + len(value)] = value
            else:
                width = {8: 2, 10: 2, 12: 4, 16: 8, 24: 8, 44: 4}[offset]
                changed[offset:offset + width] = value.to_bytes(width, "big")
            with self.subTest(result_offset=offset):
                with self.assertRaises(ApplianceErrorV3):
                    wire.decode_standalone_readiness_result_v3(bytes(changed))

    def test_c_gateway_exact_frames_and_payload_constraints(self) -> None:
        probe_payload = struct.pack(">QQ", 1, DEADLINE_NS)
        probe_header = struct.pack(
            ">8sHHHHIIIIQ32s", b"SPPIPC3\0", 3, 22, 3, 0, 1, 0, 1,
            16, 16, b"\0" * 32,
        )
        probe = probe_header + probe_payload
        self.assertEqual(len(probe), 88)
        decoded_probe = wire.decode_serving_wire_frame_v3(probe)
        self.assertEqual(decoded_probe.payload, wire.GatewayReadinessProbePayloadV3(1, DEADLINE_NS))
        result = _gateway_frame()
        self.assertEqual(len(result), 128)
        decoded_result = wire.decode_serving_wire_frame_v3(result)
        self.assertEqual(
            decoded_result.payload,
            wire.GatewayReadinessResultPayloadV3(1, 7104, 2, 1, b"d" * 32, COOKIE),
        )
        for payload in (
            wire.GatewayReadinessProbePayloadV3(0, DEADLINE_NS),
            wire.GatewayReadinessProbePayloadV3(2, DEADLINE_NS),
            wire.GatewayReadinessProbePayloadV3(True, DEADLINE_NS),
            wire.GatewayReadinessProbePayloadV3(1, 0),
        ):
            with self.assertRaises(ApplianceErrorV3):
                wire.encode_gateway_readiness_probe_payload_v3(payload)
        for payload in (
            wire.GatewayReadinessResultPayloadV3(0, 7104, 2, 1, b"d" * 32, COOKIE),
            wire.GatewayReadinessResultPayloadV3(True, 7104, 2, 1, b"d" * 32, COOKIE),
            wire.GatewayReadinessResultPayloadV3(1, 0, 2, 1, b"d" * 32, COOKIE),
            wire.GatewayReadinessResultPayloadV3(1, 7104, 5, 1, b"d" * 32, COOKIE),
            wire.GatewayReadinessResultPayloadV3(1, 7104, 2, 0, b"d" * 32, COOKIE),
            wire.GatewayReadinessResultPayloadV3(1, 7104, 2, True, b"d" * 32, COOKIE),
            wire.GatewayReadinessResultPayloadV3(1, 7104, 2, 1, b"d" * 32, 0),
        ):
            with self.assertRaises(ApplianceErrorV3):
                wire.encode_gateway_readiness_result_payload_v3(payload)

    def test_d_standalone_bool_generation_and_flags_are_rejected(self) -> None:
        for value in (
            wire.StandaloneReadinessProbeV3(1, True, DEADLINE_NS),
            wire.StandaloneReadinessResultV3(
                1, True, 1, DEADLINE_NS, 7101, 61100, 61100, b"a" * 32,
            ),
            wire.StandaloneReadinessResultV3(
                1, 1, True, DEADLINE_NS, 7101, 61100, 61100, b"a" * 32,
            ),
        ):
            encoder = (
                wire.encode_standalone_readiness_probe_v3
                if type(value) is wire.StandaloneReadinessProbeV3
                else wire.encode_standalone_readiness_result_v3
            )
            with self.subTest(value=value):
                with self.assertRaises(ApplianceErrorV3):
                    encoder(value)


class ReadinessBarrierTests(unittest.TestCase):
    def test_a_only_exact_all_four_mints_and_consumes_once(self) -> None:
        barrier = _barrier()
        probes = []
        for index in range(4):
            probe = barrier.next_probe(
                controller_epoch=EPOCH, controller_terminal=False,
                now_ns=START_NS + index,
            )
            probes.append((probe.role, len(probe.data)))
            data = _standalone_result(index) if index < 3 else _gateway_frame()
            barrier.accept_result(
                role=ROLE_PIDS[index][0], datagram=_datagram(index, data),
                controller_epoch=EPOCH, controller_terminal=False,
                now_ns=START_NS + 100 + index,
            )
        self.assertEqual(probes, [
            ("attestation-broker", 32), ("inference", 32), ("asr", 32),
            ("gateway", 88),
        ])
        self.assertEqual(barrier.state, "candidate")
        completion = barrier.complete(controller_epoch=EPOCH, controller_terminal=False)
        material = b""
        for index, identity in enumerate(_identities()):
            role = identity.role.encode("ascii")
            material += (
                len(role).to_bytes(1, "big") + role + identity.pid.to_bytes(4, "big")
                + identity.uid.to_bytes(4, "big") + identity.gid.to_bytes(4, "big")
                + identity.executable_sha256
            )
            if index == 3:
                material += WORKERS.to_bytes(2, "big") + COOKIE.to_bytes(8, "big")
        expected_digest = hashlib.sha256(b"sol-spp-launch-readiness-v3\0" + material).digest()
        self.assertEqual(completion, boot.ReadinessCompletionV3(EPOCH, 1, DEADLINE_NS, expected_digest))
        barrier.consume(completion, controller_epoch=EPOCH, controller_terminal=False)
        self.assertEqual(barrier.state, "consumed")
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION):
            barrier.consume(completion, controller_epoch=EPOCH, controller_terminal=False)
        self.assertEqual(barrier.state, "failed")

    def test_b_duplicate_partial_reorder_late_crossfeed_fifth_and_identity_fail(self) -> None:
        cases = []
        barrier = _barrier()
        barrier.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS)
        cases.append((barrier, lambda b: b.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS + 1)))

        barrier = _barrier()
        barrier.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS)
        cases.append((barrier, lambda b: b.accept_result(role="inference", datagram=_datagram(1, _standalone_result(1)), controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS + 1)))

        barrier = _barrier()
        barrier.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS)
        cases.append((barrier, lambda b: b.accept_result(role="attestation-broker", datagram=_datagram(0, _standalone_result(0)), controller_epoch=EPOCH, controller_terminal=False, now_ns=DEADLINE_NS)))

        barrier = _barrier()
        barrier.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS)
        cases.append((barrier, lambda b: b.accept_result(role="attestation-broker", datagram=_datagram(0, _gateway_frame()), controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS + 1)))

        barrier = _barrier()
        barrier.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS)
        cases.append((barrier, lambda b: b.accept_result(role="attestation-broker", datagram=_datagram(0, _standalone_result(0), credentials=()), controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS + 1)))

        barrier = _barrier()
        barrier.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS)
        cases.append((barrier, lambda b: b.accept_result(role="attestation-broker", datagram=_datagram(0, _standalone_result(0), fds=(9,)), controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS + 1)))

        barrier = _barrier()
        barrier.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS)
        cases.append((barrier, lambda b: b.accept_result(role="attestation-broker", datagram=_datagram(0, _standalone_result(0) + b"x"), controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS + 1)))

        barrier = _barrier()
        _feed_one(barrier, 0)
        cases.append((barrier, lambda b: b.complete(controller_epoch=EPOCH, controller_terminal=False)))

        barrier = _barrier()
        cases.append((barrier, lambda b: b.next_probe(controller_epoch=EPOCH + 1, controller_terminal=False, now_ns=START_NS)))

        for barrier, operation in cases:
            with self.subTest(case=len(cases)):
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION):
                    operation(barrier)
                self.assertEqual(barrier.state, "failed")

        for offset, width, value in (
            (16, 8, 2), (24, 8, DEADLINE_NS + 1), (32, 4, 9999),
            (36, 4, 9999), (40, 4, 9999),
        ):
            data = bytearray(_standalone_result(0))
            data[offset:offset + width] = value.to_bytes(width, "big")
            barrier = _barrier()
            barrier.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS)
            with self.subTest(standalone_identity_offset=offset):
                with self.assertRaises(ApplianceErrorV3):
                    barrier.accept_result(
                        role="attestation-broker", datagram=_datagram(0, bytes(data)),
                        controller_epoch=EPOCH, controller_terminal=False,
                        now_ns=START_NS + 1,
                    )
                self.assertEqual(barrier.state, "failed")
        data = bytearray(_standalone_result(0))
        data[48] ^= 1
        barrier = _barrier()
        barrier.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS)
        with self.assertRaises(ApplianceErrorV3):
            barrier.accept_result(
                role="attestation-broker", datagram=_datagram(0, bytes(data)),
                controller_epoch=EPOCH, controller_terminal=False,
                now_ns=START_NS + 1,
            )
        self.assertEqual(barrier.state, "failed")

        barrier = _barrier()
        for index in range(4):
            _feed_one(barrier, index)
        with self.assertRaises(ApplianceErrorV3):
            barrier.accept_result(
                role="gateway", datagram=_datagram(3, _gateway_frame()),
                controller_epoch=EPOCH, controller_terminal=False,
                now_ns=START_NS + 200,
            )
        self.assertEqual(barrier.state, "failed")

    def test_c_gateway_header_payload_and_ledger_negatives(self) -> None:
        mutations = (
            _gateway_frame(generation=2), _gateway_frame(pid=9999),
            _gateway_frame(workers=1), _gateway_frame(flags=0),
            _gateway_frame(digest=b"x" * 32), _gateway_frame(cookie=9),
            _gateway_frame(message_type=22), _gateway_frame(sequence=2),
            _gateway_frame(session=b"s" * 32), _gateway_frame(header_flags=0),
            _gateway_frame() + b"x",
        )
        for data in mutations:
            barrier = _barrier()
            for index in range(3):
                _feed_one(barrier, index)
            barrier.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS + 3)
            with self.subTest(length=len(data)):
                with self.assertRaises(ApplianceErrorV3):
                    barrier.accept_result(
                        role="gateway", datagram=_datagram(3, data),
                        controller_epoch=EPOCH, controller_terminal=False,
                        now_ns=START_NS + 103,
                    )
                self.assertEqual(barrier.state, "failed")

    def test_d_terminal_epoch_wins_every_required_boundary(self) -> None:
        terminal_events = (
            "SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT", "unknown_child_exit",
            "attestation-broker_exit", "inference_exit", "asr_exit", "gateway_exit",
        )
        for event in terminal_events:
            for boundary in range(5):
                barrier = _barrier()
                for index in range(boundary):
                    _feed_one(barrier, index)
                with self.subTest(event=event, boundary=boundary):
                    with self.assertRaises(ApplianceErrorV3):
                        barrier.note_terminal(controller_epoch=EPOCH, event=event)
                    self.assertEqual(barrier.state, "failed")
            barrier = _barrier()
            for index in range(3):
                _feed_one(barrier, index)
            barrier.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS + 3)
            with self.subTest(event=event, same_batch="fourth"):
                with self.assertRaises(ApplianceErrorV3):
                    barrier.accept_result(
                        role="gateway", datagram=_datagram(3, _gateway_frame()),
                        controller_epoch=EPOCH, controller_terminal=True,
                        now_ns=START_NS + 103,
                    )
                self.assertEqual(barrier.state, "failed")
            barrier = _barrier()
            for index in range(4):
                _feed_one(barrier, index)
            with self.subTest(event=event, after_fourth="before_complete"):
                with self.assertRaises(ApplianceErrorV3):
                    barrier.note_terminal(controller_epoch=EPOCH, event=event)
                self.assertEqual(barrier.state, "failed")
            barrier = _barrier()
            completion = _feed_all(barrier)
            with self.subTest(event=event, after_complete="before_consume"):
                with self.assertRaises(ApplianceErrorV3):
                    barrier.note_terminal(controller_epoch=EPOCH, event=event)
                with self.assertRaises(ApplianceErrorV3):
                    barrier.consume(completion, controller_epoch=EPOCH, controller_terminal=False)

    def test_e_engine_admission_connection_one_census_and_post_serving_route(self) -> None:
        docs, contract = build_v3_fixture()
        blocked = boot.BootTransitionEngineV3(boot.bind_boot_inputs_v3(contract=contract, **docs))
        blocked._state = boot.BootTransitionStateV3.SERVING_AVAILABLE
        blocked._serving_effect_completed = True
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION):
            blocked.admit_serving_authority()

        docs, contract = build_v3_fixture()
        binding = boot.bind_boot_inputs_v3(contract=contract, **docs)
        engine = boot.BootTransitionEngineV3(binding)
        engine._state = boot.BootTransitionStateV3.SERVING_AVAILABLE
        engine._serving_effect_completed = True
        barrier = engine.begin_launch_readiness_census_v3(
            controller_epoch=EPOCH, census_start_ns=START_NS, role_pids=ROLE_PIDS,
            gateway_live_session_worker_count=WORKERS,
            gateway_control_endpoint_so_cookie=COOKIE,
        )
        production_identities = barrier._identities
        for index, identity in enumerate(production_identities):
            probe = barrier.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS + index)
            self.assertEqual(probe.role, identity.role)
            if index < 3:
                data = struct.pack(
                    ">8sHHIQQIIII32s", b"SPPRDR3\0", 3, index + 1, 1, 1,
                    DEADLINE_NS, identity.pid, identity.uid, identity.gid, 0,
                    identity.executable_sha256,
                )
            else:
                data = _gateway_frame(digest=identity.executable_sha256)
            barrier.accept_result(
                role=identity.role,
                datagram=boot.ReadinessDatagramV3(
                    data, (boot.ReadinessProcessCredentialsV3(identity.pid, identity.uid, identity.gid),),
                ),
                controller_epoch=EPOCH, controller_terminal=False,
                now_ns=START_NS + 100 + index,
            )
        completion = barrier.complete(controller_epoch=EPOCH, controller_terminal=False)
        engine.consume_launch_readiness_completion_v3(
            completion, controller_epoch=EPOCH, controller_terminal=False,
        )
        wrapper = engine.admit_serving_authority()
        engine.report_controller_terminal_v3(controller_epoch=EPOCH, event="SIGTERM")
        self.assertEqual(engine._state, boot.BootTransitionStateV3.FAILED_NON_SERVING)
        self.assertTrue(wrapper._resource.revoked)

        docs, contract = build_v3_fixture()
        retry_engine = boot.BootTransitionEngineV3(boot.bind_boot_inputs_v3(contract=contract, **docs))
        retry_engine._state = boot.BootTransitionStateV3.SERVING_AVAILABLE
        retry_engine._serving_effect_completed = True
        failed = retry_engine.begin_launch_readiness_census_v3(
            controller_epoch=EPOCH, census_start_ns=START_NS, role_pids=ROLE_PIDS,
            gateway_live_session_worker_count=WORKERS,
            gateway_control_endpoint_so_cookie=COOKIE,
        )
        failed.next_probe(controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS)
        with self.assertRaises(ApplianceErrorV3):
            failed.accept_result(
                role="inference", datagram=_datagram(1, _standalone_result(1)),
                controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS + 1,
            )
        with self.assertRaises(ApplianceErrorV3):
            retry_engine.begin_launch_readiness_census_v3(
                controller_epoch=EPOCH, census_start_ns=START_NS, role_pids=ROLE_PIDS,
                gateway_live_session_worker_count=WORKERS,
                gateway_control_endpoint_so_cookie=COOKIE,
            )

    def test_f_terminal_and_completion_race_serializes_to_no_consumable_token(self) -> None:
        barrier = _barrier()
        for index in range(4):
            _feed_one(barrier, index)
        start = threading.Barrier(3)
        completions: list[boot.ReadinessCompletionV3] = []
        errors: list[BaseException] = []

        def complete() -> None:
            start.wait()
            try:
                completions.append(barrier.complete(controller_epoch=EPOCH, controller_terminal=False))
            except BaseException as error:
                errors.append(error)

        def terminate() -> None:
            start.wait()
            try:
                barrier.note_terminal(controller_epoch=EPOCH, event="SIGTERM")
            except BaseException as error:
                errors.append(error)

        threads = (threading.Thread(target=complete), threading.Thread(target=terminate))
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(barrier.state, "failed")
        self.assertTrue(errors)
        for completion in completions:
            with self.assertRaises(ApplianceErrorV3):
                barrier.consume(completion, controller_epoch=EPOCH, controller_terminal=False)

    def test_g_every_followup_rejects_bool_and_equality_forging_epochs(self) -> None:
        for captured_epoch, invalid_epoch in (
            (EPOCH, EqualityForgingEpoch()),
            (1, True),
        ):
            for transition in ("next_probe", "accept_result", "complete", "consume", "terminal"):
                barrier = _barrier(captured_epoch)
                completion = None
                if transition == "accept_result":
                    barrier.next_probe(
                        controller_epoch=captured_epoch, controller_terminal=False,
                        now_ns=START_NS,
                    )
                elif transition in ("complete", "consume"):
                    for index in range(4):
                        _feed_one(barrier, index, controller_epoch=captured_epoch)
                    if transition == "consume":
                        completion = barrier.complete(
                            controller_epoch=captured_epoch, controller_terminal=False,
                        )

                with self.subTest(
                    captured_epoch=captured_epoch,
                    invalid_type=type(invalid_epoch).__name__,
                    transition=transition,
                ):
                    with self.assertRaises(ApplianceErrorV3):
                        if transition == "next_probe":
                            barrier.next_probe(
                                controller_epoch=invalid_epoch, controller_terminal=False,
                                now_ns=START_NS,
                            )
                        elif transition == "accept_result":
                            barrier.accept_result(
                                role="attestation-broker",
                                datagram=_datagram(0, _standalone_result(0)),
                                controller_epoch=invalid_epoch, controller_terminal=False,
                                now_ns=START_NS + 1,
                            )
                        elif transition == "complete":
                            barrier.complete(
                                controller_epoch=invalid_epoch, controller_terminal=False,
                            )
                        elif transition == "consume":
                            barrier.consume(
                                completion, controller_epoch=invalid_epoch,
                                controller_terminal=False,
                            )
                        else:
                            barrier.note_terminal(
                                controller_epoch=invalid_epoch, event="SIGTERM",
                            )
                    self.assertEqual(barrier.state, "failed")

        for invalid_epoch in (True, EqualityForgingEpoch(), 0, 1 << 64):
            with self.subTest(constructor_epoch=type(invalid_epoch).__name__):
                with self.assertRaises(ApplianceErrorV3):
                    _barrier(invalid_epoch)

    def test_h_concurrent_census_begins_have_exactly_one_winner(self) -> None:
        engine = _engine_at_serving()
        transition_lock = engine._launch_transition_lock
        transition_lock.acquire()
        entered = (threading.Event(), threading.Event())
        successes: list[boot.LaunchReadinessBarrierV3] = []
        errors: list[BaseException] = []

        def begin(index: int) -> None:
            entered[index].set()
            try:
                successes.append(engine.begin_launch_readiness_census_v3(
                    controller_epoch=EPOCH,
                    census_start_ns=START_NS,
                    role_pids=ROLE_PIDS,
                    gateway_live_session_worker_count=WORKERS,
                    gateway_control_endpoint_so_cookie=COOKIE,
                ))
            except BaseException as error:
                errors.append(error)

        threads = tuple(threading.Thread(target=begin, args=(index,)) for index in range(2))
        try:
            for thread in threads:
                thread.start()
            for event in entered:
                self.assertTrue(event.wait(5))
        finally:
            transition_lock.release()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 1)
        self.assertIs(successes[0], engine._launch_readiness_barrier)
        self.assertIsInstance(errors[0], ApplianceErrorV3)

    def test_i_terminal_winner_prevents_late_admission_publish(self) -> None:
        engine = _engine_at_serving()
        _consume_production_readiness(engine)
        original_fail = engine._fail
        terminal_has_transition_authority = threading.Event()
        release_terminal = threading.Event()
        admission_started = threading.Event()
        terminal_errors: list[BaseException] = []
        admission_errors: list[BaseException] = []
        admitted: list[boot.ServingAuthorityWrapperV3] = []

        def paused_fail(reason_code: str, message: str) -> None:
            terminal_has_transition_authority.set()
            if not release_terminal.wait(5):
                raise AssertionError("terminal transition pause timed out")
            original_fail(reason_code, message)

        engine._fail = paused_fail

        def terminate() -> None:
            try:
                engine.report_controller_terminal_v3(
                    controller_epoch=EPOCH, event="SIGTERM",
                )
            except BaseException as error:
                terminal_errors.append(error)

        def admit() -> None:
            admission_started.set()
            try:
                admitted.append(engine.admit_serving_authority())
            except BaseException as error:
                admission_errors.append(error)

        terminal_thread = threading.Thread(target=terminate)
        admission_thread = threading.Thread(target=admit)
        terminal_thread.start()
        self.assertTrue(terminal_has_transition_authority.wait(5))
        admission_thread.start()
        self.assertTrue(admission_started.wait(5))
        release_terminal.set()
        for thread in (terminal_thread, admission_thread):
            thread.join(5)
            self.assertFalse(thread.is_alive())

        self.assertFalse(admitted)
        self.assertTrue(terminal_errors)
        self.assertTrue(admission_errors)
        self.assertIsNone(engine._serving_authority)
        self.assertEqual(engine._state, boot.BootTransitionStateV3.FAILED_NON_SERVING)

    def test_j_engine_terminal_rejects_equality_forging_epoch(self) -> None:
        engine = _engine_at_serving()
        engine.begin_launch_readiness_census_v3(
            controller_epoch=EPOCH, census_start_ns=START_NS, role_pids=ROLE_PIDS,
            gateway_live_session_worker_count=WORKERS,
            gateway_control_endpoint_so_cookie=COOKIE,
        )
        with self.assertRaises(ApplianceErrorV3):
            engine.report_controller_terminal_v3(
                controller_epoch=EqualityForgingEpoch(), event="SIGTERM",
            )
        self.assertEqual(engine._state, boot.BootTransitionStateV3.FAILED_NON_SERVING)

    def test_k_terminal_and_concurrent_wrapper_cleanup_do_not_deadlock(self) -> None:
        engine = _engine_at_serving()
        _consume_production_readiness(engine)
        wrapper = engine.admit_serving_authority()
        original_fail = engine._fail
        original_global_fault = wrapper._on_global_fault
        terminal_has_transition_authority = threading.Event()
        release_terminal = threading.Event()
        cleanup_reached_engine_callback = threading.Event()
        errors: list[BaseException] = []

        def paused_fail(reason_code: str, message: str) -> None:
            terminal_has_transition_authority.set()
            if not release_terminal.wait(5):
                raise AssertionError("terminal transition pause timed out")
            original_fail(reason_code, message)

        def observed_global_fault() -> None:
            cleanup_reached_engine_callback.set()
            if original_global_fault is not None:
                original_global_fault()

        engine._fail = paused_fail
        wrapper._on_global_fault = observed_global_fault

        def terminate() -> None:
            try:
                engine.report_controller_terminal_v3(
                    controller_epoch=EPOCH, event="SIGTERM",
                )
            except BaseException as error:
                errors.append(error)

        def cleanup() -> None:
            try:
                wrapper.global_revoke()
            except BaseException as error:
                errors.append(error)

        terminal_thread = threading.Thread(target=terminate)
        cleanup_thread = threading.Thread(target=cleanup)
        terminal_thread.start()
        self.assertTrue(terminal_has_transition_authority.wait(5))
        cleanup_thread.start()
        self.assertTrue(cleanup_reached_engine_callback.wait(5))
        release_terminal.set()
        for thread in (terminal_thread, cleanup_thread):
            thread.join(5)
            self.assertFalse(thread.is_alive())

        self.assertFalse(errors)
        self.assertTrue(wrapper._resource.revoked)
        self.assertEqual(engine._state, boot.BootTransitionStateV3.FAILED_NON_SERVING)

    def test_l_paused_publication_serializes_advance_terminal_failure(self) -> None:
        engine = _engine_at_serving()
        _consume_production_readiness(engine)
        original_publish = boot._publish_serving_wrapper_v3
        original_fail = engine._fail
        publication_entered = threading.Event()
        release_publication = threading.Event()
        terminal_started = threading.Event()
        terminal_mutation_entered = threading.Event()
        admitted: list[boot.ServingAuthorityWrapperV3] = []
        admission_errors: list[BaseException] = []
        terminal_errors: list[BaseException] = []

        def paused_publish(
            target: boot.BootTransitionEngineV3,
            capability: object,
            wrapper: boot.ServingAuthorityWrapperV3,
        ) -> boot.ServingAuthorityWrapperV3:
            publication_entered.set()
            if not release_publication.wait(5):
                raise AssertionError("publication pause timed out")
            return original_publish(target, capability, wrapper)

        def observed_fail(reason_code: str, message: str) -> None:
            terminal_mutation_entered.set()
            original_fail(reason_code, message)

        def admit() -> None:
            try:
                admitted.append(engine.admit_serving_authority())
            except BaseException as error:
                admission_errors.append(error)

        def terminate() -> None:
            terminal_started.set()
            try:
                engine.advance(None)
            except BaseException as error:
                terminal_errors.append(error)

        boot._publish_serving_wrapper_v3 = paused_publish
        engine._fail = observed_fail
        admission_thread = threading.Thread(target=admit)
        terminal_thread = threading.Thread(target=terminate)
        try:
            admission_thread.start()
            self.assertTrue(publication_entered.wait(5))
            terminal_thread.start()
            self.assertTrue(terminal_started.wait(5))
            self.assertFalse(terminal_mutation_entered.wait(0.5))
        finally:
            release_publication.set()
            boot._publish_serving_wrapper_v3 = original_publish
        for thread in (admission_thread, terminal_thread):
            thread.join(5)
            self.assertFalse(thread.is_alive())

        self.assertFalse(admission_errors)
        self.assertEqual(len(admitted), 1)
        self.assertEqual(len(terminal_errors), 1)
        self.assertIsInstance(terminal_errors[0], ApplianceErrorV3)
        self.assertTrue(terminal_mutation_entered.is_set())
        self.assertTrue(admitted[0]._resource.revoked)
        self.assertEqual(engine._state, boot.BootTransitionStateV3.FAILED_NON_SERVING)

    def test_m_direct_duplicate_barrier_consume_invalidates_engine_admission(self) -> None:
        engine = _engine_at_serving()
        barrier = _consume_production_readiness(engine)
        completion = barrier._completion
        self.assertIs(completion, engine._launch_readiness_consumed_completion)
        with self.assertRaises(ApplianceErrorV3):
            barrier.consume(
                completion, controller_epoch=EPOCH, controller_terminal=False,
            )
        self.assertEqual(barrier.state, "failed")
        self.assertEqual(engine._state, boot.BootTransitionStateV3.FAILED_NON_SERVING)
        with self.assertRaises(ApplianceErrorV3):
            engine.admit_serving_authority()
        self.assertIsNone(engine._serving_authority)

        published_engine = _engine_at_serving()
        published_barrier = _consume_production_readiness(published_engine)
        published_completion = published_barrier._completion
        wrapper = published_engine.admit_serving_authority()
        with self.assertRaises(ApplianceErrorV3):
            published_barrier.consume(
                published_completion, controller_epoch=EPOCH, controller_terminal=False,
            )
        self.assertEqual(
            published_engine._state, boot.BootTransitionStateV3.FAILED_NON_SERVING,
        )
        self.assertTrue(wrapper._resource.revoked)

    def test_n_credential_fields_reject_equality_forging_objects(self) -> None:
        identity = _identities()[0]
        for field_name in ("pid", "uid", "gid"):
            values: dict[str, object] = {
                "pid": identity.pid,
                "uid": identity.uid,
                "gid": identity.gid,
            }
            values[field_name] = EqualityForgingEpoch()
            credential = boot.ReadinessProcessCredentialsV3(
                values["pid"], values["uid"], values["gid"],
            )
            barrier = _barrier()
            barrier.next_probe(
                controller_epoch=EPOCH, controller_terminal=False, now_ns=START_NS,
            )
            with self.subTest(field=field_name):
                with self.assertRaises(ApplianceErrorV3):
                    barrier.accept_result(
                        role=identity.role,
                        datagram=_datagram(
                            0, _standalone_result(0), credentials=(credential,),
                        ),
                        controller_epoch=EPOCH, controller_terminal=False,
                    now_ns=START_NS + 1,
                )
            self.assertEqual(barrier.state, "failed")

    def test_o_identity_constructor_rejects_forged_standalone_role_ids(self) -> None:
        identities = _identities()
        for invalid_role_id in (True, EqualityForgingEpoch()):
            changed = list(identities)
            changed[0] = dataclasses.replace(
                identities[0], role_id=invalid_role_id,
            )
            with self.subTest(invalid_type=type(invalid_role_id).__name__):
                with self.assertRaises(ApplianceErrorV3):
                    boot.LaunchReadinessBarrierV3(
                        controller_epoch=EPOCH,
                        census_start_ns=START_NS,
                        expected_identities=tuple(changed),
                    )

    def test_p_identity_constructor_checks_member_and_role_types_before_equality(self) -> None:
        identities = _identities()
        raw_member = list(identities)
        raw_member[0] = RolePropertyTrap()
        with self.assertRaises(ApplianceErrorV3):
            boot.LaunchReadinessBarrierV3(
                controller_epoch=EPOCH,
                census_start_ns=START_NS,
                expected_identities=tuple(raw_member),
            )

        forged_role = list(identities)
        forged_role[0] = dataclasses.replace(
            identities[0], role=EqualityForgingEpoch(),
        )
        with self.assertRaises(ApplianceErrorV3):
            boot.LaunchReadinessBarrierV3(
                controller_epoch=EPOCH,
                census_start_ns=START_NS,
                expected_identities=tuple(forged_role),
            )


class ClosureAndDeletionTests(unittest.TestCase):
    def test_a_launch_sources_are_exact_executable_graph_nodes(self) -> None:
        docs, contract = build_v3_fixture()
        binding = boot.bind_boot_inputs_v3(contract=contract, **docs)
        source_paths = tuple(row["source_path"] for row in oracle.LAUNCH_ROWS)
        node_paths = {
            node.path for node in binding.predicate5.executable_graph.nodes
            if hasattr(node, "path")
        }
        self.assertEqual(set(source_paths) - node_paths, set())
        self.assertEqual(tuple(role.authority.source_path for role in binding.launch_projection.roles), source_paths)

    def test_b_temporary_coherent_delete_fails_oracle_and_issuance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="spp-a31b-delete-") as temporary:
            copy_root = Path(temporary) / "conf-proc"
            shutil.copytree(
                ROOT, copy_root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".venv"),
            )
            table_path = copy_root / "conf_proc_spp_boot_v3_tables.py"
            table_source = table_path.read_text(encoding="utf-8")
            start = table_source.index("    # COHERENT_DELETE_COLLECTOR_START")
            end_marker = "    # COHERENT_DELETE_COLLECTOR_END\n"
            end = table_source.index(end_marker, start) + len(end_marker)
            table_path.write_text(table_source[:start] + table_source[end:], encoding="utf-8")

            ordinary_path = copy_root / "test" / "conf-proc-spp-boot-v3-launch-selftest.py"
            ordinary = ordinary_path.read_text(encoding="utf-8")
            test_start = ordinary.index("    # COHERENT_DELETE_COLLECTOR_TEST_START")
            test_end_marker = "    # COHERENT_DELETE_COLLECTOR_TEST_END\n"
            test_end = ordinary.index(test_end_marker, test_start) + len(test_end_marker)
            ordinary_path.write_text(ordinary[:test_start] + ordinary[test_end:], encoding="utf-8")

            checker = r'''
import sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "test"))
import conf_proc_spp_boot_v3 as boot
import conf_proc_spp_boot_v3_tables as tables
import conf_proc_spp_boot_v3_readiness_oracle as oracle
from conf_proc_spp_boot_v3_fixture import build_v3_fixture
oracle_failed = len(tables.LAUNCH_ROLE_ROWS_V3) != len(oracle.LAUNCH_ROWS)
print("ORACLE_DENOMINATOR_FAIL" if oracle_failed else "ORACLE_UNEXPECTED_PASS")
try:
    docs, contract = build_v3_fixture()
    boot.bind_boot_inputs_v3(contract=contract, **docs)
except BaseException:
    issuance_failed = True
else:
    issuance_failed = False
print("EXECUTABLE_ISSUANCE_FAIL" if issuance_failed else "EXECUTABLE_ISSUANCE_UNEXPECTED_PASS")
raise SystemExit(9 if oracle_failed and issuance_failed else 0)
'''
            completed = subprocess.run(
                [sys.executable, "-c", checker, str(copy_root)],
                cwd=copy_root,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(completed.returncode, 9, completed.stdout + completed.stderr)
            self.assertIn("ORACLE_DENOMINATOR_FAIL", completed.stdout)
            self.assertIn("EXECUTABLE_ISSUANCE_FAIL", completed.stdout)
            self.assertEqual(
                (copy_root / "test" / "conf_proc_spp_boot_v3_readiness_oracle.py").read_bytes(),
                (ROOT / "test" / "conf_proc_spp_boot_v3_readiness_oracle.py").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
