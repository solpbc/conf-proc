#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Focused authority KATs for the v3 launch and declarative wire tables."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

import conf_proc_spp_boot_v3 as boot
import conf_proc_spp_boot_v3_semantics as semantics
import conf_proc_spp_boot_v3_tables as tables
from conf_proc_spp_boot_v3_fixture import build_v3_fixture
from conf_proc_spp_reasons_v3 import ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION


def _tuple(*fields: object) -> tuple[object, ...]:
    return tuple(fields)


_EXPECTED_PROCESS_AUTHORITY = _tuple(
    _tuple("unit:spp.service"),
    _tuple(
        _tuple("asr", "interpreter", "/usr/bin/python3.10", "ebad5b838937791ccc924214b1db8316ed73019852b578db62343dc28d98ff9a", _tuple("/usr/bin/python3.10", "-I", "-B", "-S", "/usr/lib/spp/conf_proc_spp_role_bootstrap.py", "--role=asr"), "loopback", _tuple(), "runtime-python310"),
        _tuple("attestation-broker", "interpreter", "/usr/bin/python3.10", "ebad5b838937791ccc924214b1db8316ed73019852b578db62343dc28d98ff9a", _tuple("/usr/bin/python3.10", "-I", "-B", "-S", "/usr/lib/spp/conf_proc_spp_role_bootstrap.py", "--role=attestation-broker"), "none", _tuple(), "runtime-python310"),
        _tuple("collector", "interpreter", "/usr/bin/python3.10", "ebad5b838937791ccc924214b1db8316ed73019852b578db62343dc28d98ff9a", _tuple("/usr/bin/python3.10", "-I", "-B", "-S", "/usr/lib/spp/conf_proc_spp_role_bootstrap.py", "--role=collector"), "none", _tuple(), "runtime-python310"),
        _tuple("exec:/usr/bin/spp", "exec", "/usr/bin/spp", "725c546b990dd1b41f3d5791b37c3c0edcb1f08cf150bdae32a73dfd166e02d7", _tuple("/usr/bin/spp"), "none", _tuple(), "stub"),
        _tuple("gateway", "interpreter", "/usr/bin/python3.10", "ebad5b838937791ccc924214b1db8316ed73019852b578db62343dc28d98ff9a", _tuple("/usr/bin/python3.10", "-I", "-B", "-S", "/usr/lib/spp/conf_proc_spp_role_bootstrap.py", "--role=gateway"), "loopback", _tuple(), "runtime-python310"),
        _tuple("inference", "interpreter", "/usr/bin/python3.10", "ebad5b838937791ccc924214b1db8316ed73019852b578db62343dc28d98ff9a", _tuple("/usr/bin/python3.10", "-I", "-B", "-S", "/usr/lib/spp/conf_proc_spp_role_bootstrap.py", "--role=inference"), "loopback", _tuple(), "runtime-python310"),
        _tuple("unit:spp.service", "unit", "spp.service", None, _tuple(), "none", _tuple(), None),
    ),
    _tuple(
        _tuple("unit:spp.service", "asr", "script_interpreter", "/usr/lib/spp/asr_shim.py", "stage2-launch"),
        _tuple("unit:spp.service", "attestation-broker", "script_interpreter", "/usr/lib/spp/conf_proc_spp_attestation_broker.py", "stage2-launch"),
        _tuple("unit:spp.service", "collector", "script_interpreter", "/usr/lib/spp/ratls_collector.py", "stage2-launch"),
        _tuple("unit:spp.service", "exec:/usr/bin/spp", "unit_exec", "spp.service", "ExecStart"),
        _tuple("unit:spp.service", "gateway", "script_interpreter", "/usr/lib/spp/ratls_gateway.py", "stage2-launch"),
        _tuple("unit:spp.service", "inference", "script_interpreter", "/usr/lib/spp/conf_proc_spp_inference.py", "stage2-launch"),
    ),
    _tuple(
        _tuple("asr", "loopback"), _tuple("attestation-broker", "none"),
        _tuple("collector", "none"), _tuple("exec:/usr/bin/spp", "none"),
        _tuple("gateway", "loopback"), _tuple("inference", "loopback"),
        _tuple("unit:spp.service", "none"),
    ),
    _tuple(
        _tuple("asr", _tuple(), _tuple(), True), _tuple("attestation-broker", _tuple(), _tuple(), True),
        _tuple("collector", _tuple(), _tuple(), True), _tuple("gateway", _tuple(), _tuple(), True),
        _tuple("inference", _tuple(), _tuple(), True),
    ),
)
_EXPECTED_PROCESS_AUTHORITY_FRAME_SHA256 = "4f29ee11e7444c1fafd623273fceb95ebf6009885cc7cac440f079790b237c1c"


class BootV3LaunchAuthoritySelftest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.docs, cls.contract = build_v3_fixture()
        cls.binding = boot.bind_boot_inputs_v3(contract=cls.contract, **cls.docs)

    @classmethod
    def _parsed(cls) -> semantics.ParsedPredecessorsV3:
        return semantics.parse_predecessors_v3(
            root_lock_bytes=cls.docs["root_lock_bytes"], runtime_closure_bytes=cls.docs["runtime_closure_bytes"],
            verity_rules_bytes=cls.docs["verity_rules_bytes"], tcb_identity_bytes=cls.docs["tcb_identity_bytes"],
            builder_source_bytes=cls.docs["builder_source_bytes"], policy_bytes=cls.docs["policy_bytes"],
            accepted_manifest_bytes=cls.docs["accepted_manifest_bytes"], kernel_feature_contract_bytes=cls.docs["kernel_feature_contract_bytes"],
            trusted_certificate_bundle_bytes=cls.docs["trusted_certificate_bundle_bytes"], module_plan_bytes=cls.docs["module_plan_bytes"],
            gpt_layout_rules_bytes=cls.docs["gpt_layout_rules_bytes"],
        )

    def test_five_roles_are_predecessor_projected(self) -> None:
        projection = self.binding.launch_projection
        self.assertEqual(tuple(item.authority.role for item in projection.roles), (
            "attestation-broker", "inference", "asr", "gateway", "collector",
        ))
        self.assertEqual(
            tuple(item.source.runtime_closure_role for item in projection.roles),
            ("runtime_tree_input",) * 5,
        )
        self.assertEqual(
            tuple(item.source.content_class for item in projection.roles),
            ("executable",) * 5,
        )
        self.assertEqual(len({item.source.source_input_id for item in projection.roles}), 5)
        for item in projection.roles:
            self.assertEqual(item.authority.expected_process_capabilities, ())
            self.assertEqual(item.authority.expected_capability_bounding_set, ())
            self.assertEqual(item.authority.expected_ambient_capabilities, ())
            self.assertTrue(item.authority.expected_no_new_privileges)

    def _assert_graph_rejected(self, parsed: semantics.ParsedPredecessorsV3) -> None:
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION):
            semantics._launch_projection_v3(parsed)

    def test_exact_process_authority_projection_and_measurement_frame(self) -> None:
        process = self.binding.process_authority
        self.assertEqual(
            (
                process.boot_roots,
                process.process_nodes,
                process.process_edges,
                process.network_policy,
                process.capability_policy,
            ),
            _EXPECTED_PROCESS_AUTHORITY,
        )
        self.assertEqual((len(process.process_nodes), len(process.process_edges)), (7, 6))
        self.assertEqual((len(process.network_policy), len(process.capability_policy)), (7, 5))
        frame = ("process_authority", * _EXPECTED_PROCESS_AUTHORITY)
        frame_bytes = repr(frame).encode("utf-8")
        self.assertEqual(
            hashlib.sha256(frame_bytes).hexdigest(),
            _EXPECTED_PROCESS_AUTHORITY_FRAME_SHA256,
        )
        self.assertIn(frame_bytes, self.binding.literal_v3_observation_shape_bytes)
        self.assertLess(
            self.binding.literal_v3_observation_shape_bytes.index(frame_bytes),
            self.binding.literal_v3_observation_shape_bytes.rindex(b"('wire_message_types',"),
        )
        self.assertNotEqual(
            boot._literal_v3_observation_shape_bytes(
                replace(process, boot_roots=("exec:/usr/bin/spp",))
            ),
            self.binding.literal_v3_observation_shape_bytes,
        )

    def test_exact_process_authority_mutations_are_rejected(self) -> None:
        node_mutations = {
            "id": "z-extra", "kind": "exec", "path": "/bad", "sha256": "0" * 64,
            "argv": ("/bad",), "network_scope": "none", "capabilities": ("CAP_NET_ADMIN",),
            "source_input_id": "other-input",
        }
        for field, replacement in node_mutations.items():
            with self.subTest(node_field=field):
                parsed = self._parsed()
                node = next(value for value in parsed.policy.process_nodes if value.id == "asr")
                object.__setattr__(parsed.policy, "process_nodes", tuple(
                    replace(value, **{field: replacement}) if value is node else value
                    for value in parsed.policy.process_nodes
                ))
                self._assert_graph_rejected(parsed)

        edge_mutations = {
            "from_id": "exec:/usr/bin/spp", "to_id": "gateway", "kind": "unit_exec",
            "origin_path": "spp.service", "origin_key": "ExecStart",
        }
        for field, replacement in edge_mutations.items():
            with self.subTest(edge_field=field):
                parsed = self._parsed()
                edge = next(value for value in parsed.policy.process_edges if value.to_id == "asr")
                object.__setattr__(parsed.policy, "process_edges", tuple(
                    replace(value, **{field: replacement}) if value is edge else value
                    for value in parsed.policy.process_edges
                ))
                self._assert_graph_rejected(parsed)

        parsed = self._parsed()
        role_edges = [edge for edge in parsed.policy.process_edges if edge.kind == "script_interpreter"]
        swapped_paths = {edge.to_id: path for edge, path in zip(role_edges, reversed([edge.origin_path for edge in role_edges]), strict=True)}
        object.__setattr__(parsed.policy, "process_edges", tuple(
            replace(edge, origin_path=swapped_paths[edge.to_id]) if edge.to_id in swapped_paths else edge
            for edge in parsed.policy.process_edges
        ))
        self._assert_graph_rejected(parsed)

        for mutation in ("remove_node", "duplicate_node", "extra_node", "remove_edge", "duplicate_edge", "extra_edge"):
            with self.subTest(cardinality=mutation):
                parsed = self._parsed()
                if mutation.endswith("node"):
                    values = list(parsed.policy.process_nodes)
                    if mutation == "remove_node":
                        values.pop()
                    elif mutation == "duplicate_node":
                        values.append(values[0])
                    else:
                        values.append(replace(values[0], id="z-extra"))
                    object.__setattr__(parsed.policy, "process_nodes", tuple(values))
                else:
                    values = list(parsed.policy.process_edges)
                    if mutation == "remove_edge":
                        values.pop()
                    elif mutation == "duplicate_edge":
                        values.append(values[0])
                    else:
                        values.append(replace(values[0], to_id="z-extra", origin_path="/z-extra"))
                    object.__setattr__(parsed.policy, "process_edges", tuple(values))
                self._assert_graph_rejected(parsed)

        parsed = self._parsed()
        object.__setattr__(parsed.policy, "boot_roots", ("exec:/usr/bin/spp",))
        self._assert_graph_rejected(parsed)

        for mutation in ("network_value", "network_missing", "network_extra", "capability_bounding", "capability_ambient", "capability_nnp", "capability_missing", "capability_extra"):
            with self.subTest(policy=mutation):
                parsed = self._parsed()
                if mutation.startswith("network"):
                    values = dict(parsed.policy.network_policy)
                    if mutation == "network_value":
                        values["gateway"] = "none"
                    elif mutation == "network_missing":
                        del values["gateway"]
                    else:
                        values["z-extra"] = "none"
                    object.__setattr__(parsed.policy, "network_policy", values)
                else:
                    values = dict(parsed.policy.capability_policy)
                    if mutation == "capability_bounding":
                        values["gateway"] = replace(values["gateway"], capability_bounding_set=("CAP_NET_ADMIN",))
                    elif mutation == "capability_ambient":
                        values["gateway"] = replace(values["gateway"], ambient_capabilities=("CAP_NET_ADMIN",))
                    elif mutation == "capability_nnp":
                        values["gateway"] = replace(values["gateway"], no_new_privileges=False)
                    elif mutation == "capability_missing":
                        del values["gateway"]
                    else:
                        values["z-extra"] = values["gateway"]
                    object.__setattr__(parsed.policy, "capability_policy", values)
                self._assert_graph_rejected(parsed)

    def test_role_operational_literals_and_policy_agreement_are_closed(self) -> None:
        original_rows = tables.LAUNCH_ROLE_ROWS_V3
        row = original_rows[1]
        tables.LAUNCH_ROLE_ROWS_V3 = (original_rows[0], replace(row, argv=("/wrong",)), *original_rows[2:])
        try:
            with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION):
                boot.bind_boot_inputs_v3(contract=self.contract, **self.docs)
        finally:
            tables.LAUNCH_ROLE_ROWS_V3 = original_rows

        parsed = self._parsed()
        inference = next(node for node in parsed.policy.process_nodes if node.id == "inference")
        object.__setattr__(parsed.policy, "process_nodes", tuple(
            replace(node, network_scope="none") if node is inference else node
            for node in parsed.policy.process_nodes
        ))
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION):
            semantics._launch_projection_v3(parsed)

    def test_bootstrap_and_controller_sources_require_every_predecessor_projection(self) -> None:
        self.assertEqual(
            self.binding.predicate5.bootstrap_source.path,
            "/usr/lib/spp/conf_proc_spp_role_bootstrap.py",
        )
        self.assertEqual(
            self.binding.stage2_controller.source.path,
            "/usr/lib/spp/conf_proc_spp_init.py",
        )
        self.assertEqual(
            (
                self.binding.stage2_controller.source.size_bytes,
                self.binding.stage2_controller.source.sha256,
            ),
            (
                4604,
                "32b7c8f5b6772f52433adcca11051ad1e883bb59aa4f7c66116e43a379bd1dd3",
            ),
        )
        parsed = self._parsed()
        object.__setattr__(parsed.lock, "inputs", tuple(item for item in parsed.lock.inputs if item.id != "runtime-stage2-controller"))
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION):
            semantics._launch_projection_v3(parsed)
        mutations = (
            "lock",
            "policy",
            "manifest",
            "runtime_closure",
            "duplicate_runtime_closure",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                parsed = self._parsed()
                path = "/usr/lib/spp/conf_proc_spp_role_bootstrap.py"
                if mutation == "lock":
                    object.__setattr__(parsed.lock, "inputs", tuple(item for item in parsed.lock.inputs if item.id != "runtime-role-bootstrap"))
                elif mutation == "policy":
                    image = parsed.policy.images["runtime-policy"]
                    parsed.policy.images["runtime-policy"] = replace(image, nodes=tuple(node for node in image.nodes if node.path != path))
                elif mutation == "manifest":
                    parsed.manifest.raw["inventory"]["runtime-policy"] = [item for item in parsed.manifest.raw["inventory"]["runtime-policy"] if item["path"] != path]
                else:
                    entries = parsed.runtime_closure["entries"]
                    entry = next(item for item in entries if item["path"] == path)
                    if mutation == "runtime_closure":
                        entries.remove(entry)
                    else:
                        entries.append(dict(entry))
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION):
                    semantics._runtime_source_projection_v3(parsed, path=path, label="role bootstrap")

        parsed = self._parsed()
        service = next(item for item in parsed.runtime_closure["entries"] if item["path"] == "/usr/lib/spp/conf_proc_spp_inference.py")
        service["logical_role"] = "conf_proc_source"
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION):
            semantics._launch_projection_v3(parsed)

    def test_controller_source_bytes_must_match_packaged_authority(self) -> None:
        docs, contract = build_v3_fixture(
            controller_source_bytes=b"stage2-controller-source",
        )
        with self.assertRaisesRegex(
            ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION,
        ):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

    def test_gateway_and_controller_literal_agreements_are_measured(self) -> None:
        parsed = self._parsed()
        capabilities = dict(parsed.policy.capability_policy)
        capabilities["gateway"] = replace(capabilities["gateway"], capability_bounding_set=("CAP_NET_ADMIN",))
        object.__setattr__(parsed.policy, "capability_policy", capabilities)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION):
            semantics._launch_projection_v3(parsed)

        parsed = self._parsed()
        gateway = next(node for node in parsed.policy.process_nodes if node.id == "gateway")
        object.__setattr__(parsed.policy, "process_nodes", tuple(replace(node, network_scope="none") if node is gateway else node for node in parsed.policy.process_nodes))
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_LAUNCH_SUPERVISION):
            semantics._launch_projection_v3(parsed)

        baseline = boot._literal_v3_observation_shape_bytes(self.binding.process_authority)
        original_rows = tables.LAUNCH_ROLE_ROWS_V3
        original_controller = tables.STAGE2_CONTROLLER_ROW_V3
        try:
            gateway_row = original_rows[3]
            tables.LAUNCH_ROLE_ROWS_V3 = (*original_rows[:3], replace(gateway_row, upstream_policy="non_loopback"), *original_rows[4:])
            self.assertNotEqual(boot._literal_v3_observation_shape_bytes(self.binding.process_authority), baseline)
            tables.LAUNCH_ROLE_ROWS_V3 = original_rows
            tables.STAGE2_CONTROLLER_ROW_V3 = replace(original_controller, initial_capabilities=original_controller.initial_capabilities[:-1])
            self.assertNotEqual(boot._literal_v3_observation_shape_bytes(self.binding.process_authority), baseline)
            tables.STAGE2_CONTROLLER_ROW_V3 = replace(original_controller, steady_capabilities=(*original_controller.steady_capabilities, "CAP_NET_BIND_SERVICE"))
            self.assertNotEqual(boot._literal_v3_observation_shape_bytes(self.binding.process_authority), baseline)
        finally:
            tables.LAUNCH_ROLE_ROWS_V3 = original_rows
            tables.STAGE2_CONTROLLER_ROW_V3 = original_controller

    def test_readiness_literal_shape_covers_exact_buffers(self) -> None:
        readiness = tables.LAUNCH_ROLE_ROWS_V3[0].readiness
        assert readiness is not None
        request = readiness.request_magic + b"\0" * (readiness.request_bytes - len(readiness.request_magic))
        result = readiness.result_magic + b"\0" * (readiness.result_bytes - len(readiness.result_magic))
        self.assertEqual((len(request), len(result)), (32, 80))
        self.assertNotEqual(bytes([request[0] ^ 1]) + request[1:], request)
        self.assertNotEqual(bytes([result[0] ^ 1]) + result[1:], result)
        baseline = boot._literal_v3_observation_shape_bytes(self.binding.process_authority)
        original_rows = tables.LAUNCH_ROLE_ROWS_V3
        try:
            row = original_rows[0]
            assert row.readiness is not None
            tables.LAUNCH_ROLE_ROWS_V3 = (replace(row, readiness=replace(row.readiness, request_magic=b"BADRDQ3\0")), *original_rows[1:])
            self.assertNotEqual(boot._literal_v3_observation_shape_bytes(self.binding.process_authority), baseline)
        finally:
            tables.LAUNCH_ROLE_ROWS_V3 = original_rows

    def test_controller_fd5_and_readiness_literals_are_measured(self) -> None:
        controller = tables.STAGE2_CONTROLLER_ROW_V3
        self.assertEqual(tuple(row.fd for row in controller.exec_fd_census), (0, 1, 2, 3, 4, 5, 6))
        self.assertIn("bounded_broker_TPM_transfer", controller.exec_fd_census[5].purpose)
        self.assertIn("close_pid1_copy_prove_absence", controller.exec_fd_census[5].stage2_action)
        self.assertEqual(controller.exec_fd_census[6].purpose, "predicate5_trace")
        self.assertIn("unissuable", controller.exec_fd_census[6].stage2_action)
        self.assertEqual(controller.entitlement_dns[0], ("hostname", "services.solstone.app"))
        self.assertEqual(controller.entitlement_dns[1], ("resolver", "168.63.129.16:53"))
        self.assertIn("CAP_SYS_BOOT", controller.initial_capabilities)
        self.assertIn("CAP_SETPCAP", controller.initial_capabilities)
        self.assertIn("CAP_SYS_PTRACE", controller.initial_capabilities)
        self.assertNotIn("CAP_NET_BIND_SERVICE", controller.steady_capabilities)
        self.assertNotIn("CAP_SETPCAP", controller.steady_capabilities)
        for row in tables.LAUNCH_ROLE_ROWS_V3[:3]:
            readiness = row.readiness
            assert readiness is not None
            self.assertEqual((readiness.request_magic, readiness.result_magic), (b"SPPRDQ3\0", b"SPPRDR3\0"))
            self.assertEqual((readiness.request_bytes, readiness.result_bytes), (32, 80))
            self.assertEqual((readiness.clock, readiness.deadline_unit, readiness.ancillary_fd_rule), ("CLOCK_MONOTONIC", "nanoseconds", "no_ancillary_fd"))
        self.assertEqual(tables.LAUNCH_ROLE_ROWS_V3[0].pipe_census[0].detection_bytes, 1)
        self.assertEqual(tables.LAUNCH_ROLE_ROWS_V3[-1].pipe_census[0].census_budget_bytes, 8388608)

    # COHERENT_DELETE_COLLECTOR_TEST_START
    def test_collector_launch_row_has_its_bounded_transient_shape(self) -> None:
        collector = tables.LAUNCH_ROLE_ROWS_V3[4]
        self.assertEqual(collector.role, "collector")
        self.assertEqual(collector.cardinality, "zero_or_one_transient")
        self.assertEqual(tuple(row.fd for row in collector.fd_surface), (0, 1, 2))
        self.assertEqual(collector.pipe_census[0].census_budget_bytes, 8388608)
        self.assertIsNone(collector.readiness)
    # COHERENT_DELETE_COLLECTOR_TEST_END

    def test_every_wire_row_and_constraint_is_measured(self) -> None:
        original = tables.WIRE_MESSAGE_AUTHORITY_ROWS_V3
        baseline = boot._literal_v3_observation_shape_bytes(self.binding.process_authority)
        self.assertEqual(tuple(row.type_id for row in original), tuple(range(1, 28)))
        self.assertEqual(tuple(row.type_id for row in original if row.fd_rule != "no_fd"), (1, 25))
        try:
            for index, row in enumerate(original):
                changed = list(original)
                changed[index] = replace(row, prerequisite=row.prerequisite + "_mutated")
                tables.WIRE_MESSAGE_AUTHORITY_ROWS_V3 = tuple(changed)
                with self.subTest(type_id=row.type_id):
                    self.assertNotEqual(boot._literal_v3_observation_shape_bytes(self.binding.process_authority), baseline)
            for index, row in ((0, original[0]), (2, original[2]), (24, original[24])):
                changed = list(original)
                changed[index] = replace(row, payload_shape=(replace(row.payload_shape[0], name="mutated_field"), *row.payload_shape[1:]))
                tables.WIRE_MESSAGE_AUTHORITY_ROWS_V3 = tuple(changed)
                with self.subTest(payload_type_id=row.type_id):
                    self.assertNotEqual(boot._literal_v3_observation_shape_bytes(self.binding.process_authority), baseline)
            changed = list(original)
            changed[0] = replace(original[0], fd_rule="no_fd", direction="gateway->PID1", type_id=99)
            tables.WIRE_MESSAGE_AUTHORITY_ROWS_V3 = tuple(changed)
            self.assertNotEqual(boot._literal_v3_observation_shape_bytes(self.binding.process_authority), baseline)
        finally:
            tables.WIRE_MESSAGE_AUTHORITY_ROWS_V3 = original
        original_routes = tables.WIRE_ROUTE_ENUM_ROWS_V3
        tables.WIRE_ROUTE_ENUM_ROWS_V3 = (replace(original_routes[0], name="mutated"), *original_routes[1:])
        try:
            self.assertNotEqual(boot._literal_v3_observation_shape_bytes(self.binding.process_authority), baseline)
        finally:
            tables.WIRE_ROUTE_ENUM_ROWS_V3 = original_routes
        self.assertEqual(tables.WIRE_HEADER_BYTES_V3, 72)
        self.assertEqual(tables.WIRE_HAS_FD_TYPE_IDS_V3, (1, 25))
        self.assertIn("0xffffffff", tables.WIRE_SEQUENCE_RULE_V3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
