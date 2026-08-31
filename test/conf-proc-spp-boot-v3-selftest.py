#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Focused self-tests for SPP boot authority v3 document binding."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from conf_proc_json import canonical_dumps
from conf_proc_json import canonical_loads
from conf_proc_spp_boot_dispatch_v3 import parse_boot_contract_document_v3
import conf_proc_spp_boot_v3 as boot_v3
from conf_proc_spp_boot_v3_resource import ServingAuthorityWrapperV3
import conf_proc_spp_boot_v3_tables as tables
from conf_proc_spp_boot_v3 import (
    AuthorityStepReadbackV3,
    BOOT_CONTRACT_V3_SCHEMA,
    BootBindingV3,
    BootTransitionEngineV3,
    BootTransitionStateV3,
    FailureControllerReadbackV3,
    FailureControllerV3,
    FailureStageV3,
    bind_boot_inputs_v3,
    is_issued_boot_binding_v3,
    parse_boot_contract_v3,
)
from conf_proc_spp_reasons_v3 import ApplianceErrorV3, CP_BOOT_V3_BINDING
from conf_proc_spp_boot_v3_fixture import (
    build_v3_fixture,
    install_consumed_readiness_for_test,
    refresh_v3_contract_bindings,
)


_INPUT_NAMES = (
    "root_lock_bytes",
    "runtime_closure_bytes",
    "verity_rules_bytes",
    "tcb_identity_bytes",
    "builder_source_bytes",
    "policy_bytes",
    "accepted_manifest_bytes",
    "kernel_feature_contract_bytes",
    "trusted_certificate_bundle_bytes",
    "module_plan_bytes",
    "gpt_layout_rules_bytes",
)
def _fixture() -> tuple[dict[str, bytes], object]:
    return build_v3_fixture()


def _bind(inputs: dict[str, bytes], contract: object):
    return bind_boot_inputs_v3(contract=contract, **inputs)


class _AuthorityTransport:
    def __init__(self) -> None:
        self.effects: list[object] = []

    def execute(self, effect: object) -> object:
        self.effects.append(effect)
        assert type(effect) is boot_v3.AuthorityStepEffectV3
        observed = effect.expected if effect.expected is not None else ("present", effect.action)
        if effect.state is BootTransitionStateV3.PCR15_EXTENDED:
            observed = boot_v3.Pcr15ExtendOutcome.ACKNOWLEDGED
        return AuthorityStepReadbackV3(
            effect.contract_sha256, effect.state, effect.action, observed
        )


class _FailureTransport:
    def __init__(self, *, confirmed: bool = False, raises: bool = False, stages: list[object] | None = None, controller: object = None) -> None:
        self.confirmed = confirmed
        self.raises = raises
        self.stages = stages
        self.controller = controller
        self.calls: list[str] = []

    def execute(self, effect: object) -> object:
        assert type(effect) is boot_v3.FailureControllerEffectV3
        self.calls.append(effect.action)
        if self.stages is not None:
            self.stages.append(self.controller.stage)
        if self.raises:
            raise RuntimeError("transport failure")
        return FailureControllerReadbackV3(effect.contract_sha256, effect.action, self.confirmed)


class BootAuthorityV3SelfTest(unittest.TestCase):
    def test_parse_bind_and_issued_marker(self) -> None:
        inputs, contract = _fixture()
        parsed = parse_boot_contract_document_v3(inputs["boot_contract_bytes"])
        self.assertEqual(parsed, contract)
        binding = _bind(inputs, contract)
        self.assertTrue(is_issued_boot_binding_v3(binding))
        hand_constructed = BootBindingV3(
            binding.root_lock_bytes,
            binding.runtime_closure_bytes,
            binding.verity_rules_bytes,
            binding.tcb_identity_bytes,
            binding.builder_source_bytes,
            binding.policy_bytes,
            binding.accepted_manifest_bytes,
            binding.kernel_feature_contract_bytes,
            binding.trusted_certificate_bundle_bytes,
            binding.boot_contract_bytes,
            binding.module_plan_bytes,
            binding.gpt_layout_rules_bytes,
            binding.literal_v3_observation_shape_bytes,
            binding.boot_contract,
            binding.source_digests,
            binding.storage,
            binding.kernel_identity,
            binding.module_authority,
            binding.control_inventory,
            binding.launch_projection,
            binding.stage2_controller,
            binding.process_authority,
            binding.predicate5,
        )
        self.assertFalse(is_issued_boot_binding_v3(hand_constructed))
        with self.assertRaises(ApplianceErrorV3):
            BootTransitionEngineV3(hand_constructed)

    def test_each_cross_document_reference_mismatch_rejects(self) -> None:
        inputs, contract = _fixture()
        for name in _INPUT_NAMES:
            with self.subTest(name=name):
                mismatched = dict(inputs)
                mismatched[name] += b"-wrong"
                with self.assertRaises(ApplianceErrorV3) as raised:
                    _bind(mismatched, contract)
                self.assertEqual(raised.exception.reason_code, CP_BOOT_V3_BINDING)

    def test_dispatcher_rejects_predecessor_and_malformed_documents(self) -> None:
        for schema in (
            "conf-proc-spp-boot-contract/v1",
            "conf-proc-spp-boot-contract/v2",
        ):
            with self.subTest(schema=schema), self.assertRaises(ApplianceErrorV3):
                parse_boot_contract_document_v3(canonical_dumps({"schema": schema}))
        with self.assertRaises(ApplianceErrorV3):
            parse_boot_contract_document_v3(canonical_dumps({}))
        with self.assertRaises(ApplianceErrorV3):
            parse_boot_contract_document_v3(b"{")

    def test_predecessor_parse_and_semantic_falsifications_reject(self) -> None:
        inputs, contract = _fixture()
        malformed = dict(inputs)
        malformed["policy_bytes"] = b"{}"
        with self.assertRaises(ApplianceErrorV3) as raised:
            _bind(malformed, contract)
        self.assertEqual(raised.exception.reason_code, CP_BOOT_V3_BINDING)

        incoherent = dict(inputs)
        tcb = canonical_loads(incoherent["tcb_identity_bytes"])
        tcb["kernel_feature_contract"]["sha256"] = "0" * 64
        incoherent["tcb_identity_bytes"] = canonical_dumps(tcb)
        refresh_v3_contract_bindings(incoherent)
        with self.assertRaises(ApplianceErrorV3) as raised:
            _bind(incoherent, parse_boot_contract_v3(incoherent["boot_contract_bytes"]))
        self.assertEqual(raised.exception.reason_code, CP_BOOT_V3_BINDING)

    def test_module_plan_binding_is_one_way_and_contract_has_no_plan_hash(self) -> None:
        inputs, contract = _fixture()
        old_contract = canonical_loads(inputs["boot_contract_bytes"])
        old_contract["module_plan_sha256"] = hashlib.sha256(inputs["module_plan_bytes"]).hexdigest()
        with self.assertRaises(ApplianceErrorV3):
            parse_boot_contract_v3(canonical_dumps(old_contract))
        bad_plan = dict(inputs)
        plan = canonical_loads(bad_plan["module_plan_bytes"])
        plan["boot_contract_sha256"] = "0" * 64
        bad_plan["module_plan_bytes"] = canonical_dumps(plan)
        with self.assertRaises(ApplianceErrorV3) as raised:
            _bind(bad_plan, contract)
        self.assertEqual(raised.exception.reason_code, CP_BOOT_V3_BINDING)

    def test_every_measurement_frame_and_closed_table_affects_measurement(self) -> None:
        inputs, contract = _fixture()
        binding = _bind(inputs, contract)
        engine = BootTransitionEngineV3(binding)
        measurement = engine.pcr15_measurement_v3
        frame_names = (
            "root_lock_bytes",
            "runtime_closure_bytes",
            "verity_rules_bytes",
            "tcb_identity_bytes",
            "builder_source_bytes",
            "policy_bytes",
            "accepted_manifest_bytes",
            "kernel_feature_contract_bytes",
            "trusted_certificate_bundle_bytes",
            "boot_contract_bytes",
            "module_plan_bytes",
            "gpt_layout_rules_bytes",
            "literal_v3_observation_shape_bytes",
        )
        for name in frame_names:
            with self.subTest(name=name):
                changed_binding = _bind(inputs, contract)
                changed_engine = BootTransitionEngineV3(changed_binding)
                original = getattr(changed_binding, name)
                object.__setattr__(changed_binding, name, original + b"\0")
                with self.assertRaises(ApplianceErrorV3) as raised:
                    _ = changed_engine.pcr15_measurement_v3
                self.assertEqual(raised.exception.reason_code, CP_BOOT_V3_BINDING)
                object.__setattr__(changed_binding, name, original)
                self.assertFalse(boot_v3.is_issued_boot_binding_v3(changed_binding))
        self.assertEqual(
            engine.predicted_pcr15_v3,
            hashlib.sha256(b"\0" * 32 + measurement).digest(),
        )

        original_late_codes = tables.FAILURE_LATE_CODES_V3
        tables.FAILURE_LATE_CODES_V3 = (*original_late_codes, "test-only-table-mutation")
        try:
            changed = _bind(inputs, contract)
        finally:
            tables.FAILURE_LATE_CODES_V3 = original_late_codes
        self.assertNotEqual(changed.literal_v3_observation_shape_bytes, binding.literal_v3_observation_shape_bytes)
        self.assertNotEqual(BootTransitionEngineV3(changed).pcr15_measurement_v3, measurement)

    @staticmethod
    def _engine() -> BootTransitionEngineV3:
        inputs, contract = _fixture()
        return BootTransitionEngineV3(_bind(inputs, contract))

    @staticmethod
    def _accept_current(engine: BootTransitionEngineV3) -> None:
        effect = engine.next_effect()
        assert effect is not None
        observed = effect.expected if effect.expected is not None else ("present", effect.action)
        if effect.state is BootTransitionStateV3.PCR15_EXTENDED:
            observed = boot_v3.Pcr15ExtendOutcome.ACKNOWLEDGED
        engine.accept(AuthorityStepReadbackV3(effect.contract_sha256, effect.state, effect.action, observed))

    def test_adjacent_boundary_failures_select_distinct_diagnostic_tokens(self) -> None:
        cases = (
            ((0, "pid1"), (1, "adapter")),
            ((1, "adapter"), (2, "runtime_authority")),
            ((10, "runtime_authority"), (11, "root_transition")),
        )
        for earlier, later in cases:
            with self.subTest(earlier=earlier, later=later):
                tokens: list[str | None] = []
                for valid_steps, expected_token in (earlier, later):
                    engine = self._engine()
                    for _ in range(valid_steps):
                        self._accept_current(engine)
                    effect = engine.next_effect()
                    assert effect is not None
                    with self.assertRaises(ApplianceErrorV3):
                        engine.accept(
                            AuthorityStepReadbackV3(
                                effect.contract_sha256,
                                effect.state,
                                effect.action,
                                effect.expected if effect.expected is not None else ("present", effect.action),
                                accepted=False,
                            )
                        )
                    self.assertEqual(engine.failure_diagnostic_token, expected_token)
                    self.assertEqual(engine.state, BootTransitionStateV3.FAILED_NON_SERVING)
                    tokens.append(engine.failure_diagnostic_token)
                self.assertNotEqual(tokens[0], tokens[1])

    def test_admit_serving_authority_rejects_before_serving_available(self) -> None:
        engine = self._engine()
        self.assertIsNone(engine._serving_authority)
        with self.assertRaises(ApplianceErrorV3):
            engine.admit_serving_authority()
        self.assertEqual(engine.state, BootTransitionStateV3.FAILED_NON_SERVING)

    def test_step_order_and_closed_inventory_comparisons(self) -> None:
        engine = self._engine()
        for _ in range(4):
            self._accept_current(engine)
        self.assertEqual(engine.state, BootTransitionStateV3.NIC_CENSUS_ESTABLISHED)
        effect = engine.next_effect()
        assert effect is not None
        with self.assertRaises(ApplianceErrorV3):
            engine.accept(
                AuthorityStepReadbackV3(
                    effect.contract_sha256,
                    BootTransitionStateV3.EARLY_MODULES_LOADED,
                    BootTransitionStateV3.EARLY_MODULES_LOADED.value,
                    boot_v3._EARLY_MODULE_EXPECTED_V3,
                )
            )

        engine = self._engine()
        for _ in range(5):
            self._accept_current(engine)
        self.assertEqual(engine.state, BootTransitionStateV3.EARLY_MODULES_LOADED)
        original_spec = boot_v3._STEP_BY_STATE_V3[BootTransitionStateV3.EARLY_MODULES_LOADED]
        shortened = original_spec.expected[0][:-1]
        boot_v3._STEP_BY_STATE_V3[BootTransitionStateV3.EARLY_MODULES_LOADED] = boot_v3._StepSpecV3(
            original_spec.state,
            original_spec.action,
            (shortened, *original_spec.expected[1:]),
        )
        try:
            effect = engine.next_effect()
            assert effect is not None
            with self.assertRaises(ApplianceErrorV3):
                engine.accept(
                    AuthorityStepReadbackV3(
                        effect.contract_sha256,
                        effect.state,
                        effect.action,
                        boot_v3._EARLY_MODULE_EXPECTED_V3,
                    )
                )
        finally:
            boot_v3._STEP_BY_STATE_V3[BootTransitionStateV3.EARLY_MODULES_LOADED] = original_spec

    def test_failure_controller_never_reports_success(self) -> None:
        controller = FailureControllerV3("adapter")
        with self.assertRaises(ApplianceErrorV3):
            controller._set_late_code("network_close")
        self.assertEqual(controller.render_diagnostic(), "conf-proc-spp-boot-v3: adapter")
        with self.assertRaises(ApplianceErrorV3):
            controller.render_diagnostic()
        close = _FailureTransport()
        self.assertFalse(controller.attempt_network_close(close))
        self.assertFalse(controller.attempt_network_close(close))
        self.assertFalse(controller.attempt_network_close(close))
        self.assertEqual(controller.stage, FailureStageV3.POWEROFF_REQUESTED)
        self.assertEqual(controller.late_code, "network_close")
        with self.assertRaises(ApplianceErrorV3):
            controller.attempt_network_close(close)

        stages: list[object] = []
        poweroff = _FailureTransport(stages=stages, controller=controller)
        controller.dispatch_poweroff(poweroff)
        self.assertEqual(stages, [FailureStageV3.POWEROFF_REQUESTED])
        self.assertEqual(controller.stage, FailureStageV3.FAIL_STOP)
        self.assertEqual(controller.late_code, "poweroff_returned")
        for _ in range(3):
            controller.fail_stop_cycle(
                close_transport=_FailureTransport(),
                deny_all_transport=_FailureTransport(),
                poweroff_transport=_FailureTransport(raises=True),
            )
            self.assertEqual(controller.stage, FailureStageV3.FAIL_STOP)

        raised = FailureControllerV3("adapter")
        raised.render_diagnostic()
        for _ in range(3):
            raised.attempt_network_close(_FailureTransport())
        raised.dispatch_poweroff(_FailureTransport(raises=True))
        self.assertEqual(raised.stage, FailureStageV3.FAIL_STOP)

    def test_full_causal_chain_ends_serving_available(self) -> None:
        engine = self._engine()
        transport = _AuthorityTransport()
        while engine.next_effect() is not None:
            self.assertIsNone(engine._serving_authority)
            engine.advance(transport)
        self.assertEqual(engine.state, BootTransitionStateV3.SERVING_AVAILABLE)
        self.assertEqual(len(transport.effects), len(boot_v3.BOOT_TRANSITION_STEPS_V3))
        self.assertIsNone(engine._serving_authority)
        # The exact launch barrier and its admission connection have their own KAT.
        install_consumed_readiness_for_test(engine)
        wrapper = engine.admit_serving_authority()
        self.assertIsInstance(wrapper, ServingAuthorityWrapperV3)
        self.assertIs(wrapper, engine.admit_serving_authority())
        session = wrapper.open_session(transport, lambda: None)
        self.assertIsNotNone(session)
        wrapper.global_revoke()
        self.assertEqual(engine.state, BootTransitionStateV3.FAILED_NON_SERVING)
        self.assertEqual(engine.failure_diagnostic_token, "serving_integrity")
        self.assertIsNone(engine.next_effect())
        with self.assertRaises(ApplianceErrorV3):
            engine.advance(transport)
        with self.assertRaises(ApplianceErrorV3):
            engine.accept(
                AuthorityStepReadbackV3(
                    engine.contract_sha256,
                    BootTransitionStateV3.SERVING_AVAILABLE,
                    "serving_available",
                    tables.LAUNCH_ROLE_ROWS_V3,
                )
            )


if __name__ == "__main__":
    unittest.main()
