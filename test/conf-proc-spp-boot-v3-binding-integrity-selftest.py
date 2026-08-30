#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Focused issuance, identity, and serving-cleanup tests for SPP boot v3."""

from __future__ import annotations

import copy
import gc
import hashlib
import sys
import threading
import unittest
import weakref
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import conf_proc_spp_boot as boot
import conf_proc_spp_boot_v3 as boot_v3
from conf_proc_json import canonical_dumps
from conf_proc_spp_boot_v3 import (
    BootBindingV3,
    BootTransitionEngineV3,
    BootTransitionStateV3,
    bind_boot_inputs_v3,
    is_issued_boot_binding_v3,
)
from conf_proc_spp_boot_v3_resource import ServingAuthorityWrapperV3
from conf_proc_spp_boot_v3_wire import CollectorGenerationV3, RouteV3, WorkFinishOutcomeV3
from conf_proc_spp_reasons_v3 import (
    ApplianceErrorV3,
    CP_BOOT_V3_BINDING,
    CP_BOOT_V3_RESOURCE_REDUCER,
)
from conf_proc_spp_boot_v3_fixture import build_v3_fixture


def _binding() -> BootBindingV3:
    inputs, contract = build_v3_fixture()
    return bind_boot_inputs_v3(contract=contract, **inputs)


def _engine(*, serving: bool = False) -> BootTransitionEngineV3:
    engine = BootTransitionEngineV3(_binding())
    if serving:
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
    return engine


def _binding_error(test: unittest.TestCase, operation: object) -> None:
    with test.assertRaises(ApplianceErrorV3) as raised:
        assert callable(operation)
        operation()
    test.assertEqual(raised.exception.reason_code, CP_BOOT_V3_BINDING)


def _exact_binding_error(test: unittest.TestCase, operation: object) -> None:
    with test.assertRaises(ApplianceErrorV3) as raised:
        assert callable(operation)
        operation()
    test.assertEqual(raised.exception.reason_code, CP_BOOT_V3_BINDING)
    test.assertEqual(str(raised.exception), "CP_BOOT_V3_BINDING: binding was not issued")


class _SessionTransport:
    def __init__(self, handle: object) -> None:
        self.handle = handle

    def execute(self, effect: boot.BootEffect) -> boot.BootObservation:
        assert type(effect) is boot.ServingSessionEffect
        if effect.action == "credential_observed":
            return boot.CredentialObservedV2(effect.contract_sha256, self.handle, "a" * 64)
        if effect.action == "entitlement_dns_result":
            return boot.EntitlementDnsResultV2(effect.contract_sha256, effect.token, "203.0.113.8", 60)
        if effect.action == "entitlement_tls_connect":
            return boot.EntitlementTlsConnectedV2(
                effect.contract_sha256, effect.token, effect.ipv4_address, 0
            )
        return boot.ServingSessionReadback(effect.contract_sha256, effect.action)


def _walk_non_primitives(value: object, seen: set[int] | None = None):
    if seen is None:
        seen = set()
    value_type = type(value)
    if value is None or value_type in (bool, int, str, bytes):
        return
    if value_type is tuple:
        if id(value) in seen:
            return
        seen.add(id(value))
        for item in value:
            yield from _walk_non_primitives(item, seen)
        return
    yield value
    if id(value) in seen:
        return
    seen.add(id(value))
    if is_dataclass(value):
        for field in fields(value):
            yield from _walk_non_primitives(getattr(value, field.name), seen)


_INDEPENDENT_TYPE_TAGS = {
    BootBindingV3: "binding",
    boot_v3.BootContractV3: "contract",
    boot_v3.semantics.FrozenJsonObjectV3: "fjson",
    boot_v3.ExecutionClosureV3: "closure",
    boot_v3.semantics.ControllerBootstrapCacheProjectionV3: "controller_cache",
    boot_v3.semantics.RoleBootstrapCacheProjectionV3: "role_cache",
    boot_v3.SourceDigestsV3: "digests",
    boot_v3.semantics.PartitionLocatorSnapshotV3: "partition",
    boot_v3.semantics.VerityPairSnapshotV3: "verity",
    boot_v3.StorageSnapshotV3: "storage",
    boot_v3.KernelIdentitySnapshotV3: "kernel",
    boot_v3.semantics.ModuleEntrySnapshotV3: "module_entry",
    boot_v3.ModuleAuthoritySnapshotV3: "module_authority",
    boot_v3.ControlInventorySnapshotV3: "control_inventory",
    boot_v3.LaunchSourceProjectionV3: "launch_source",
    boot_v3.semantics.RoleLaunchSnapshotV3: "role_launch",
    boot_v3.LaunchProjectionV3: "launch",
    boot_v3.Stage2ControllerSnapshotV3: "stage2",
    boot_v3.ProcessAuthoritySnapshotV3: "process_authority",
    boot_v3.semantics.EligibleFileSnapshotV3: "eligible_file",
    boot_v3.semantics.LoaderControlSnapshotV3: "loader_control",
    boot_v3.semantics.JitInputSnapshotV3: "jit_input",
    boot_v3.semantics.JitDerivationSnapshotV3: "jit_derivation",
    boot_v3.semantics.CacheSelectorSnapshotV3: "cache_selector",
    boot_v3.Predicate5SnapshotV3: "predicate5",
    boot_v3.tables.ControlValueRuleV3: "control_rule",
    boot_v3.tables.ControlInventoryRowV3: "control_row",
    boot_v3.tables.LaunchFdRowV3: "launch_fd",
    boot_v3.tables.PipeCensusRowV3: "pipe",
    boot_v3.tables.ReadinessProtocolRowV3: "readiness",
    boot_v3.tables.LaunchRoleRowV3: "launch_role",
    boot_v3.tables.Stage2FdRowV3: "stage2_fd",
    boot_v3.tables.Stage2ControllerRowV3: "stage2_row",
}


def _independent_fingerprint(value: object) -> bytes:
    active: set[int] = set()

    def normalize(item: object) -> object:
        item_type = type(item)
        if item is None:
            return ["none"]
        if item_type is bool:
            return ["bool", item]
        if item_type is int:
            return ["int", str(item)]
        if item_type is str:
            return ["str", item]
        if item_type is bytes:
            return ["bytes", len(item), hashlib.sha256(item).hexdigest()]
        if item_type is tuple:
            if id(item) in active:
                raise TypeError("cycle")
            active.add(id(item))
            try:
                return ["tuple", len(item), [normalize(member) for member in item]]
            finally:
                active.remove(id(item))
        tag = _INDEPENDENT_TYPE_TAGS.get(item_type)
        if tag is None:
            raise TypeError("unrecognized type")
        if id(item) in active:
            raise TypeError("cycle")
        active.add(id(item))
        try:
            if item_type in {kind for kind in _INDEPENDENT_TYPE_TAGS if issubclass(kind, Enum)}:
                return ["enum", tag, item.name, normalize(item.value)]
            declared = fields(item)
            if set(vars(item)) != {field.name for field in declared}:
                raise TypeError("invalid dataclass fields")
            return [
                "dataclass",
                tag,
                [[field.name, normalize(getattr(item, field.name))] for field in declared],
            ]
        finally:
            active.remove(id(item))

    encoded = canonical_dumps(normalize(value))
    return hashlib.sha256(
        b"sol-spp-boot-binding-v3\0" + len(encoded).to_bytes(8, "big") + encoded
    ).digest()


class _ConstructionFailure(BaseException):
    pass


class BootBindingIntegritySelftest(unittest.TestCase):
    def test_independent_fingerprint_known_answer(self) -> None:
        binding = _binding()
        independent = _independent_fingerprint(binding)
        self.assertEqual(
            independent.hex(),
            "ea046629df5ea4833b6d4084aecc45c2900fa52d447316a637c127cb603d3f71",
        )
        record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[id(binding)]
        self.assertEqual(record.fingerprint, independent)

    def test_type_tag_map_covers_every_reachable_nonprimitive_type(self) -> None:
        binding = _binding()
        encountered = {type(value) for value in _walk_non_primitives(binding)}
        self.assertTrue(encountered)
        self.assertTrue(encountered <= set(boot_v3._BINDING_TYPE_TAGS_V3))
        self.assertIsInstance(boot_v3._BINDING_TYPE_TAGS_V3, type(boot_v3.MappingProxyType({})))

    def test_caller_contract_is_only_an_equality_assertion(self) -> None:
        inputs, caller_contract = build_v3_fixture()
        parsed_contract = boot_v3.parse_boot_contract_v3(inputs["boot_contract_bytes"])
        original_validate = boot_v3.validate_semantic_conjunction_v3
        original_register = boot_v3._register_boot_binding_v3
        validation_entered = threading.Event()
        release_validation = threading.Event()
        registration_entered = threading.Event()
        release_registration = threading.Event()
        bindings: list[BootBindingV3] = []
        errors: list[BaseException] = []

        def validate_after_mutation(**kwargs: object):
            validation_entered.set()
            self.assertIsNot(kwargs["contract"], caller_contract)
            self.assertTrue(release_validation.wait(5))
            return original_validate(**kwargs)

        def register_after_mutation(binding: BootBindingV3) -> BootBindingV3:
            registration_entered.set()
            self.assertIsNot(binding.boot_contract, caller_contract)
            self.assertTrue(release_registration.wait(5))
            return original_register(binding)

        def issue() -> None:
            try:
                bindings.append(bind_boot_inputs_v3(contract=caller_contract, **inputs))
            except BaseException as error:
                errors.append(error)

        boot_v3.validate_semantic_conjunction_v3 = validate_after_mutation
        boot_v3._register_boot_binding_v3 = register_after_mutation
        try:
            issuer = threading.Thread(target=issue)
            issuer.start()
            self.assertTrue(validation_entered.wait(5))
            object.__setattr__(caller_contract, "cache_policy", "caller-mutated")
            release_validation.set()
            self.assertTrue(registration_entered.wait(5))
            object.__setattr__(caller_contract, "execution_mode", "caller-mutated-again")
            release_registration.set()
            issuer.join(5)
            self.assertFalse(issuer.is_alive())
        finally:
            release_validation.set()
            release_registration.set()
            boot_v3.validate_semantic_conjunction_v3 = original_validate
            boot_v3._register_boot_binding_v3 = original_register
        self.assertEqual(errors, [])
        self.assertEqual(len(bindings), 1)
        binding = bindings[0]
        self.assertTrue(validation_entered.is_set())
        self.assertTrue(registration_entered.is_set())
        self.assertEqual(binding.boot_contract, parsed_contract)
        self.assertIsNot(binding.boot_contract, caller_contract)
        self.assertTrue(is_issued_boot_binding_v3(binding))

    def test_caller_contract_mutation_before_equality_fails(self) -> None:
        inputs, caller_contract = build_v3_fixture()
        original_parse = boot_v3.parse_boot_contract_v3
        parse_complete = threading.Event()
        release_parse = threading.Event()
        errors: list[BaseException] = []

        def paused_parse(data: bytes):
            parsed = original_parse(data)
            parse_complete.set()
            self.assertTrue(release_parse.wait(5))
            return parsed

        def issue() -> None:
            try:
                bind_boot_inputs_v3(contract=caller_contract, **inputs)
            except BaseException as error:
                errors.append(error)

        boot_v3.parse_boot_contract_v3 = paused_parse
        try:
            issuer = threading.Thread(target=issue)
            issuer.start()
            self.assertTrue(parse_complete.wait(5))
            object.__setattr__(caller_contract, "cache_policy", "caller-mutated")
            release_parse.set()
            issuer.join(5)
            self.assertFalse(issuer.is_alive())
        finally:
            release_parse.set()
            boot_v3.parse_boot_contract_v3 = original_parse
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ApplianceErrorV3)
        self.assertEqual(errors[0].reason_code, CP_BOOT_V3_BINDING)

    def test_verified_material_is_detached_and_every_entry_reverifies(self) -> None:
        binding = _binding()
        engine = BootTransitionEngineV3(binding)
        baseline_contract = engine.contract_sha256
        baseline_measurement = engine.pcr15_measurement_v3
        baseline_effect = engine.next_effect()
        record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[id(binding)]
        self.assertIs(type(record.material_bytes), bytes)
        self.assertFalse(hasattr(record, "material"))
        self.assertFalse(hasattr(engine, "binding"))
        self.assertFalse(hasattr(engine, "material"))
        for name in ("material", "_material", "_detached_material", "binding"):
            setattr(engine, name, object())
        self.assertEqual(engine.contract_sha256, baseline_contract)
        self.assertEqual(engine.pcr15_measurement_v3, baseline_measurement)
        self.assertIs(engine.next_effect(), baseline_effect)

        original = binding.root_lock_bytes
        object.__setattr__(binding, "root_lock_bytes", original + b"racing-mutation")
        for operation in (
            lambda: engine.contract_sha256,
            lambda: engine.pcr15_measurement_v3,
            engine.next_effect,
        ):
            _exact_binding_error(self, operation)
        object.__setattr__(binding, "root_lock_bytes", original)
        self.assertFalse(is_issued_boot_binding_v3(binding))
        _exact_binding_error(self, lambda: engine.contract_sha256)

    def test_registry_record_forgery_and_tombstone_cannot_reauthorize(self) -> None:
        def registration_rejects(binding: BootBindingV3) -> None:
            with self.assertRaises(ApplianceErrorV3) as raised:
                boot_v3._register_boot_binding_v3(binding)
            self.assertEqual(raised.exception.reason_code, CP_BOOT_V3_BINDING)
            self.assertEqual(
                str(raised.exception),
                "CP_BOOT_V3_BINDING: binding was not issued",
            )

        duplicate = _binding()
        registration_rejects(duplicate)
        self.assertTrue(is_issued_boot_binding_v3(duplicate))

        class WeakCarrier:
            pass

        carrier = WeakCarrier()
        dead_reference = weakref.ref(carrier)
        del carrier
        gc.collect()
        self.assertIsNone(dead_reference())

        binding = _binding()
        binding_id = id(binding)
        record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = replace(
            record,
            binding_ref=dead_reference,
        )
        registration_rejects(binding)
        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = record

        binding = _binding()
        binding_id = id(binding)
        record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = replace(record)
        self.assertFalse(is_issued_boot_binding_v3(binding))
        self.assertIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones)
        registration_rejects(binding)
        tombstone = boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id]
        boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id] = replace(
            tombstone,
            binding_ref=dead_reference,
        )
        registration_rejects(binding)
        boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id] = tombstone

        binding = _binding()
        binding_id = id(binding)
        record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = replace(
            record,
            binding_ref=weakref.ref(binding),
        )
        self.assertFalse(is_issued_boot_binding_v3(binding))
        registration_rejects(binding)

        binding = _binding()
        binding_id = id(binding)
        record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        original = binding.root_lock_bytes
        object.__setattr__(binding, "root_lock_bytes", original + b"recomputed")
        normalized, _layout = boot_v3._normalize_binding_material_v3(binding)
        recomputed = boot_v3._binding_fingerprint_v3(normalized)
        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = replace(
            record,
            fingerprint=recomputed,
        )
        self.assertFalse(is_issued_boot_binding_v3(binding))
        object.__setattr__(binding, "root_lock_bytes", original)
        registration_rejects(binding)

        binding = _binding()
        binding_id = id(binding)
        record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        original_fingerprint = record.fingerprint
        object.__setattr__(record, "fingerprint", b"\xff" * 32)
        self.assertFalse(is_issued_boot_binding_v3(binding))
        object.__setattr__(record, "fingerprint", original_fingerprint)
        registration_rejects(binding)

        binding = _binding()
        engine = BootTransitionEngineV3(binding)
        binding_id = id(binding)
        record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = replace(
            record,
            engine_ref=weakref.ref(engine),
        )
        _exact_binding_error(self, lambda: engine.contract_sha256)
        self.assertFalse(is_issued_boot_binding_v3(binding))
        registration_rejects(binding)

    def test_verified_material_aba_uses_only_operation_local_decode(self) -> None:
        def run_after_verify(
            engine: BootTransitionEngineV3,
            operation: object,
        ) -> object:
            assert callable(operation)
            verified = threading.Event()
            release = threading.Event()
            original_verify = engine._verify_v3
            results: list[object] = []
            errors: list[BaseException] = []

            def paused_verify() -> object:
                material = original_verify()
                verified.set()
                if not release.wait(5):
                    raise AssertionError("verified-material ABA barrier was not released")
                return material

            def invoke() -> None:
                try:
                    results.append(operation())
                except BaseException as error:
                    errors.append(error)

            engine._verify_v3 = paused_verify
            thread = threading.Thread(target=invoke)
            binding = engine._binding_liveness_anchor
            original_root = binding.root_lock_bytes
            original_policy = binding.policy_bytes
            try:
                thread.start()
                self.assertTrue(verified.wait(5))
                object.__setattr__(binding, "root_lock_bytes", original_root + b"aba")
                object.__setattr__(binding, "policy_bytes", original_policy + b"aba")
                object.__setattr__(binding, "root_lock_bytes", original_root)
                object.__setattr__(binding, "policy_bytes", original_policy)
                release.set()
                thread.join(5)
            finally:
                object.__setattr__(binding, "root_lock_bytes", original_root)
                object.__setattr__(binding, "policy_bytes", original_policy)
                release.set()
                engine._verify_v3 = original_verify
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(results), 1)
            self.assertTrue(is_issued_boot_binding_v3(binding))
            return results[0]

        engine = _engine()
        expected_contract = engine.contract_sha256
        expected_measurement = engine.pcr15_measurement_v3
        expected_pcr = engine.predicted_pcr15_v3
        self.assertEqual(
            run_after_verify(engine, lambda: engine.contract_sha256),
            expected_contract,
        )
        self.assertEqual(
            run_after_verify(engine, lambda: engine.pcr15_measurement_v3),
            expected_measurement,
        )
        self.assertEqual(
            run_after_verify(engine, lambda: engine.predicted_pcr15_v3),
            expected_pcr,
        )
        self.assertEqual(
            run_after_verify(engine, lambda: engine.state),
            BootTransitionStateV3.PID1_IDENTITY_ESTABLISHED,
        )

        effect_engine = _engine()
        effect = run_after_verify(effect_engine, effect_engine.next_effect)
        self.assertIs(type(effect), boot_v3.AuthorityStepEffectV3)
        self.assertEqual(effect.contract_sha256, expected_contract)
        self.assertIs(effect_engine._pending, effect)

        accept_engine = _engine()
        pending = accept_engine.next_effect()
        assert pending is not None
        observed = pending.expected
        if observed is None:
            observed = ("present", pending.action)
        observation = boot_v3.AuthorityStepReadbackV3(
            pending.contract_sha256,
            pending.state,
            pending.action,
            observed,
        )
        accepted_state = run_after_verify(
            accept_engine,
            lambda: accept_engine.accept(observation),
        )
        self.assertEqual(accepted_state, boot_v3._NEXT_STATE_V3[pending.state])
        self.assertIsNone(accept_engine._pending)

    def test_direct_wrapper_construction_requires_a_live_capability(self) -> None:
        def rejected(capability: object = None) -> None:
            with self.assertRaises(TypeError):
                ServingAuthorityWrapperV3(admission_capability=capability)

        rejected()
        rejected(object())

        class ServingAdmissionCapabilityV3:
            pass

        ServingAdmissionCapabilityV3.__module__ = boot_v3.ServingAdmissionCapabilityV3.__module__
        rejected(ServingAdmissionCapabilityV3())

        foreign_engine = _engine(serving=True)
        foreign_capability = boot_v3._serving_admission_capability_v3(foreign_engine)
        rejected(foreign_capability)

        stale_binding = _binding()
        stale_engine = BootTransitionEngineV3(stale_binding)
        stale_capability = boot_v3._serving_admission_capability_v3(stale_engine)
        stale_reference = weakref.ref(stale_binding)
        del stale_engine
        del stale_binding
        gc.collect()
        self.assertIsNone(stale_reference())
        rejected(stale_capability)

        engine = _engine(serving=True)
        wrapper = engine.admit_serving_authority()
        capability = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[
            id(engine._binding_liveness_anchor)
        ].admission_capability
        assert capability is not None
        rejected(capability)
        self.assertIs(wrapper, engine.admit_serving_authority())

    def test_pre_serving_admission_does_not_mint_a_capability(self) -> None:
        binding = _binding()
        engine = BootTransitionEngineV3(binding)
        record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[id(binding)]
        self.assertIsNone(record.admission_capability)
        self.assertIsNone(record.admitted_wrapper_ref)
        self.assertIsNone(engine._serving_authority)
        with self.assertRaises(ApplianceErrorV3) as raised:
            engine.admit_serving_authority()
        self.assertEqual(raised.exception.reason_code, boot_v3.CP_BOOT_V3_LAUNCH_SUPERVISION)
        current = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[id(binding)]
        self.assertIsNone(current.admission_capability)
        self.assertIsNone(current.admitted_wrapper_ref)
        self.assertIsNone(engine._serving_authority)

    def test_concurrent_waiters_retry_after_the_builder_fails(self) -> None:
        engine = _engine(serving=True)
        capability = boot_v3._serving_admission_capability_v3(engine)
        original_init = boot_v3.ServingAuthorityWrapperV3.__init__
        builder_entered = threading.Event()
        release_failure = threading.Event()
        waiters_waiting = threading.Event()
        wait_lock = threading.Lock()
        waiting_threads: set[int] = set()
        original_wait = capability.condition.wait
        failed = False

        def tracked_wait(timeout: float | None = None) -> bool:
            with wait_lock:
                waiting_threads.add(threading.get_ident())
                if len(waiting_threads) == 2:
                    waiters_waiting.set()
            return original_wait(timeout)

        def fail_once(self: ServingAuthorityWrapperV3, **kwargs: object) -> None:
            nonlocal failed
            if not failed:
                failed = True
                builder_entered.set()
                if not release_failure.wait(5):
                    raise AssertionError("builder failure was not released")
                raise _ConstructionFailure("planned concurrent failure")
            original_init(self, **kwargs)

        capability.condition.wait = tracked_wait
        boot_v3.ServingAuthorityWrapperV3.__init__ = fail_once
        wrappers: list[ServingAuthorityWrapperV3] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def admit() -> None:
            try:
                wrapper = engine.admit_serving_authority()
                with lock:
                    wrappers.append(wrapper)
            except BaseException as error:
                with lock:
                    errors.append(error)

        builder = threading.Thread(target=admit)
        builder.start()
        self.assertTrue(builder_entered.wait(5))
        waiters = [threading.Thread(target=admit) for _ in range(2)]
        for waiter in waiters:
            waiter.start()
        self.assertTrue(waiters_waiting.wait(5))
        release_failure.set()
        for thread in (builder, *waiters):
            thread.join(5)
            self.assertFalse(thread.is_alive())
        capability.condition.wait = original_wait
        boot_v3.ServingAuthorityWrapperV3.__init__ = original_init

        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], _ConstructionFailure)
        self.assertEqual(len(wrappers), 2)
        self.assertIs(wrappers[0], wrappers[1])
        self.assertIs(wrappers[0], engine.admit_serving_authority())
        current = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[
            id(engine._binding_liveness_anchor)
        ]
        fresh_capability = current.admission_capability
        assert fresh_capability is not None
        self.assertIsNot(fresh_capability, capability)
        self.assertNotEqual(fresh_capability.nonce, capability.nonce)
        self.assertEqual(capability.phase, "failed")
        self.assertFalse(capability.retired)
        with self.assertRaises(TypeError):
            ServingAuthorityWrapperV3(admission_capability=capability)

    def test_post_allocation_construction_failure_consumes_capability(self) -> None:
        engine = _engine(serving=True)
        failed_capability = boot_v3._serving_admission_capability_v3(engine)
        original_init = boot_v3.ServingAuthorityWrapperV3.__init__
        allocated: list[ServingAuthorityWrapperV3] = []

        def fail_after_allocation(
            wrapper: ServingAuthorityWrapperV3, **kwargs: object
        ) -> None:
            original_init(wrapper, **kwargs)
            allocated.append(wrapper)
            raise _ConstructionFailure("post-allocation failure")

        boot_v3.ServingAuthorityWrapperV3.__init__ = fail_after_allocation
        try:
            with self.assertRaisesRegex(_ConstructionFailure, "post-allocation"):
                engine.admit_serving_authority()
        finally:
            boot_v3.ServingAuthorityWrapperV3.__init__ = original_init
        self.assertEqual(len(allocated), 1)
        discarded = allocated[0]
        self.assertEqual(discarded._cleanup_phase, "complete")
        self.assertEqual(discarded._revoke_count, 1)
        self.assertTrue(discarded._resource.revoked)
        self.assertEqual(discarded._resource.sessions, {})
        self.assertEqual(failed_capability.phase, "failed")
        self.assertIsNone(failed_capability.constructing_wrapper_ref)
        with self.assertRaises(TypeError):
            ServingAuthorityWrapperV3(admission_capability=failed_capability)
        admitted = engine.admit_serving_authority()
        current = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[
            id(engine._binding_liveness_anchor)
        ]
        self.assertIs(current.admitted_wrapper_ref(), admitted)
        self.assertIsNot(current.admission_capability, failed_capability)
        self.assertNotEqual(
            current.admission_capability.nonce,
            failed_capability.nonce,
        )
        self.assertEqual(discarded._revoke_count, 1)

    def test_unpublished_admission_retirement_is_terminal(self) -> None:
        engine = _engine(serving=True)
        capability = boot_v3._serving_admission_capability_v3(engine)
        with capability.condition:
            capability.phase = "constructing"
            capability.owner_thread_id = threading.get_ident()
        in_progress = ServingAuthorityWrapperV3(admission_capability=capability)
        barrier = threading.Barrier(2)

        def retire() -> None:
            barrier.wait()
            boot_v3._retire_serving_admission_v3(capability, in_progress)

        retire_thread = threading.Thread(target=retire)
        retire_thread.start()
        barrier.wait()
        retire_thread.join(5)
        self.assertFalse(retire_thread.is_alive())
        with capability.condition:
            self.assertTrue(capability.retired)
            self.assertEqual(capability.phase, "retired")
        _binding_error(self, engine.admit_serving_authority)

    def test_binding_retirement_discards_allocated_unpublished_wrapper(self) -> None:
        binding = _binding()
        engine = BootTransitionEngineV3(binding)
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        capability = boot_v3._serving_admission_capability_v3(engine)
        original_init = boot_v3.ServingAuthorityWrapperV3.__init__
        original_wait = capability.condition.wait
        allocation_ready = threading.Event()
        waiter_waiting = threading.Event()
        release_constructor = threading.Event()
        constructed: list[ServingAuthorityWrapperV3] = []
        errors: list[BaseException] = []
        error_lock = threading.Lock()
        waiter_thread_id: list[int] = []

        def paused_after_allocation(
            wrapper: ServingAuthorityWrapperV3, **kwargs: object
        ) -> None:
            original_init(wrapper, **kwargs)
            constructed.append(wrapper)
            allocation_ready.set()
            if not release_constructor.wait(5):
                raise AssertionError("constructor retirement barrier was not released")

        def tracked_wait(timeout: float | None = None) -> bool:
            if waiter_thread_id and threading.get_ident() == waiter_thread_id[0]:
                waiter_waiting.set()
            return original_wait(timeout)

        def admit(*, waiter: bool = False) -> None:
            if waiter:
                waiter_thread_id.append(threading.get_ident())
            try:
                engine.admit_serving_authority()
            except BaseException as error:
                with error_lock:
                    errors.append(error)

        boot_v3.ServingAuthorityWrapperV3.__init__ = paused_after_allocation
        capability.condition.wait = tracked_wait
        owner = threading.Thread(target=admit)
        waiter = threading.Thread(target=lambda: admit(waiter=True))
        original = binding.root_lock_bytes
        try:
            owner.start()
            self.assertTrue(allocation_ready.wait(5))
            waiter.start()
            self.assertTrue(waiter_waiting.wait(5))
            object.__setattr__(binding, "root_lock_bytes", original + b"retire-construction")
            self.assertFalse(is_issued_boot_binding_v3(binding))
            release_constructor.set()
            owner.join(5)
            waiter.join(5)
        finally:
            object.__setattr__(binding, "root_lock_bytes", original)
            release_constructor.set()
            capability.condition.wait = original_wait
            boot_v3.ServingAuthorityWrapperV3.__init__ = original_init
        self.assertFalse(owner.is_alive())
        self.assertFalse(waiter.is_alive())
        self.assertEqual(len(constructed), 1)
        wrapper = constructed[0]
        self.assertEqual(len(errors), 2)
        self.assertTrue(all(type(error) is ApplianceErrorV3 for error in errors))
        self.assertTrue(all(error.reason_code == CP_BOOT_V3_BINDING for error in errors))
        self.assertTrue(all(
            str(error) == "CP_BOOT_V3_BINDING: binding was not issued"
            for error in errors
        ))
        self.assertIsNone(engine._serving_authority)
        self.assertEqual(capability.phase, "retired")
        self.assertTrue(capability.retired)
        self.assertIsNone(capability.constructing_wrapper_ref)
        self.assertIsNone(capability.published_wrapper_ref)
        self.assertEqual(wrapper._cleanup_phase, "complete")
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertTrue(wrapper._resource.revoked)
        self.assertEqual(wrapper._resource.sessions, {})
        _exact_binding_error(self, engine.admit_serving_authority)
        self.assertEqual(wrapper._revoke_count, 1)

    def test_construction_owner_detects_mutation_after_allocation(self) -> None:
        binding = _binding()
        engine = BootTransitionEngineV3(binding)
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        capability = boot_v3._serving_admission_capability_v3(engine)
        original_init = boot_v3.ServingAuthorityWrapperV3.__init__
        constructed: list[ServingAuthorityWrapperV3] = []
        original = binding.root_lock_bytes

        def mutate_after_allocation(
            wrapper: ServingAuthorityWrapperV3, **kwargs: object
        ) -> None:
            original_init(wrapper, **kwargs)
            constructed.append(wrapper)
            object.__setattr__(binding, "root_lock_bytes", original + b"owner-observed")

        boot_v3.ServingAuthorityWrapperV3.__init__ = mutate_after_allocation
        try:
            _exact_binding_error(self, engine.admit_serving_authority)
        finally:
            object.__setattr__(binding, "root_lock_bytes", original)
            boot_v3.ServingAuthorityWrapperV3.__init__ = original_init
        self.assertEqual(len(constructed), 1)
        wrapper = constructed[0]
        self.assertFalse(is_issued_boot_binding_v3(binding))
        self.assertIsNone(engine._serving_authority)
        self.assertTrue(capability.retired)
        self.assertEqual(capability.phase, "retired")
        self.assertIsNone(capability.constructing_wrapper_ref)
        self.assertIsNone(capability.published_wrapper_ref)
        self.assertEqual(wrapper._cleanup_phase, "complete")
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertTrue(wrapper._resource.revoked)
        _exact_binding_error(self, engine.admit_serving_authority)
        self.assertEqual(wrapper._revoke_count, 1)

    def test_retirement_before_construction_claim_is_binding_error_for_owner(self) -> None:
        binding = _binding()
        engine = BootTransitionEngineV3(binding)
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        capability = boot_v3._serving_admission_capability_v3(engine)
        original_init = boot_v3.ServingAuthorityWrapperV3.__init__
        original_wait = capability.condition.wait
        before_claim = threading.Event()
        release_claim = threading.Event()
        waiter_waiting = threading.Event()
        owner_thread_id: list[int] = []
        waiter_thread_id: list[int] = []
        wrapper_objects: list[ServingAuthorityWrapperV3] = []
        errors: list[BaseException] = []
        owner_reuse_errors: list[BaseException] = []
        error_lock = threading.Lock()

        def paused_before_claim(
            wrapper: ServingAuthorityWrapperV3, **kwargs: object
        ) -> None:
            wrapper_objects.append(wrapper)
            before_claim.set()
            if not release_claim.wait(5):
                raise AssertionError("pre-claim retirement barrier was not released")
            original_init(wrapper, **kwargs)

        def tracked_wait(timeout: float | None = None) -> bool:
            if waiter_thread_id and threading.get_ident() == waiter_thread_id[0]:
                waiter_waiting.set()
            return original_wait(timeout)

        def admit(*, waiter: bool = False) -> None:
            if waiter:
                waiter_thread_id.append(threading.get_ident())
            else:
                owner_thread_id.append(threading.get_ident())
            try:
                engine.admit_serving_authority()
            except BaseException as error:
                with error_lock:
                    errors.append(error)
                if not waiter:
                    try:
                        ServingAuthorityWrapperV3(admission_capability=capability)
                    except BaseException as reuse_error:
                        owner_reuse_errors.append(reuse_error)

        boot_v3.ServingAuthorityWrapperV3.__init__ = paused_before_claim
        capability.condition.wait = tracked_wait
        owner = threading.Thread(target=admit)
        waiter = threading.Thread(target=lambda: admit(waiter=True))
        original = binding.root_lock_bytes
        try:
            owner.start()
            self.assertTrue(before_claim.wait(5))
            waiter.start()
            self.assertTrue(waiter_waiting.wait(5))
            object.__setattr__(binding, "root_lock_bytes", original + b"retired-before-claim")
            self.assertFalse(is_issued_boot_binding_v3(binding))
            release_claim.set()
            owner.join(5)
            waiter.join(5)
        finally:
            object.__setattr__(binding, "root_lock_bytes", original)
            release_claim.set()
            capability.condition.wait = original_wait
            boot_v3.ServingAuthorityWrapperV3.__init__ = original_init
        self.assertFalse(owner.is_alive())
        self.assertFalse(waiter.is_alive())
        self.assertEqual(len(errors), 2)
        self.assertTrue(all(type(error) is ApplianceErrorV3 for error in errors))
        self.assertTrue(all(error.reason_code == CP_BOOT_V3_BINDING for error in errors))
        self.assertTrue(all(
            str(error) == "CP_BOOT_V3_BINDING: binding was not issued"
            for error in errors
        ))
        self.assertIsNone(capability.retired_construction_owner_thread_id)
        self.assertTrue(capability.retired)
        self.assertEqual(capability.phase, "retired")
        self.assertIsNone(capability.constructing_wrapper_ref)
        self.assertIsNone(capability.published_wrapper_ref)
        self.assertIsNone(engine._serving_authority)
        self.assertEqual(len(wrapper_objects), 2)
        self.assertTrue(all(not hasattr(wrapper, "_resource") for wrapper in wrapper_objects))
        self.assertEqual(len(owner_reuse_errors), 1)
        self.assertIs(type(owner_reuse_errors[0]), TypeError)
        with self.assertRaises(TypeError):
            ServingAuthorityWrapperV3(admission_capability=capability)
        _exact_binding_error(self, engine.admit_serving_authority)

    def test_retirement_after_claim_verification_is_binding_error_for_owner(self) -> None:
        binding = _binding()
        engine = BootTransitionEngineV3(binding)
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        capability = boot_v3._serving_admission_capability_v3(engine)
        original_verify = BootTransitionEngineV3._verify_v3
        original_init = boot_v3.ServingAuthorityWrapperV3.__init__
        after_claim_verification = threading.Event()
        release_registry_lookup = threading.Event()
        verify_calls: list[None] = []
        wrapper_objects: list[ServingAuthorityWrapperV3] = []
        errors: list[BaseException] = []
        owner_reuse_errors: list[BaseException] = []

        def paused_verify(target: BootTransitionEngineV3) -> None:
            original_verify(target)
            if target is engine:
                verify_calls.append(None)
                if len(verify_calls) == 2:
                    after_claim_verification.set()
                    if not release_registry_lookup.wait(5):
                        raise AssertionError("post-verification registry barrier was not released")

        def tracked_init(
            wrapper: ServingAuthorityWrapperV3, **kwargs: object
        ) -> None:
            wrapper_objects.append(wrapper)
            original_init(wrapper, **kwargs)

        def admit_and_reuse() -> None:
            try:
                engine.admit_serving_authority()
            except BaseException as error:
                errors.append(error)
            try:
                ServingAuthorityWrapperV3(admission_capability=capability)
            except BaseException as error:
                owner_reuse_errors.append(error)

        BootTransitionEngineV3._verify_v3 = paused_verify
        boot_v3.ServingAuthorityWrapperV3.__init__ = tracked_init
        owner = threading.Thread(target=admit_and_reuse)
        original = binding.root_lock_bytes
        try:
            owner.start()
            self.assertTrue(after_claim_verification.wait(5))
            object.__setattr__(binding, "root_lock_bytes", original + b"post-verification")
            self.assertFalse(is_issued_boot_binding_v3(binding))
            release_registry_lookup.set()
            owner.join(5)
        finally:
            object.__setattr__(binding, "root_lock_bytes", original)
            release_registry_lookup.set()
            BootTransitionEngineV3._verify_v3 = original_verify
            boot_v3.ServingAuthorityWrapperV3.__init__ = original_init
        self.assertFalse(owner.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIs(type(errors[0]), ApplianceErrorV3)
        self.assertEqual(errors[0].reason_code, CP_BOOT_V3_BINDING)
        self.assertEqual(
            str(errors[0]),
            "CP_BOOT_V3_BINDING: binding was not issued",
        )
        self.assertEqual(len(owner_reuse_errors), 1)
        self.assertIs(type(owner_reuse_errors[0]), TypeError)
        self.assertEqual(len(wrapper_objects), 2)
        self.assertTrue(all(not hasattr(wrapper, "_resource") for wrapper in wrapper_objects))
        self.assertIsNone(capability.retired_construction_owner_thread_id)
        self.assertTrue(capability.retired)
        self.assertEqual(capability.phase, "retired")
        self.assertIsNone(capability.constructing_wrapper_ref)
        self.assertIsNone(capability.published_wrapper_ref)
        self.assertIsNone(engine._serving_authority)
        _exact_binding_error(self, engine.admit_serving_authority)

    def test_registry_pop_before_retirement_publication_preserves_owner_error(self) -> None:
        binding = _binding()
        engine = BootTransitionEngineV3(binding)
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        capability = boot_v3._serving_admission_capability_v3(engine)
        original_init = boot_v3.ServingAuthorityWrapperV3.__init__
        original_retire = boot_v3._retire_record_admission_v3
        original_wait = capability.condition.wait
        before_claim = threading.Event()
        release_claim = threading.Event()
        registry_popped = threading.Event()
        release_retirement_publication = threading.Event()
        waiter_waiting = threading.Event()
        owner_unwound = threading.Event()
        allow_owner_reuse = threading.Event()
        waiter_thread_id: list[int] = []
        wrapper_objects: list[ServingAuthorityWrapperV3] = []
        errors: list[BaseException] = []
        owner_reuse_errors: list[BaseException] = []
        retirement_results: list[bool] = []
        error_lock = threading.Lock()

        def paused_before_claim(
            wrapper: ServingAuthorityWrapperV3, **kwargs: object
        ) -> None:
            wrapper_objects.append(wrapper)
            before_claim.set()
            if not release_claim.wait(5):
                raise AssertionError("pre-claim registry-pop barrier was not released")
            original_init(wrapper, **kwargs)

        def paused_retirement_publication(record: object) -> None:
            registry_popped.set()
            if not release_retirement_publication.wait(5):
                raise AssertionError("retirement-publication barrier was not released")
            original_retire(record)

        def tracked_wait(timeout: float | None = None) -> bool:
            if waiter_thread_id and threading.get_ident() == waiter_thread_id[0]:
                waiter_waiting.set()
            return original_wait(timeout)

        def admit(*, waiter: bool = False) -> None:
            if waiter:
                waiter_thread_id.append(threading.get_ident())
            try:
                engine.admit_serving_authority()
            except BaseException as error:
                with error_lock:
                    errors.append(error)
            if not waiter:
                owner_unwound.set()
                if not allow_owner_reuse.wait(5):
                    owner_reuse_errors.append(
                        AssertionError("post-retirement owner reuse was not released")
                    )
                    return
                try:
                    ServingAuthorityWrapperV3(admission_capability=capability)
                except BaseException as error:
                    owner_reuse_errors.append(error)

        def retire_binding() -> None:
            retirement_results.append(is_issued_boot_binding_v3(binding))

        boot_v3.ServingAuthorityWrapperV3.__init__ = paused_before_claim
        boot_v3._retire_record_admission_v3 = paused_retirement_publication
        capability.condition.wait = tracked_wait
        owner = threading.Thread(target=admit)
        waiter = threading.Thread(target=lambda: admit(waiter=True))
        retirement = threading.Thread(target=retire_binding)
        original = binding.root_lock_bytes
        try:
            owner.start()
            self.assertTrue(before_claim.wait(5))
            waiter.start()
            self.assertTrue(waiter_waiting.wait(5))
            object.__setattr__(binding, "root_lock_bytes", original + b"pop-before-retire")
            retirement.start()
            self.assertTrue(registry_popped.wait(5))
            release_claim.set()
            self.assertTrue(owner_unwound.wait(5))
            waiter.join(5)
            self.assertFalse(waiter.is_alive())
            release_retirement_publication.set()
            retirement.join(5)
            self.assertFalse(retirement.is_alive())
            allow_owner_reuse.set()
            owner.join(5)
        finally:
            object.__setattr__(binding, "root_lock_bytes", original)
            release_claim.set()
            release_retirement_publication.set()
            allow_owner_reuse.set()
            capability.condition.wait = original_wait
            boot_v3._retire_record_admission_v3 = original_retire
            boot_v3.ServingAuthorityWrapperV3.__init__ = original_init
        self.assertFalse(owner.is_alive())
        self.assertEqual(retirement_results, [False])
        self.assertEqual(len(errors), 2)
        self.assertTrue(all(type(error) is ApplianceErrorV3 for error in errors))
        self.assertTrue(all(error.reason_code == CP_BOOT_V3_BINDING for error in errors))
        self.assertTrue(all(
            str(error) == "CP_BOOT_V3_BINDING: binding was not issued"
            for error in errors
        ))
        self.assertEqual(len(owner_reuse_errors), 1)
        self.assertIs(type(owner_reuse_errors[0]), TypeError)
        self.assertEqual(len(wrapper_objects), 2)
        self.assertTrue(all(not hasattr(wrapper, "_resource") for wrapper in wrapper_objects))
        self.assertIsNone(capability.retired_construction_owner_thread_id)
        self.assertTrue(capability.retired)
        self.assertEqual(capability.phase, "retired")
        self.assertIsNone(capability.constructing_wrapper_ref)
        self.assertIsNone(capability.published_wrapper_ref)
        self.assertIsNone(engine._serving_authority)
        with self.assertRaises(TypeError):
            ServingAuthorityWrapperV3(admission_capability=capability)
        _exact_binding_error(self, engine.admit_serving_authority)

    def test_retirement_after_registry_validation_discards_local_wrapper(self) -> None:
        binding = _binding()
        engine = BootTransitionEngineV3(binding)
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        capability = boot_v3._serving_admission_capability_v3(engine)
        original_condition = capability.condition
        original_init = boot_v3.ServingAuthorityWrapperV3.__init__
        after_registry_validation = threading.Event()
        release_condition_claim = threading.Event()
        registry_popped = threading.Event()
        release_retirement_publication = threading.Event()
        waiter_waiting = threading.Event()
        owner_unwound = threading.Event()
        allow_owner_reuse = threading.Event()
        owner_thread_id: list[int] = []
        waiter_thread_id: list[int] = []
        retirement_thread_id: list[int] = []
        owner_claim_entries: list[None] = []
        wrapper_objects: list[ServingAuthorityWrapperV3] = []
        errors: list[tuple[str, BaseException]] = []
        owner_reuse_errors: list[BaseException] = []
        retirement_results: list[bool] = []
        error_lock = threading.Lock()

        class BarrierCondition:
            def __enter__(self) -> object:
                thread_id = threading.get_ident()
                if (
                    owner_thread_id
                    and thread_id == owner_thread_id[0]
                    and capability.phase == "constructing"
                    and capability.constructing_wrapper_ref is None
                ):
                    owner_claim_entries.append(None)
                    if len(owner_claim_entries) == 2:
                        after_registry_validation.set()
                        if not release_condition_claim.wait(5):
                            raise AssertionError("registry-validation barrier was not released")
                if retirement_thread_id and thread_id == retirement_thread_id[0]:
                    registry_popped.set()
                    if not release_retirement_publication.wait(5):
                        raise AssertionError("retirement-publication barrier was not released")
                return original_condition.__enter__()

            def __exit__(self, *args: object) -> object:
                return original_condition.__exit__(*args)

            def wait(self, timeout: float | None = None) -> bool:
                if waiter_thread_id and threading.get_ident() == waiter_thread_id[0]:
                    waiter_waiting.set()
                return original_condition.wait(timeout)

            def __getattr__(self, name: str) -> object:
                return getattr(original_condition, name)

        def tracked_init(
            wrapper: ServingAuthorityWrapperV3, **kwargs: object
        ) -> None:
            wrapper_objects.append(wrapper)
            original_init(wrapper, **kwargs)

        def admit(*, role: str) -> None:
            if role == "owner":
                owner_thread_id.append(threading.get_ident())
            else:
                waiter_thread_id.append(threading.get_ident())
            try:
                engine.admit_serving_authority()
            except BaseException as error:
                with error_lock:
                    errors.append((role, error))
            if role == "owner":
                owner_unwound.set()
                if not allow_owner_reuse.wait(5):
                    owner_reuse_errors.append(
                        AssertionError("post-retirement owner reuse was not released")
                    )
                    return
                try:
                    ServingAuthorityWrapperV3(admission_capability=capability)
                except BaseException as error:
                    owner_reuse_errors.append(error)

        def retire_binding() -> None:
            retirement_thread_id.append(threading.get_ident())
            retirement_results.append(is_issued_boot_binding_v3(binding))

        capability.condition = BarrierCondition()
        boot_v3.ServingAuthorityWrapperV3.__init__ = tracked_init
        owner = threading.Thread(target=lambda: admit(role="owner"))
        waiter = threading.Thread(target=lambda: admit(role="waiter"))
        retirement = threading.Thread(target=retire_binding)
        original = binding.root_lock_bytes
        wrapper: ServingAuthorityWrapperV3 | None = None
        try:
            owner.start()
            self.assertTrue(after_registry_validation.wait(5))
            waiter.start()
            self.assertTrue(waiter_waiting.wait(5))
            object.__setattr__(binding, "root_lock_bytes", original + b"post-registry")
            retirement.start()
            self.assertTrue(registry_popped.wait(5))
            release_condition_claim.set()
            self.assertTrue(owner_unwound.wait(5))
            self.assertEqual(len(wrapper_objects), 1)
            wrapper = wrapper_objects[0]
            self.assertEqual(wrapper._cleanup_phase, "complete")
            self.assertEqual(wrapper._revoke_count, 1)
            self.assertTrue(wrapper._resource.revoked)
            waiter.join(5)
            self.assertFalse(waiter.is_alive())
            release_retirement_publication.set()
            retirement.join(5)
            self.assertFalse(retirement.is_alive())
            self.assertEqual(wrapper._cleanup_phase, "complete")
            self.assertEqual(wrapper._revoke_count, 1)
            self.assertTrue(wrapper._resource.revoked)
            allow_owner_reuse.set()
            owner.join(5)
        finally:
            object.__setattr__(binding, "root_lock_bytes", original)
            release_condition_claim.set()
            release_retirement_publication.set()
            allow_owner_reuse.set()
            capability.condition = original_condition
            boot_v3.ServingAuthorityWrapperV3.__init__ = original_init
        self.assertFalse(owner.is_alive())
        self.assertEqual(retirement_results, [False])
        self.assertEqual({role for role, _error in errors}, {"owner", "waiter"})
        self.assertTrue(all(type(error) is ApplianceErrorV3 for _role, error in errors))
        self.assertTrue(all(error.reason_code == CP_BOOT_V3_BINDING for _role, error in errors))
        self.assertTrue(all(
            str(error) == "CP_BOOT_V3_BINDING: binding was not issued"
            for _role, error in errors
        ))
        self.assertEqual(len(owner_reuse_errors), 1)
        self.assertIs(type(owner_reuse_errors[0]), TypeError)
        self.assertEqual(len(wrapper_objects), 2)
        self.assertTrue(all(
            wrapper is wrapper_objects[0] or not hasattr(wrapper, "_resource")
            for wrapper in wrapper_objects
        ))
        assert wrapper is not None
        self.assertEqual(wrapper._cleanup_phase, "complete")
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertTrue(wrapper._resource.revoked)
        self.assertEqual(wrapper._resource.sessions, {})
        self.assertTrue(capability.retired)
        self.assertEqual(capability.phase, "retired")
        self.assertIsNone(capability.constructing_wrapper_ref)
        self.assertIsNone(capability.published_wrapper_ref)
        self.assertIsNone(engine._serving_authority)
        _exact_binding_error(self, engine.admit_serving_authority)
        self.assertEqual(wrapper._revoke_count, 1)

    def test_no_enum_is_reachable_from_an_issued_binding(self) -> None:
        binding = _binding()
        self.assertEqual(
            [value for value in _walk_non_primitives(binding) if isinstance(value, Enum)],
            [],
        )

    def test_binding_mutations_extra_fields_deleted_fields_and_clones_reject(self) -> None:
        binding = _binding()
        engine = BootTransitionEngineV3(binding)
        original = binding.root_lock_bytes
        object.__setattr__(binding, "root_lock_bytes", original + b"changed")
        self.assertFalse(is_issued_boot_binding_v3(binding))
        _binding_error(self, lambda: BootTransitionEngineV3(binding))
        for operation in (
            lambda: engine.contract_sha256,
            lambda: engine.pcr15_measurement_v3,
            lambda: engine.predicted_pcr15_v3,
            engine.next_effect,
            lambda: engine.advance(None),
            lambda: engine.accept(None),
            engine.admit_serving_authority,
        ):
            _exact_binding_error(self, operation)
        object.__setattr__(binding, "root_lock_bytes", original)
        self.assertFalse(is_issued_boot_binding_v3(binding))
        _exact_binding_error(self, engine.next_effect)

        binding = _binding()
        object.__setattr__(binding, "extra_field", 1)
        self.assertFalse(is_issued_boot_binding_v3(binding))
        object.__delattr__(binding, "extra_field")
        self.assertFalse(is_issued_boot_binding_v3(binding))

        binding = _binding()
        contract = binding.boot_contract
        object.__delattr__(binding, "boot_contract")
        self.assertFalse(is_issued_boot_binding_v3(binding))
        object.__setattr__(binding, "boot_contract", contract)
        self.assertFalse(is_issued_boot_binding_v3(binding))

        binding = _binding()
        for clone in (
            copy.copy(binding),
            copy.deepcopy(binding),
        ):
            self.assertFalse(is_issued_boot_binding_v3(clone))
            _binding_error(self, lambda clone=clone: BootTransitionEngineV3(clone))
        exact_clone = object.__new__(BootBindingV3)
        exact_clone.__dict__.update(binding.__dict__)
        self.assertFalse(is_issued_boot_binding_v3(exact_clone))
        _binding_error(self, lambda: BootTransitionEngineV3(exact_clone))

    def test_all_top_level_and_nested_dataclass_mutations_are_detected(self) -> None:
        prototype = _binding()
        top_level_fields = fields(prototype)
        nested_types = {
            type(value)
            for value in _walk_non_primitives(prototype)
            if is_dataclass(value) and value is not prototype
        }
        for field in top_level_fields:
            binding = _binding()
            original = getattr(binding, field.name)
            object.__setattr__(binding, field.name, None if original is not None else "changed")
            with self.subTest(top_level=field.name):
                self.assertFalse(is_issued_boot_binding_v3(binding))
            object.__setattr__(binding, field.name, original)
            self.assertFalse(is_issued_boot_binding_v3(binding))

        for nested_type in nested_types:
            binding = _binding()
            snapshot = next(
                value
                for value in _walk_non_primitives(binding)
                if type(value) is nested_type
            )
            field = fields(snapshot)[0]
            original = getattr(snapshot, field.name)
            object.__setattr__(snapshot, field.name, None if original is not None else "changed")
            with self.subTest(snapshot=type(snapshot).__name__, field=field.name):
                self.assertFalse(is_issued_boot_binding_v3(binding))
            object.__setattr__(snapshot, field.name, original)
            self.assertFalse(is_issued_boot_binding_v3(binding))

    def test_forged_types_and_nested_field_tampering_reject(self) -> None:
        binding = _binding()

        @dataclass(frozen=True)
        class ForgedContract:
            schema: str

        ForgedContract.__module__ = boot_v3.BootContractV3.__module__
        ForgedContract.__qualname__ = boot_v3.BootContractV3.__qualname__
        original = binding.boot_contract
        object.__setattr__(binding, "boot_contract", ForgedContract("fake"))
        self.assertFalse(is_issued_boot_binding_v3(binding))
        object.__setattr__(binding, "boot_contract", original)
        self.assertFalse(is_issued_boot_binding_v3(binding))

        @dataclass(frozen=True)
        class ForgedEnumCarrier:
            value: object

        binding = _binding()
        original_process_authority = binding.process_authority
        object.__setattr__(binding, "process_authority", ForgedEnumCarrier(None))
        self.assertFalse(is_issued_boot_binding_v3(binding))
        object.__setattr__(binding, "process_authority", original_process_authority)
        self.assertFalse(is_issued_boot_binding_v3(binding))

    def test_nested_shape_and_same_fqcn_forgery_reject(self) -> None:
        prototype = _binding()
        nested_types = {
            type(value)
            for value in _walk_non_primitives(prototype)
            if is_dataclass(value) and value is not prototype
        }
        for nested_type in nested_types:
            binding = _binding()
            snapshot = next(
                value
                for value in _walk_non_primitives(binding)
                if type(value) is nested_type
            )
            object.__setattr__(snapshot, "unexpected_field", "forged")
            with self.subTest(nested=nested_type.__name__, mutation="extra"):
                self.assertFalse(is_issued_boot_binding_v3(binding))
            object.__delattr__(snapshot, "unexpected_field")
            self.assertFalse(is_issued_boot_binding_v3(binding))

            binding = _binding()
            snapshot = next(
                value
                for value in _walk_non_primitives(binding)
                if type(value) is nested_type
            )
            declared = fields(snapshot)[0]
            value = getattr(snapshot, declared.name)
            object.__delattr__(snapshot, declared.name)
            with self.subTest(nested=nested_type.__name__, mutation="deleted"):
                self.assertFalse(is_issued_boot_binding_v3(binding))
            object.__setattr__(snapshot, declared.name, value)
            self.assertFalse(is_issued_boot_binding_v3(binding))

        binding = _binding()
        snapshot = binding.process_authority

        class SameFqcnSnapshot(type(snapshot)):
            pass

        SameFqcnSnapshot.__module__ = type(snapshot).__module__
        SameFqcnSnapshot.__qualname__ = type(snapshot).__qualname__
        forged_snapshot = object.__new__(SameFqcnSnapshot)
        forged_snapshot.__dict__.update(snapshot.__dict__)
        object.__setattr__(binding, "process_authority", forged_snapshot)
        self.assertFalse(is_issued_boot_binding_v3(binding))

        SameFqcnEnum = Enum(
            type(snapshot).__name__,
            {"FORGED": "forged"},
            module=type(snapshot).__module__,
        )
        SameFqcnEnum.__qualname__ = type(snapshot).__qualname__
        binding = _binding()
        object.__setattr__(
            binding,
            "process_authority",
            next(iter(SameFqcnEnum)),
        )
        self.assertFalse(is_issued_boot_binding_v3(binding))

    def test_engine_identity_clones_reject_while_the_recorded_engine_stays_valid(self) -> None:
        engine = _engine()
        state_before = engine._state
        pending_before = engine._pending
        clones: list[BootTransitionEngineV3] = [copy.copy(engine), copy.deepcopy(engine)]
        exact_clone = object.__new__(BootTransitionEngineV3)
        exact_clone.__dict__.update(engine.__dict__)
        clones.append(exact_clone)
        for clone in clones:
            for operation in (
                lambda clone=clone: clone.state,
                lambda clone=clone: clone.failure_diagnostic_token,
                lambda clone=clone: clone.contract_sha256,
                lambda clone=clone: clone.pcr15_measurement_v3,
                lambda clone=clone: clone.predicted_pcr15_v3,
                clone.next_effect,
                lambda clone=clone: clone.advance(None),
                lambda clone=clone: clone.accept(None),
                clone.admit_serving_authority,
            ):
                _exact_binding_error(self, operation)
        self.assertIs(engine._state, state_before)
        self.assertIs(engine._pending, pending_before)
        self.assertIsNotNone(engine.next_effect())
        with self.assertRaises(AttributeError):
            engine.state = BootTransitionStateV3.SERVING_AVAILABLE
        with self.assertRaises(AttributeError):
            engine.failure_diagnostic_token = "forged"

    def test_wrapper_and_session_identity_guards_and_session_opacity(self) -> None:
        engine = _engine(serving=True)
        wrapper = engine.admit_serving_authority()
        handle = object()
        session = wrapper.open_session(_SessionTransport(handle), lambda: None)
        assert session is not None
        sessions_before = dict(wrapper._sessions)
        reducers_before = dict(wrapper._reducers)
        resource_sessions_before = dict(wrapper._resource.sessions)
        with self.assertRaises(AttributeError):
            _ = session.session_reducer

        wrapper_clones = [copy.copy(wrapper), copy.deepcopy(wrapper)]
        exact_clone = object.__new__(ServingAuthorityWrapperV3)
        exact_clone.__dict__.update(wrapper.__dict__)
        wrapper_clones.append(exact_clone)
        for clone in wrapper_clones:
            for operation in (
                lambda clone=clone: clone.open_session(None, None),
                lambda clone=clone: clone.begin_request(None, path="/", body_length=0, opaque_handle=None),
                lambda clone=clone: clone.work_begin(None, b""),
                lambda clone=clone: clone.work_finish(None, b"", WorkFinishOutcomeV3.ORDINARY),
                lambda clone=clone: clone.request_release(None, b""),
                lambda clone=clone: clone.session_release(None),
                clone.global_revoke,
                lambda clone=clone: clone.next_effect(None),
                lambda clone=clone: clone.advance(None, None),
                lambda clone=clone: clone.accept(None, None),
                lambda clone=clone: clone.collector_acquire(None, CollectorGenerationV3.CERTIFICATE),
                lambda clone=clone: clone.collector_finish(None, CollectorGenerationV3.CERTIFICATE, b""),
                lambda clone=clone: clone.collector_abort(None, CollectorGenerationV3.CERTIFICATE, b""),
            ):
                _exact_binding_error(self, operation)

        session_clones = [copy.copy(session), copy.deepcopy(session)]
        exact_session_clone = object.__new__(type(session))
        object.__setattr__(
            exact_session_clone,
            "session_token",
            session.session_token,
        )
        session_clones.append(exact_session_clone)
        for session_clone in session_clones:
            for operation in (
                lambda session_clone=session_clone: wrapper.begin_request(
                    session_clone,
                    path="/v1/inference",
                    body_length=0,
                    opaque_handle=None,
                ),
                lambda session_clone=session_clone: wrapper.work_begin(
                    session_clone, b""
                ),
                lambda session_clone=session_clone: wrapper.work_finish(
                    session_clone, b"", WorkFinishOutcomeV3.ORDINARY
                ),
                lambda session_clone=session_clone: wrapper.request_release(
                    session_clone, b""
                ),
                lambda session_clone=session_clone: wrapper.session_release(
                    session_clone
                ),
                lambda session_clone=session_clone: wrapper.next_effect(session_clone),
                lambda session_clone=session_clone: wrapper.advance(session_clone, None),
                lambda session_clone=session_clone: wrapper.accept(session_clone, None),
                lambda session_clone=session_clone: wrapper.collector_acquire(
                    session_clone, CollectorGenerationV3.CERTIFICATE
                ),
                lambda session_clone=session_clone: wrapper.collector_finish(
                    session_clone, CollectorGenerationV3.CERTIFICATE, b""
                ),
                lambda session_clone=session_clone: wrapper.collector_abort(
                    session_clone, CollectorGenerationV3.CERTIFICATE, b""
                ),
            ):
                with self.assertRaises(ApplianceErrorV3) as raised:
                    operation()
                self.assertEqual(
                    raised.exception.reason_code,
                    CP_BOOT_V3_RESOURCE_REDUCER,
                )
        self.assertEqual(wrapper._sessions, sessions_before)
        self.assertEqual(wrapper._reducers, reducers_before)
        self.assertEqual(wrapper._resource.sessions, resource_sessions_before)
        self.assertIsNone(wrapper.next_effect(session))

    def test_engine_claim_is_atomic_and_permanent(self) -> None:
        binding = _binding()
        barrier = threading.Barrier(4)
        winners: list[BootTransitionEngineV3] = []
        errors: list[ApplianceErrorV3] = []

        def construct() -> None:
            barrier.wait()
            try:
                winners.append(BootTransitionEngineV3(binding))
            except ApplianceErrorV3 as error:
                errors.append(error)

        threads = [threading.Thread(target=construct) for _ in range(3)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(5)
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(errors), 2)
        self.assertTrue(all(error.reason_code == CP_BOOT_V3_BINDING for error in errors))
        self.assertTrue(all(
            str(error)
            == "CP_BOOT_V3_BINDING: binding already has a transition engine"
            for error in errors
        ))
        del winners[:]
        gc.collect()
        with self.assertRaises(ApplianceErrorV3) as raised:
            BootTransitionEngineV3(binding)
        self.assertEqual(
            str(raised.exception),
            "CP_BOOT_V3_BINDING: binding already has a transition engine",
        )

    def test_valid_record_replay_cannot_rollback_transition_high_water(self) -> None:
        binding = _binding()
        binding_id = id(binding)
        pre_claim = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        high_water = (
            boot_v3._ISSUED_BOOT_BINDINGS_V3.transition_high_water[binding_id]
        )
        winner = BootTransitionEngineV3(binding)
        winner_contract = winner.contract_sha256
        claimed = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        self.assertGreater(claimed.transition_counter, pre_claim.transition_counter)

        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = pre_claim
        with self.assertRaises(ApplianceErrorV3) as raised:
            BootTransitionEngineV3(binding)
        self.assertEqual(
            str(raised.exception),
            "CP_BOOT_V3_BINDING: binding already has a transition engine",
        )
        self.assertIs(
            boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id], claimed
        )
        self.assertIs(
            boot_v3._ISSUED_BOOT_BINDINGS_V3
            .transition_high_water[binding_id]
            .current_record,
            claimed,
        )
        self.assertIs(
            boot_v3._ISSUED_BOOT_BINDINGS_V3.transition_high_water[binding_id],
            high_water,
        )
        self.assertNotIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones)
        self.assertEqual(winner.contract_sha256, winner_contract)

        winner._state = BootTransitionStateV3.SERVING_AVAILABLE
        pre_capability = claimed
        capability = boot_v3._serving_admission_capability_v3(winner)
        pre_admitted = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        wrapper = winner.admit_serving_authority()
        admitted = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        self.assertGreater(
            pre_admitted.transition_counter, pre_capability.transition_counter
        )
        self.assertGreater(
            admitted.transition_counter, pre_admitted.transition_counter
        )
        self.assertIs(admitted.admission_capability, capability)
        self.assertIs(admitted.admitted_wrapper_ref(), wrapper)

        for stale in (pre_capability, pre_admitted):
            boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = stale
            self.assertIs(winner.admit_serving_authority(), wrapper)
            self.assertIs(
                boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id], admitted
            )
            self.assertIs(
                boot_v3._ISSUED_BOOT_BINDINGS_V3
                .transition_high_water[binding_id]
                .current_record,
                admitted,
            )
        self.assertEqual(wrapper._revoke_count, 0)
        self.assertFalse(wrapper._resource.revoked)
        self.assertNotIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones)

    def test_missing_current_record_is_terminal_only_under_authentic_high_water(self) -> None:
        binding = _binding()
        binding_id = id(binding)
        saved_record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        authentic = (
            boot_v3._ISSUED_BOOT_BINDINGS_V3.transition_high_water[binding_id]
        )
        forged = copy.copy(authentic)

        dead_binding = _binding()
        dead_high_water = (
            boot_v3._ISSUED_BOOT_BINDINGS_V3
            .transition_high_water[id(dead_binding)]
        )
        dead_reference = weakref.ref(dead_binding)
        del dead_binding
        gc.collect()
        self.assertIsNone(dead_reference())

        foreign_binding = _binding()
        foreign_high_water = (
            boot_v3._ISSUED_BOOT_BINDINGS_V3
            .transition_high_water[id(foreign_binding)]
        )
        for unauthoritative in (forged, dead_high_water, foreign_high_water):
            boot_v3._ISSUED_BOOT_BINDINGS_V3.transition_high_water[
                binding_id
            ] = unauthoritative
            del boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
            self.assertFalse(is_issued_boot_binding_v3(binding))
            self.assertNotIn(
                binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones
            )
            boot_v3._ISSUED_BOOT_BINDINGS_V3.transition_high_water[
                binding_id
            ] = authentic
            boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = saved_record
            self.assertTrue(is_issued_boot_binding_v3(binding))

        pristine = _binding()
        pristine_id = id(pristine)
        pristine_record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[pristine_id]
        del boot_v3._ISSUED_BOOT_BINDINGS_V3.records[pristine_id]
        self.assertFalse(is_issued_boot_binding_v3(pristine))
        self.assertIn(pristine_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones)
        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[pristine_id] = pristine_record
        self.assertFalse(is_issued_boot_binding_v3(pristine))
        _exact_binding_error(self, lambda: BootTransitionEngineV3(pristine))

        serving_binding = _binding()
        serving_id = id(serving_binding)
        engine = BootTransitionEngineV3(serving_binding)
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        wrapper = engine.admit_serving_authority()
        admitted_record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[serving_id]
        del boot_v3._ISSUED_BOOT_BINDINGS_V3.records[serving_id]
        _exact_binding_error(self, lambda: engine.state)
        self.assertIn(serving_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones)
        self.assertNotIn(serving_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.records)
        self.assertEqual(wrapper._cleanup_phase, "complete")
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertEqual(wrapper._sessions, {})
        self.assertEqual(wrapper._reducers, {})
        self.assertTrue(wrapper._resource.revoked)

        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[serving_id] = admitted_record
        _exact_binding_error(self, lambda: engine.state)
        self.assertFalse(is_issued_boot_binding_v3(serving_binding))
        self.assertNotIn(serving_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.records)
        self.assertEqual(wrapper._revoke_count, 1)

    def test_admission_linearizes_failure_retries_and_retirement(self) -> None:
        engine = _engine(serving=True)
        barrier = threading.Barrier(4)
        wrappers: list[ServingAuthorityWrapperV3] = []

        def admit() -> None:
            barrier.wait()
            wrappers.append(engine.admit_serving_authority())

        threads = [threading.Thread(target=admit) for _ in range(3)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(5)
        self.assertEqual(len(wrappers), 3)
        self.assertTrue(all(wrapper is wrappers[0] for wrapper in wrappers))

        retry_engine = _engine(serving=True)
        original_init = boot_v3.ServingAuthorityWrapperV3.__init__
        failed = False

        def fail_once(self: ServingAuthorityWrapperV3, **kwargs: object) -> None:
            nonlocal failed
            if not failed:
                failed = True
                raise _ConstructionFailure("planned")
            original_init(self, **kwargs)

        boot_v3.ServingAuthorityWrapperV3.__init__ = fail_once
        try:
            with self.assertRaises(_ConstructionFailure):
                retry_engine.admit_serving_authority()
        finally:
            boot_v3.ServingAuthorityWrapperV3.__init__ = original_init
        self.assertIsInstance(retry_engine.admit_serving_authority(), ServingAuthorityWrapperV3)

    def test_cleanup_linearizes_callbacks_and_retirement(self) -> None:
        engine = _engine(serving=True)
        wrapper = engine.admit_serving_authority()
        entered = threading.Event()
        release = threading.Event()
        closed: list[str] = []
        reentered: list[object] = []

        def first() -> None:
            closed.append("first")
            reentered.append(wrapper.global_revoke())
            entered.set()
            self.assertTrue(release.wait(5))

        for callback in (first, lambda: closed.append("middle"), lambda: closed.append("last")):
            session = wrapper.open_session(_SessionTransport(object()), callback)
            assert session is not None
        outcomes: list[BaseException] = []

        def revoke() -> None:
            try:
                wrapper.global_revoke()
            except BaseException as error:
                outcomes.append(error)

        owner = threading.Thread(target=revoke)
        owner.start()
        self.assertTrue(entered.wait(5))
        waiter = threading.Thread(target=revoke)
        waiter.start()
        self.assertFalse(release.is_set())
        release.set()
        owner.join(5)
        waiter.join(5)
        self.assertFalse(owner.is_alive())
        self.assertFalse(waiter.is_alive())
        self.assertEqual(outcomes, [])
        self.assertEqual(closed, ["first", "middle", "last"])
        self.assertEqual(reentered, [None])
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertEqual(wrapper._sessions, {})
        self.assertEqual(wrapper._reducers, {})
        self.assertEqual(wrapper._resource.sessions, {})
        self.assertTrue(wrapper._resource.revoked)
        _binding_error(self, engine.admit_serving_authority)

        error_engine = _engine(serving=True)
        error_wrapper = error_engine.admit_serving_authority()
        session = error_wrapper.open_session(_SessionTransport(object()), lambda: (_ for _ in ()).throw(SystemExit("close")))
        assert session is not None
        with self.assertRaises(SystemExit):
            error_wrapper.global_revoke()
        self.assertEqual(error_wrapper._sessions, {})
        self.assertEqual(error_wrapper._reducers, {})
        with self.assertRaises(SystemExit):
            error_wrapper.global_revoke()

    def test_cleanup_waiter_releases_operation_lock_before_owner_reentry(self) -> None:
        engine = _engine(serving=True)
        wrapper = engine.admit_serving_authority()
        callback_entered = threading.Event()
        waiter_waiting = threading.Event()
        allow_reentry = threading.Event()
        reentered: list[object] = []
        errors: list[BaseException] = []
        waiter_thread_id: list[int] = []
        original_wait = wrapper._cleanup_condition.wait

        def tracked_wait(timeout: float | None = None) -> bool:
            if waiter_thread_id and threading.get_ident() == waiter_thread_id[0]:
                waiter_waiting.set()
            return original_wait(timeout)

        def close_callback() -> None:
            callback_entered.set()
            self.assertTrue(allow_reentry.wait(5))
            reentered.append(wrapper.global_revoke())

        session = wrapper.open_session(_SessionTransport(object()), close_callback)
        assert session is not None
        wrapper._cleanup_condition.wait = tracked_wait

        def revoke(*, waiter: bool = False) -> None:
            if waiter:
                waiter_thread_id.append(threading.get_ident())
            try:
                wrapper.global_revoke()
            except BaseException as error:
                errors.append(error)

        owner = threading.Thread(target=revoke)
        owner.start()
        self.assertTrue(callback_entered.wait(5))
        waiter = threading.Thread(target=lambda: revoke(waiter=True))
        waiter.start()
        try:
            self.assertTrue(waiter_waiting.wait(5))
            allow_reentry.set()
            owner.join(5)
            waiter.join(5)
        finally:
            wrapper._cleanup_condition.wait = original_wait
        self.assertFalse(owner.is_alive())
        self.assertFalse(waiter.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(reentered, [None])
        self.assertEqual(wrapper._revoke_count, 1)

    def test_engine_detected_mismatch_permanently_cleans_wrapper_once(self) -> None:
        binding = _binding()
        engine = BootTransitionEngineV3(binding)
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        wrapper = engine.admit_serving_authority()
        closed: list[str] = []
        callback_lock_state: list[tuple[bool, bool]] = []
        sessions = []

        def first() -> None:
            callback_lock_state.append((
                wrapper._operation_lock._is_owned(),
                boot_v3._ISSUED_BOOT_BINDINGS_V3.lock._is_owned(),
            ))
            closed.append("first")

        def reenter() -> None:
            closed.append("reenter")
            _exact_binding_error(self, lambda: wrapper.next_effect(sessions[0]))

        callbacks = (
            first,
            reenter,
            lambda: (_ for _ in ()).throw(SystemExit("discarded")),
        )
        for callback in callbacks:
            session = wrapper.open_session(_SessionTransport(object()), callback)
            assert session is not None
            sessions.append(session)
        state_before = engine._state
        pending_before = engine._pending
        original = binding.root_lock_bytes
        object.__setattr__(binding, "root_lock_bytes", original + b"observed-mismatch")
        _exact_binding_error(self, lambda: engine.contract_sha256)
        object.__setattr__(binding, "root_lock_bytes", original)

        self.assertEqual(engine._state, state_before)
        self.assertIs(engine._pending, pending_before)
        self.assertEqual(closed, ["first", "reenter"])
        self.assertEqual(callback_lock_state, [(False, False)])
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertEqual(wrapper._cleanup_phase, "complete")
        self.assertEqual(wrapper._sessions, {})
        self.assertEqual(wrapper._reducers, {})
        self.assertEqual(wrapper._resource.sessions, {})
        self.assertTrue(wrapper._resource.revoked)
        self.assertFalse(is_issued_boot_binding_v3(binding))
        for operation in (
            lambda: engine.state,
            lambda: engine.failure_diagnostic_token,
            engine.next_effect,
            engine.admit_serving_authority,
            lambda: wrapper.next_effect(sessions[0]),
            wrapper.global_revoke,
        ):
            _exact_binding_error(self, operation)
        self.assertEqual(wrapper._revoke_count, 1)
        engine_reference = weakref.ref(engine)
        del engine
        gc.collect()
        self.assertIsNone(engine_reference())
        for operation in (
            wrapper.global_revoke,
            lambda: wrapper.next_effect(sessions[0]),
        ):
            _exact_binding_error(self, operation)
        clones = [copy.copy(wrapper), copy.deepcopy(wrapper)]
        exact_clone = object.__new__(ServingAuthorityWrapperV3)
        exact_clone.__dict__.update(wrapper.__dict__)
        clones.append(exact_clone)
        for clone in clones:
            _exact_binding_error(self, clone.global_revoke)
            _exact_binding_error(self, lambda clone=clone: clone.next_effect(sessions[0]))
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertEqual(wrapper._cleanup_phase, "complete")
        self.assertEqual(wrapper._sessions, {})
        self.assertEqual(wrapper._reducers, {})
        self.assertEqual(wrapper._resource.sessions, {})
        self.assertTrue(wrapper._resource.revoked)

    def test_normal_cleanup_promotes_to_terminal_mismatch_after_record_loss(self) -> None:
        binding = _binding()
        binding_id = id(binding)
        engine = BootTransitionEngineV3(binding)
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        wrapper = engine.admit_serving_authority()
        closed: list[str] = []
        session = wrapper.open_session(
            _SessionTransport(object()), lambda: closed.append("closed")
        )
        assert session is not None

        wrapper.global_revoke()
        self.assertEqual(closed, ["closed"])
        self.assertEqual(wrapper._cleanup_phase, "complete")
        self.assertFalse(wrapper._cleanup_binding_mismatch)
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertEqual(wrapper._sessions, {})
        self.assertEqual(wrapper._reducers, {})
        self.assertTrue(wrapper._resource.revoked)

        clones = [wrapper, copy.copy(wrapper), copy.deepcopy(wrapper)]
        exact_clone = object.__new__(ServingAuthorityWrapperV3)
        exact_clone.__dict__.update(wrapper.__dict__)
        clones.append(exact_clone)
        self.assertTrue(all(
            candidate._cleanup_state is wrapper._cleanup_state
            for candidate in clones
        ))

        del boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        _exact_binding_error(self, lambda: engine.state)
        self.assertTrue(wrapper._cleanup_binding_mismatch)
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertEqual(closed, ["closed"])

        engine_reference = weakref.ref(engine)
        del engine
        gc.collect()
        self.assertIsNone(engine_reference())
        for candidate in clones:
            _exact_binding_error(self, candidate.global_revoke)
            _exact_binding_error(
                self,
                lambda candidate=candidate: candidate.next_effect(session),
            )
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertEqual(wrapper._cleanup_phase, "complete")
        self.assertEqual(wrapper._sessions, {})
        self.assertEqual(wrapper._reducers, {})
        self.assertEqual(wrapper._resource.sessions, {})
        self.assertTrue(wrapper._resource.revoked)
        self.assertEqual(closed, ["closed"])

    def test_wrapper_resolves_registry_loss_before_dead_engine_staleness(self) -> None:
        binding = _binding()
        binding_id = id(binding)
        engine = BootTransitionEngineV3(binding)
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        wrapper = engine.admit_serving_authority()
        closed: list[str] = []
        session = wrapper.open_session(
            _SessionTransport(object()), lambda: closed.append("closed")
        )
        assert session is not None
        wrapper.global_revoke()

        clones = [copy.copy(wrapper), copy.deepcopy(wrapper)]
        exact_clone = object.__new__(ServingAuthorityWrapperV3)
        exact_clone.__dict__.update(wrapper.__dict__)
        clones.extend((exact_clone, wrapper))
        self.assertTrue(all(
            candidate._cleanup_state is wrapper._cleanup_state
            for candidate in clones
        ))

        del boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        engine_reference = weakref.ref(engine)
        del engine
        gc.collect()
        self.assertIsNone(engine_reference())
        for candidate in clones:
            _exact_binding_error(self, candidate.global_revoke)
            _exact_binding_error(
                self,
                lambda candidate=candidate: candidate.next_effect(session),
            )
        self.assertIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones)
        self.assertTrue(wrapper._cleanup_binding_mismatch)
        self.assertEqual(wrapper._cleanup_phase, "complete")
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertEqual(wrapper._sessions, {})
        self.assertEqual(wrapper._reducers, {})
        self.assertEqual(wrapper._resource.sessions, {})
        self.assertTrue(wrapper._resource.revoked)
        self.assertEqual(closed, ["closed"])

        valid_engine = _engine(serving=True)
        valid_wrapper = valid_engine.admit_serving_authority()
        valid_wrapper.global_revoke()
        valid_reference = weakref.ref(valid_engine)
        del valid_engine
        gc.collect()
        self.assertIsNone(valid_reference())
        with self.assertRaises(ApplianceErrorV3) as raised:
            valid_wrapper.global_revoke()
        self.assertEqual(
            str(raised.exception),
            "CP_BOOT_V3_BINDING: serving admission capability is stale",
        )
        self.assertFalse(valid_wrapper._cleanup_binding_mismatch)
        self.assertEqual(valid_wrapper._revoke_count, 1)

    def test_mismatch_cleanup_callback_matrix_and_detector_waiter(self) -> None:
        for behaviors in (
            ("throw", "return", "return"),
            ("return", "throw", "return"),
            ("throw", "throw", "throw"),
            ("reenter", "return", "throw"),
        ):
            with self.subTest(behaviors=behaviors):
                binding = _binding()
                engine = BootTransitionEngineV3(binding)
                engine._state = BootTransitionStateV3.SERVING_AVAILABLE
                wrapper = engine.admit_serving_authority()
                invoked: list[int] = []
                sessions = []

                def callback(index: int, behavior: str) -> object:
                    def close() -> None:
                        invoked.append(index)
                        if behavior == "throw":
                            raise SystemExit(f"close-{index}")
                        if behavior == "reenter":
                            _exact_binding_error(
                                self,
                                lambda: wrapper.next_effect(sessions[0]),
                            )
                    return close

                for index, behavior in enumerate(behaviors):
                    session = wrapper.open_session(
                        _SessionTransport(object()),
                        callback(index, behavior),
                    )
                    assert session is not None
                    sessions.append(session)
                original = binding.root_lock_bytes
                object.__setattr__(binding, "root_lock_bytes", original + b"matrix")
                _exact_binding_error(self, lambda: engine.contract_sha256)
                object.__setattr__(binding, "root_lock_bytes", original)
                self.assertEqual(invoked, [0, 1, 2])
                self.assertEqual(wrapper._cleanup_phase, "complete")
                self.assertEqual(wrapper._revoke_count, 1)
                self.assertEqual(wrapper._sessions, {})
                self.assertEqual(wrapper._reducers, {})
                self.assertEqual(wrapper._resource.sessions, {})
                self.assertTrue(wrapper._resource.revoked)
                _exact_binding_error(self, lambda: wrapper.next_effect(sessions[0]))
                self.assertEqual(wrapper._revoke_count, 1)

        binding = _binding()
        engine = BootTransitionEngineV3(binding)
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        wrapper = engine.admit_serving_authority()
        callback_entered = threading.Event()
        release_callback = threading.Event()
        waiter_waiting = threading.Event()
        waiter_thread_id: list[int] = []
        original_wait = wrapper._cleanup_condition.wait
        sessions = []

        def tracked_wait(timeout: float | None = None) -> bool:
            if waiter_thread_id and threading.get_ident() == waiter_thread_id[0]:
                waiter_waiting.set()
            return original_wait(timeout)

        def blocking_close() -> None:
            self.assertFalse(wrapper._operation_lock._is_owned())
            self.assertFalse(boot_v3._ISSUED_BOOT_BINDINGS_V3.lock._is_owned())
            callback_entered.set()
            self.assertTrue(release_callback.wait(5))

        def reentering_close() -> None:
            _exact_binding_error(self, lambda: wrapper.next_effect(sessions[0]))

        for close in (blocking_close, reentering_close, lambda: (_ for _ in ()).throw(SystemExit())):
            session = wrapper.open_session(_SessionTransport(object()), close)
            assert session is not None
            sessions.append(session)
        wrapper._cleanup_condition.wait = tracked_wait
        original = binding.root_lock_bytes
        object.__setattr__(binding, "root_lock_bytes", original + b"detector-race")
        errors: list[BaseException] = []

        def detect(*, waiter: bool = False) -> None:
            if waiter:
                waiter_thread_id.append(threading.get_ident())
            try:
                if waiter:
                    wrapper.next_effect(sessions[0])
                else:
                    _ = engine.contract_sha256
            except BaseException as error:
                errors.append(error)

        owner = threading.Thread(target=detect)
        waiter = threading.Thread(target=lambda: detect(waiter=True))
        try:
            owner.start()
            self.assertTrue(callback_entered.wait(5))
            waiter.start()
            self.assertTrue(waiter_waiting.wait(5))
            self.assertTrue(waiter.is_alive())
            release_callback.set()
            owner.join(5)
            waiter.join(5)
        finally:
            object.__setattr__(binding, "root_lock_bytes", original)
            release_callback.set()
            wrapper._cleanup_condition.wait = original_wait
        self.assertFalse(owner.is_alive())
        self.assertFalse(waiter.is_alive())
        self.assertEqual(len(errors), 2)
        self.assertTrue(all(type(error) is ApplianceErrorV3 for error in errors))
        self.assertTrue(all(
            str(error) == "CP_BOOT_V3_BINDING: binding was not issued"
            for error in errors
        ))
        self.assertEqual(wrapper._cleanup_phase, "complete")
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertEqual(wrapper._sessions, {})
        self.assertEqual(wrapper._reducers, {})
        self.assertEqual(wrapper._resource.sessions, {})

    def test_inline_binding_liveness_and_generation_qualified_retirement(self) -> None:
        engine = BootTransitionEngineV3(_binding())
        binding = engine._binding_liveness_anchor
        binding_id = id(binding)
        record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        reference = weakref.ref(binding)
        del binding
        gc.collect()
        self.assertIsNotNone(reference())
        self.assertEqual(engine.state, BootTransitionStateV3.PID1_IDENTITY_ESTABLISHED)
        boot_v3._retire_boot_binding_v3(binding_id, record.generation - 1)
        self.assertIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.records)

        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        wrapper = engine.admit_serving_authority()
        gc.collect()
        self.assertIsNotNone(reference())
        self.assertIs(wrapper, engine.admit_serving_authority())
        del engine
        gc.collect()
        self.assertIsNotNone(reference())
        del wrapper
        gc.collect()
        self.assertIsNone(reference())
        self.assertNotIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.records)

    def test_registry_record_retires_when_the_binding_is_collected(self) -> None:
        binding = _binding()
        binding_id = id(binding)
        reference = weakref.ref(binding)
        self.assertIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.records)
        self.assertIn(
            binding_id,
            boot_v3._ISSUED_BOOT_BINDINGS_V3.transition_high_water,
        )
        del binding
        gc.collect()
        self.assertIsNone(reference())
        self.assertNotIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.records)
        self.assertNotIn(
            binding_id,
            boot_v3._ISSUED_BOOT_BINDINGS_V3.transition_high_water,
        )

    def test_tombstone_is_generation_qualified_and_weak(self) -> None:
        binding = _binding()
        binding_id = id(binding)
        generation = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id].generation
        original = binding.root_lock_bytes
        object.__setattr__(binding, "root_lock_bytes", original + b"tombstone")
        self.assertFalse(is_issued_boot_binding_v3(binding))
        object.__setattr__(binding, "root_lock_bytes", original)
        self.assertIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones)
        boot_v3._retire_boot_binding_v3(binding_id, generation - 1)
        self.assertIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones)
        with self.assertRaises(ApplianceErrorV3) as raised:
            boot_v3._register_boot_binding_v3(binding)
        self.assertEqual(
            str(raised.exception),
            "CP_BOOT_V3_BINDING: binding was not issued",
        )
        reference = weakref.ref(binding)
        del binding
        gc.collect()
        self.assertIsNone(reference())
        self.assertNotIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones)

    def test_live_exact_tombstone_dominates_saved_valid_record_replay(self) -> None:
        binding = _binding()
        binding_id = id(binding)
        record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]

        forged = boot_v3._BindingTombstoneV3(
            record.binding_ref, record.generation, b"\0" * 32
        )
        boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id] = forged
        self.assertTrue(is_issued_boot_binding_v3(binding))
        self.assertIs(boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id], record)

        class WeakCarrier:
            pass

        carrier = WeakCarrier()
        dead_reference = weakref.ref(carrier)
        del carrier
        gc.collect()
        self.assertIsNone(dead_reference())
        boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id] = (
            boot_v3._new_tombstone_v3(dead_reference, record.generation)
        )
        self.assertTrue(is_issued_boot_binding_v3(binding))
        self.assertIs(boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id], record)

        other_binding = _binding()
        other_record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[id(other_binding)]
        foreign = boot_v3._new_tombstone_v3(
            other_record.binding_ref, record.generation + 1
        )
        boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id] = foreign
        self.assertTrue(is_issued_boot_binding_v3(binding))
        self.assertIs(boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id], record)
        del boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id]

        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = replace(record)
        self.assertFalse(is_issued_boot_binding_v3(binding))
        cross_generation_tombstone = (
            boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id]
        )
        self.assertNotEqual(
            cross_generation_tombstone.generation, record.generation
        )
        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = record
        self.assertFalse(is_issued_boot_binding_v3(binding))
        self.assertNotIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.records)
        self.assertIs(
            boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id],
            cross_generation_tombstone,
        )

        binding = _binding()
        binding_id = id(binding)
        engine = BootTransitionEngineV3(binding)
        engine._state = BootTransitionStateV3.SERVING_AVAILABLE
        wrapper = engine.admit_serving_authority()
        saved_record = boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        original = binding.root_lock_bytes
        object.__setattr__(binding, "root_lock_bytes", original + b"retire")
        _exact_binding_error(self, lambda: engine.state)
        object.__setattr__(binding, "root_lock_bytes", original)
        tombstone = boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id]
        self.assertEqual(wrapper._cleanup_phase, "complete")
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertTrue(wrapper._resource.revoked)

        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = saved_record
        _exact_binding_error(self, lambda: engine.state)
        self.assertNotIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.records)
        self.assertIs(
            boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id], tombstone
        )

        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = saved_record
        _exact_binding_error(
            self,
            lambda: wrapper.open_session(_SessionTransport(object()), lambda: None),
        )
        self.assertNotIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.records)
        self.assertIs(
            boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id], tombstone
        )

        boot_v3._ISSUED_BOOT_BINDINGS_V3.records[binding_id] = saved_record
        _exact_binding_error(
            self, lambda: boot_v3._register_boot_binding_v3(binding)
        )
        self.assertIs(
            boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id], tombstone
        )
        self.assertFalse(is_issued_boot_binding_v3(binding))
        self.assertNotIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.records)
        self.assertIs(
            boot_v3._ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id], tombstone
        )
        self.assertEqual(wrapper._cleanup_phase, "complete")
        self.assertEqual(wrapper._revoke_count, 1)
        self.assertTrue(wrapper._resource.revoked)
        _exact_binding_error(self, lambda: engine.contract_sha256)


if __name__ == "__main__":
    unittest.main()
