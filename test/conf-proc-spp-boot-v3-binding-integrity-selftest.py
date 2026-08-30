#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Focused issuance, identity, and serving-cleanup tests for SPP boot v3."""

from __future__ import annotations

import copy
import gc
import sys
import threading
import unittest
import weakref
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import conf_proc_spp_boot as boot
import conf_proc_spp_boot_v3 as boot_v3
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
        engine.state = BootTransitionStateV3.SERVING_AVAILABLE
    return engine


def _binding_error(test: unittest.TestCase, operation: object) -> None:
    with test.assertRaises(ApplianceErrorV3) as raised:
        assert callable(operation)
        operation()
    test.assertEqual(raised.exception.reason_code, CP_BOOT_V3_BINDING)


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


class _ConstructionFailure(BaseException):
    pass


class BootBindingIntegritySelftest(unittest.TestCase):
    def test_type_tag_map_covers_every_reachable_nonprimitive_type(self) -> None:
        binding = _binding()
        encountered = {type(value) for value in _walk_non_primitives(binding)}
        self.assertTrue(encountered)
        self.assertTrue(encountered <= set(boot_v3._BINDING_TYPE_TAGS_V3))
        self.assertIsInstance(boot_v3._BINDING_TYPE_TAGS_V3, type(boot_v3.MappingProxyType({})))

    def test_verified_material_is_detached_and_every_entry_reverifies(self) -> None:
        engine = _engine()
        baseline_contract = engine.contract_sha256
        baseline_measurement = engine.pcr15_measurement_v3
        baseline_effect = engine.next_effect()
        record = engine._verify_v3()
        self.assertIsNot(record.material, engine.binding)
        original = engine.binding.root_lock_bytes
        self.assertEqual(record.material.root_lock_bytes, original)

        object.__setattr__(engine.binding, "root_lock_bytes", original + b"racing-mutation")
        self.assertEqual(record.material.root_lock_bytes, original)
        self.assertNotEqual(engine.binding.root_lock_bytes, record.material.root_lock_bytes)
        for operation in (
            lambda: engine.contract_sha256,
            lambda: engine.pcr15_measurement_v3,
            engine.next_effect,
        ):
            _binding_error(self, operation)
        object.__setattr__(engine.binding, "root_lock_bytes", original)
        self.assertEqual(engine.contract_sha256, baseline_contract)
        self.assertEqual(engine.pcr15_measurement_v3, baseline_measurement)
        self.assertIs(engine.next_effect(), baseline_effect)

    def test_direct_wrapper_construction_requires_a_live_capability(self) -> None:
        def rejected(capability: object = None) -> None:
            _binding_error(
                self,
                lambda: ServingAuthorityWrapperV3(admission_capability=capability),
            )

        rejected()
        rejected(object())

        class ServingAdmissionCapabilityV3:
            pass

        ServingAdmissionCapabilityV3.__module__ = boot_v3.ServingAdmissionCapabilityV3.__module__
        rejected(ServingAdmissionCapabilityV3())

        foreign_engine = _engine(serving=True)
        foreign_capability = boot_v3._serving_admission_capability_v3(
            foreign_engine.binding, foreign_engine
        )
        rejected(foreign_capability)

        stale_binding = _binding()
        stale_engine = BootTransitionEngineV3(stale_binding)
        stale_capability = boot_v3._serving_admission_capability_v3(stale_binding, stale_engine)
        stale_reference = weakref.ref(stale_binding)
        del stale_engine
        del stale_binding
        gc.collect()
        self.assertIsNone(stale_reference())
        rejected(stale_capability)

        engine = _engine(serving=True)
        wrapper = engine.admit_serving_authority()
        capability = engine._verify_v3().admission_capability
        assert capability is not None
        rejected(capability)
        self.assertIs(wrapper, engine.admit_serving_authority())

    def test_concurrent_waiters_retry_after_the_builder_fails(self) -> None:
        engine = _engine(serving=True)
        capability = boot_v3._serving_admission_capability_v3(engine.binding, engine)
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

    def test_unpublished_admission_retirement_is_terminal(self) -> None:
        engine = _engine(serving=True)
        capability = boot_v3._serving_admission_capability_v3(engine.binding, engine)
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
            _binding_error(self, operation)
        object.__setattr__(binding, "root_lock_bytes", original)
        self.assertTrue(is_issued_boot_binding_v3(binding))
        self.assertIsNotNone(engine.next_effect())

        object.__setattr__(binding, "extra_field", 1)
        self.assertFalse(is_issued_boot_binding_v3(binding))
        object.__delattr__(binding, "extra_field")
        contract = binding.boot_contract
        object.__delattr__(binding, "boot_contract")
        self.assertFalse(is_issued_boot_binding_v3(binding))
        object.__setattr__(binding, "boot_contract", contract)
        self.assertTrue(is_issued_boot_binding_v3(binding))

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
        binding = _binding()
        for field in fields(binding):
            original = getattr(binding, field.name)
            object.__setattr__(binding, field.name, None if original is not None else "changed")
            with self.subTest(top_level=field.name):
                self.assertFalse(is_issued_boot_binding_v3(binding))
            object.__setattr__(binding, field.name, original)

        nested = [value for value in _walk_non_primitives(binding) if is_dataclass(value) and value is not binding]
        for snapshot in nested:
            field = fields(snapshot)[0]
            original = getattr(snapshot, field.name)
            object.__setattr__(snapshot, field.name, None if original is not None else "changed")
            with self.subTest(snapshot=type(snapshot).__name__, field=field.name):
                self.assertFalse(is_issued_boot_binding_v3(binding))
            object.__setattr__(snapshot, field.name, original)
        self.assertTrue(is_issued_boot_binding_v3(binding))

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

        @dataclass(frozen=True)
        class ForgedEnumCarrier:
            value: object

        original_process_authority = binding.process_authority
        object.__setattr__(binding, "process_authority", ForgedEnumCarrier(None))
        self.assertFalse(is_issued_boot_binding_v3(binding))
        object.__setattr__(binding, "process_authority", original_process_authority)
        self.assertTrue(is_issued_boot_binding_v3(binding))

    def test_engine_identity_clones_reject_while_the_recorded_engine_stays_valid(self) -> None:
        engine = _engine()
        clones: list[BootTransitionEngineV3] = [copy.copy(engine), copy.deepcopy(engine)]
        exact_clone = object.__new__(BootTransitionEngineV3)
        exact_clone.__dict__.update(engine.__dict__)
        clones.append(exact_clone)
        for clone in clones:
            for operation in (
                lambda clone=clone: clone.contract_sha256,
                lambda clone=clone: clone.pcr15_measurement_v3,
                lambda clone=clone: clone.predicted_pcr15_v3,
                clone.next_effect,
                lambda clone=clone: clone.advance(None),
                lambda clone=clone: clone.accept(None),
                clone.admit_serving_authority,
            ):
                _binding_error(self, operation)
        self.assertIsNotNone(engine.next_effect())

    def test_wrapper_and_session_identity_guards_and_session_opacity(self) -> None:
        engine = _engine(serving=True)
        wrapper = engine.admit_serving_authority()
        handle = object()
        session = wrapper.open_session(_SessionTransport(handle), lambda: None)
        assert session is not None
        with self.assertRaises(AttributeError):
            _ = session.session_reducer

        for clone in (copy.copy(wrapper), copy.deepcopy(wrapper)):
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
                _binding_error(self, operation)
        exact_clone = object.__new__(ServingAuthorityWrapperV3)
        exact_clone.__dict__.update(wrapper.__dict__)
        _binding_error(self, lambda: exact_clone.open_session(None, None))

        session_clone = copy.copy(session)
        with self.assertRaises(ApplianceErrorV3) as raised:
            wrapper.next_effect(session_clone)
        self.assertEqual(raised.exception.reason_code, CP_BOOT_V3_RESOURCE_REDUCER)
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
        del winners[:]
        gc.collect()
        _binding_error(self, lambda: BootTransitionEngineV3(binding))

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

    def test_registry_record_retires_when_the_binding_is_collected(self) -> None:
        binding = _binding()
        binding_id = id(binding)
        reference = weakref.ref(binding)
        self.assertIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.records)
        del binding
        gc.collect()
        self.assertIsNone(reference())
        self.assertNotIn(binding_id, boot_v3._ISSUED_BOOT_BINDINGS_V3.records)


if __name__ == "__main__":
    unittest.main()
