#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Focused self-tests for the additive v2 SPP boot authority."""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

import conf_proc_spp_boot as boot
from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_reasons import ApplianceError


_V1_SPEC = importlib.util.spec_from_file_location("_v1_boot_fixture", ROOT / "test" / "conf-proc-spp-boot-selftest.py")
assert _V1_SPEC is not None and _V1_SPEC.loader is not None
_V1 = importlib.util.module_from_spec(_V1_SPEC)
_V1_SPEC.loader.exec_module(_V1)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _v2_docs(*, jit_policy: object = None) -> dict[str, bytes]:
    docs = _V1.build_compact_fixture()
    contract = canonical_loads(docs["boot_contract_bytes"])
    contract["schema"] = boot.BOOT_CONTRACT_V2_SCHEMA
    contract["contract_version"] = 2
    contract["mutable_control_order"] = list(boot._CONTROL_ORDER_V2)
    contract["observation_contract_sha256"] = boot.OBSERVATION_CONTRACT_SHA256_V2
    contract["jit_policy"] = jit_policy
    docs["boot_contract_bytes"] = canonical_dumps(contract)
    plan = canonical_loads(docs["module_plan_bytes"])
    plan["boot_contract_sha256"] = _sha(docs["boot_contract_bytes"])
    docs["module_plan_bytes"] = canonical_dumps(plan)
    return docs


def _binding() -> boot.BootBindingV2:
    return boot.bind_boot_inputs_v2(**_v2_docs())


def _jit_policy() -> dict:
    return {
        "workspace": {"path": "/run/spp-jit", "mode": 0o700, "size_bytes": 1048576},
        "compiler_loader_args": list(boot.JIT_COMPILER_LOADER_ARGS_V2),
        "inputs": [{
            "kind": "source", "input_id": "source", "role": "conf_proc_source", "image_id": "runtime-policy",
            "path": "/usr/bin/spp", "sha256": _sha(b"compact builder source"), "size_bytes": len(b"compact builder source"), "mode": 0o644,
        }],
    }


def _observation(effect: boot.BootEffect) -> boot.BootObservation:
    contract = effect.contract_sha256
    if type(effect) is boot.BootstrapMountEffectV2:
        return boot.BootstrapMountReadbackV2(contract, effect.mount)
    if type(effect) in (boot.ApplyNetworkPolicyEffectV2, boot.ReadNetworkPolicyEffectV2):
        return boot.NetworkPolicyReadbackV2(contract, effect.policy)
    if type(effect) is boot.CheckCmdlineEffect:
        return boot.CmdlineObservation(contract, effect.cmdline, ())
    if type(effect) is boot.ReadPcr15Effect:
        return boot.Pcr15Readback(contract, effect.expected_value)
    if type(effect) is boot.LocateExpectedDiskEffect:
        return boot.DiskLocatorsObservation(contract, effect.disk_guid, effect.locators)
    if type(effect) is boot.MapVerityEffect:
        return boot.VerityMappedObservation(contract, effect.pair, effect.pair.image_id + "-map")
    if type(effect) is boot.VerifyVerityEffect:
        return boot.VerityVerifiedObservation(contract, effect.pair, effect.expected_mapping_identity)
    if type(effect) is boot.ReadMappingIdentityEffect:
        return boot.MappingIdentityObservation(contract, effect.pair, effect.expected_mapping_identity)
    if type(effect) is boot.MountImageEffect:
        return boot.MountReadback(contract, effect.image_id, effect.destination, effect.flags)
    if type(effect) is boot.ConfineRuntimeExecutablesEffect:
        return boot.RuntimeExecutableObservation(contract, effect.executable_paths)
    if type(effect) is boot.CheckMutableRootClassesEffectV2:
        return boot.MutableRootClassesReadbackV2(contract, effect.phase, effect.bootstrap_mounts, effect.application_roots)
    if type(effect) is boot.CreateTmpfsEffectV2:
        return boot.TmpfsReadbackV2(contract, effect.root)
    if type(effect) is boot.LoadModulesEffect:
        return boot.ModuleReadback(contract, tuple(entry.identity for entry in effect.entries))
    if type(effect) is boot.CloseModulesEffect:
        return boot.ModulesDisabledReadback(contract, boot.ModulesDisabledStatus.SET_TO_1)
    if type(effect) is boot.CloseMutableControlEffect:
        return boot.ControlReadback(contract, effect.control, boot.ControlReadbackStatus.DISABLED)
    if type(effect) is boot.ExtendPcr15Effect:
        return boot.Pcr15ExtendObservation(contract, boot.Pcr15ExtendOutcome.ACKNOWLEDGED)
    if type(effect) is boot.CloseTransportEffect:
        return boot.TransportClosedObservation(contract, boot.TransportClosureStatus.CLOSED)
    if type(effect) is boot.JitPolicyEffectV2:
        return boot.JitPolicyReadbackV2(contract, effect.action, effect.policy)
    if type(effect) is boot.ActivationEffectV2:
        return boot.ActivationReadbackV2(contract, effect.action, effect.policy)
    if type(effect) is boot.ServingReadyEffectV2:
        return boot.ServingReadyReadbackV2(contract, True)
    if type(effect) is boot.SafeDiagnosticEffect:
        return boot.FailureEffectAcknowledgement(contract, boot.FailureEffectKind.DIAGNOSTIC)
    if type(effect) is boot.CloseServingNetworkEffect:
        return boot.FailureEffectAcknowledgement(contract, boot.FailureEffectKind.CLOSE_SERVING_NETWORK)
    if type(effect) is boot.PoweroffEffect:
        return boot.FailureEffectAcknowledgement(contract, boot.FailureEffectKind.POWEROFF)
    raise AssertionError(type(effect))


class _Transport:
    def __init__(self) -> None:
        self.effects: list[boot.BootEffect] = []
        self.raise_once = False

    def execute(self, effect: boot.BootEffect) -> boot.BootObservation:
        self.effects.append(effect)
        if self.raise_once:
            self.raise_once = False
            raise RuntimeError("transport failure")
        return _observation(effect)


def _reach(engine: boot.BootTransitionEngineV2, target: boot.BootTransitionStateV2, boot_transport: _Transport, activation: _Transport) -> None:
    while engine.state is not target:
        if engine.state is boot.BootTransitionStateV2.SERVING_TRANSPORT_CLAIMED:
            engine.claim_activation_transport(activation)
        else:
            engine.advance(boot_transport if engine.state.value != boot.BootTransitionStateV2.JIT_INPUTS_CHECKED.value and engine._activation_transport is None else (activation if engine._activation_transport is not None else boot_transport))


class BootV2Tests(unittest.TestCase):
    def test_a_schema_matrix_and_dispatch(self) -> None:
        docs = _v2_docs()
        self.assertIsInstance(boot.parse_boot_contract_v2(docs["boot_contract_bytes"]), boot.BootContractV2)
        self.assertIsInstance(boot.parse_boot_contract_document(docs["boot_contract_bytes"]), boot.BootContractV2)
        self.assertIsInstance(
            boot.parse_boot_contract_document(_V1.build_compact_fixture()["boot_contract_bytes"]),
            boot.BootContract,
        )
        raw = canonical_loads(docs["boot_contract_bytes"])
        raw["schema"] = "conf-proc-spp-boot-contract/v3"
        with self.assertRaises(ApplianceError):
            boot.parse_boot_contract_document(canonical_dumps(raw))
        raw = canonical_loads(docs["boot_contract_bytes"])
        raw["contract_version"] = 1
        with self.assertRaises(ApplianceError):
            boot.parse_boot_contract_document(canonical_dumps(raw))

    def test_b_bootstrap_literals_and_initial_network_order(self) -> None:
        engine = boot.BootTransitionEngineV2(_binding())
        normal, failure = _Transport(), _Transport()
        engine.claim_boot_transports(normal, failure)
        self.assertEqual(
            boot.BOOTSTRAP_MOUNTS_V2,
            (
                boot.BootstrapMountV2("proc", "/proc", "proc", ("nosuid", "nodev", "noexec"), 0o555, None),
                boot.BootstrapMountV2("sysfs", "/sys", "sysfs", ("nosuid", "nodev", "noexec"), 0o555, None),
                boot.BootstrapMountV2("devtmpfs", "/dev", "devtmpfs", ("nosuid", "noexec"), 0o755, None),
                boot.BootstrapMountV2("tmpfs", "/run", "tmpfs", ("nosuid", "nodev", "noexec"), 0o755, 67108864),
            ),
        )
        seen = []
        for expected in boot.BOOTSTRAP_MOUNTS_V2:
            effect = engine.next_effect()
            self.assertIsInstance(effect, boot.BootstrapMountEffectV2)
            self.assertEqual(effect.mount, expected)
            seen.append(effect.mount.target)
            engine.advance(normal)
        self.assertEqual(seen, ["/proc", "/sys", "/dev", "/run"])
        self.assertIsInstance(engine.next_effect(), boot.ApplyNetworkPolicyEffectV2)
        self.assertEqual(engine.next_effect().policy, boot.INITIAL_NETWORK_POLICY_V2)
        engine.advance(normal)
        self.assertIsInstance(engine.next_effect(), boot.ReadNetworkPolicyEffectV2)
        with self.assertRaises(ApplianceError):
            engine.accept(boot.NetworkPolicyReadbackV2(engine.contract_sha256, boot.SERVING_NETWORK_POLICY_V2))
        self.assertIs(engine.state, boot.BootTransitionStateV2.FAILED_NON_SERVING)

        serving = boot.BootTransitionEngineV2(_binding())
        serving.claim_boot_transports(_Transport(), _Transport())
        serving.state = boot.BootTransitionStateV2.SERVING_NETWORK_READBACK
        self.assertIsInstance(serving.next_effect(), boot.ReadNetworkPolicyEffectV2)
        with self.assertRaises(ApplianceError):
            serving.accept(boot.NetworkPolicyReadbackV2(serving.contract_sha256, boot.INITIAL_NETWORK_POLICY_V2))
        self.assertIs(serving.state, boot.BootTransitionStateV2.FAILED_NON_SERVING)

    def test_c_boot_failure_and_activation_transport_epochs(self) -> None:
        engine = boot.BootTransitionEngineV2(_binding())
        transport = _Transport()
        with self.assertRaises(ApplianceError):
            engine.claim_boot_transports(transport, transport)
        boot_transport, failure, activation = _Transport(), _Transport(), _Transport()
        engine.claim_boot_transports(boot_transport, failure)
        with self.assertRaises(ApplianceError):
            engine.advance(activation)
        self.assertIs(engine.state, boot.BootTransitionStateV2.FAILED_NON_SERVING)
        with self.assertRaises(ApplianceError):
            engine.advance(boot_transport)
        self.assertIs(engine.advance(failure), boot.BootTransitionStateV2.FAILED_NON_SERVING)

    def test_d_jit_parser_and_mutable_root_classes(self) -> None:
        policy = _jit_policy()
        docs = _v2_docs(jit_policy=policy)
        contract = boot.parse_boot_contract_v2(docs["boot_contract_bytes"])
        self.assertEqual(contract.jit_policy.compiler_loader_args, boot.JIT_COMPILER_LOADER_ARGS_V2)
        self.assertEqual(contract.jit_policy.workspace.mode, 0o700)
        raw = canonical_loads(docs["boot_contract_bytes"])
        raw["jit_policy"]["workspace"]["mode"] = 0o755
        with self.assertRaises(ApplianceError):
            boot.parse_boot_contract_v2(canonical_dumps(raw))
        disabled = canonical_loads(_v2_docs()["boot_contract_bytes"])
        disabled["tmpfs_mounts"][0]["path"] = "/run/spp-jit"
        with self.assertRaises(ApplianceError):
            boot.parse_boot_contract_v2(canonical_dumps(disabled))
        engine = boot.BootTransitionEngineV2(_binding())
        self.assertTrue(all(root.flags == ("nosuid", "nodev", "noexec") for root in engine.application_roots))
        self.assertFalse(any(root.path == "/run/spp-jit" for root in engine.application_roots))

    def test_e_jit_cross_projection_rejects_unbound_input(self) -> None:
        docs = _v2_docs(jit_policy=_jit_policy())
        with self.assertRaises(ApplianceError):
            boot.bind_boot_inputs_v2(**docs)

    def test_f_real_fixture_anchors_jit_disabled_document(self) -> None:
        from conf_proc_provenance_v2_inspect_fixture import build_positive_fixture

        fixture = build_positive_fixture()
        try:
            manifest = Path(fixture.bundle, "appliance.manifest.json").read_bytes()
            docs = _v2_docs()
            raw = canonical_loads(docs["boot_contract_bytes"])
            raw["predecessor_sha256"]["accepted_manifest_sha256"] = _sha(manifest)
            raw["jit_policy"] = None
            self.assertIsNone(boot.parse_boot_contract_v2(canonical_dumps(raw)).jit_policy)
        finally:
            fixture.cleanup()

    def test_g_measurement_is_framed_and_domain_separated(self) -> None:
        engine = boot.BootTransitionEngineV2(_binding())
        artifacts = (
            engine.binding.accepted_manifest_bytes,
            engine.binding.boot_contract_bytes,
            engine.binding.module_plan_bytes,
            engine.binding.kernel_feature_contract_bytes,
            engine.binding.gpt_layout_rules_bytes,
            engine.binding.root_lock_bytes,
            engine.binding.runtime_closure_bytes,
            engine.binding.policy_bytes,
            boot._OBSERVATION_SHAPE_V2_BYTES,
        )
        framed = b"".join(len(value).to_bytes(8, "big") + value for value in artifacts)
        self.assertEqual(
            engine.pcr15_measurement_v2,
            hashlib.sha256(b"sol-spp-appliance-manifest-v2\0" + framed).digest(),
        )
        for index, artifact in enumerate(artifacts):
            changed = list(artifacts)
            changed[index] = artifact + b"!"
            self.assertNotEqual(
                engine.pcr15_measurement_v2,
                hashlib.sha256(
                    b"sol-spp-appliance-manifest-v2\0"
                    + b"".join(len(value).to_bytes(8, "big") + value for value in changed)
                ).digest(),
            )
        self.assertEqual(len(engine.pcr15_measurement_v2), 32)
        self.assertNotEqual(engine.pcr15_measurement_v2, hashlib.sha256(b"sol-spp-appliance-manifest-v1\0" + engine.binding.accepted_manifest_bytes).digest())
        self.assertEqual(engine.predicted_pcr15_v2, hashlib.sha256(b"\0" * 32 + engine.pcr15_measurement_v2).digest())
        engine.state = boot.BootTransitionStateV2.PCR15_READBACK
        engine._pending = boot.ReadPcr15Effect(engine.contract_sha256, engine.predicted_pcr15_v2)
        old_value = hashlib.sha256(
            b"\0" * 32
            + hashlib.sha256(b"sol-spp-appliance-manifest-v1\0" + engine.binding.accepted_manifest_bytes).digest()
        ).digest()
        with self.assertRaises(ApplianceError):
            engine.accept(boot.Pcr15Readback(engine.contract_sha256, old_value))
        self.assertIs(engine.state, boot.BootTransitionStateV2.FAILED_NON_SERVING)

    def test_h_golden_order_and_failure_retry(self) -> None:
        self.assertEqual(
            tuple(state.value for state in boot.BootTransitionStateV2)[0:-2],
            tuple(boot._OBSERVATION_SHAPE_V2["states"]),
        )
        engine = boot.BootTransitionEngineV2(_binding())
        normal, failure = _Transport(), _Transport()
        engine.claim_boot_transports(normal, failure)
        with self.assertRaises(ApplianceError):
            engine.accept(boot.Pcr15Readback(engine.contract_sha256, b"\0" * 32))
        failure.raise_once = True
        with self.assertRaises(ApplianceError):
            engine.advance(failure)
        self.assertIs(engine.advance(failure), boot.BootTransitionStateV2.FAILED_NON_SERVING)
        self.assertIs(engine.advance(failure), boot.BootTransitionStateV2.FAILED_NON_SERVING)
        self.assertIs(engine.advance(failure), boot.BootTransitionStateV2.POWEROFF)

    def test_i_serving_sessions_follow_the_entitlement_and_request_branches(self) -> None:
        engine = boot.BootTransitionEngineV2(_binding())
        boot_transport, failure = _Transport(), _Transport()
        engine.claim_boot_transports(boot_transport, failure)
        engine.state = boot.BootTransitionStateV2.SERVING_AVAILABLE

        empty = engine.admit_serving_session(_Transport())
        empty.close()
        self.assertIsNone(empty.next_effect())

        def accept_until_closed(session: boot.ServingSessionReducer, *, path: str, body_length: int, bearer: str) -> list[boot.ServingSessionEffect]:
            handle = object()
            session.begin_request(path=path, body_length=body_length, opaque_handle=handle)
            effects: list[boot.ServingSessionEffect] = []
            while session.state is not boot.ServingSessionState.REQUEST_CLOSED:
                effect = session.next_effect()
                self.assertIsNotNone(effect)
                assert effect is not None
                effects.append(effect)
                if session.state is boot.ServingSessionState.CREDENTIAL_OBSERVED:
                    observation = boot.CredentialObservedV2(effect.contract_sha256, handle, bearer)
                elif session.state is boot.ServingSessionState.ENTITLEMENT_DNS_RESULT:
                    observation = boot.EntitlementDnsResultV2(effect.contract_sha256, "203.0.113.8", 60)
                else:
                    observation = boot.ServingSessionReadback(effect.contract_sha256, effect.action)
                session.accept(observation)
            return effects

        bearer = _sha(b"session bearer")
        session = engine.admit_serving_session(_Transport())
        effects = accept_until_closed(session, path="/v1/chat/completions", body_length=4, bearer=bearer)
        self.assertEqual(
            [effect.action for effect in effects],
            [
                "request_started", "credential_observed", "entitlement_dns_query", "entitlement_dns_result",
                "entitlement_tls_connect", "entitlement_tls_verified", "entitlement_authorize_request",
                "entitlement_authorized", "upstream_open", "upstream_opened",
            ],
        )
        open_effect = next(effect for effect in effects if effect.action == "upstream_open")
        self.assertEqual(open_effect.upstream_role, "inference")
        authorization = next(effect for effect in effects if effect.action == "entitlement_authorize_request")
        self.assertEqual(authorization.bearer_sha256, bearer)
        self.assertFalse(hasattr(authorization, "opaque_handle"))
        accept_until_closed(session, path="/v1/audio/transcriptions", body_length=1, bearer=bearer)
        with self.assertRaises(ApplianceError):
            accept_until_closed(session, path="/v1/chat/completions", body_length=1, bearer=_sha(b"another bearer"))
        self.assertIs(session.state, boot.ServingSessionState.SESSION_CLOSED)

        oversized = engine.admit_serving_session(_Transport())
        handle = object()
        oversized.begin_request(path="/v1/audio/transcriptions", body_length=11534337, opaque_handle=handle)
        while oversized.state is not boot.ServingSessionState.REJECT_413:
            effect = oversized.next_effect()
            self.assertIsNotNone(effect)
            assert effect is not None
            if oversized.state is boot.ServingSessionState.CREDENTIAL_OBSERVED:
                observation = boot.CredentialObservedV2(effect.contract_sha256, handle, bearer)
            elif oversized.state is boot.ServingSessionState.ENTITLEMENT_DNS_RESULT:
                observation = boot.EntitlementDnsResultV2(effect.contract_sha256, "203.0.113.8", 60)
            else:
                observation = boot.ServingSessionReadback(effect.contract_sha256, effect.action)
            oversized.accept(observation)
        self.assertEqual(oversized.next_effect().action, "reject_413")
        oversized.accept(boot.ServingSessionReadback("serving-session/v2", "reject_413"))
        self.assertEqual(oversized.next_effect().action, "drain_exact")
        oversized.accept(boot.DrainExactReadbackV2("serving-session/v2", 11534337))
        self.assertIs(oversized.state, boot.ServingSessionState.REQUEST_CLOSED)

    def test_j_serving_session_isolated_and_bounded(self) -> None:
        engine = boot.BootTransitionEngineV2(_binding())
        boot_transport, failure, activation = _Transport(), _Transport(), _Transport()
        engine.claim_boot_transports(boot_transport, failure)
        engine.state = boot.BootTransitionStateV2.SERVING_AVAILABLE
        first, second = _Transport(), _Transport()
        one = engine.admit_serving_session(first)
        two = engine.admit_serving_session(second)
        one.begin_request(path="/v1/audio/transcriptions", body_length=11534337, opaque_handle=object())
        two.begin_request(path="/v1/chat/completions", body_length=4, opaque_handle=object())
        self.assertEqual(one.next_effect().action, "request_started")
        self.assertEqual(two.next_effect().action, "request_started")
        one.close()
        replacement = engine.admit_serving_session(first)
        replacement.close()
        with self.assertRaises(ApplianceError):
            one.advance(second)

    def test_z_shared_pcr_latch_rejects_v2_after_v1_claim(self) -> None:
        v1 = boot.BootTransitionEngine(_V1.build_compact_fixture() and boot.bind_boot_inputs(**_V1.build_compact_fixture()))
        while v1.state is not boot.BootTransitionState.PCR15_EXTEND:
            v1.advance(_V1._FixtureTransport())
        v2 = boot.BootTransitionEngineV2(_binding())
        normal, failure, activation = _Transport(), _Transport(), _Transport()
        v2.claim_boot_transports(normal, failure)
        while v2.state is not boot.BootTransitionStateV2.PCR15_EXTEND:
            v2.advance(normal)
        v1.advance(_V1._FixtureTransport())
        with self.assertRaises(ApplianceError):
            v2.advance(normal)


if __name__ == "__main__":
    unittest.main()
