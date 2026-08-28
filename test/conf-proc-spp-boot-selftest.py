#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Direct self-tests for the bounded SPP boot-transition reducer.

The compact fixture is intentionally canonical predecessor data.  It does
not claim that the real H3 fixture has a KFC relationship; the real fixture
is used only for its already accepted raw manifest bytes.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import unittest
from dataclasses import fields, replace
from functools import lru_cache
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import conf_proc_spp_boot as boot
from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_lock import parse_lock
from conf_proc_module_authority import check_authorized_signers_match_bundle
from conf_proc_provenance_v2 import supported_verity_rules_bytes
from conf_proc_provenance_v2_build_manifest import (
    ProvenanceV2FirmwareObservation,
    ProvenanceV2ImageRecord,
    ProvenanceV2ModuleObservation,
    produce_provenance_v2,
)
from conf_proc_provenance_v2_manifest import parse_manifest_v2
from conf_proc_reasons import ApplianceError


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _record(input_id: str, role: str, data: bytes, placements: list[dict], component: str | None = None) -> dict:
    digest = _sha(data)
    return {
        "id": input_id,
        "role": role,
        "component": component or input_id,
        "sha256": digest,
        "size_bytes": len(data),
        "source_local_path": input_id + ".bin",
        "source_retrieval_scheme": "local-fixture",
        "source_retrieval_identity": "fixture:" + input_id,
        "source_retrieval_immutable_ref": "sha256:" + digest,
        "derivation_kind": "fixture",
        "derivation_recipe_id": "fixture-v1",
        "derivation_parent_ids": [],
        "derivation_parameters_sha256": _sha(b"parameters"),
        "placements": placements,
    }


def _placement(image: str, path: str, input_id: str) -> dict:
    return {
        "image": image,
        "path": path,
        "node_type": "file",
        "mode": 0o644,
        "uid": 0,
        "gid": 0,
        "xattrs": [],
        "source_input_id": input_id,
        "target": None,
    }


@lru_cache(maxsize=1)
def _trusted_certificate_bundle() -> tuple[bytes, str, str, str]:
    bundle = (ROOT / "test" / "spp-boot-module-signer-fixture.pem").read_bytes()
    certificate = x509.load_pem_x509_certificate(bundle)
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return (
        bundle,
        certificate.fingerprint(hashes.SHA256()).hex(),
        _sha(spki),
        _sha(certificate.subject.public_bytes()),
    )


def _tcb(kfc_sha256: str) -> bytes:
    def executable(name: str, marker: bytes) -> dict:
        return {
            "logical_name": name,
            "sha256": _sha(marker),
            "linkage": "static",
            "interpreter_sha256": None,
            "loader_sha256": None,
            "library_sha256s": [],
        }

    return canonical_dumps(
        {
            "schema": "conf-proc-pre-sandbox-tcb/v1",
            "status": "declared_unverified",
            "caller": executable("caller", b"caller"),
            "launcher": executable("launcher", b"launcher"),
            "sandbox": {"backend": "bubblewrap", "executable": executable("sandbox", b"sandbox"), "helper": None},
            "kernel_feature_contract": {"schema": "conf-proc-kernel-features/v1", "sha256": kfc_sha256},
        }
    )


def _policy(*, strict_subset: bool = False, unreachable_executable: bool = False) -> bytes:
    def node(path: str, source: str, content_class: str) -> dict:
        return {
            "path": path,
            "node_type": "file",
            "mode": 0o644,
            "uid": 0,
            "gid": 0,
            "xattrs": [],
            "source_input_id": source,
            "target": None,
            "content_class": content_class,
        }

    runtime_nodes = [
        node("/etc/spp/policy.json", "policy", "config"),
        node("/usr/bin/spp", "stub", "executable"),
        node("/usr/lib/firmware/spp/fw.bin", "firmware", "runtime_data"),
        node("/usr/lib/modules/spp/boot.ko", "driver", "runtime_data"),
    ]
    if strict_subset:
        runtime_nodes.append(node("/usr/lib/modules/spp/idle.ko", "driver", "runtime_data"))
    runtime_nodes.append(node("/usr/lib/modules/spp/serve.ko", "driver", "runtime_data"))
    if unreachable_executable:
        runtime_nodes.insert(2, node("/usr/bin/unreachable", "stub", "executable"))
    process_nodes = [
        {
            "id": "exec:/usr/bin/spp",
            "kind": "exec",
            "path": "/usr/bin/spp",
            "sha256": _sha(b"stub"),
            "argv": ["/usr/bin/spp"],
            "network_scope": "none",
            "capabilities": [],
            "source_input_id": "stub",
        },
        {
            "id": "unit:spp.service",
            "kind": "unit",
            "path": "spp.service",
            "sha256": None,
            "argv": [],
            "network_scope": "none",
            "capabilities": [],
            "source_input_id": None,
        },
    ]
    if unreachable_executable:
        process_nodes.insert(1, {
            "id": "exec:/usr/bin/unreachable",
            "kind": "exec",
            "path": "/usr/bin/unreachable",
            "sha256": _sha(b"stub"),
            "argv": ["/usr/bin/unreachable"],
            "network_scope": "none",
            "capabilities": [],
            "source_input_id": "stub",
        })
    return canonical_dumps(
        {
            "schema": "conf-proc-policy/v1",
            "policy_version": 1,
            "images": {
                "models": {"nodes": [node("/models/inference", "inference", "model")]},
                "runtime-policy": {"nodes": runtime_nodes},
            },
            "boot_roots": ["unit:spp.service"],
            "process_nodes": process_nodes,
            "process_edges": [
                {"from_id": "unit:spp.service", "to_id": "exec:/usr/bin/spp", "kind": "unit_exec", "origin_path": "spp.service", "origin_key": "ExecStart"}
            ],
            "mounts": [
                {"unit_id": "unit:spp.service", "image": "models", "destination": "/run/spp/models", "fs_type": "squashfs", "read_only": True},
                {"unit_id": "unit:spp.service", "image": "runtime-policy", "destination": "/run/spp/runtime-policy", "fs_type": "squashfs", "read_only": True},
            ],
            "network_policy": {"exec:/usr/bin/spp": "none", "unit:spp.service": "none"},
            "capability_policy": {},
        }
    )


def build_compact_fixture(*, strict_subset: bool = False, unreachable_executable: bool = False) -> dict[str, bytes]:
    """Build compact complete predecessor bytes, with KFC made before TCB."""

    policy_bytes = _policy(strict_subset=strict_subset, unreachable_executable=unreachable_executable)
    trusted_bundle_bytes, signer, signer_spki, signer_subject = _trusted_certificate_bundle()
    contents = {
        "asrlock": b"asr lock",
        "asrmodel": b"asr model",
        "bundle": trusted_bundle_bytes,
        "driver": b"two module rows",
        "firmware": b"firmware",
        "gateway": b"gateway lock",
        "inference": b"inference",
        "kernel": b"kernel",
        "policy": policy_bytes,
        "runtime": b"runtime tree",
        "sglang": b"sglang",
        "source": b"compact builder source",
        "stub": b"stub",
        "unit": b"unit",
        "models": b"models tree",
        "tool-mksquashfs": b"mksquashfs",
        "tool-openssl": b"openssl",
        "tool-unsquashfs": b"unsquashfs",
        "tool-veritysetup": b"veritysetup",
    }
    placement_map = {
        "asrlock": [_placement("models", "/models/asr.lock", "asrlock")],
        "asrmodel": [_placement("models", "/models/asr", "asrmodel")],
        "driver": [
            _placement("runtime-policy", "/usr/lib/modules/spp/boot.ko", "driver"),
            *([_placement("runtime-policy", "/usr/lib/modules/spp/idle.ko", "driver")] if strict_subset else []),
            _placement("runtime-policy", "/usr/lib/modules/spp/serve.ko", "driver"),
        ],
        "firmware": [_placement("runtime-policy", "/usr/lib/firmware/spp/fw.bin", "firmware")],
        "gateway": [_placement("models", "/models/gateway.lock", "gateway")],
        "inference": [_placement("models", "/models/inference", "inference")],
        "kernel": [_placement("models", "/models/kernel", "kernel")],
        "models": [_placement("models", "/models/tree", "models")],
        "policy": [_placement("runtime-policy", "/etc/spp/policy.json", "policy")],
        "runtime": [_placement("runtime-policy", "/runtime.tree", "runtime")],
        "sglang": [_placement("models", "/models/sglang", "sglang")],
        "source": [_placement("runtime-policy", "/opt/conf/source.py", "source")],
        "stub": [
            _placement("runtime-policy", "/usr/bin/spp", "stub"),
            *([_placement("runtime-policy", "/usr/bin/unreachable", "stub")] if unreachable_executable else []),
        ],
        "unit": [_placement("runtime-policy", "/etc/systemd/system/spp.service", "unit")],
    }
    roles = {
        "asrlock": "asr_dependency_lock", "asrmodel": "asr_model", "bundle": "kernel_trusted_cert_bundle",
        "driver": "nvidia_cc_driver", "firmware": "nvidia_cc_firmware", "gateway": "gateway_dependency_lock",
        "inference": "inference_model", "kernel": "kernel", "models": "models_tree_input",
        "policy": "policy_tree_input", "runtime": "runtime_tree_input", "sglang": "sglang_image",
        "source": "conf_proc_source", "stub": "final_systemd_stub", "unit": "final_systemd_unit",
    }
    inputs = [_record(key, roles[key], contents[key], placement_map.get(key, [])) for key in roles]
    for tool_id, component in (
        ("tool-mksquashfs", "mksquashfs"), ("tool-openssl", "openssl"),
        ("tool-unsquashfs", "unsquashfs"), ("tool-veritysetup", "veritysetup"),
    ):
        inputs.append(_record(tool_id, "build_tool", contents[tool_id], [], component))
    inputs.sort(key=lambda value: value["id"])
    lock_raw = {
        "schema": "conf-proc-lock/v1",
        "lock_version": 1,
        "base_image_record": {
            "kind": "vhd", "provider": "fixture", "identity_namespace": "fixture", "identity_name": "compact",
            "identity_immutable_revision": "1", "content_sha256": _sha(b"base"), "content_size_bytes": 4,
            "content_media_type": "application/octet-stream", "availability": "record-only",
            "recorded_retrieval_scheme": "local-fixture", "recorded_retrieval_identity": "fixture:base",
            "recorded_retrieval_immutable_ref": "sha256:" + _sha(b"base"),
        },
        "future_cmdline": "console=ttyS0",
        "inputs": inputs,
        "authorized_module_signers": [{"certificate_sha256": signer, "spki_sha256": signer_spki, "subject_sha256": signer_subject, "usage": "kernel-module-signing"}],
        "image_specs": {"models": {}, "runtime-policy": {}},
        "policy_input_id": "policy",
        "tool_ids": ["tool-mksquashfs", "tool-openssl", "tool-unsquashfs", "tool-veritysetup"],
    }
    root_lock_bytes = canonical_dumps(lock_raw)
    closure_entries = []
    for item in inputs:
        for placement in item["placements"]:
            closure_entries.append(
                {
                    "path": placement["path"], "node_type": "file", "mode": placement["mode"], "uid": 0, "gid": 0,
                    "size_bytes": item["size_bytes"], "sha256": item["sha256"], "symlink_target": None,
                    "hardlink_group": None, "xattrs": [], "capabilities": [], "logical_role": item["role"],
                    "provenance": {"scheme": item["source_retrieval_scheme"], "identity": item["source_retrieval_identity"], "immutable_ref": item["source_retrieval_immutable_ref"]},
                    "root_lock_input_id": item["id"],
                }
            )
    runtime_closure_bytes = canonical_dumps({"schema": "conf-proc-runtime-closure/v1", "status": "declared_unverified", "entries": sorted(closure_entries, key=lambda value: value["path"])})
    kernel_digest = next(item["sha256"] for item in inputs if item["id"] == "kernel")
    controls = [
        {"name": name, "support": "conditional" if name == "kernel_debug" else "required"}
        for name in sorted(boot._CONTROL_ORDER)
    ]
    kfc_bytes = canonical_dumps({"schema": "conf-proc-kernel-features/v1", "kernel_input_sha256": kernel_digest, "kernel_release": "compact-1", "mutable_controls": controls})
    tcb_identity_bytes = _tcb(_sha(kfc_bytes))
    verity_rules_bytes = supported_verity_rules_bytes()
    image_records = (
        ProvenanceV2ImageRecord("models", _sha(b"models squashfs"), 4096, _sha(b"models hash"), 4096, _sha(b"models root")),
        ProvenanceV2ImageRecord("runtime-policy", _sha(b"runtime squashfs"), 4096, _sha(b"runtime hash"), 4096, _sha(b"runtime root")),
    )
    manifest_bytes = produce_provenance_v2(
        root_lock_bytes=root_lock_bytes, runtime_closure_bytes=runtime_closure_bytes, verity_rules_bytes=verity_rules_bytes,
        tcb_identity_bytes=tcb_identity_bytes, builder_source_bytes=contents["source"], policy_bytes=policy_bytes,
        images=image_records,
        module_observations=(
            ProvenanceV2ModuleObservation("/usr/lib/modules/spp/boot.ko", _sha(contents["driver"]), signer),
            *((ProvenanceV2ModuleObservation("/usr/lib/modules/spp/idle.ko", _sha(contents["driver"]), signer),) if strict_subset else ()),
            ProvenanceV2ModuleObservation("/usr/lib/modules/spp/serve.ko", _sha(contents["driver"]), signer),
        ),
        firmware_observations=(ProvenanceV2FirmwareObservation("/usr/lib/firmware/spp/fw.bin", _sha(contents["firmware"])),),
    ).manifest_bytes
    gpt_rules_bytes = canonical_dumps(
        {
            "schema": "conf-proc-spp-gpt-layout-rules/v1", "rules_version": 1,
            "geometry": {"logical_sector_bytes": 512, "first_partition_lba": 2048, "alignment_lba": 2048},
            "guid_derivation": {"algorithm": "sha256-rfc4122-v5-shaped/v1", "disk_domain": "sol-spp-disk/v1", "partuuid_domain": "sol-spp-partuuid/v1"},
            "partitions": [
                {"ordinal": 1, "role": "runtime-policy-data", "image_id": "runtime-policy", "payload": "data", "type_guid": "0fc63daf-8483-4772-8e79-3d69d8477de4"},
                {"ordinal": 2, "role": "runtime-policy-verity", "image_id": "runtime-policy", "payload": "hash", "type_guid": "a19d880f-05fc-4d3b-a006-743f0f84911e"},
                {"ordinal": 3, "role": "models-data", "image_id": "models", "payload": "data", "type_guid": "933ac7e1-2eb4-4f13-b844-0e14e2aef915"},
                {"ordinal": 4, "role": "models-verity", "image_id": "models", "payload": "hash", "type_guid": "ca7d7ccb-63ed-4c53-861c-1742536059cc"},
            ],
        }
    )
    identities = [
        {"path": "/usr/lib/modules/spp/boot.ko", "sha256": _sha(contents["driver"]), "signer_certificate_sha256": signer},
        *([{ "path": "/usr/lib/modules/spp/idle.ko", "sha256": _sha(contents["driver"]), "signer_certificate_sha256": signer}] if strict_subset else []),
        {"path": "/usr/lib/modules/spp/serve.ko", "sha256": _sha(contents["driver"]), "signer_certificate_sha256": signer},
    ]
    predecessor_sha256 = {
        "root_lock_sha256": _sha(root_lock_bytes), "runtime_closure_sha256": _sha(runtime_closure_bytes),
        "verity_rules_sha256": _sha(verity_rules_bytes), "tcb_identity_sha256": _sha(tcb_identity_bytes),
        "builder_source_sha256": _sha(contents["source"]), "policy_sha256": _sha(policy_bytes),
        "accepted_manifest_sha256": _sha(manifest_bytes), "kernel_feature_contract_sha256": _sha(kfc_bytes),
        "trusted_certificate_bundle_sha256": _sha(trusted_bundle_bytes),
    }
    boot_contract_bytes = canonical_dumps(
        {
            "schema": "conf-proc-spp-boot-contract/v1", "contract_version": 1,
            "predecessor_sha256": predecessor_sha256, "image_order": ["models", "runtime-policy"],
            "module_roles": {"boot": [identities[0]], "serving": [identities[-1]]},
            "non_runtime_loadable_modules": [identities[1]] if strict_subset else [],
            "tmpfs_mounts": [{"path": "/run/spp-state", "size_bytes": 1048576, "mode": 0o755}],
            "mutable_control_order": list(boot._CONTROL_ORDER),
            "observation_contract_sha256": boot.OBSERVATION_CONTRACT_SHA256,
            "gpt_layout_rules_sha256": _sha(gpt_rules_bytes),
        }
    )
    module_plan_bytes = canonical_dumps(
        {
            "schema": "conf-proc-spp-module-load-plan/v1", "plan_version": 1,
            "boot_contract_sha256": _sha(boot_contract_bytes), "measurement_scope": "future-pcr4-only",
            "entries": [
                {"index": 0, **identities[0], "predecessor_indices": []},
                {"index": 1, **identities[-1], "predecessor_indices": [0]},
            ],
        }
    )
    return {
        "root_lock_bytes": root_lock_bytes, "runtime_closure_bytes": runtime_closure_bytes,
        "verity_rules_bytes": verity_rules_bytes, "tcb_identity_bytes": tcb_identity_bytes,
        "builder_source_bytes": contents["source"], "policy_bytes": policy_bytes,
        "accepted_manifest_bytes": manifest_bytes, "kernel_feature_contract_bytes": kfc_bytes,
        "trusted_certificate_bundle_bytes": trusted_bundle_bytes,
        "boot_contract_bytes": boot_contract_bytes, "module_plan_bytes": module_plan_bytes,
        "gpt_layout_rules_bytes": gpt_rules_bytes,
    }


def _binding() -> boot.BootBinding:
    return boot.bind_boot_inputs(**build_compact_fixture())


def _refresh_boot_document_bindings(docs: dict[str, bytes]) -> None:
    contract = canonical_loads(docs["boot_contract_bytes"])
    contract["predecessor_sha256"] = {
        "root_lock_sha256": _sha(docs["root_lock_bytes"]),
        "runtime_closure_sha256": _sha(docs["runtime_closure_bytes"]),
        "verity_rules_sha256": _sha(docs["verity_rules_bytes"]),
        "tcb_identity_sha256": _sha(docs["tcb_identity_bytes"]),
        "builder_source_sha256": _sha(docs["builder_source_bytes"]),
        "policy_sha256": _sha(docs["policy_bytes"]),
        "accepted_manifest_sha256": _sha(docs["accepted_manifest_bytes"]),
        "kernel_feature_contract_sha256": _sha(docs["kernel_feature_contract_bytes"]),
        "trusted_certificate_bundle_sha256": _sha(docs["trusted_certificate_bundle_bytes"]),
    }
    docs["boot_contract_bytes"] = canonical_dumps(contract)
    plan = canonical_loads(docs["module_plan_bytes"])
    plan["boot_contract_sha256"] = _sha(docs["boot_contract_bytes"])
    docs["module_plan_bytes"] = canonical_dumps(plan)


def _observation(effect: boot.BootEffect) -> boot.BootObservation:
    contract = effect.contract_sha256
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
    if type(effect) is boot.CheckMutableRootsEffect:
        return boot.MutableRootsObservation(contract, ())
    if type(effect) is boot.CreateTmpfsEffect:
        return boot.TmpfsReadback(contract, effect.mounts, effect.flags)
    if type(effect) is boot.LoadModulesEffect:
        return boot.ModuleReadback(contract, tuple(item.identity for item in effect.entries))
    if type(effect) is boot.CloseModulesEffect:
        return boot.ModulesDisabledReadback(contract, boot.ModulesDisabledStatus.SET_TO_1)
    if type(effect) is boot.CloseMutableControlEffect:
        return boot.ControlReadback(contract, effect.control, boot.ControlReadbackStatus.DISABLED)
    if type(effect) is boot.ExtendPcr15Effect:
        return boot.Pcr15ExtendObservation(contract, boot.Pcr15ExtendOutcome.ACKNOWLEDGED)
    if type(effect) is boot.CloseTransportEffect:
        return boot.TransportClosedObservation(contract, boot.TransportClosureStatus.CLOSED)
    if type(effect) is boot.ServingReadyEffect:
        return boot.ServingReadyObservation(contract, boot.ServingAuthorizationStatus.AUTHORIZED)
    raise AssertionError(type(effect))


class _FixtureTransport:
    def __init__(self, extend_outcome: boot.Pcr15ExtendOutcome = boot.Pcr15ExtendOutcome.ACKNOWLEDGED) -> None:
        self.extend_outcome = extend_outcome
        self.invocations: list[boot.BootEffect] = []

    def execute(self, effect: boot.BootEffect) -> boot.BootObservation:
        self.invocations.append(effect)
        if type(effect) is boot.ExtendPcr15Effect:
            return boot.Pcr15ExtendObservation(effect.contract_sha256, self.extend_outcome)
        if type(effect) is boot.ServingActionEffect:
            return boot.ServingActionObservation(
                effect.contract_sha256,
                effect.action,
                boot.ServingActionStatus.COMPLETED,
            )
        return _observation(effect)


def _reach(engine: boot.BootTransitionEngine, state: boot.BootTransitionState) -> None:
    while engine.state is not state:
        effect = engine.next_effect()
        assert effect is not None
        engine.accept(_observation(effect))


def _child_legal() -> int:
    return _child_pcr_outcome(boot.Pcr15ExtendOutcome.ACKNOWLEDGED)


def _child_pcr_outcome(outcome: boot.Pcr15ExtendOutcome) -> int:
    engine = boot.BootTransitionEngine(_binding())
    transport = _FixtureTransport(outcome)
    states = []
    controls = []
    while engine.state is not boot.BootTransitionState.SERVING:
        requested_state = engine.state
        states.append(requested_state)
        if requested_state is boot.BootTransitionState.PCR15_EXTEND:
            invocation_count = len(transport.invocations)
            engine.advance(transport)
            assert len(transport.invocations) == invocation_count + 1
            effect = transport.invocations[-1]
        else:
            effect = engine.next_effect()
            assert effect is not None
            engine.advance(transport)
        if requested_state is not boot.BootTransitionState.SERVING_READY:
            assert type(effect) is not boot.ServingReadyEffect
        if type(effect) is boot.CloseMutableControlEffect:
            controls.append(effect.control)
    assert engine.next_effect() is None
    assert states == [
        boot.BootTransitionState.CMDLINE, boot.BootTransitionState.PCR15_ZERO,
        boot.BootTransitionState.DISK_LOCATORS, boot.BootTransitionState.RUNTIME_MAP,
        boot.BootTransitionState.RUNTIME_VERIFY, boot.BootTransitionState.RUNTIME_MAPPING_IDENTITY,
        boot.BootTransitionState.MODELS_MAP, boot.BootTransitionState.MODELS_VERIFY,
        boot.BootTransitionState.MODELS_MAPPING_IDENTITY, boot.BootTransitionState.RUNTIME_MOUNT,
        boot.BootTransitionState.RUNTIME_EXECUTABLE_CONFINEMENT, boot.BootTransitionState.MODELS_MOUNT,
        boot.BootTransitionState.MUTABLE_ROOTS, boot.BootTransitionState.TMPFS,
        boot.BootTransitionState.MODULES, boot.BootTransitionState.MODULES_DISABLED,
        boot.BootTransitionState.MUTABLE_CONTROLS, boot.BootTransitionState.MUTABLE_CONTROLS,
        boot.BootTransitionState.MUTABLE_CONTROLS, boot.BootTransitionState.MUTABLE_CONTROLS,
        boot.BootTransitionState.MUTABLE_CONTROLS, boot.BootTransitionState.MUTABLE_CONTROLS,
        boot.BootTransitionState.MUTABLE_CONTROLS, boot.BootTransitionState.MUTABLE_CONTROLS,
        boot.BootTransitionState.MUTABLE_CONTROLS, boot.BootTransitionState.PCR15_EXTEND,
        boot.BootTransitionState.PCR15_READBACK, boot.BootTransitionState.TRANSPORT_CLOSED,
        boot.BootTransitionState.SERVING_READY,
    ]
    assert controls == list(boot._CONTROL_ORDER[1:])
    for action in boot.ServingAction:
        observation = engine.invoke_serving_action(action, transport)
        assert type(observation) is boot.ServingActionObservation
    return 0


_PCR_KAT_MEASUREMENT_HEX = "c96583eab2f1fe78a62bd1b9ad6c076efbd6f82ae11af4528ea1a2bc0c8a5290"
_PCR_KAT_AFTER_HEX = "7969a2786774fada6e734a611712bb86879f3d4752ee2593c83e75030c3fc010"


def _child_pcr_known_answer() -> int:
    engine = boot.BootTransitionEngine(_binding())
    _reach(engine, boot.BootTransitionState.PCR15_EXTEND)
    transport = _FixtureTransport()
    engine.advance(transport)
    effect = transport.invocations[-1]
    assert type(effect) is boot.ExtendPcr15Effect
    assert effect.measurement.hex() == _PCR_KAT_MEASUREMENT_HEX
    assert engine.predicted_pcr15.hex() == _PCR_KAT_AFTER_HEX
    return 0


def _child_transition_table() -> int:
    engine = boot.BootTransitionEngine(_binding())
    transport = _FixtureTransport()
    for row in boot.BOOT_TRANSITION_TABLE:
        assert engine.state is row.state
        while engine.state is row.state:
            if engine.state is boot.BootTransitionState.PCR15_EXTEND:
                engine.advance(transport)
                effect = transport.invocations[-1]
            else:
                effect = engine.next_effect()
                assert effect is not None
                engine.advance(transport)
            assert type(effect).__name__ == row.effect_name
    assert engine.state is boot.BootTransitionState.SERVING
    return 0


class SppBootSelftest(unittest.TestCase):
    def test_a0_vpe_dormant_policy_covers_the_boot_authority_consumer(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "test" / "conf-proc-provenance-independence-selftest.py")],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_parser_and_source_binding_strictness(self) -> None:
        docs = build_compact_fixture()
        binding = boot.bind_boot_inputs(**docs)
        self.assertEqual(binding.kernel_feature_contract.kernel_input_sha256, next(item.sha256 for item in binding.lock.inputs if item.role == "kernel"))
        changed = canonical_loads(docs["boot_contract_bytes"])
        changed["unexpected"] = 1
        with self.assertRaises(ApplianceError):
            boot.parse_boot_contract(canonical_dumps(changed))
        changed = canonical_loads(docs["boot_contract_bytes"])
        changed["predecessor_sha256"]["kernel_feature_contract_sha256"] = "0" * 64
        docs["boot_contract_bytes"] = canonical_dumps(changed)
        with self.assertRaises(ApplianceError):
            boot.bind_boot_inputs(**docs)

    def test_a1_binder_seal_and_snapshots_reject_injection_and_source_mutation(self) -> None:
        docs = build_compact_fixture()
        decoded_manifest = parse_manifest_v2(docs["accepted_manifest_bytes"])
        decoded_policy = canonical_loads(docs["policy_bytes"])
        binding = boot.bind_boot_inputs(**docs)
        before = boot.BootTransitionEngine(binding)
        _reach(before, boot.BootTransitionState.RUNTIME_MAP)
        expected_effect = before.next_effect()
        self.assertIsInstance(expected_effect, boot.MapVerityEffect)
        decoded_manifest.raw["images"]["runtime-policy"]["root_hash"] = "0" * 64
        decoded_policy["images"]["runtime-policy"]["nodes"][1]["path"] = "/mutated"
        binding.lock.image_specs["runtime-policy"]["caller_mutation"] = True
        after = boot.BootTransitionEngine(binding)
        _reach(after, boot.BootTransitionState.RUNTIME_MAP)
        self.assertEqual(after.next_effect(), expected_effect)
        forged_binding = boot.BootBinding(**{
            member.name: getattr(binding, member.name)
            for member in fields(boot.BootBinding)
        })
        with self.assertRaises(ApplianceError):
            boot.BootTransitionEngine(forged_binding)

    def test_a2_canonical_unknown_and_malformed_contract_values_are_rejected(self) -> None:
        docs = build_compact_fixture()
        with self.assertRaises(ApplianceError):
            boot.parse_kernel_feature_contract(b"{}")
        with self.assertRaises(ApplianceError):
            boot.parse_kernel_feature_contract(b" " + docs["kernel_feature_contract_bytes"])
        kfc = canonical_loads(docs["kernel_feature_contract_bytes"])
        kfc["mutable_controls"][0]["support"] = "optional-on-error"
        with self.assertRaises(ApplianceError):
            boot.parse_kernel_feature_contract(canonical_dumps(kfc))
        plan = canonical_loads(docs["module_plan_bytes"])
        plan["measurement_scope"] = "pcr15"
        with self.assertRaises(ApplianceError):
            boot.parse_module_load_plan(canonical_dumps(plan))
        rules = canonical_loads(docs["gpt_layout_rules_bytes"])
        rules["boot_contract_sha256"] = "0" * 64
        with self.assertRaises(ApplianceError):
            boot.parse_gpt_layout_rules(canonical_dumps(rules))

    def test_b_manifest_cross_checks_and_real_raw_manifest_regression(self) -> None:
        docs = build_compact_fixture()
        raw = canonical_loads(docs["accepted_manifest_bytes"])
        raw["future_cmdline"] = "console=wrong"
        docs["accepted_manifest_bytes"] = canonical_dumps(raw)
        with self.assertRaises(ApplianceError):
            boot.bind_boot_inputs(**docs)
        sys.path.insert(0, str(ROOT / "test"))
        from conf_proc_provenance_v2_inspect_fixture import build_positive_fixture

        fixture = build_positive_fixture()
        try:
            manifest_bytes = Path(fixture.bundle, "appliance.manifest.json").read_bytes()
            self.assertEqual(_sha(manifest_bytes), fixture.assembly.manifest_sha256)
            manifest = parse_manifest_v2(manifest_bytes).raw
            self.assertEqual(manifest["schema"], "conf-proc-appliance-manifest/v2")
            real_lock = parse_lock(Path(fixture.h3.lock_path).read_bytes())
            real_bundle = Path(fixture.h3._input("bundle.pem")).read_bytes()
            check_authorized_signers_match_bundle(real_lock, real_bundle)
            bundle_input = next(item for item in real_lock.inputs if item.role == "kernel_trusted_cert_bundle")
            self.assertEqual(manifest["module_authority"]["trusted_bundle_input_id"], bundle_input.id)
            self.assertEqual(
                manifest["module_authority"]["authorized_signer_certificate_sha256"],
                [item.certificate_sha256 for item in real_lock.authorized_module_signers],
            )
        finally:
            fixture.cleanup()

    def test_b1_trusted_bundle_bytes_are_a_bound_predecessor_authority(self) -> None:
        docs = build_compact_fixture()
        docs["trusted_certificate_bundle_bytes"] = b"not the locked PEM bundle"
        _refresh_boot_document_bindings(docs)
        with self.assertRaises(ApplianceError):
            boot.bind_boot_inputs(**docs)

    def test_b2_each_major_predecessor_duplicate_is_cross_checked(self) -> None:
        mutations = (
            ("lock_schema", "conf-proc-lock/other"),
            ("future_cmdline", "console=wrong"),
            ("policy.process_policy_sha256", "0" * 64),
            ("module_authority.authorized_signer_certificate_sha256", ["0" * 64]),
            ("module_authority.firmware_inventory.0.sha256", "0" * 64),
            ("provenance.policy_sha256", "0" * 64),
        )
        for label, value in mutations:
            with self.subTest(field=label):
                docs = build_compact_fixture()
                manifest = canonical_loads(docs["accepted_manifest_bytes"])
                target = manifest
                components = label.split(".")
                for component in components[:-1]:
                    target = target[int(component)] if component.isdigit() else target[component]
                last = components[-1]
                target[int(last) if last.isdigit() else last] = value
                docs["accepted_manifest_bytes"] = canonical_dumps(manifest)
                _refresh_boot_document_bindings(docs)
                with self.assertRaises(ApplianceError):
                    boot.bind_boot_inputs(**docs)

    def test_c_gpt_prediction_is_fixed_and_contract_independent(self) -> None:
        binding = _binding()
        self.assertEqual(binding.gpt_plan.prediction_status, "predicted")
        self.assertEqual(binding.gpt_plan.physical_qualification, "not_physical_qualified")
        self.assertEqual(len(binding.gpt_plan.partitions), 4)
        self.assertEqual(
            binding.gpt_plan.disk_guid,
            boot.derive_sha256_v5_guid(binding.root_lock_sha256, binding.gpt_layout_rules_sha256, binding.gpt_layout_rules.disk_domain, 0),
        )
        for ordinal, partition in enumerate(binding.gpt_plan.partitions, start=1):
            with self.subTest(ordinal=ordinal):
                self.assertEqual(partition.ordinal, ordinal)
                self.assertEqual(
                    partition.partuuid,
                    boot.derive_sha256_v5_guid(binding.root_lock_sha256, binding.gpt_layout_rules_sha256, binding.gpt_layout_rules.partuuid_domain, ordinal),
                )
                self.assertEqual(partition.start_lba % binding.gpt_layout_rules.alignment_lba, 0)
                self.assertEqual(
                    partition.end_lba,
                    partition.start_lba + (partition.size_bytes + binding.gpt_layout_rules.logical_sector_bytes - 1) // binding.gpt_layout_rules.logical_sector_bytes - 1,
                )
        self.assertEqual(
            tuple(partition.start_lba for partition in binding.gpt_plan.partitions),
            tuple(locator.start_lba for locator in binding.runtime.disk_locators),
        )
        self.assertTrue(all(
            left.end_lba < right.start_lba
            for left, right in zip(binding.gpt_plan.partitions, binding.gpt_plan.partitions[1:])
        ))

    def test_c2_verity_effects_bind_complete_predicted_pairs(self) -> None:
        binding = _binding()
        expected_ordinals = {"runtime-policy": (1, 2), "models": (3, 4)}
        for pair in (binding.runtime.runtime_policy_verity, binding.runtime.models_verity):
            with self.subTest(image=pair.image_id):
                data_partition = binding.gpt_plan.partitions[pair.data_partition.ordinal - 1]
                hash_partition = binding.gpt_plan.partitions[pair.hash_partition.ordinal - 1]
                self.assertEqual((pair.data_partition.ordinal, pair.hash_partition.ordinal), expected_ordinals[pair.image_id])
                self.assertEqual(pair.data_partition, binding.runtime.disk_locators[pair.data_partition.ordinal - 1])
                self.assertEqual(pair.hash_partition, binding.runtime.disk_locators[pair.hash_partition.ordinal - 1])
                self.assertEqual(
                    (pair.data_partition.type_guid, pair.data_partition.partuuid, pair.data_partition.start_lba, pair.data_partition.end_lba),
                    (data_partition.type_guid, data_partition.partuuid, data_partition.start_lba, data_partition.end_lba),
                )
                self.assertEqual(
                    (pair.hash_partition.type_guid, pair.hash_partition.partuuid, pair.hash_partition.start_lba, pair.hash_partition.end_lba),
                    (hash_partition.type_guid, hash_partition.partuuid, hash_partition.start_lba, hash_partition.end_lba),
                )
                self.assertEqual(pair.data_size_bytes, pair.data_partition.size_bytes)
                self.assertEqual(pair.hash_size_bytes, pair.hash_partition.size_bytes)
                self.assertEqual(
                    (pair.data_sha256, pair.data_size_bytes, pair.hash_sha256, pair.hash_size_bytes),
                    (data_partition.expected_sha256, data_partition.expected_bytes, hash_partition.expected_sha256, hash_partition.expected_bytes),
                )
                self.assertEqual(
                    (pair.root_hash, pair.verity_uuid, pair.salt, pair.data_block_size, pair.hash_block_size),
                    (data_partition.root_hash, data_partition.verity_uuid, data_partition.salt, data_partition.data_block_size, data_partition.hash_block_size),
                )
        for state in (boot.BootTransitionState.RUNTIME_MAP, boot.BootTransitionState.MODELS_MAP):
            with self.subTest(state=state):
                engine = boot.BootTransitionEngine(binding)
                _reach(engine, state)
                map_effect = engine.next_effect()
                self.assertIsInstance(map_effect, boot.MapVerityEffect)
                bad_pair = replace(map_effect.pair, hash_partition=replace(map_effect.pair.hash_partition, partuuid="00000000-0000-5000-8000-000000000000"))
                with self.assertRaises(ApplianceError):
                    engine.accept(boot.VerityMappedObservation(map_effect.contract_sha256, bad_pair, "map"))
        engine = boot.BootTransitionEngine(binding)
        _reach(engine, boot.BootTransitionState.RUNTIME_VERIFY)
        verify_effect = engine.next_effect()
        self.assertIsInstance(verify_effect, boot.VerifyVerityEffect)
        self.assertEqual(verify_effect.pair, binding.runtime.runtime_policy_verity)
        with self.assertRaises(ApplianceError):
            engine.accept(boot.VerityVerifiedObservation(verify_effect.contract_sha256, replace(verify_effect.pair, root_hash="0" * 64), verify_effect.expected_mapping_identity))

    def test_c3_policy_requires_reachable_boot_graph_executables(self) -> None:
        with self.assertRaises(ApplianceError):
            boot.bind_boot_inputs(**build_compact_fixture(unreachable_executable=True))

    def test_c4_tmpfs_cannot_hide_or_nest_an_immutable_image_mount(self) -> None:
        docs = build_compact_fixture()
        contract = canonical_loads(docs["boot_contract_bytes"])
        contract["tmpfs_mounts"] = [{"path": "/run/spp", "size_bytes": 1048576, "mode": 0o755}]
        docs["boot_contract_bytes"] = canonical_dumps(contract)
        plan = canonical_loads(docs["module_plan_bytes"])
        plan["boot_contract_sha256"] = _sha(docs["boot_contract_bytes"])
        docs["module_plan_bytes"] = canonical_dumps(plan)
        with self.assertRaises(ApplianceError):
            boot.bind_boot_inputs(**docs)

        contract["tmpfs_mounts"] = [
            {"path": "/run/a", "size_bytes": 4096, "mode": 0o700},
            {"path": "/run/a/nested", "size_bytes": 4096, "mode": 0o700},
        ]
        with self.assertRaises(ApplianceError):
            boot.parse_boot_contract(canonical_dumps(contract))

    def test_d_module_subset_order_roles_and_nonruntime_closure(self) -> None:
        docs = build_compact_fixture()
        plan = canonical_loads(docs["module_plan_bytes"])
        plan["entries"][1]["predecessor_indices"] = [1]
        with self.assertRaises(ApplianceError):
            boot.parse_module_load_plan(canonical_dumps(plan))
        docs = build_compact_fixture()
        plan = canonical_loads(docs["module_plan_bytes"])
        plan["entries"] = plan["entries"][:1]
        docs["module_plan_bytes"] = canonical_dumps(plan)
        with self.assertRaises(ApplianceError):
            boot.bind_boot_inputs(**docs)
        subset = boot.bind_boot_inputs(**build_compact_fixture(strict_subset=True))
        self.assertEqual(len(subset.module_plan.entries), 2)
        self.assertEqual(len(subset.boot_contract.non_runtime_loadable_modules), 1)
        self.assertNotIn(
            subset.boot_contract.non_runtime_loadable_modules[0],
            tuple(item.identity for item in subset.module_plan.entries),
        )

    def test_d2_module_cycle_duplicate_role_and_nonruntime_overlap_are_rejected(self) -> None:
        docs = build_compact_fixture()
        plan = canonical_loads(docs["module_plan_bytes"])
        plan["entries"][0]["predecessor_indices"] = [0]
        with self.assertRaises(ApplianceError):
            boot.parse_module_load_plan(canonical_dumps(plan))
        contract = canonical_loads(docs["boot_contract_bytes"])
        contract["non_runtime_loadable_modules"] = contract["module_roles"]["boot"]
        with self.assertRaises(ApplianceError):
            boot.parse_boot_contract(canonical_dumps(contract))

    def test_d3_omitted_dependency_and_ambiguous_basename_are_rejected(self) -> None:
        docs = build_compact_fixture()
        plan = canonical_loads(docs["module_plan_bytes"])
        plan["entries"][1]["predecessor_indices"] = []
        with self.assertRaises(ApplianceError):
            boot.parse_module_load_plan(canonical_dumps(plan))

        plan = canonical_loads(docs["module_plan_bytes"])
        plan["entries"][1]["path"] = "/alternate/boot.ko"
        with self.assertRaises(ApplianceError):
            boot.parse_module_load_plan(canonical_dumps(plan))

    def test_e_wrong_and_out_of_order_observations_fail_closed(self) -> None:
        engine = boot.BootTransitionEngine(_binding())
        with self.assertRaises(ApplianceError):
            engine.accept(boot.Pcr15Readback(engine.contract_sha256, b"\0" * 32))
        self.assertIs(engine.state, boot.BootTransitionState.FAILED_NON_SERVING)
        diagnostic = engine.next_effect()
        self.assertIsInstance(diagnostic, boot.SafeDiagnosticEffect)
        self.assertEqual(set(diagnostic.diagnostic.__dict__), {"code", "stage", "contract_prefix"})
        with self.assertRaises(ApplianceError):
            engine.accept(boot.FailureEffectAcknowledgement("0" * 64, boot.FailureEffectKind.DIAGNOSTIC))
        engine.accept(boot.FailureEffectAcknowledgement(engine.contract_sha256, boot.FailureEffectKind.DIAGNOSTIC))
        self.assertIsInstance(engine.next_effect(), boot.CloseServingNetworkEffect)
        engine.accept(boot.FailureEffectAcknowledgement(engine.contract_sha256, boot.FailureEffectKind.CLOSE_SERVING_NETWORK))
        self.assertIsInstance(engine.next_effect(), boot.PoweroffEffect)
        engine.accept(boot.FailureEffectAcknowledgement(engine.contract_sha256, boot.FailureEffectKind.POWEROFF))
        self.assertIsNone(engine.next_effect())

    def test_f_verity_mount_tmpfs_module_and_control_failures(self) -> None:
        cases = (
            (boot.BootTransitionState.RUNTIME_VERIFY, lambda e: boot.VerityVerifiedObservation(e.contract_sha256, e.next_effect().pair, "wrong-mapping")),
            (boot.BootTransitionState.RUNTIME_MOUNT, lambda e: boot.MountReadback(e.contract_sha256, "runtime-policy", "/run/spp/runtime-policy", ("ro",))),
            (boot.BootTransitionState.TMPFS, lambda e: boot.TmpfsReadback(e.contract_sha256, (), ("nosuid", "nodev", "noexec"))),
            (boot.BootTransitionState.MODULES, lambda e: boot.ModuleReadback(e.contract_sha256, ())),
            (boot.BootTransitionState.MODULES_DISABLED, lambda e: boot.ModulesDisabledReadback(e.contract_sha256, "kernel.modules_disabled=1")),
        )
        for state, bad in cases:
            with self.subTest(state=state):
                engine = boot.BootTransitionEngine(_binding())
                _reach(engine, state)
                with self.assertRaises(ApplianceError):
                    engine.accept(bad(engine))
                self.assertIs(engine.state, boot.BootTransitionState.FAILED_NON_SERVING)

    def test_f2_stale_contract_and_required_control_are_rejected(self) -> None:
        engine = boot.BootTransitionEngine(_binding())
        with self.assertRaises(ApplianceError):
            engine.accept(boot.CmdlineObservation("0" * 64, "console=ttyS0", ()))
        self.assertIs(engine.state, boot.BootTransitionState.FAILED_NON_SERVING)
        engine = boot.BootTransitionEngine(_binding())
        _reach(engine, boot.BootTransitionState.MUTABLE_CONTROLS)
        self.assertIsInstance(engine.next_effect(), boot.CloseMutableControlEffect)
        with self.assertRaises(ApplianceError):
            engine.accept(boot.ControlReadback(engine.contract_sha256, "kexec_loading", boot.ControlReadbackStatus.NOT_APPLICABLE_NONEXISTENT))
        self.assertIs(engine.state, boot.BootTransitionState.FAILED_NON_SERVING)

    def test_f3_repeated_observation_and_conditional_control_semantics(self) -> None:
        engine = boot.BootTransitionEngine(_binding())
        engine.accept(_observation(engine.next_effect()))
        with self.assertRaises(ApplianceError):
            engine.accept(boot.CmdlineObservation(engine.contract_sha256, "console=ttyS0", ()))
        self.assertIs(engine.state, boot.BootTransitionState.FAILED_NON_SERVING)
        engine = boot.BootTransitionEngine(_binding())
        _reach(engine, boot.BootTransitionState.MUTABLE_CONTROLS)
        while type(engine.next_effect()) is boot.CloseMutableControlEffect and engine.next_effect().control != "kernel_debug":
            engine.accept(_observation(engine.next_effect()))
        effect = engine.next_effect()
        self.assertEqual(effect.control, "kernel_debug")
        engine.accept(boot.ControlReadback(engine.contract_sha256, "kernel_debug", boot.ControlReadbackStatus.NOT_APPLICABLE_NONEXISTENT))
        self.assertIs(engine.state, boot.BootTransitionState.MUTABLE_CONTROLS)

    def test_g_no_pre_ready_serving_effect_and_final_boundary(self) -> None:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "_child_legal"], check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_g1_each_serving_action_fails_before_ready_without_transport_use(self) -> None:
        binding = _binding()
        with self.assertRaises(TypeError):
            boot.ServingReadyEffect(binding.boot_contract_sha256)
        with self.assertRaises(TypeError):
            boot.ServingActionEffect(binding.boot_contract_sha256)
        with self.assertRaises(TypeError):
            boot.ExtendPcr15Effect(binding.boot_contract_sha256)
        pre_ready_states = tuple(row.state for row in boot.BOOT_TRANSITION_TABLE)
        for state in pre_ready_states:
            for action in boot.ServingAction:
                with self.subTest(state=state, action=action):
                    engine = boot.BootTransitionEngine(binding)
                    engine.state = state
                    transport = _FixtureTransport()
                    with self.assertRaises(ApplianceError):
                        engine.invoke_serving_action(action, transport)
                    self.assertEqual(transport.invocations, [])
                    self.assertIs(engine.state, boot.BootTransitionState.FAILED_NON_SERVING)

    def test_g2_transition_table_matches_reducer_effects(self) -> None:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "_child_transition_table"], check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_h_pcr_known_answer_and_legal_child_path(self) -> None:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "_child_pcr_known_answer"], check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_h2_ambiguous_and_error_extend_outcomes_resolve_only_by_predicted_readback(self) -> None:
        for mode in ("_child_timeout", "_child_error"):
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable, str(Path(__file__).resolve()), mode], check=False, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_i_pcr_latch_is_claimed_by_one_transport_across_different_contracts(self) -> None:
        first = boot.BootTransitionEngine(_binding())
        _reach(first, boot.BootTransitionState.PCR15_EXTEND)
        with self.assertRaises(TypeError):
            boot.ExtendPcr15Effect(first.contract_sha256, first.pcr15_measurement, boot.Pcr15EvidenceClass.DERIVED_APPRAISED_CONJUNCTION)

        second_docs = build_compact_fixture()
        second_contract = canonical_loads(second_docs["boot_contract_bytes"])
        second_contract["tmpfs_mounts"] = [{"path": "/run/spp-second", "size_bytes": 1048576, "mode": 0o755}]
        second_docs["boot_contract_bytes"] = canonical_dumps(second_contract)
        second_plan = canonical_loads(second_docs["module_plan_bytes"])
        second_plan["boot_contract_sha256"] = _sha(second_docs["boot_contract_bytes"])
        second_docs["module_plan_bytes"] = canonical_dumps(second_plan)
        second = boot.BootTransitionEngine(boot.bind_boot_inputs(**second_docs))
        self.assertNotEqual(first.contract_sha256, second.contract_sha256)
        _reach(second, boot.BootTransitionState.PCR15_EXTEND)

        first_transport = _FixtureTransport()
        second_transport = _FixtureTransport()
        first.advance(first_transport)
        first_effect = first_transport.invocations[-1]
        self.assertIsInstance(first_effect, boot.ExtendPcr15Effect)
        self.assertIs(first_effect.evidence_class, boot.Pcr15EvidenceClass.DERIVED_APPRAISED_CONJUNCTION)
        self.assertIs(first.state, boot.BootTransitionState.PCR15_READBACK)
        with self.assertRaises(ApplianceError):
            second.advance(second_transport)
        self.assertIs(second.state, boot.BootTransitionState.FAILED_NON_SERVING)
        self.assertEqual(second_transport.invocations, [])

        replacement_transport = _FixtureTransport()
        with self.assertRaises(ApplianceError):
            first.advance(replacement_transport)
        self.assertIs(first.state, boot.BootTransitionState.FAILED_NON_SERVING)

    def test_j_transport_exception_is_not_retained_in_safe_failure(self) -> None:
        class SecretFailureTransport:
            def execute(self, effect: boot.BootEffect) -> boot.BootObservation:
                raise RuntimeError("/owner/path bearer-secret raw-child-output")

        engine = boot.BootTransitionEngine(_binding())
        with self.assertRaises(ApplianceError) as captured:
            engine.advance(SecretFailureTransport())
        self.assertIsNone(captured.exception.__cause__)
        self.assertIsNone(captured.exception.__context__)
        self.assertNotIn("secret", str(captured.exception))
        diagnostic = engine.next_effect()
        self.assertIsInstance(diagnostic, boot.SafeDiagnosticEffect)
        self.assertNotIn("secret", repr(diagnostic))


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "_child_legal":
        raise SystemExit(_child_legal())
    if len(sys.argv) == 2 and sys.argv[1] == "_child_timeout":
        raise SystemExit(_child_pcr_outcome(boot.Pcr15ExtendOutcome.TIMEOUT))
    if len(sys.argv) == 2 and sys.argv[1] == "_child_error":
        raise SystemExit(_child_pcr_outcome(boot.Pcr15ExtendOutcome.ERROR))
    if len(sys.argv) == 2 and sys.argv[1] == "_child_pcr_known_answer":
        raise SystemExit(_child_pcr_known_answer())
    if len(sys.argv) == 2 and sys.argv[1] == "_child_transition_table":
        raise SystemExit(_child_transition_table())
    unittest.main()
