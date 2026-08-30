#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Document binding and PCR-15 measurement for SPP boot authority v3."""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import secrets
import threading
import weakref
from collections import namedtuple
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_spp_boot import (
    BootEffect,
    BootObservation,
    BootTransport,
    Pcr15ExtendOutcome,
    StateEffectPostcondition,
    _claim_extend_transport,
    _record_extend_outcome,
    _record_extend_transport_closed,
)
from conf_proc_spp_boot_v3_resource import ServingAuthorityWrapperV3
import conf_proc_spp_boot_v3_semantics as semantics
from conf_proc_spp_boot_v3_semantics import (
    ControlInventorySnapshotV3,
    ExecutionClosureV3,
    KernelIdentitySnapshotV3,
    LaunchProjectionV3,
    LaunchSourceProjectionV3,
    ModuleAuthoritySnapshotV3,
    Predicate5SnapshotV3,
    ProcessAuthoritySnapshotV3,
    SourceDigestsV3,
    Stage2ControllerSnapshotV3,
    StorageSnapshotV3,
    parse_execution_closure_v3,
    validate_execution_mode_v3,
    validate_semantic_conjunction_v3,
)
import conf_proc_spp_boot_v3_tables as tables
from conf_proc_spp_reasons_v3 import (
    ApplianceErrorV3,
    CP_BOOT_V3_BINDING,
    CP_BOOT_V3_CONTROL,
    CP_BOOT_V3_DEVICE_MONITOR,
    CP_BOOT_V3_DEV_TREE,
    CP_BOOT_V3_FAILURE_PROTOCOL,
    CP_BOOT_V3_LATCH,
    CP_BOOT_V3_LAUNCH_SUPERVISION,
    CP_BOOT_V3_MODULE_AUTHORITY,
    CP_BOOT_V3_MOUNT_CENSUS,
    CP_BOOT_V3_NETWORK_POLICY,
    CP_BOOT_V3_PCR,
    CP_BOOT_V3_PID1_IDENTITY,
    CP_BOOT_V3_ROOT_TRANSITION,
    CP_BOOT_V3_SCHEMA,
)


BOOT_CONTRACT_V3_SCHEMA: Final = "conf-proc-spp-boot-contract/v3"
_SHA_CHARS_V3: Final = frozenset("0123456789abcdef")
_HASH_REFERENCE_FIELDS_V3: Final = (
    "root_lock_sha256",
    "runtime_closure_sha256",
    "verity_rules_sha256",
    "tcb_identity_sha256",
    "builder_source_sha256",
    "policy_sha256",
    "accepted_manifest_sha256",
    "kernel_feature_contract_sha256",
    "trusted_certificate_bundle_sha256",
    "gpt_layout_rules_sha256",
)
_InputReferenceV3 = namedtuple("_InputReferenceV3", "input_name reference_name")
_INPUT_TO_REFERENCE_V3: Final = (
    _InputReferenceV3("root_lock_bytes", "root_lock_sha256"),
    _InputReferenceV3("runtime_closure_bytes", "runtime_closure_sha256"),
    _InputReferenceV3("verity_rules_bytes", "verity_rules_sha256"),
    _InputReferenceV3("tcb_identity_bytes", "tcb_identity_sha256"),
    _InputReferenceV3("builder_source_bytes", "builder_source_sha256"),
    _InputReferenceV3("policy_bytes", "policy_sha256"),
    _InputReferenceV3("accepted_manifest_bytes", "accepted_manifest_sha256"),
    _InputReferenceV3("kernel_feature_contract_bytes", "kernel_feature_contract_sha256"),
    _InputReferenceV3("trusted_certificate_bundle_bytes", "trusted_certificate_bundle_sha256"),
    _InputReferenceV3("gpt_layout_rules_bytes", "gpt_layout_rules_sha256"),
)


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ApplianceErrorV3(code, message)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA_CHARS_V3


def _load_contract_document(data: bytes) -> object:
    try:
        return canonical_loads(data)
    except Exception:
        raise ApplianceErrorV3(CP_BOOT_V3_SCHEMA, "v3 boot contract is not canonical JSON") from None


@dataclass(frozen=True)
class BootContractV3:
    schema: str
    contract_version: int
    root_lock_sha256: str
    runtime_closure_sha256: str
    verity_rules_sha256: str
    tcb_identity_sha256: str
    builder_source_sha256: str
    policy_sha256: str
    accepted_manifest_sha256: str
    kernel_feature_contract_sha256: str
    trusted_certificate_bundle_sha256: str
    gpt_layout_rules_sha256: str
    execution_closure: ExecutionClosureV3
    execution_mode: str
    cache_policy: str


def parse_boot_contract_v3(data: bytes) -> BootContractV3:
    """Parse the v3 document itself; other authority bytes bind separately."""

    raw = _load_contract_document(data)
    expected = {
        "schema", "contract_version", *_HASH_REFERENCE_FIELDS_V3,
        "execution_closure", "execution_mode", "cache_policy",
    }
    _require(type(raw) is dict and set(raw) == expected, CP_BOOT_V3_SCHEMA, "v3 boot contract fields are invalid")
    _require(
        raw["schema"] == BOOT_CONTRACT_V3_SCHEMA and raw["contract_version"] == 3,
        CP_BOOT_V3_SCHEMA,
        "v3 boot contract schema is invalid",
    )
    _require(
        all(_sha(raw[field]) for field in _HASH_REFERENCE_FIELDS_V3),
        CP_BOOT_V3_SCHEMA,
        "v3 boot contract hash references are invalid",
    )
    closure = parse_execution_closure_v3(raw["execution_closure"])
    validate_execution_mode_v3(raw["execution_mode"], raw["cache_policy"], closure)
    return BootContractV3(
        raw["schema"], raw["contract_version"],
        *[raw[field] for field in _HASH_REFERENCE_FIELDS_V3],
        closure, raw["execution_mode"], raw["cache_policy"],
    )


@dataclass(frozen=True)
class BootBindingV3:
    root_lock_bytes: bytes
    runtime_closure_bytes: bytes
    verity_rules_bytes: bytes
    tcb_identity_bytes: bytes
    builder_source_bytes: bytes
    policy_bytes: bytes
    accepted_manifest_bytes: bytes
    kernel_feature_contract_bytes: bytes
    trusted_certificate_bundle_bytes: bytes
    boot_contract_bytes: bytes
    module_plan_bytes: bytes
    gpt_layout_rules_bytes: bytes
    literal_v3_observation_shape_bytes: bytes
    boot_contract: BootContractV3
    source_digests: SourceDigestsV3
    storage: StorageSnapshotV3
    kernel_identity: KernelIdentitySnapshotV3
    module_authority: ModuleAuthoritySnapshotV3
    control_inventory: ControlInventorySnapshotV3
    launch_projection: LaunchProjectionV3
    stage2_controller: Stage2ControllerSnapshotV3
    process_authority: ProcessAuthoritySnapshotV3
    predicate5: Predicate5SnapshotV3

    @property
    def boot_contract_sha256(self) -> str:
        return hashlib.sha256(self.boot_contract_bytes).hexdigest()


_BINDING_TYPE_TAGS_V3: Final = MappingProxyType({
    BootBindingV3: "binding",
    BootContractV3: "contract",
    semantics.FrozenJsonObjectV3: "fjson",
    ExecutionClosureV3: "closure",
    semantics.ControllerBootstrapCacheProjectionV3: "controller_cache",
    semantics.RoleBootstrapCacheProjectionV3: "role_cache",
    SourceDigestsV3: "digests",
    semantics.PartitionLocatorSnapshotV3: "partition",
    semantics.VerityPairSnapshotV3: "verity",
    StorageSnapshotV3: "storage",
    KernelIdentitySnapshotV3: "kernel",
    semantics.ModuleEntrySnapshotV3: "module_entry",
    ModuleAuthoritySnapshotV3: "module_authority",
    ControlInventorySnapshotV3: "control_inventory",
    LaunchSourceProjectionV3: "launch_source",
    semantics.RoleLaunchSnapshotV3: "role_launch",
    LaunchProjectionV3: "launch",
    Stage2ControllerSnapshotV3: "stage2",
    ProcessAuthoritySnapshotV3: "process_authority",
    semantics.EligibleFileSnapshotV3: "eligible_file",
    semantics.LoaderControlSnapshotV3: "loader_control",
    semantics.JitInputSnapshotV3: "jit_input",
    semantics.JitDerivationSnapshotV3: "jit_derivation",
    semantics.CacheSelectorSnapshotV3: "cache_selector",
    Predicate5SnapshotV3: "predicate5",
    tables.ControlValueRuleV3: "control_rule",
    tables.ControlInventoryRowV3: "control_row",
    tables.LaunchFdRowV3: "launch_fd",
    tables.PipeCensusRowV3: "pipe",
    tables.ReadinessProtocolRowV3: "readiness",
    tables.LaunchRoleRowV3: "launch_role",
    tables.Stage2FdRowV3: "stage2_fd",
    tables.Stage2ControllerRowV3: "stage2_row",
})
_BINDING_MATERIAL_BYTE_FIELDS_V3: Final = frozenset({
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
})


def _normalize_binding_material_v3(
    value: object,
    *,
    _root_byte_capture: dict[str, bytes] | None = None,
) -> tuple[bytes, tuple[tuple[tuple[str | int, ...], int], ...]]:
    """Return the exact tagged canonical tree and its traversed object layout."""

    layout: list[tuple[tuple[str | int, ...], int]] = []
    active: set[int] = set()

    def walk(item: object, path: tuple[str | int, ...]) -> object:
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
            object_id = id(item)
            if object_id in active:
                raise TypeError("binding material contains a cycle")
            active.add(object_id)
            layout.append((path, object_id))
            try:
                return [
                    "tuple",
                    len(item),
                    [walk(member, path + (index,)) for index, member in enumerate(item)],
                ]
            finally:
                active.remove(object_id)
        tag = _BINDING_TYPE_TAGS_V3.get(item_type)
        if tag is None:
            raise TypeError("binding material has an unrecognized type")
        object_id = id(item)
        if object_id in active:
            raise TypeError("binding material contains a cycle")
        active.add(object_id)
        layout.append((path, object_id))
        try:
            if item_type in _BINDING_ENUM_TYPES_V3:
                return [
                    "enum",
                    tag,
                    item.name,
                    walk(item.value, path + ("value",)),
                ]
            if not dataclasses.is_dataclass(item):
                raise TypeError("binding material type is neither dataclass nor enum")
            declared_fields = dataclasses.fields(item)
            if set(vars(item)) != {field.name for field in declared_fields}:
                raise TypeError("binding material dataclass fields are invalid")
            fields_tree = []
            for field in declared_fields:
                field_value = getattr(item, field.name)
                if (
                    _root_byte_capture is not None
                    and path == ()
                    and field.name in _BINDING_MATERIAL_BYTE_FIELDS_V3
                ):
                    if type(field_value) is not bytes:
                        raise TypeError("binding material byte field is invalid")
                    _root_byte_capture[field.name] = field_value
                fields_tree.append([
                    field.name,
                    walk(field_value, path + (field.name,)),
                ])
            return ["dataclass", tag, fields_tree]
        finally:
            active.remove(object_id)

    return canonical_dumps(walk(value, ())), tuple(layout)


_BINDING_ENUM_TYPES_V3: Final = frozenset(
    concrete_type
    for concrete_type in _BINDING_TYPE_TAGS_V3
    if issubclass(concrete_type, Enum)
)


def _binding_fingerprint_v3(normalized: bytes) -> bytes:
    domain = b"sol-spp-boot-binding-v3\0"
    return hashlib.sha256(domain + len(normalized).to_bytes(8, "big") + normalized).digest()


@dataclass(frozen=True)
class _OperationMaterialV3:
    generation: int
    contract_sha256: str
    pcr15_measurement: bytes
    predicted_pcr15: bytes


def _measurement_from_captured_bytes_v3(captured: dict[str, bytes]) -> bytes:
    if set(captured) != _BINDING_MATERIAL_BYTE_FIELDS_V3:
        _binding_reject_v3("binding was not issued")
    frame = lambda value: len(value).to_bytes(8, "big") + value
    material = (
        b"sol-spp-appliance-manifest-v3" + b"\0"
        + frame(captured["root_lock_bytes"])
        + frame(captured["runtime_closure_bytes"])
        + frame(captured["verity_rules_bytes"])
        + frame(captured["tcb_identity_bytes"])
        + frame(captured["builder_source_bytes"])
        + frame(captured["policy_bytes"])
        + frame(captured["accepted_manifest_bytes"])
        + frame(captured["kernel_feature_contract_bytes"])
        + frame(captured["trusted_certificate_bundle_bytes"])
        + frame(captured["boot_contract_bytes"])
        + frame(captured["module_plan_bytes"])
        + frame(captured["gpt_layout_rules_bytes"])
        + frame(captured["literal_v3_observation_shape_bytes"])
    )
    return hashlib.sha256(material).digest()


def _issued_material_bytes_v3(captured: dict[str, bytes], generation: int) -> bytes:
    measurement = _measurement_from_captured_bytes_v3(captured)
    return canonical_dumps({
        "schema": "sol-spp-boot-binding-issued-material/v3",
        "generation": generation,
        "contract_sha256": _sha256(captured["boot_contract_bytes"]),
        "pcr15_measurement": measurement.hex(),
        "predicted_pcr15": hashlib.sha256(b"\0" * 32 + measurement).hexdigest(),
    })


def _decode_issued_material_v3(value: bytes) -> _OperationMaterialV3:
    try:
        raw = canonical_loads(value)
    except BaseException:
        _binding_reject_v3("binding was not issued")
    if (
        type(raw) is not dict
        or set(raw) != {
            "schema", "generation", "contract_sha256",
            "pcr15_measurement", "predicted_pcr15",
        }
        or raw["schema"] != "sol-spp-boot-binding-issued-material/v3"
        or type(raw["generation"]) is not int
        or raw["generation"] < 1
        or not _sha(raw["contract_sha256"])
        or not _sha(raw["pcr15_measurement"])
        or not _sha(raw["predicted_pcr15"])
    ):
        _binding_reject_v3("binding was not issued")
    return _OperationMaterialV3(
        raw["generation"],
        raw["contract_sha256"],
        bytes.fromhex(raw["pcr15_measurement"]),
        bytes.fromhex(raw["predicted_pcr15"]),
    )


@dataclass(frozen=True)
class _IssuedBindingRecordV3:
    binding_ref: weakref.ReferenceType[BootBindingV3]
    generation: int
    transition_counter: int
    fingerprint: bytes
    material_bytes: bytes
    engine_claimed: bool = False
    engine_ref: weakref.ReferenceType["BootTransitionEngineV3"] | None = None
    admission_capability: "ServingAdmissionCapabilityV3 | None" = None
    admitted_wrapper_ref: weakref.ReferenceType[ServingAuthorityWrapperV3] | None = None
    integrity_seal: bytes = b""


@dataclass(frozen=True)
class _BindingTombstoneV3:
    binding_ref: weakref.ReferenceType[BootBindingV3]
    generation: int
    integrity_seal: bytes = b""


class _BindingTransitionHighWaterV3:
    __slots__ = (
        "binding_ref",
        "generation",
        "transition_counter",
        "current_record",
        "integrity_seal",
    )

    def __init__(
        self,
        binding_ref: weakref.ReferenceType[BootBindingV3],
        generation: int,
        current_record: _IssuedBindingRecordV3,
    ) -> None:
        self.binding_ref = binding_ref
        self.generation = generation
        self.transition_counter = current_record.transition_counter
        self.current_record = current_record
        self.integrity_seal = b""


class _IssuedBindingRegistryV3:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.generation = 0
        self.records: dict[int, _IssuedBindingRecordV3] = {}
        self.tombstones: dict[int, _BindingTombstoneV3] = {}
        self.transition_high_water: dict[int, _BindingTransitionHighWaterV3] = {}


_ISSUED_BOOT_BINDINGS_V3: Final = _IssuedBindingRegistryV3()
_RECORD_INTEGRITY_KEY_V3: Final = secrets.token_bytes(32)


def _reference_identity_v3(reference: object) -> tuple[int, int]:
    if type(reference) is not weakref.ReferenceType:
        return (0, 0)
    # The weak-reference object is stable authority; its target liveness is
    # checked separately.  Folding the changing target into the seal would
    # invalidate a permanent engine claim merely because its engine died.
    return (id(reference), 0)


def _record_integrity_payload_v3(record: _IssuedBindingRecordV3) -> bytes:
    engine_reference_id, engine_id = _reference_identity_v3(record.engine_ref)
    binding_reference_id, binding_id = _reference_identity_v3(record.binding_ref)
    capability = record.admission_capability
    capability_id = 0
    capability_nonce = b""
    if type(capability) is ServingAdmissionCapabilityV3:
        capability_id = id(capability)
        capability_nonce = capability.nonce
    wrapper_reference_id, wrapper_id = _reference_identity_v3(
        record.admitted_wrapper_ref
    )
    return canonical_dumps({
        "record_id": id(record),
        "binding_reference_id": binding_reference_id,
        "binding_id": binding_id,
        "generation": record.generation,
        "transition_counter": record.transition_counter,
        "fingerprint_length": len(record.fingerprint),
        "fingerprint_sha256": hashlib.sha256(record.fingerprint).hexdigest(),
        "material_length": len(record.material_bytes),
        "material_sha256": hashlib.sha256(record.material_bytes).hexdigest(),
        "engine_claimed": record.engine_claimed,
        "engine_reference_id": engine_reference_id,
        "engine_id": engine_id,
        "capability_id": capability_id,
        "capability_nonce_sha256": hashlib.sha256(capability_nonce).hexdigest(),
        "wrapper_reference_id": wrapper_reference_id,
        "wrapper_id": wrapper_id,
    })


def _seal_record_v3(record: _IssuedBindingRecordV3) -> _IssuedBindingRecordV3:
    seal = hmac.new(
        _RECORD_INTEGRITY_KEY_V3,
        _record_integrity_payload_v3(record),
        hashlib.sha256,
    ).digest()
    object.__setattr__(record, "integrity_seal", seal)
    return record


def _new_record_v3(
    binding_ref: weakref.ReferenceType[BootBindingV3],
    generation: int,
    fingerprint: bytes,
    material_bytes: bytes,
    *,
    transition_counter: int = 0,
    engine_claimed: bool = False,
    engine_ref: weakref.ReferenceType["BootTransitionEngineV3"] | None = None,
    admission_capability: "ServingAdmissionCapabilityV3 | None" = None,
    admitted_wrapper_ref: weakref.ReferenceType[ServingAuthorityWrapperV3] | None = None,
) -> _IssuedBindingRecordV3:
    return _seal_record_v3(_IssuedBindingRecordV3(
        binding_ref,
        generation,
        transition_counter,
        fingerprint,
        material_bytes,
        engine_claimed,
        engine_ref,
        admission_capability,
        admitted_wrapper_ref,
    ))


def _valid_record_integrity_v3(record: object) -> bool:
    if type(record) is not _IssuedBindingRecordV3:
        return False
    if set(vars(record)) != {field.name for field in dataclasses.fields(_IssuedBindingRecordV3)}:
        return False
    if (
        type(record.binding_ref) is not weakref.ReferenceType
        or type(record.generation) is not int
        or record.generation < 1
        or type(record.transition_counter) is not int
        or record.transition_counter < 0
        or type(record.fingerprint) is not bytes
        or len(record.fingerprint) != 32
        or type(record.material_bytes) is not bytes
        or type(record.engine_claimed) is not bool
        or (record.engine_ref is not None and type(record.engine_ref) is not weakref.ReferenceType)
        or (
            record.admission_capability is not None
            and (
                type(record.admission_capability) is not ServingAdmissionCapabilityV3
                or type(record.admission_capability.nonce) is not bytes
                or len(record.admission_capability.nonce) != 32
            )
        )
        or (
            record.admitted_wrapper_ref is not None
            and type(record.admitted_wrapper_ref) is not weakref.ReferenceType
        )
        or type(record.integrity_seal) is not bytes
        or len(record.integrity_seal) != 32
    ):
        return False
    expected = hmac.new(
        _RECORD_INTEGRITY_KEY_V3,
        _record_integrity_payload_v3(record),
        hashlib.sha256,
    ).digest()
    return hmac.compare_digest(record.integrity_seal, expected)


def _transition_high_water_integrity_payload_v3(
    high_water: _BindingTransitionHighWaterV3,
) -> bytes:
    binding_reference_id, binding_id = _reference_identity_v3(
        high_water.binding_ref
    )
    return canonical_dumps({
        "high_water_id": id(high_water),
        "binding_reference_id": binding_reference_id,
        "binding_id": binding_id,
        "generation": high_water.generation,
        "transition_counter": high_water.transition_counter,
        "current_record_id": id(high_water.current_record),
        "current_record_seal_sha256": hashlib.sha256(
            high_water.current_record.integrity_seal
        ).hexdigest(),
    })


def _seal_transition_high_water_v3(
    high_water: _BindingTransitionHighWaterV3,
) -> _BindingTransitionHighWaterV3:
    high_water.integrity_seal = hmac.new(
        _RECORD_INTEGRITY_KEY_V3,
        _transition_high_water_integrity_payload_v3(high_water),
        hashlib.sha256,
    ).digest()
    return high_water


def _new_transition_high_water_v3(
    binding_ref: weakref.ReferenceType[BootBindingV3],
    generation: int,
    current_record: _IssuedBindingRecordV3,
) -> _BindingTransitionHighWaterV3:
    return _seal_transition_high_water_v3(
        _BindingTransitionHighWaterV3(binding_ref, generation, current_record)
    )


def _valid_transition_high_water_v3(high_water: object) -> bool:
    if type(high_water) is not _BindingTransitionHighWaterV3:
        return False
    if any(
        not hasattr(high_water, field)
        for field in _BindingTransitionHighWaterV3.__slots__
    ):
        return False
    if (
        type(high_water.binding_ref) is not weakref.ReferenceType
        or type(high_water.generation) is not int
        or high_water.generation < 1
        or type(high_water.transition_counter) is not int
        or high_water.transition_counter < 0
        or not _valid_record_integrity_v3(high_water.current_record)
        or high_water.current_record.binding_ref is not high_water.binding_ref
        or high_water.current_record.generation != high_water.generation
        or high_water.current_record.transition_counter
        != high_water.transition_counter
        or type(high_water.integrity_seal) is not bytes
        or len(high_water.integrity_seal) != 32
    ):
        return False
    expected = hmac.new(
        _RECORD_INTEGRITY_KEY_V3,
        _transition_high_water_integrity_payload_v3(high_water),
        hashlib.sha256,
    ).digest()
    return hmac.compare_digest(high_water.integrity_seal, expected)


def _record_matches_transition_high_water_locked_v3(
    record: object, binding: BootBindingV3
) -> bool:
    high_water = _ISSUED_BOOT_BINDINGS_V3.transition_high_water.get(id(binding))
    return (
        _valid_transition_high_water_v3(high_water)
        and high_water.binding_ref() is binding
        and high_water.current_record is record
    )


def _current_high_water_record_locked_v3(
    binding: BootBindingV3,
) -> _IssuedBindingRecordV3 | None:
    high_water = _ISSUED_BOOT_BINDINGS_V3.transition_high_water.get(id(binding))
    if (
        _valid_transition_high_water_v3(high_water)
        and high_water.binding_ref() is binding
    ):
        return high_water.current_record
    return None


def _record_for_use_locked_v3(binding: BootBindingV3) -> object:
    record = _ISSUED_BOOT_BINDINGS_V3.records.get(id(binding))
    high_water = _ISSUED_BOOT_BINDINGS_V3.transition_high_water.get(id(binding))
    if record is None:
        canonical = _current_high_water_record_locked_v3(binding)
        if canonical is not None and not _live_tombstone_matches_locked_v3(binding):
            _install_tombstone_locked_v3(
                binding,
                generation=canonical.generation,
                binding_ref=canonical.binding_ref,
            )
        return None
    if (
        _valid_record_integrity_v3(record)
        and record.binding_ref() is binding
        and _valid_transition_high_water_v3(high_water)
        and high_water.binding_ref() is binding
        and record.generation == high_water.generation
        and record.transition_counter < high_water.transition_counter
    ):
        record = high_water.current_record
        _ISSUED_BOOT_BINDINGS_V3.records[id(binding)] = record
    return record


def _transition_current_record_locked_v3(
    binding: BootBindingV3,
    current: _IssuedBindingRecordV3,
    *,
    engine_claimed: bool,
    engine_ref: weakref.ReferenceType["BootTransitionEngineV3"] | None,
    admission_capability: "ServingAdmissionCapabilityV3 | None",
    admitted_wrapper_ref: weakref.ReferenceType[ServingAuthorityWrapperV3] | None,
) -> _IssuedBindingRecordV3:
    if not _record_matches_transition_high_water_locked_v3(current, binding):
        _binding_reject_v3("binding was not issued")
    replacement = _new_record_v3(
        current.binding_ref,
        current.generation,
        current.fingerprint,
        current.material_bytes,
        transition_counter=current.transition_counter + 1,
        engine_claimed=engine_claimed,
        engine_ref=engine_ref,
        admission_capability=admission_capability,
        admitted_wrapper_ref=admitted_wrapper_ref,
    )
    high_water = _ISSUED_BOOT_BINDINGS_V3.transition_high_water[id(binding)]
    high_water.transition_counter = replacement.transition_counter
    high_water.current_record = replacement
    _seal_transition_high_water_v3(high_water)
    _ISSUED_BOOT_BINDINGS_V3.records[id(binding)] = replacement
    return replacement


def _tombstone_integrity_payload_v3(tombstone: _BindingTombstoneV3) -> bytes:
    reference_id, binding_id = _reference_identity_v3(tombstone.binding_ref)
    return canonical_dumps({
        "tombstone_id": id(tombstone),
        "binding_reference_id": reference_id,
        "binding_id": binding_id,
        "generation": tombstone.generation,
    })


def _new_tombstone_v3(
    binding_ref: weakref.ReferenceType[BootBindingV3], generation: int
) -> _BindingTombstoneV3:
    tombstone = _BindingTombstoneV3(binding_ref, generation)
    seal = hmac.new(
        _RECORD_INTEGRITY_KEY_V3,
        _tombstone_integrity_payload_v3(tombstone),
        hashlib.sha256,
    ).digest()
    object.__setattr__(tombstone, "integrity_seal", seal)
    return tombstone


def _valid_tombstone_integrity_v3(tombstone: object) -> bool:
    if type(tombstone) is not _BindingTombstoneV3:
        return False
    if set(vars(tombstone)) != {field.name for field in dataclasses.fields(_BindingTombstoneV3)}:
        return False
    if (
        type(tombstone.binding_ref) is not weakref.ReferenceType
        or type(tombstone.generation) is not int
        or tombstone.generation < 1
        or type(tombstone.integrity_seal) is not bytes
        or len(tombstone.integrity_seal) != 32
    ):
        return False
    expected = hmac.new(
        _RECORD_INTEGRITY_KEY_V3,
        _tombstone_integrity_payload_v3(tombstone),
        hashlib.sha256,
    ).digest()
    return hmac.compare_digest(tombstone.integrity_seal, expected)


def _live_tombstone_matches_locked_v3(binding: BootBindingV3) -> bool:
    tombstone = _ISSUED_BOOT_BINDINGS_V3.tombstones.get(id(binding))
    return (
        _valid_tombstone_integrity_v3(tombstone)
        and tombstone.binding_ref() is binding
    )


def _record_shadowed_by_live_tombstone_locked_v3(
    record: object, binding: BootBindingV3
) -> bool:
    return (
        _valid_record_integrity_v3(record)
        and record.binding_ref() is binding
        and _live_tombstone_matches_locked_v3(binding)
    )


def _retire_boot_binding_v3(
    binding_id: int,
    generation: int,
    expected_reference: weakref.ReferenceType[BootBindingV3] | None = None,
) -> None:
    with _ISSUED_BOOT_BINDINGS_V3.lock:
        record = _ISSUED_BOOT_BINDINGS_V3.records.get(binding_id)
        if (
            type(record) is _IssuedBindingRecordV3
            and record.generation == generation
            and (expected_reference is None or record.binding_ref is expected_reference)
            and record.binding_ref() is None
        ):
            del _ISSUED_BOOT_BINDINGS_V3.records[binding_id]
        high_water = _ISSUED_BOOT_BINDINGS_V3.transition_high_water.get(binding_id)
        if (
            type(high_water) is _BindingTransitionHighWaterV3
            and high_water.generation == generation
            and (
                expected_reference is None
                or high_water.binding_ref is expected_reference
            )
            and high_water.binding_ref() is None
        ):
            del _ISSUED_BOOT_BINDINGS_V3.transition_high_water[binding_id]
        tombstone = _ISSUED_BOOT_BINDINGS_V3.tombstones.get(binding_id)
        if (
            type(tombstone) is _BindingTombstoneV3
            and tombstone.generation == generation
            and (expected_reference is None or tombstone.binding_ref is expected_reference)
            and tombstone.binding_ref() is None
        ):
            del _ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id]


def _binding_reference_v3(
    binding: BootBindingV3, generation: int
) -> weakref.ReferenceType[BootBindingV3]:
    binding_id = id(binding)
    reference: weakref.ReferenceType[BootBindingV3]

    def retire(collected_reference: weakref.ReferenceType[BootBindingV3]) -> None:
        _retire_boot_binding_v3(binding_id, generation, collected_reference)

    reference = weakref.ref(binding, retire)
    return reference


def _install_tombstone_locked_v3(
    binding: BootBindingV3,
    *,
    generation: int | None = None,
    binding_ref: weakref.ReferenceType[BootBindingV3] | None = None,
) -> None:
    if generation is None or binding_ref is None or binding_ref() is not binding:
        _ISSUED_BOOT_BINDINGS_V3.generation += 1
        generation = _ISSUED_BOOT_BINDINGS_V3.generation
        binding_ref = _binding_reference_v3(binding, generation)
    _ISSUED_BOOT_BINDINGS_V3.tombstones[id(binding)] = _new_tombstone_v3(
        binding_ref, generation
    )


def _invalidate_latest_record_locked_v3(
    binding: BootBindingV3, record: object
) -> _IssuedBindingRecordV3 | None:
    high_water = _ISSUED_BOOT_BINDINGS_V3.transition_high_water.get(id(binding))
    canonical = (
        high_water.current_record
        if (
            _valid_transition_high_water_v3(high_water)
            and high_water.binding_ref() is binding
        )
        else None
    )
    del _ISSUED_BOOT_BINDINGS_V3.records[id(binding)]
    if (
        _valid_record_integrity_v3(record)
        and record.binding_ref() is binding
    ):
        if not _live_tombstone_matches_locked_v3(binding):
            _install_tombstone_locked_v3(
                binding,
                generation=record.generation,
                binding_ref=record.binding_ref,
            )
        return canonical if canonical is not None else record
    _install_tombstone_locked_v3(binding)
    return canonical


def _retire_record_admission_v3(record: _IssuedBindingRecordV3) -> None:
    capability = record.admission_capability
    if capability is None:
        return
    wrapper: ServingAuthorityWrapperV3 | None = (
        None
        if record.admitted_wrapper_ref is None
        else record.admitted_wrapper_ref()
    )
    constructing = False
    with capability.condition:
        if capability.phase == "constructing":
            capability.retired_construction_owner_thread_id = capability.owner_thread_id
        capability.retired = True
        capability.phase = "retired"
        capability.owner_thread_id = None
        if wrapper is not None:
            constructing = False
        elif capability.published_wrapper_ref is not None:
            wrapper = capability.published_wrapper_ref()
        elif capability.constructing_wrapper_ref is not None:
            wrapper = capability.constructing_wrapper_ref()
            constructing = wrapper is not None
            capability.constructing_wrapper_ref = None
        capability.condition.notify_all()
    if wrapper is not None:
        if constructing:
            wrapper._discard_unpublished_construction_v3()
        else:
            wrapper._binding_mismatch_cleanup_v3()


def _binding_record_v3(binding: object) -> _IssuedBindingRecordV3 | None:
    if type(binding) is not BootBindingV3:
        return None
    try:
        normalized, _identity_layout = _normalize_binding_material_v3(binding)
        fingerprint = _binding_fingerprint_v3(normalized)
    except BaseException:
        fingerprint = None
    retired: _IssuedBindingRecordV3 | None = None
    missing = False
    with _ISSUED_BOOT_BINDINGS_V3.lock:
        tombstone_already_live = _live_tombstone_matches_locked_v3(binding)
        record = _record_for_use_locked_v3(binding)
        if record is None:
            missing = True
            if (
                not tombstone_already_live
                and _live_tombstone_matches_locked_v3(binding)
            ):
                retired = _current_high_water_record_locked_v3(binding)
        elif (
            not _valid_record_integrity_v3(record)
            or record.binding_ref() is not binding
        ):
            retired = _invalidate_latest_record_locked_v3(binding, record)
        elif _record_shadowed_by_live_tombstone_locked_v3(record, binding):
            retired = _invalidate_latest_record_locked_v3(binding, record)
        elif not _record_matches_transition_high_water_locked_v3(record, binding):
            retired = _invalidate_latest_record_locked_v3(binding, record)
        elif fingerprint is None or not hmac.compare_digest(record.fingerprint, fingerprint):
            retired = _invalidate_latest_record_locked_v3(binding, record)
        else:
            return record
    if retired is not None:
        _retire_record_admission_v3(retired)
    if missing:
        return None
    return None


def _register_boot_binding_v3(binding: BootBindingV3) -> BootBindingV3:
    captured: dict[str, bytes] = {}
    try:
        normalized, _identity_layout = _normalize_binding_material_v3(
            binding,
            _root_byte_capture=captured,
        )
        confirmed, _confirmed_layout = _normalize_binding_material_v3(binding)
    except BaseException:
        raise ApplianceErrorV3(CP_BOOT_V3_BINDING, "binding material cannot be normalized") from None
    _require(
        hmac.compare_digest(normalized, confirmed),
        CP_BOOT_V3_BINDING,
        "binding material changed during registration",
    )
    fingerprint = _binding_fingerprint_v3(normalized)
    binding_id = id(binding)
    with _ISSUED_BOOT_BINDINGS_V3.lock:
        existing = _ISSUED_BOOT_BINDINGS_V3.records.get(binding_id)
        if existing is not None:
            if (
                _valid_record_integrity_v3(existing)
                and existing.binding_ref() is None
            ):
                del _ISSUED_BOOT_BINDINGS_V3.records[binding_id]
            else:
                _binding_reject_v3("binding was not issued")
        tombstone = _ISSUED_BOOT_BINDINGS_V3.tombstones.get(binding_id)
        if tombstone is not None:
            if (
                _valid_tombstone_integrity_v3(tombstone)
                and tombstone.binding_ref() is None
            ):
                del _ISSUED_BOOT_BINDINGS_V3.tombstones[binding_id]
            else:
                _binding_reject_v3("binding was not issued")
        high_water = _ISSUED_BOOT_BINDINGS_V3.transition_high_water.get(binding_id)
        if high_water is not None:
            if (
                _valid_transition_high_water_v3(high_water)
                and high_water.binding_ref() is None
            ):
                del _ISSUED_BOOT_BINDINGS_V3.transition_high_water[binding_id]
            else:
                _binding_reject_v3("binding was not issued")
        if (
            existing is not None
            and binding_id in _ISSUED_BOOT_BINDINGS_V3.records
        ):
            _binding_reject_v3("binding was not issued")
        _ISSUED_BOOT_BINDINGS_V3.generation += 1
        generation = _ISSUED_BOOT_BINDINGS_V3.generation
        binding_ref = _binding_reference_v3(binding, generation)
        record = _new_record_v3(
            binding_ref,
            generation,
            fingerprint,
            _issued_material_bytes_v3(captured, generation),
        )
        _ISSUED_BOOT_BINDINGS_V3.records[binding_id] = record
        _ISSUED_BOOT_BINDINGS_V3.transition_high_water[binding_id] = (
            _new_transition_high_water_v3(binding_ref, generation, record)
        )
    return binding


def is_issued_boot_binding_v3(binding: object) -> bool:
    """Return whether this exact, unmodified binding object was issued by v3."""

    return _binding_record_v3(binding) is not None


def _binding_reject_v3(message: str) -> None:
    raise ApplianceErrorV3(CP_BOOT_V3_BINDING, message)


def _literal_v3_observation_shape_bytes(
    process_authority: ProcessAuthoritySnapshotV3,
) -> bytes:
    """Serialize every v3-owned closed inventory in a stable, ordered form."""

    shape = (
        ("schema", "conf-proc-spp-boot-observation-shape/v3"),
        ("bootstrap_mounts", tables.BOOTSTRAP_MOUNTS_V3),
        (
            "early_modules",
            tables.EARLY_MODULE_TARGET_KERNEL_RELEASE_V3,
            tables.EARLY_MODULE_TARGET_CONFIG_SHA256_V3,
            tables.EARLY_MODULE_SIGNER_V3,
            tables.EARLY_MODULE_SIGNATURE_KEY_ID_V3,
            tables.EARLY_MODULE_RELEASE_ROOT_V3,
            tables.EARLY_MODULE_ROWS_V3,
            tables.EARLY_MODULE_BUILTIN_DEPENDENCIES_V3,
        ),
        ("kernel_config_binding", tables.KERNEL_CONFIG_BINDING_ROWS_V3),
        ("control_inventory", tables.CONTROL_INVENTORY_ROWS_V3),
        (
            "dev_tree",
            tables.DEV_TREE_DIRECTORY_ROWS_V3,
            tables.DEV_TREE_ROWS_V3,
            tables.DEV_TREE_FORBIDDEN_PATH_PATTERNS_V3,
            tables.DEV_TREE_FORBIDDEN_NODE_KINDS_V3,
        ),
        (
            "failure_inventory",
            tables.FAILURE_DIAGNOSTIC_TOKENS_V3,
            tables.FAILURE_LATE_CODES_V3,
            tables.FAILURE_STAGES_V3,
        ),
        ("launch_roles", tables.LAUNCH_ROLE_ROWS_V3),
        ("stage2_controller", tables.STAGE2_CONTROLLER_ROW_V3),
        (
            "wire_message_authority",
            tables.WIRE_HEADER_FIELDS_V3,
            tables.WIRE_HEADER_BYTES_V3,
            tables.WIRE_SEQUENCE_RULE_V3,
            tables.WIRE_HAS_FD_TYPE_IDS_V3,
            tables.WIRE_SESSION_COORDINATE_RULES_V3,
            tables.WIRE_ROUTE_ENUM_ROWS_V3,
            tables.WIRE_COLLECTOR_GENERATION_ENUM_ROWS_V3,
            tables.WIRE_COLLECTOR_RESULT_ENUM_ROWS_V3,
            tables.WIRE_COLLECTOR_ABORT_REASON_ENUM_ROWS_V3,
            tables.WIRE_INVALID_COLLECTOR_ACK_REASON_ENUM_ROWS_V3,
            tables.WIRE_INVALID_COLLECTOR_ACK_ABORT_MAPPING_V3,
            tables.WIRE_COLLECTOR_CANCEL_REASON_ENUM_ROWS_V3,
            tables.WIRE_REQUEST_REJECT_REASON_ENUM_ROWS_V3,
            tables.WIRE_WORK_FINISH_OUTCOME_ENUM_ROWS_V3,
            tables.WIRE_REQUEST_RELEASE_STATE_ENUM_ROWS_V3,
            tables.WIRE_SESSION_RELEASE_HELD_BITS_V3,
            tables.WIRE_SESSION_RELEASE_REASON_ENUM_ROWS_V3,
            tables.WIRE_PRE_REQUEST_REJECT_REASON_ENUM_ROWS_V3,
            tables.WIRE_GLOBAL_FAULT_REASON_ENUM_ROWS_V3,
            tables.WIRE_ENTITLEMENT_CONNECT_REJECT_REASON_ENUM_ROWS_V3,
            tables.WIRE_CONDITIONAL_SHAPE_ROWS_V3,
            tables.WIRE_MESSAGE_AUTHORITY_ROWS_V3,
        ),
        ("resource_actions", tables.RESOURCE_ACTION_ROWS_V3),
        (
            "resource_capacities",
            tables.LISTEN_BACKLOG_V3,
            tables.SOMAXCONN_MINIMUM_V3,
            tables.MAX_LIVE_SESSIONS_V3,
            tables.COLLECTOR_OPERATION_PERMITS_V3,
            tables.COLLECTOR_OPERATION_BOUND_SECONDS_V3,
            tables.COLLECTOR_OUTPUT_CAPACITY_BYTES_V3,
            tables.ROUTE_WORK_PERMITS_TOTAL_V3,
            tables.STREAM_BUFFER_BYTES_V3,
            tables.AGGREGATE_BUFFER_BYTES_V3,
            tables.REQUEST_HEAD_CAPACITY_BYTES_V3,
            tables.RELAY_COPY_CHUNK_BYTES_V3,
        ),
        (
            "process_authority",
            process_authority.boot_roots,
            process_authority.process_nodes,
            process_authority.process_edges,
            process_authority.network_policy,
            process_authority.capability_policy,
        ),
        ("wire_message_types", tables.WIRE_MESSAGE_TYPE_ROWS_V3),
    )
    return repr(shape).encode("utf-8")


def bind_boot_inputs_v3(
    *,
    contract: BootContractV3,
    root_lock_bytes: bytes,
    runtime_closure_bytes: bytes,
    verity_rules_bytes: bytes,
    tcb_identity_bytes: bytes,
    builder_source_bytes: bytes,
    policy_bytes: bytes,
    accepted_manifest_bytes: bytes,
    kernel_feature_contract_bytes: bytes,
    trusted_certificate_bundle_bytes: bytes,
    module_plan_bytes: bytes,
    gpt_layout_rules_bytes: bytes,
    boot_contract_bytes: bytes,
) -> BootBindingV3:
    """Cross-bind v3 component bytes to the parsed contract references."""

    _require(type(contract) is BootContractV3, CP_BOOT_V3_BINDING, "v3 contract is invalid")
    supplied = {
        "root_lock_bytes": root_lock_bytes,
        "runtime_closure_bytes": runtime_closure_bytes,
        "verity_rules_bytes": verity_rules_bytes,
        "tcb_identity_bytes": tcb_identity_bytes,
        "builder_source_bytes": builder_source_bytes,
        "policy_bytes": policy_bytes,
        "accepted_manifest_bytes": accepted_manifest_bytes,
        "kernel_feature_contract_bytes": kernel_feature_contract_bytes,
        "trusted_certificate_bundle_bytes": trusted_certificate_bundle_bytes,
        "module_plan_bytes": module_plan_bytes,
        "gpt_layout_rules_bytes": gpt_layout_rules_bytes,
        "boot_contract_bytes": boot_contract_bytes,
    }
    _require(all(type(value) is bytes for value in supplied.values()), CP_BOOT_V3_BINDING, "all v3 boot authority inputs must be bytes")
    private_contract = parse_boot_contract_v3(boot_contract_bytes)
    _require(
        private_contract == contract,
        CP_BOOT_V3_BINDING,
        "v3 contract bytes disagree with parsed contract",
    )
    snapshots = validate_semantic_conjunction_v3(
        contract=private_contract,
        boot_contract_bytes=boot_contract_bytes,
        root_lock_bytes=root_lock_bytes,
        runtime_closure_bytes=runtime_closure_bytes,
        verity_rules_bytes=verity_rules_bytes,
        tcb_identity_bytes=tcb_identity_bytes,
        builder_source_bytes=builder_source_bytes,
        policy_bytes=policy_bytes,
        accepted_manifest_bytes=accepted_manifest_bytes,
        kernel_feature_contract_bytes=kernel_feature_contract_bytes,
        trusted_certificate_bundle_bytes=trusted_certificate_bundle_bytes,
        module_plan_bytes=module_plan_bytes,
        gpt_layout_rules_bytes=gpt_layout_rules_bytes,
    )
    return _register_boot_binding_v3(
        BootBindingV3(
            root_lock_bytes,
            runtime_closure_bytes,
            verity_rules_bytes,
            tcb_identity_bytes,
            builder_source_bytes,
            policy_bytes,
            accepted_manifest_bytes,
            kernel_feature_contract_bytes,
            trusted_certificate_bundle_bytes,
            boot_contract_bytes,
            module_plan_bytes,
            gpt_layout_rules_bytes,
            _literal_v3_observation_shape_bytes(snapshots.process_authority),
            private_contract,
            snapshots.source_digests,
            snapshots.storage,
            snapshots.kernel_identity,
            snapshots.module_authority,
            snapshots.control_inventory,
            snapshots.launch_projection,
            snapshots.stage2_controller,
            snapshots.process_authority,
            snapshots.predicate5,
        )
    )


class ServingAdmissionCapabilityV3:
    """One binding-scoped, single-publication serving admission capability."""

    def __init__(self, binding: BootBindingV3, generation: int, engine: "BootTransitionEngineV3") -> None:
        self.nonce = secrets.token_bytes(32)
        self.binding_ref = weakref.ref(binding)
        self.binding_id = id(binding)
        self.generation = generation
        self.engine_ref = weakref.ref(engine)
        self.condition = threading.Condition(threading.RLock())
        self.phase = "none"
        self.owner_thread_id: int | None = None
        self.retired_construction_owner_thread_id: int | None = None
        self.constructing_wrapper_ref: weakref.ReferenceType[ServingAuthorityWrapperV3] | None = None
        self.published_wrapper_ref: weakref.ReferenceType[ServingAuthorityWrapperV3] | None = None
        self.retired = False


def _record_generation_matches_v3(
    record: object,
    binding: BootBindingV3,
    generation: int,
) -> bool:
    return (
        _valid_record_integrity_v3(record)
        and record.generation == generation
        and record.binding_ref() is binding
        and _record_matches_transition_high_water_locked_v3(record, binding)
        and not _record_shadowed_by_live_tombstone_locked_v3(record, binding)
    )


def _record_engine_matches_v3(
    record: object,
    binding: BootBindingV3,
    generation: int,
    engine: "BootTransitionEngineV3",
) -> bool:
    return (
        _record_generation_matches_v3(record, binding, generation)
        and record.engine_claimed
        and record.engine_ref is not None
        and record.engine_ref() is engine
    )


def _claim_engine_v3(
    binding: BootBindingV3, engine: "BootTransitionEngineV3"
) -> _OperationMaterialV3:
    record = _binding_record_v3(binding)
    if record is None:
        _binding_reject_v3("binding was not issued")
    generation = record.generation
    retired: _IssuedBindingRecordV3 | None = None
    with _ISSUED_BOOT_BINDINGS_V3.lock:
        current = _record_for_use_locked_v3(binding)
        if not _record_generation_matches_v3(current, binding, generation):
            if current is not None:
                retired = _invalidate_latest_record_locked_v3(binding, current)
        elif current.engine_claimed:
            _binding_reject_v3("binding already has a transition engine")
        else:
            material = _decode_issued_material_v3(current.material_bytes)
            _transition_current_record_locked_v3(
                binding,
                current,
                engine_claimed=True,
                engine_ref=weakref.ref(engine),
                admission_capability=current.admission_capability,
                admitted_wrapper_ref=current.admitted_wrapper_ref,
            )
            return material
    if retired is not None:
        _retire_record_admission_v3(retired)
    _binding_reject_v3("binding was not issued")


def _verified_engine_record_v3(
    engine: "BootTransitionEngineV3",
) -> tuple[_IssuedBindingRecordV3, _OperationMaterialV3]:
    binding = getattr(engine, "_binding_liveness_anchor", None)
    if type(binding) is not BootBindingV3:
        engine._binding_mismatch_cleanup_v3()
        _binding_reject_v3("binding was not issued")
    record = _binding_record_v3(binding)
    if record is None:
        engine._binding_mismatch_cleanup_v3()
        _binding_reject_v3("binding was not issued")
    generation = record.generation
    retired: _IssuedBindingRecordV3 | None = None
    with _ISSUED_BOOT_BINDINGS_V3.lock:
        current = _record_for_use_locked_v3(binding)
        if not _record_generation_matches_v3(current, binding, generation):
            if current is not None:
                retired = _invalidate_latest_record_locked_v3(binding, current)
            missing = True
        elif current.engine_ref is None or current.engine_ref() is not engine:
            _binding_reject_v3("binding was not issued")
        else:
            return current, _decode_issued_material_v3(current.material_bytes)
    if retired is not None:
        _retire_record_admission_v3(retired)
    if missing:
        engine._binding_mismatch_cleanup_v3()
    _binding_reject_v3("binding was not issued")


def _serving_admission_capability_v3(
    engine: "BootTransitionEngineV3",
) -> ServingAdmissionCapabilityV3:
    record, _material = _verified_engine_record_v3(engine)
    binding = engine._binding_liveness_anchor
    generation = record.generation
    retired: _IssuedBindingRecordV3 | None = None
    with _ISSUED_BOOT_BINDINGS_V3.lock:
        current = _record_for_use_locked_v3(binding)
        if not _record_engine_matches_v3(current, binding, generation, engine):
            if current is not None:
                retired = _invalidate_latest_record_locked_v3(binding, current)
            capability = None
        else:
            capability = current.admission_capability
        if capability is None and retired is None and current is not None:
            capability = ServingAdmissionCapabilityV3(binding, generation, engine)
            _transition_current_record_locked_v3(
                binding,
                current,
                engine_claimed=current.engine_claimed,
                engine_ref=current.engine_ref,
                admission_capability=capability,
                admitted_wrapper_ref=current.admitted_wrapper_ref,
            )
    if retired is not None:
        _retire_record_admission_v3(retired)
    if capability is None:
        engine._binding_mismatch_cleanup_v3()
        _binding_reject_v3("binding was not issued")
    return capability


def _claim_serving_wrapper_construction_v3(
    capability: object, wrapper: ServingAuthorityWrapperV3
) -> BootBindingV3:
    if type(capability) is not ServingAdmissionCapabilityV3:
        raise TypeError("serving authority construction is private")
    binding = capability.binding_ref()
    engine = capability.engine_ref()
    if binding is None or engine is None:
        raise TypeError("serving authority construction is private")
    thread_id = threading.get_ident()
    with capability.condition:
        retired_owner = (
            capability.retired
            and capability.phase == "retired"
            and capability.retired_construction_owner_thread_id == thread_id
        )
        active_owner = (
            not capability.retired
            and capability.phase == "constructing"
            and capability.owner_thread_id == thread_id
            and capability.constructing_wrapper_ref is None
        )
    if retired_owner:
        _binding_reject_v3("binding was not issued")
    if not active_owner:
        raise TypeError("serving authority construction is private")
    try:
        engine._verify_v3()
    except ApplianceErrorV3:
        # active_owner was established under the capability condition before
        # verification.  Preserve that entitlement while registry retirement
        # publishes its capability metadata outside the registry lock.
        raise
    retired: _IssuedBindingRecordV3 | None = None
    foreign_capability = False
    with _ISSUED_BOOT_BINDINGS_V3.lock:
        record = _record_for_use_locked_v3(binding)
        valid_engine = _record_engine_matches_v3(
            record, binding, capability.generation, engine
        )
        valid_capability = valid_engine and record.admission_capability is capability
        foreign_capability = valid_engine and not valid_capability
        if not valid_engine and record is not None:
            retired = _invalidate_latest_record_locked_v3(binding, record)
    if retired is not None:
        _retire_record_admission_v3(retired)
    if not valid_capability:
        if foreign_capability:
            raise TypeError("serving authority construction is private")
        _binding_reject_v3("binding was not issued")
    with capability.condition:
        if (
            capability.retired
            and capability.phase == "retired"
            and capability.retired_construction_owner_thread_id == thread_id
        ):
            _binding_reject_v3("binding was not issued")
        if (
            capability.retired
            or capability.phase != "constructing"
            or capability.owner_thread_id != threading.get_ident()
            or capability.constructing_wrapper_ref is not None
        ):
            raise TypeError("serving authority construction is private")
        capability.constructing_wrapper_ref = weakref.ref(wrapper)
    return binding


def _abandon_serving_wrapper_construction_v3(
    capability: ServingAdmissionCapabilityV3,
    wrapper: ServingAuthorityWrapperV3 | None,
) -> None:
    binding = capability.binding_ref()
    engine = capability.engine_ref()
    thread_id = threading.get_ident()
    retired: _IssuedBindingRecordV3 | None = None
    with _ISSUED_BOOT_BINDINGS_V3.lock:
        current = (
            _record_for_use_locked_v3(binding)
            if type(binding) is BootBindingV3
            else None
        )
        if (
            type(binding) is BootBindingV3
            and _record_shadowed_by_live_tombstone_locked_v3(current, binding)
        ):
            retired = _invalidate_latest_record_locked_v3(binding, current)
            current = None
        current_capability = (
            type(binding) is BootBindingV3
            and type(engine) is BootTransitionEngineV3
            and _record_engine_matches_v3(
                current, binding, capability.generation, engine
            )
            and current.admission_capability is capability
        )
        with capability.condition:
            if capability.retired_construction_owner_thread_id == thread_id:
                capability.retired_construction_owner_thread_id = None
            if (
                capability.constructing_wrapper_ref is not None
                and capability.constructing_wrapper_ref() is wrapper
            ):
                capability.constructing_wrapper_ref = None
            if capability.phase == "constructing" and capability.owner_thread_id == thread_id:
                capability.phase = "failed" if current_capability else "retired"
                capability.retired = not current_capability
                capability.owner_thread_id = None
                if current_capability:
                    _transition_current_record_locked_v3(
                        binding,
                        current,
                        engine_claimed=current.engine_claimed,
                        engine_ref=current.engine_ref,
                        admission_capability=None,
                        admitted_wrapper_ref=current.admitted_wrapper_ref,
                    )
                capability.condition.notify_all()
    if retired is not None:
        _retire_record_admission_v3(retired)


def _verify_serving_wrapper_v3(
    capability: object, wrapper: ServingAuthorityWrapperV3, *, allow_complete: bool = False
) -> None:
    if type(capability) is not ServingAdmissionCapabilityV3:
        _binding_reject_v3("serving admission capability is invalid")
    binding = capability.binding_ref()
    if binding is None:
        _binding_reject_v3("serving admission capability is stale")
    with capability.condition:
        published_wrapper = (
            None
            if capability.published_wrapper_ref is None
            else capability.published_wrapper_ref()
        )
        terminal_wrapper_identity = (
            published_wrapper is wrapper
        )
    if wrapper._terminal_binding_mismatch_v3():
        # A saved, still-sealed record may have been replayed after the
        # terminal mismatch.  Consult the binding registry before reporting
        # the durable cause so its live tombstone also retires that replay.
        # Copied terminal state only selects this fail-closed error; it does
        # not grant clones the exact wrapper's cleanup or registry authority.
        if terminal_wrapper_identity:
            _binding_record_v3(binding)
        _binding_reject_v3("binding was not issued")
    with _ISSUED_BOOT_BINDINGS_V3.lock:
        canonical = _current_high_water_record_locked_v3(binding)
        canonical_capability = (
            canonical is not None
            and canonical.generation == capability.generation
            and canonical.admission_capability is capability
            and canonical.admitted_wrapper_ref is not None
            and canonical.admitted_wrapper_ref() is published_wrapper
            and published_wrapper is not None
        )
    if canonical_capability and _binding_record_v3(binding) is None:
        # Registry loss is binding authority loss even after the weak engine
        # has died.  The authenticated current record carries the exact
        # published wrapper used for cleanup; clones only share the promoted
        # fail-closed cause and receive no cleanup or serving authority.
        published_wrapper._binding_mismatch_cleanup_v3()
        _binding_reject_v3("binding was not issued")
    engine = capability.engine_ref()
    if engine is None:
        _binding_reject_v3("serving admission capability is stale")
    engine._verify_v3()
    retired: _IssuedBindingRecordV3 | None = None
    invalid = False
    tombstone_rejection = False
    with _ISSUED_BOOT_BINDINGS_V3.lock:
        record = _record_for_use_locked_v3(binding)
        if (
            not _record_engine_matches_v3(
                record, binding, capability.generation, engine
            )
            or record.admission_capability is not capability
        ):
            invalid = True
            tombstone_rejection = _record_shadowed_by_live_tombstone_locked_v3(
                record, binding
            )
            if record is not None and (
                not _valid_record_integrity_v3(record)
                or tombstone_rejection
                or not _record_matches_transition_high_water_locked_v3(
                    record, binding
                )
            ):
                retired = _invalidate_latest_record_locked_v3(binding, record)
            admitted_wrapper_matches = False
        else:
            admitted_wrapper_matches = (
                record.admitted_wrapper_ref is not None
                and record.admitted_wrapper_ref() is wrapper
            )
    if retired is not None:
        _retire_record_admission_v3(retired)
    if invalid:
        if tombstone_rejection:
            _binding_reject_v3("binding was not issued")
        _binding_reject_v3("serving admission capability is foreign")
    with capability.condition:
        constructing = (
            capability.phase == "constructing"
            and capability.constructing_wrapper_ref is not None
            and capability.constructing_wrapper_ref() is wrapper
        )
        published = (
            admitted_wrapper_matches
            and
            capability.phase == "admitted"
            and capability.published_wrapper_ref is not None
            and capability.published_wrapper_ref() is wrapper
        )
        completed = (
            allow_complete
            and admitted_wrapper_matches
            and capability.phase == "retired"
            and capability.published_wrapper_ref is not None
            and capability.published_wrapper_ref() is wrapper
        )
        if not (constructing or published or completed):
            _binding_reject_v3("binding was not issued")


def _retire_serving_admission_v3(
    capability: ServingAdmissionCapabilityV3, wrapper: ServingAuthorityWrapperV3
) -> None:
    with capability.condition:
        if capability.published_wrapper_ref is not None and capability.published_wrapper_ref() is wrapper:
            capability.phase = "retired"
            capability.retired = True
            capability.owner_thread_id = None
            capability.condition.notify_all()
        elif capability.constructing_wrapper_ref is not None and capability.constructing_wrapper_ref() is wrapper:
            capability.phase = "retired"
            capability.retired = True
            capability.owner_thread_id = None
            capability.condition.notify_all()


def _return_admitted_wrapper_v3(
    engine: "BootTransitionEngineV3",
    capability: ServingAdmissionCapabilityV3,
) -> ServingAuthorityWrapperV3 | None:
    binding = engine._binding_liveness_anchor
    retired: _IssuedBindingRecordV3 | None = None
    invalid = False
    wrapper: ServingAuthorityWrapperV3 | None = None
    with _ISSUED_BOOT_BINDINGS_V3.lock:
        record = _record_for_use_locked_v3(binding)
        if not (
            _record_engine_matches_v3(
                record, binding, capability.generation, engine
            )
            and record.admission_capability is capability
        ):
            invalid = True
            if record is not None and (
                not _valid_record_integrity_v3(record)
                or _record_shadowed_by_live_tombstone_locked_v3(record, binding)
                or not _record_matches_transition_high_water_locked_v3(
                    record, binding
                )
            ):
                retired = _invalidate_latest_record_locked_v3(binding, record)
        else:
            with capability.condition:
                if capability.phase == "failed":
                    return None
                if capability.retired or capability.phase == "retired":
                    invalid = True
                elif (
                    capability.phase != "admitted"
                    or capability.published_wrapper_ref is None
                    or record.admitted_wrapper_ref is None
                ):
                    invalid = True
                else:
                    wrapper = capability.published_wrapper_ref()
                    if wrapper is None or record.admitted_wrapper_ref() is not wrapper:
                        invalid = True
                    else:
                        engine._serving_authority = wrapper
    if retired is not None:
        _retire_record_admission_v3(retired)
    if invalid or wrapper is None:
        engine._binding_mismatch_cleanup_v3()
        _binding_reject_v3("binding was not issued")
    return wrapper


def _publish_serving_wrapper_v3(
    engine: "BootTransitionEngineV3",
    capability: ServingAdmissionCapabilityV3,
    wrapper: ServingAuthorityWrapperV3,
) -> ServingAuthorityWrapperV3:
    binding = engine._binding_liveness_anchor
    retired: _IssuedBindingRecordV3 | None = None
    published = False
    with _ISSUED_BOOT_BINDINGS_V3.lock:
        record = _record_for_use_locked_v3(binding)
        valid_record = (
            _record_engine_matches_v3(
                record, binding, capability.generation, engine
            )
            and record.admission_capability is capability
        )
        if not valid_record:
            if record is not None and (
                not _valid_record_integrity_v3(record)
                or _record_shadowed_by_live_tombstone_locked_v3(record, binding)
                or not _record_matches_transition_high_water_locked_v3(
                    record, binding
                )
            ):
                retired = _invalidate_latest_record_locked_v3(binding, record)
        else:
            with capability.condition:
                if (
                    not capability.retired
                    and capability.phase == "constructing"
                    and capability.owner_thread_id == threading.get_ident()
                    and capability.constructing_wrapper_ref is not None
                    and capability.constructing_wrapper_ref() is wrapper
                ):
                    wrapper_ref = weakref.ref(wrapper)
                    _transition_current_record_locked_v3(
                        binding,
                        record,
                        engine_claimed=record.engine_claimed,
                        engine_ref=record.engine_ref,
                        admission_capability=capability,
                        admitted_wrapper_ref=wrapper_ref,
                    )
                    engine._serving_authority = wrapper
                    capability.published_wrapper_ref = wrapper_ref
                    capability.phase = "admitted"
                    capability.owner_thread_id = None
                    capability.condition.notify_all()
                    published = True
    if retired is not None:
        _retire_record_admission_v3(retired)
    if not published:
        _binding_reject_v3("binding was not issued")
    return wrapper


class BootTransitionEngineV3:
    """The sealed v3 causal chain and its PCR-15 authority calculation."""

    def __init__(self, binding: BootBindingV3) -> None:
        self._binding_liveness_anchor = binding
        _claim_engine_v3(binding, self)
        self._state = BootTransitionStateV3.PID1_IDENTITY_ESTABLISHED
        self._pending: AuthorityStepEffectV3 | None = None
        self._extend_transport: BootTransport | None = None
        self._extend_request_issued = False
        self._serving_effect_completed = False
        self._serving_authority: ServingAuthorityWrapperV3 | None = None
        self._failure_diagnostic_token: str | None = None

    def _binding_mismatch_cleanup_v3(self) -> None:
        wrapper = getattr(self, "_serving_authority", None)
        if type(wrapper) is ServingAuthorityWrapperV3:
            wrapper._binding_mismatch_cleanup_v3()

    def _verify_v3(self) -> _OperationMaterialV3:
        _record, material = _verified_engine_record_v3(self)
        return material

    @property
    def state(self) -> "BootTransitionStateV3":
        self._verify_v3()
        return self._state

    @property
    def failure_diagnostic_token(self) -> str | None:
        self._verify_v3()
        return self._failure_diagnostic_token

    @property
    def contract_sha256(self) -> str:
        return self._verify_v3().contract_sha256

    @property
    def pcr15_measurement_v3(self) -> bytes:
        return self._verify_v3().pcr15_measurement

    @property
    def predicted_pcr15_v3(self) -> bytes:
        return self._verify_v3().predicted_pcr15

    def next_effect(self) -> AuthorityStepEffectV3 | None:
        material = self._verify_v3()
        if self._pending is not None:
            return self._pending
        if self._state is BootTransitionStateV3.FAILED_NON_SERVING:
            return None
        if self._state is BootTransitionStateV3.SERVING_AVAILABLE and self._serving_effect_completed:
            return None
        step = _STEP_BY_STATE_V3[self._state]
        if self._state is BootTransitionStateV3.PCR15_EXTENDED:
            if not _claim_extend_transport():
                self._fail(CP_BOOT_V3_LATCH, "a PCR15 extend transport was already claimed for this process")
            self._extend_request_issued = True
            expected: object = material.pcr15_measurement
        else:
            expected = step.expected
        self._pending = AuthorityStepEffectV3(
            material.contract_sha256, self._state, step.action, expected
        )
        return self._pending

    def advance(self, transport: BootTransport) -> BootTransitionStateV3:
        self._verify_v3()
        effect = self.next_effect()
        if effect is None:
            self._fail(_reason_for_state_v3(self._state), "v3 boot transition has no further normal effect")
        if self._state is BootTransitionStateV3.PCR15_EXTENDED:
            if self._extend_transport is None:
                self._extend_transport = transport
            elif transport is not self._extend_transport:
                self._pending = None
                self._fail(CP_BOOT_V3_LATCH, "PCR15 extend requires its claimed transport")
        elif self._state is BootTransitionStateV3.TPM_BOOT_TRANSPORT_CLOSED and transport is not self._extend_transport:
            self._pending = None
            self._fail(CP_BOOT_V3_LATCH, "PCR15 transport closure requires the claimed transport")
        try:
            observation = transport.execute(effect)
        except Exception:
            if self._state is BootTransitionStateV3.PCR15_EXTENDED:
                return self.accept(
                    AuthorityStepReadbackV3(
                        self.contract_sha256,
                        self._state,
                        effect.action,
                        Pcr15ExtendOutcome.ERROR,
                    )
                )
            self._pending = None
            self._fail(_reason_for_state_v3(self._state), "typed v3 boot transport failed")
        return self.accept(observation)

    def accept(self, observation: BootObservation) -> BootTransitionStateV3:
        """Accept one typed step readback for deterministic reducer tests."""

        material = self._verify_v3()
        state = self._state
        step = _STEP_BY_STATE_V3.get(state)
        if step is None:
            self._fail(_reason_for_state_v3(state), "v3 observation is unavailable in this state")
        effect = self._pending
        if (
            effect is None
            or type(observation) is not AuthorityStepReadbackV3
            or observation.contract_sha256 != material.contract_sha256
            or observation.state is not state
            or observation.action != step.action
            or observation.accepted is not True
        ):
            self._fail(_reason_for_state_v3(state), "v3 observation is stale, unordered, or malformed")
        self._pending = None
        if state is BootTransitionStateV3.PCR15_EXTENDED:
            if not self._extend_request_issued or self._extend_transport is None or type(observation.observed) is not Pcr15ExtendOutcome:
                self._fail(CP_BOOT_V3_LATCH, "v3 PCR extend has no shared-latch transport")
            _record_extend_outcome(observation.observed)
        elif state is BootTransitionStateV3.TPM_BOOT_TRANSPORT_CLOSED:
            if self._extend_transport is None:
                self._fail(CP_BOOT_V3_LATCH, "v3 PCR transport closure has no claimed transport")
            if observation.observed is None:
                self._fail(CP_BOOT_V3_LATCH, "v3 PCR transport closure readback is invalid")
            _record_extend_transport_closed()
            self._extend_transport = None
        elif step.expected is None:
            if observation.observed is None:
                self._fail(_reason_for_state_v3(state), "v3 step observation is absent")
        elif observation.observed != step.expected:
            self._fail(_reason_for_state_v3(state), "v3 step observation disagrees with authority")
        self._state = _NEXT_STATE_V3[state]
        if state is BootTransitionStateV3.SERVING_AVAILABLE:
            self._serving_effect_completed = True
        return self._state

    def _fail(self, reason_code: str, message: str) -> None:
        if self._state is not BootTransitionStateV3.FAILED_NON_SERVING:
            self._failure_diagnostic_token = DIAGNOSTIC_TOKEN_FOR_STATE_V3[self._state]
            self._state = BootTransitionStateV3.FAILED_NON_SERVING
        self._pending = None
        raise ApplianceErrorV3(reason_code, message)

    def admit_serving_authority(self) -> ServingAuthorityWrapperV3:
        self._verify_v3()
        if self._state is not BootTransitionStateV3.SERVING_AVAILABLE:
            if type(self._serving_authority) is ServingAuthorityWrapperV3:
                _binding_reject_v3("binding was not issued")
            self._fail(
                CP_BOOT_V3_LAUNCH_SUPERVISION,
                "v3 serving authority is not available before SERVING_AVAILABLE",
            )
        while True:
            capability = _serving_admission_capability_v3(self)
            retry = False
            wait = False
            admitted = False
            with capability.condition:
                if capability.phase == "failed":
                    retry = True
                elif capability.retired or capability.phase == "retired":
                    _binding_reject_v3("binding was not issued")
                elif capability.phase == "admitted":
                    admitted = True
                elif capability.phase == "constructing":
                    capability.condition.wait()
                    wait = True
                elif capability.phase != "none":
                    _binding_reject_v3("serving admission capability is invalid")
                else:
                    capability.phase = "constructing"
                    capability.owner_thread_id = threading.get_ident()
                    capability.retired_construction_owner_thread_id = None
                    capability.constructing_wrapper_ref = None
                    break
            if admitted:
                wrapper = _return_admitted_wrapper_v3(self, capability)
                if wrapper is not None:
                    return wrapper
            if wait:
                self._verify_v3()
            if retry or wait:
                continue
        try:
            wrapper = object.__new__(ServingAuthorityWrapperV3)
            ServingAuthorityWrapperV3.__init__(
                wrapper,
                admission_capability=capability,
                on_global_fault=self._on_wrapper_global_fault,
            )
            self._verify_v3()
            return _publish_serving_wrapper_v3(self, capability, wrapper)
        except BaseException:
            constructed_wrapper = locals().get("wrapper")
            if (
                type(constructed_wrapper) is ServingAuthorityWrapperV3
                and hasattr(constructed_wrapper, "_construction_condition")
            ):
                constructed_wrapper._discard_unpublished_construction_v3()
            _abandon_serving_wrapper_construction_v3(capability, constructed_wrapper)
            raise

    def _on_wrapper_global_fault(self) -> None:
        self._verify_v3()
        if self._state is BootTransitionStateV3.FAILED_NON_SERVING:
            return
        try:
            self._fail(
                CP_BOOT_V3_LAUNCH_SUPERVISION,
                "v3 serving authority reported a global fault",
            )
        except ApplianceErrorV3:
            # The wrapper must continue directly to resource revocation after
            # the outer engine enters its terminal failure state.
            return


class BootTransitionStateV3(Enum):
    PID1_IDENTITY_ESTABLISHED = "pid1_identity_established"
    ADAPTER_CONSTRUCTED = "adapter_constructed"
    BOOTSTRAP_MOUNTED = "bootstrap_mounted"
    NETWORK_PREFLIGHT_STARTED = "network_preflight_started"
    NIC_CENSUS_ESTABLISHED = "nic_census_established"
    EARLY_MODULES_LOADED = "early_modules_loaded"
    NIC_CENSUS_REVALIDATED = "nic_census_revalidated"
    NETWORK_DENY_INSTALLED = "network_deny_installed"
    CMDLINE_SEALED = "cmdline_sealed"
    PCR15_ZERO_CONFIRMED = "pcr15_zero_confirmed"
    DISK_IDENTIFIED = "disk_identified"
    ROOT_MODEL_VERITY_MAPPED = "root_model_verity_mapped"
    ROOT_MODEL_MOUNTED = "root_model_mounted"
    C1_CENSUS_ESTABLISHED = "c1_census_established"
    FINAL_RUN_CREATED = "final_run_created"
    C2_CENSUS_ESTABLISHED = "c2_census_established"
    LATER_MODULES_LOADED = "later_modules_loaded"
    MODULES_DISABLED = "modules_disabled"
    MUTABLE_CONTROLS_ENFORCED = "mutable_controls_enforced"
    PCR15_EXTENDED = "pcr15_extended"
    TPM_BOOT_TRANSPORT_CLOSED = "tpm_boot_transport_closed"
    DEVICE_MONITOR_SEALED = "device_monitor_sealed"
    DEV_TREE_PRUNED = "dev_tree_pruned"
    DEVICE_MONITOR_RECONCILED = "device_monitor_reconciled"
    SECURITYFS_UNMOUNTED = "securityfs_unmounted"
    KERNEL_INTERFACES_MOVED = "kernel_interfaces_moved"
    C3_CENSUS_ESTABLISHED = "c3_census_established"
    HANDOFF_SEALED = "handoff_sealed"
    SWITCH_ROOT_COMPLETED = "switch_root_completed"
    STAGE2_ADMITTED = "stage2_admitted"
    POST_ROOT_RUNTIME_SEALED = "post_root_runtime_sealed"
    LAUNCH_SUPERVISION_READY = "launch_supervision_ready"
    SERVING_AVAILABLE = "serving_available"
    FAILED_NON_SERVING = "failed_non_serving"


@dataclass(frozen=True)
class AuthorityStepEffectV3(BootEffect):
    state: BootTransitionStateV3
    action: str
    expected: object


@dataclass(frozen=True)
class AuthorityStepReadbackV3(BootObservation):
    state: BootTransitionStateV3
    action: str
    observed: object
    accepted: bool = True


@dataclass(frozen=True)
class _StepSpecV3:
    state: BootTransitionStateV3
    action: str
    expected: object


_NETWORK_CENSUS_REQUIREMENTS_V3: Final = (
    "interfaces_down",
    "interfaces_unaddressed",
    "interfaces_unrouted",
    "listener_count=0",
    "af_packet_count=0",
    "monitor_family=AF_NETLINK",
    "monitor_protocol=NETLINK_ROUTE",
)
_NORMAL_STATES_V3: Final = tuple(
    state for state in BootTransitionStateV3 if state is not BootTransitionStateV3.FAILED_NON_SERVING
)
_EARLY_MODULE_EXPECTED_V3: Final = (
    tables.EARLY_MODULE_ROWS_V3,
    tables.EARLY_MODULE_TARGET_KERNEL_RELEASE_V3,
    tables.EARLY_MODULE_TARGET_CONFIG_SHA256_V3,
    tables.EARLY_MODULE_SIGNER_V3,
    tables.EARLY_MODULE_SIGNATURE_KEY_ID_V3,
    tables.EARLY_MODULE_RELEASE_ROOT_V3,
    tables.EARLY_MODULE_BUILTIN_DEPENDENCIES_V3,
)
_DEV_TREE_EXPECTED_V3: Final = (
    tables.DEV_TREE_DIRECTORY_ROWS_V3,
    tables.DEV_TREE_ROWS_V3,
    tables.DEV_TREE_FORBIDDEN_PATH_PATTERNS_V3,
    tables.DEV_TREE_FORBIDDEN_NODE_KINDS_V3,
)
_STEP_EXPECTED_V3: Final = {
    BootTransitionStateV3.BOOTSTRAP_MOUNTED: tables.BOOTSTRAP_MOUNTS_V3,
    BootTransitionStateV3.NETWORK_PREFLIGHT_STARTED: _NETWORK_CENSUS_REQUIREMENTS_V3,
    BootTransitionStateV3.NIC_CENSUS_ESTABLISHED: _NETWORK_CENSUS_REQUIREMENTS_V3,
    BootTransitionStateV3.EARLY_MODULES_LOADED: _EARLY_MODULE_EXPECTED_V3,
    BootTransitionStateV3.NIC_CENSUS_REVALIDATED: _NETWORK_CENSUS_REQUIREMENTS_V3,
    BootTransitionStateV3.NETWORK_DENY_INSTALLED: _NETWORK_CENSUS_REQUIREMENTS_V3,
    BootTransitionStateV3.PCR15_ZERO_CONFIRMED: b"\0" * 32,
    BootTransitionStateV3.MUTABLE_CONTROLS_ENFORCED: tables.CONTROL_INVENTORY_ROWS_V3,
    BootTransitionStateV3.DEV_TREE_PRUNED: _DEV_TREE_EXPECTED_V3,
    BootTransitionStateV3.LAUNCH_SUPERVISION_READY: tables.LAUNCH_ROLE_ROWS_V3,
    BootTransitionStateV3.SERVING_AVAILABLE: tables.LAUNCH_ROLE_ROWS_V3,
}
BOOT_TRANSITION_STEPS_V3: Final = tuple(
    _StepSpecV3(state, state.value, _STEP_EXPECTED_V3.get(state)) for state in _NORMAL_STATES_V3
)
_STEP_BY_STATE_V3: Final = {step.state: step for step in BOOT_TRANSITION_STEPS_V3}
_NEXT_STATE_V3: Final = {
    state: _NORMAL_STATES_V3[index + 1]
    for index, state in enumerate(_NORMAL_STATES_V3[:-1])
}
_NEXT_STATE_V3[BootTransitionStateV3.SERVING_AVAILABLE] = BootTransitionStateV3.SERVING_AVAILABLE
STATE_EFFECT_POSTCONDITIONS_V3: Final = tuple(
    StateEffectPostcondition(step.state, "AuthorityStepEffectV3", step.action)
    for step in BOOT_TRANSITION_STEPS_V3
)

DIAGNOSTIC_TOKEN_FOR_STATE_V3: Final = {
    BootTransitionStateV3.PID1_IDENTITY_ESTABLISHED: "pid1",
    BootTransitionStateV3.ADAPTER_CONSTRUCTED: "adapter",
    BootTransitionStateV3.BOOTSTRAP_MOUNTED: "runtime_authority",
    BootTransitionStateV3.NETWORK_PREFLIGHT_STARTED: "runtime_authority",
    BootTransitionStateV3.NIC_CENSUS_ESTABLISHED: "runtime_authority",
    BootTransitionStateV3.EARLY_MODULES_LOADED: "runtime_authority",
    BootTransitionStateV3.NIC_CENSUS_REVALIDATED: "runtime_authority",
    BootTransitionStateV3.NETWORK_DENY_INSTALLED: "runtime_authority",
    BootTransitionStateV3.CMDLINE_SEALED: "runtime_authority",
    BootTransitionStateV3.PCR15_ZERO_CONFIRMED: "runtime_authority",
    BootTransitionStateV3.DISK_IDENTIFIED: "runtime_authority",
    BootTransitionStateV3.ROOT_MODEL_VERITY_MAPPED: "root_transition",
    BootTransitionStateV3.ROOT_MODEL_MOUNTED: "root_transition",
    BootTransitionStateV3.C1_CENSUS_ESTABLISHED: "root_transition",
    BootTransitionStateV3.FINAL_RUN_CREATED: "root_transition",
    BootTransitionStateV3.C2_CENSUS_ESTABLISHED: "root_transition",
    BootTransitionStateV3.LATER_MODULES_LOADED: "root_transition",
    BootTransitionStateV3.MODULES_DISABLED: "root_transition",
    BootTransitionStateV3.MUTABLE_CONTROLS_ENFORCED: "root_transition",
    BootTransitionStateV3.PCR15_EXTENDED: "root_transition",
    BootTransitionStateV3.TPM_BOOT_TRANSPORT_CLOSED: "root_transition",
    BootTransitionStateV3.DEVICE_MONITOR_SEALED: "root_transition",
    BootTransitionStateV3.DEV_TREE_PRUNED: "root_transition",
    BootTransitionStateV3.DEVICE_MONITOR_RECONCILED: "root_transition",
    BootTransitionStateV3.SECURITYFS_UNMOUNTED: "root_transition",
    BootTransitionStateV3.KERNEL_INTERFACES_MOVED: "root_transition",
    BootTransitionStateV3.C3_CENSUS_ESTABLISHED: "root_transition",
    BootTransitionStateV3.HANDOFF_SEALED: "root_transition",
    BootTransitionStateV3.SWITCH_ROOT_COMPLETED: "root_transition",
    BootTransitionStateV3.STAGE2_ADMITTED: "root_transition",
    BootTransitionStateV3.POST_ROOT_RUNTIME_SEALED: "runtime_authority",
    BootTransitionStateV3.LAUNCH_SUPERVISION_READY: "serving_integrity",
    BootTransitionStateV3.SERVING_AVAILABLE: "serving_integrity",
}
assert set(DIAGNOSTIC_TOKEN_FOR_STATE_V3) == set(_NORMAL_STATES_V3)
assert set(DIAGNOSTIC_TOKEN_FOR_STATE_V3.values()) <= set(tables.FAILURE_DIAGNOSTIC_TOKENS_V3)


def _reason_for_state_v3(state: BootTransitionStateV3) -> str:
    if state in (
        BootTransitionStateV3.PID1_IDENTITY_ESTABLISHED,
        BootTransitionStateV3.ADAPTER_CONSTRUCTED,
    ):
        return CP_BOOT_V3_PID1_IDENTITY
    if state in (
        BootTransitionStateV3.BOOTSTRAP_MOUNTED,
        BootTransitionStateV3.C1_CENSUS_ESTABLISHED,
        BootTransitionStateV3.FINAL_RUN_CREATED,
        BootTransitionStateV3.C2_CENSUS_ESTABLISHED,
        BootTransitionStateV3.C3_CENSUS_ESTABLISHED,
    ):
        return CP_BOOT_V3_MOUNT_CENSUS
    if state in (
        BootTransitionStateV3.NETWORK_PREFLIGHT_STARTED,
        BootTransitionStateV3.NIC_CENSUS_ESTABLISHED,
        BootTransitionStateV3.NIC_CENSUS_REVALIDATED,
        BootTransitionStateV3.NETWORK_DENY_INSTALLED,
    ):
        return CP_BOOT_V3_NETWORK_POLICY
    if state in (
        BootTransitionStateV3.EARLY_MODULES_LOADED,
        BootTransitionStateV3.LATER_MODULES_LOADED,
    ):
        return CP_BOOT_V3_MODULE_AUTHORITY
    if state in (
        BootTransitionStateV3.PCR15_ZERO_CONFIRMED,
        BootTransitionStateV3.PCR15_EXTENDED,
    ):
        return CP_BOOT_V3_PCR
    if state is BootTransitionStateV3.TPM_BOOT_TRANSPORT_CLOSED:
        return CP_BOOT_V3_LATCH
    if state in (
        BootTransitionStateV3.MUTABLE_CONTROLS_ENFORCED,
        BootTransitionStateV3.MODULES_DISABLED,
        BootTransitionStateV3.SECURITYFS_UNMOUNTED,
        BootTransitionStateV3.KERNEL_INTERFACES_MOVED,
        BootTransitionStateV3.POST_ROOT_RUNTIME_SEALED,
    ):
        return CP_BOOT_V3_CONTROL
    if state is BootTransitionStateV3.DEV_TREE_PRUNED:
        return CP_BOOT_V3_DEV_TREE
    if state in (
        BootTransitionStateV3.DEVICE_MONITOR_SEALED,
        BootTransitionStateV3.DEVICE_MONITOR_RECONCILED,
    ):
        return CP_BOOT_V3_DEVICE_MONITOR
    if state in (
        BootTransitionStateV3.LAUNCH_SUPERVISION_READY,
        BootTransitionStateV3.SERVING_AVAILABLE,
    ):
        return CP_BOOT_V3_LAUNCH_SUPERVISION
    return CP_BOOT_V3_ROOT_TRANSITION


class FailureStageV3(Enum):
    DIAGNOSTIC = "diagnostic"
    CLOSE_SERVING_NETWORK = "close_serving_network"
    POWEROFF_REQUESTED = "poweroff_requested"
    FAIL_STOP = "fail_stop"


assert tuple(stage.value for stage in FailureStageV3) == tables.FAILURE_STAGES_V3


class PoweroffAckedV3(BaseException):
    """Harness-only sentinel for a non-returning poweroff dispatch."""


@dataclass(frozen=True)
class FailureControllerEffectV3(BootEffect):
    action: str


@dataclass(frozen=True)
class FailureControllerReadbackV3(BootObservation):
    action: str
    confirmed: bool


class FailureControllerV3:
    """Fail-closed diagnostic, bounded closure, and poweroff controller."""

    def __init__(self, diagnostic_token: str) -> None:
        if diagnostic_token not in tables.FAILURE_DIAGNOSTIC_TOKENS_V3:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "unknown diagnostic token")
        self.diagnostic_token = diagnostic_token
        self.stage = FailureStageV3.DIAGNOSTIC
        self._diagnostic_rendered = False
        self._network_close_attempts = 0
        self._network_close_confirmed = False
        self._poweroff_requested = False
        self.late_code: str | None = None

    def _set_late_code(self, code: str) -> None:
        if not self._diagnostic_rendered:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "late code precedes diagnostic")
        if code not in tables.FAILURE_LATE_CODES_V3:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "unknown late failure code")
        self.late_code = code

    def render_diagnostic(self) -> str:
        if self.stage is not FailureStageV3.DIAGNOSTIC or self._diagnostic_rendered:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "diagnostic is unavailable")
        self._diagnostic_rendered = True
        self.stage = FailureStageV3.CLOSE_SERVING_NETWORK
        return f"conf-proc-spp-boot-v3: {self.diagnostic_token}"

    @staticmethod
    def _confirmed_readback(observation: object, action: str) -> bool:
        return (
            type(observation) is FailureControllerReadbackV3
            and observation.contract_sha256 == "failure-controller/v3"
            and observation.action == action
            and observation.confirmed is True
        )

    def _best_effort(self, transport: BootTransport, action: str) -> bool:
        try:
            observation = transport.execute(FailureControllerEffectV3("failure-controller/v3", action))
        except BaseException:
            return False
        return self._confirmed_readback(observation, action)

    def attempt_network_close(self, transport: BootTransport) -> bool:
        if self.stage is not FailureStageV3.CLOSE_SERVING_NETWORK:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "network close is unavailable")
        if self._network_close_attempts >= 3:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "network close attempts are exhausted")
        self._network_close_attempts += 1
        confirmed = self._best_effort(transport, "close_serving_network")
        self._network_close_confirmed = self._network_close_confirmed or confirmed
        if not confirmed:
            self._set_late_code("network_close")
        if self._network_close_attempts == 3:
            self.stage = FailureStageV3.POWEROFF_REQUESTED
        return confirmed

    def _dispatch_poweroff_attempt(self, transport: BootTransport) -> None:
        self._poweroff_requested = True
        try:
            transport.execute(FailureControllerEffectV3("failure-controller/v3", "poweroff"))
        except PoweroffAckedV3:
            raise
        except BaseException:
            self._set_late_code("poweroff_returned")
            self.stage = FailureStageV3.FAIL_STOP
            return
        self._set_late_code("poweroff_returned")
        self.stage = FailureStageV3.FAIL_STOP

    def dispatch_poweroff(self, transport: BootTransport) -> None:
        if self.stage is not FailureStageV3.POWEROFF_REQUESTED:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "poweroff dispatch is unavailable")
        self._dispatch_poweroff_attempt(transport)

    def fail_stop_cycle(
        self,
        *,
        close_transport: BootTransport,
        deny_all_transport: BootTransport,
        poweroff_transport: BootTransport,
    ) -> None:
        if self.stage is not FailureStageV3.FAIL_STOP:
            raise ApplianceErrorV3(CP_BOOT_V3_FAILURE_PROTOCOL, "fail-stop cycle is unavailable")
        self._best_effort(close_transport, "close_serving_network")
        self._best_effort(deny_all_transport, "deny_all")
        self._dispatch_poweroff_attempt(poweroff_transport)
        self.stage = FailureStageV3.FAIL_STOP
