#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fail-closed SPP boot-transition authority binding and reducer.

This module is deliberately an authority consumer, not a boot adapter.  Its
only side-effect boundary is ``BootTransport.execute(effect)``; the transport
can produce typed observations but has no general host, service, network, or
TPM interface.
"""

from __future__ import annotations

import hashlib
import posixpath
import threading
import uuid
import weakref
from dataclasses import dataclass
from enum import Enum
from typing import Final, Protocol

from conf_proc_geometry import derive_build_epoch, derive_verity_salt, derive_verity_uuid
from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_lock import Lock, ROLE_KERNEL_TRUSTED_CERT_BUNDLE, parse_lock
from conf_proc_module_authority import check_authorized_signers_match_bundle
from conf_proc_policy import Policy, parse_policy
from conf_proc_provenance_v2 import (
    ProvenanceInputs,
    derive_inputs,
    parse_runtime_closure,
    parse_tcb_identity,
    parse_verity_rules,
)
from conf_proc_provenance_v2_manifest import ProvenanceV2Manifest, parse_manifest_v2
from conf_proc_reasons import (
    CP_BOOT_BINDING,
    CP_BOOT_CONTROL,
    CP_BOOT_GPT,
    CP_BOOT_LATCH,
    CP_BOOT_MANIFEST,
    CP_BOOT_MODULE_PLAN,
    CP_BOOT_OBSERVATION,
    CP_BOOT_PCR,
    CP_BOOT_PROTOCOL,
    CP_BOOT_SCHEMA,
    ApplianceError,
)


BOOT_CONTRACT_SCHEMA: Final = "conf-proc-spp-boot-contract/v1"
MODULE_PLAN_SCHEMA: Final = "conf-proc-spp-module-load-plan/v1"
GPT_LAYOUT_RULES_SCHEMA: Final = "conf-proc-spp-gpt-layout-rules/v1"
KERNEL_FEATURE_CONTRACT_SCHEMA: Final = "conf-proc-kernel-features/v1"

_SHA_CHARS: Final = frozenset("0123456789abcdef")
_IMAGE_ORDER: Final = ("models", "runtime-policy")
_CONTROL_ORDER: Final = (
    "module_loading",
    "kexec_loading",
    "sysrq",
    "unprivileged_bpf",
    "userfaultfd",
    "kernel_code_loading",
    "kernel_debug",
    "recovery_mode",
    "writable_executable_roots",
    "tpm_closure",
)
_PARTITION_LAYOUT: Final = (
    (1, "runtime-policy-data", "runtime-policy", "data"),
    (2, "runtime-policy-verity", "runtime-policy", "hash"),
    (3, "models-data", "models", "data"),
    (4, "models-verity", "models", "hash"),
)
_PREDECESSOR_DIGEST_KEYS: Final = frozenset(
    {
        "root_lock_sha256",
        "runtime_closure_sha256",
        "verity_rules_sha256",
        "tcb_identity_sha256",
        "builder_source_sha256",
        "policy_sha256",
        "accepted_manifest_sha256",
        "kernel_feature_contract_sha256",
        "trusted_certificate_bundle_sha256",
    }
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ApplianceError(code, message)


def _sha(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA_CHARS


def _absolute_path(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("/")
        and value != "/"
        and not value.startswith("//")
        and "\x00" not in value
        and posixpath.normpath(value) == value
    )


def _uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _identity_sort_key(identity: "ModuleIdentity") -> tuple[str, str, str]:
    return (identity.path, identity.sha256, identity.signer_certificate_sha256)


@dataclass(frozen=True)
class ModuleIdentity:
    path: str
    sha256: str
    signer_certificate_sha256: str


@dataclass(frozen=True)
class TmpfsDescription:
    path: str
    size_bytes: int
    mode: int


class KernelControlSupport(Enum):
    REQUIRED = "required"
    CONDITIONAL = "conditional"


@dataclass(frozen=True)
class KernelFeatureControl:
    name: str
    support: KernelControlSupport


@dataclass(frozen=True)
class KernelFeatureContract:
    kernel_input_sha256: str
    kernel_release: str
    mutable_controls: tuple[KernelFeatureControl, ...]

    def support_for(self, name: str) -> KernelControlSupport:
        for control in self.mutable_controls:
            if control.name == name:
                return control.support
        raise ApplianceError(CP_BOOT_CONTROL, "kernel feature contract lacks a required mutable control")


@dataclass(frozen=True)
class BootContract:
    predecessor_sha256: tuple[tuple[str, str], ...]
    image_order: tuple[str, str]
    boot_modules: tuple[ModuleIdentity, ...]
    serving_modules: tuple[ModuleIdentity, ...]
    non_runtime_loadable_modules: tuple[ModuleIdentity, ...]
    tmpfs_mounts: tuple[TmpfsDescription, ...]
    mutable_control_order: tuple[str, ...]
    observation_contract_sha256: str
    gpt_layout_rules_sha256: str


@dataclass(frozen=True)
class ModulePlanEntry:
    index: int
    identity: ModuleIdentity
    depends_on: tuple[int, ...]


@dataclass(frozen=True)
class ModuleLoadPlan:
    boot_contract_sha256: str
    entries: tuple[ModulePlanEntry, ...]


@dataclass(frozen=True)
class GPTPartitionRule:
    ordinal: int
    role: str
    image_id: str
    payload: str
    type_guid: str


@dataclass(frozen=True)
class GPTLayoutRules:
    logical_sector_bytes: int
    first_partition_lba: int
    alignment_lba: int
    algorithm: str
    disk_domain: str
    partuuid_domain: str
    partitions: tuple[GPTPartitionRule, ...]


@dataclass(frozen=True)
class PredictedPartition:
    ordinal: int
    role: str
    type_guid: str
    partuuid: str
    start_lba: int
    end_lba: int
    size_bytes: int
    image_id: str
    payload: str
    expected_bytes: int
    expected_sha256: str
    root_hash: str
    verity_uuid: str
    salt: str
    data_block_size: int
    hash_block_size: int


@dataclass(frozen=True)
class PredictedGPTPlan:
    disk_guid: str
    partitions: tuple[PredictedPartition, ...]
    prediction_status: str = "predicted"
    physical_qualification: str = "not_physical_qualified"


@dataclass(frozen=True)
class PartitionLocator:
    """One predicted partition locator, including its exact logical range."""

    ordinal: int
    type_guid: str
    partuuid: str
    start_lba: int
    end_lba: int
    size_bytes: int


@dataclass(frozen=True)
class VerityPair:
    """All immutable inputs required to map and verify one verity image pair."""

    image_id: str
    data_partition: PartitionLocator
    hash_partition: PartitionLocator
    data_sha256: str
    data_size_bytes: int
    hash_sha256: str
    hash_size_bytes: int
    root_hash: str
    verity_uuid: str
    salt: str
    data_block_size: int
    hash_block_size: int


@dataclass(frozen=True)
class _ManifestImageSnapshot:
    image_id: str
    squashfs_sha256: str
    squashfs_size_bytes: int
    hash_device_sha256: str
    hash_device_size_bytes: int
    root_hash: str
    verity_uuid: str
    salt: str
    data_block_size: int
    hash_block_size: int


@dataclass(frozen=True)
class _PolicyRuntimeSnapshot:
    runtime_policy_destination: str
    models_destination: str
    executable_paths: tuple[str, ...]


@dataclass(frozen=True)
class _BootRuntimeSnapshot:
    cmdline: str
    disk_locators: tuple[PartitionLocator, ...]
    runtime_policy_verity: VerityPair
    models_verity: VerityPair
    runtime_policy_destination: str
    models_destination: str
    executable_paths: tuple[str, ...]
    tmpfs_mounts: tuple[TmpfsDescription, ...]
    module_entries: tuple[ModulePlanEntry, ...]
    mutable_control_order: tuple[str, ...]
    mutable_controls: tuple[KernelFeatureControl, ...]


_OBSERVATION_SHAPE: Final = {
    "schema": "conf-proc-spp-boot-observation-shape/v1",
    "states": [
        "cmdline", "pcr15_zero", "disk_locators", "runtime_map", "runtime_verify",
        "runtime_mapping_identity", "models_map", "models_verify", "models_mapping_identity",
        "runtime_mount", "runtime_executable_confinement", "models_mount", "mutable_roots",
        "tmpfs", "modules", "modules_disabled", "mutable_controls", "pcr15_extend",
        "pcr15_readback", "transport_closed", "serving_ready",
    ],
}
OBSERVATION_CONTRACT_SHA256: Final = _sha256(canonical_dumps(_OBSERVATION_SHAPE))


def parse_kernel_feature_contract(data: bytes) -> KernelFeatureContract:
    """Parse the one narrow new predecessor-byte exposure for KFC."""

    raw = canonical_loads(data)
    _require(type(raw) is dict and set(raw) == {"schema", "kernel_input_sha256", "kernel_release", "mutable_controls"}, CP_BOOT_SCHEMA, "kernel feature contract fields are invalid")
    _require(raw["schema"] == KERNEL_FEATURE_CONTRACT_SCHEMA, CP_BOOT_SCHEMA, "kernel feature contract schema is invalid")
    _require(_sha(raw["kernel_input_sha256"]), CP_BOOT_SCHEMA, "kernel input digest is invalid")
    _require(type(raw["kernel_release"]) is str and raw["kernel_release"], CP_BOOT_SCHEMA, "kernel release is invalid")
    controls = raw["mutable_controls"]
    _require(type(controls) is list and len(controls) == len(_CONTROL_ORDER), CP_BOOT_SCHEMA, "kernel controls are incomplete")
    parsed: list[KernelFeatureControl] = []
    for item in controls:
        _require(type(item) is dict and set(item) == {"name", "support"}, CP_BOOT_SCHEMA, "kernel control fields are invalid")
        _require(type(item["name"]) is str and item["name"] in _CONTROL_ORDER, CP_BOOT_SCHEMA, "kernel control name is invalid")
        _require(item["support"] in ("required", "conditional"), CP_BOOT_SCHEMA, "kernel control support is invalid")
        parsed.append(KernelFeatureControl(item["name"], KernelControlSupport(item["support"])))
    names = [item.name for item in parsed]
    _require(names == sorted(names) and set(names) == set(_CONTROL_ORDER), CP_BOOT_SCHEMA, "kernel controls must be canonical and complete")
    _require(next(item for item in parsed if item.name == "module_loading").support is KernelControlSupport.REQUIRED, CP_BOOT_SCHEMA, "module loading closure must be required")
    return KernelFeatureContract(raw["kernel_input_sha256"], raw["kernel_release"], tuple(parsed))


def _parse_identity(raw: object, code: str) -> ModuleIdentity:
    _require(type(raw) is dict and set(raw) == {"path", "sha256", "signer_certificate_sha256"}, code, "module identity fields are invalid")
    _require(_absolute_path(raw["path"]) and _sha(raw["sha256"]) and _sha(raw["signer_certificate_sha256"]), code, "module identity is invalid")
    return ModuleIdentity(raw["path"], raw["sha256"], raw["signer_certificate_sha256"])


def _parse_identity_list(raw: object, code: str, label: str, *, nonempty: bool) -> tuple[ModuleIdentity, ...]:
    _require(type(raw) is list and (bool(raw) if nonempty else True), code, f"{label} must be an array")
    identities = tuple(_parse_identity(item, code) for item in raw)
    _require(tuple(_identity_sort_key(item) for item in identities) == tuple(sorted(_identity_sort_key(item) for item in identities)), code, f"{label} must be sorted")
    _require(len(set(identities)) == len(identities), code, f"{label} must be unique")
    return identities


def parse_boot_contract(data: bytes) -> BootContract:
    raw = canonical_loads(data)
    expected = {
        "schema", "contract_version", "predecessor_sha256", "image_order", "module_roles",
        "non_runtime_loadable_modules", "tmpfs_mounts", "mutable_control_order",
        "observation_contract_sha256", "gpt_layout_rules_sha256",
    }
    _require(type(raw) is dict and set(raw) == expected, CP_BOOT_SCHEMA, "boot contract fields are invalid")
    _require(raw["schema"] == BOOT_CONTRACT_SCHEMA and raw["contract_version"] == 1, CP_BOOT_SCHEMA, "boot contract schema is invalid")
    digests = raw["predecessor_sha256"]
    _require(type(digests) is dict and set(digests) == _PREDECESSOR_DIGEST_KEYS and all(_sha(value) for value in digests.values()), CP_BOOT_SCHEMA, "predecessor digest set is invalid")
    _require(raw["image_order"] == list(_IMAGE_ORDER), CP_BOOT_SCHEMA, "boot contract image order is invalid")
    roles = raw["module_roles"]
    _require(type(roles) is dict and set(roles) == {"boot", "serving"}, CP_BOOT_SCHEMA, "module roles are invalid")
    boot = _parse_identity_list(roles["boot"], CP_BOOT_SCHEMA, "boot module roles", nonempty=True)
    serving = _parse_identity_list(roles["serving"], CP_BOOT_SCHEMA, "serving module roles", nonempty=True)
    _require(not set(boot) & set(serving), CP_BOOT_SCHEMA, "boot and serving module roles must not overlap")
    non_runtime = _parse_identity_list(raw["non_runtime_loadable_modules"], CP_BOOT_SCHEMA, "non-runtime modules", nonempty=False)
    _require(not (set(non_runtime) & (set(boot) | set(serving))), CP_BOOT_SCHEMA, "role module cannot be non-runtime-loadable")
    mounts = raw["tmpfs_mounts"]
    _require(type(mounts) is list and mounts, CP_BOOT_SCHEMA, "tmpfs mounts are invalid")
    parsed_mounts: list[TmpfsDescription] = []
    for item in mounts:
        _require(type(item) is dict and set(item) == {"path", "size_bytes", "mode"}, CP_BOOT_SCHEMA, "tmpfs description fields are invalid")
        _require(_absolute_path(item["path"]) and type(item["size_bytes"]) is int and item["size_bytes"] > 0 and type(item["mode"]) is int and 0 <= item["mode"] <= 0o777, CP_BOOT_SCHEMA, "tmpfs description is invalid")
        parsed_mounts.append(TmpfsDescription(item["path"], item["size_bytes"], item["mode"]))
    _require([item.path for item in parsed_mounts] == sorted(item.path for item in parsed_mounts) and len({item.path for item in parsed_mounts}) == len(parsed_mounts), CP_BOOT_SCHEMA, "tmpfs descriptions must be sorted and unique")
    _require(raw["mutable_control_order"] == list(_CONTROL_ORDER), CP_BOOT_SCHEMA, "mutable control order is invalid")
    _require(raw["observation_contract_sha256"] == OBSERVATION_CONTRACT_SHA256, CP_BOOT_SCHEMA, "observation shape digest is not engine-owned")
    _require(_sha(raw["gpt_layout_rules_sha256"]), CP_BOOT_SCHEMA, "GPT rules digest is invalid")
    return BootContract(
        tuple(sorted(digests.items())), tuple(raw["image_order"]), boot, serving,
        non_runtime, tuple(parsed_mounts), tuple(raw["mutable_control_order"]),
        raw["observation_contract_sha256"], raw["gpt_layout_rules_sha256"],
    )


def parse_module_load_plan(data: bytes) -> ModuleLoadPlan:
    raw = canonical_loads(data)
    _require(type(raw) is dict and set(raw) == {"schema", "plan_version", "boot_contract_sha256", "measurement_scope", "entries"}, CP_BOOT_MODULE_PLAN, "module plan fields are invalid")
    _require(raw["schema"] == MODULE_PLAN_SCHEMA and raw["plan_version"] == 1, CP_BOOT_MODULE_PLAN, "module plan schema is invalid")
    _require(_sha(raw["boot_contract_sha256"]) and raw["measurement_scope"] == "future-pcr4-only", CP_BOOT_MODULE_PLAN, "module plan binding is invalid")
    entries = raw["entries"]
    _require(type(entries) is list and entries, CP_BOOT_MODULE_PLAN, "module plan entries are invalid")
    parsed: list[ModulePlanEntry] = []
    for item in entries:
        _require(type(item) is dict and set(item) == {"index", "path", "sha256", "signer_certificate_sha256", "depends_on"}, CP_BOOT_MODULE_PLAN, "module plan entry fields are invalid")
        _require(type(item["index"]) is int and item["index"] >= 0 and type(item["depends_on"]) is list and all(type(value) is int and value >= 0 for value in item["depends_on"]), CP_BOOT_MODULE_PLAN, "module plan order is invalid")
        identity = _parse_identity({key: item[key] for key in ("path", "sha256", "signer_certificate_sha256")}, CP_BOOT_MODULE_PLAN)
        dependencies = tuple(item["depends_on"])
        _require(dependencies == tuple(sorted(dependencies)) and len(set(dependencies)) == len(dependencies) and all(value < item["index"] for value in dependencies), CP_BOOT_MODULE_PLAN, "module dependencies must be unique prior indices")
        parsed.append(ModulePlanEntry(item["index"], identity, dependencies))
    _require([item.index for item in parsed] == list(range(len(parsed))), CP_BOOT_MODULE_PLAN, "module plan indices must be contiguous")
    _require(len({item.identity for item in parsed}) == len(parsed), CP_BOOT_MODULE_PLAN, "module plan identities must be unique")
    return ModuleLoadPlan(raw["boot_contract_sha256"], tuple(parsed))


def parse_gpt_layout_rules(data: bytes) -> GPTLayoutRules:
    raw = canonical_loads(data)
    _require(type(raw) is dict and set(raw) == {"schema", "rules_version", "geometry", "guid_derivation", "partitions"}, CP_BOOT_GPT, "GPT layout fields are invalid")
    _require(raw["schema"] == GPT_LAYOUT_RULES_SCHEMA and raw["rules_version"] == 1, CP_BOOT_GPT, "GPT layout schema is invalid")
    geometry = raw["geometry"]
    _require(type(geometry) is dict and set(geometry) == {"logical_sector_bytes", "first_partition_lba", "alignment_lba"}, CP_BOOT_GPT, "GPT geometry fields are invalid")
    _require(
        geometry["logical_sector_bytes"] in (512, 4096)
        and type(geometry["first_partition_lba"]) is int
        and geometry["first_partition_lba"] > 0
        and type(geometry["alignment_lba"]) is int
        and geometry["alignment_lba"] > 0
        and geometry["first_partition_lba"] % geometry["alignment_lba"] == 0,
        CP_BOOT_GPT,
        "GPT geometry is invalid",
    )
    derivation = raw["guid_derivation"]
    _require(type(derivation) is dict and set(derivation) == {"algorithm", "disk_domain", "partuuid_domain"}, CP_BOOT_GPT, "GPT derivation fields are invalid")
    _require(derivation["algorithm"] == "sha256-rfc4122-v5-shaped/v1" and all(type(derivation[key]) is str and derivation[key] and derivation[key].isascii() for key in ("disk_domain", "partuuid_domain")), CP_BOOT_GPT, "GPT derivation is invalid")
    partitions = raw["partitions"]
    _require(type(partitions) is list and len(partitions) == 4, CP_BOOT_GPT, "GPT partitions are invalid")
    parsed: list[GPTPartitionRule] = []
    for item, expected in zip(partitions, _PARTITION_LAYOUT, strict=True):
        _require(type(item) is dict and set(item) == {"ordinal", "role", "image_id", "payload", "type_guid"}, CP_BOOT_GPT, "GPT partition fields are invalid")
        _require((item["ordinal"], item["role"], item["image_id"], item["payload"]) == expected and _uuid(item["type_guid"]), CP_BOOT_GPT, "GPT partition rule is invalid")
        parsed.append(GPTPartitionRule(item["ordinal"], item["role"], item["image_id"], item["payload"], item["type_guid"]))
    return GPTLayoutRules(geometry["logical_sector_bytes"], geometry["first_partition_lba"], geometry["alignment_lba"], derivation["algorithm"], derivation["disk_domain"], derivation["partuuid_domain"], tuple(parsed))


def derive_sha256_v5_guid(root_lock_sha256: str, rules_sha256: str, domain: str, ordinal: int) -> str:
    """Derive a RFC-4122 v5-shaped UUID from only lock, rules, domain, ordinal."""

    _require(_sha(root_lock_sha256) and _sha(rules_sha256) and type(domain) is str and domain.isascii() and domain and type(ordinal) is int and ordinal >= 0, CP_BOOT_GPT, "GUID derivation input is invalid")
    material = domain.encode("ascii") + b"\0" + bytes.fromhex(root_lock_sha256) + bytes.fromhex(rules_sha256) + ordinal.to_bytes(4, "big")
    digest = bytearray(hashlib.sha256(material).digest()[:16])
    digest[6] = (digest[6] & 0x0F) | 0x50
    digest[8] = (digest[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(digest)))


def _align_lba(value: int, alignment_lba: int) -> int:
    return ((value + alignment_lba - 1) // alignment_lba) * alignment_lba


def _derive_gpt_plan(
    root_lock_sha256: str,
    rules_sha256: str,
    rules: GPTLayoutRules,
    images: tuple[_ManifestImageSnapshot, ...],
) -> PredictedGPTPlan:
    disk_guid = derive_sha256_v5_guid(root_lock_sha256, rules_sha256, rules.disk_domain, 0)
    image_by_id = {image.image_id: image for image in images}
    _require(set(image_by_id) == set(_IMAGE_ORDER), CP_BOOT_GPT, "manifest image coverage is unusable")
    partitions: list[PredictedPartition] = []
    next_lba = rules.first_partition_lba
    for rule in rules.partitions:
        image = image_by_id[rule.image_id]
        is_data = rule.payload == "data"
        size_bytes = image.squashfs_size_bytes if is_data else image.hash_device_size_bytes
        sectors = (size_bytes + rules.logical_sector_bytes - 1) // rules.logical_sector_bytes
        _require(sectors > 0, CP_BOOT_GPT, "partition size is unusable")
        start_lba = _align_lba(next_lba, rules.alignment_lba)
        end_lba = start_lba + sectors - 1
        _require(start_lba % rules.alignment_lba == 0 and end_lba >= start_lba, CP_BOOT_GPT, "partition logical alignment is invalid")
        partitions.append(PredictedPartition(
            rule.ordinal, rule.role, rule.type_guid,
            derive_sha256_v5_guid(root_lock_sha256, rules_sha256, rules.partuuid_domain, rule.ordinal),
            start_lba, end_lba, size_bytes, rule.image_id, rule.payload,
            size_bytes, image.squashfs_sha256 if is_data else image.hash_device_sha256,
            image.root_hash, image.verity_uuid, image.salt,
            image.data_block_size, image.hash_block_size,
        ))
        next_lba = end_lba + 1
    _require(
        all(left.end_lba < right.start_lba for left, right in zip(partitions, partitions[1:], strict=False)),
        CP_BOOT_GPT,
        "predicted partitions overlap",
    )
    return PredictedGPTPlan(disk_guid, tuple(partitions))


@dataclass(frozen=True)
class BootBinding:
    """Binder-issued immutable source bytes and reducer snapshot.

    Parsed predecessor objects retained for inspection below are never read by
    the reducer.  The reducer consumes only ``runtime`` and immutable bytes.
    """

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
    root_lock_sha256: str
    runtime_closure_sha256: str
    verity_rules_sha256: str
    tcb_identity_sha256: str
    builder_source_sha256: str
    policy_sha256: str
    accepted_manifest_sha256: str
    kernel_feature_contract_sha256: str
    trusted_certificate_bundle_sha256: str
    boot_contract_sha256: str
    module_plan_sha256: str
    gpt_layout_rules_sha256: str
    lock: Lock
    kernel_feature_contract: KernelFeatureContract
    boot_contract: BootContract
    module_plan: ModuleLoadPlan
    gpt_layout_rules: GPTLayoutRules
    gpt_plan: PredictedGPTPlan
    runtime: _BootRuntimeSnapshot


_ISSUED_BOOT_BINDINGS: Final = weakref.WeakValueDictionary[int, BootBinding]()
_ISSUED_BOOT_BINDINGS_LOCK: Final = threading.Lock()


def _register_boot_binding(binding: BootBinding) -> BootBinding:
    """Record only the exact instance created by the authoritative binder."""

    with _ISSUED_BOOT_BINDINGS_LOCK:
        _ISSUED_BOOT_BINDINGS[id(binding)] = binding
    return binding


def _is_issued_boot_binding(binding: object) -> bool:
    if type(binding) is not BootBinding:
        return False
    with _ISSUED_BOOT_BINDINGS_LOCK:
        return _ISSUED_BOOT_BINDINGS.get(id(binding)) is binding


def _base_record(lock: Lock) -> dict:
    value = lock.base_image_record
    return {
        "kind": value.kind, "provider": value.provider, "identity_namespace": value.identity_namespace,
        "identity_name": value.identity_name, "identity_immutable_revision": value.identity_immutable_revision,
        "content_sha256": value.content_sha256, "content_size_bytes": value.content_size_bytes,
        "content_media_type": value.content_media_type, "availability": value.availability,
        "recorded_retrieval_scheme": value.recorded_retrieval_scheme,
        "recorded_retrieval_identity": value.recorded_retrieval_identity,
        "recorded_retrieval_immutable_ref": value.recorded_retrieval_immutable_ref,
    }


def _input_projection(item) -> dict:
    return {
        "id": item.id, "role": item.role, "sha256": item.sha256, "size_bytes": item.size_bytes,
        "source_retrieval_scheme": item.source_retrieval_scheme,
        "source_retrieval_identity": item.source_retrieval_identity,
        "source_retrieval_immutable_ref": item.source_retrieval_immutable_ref,
        "derivation_kind": item.derivation_kind, "derivation_recipe_id": item.derivation_recipe_id,
        "derivation_parent_ids": list(item.derivation_parent_ids),
        "derivation_parameters_sha256": item.derivation_parameters_sha256,
        "placements": [
            {"image": placement.image, "path": placement.path, "node_type": placement.node_type,
             "mode": placement.mode, "uid": placement.uid, "gid": placement.gid,
             "xattrs": list(placement.xattrs), "source_input_id": placement.source_input_id,
             "target": placement.target}
            for placement in sorted(item.placements, key=lambda value: (value.image, value.path))
        ],
    }


def _inventory(lock: Lock, image_id: str) -> list[dict]:
    records: list[dict] = []
    for item in lock.inputs:
        for placement in item.placements:
            if placement.image == image_id:
                records.append({
                    "path": placement.path, "node_type": placement.node_type, "mode": placement.mode,
                    "uid": placement.uid, "gid": placement.gid, "xattrs": list(placement.xattrs),
                    "sha256": item.sha256 if placement.node_type == "file" else None,
                    "size_bytes": item.size_bytes if placement.node_type == "file" else None,
                    "symlink_target": placement.target, "source_input_id": placement.source_input_id,
                })
    return sorted(records, key=lambda value: value["path"])


def _bindings(policy: Policy, image_id: str) -> dict[str, list[str]]:
    result = {"executables": [], "configs": [], "models": [], "runtime_inputs": []}
    categories = {"executable": "executables", "config": "configs", "model": "models", "runtime_data": "runtime_inputs"}
    for node in policy.images[image_id].nodes:
        if node.node_type == "file" and node.content_class is not None:
            result[categories[node.content_class]].append(node.path)
    for paths in result.values():
        paths.sort()
    return result


def _validate_policy_usable(policy: Policy) -> _PolicyRuntimeSnapshot:
    _require(policy.process_nodes, CP_BOOT_BINDING, "policy has no process graph")
    known = {node.id: node for node in policy.process_nodes}
    roots = policy.boot_roots
    _require(
        roots and roots == tuple(sorted(roots)) and len(set(roots)) == len(roots) and all(root in known for root in roots),
        CP_BOOT_BINDING,
        "policy boot roots are unusable",
    )
    adjacency = {node_id: [] for node_id in known}
    for edge in policy.process_edges:
        _require(edge.from_id in known and edge.to_id in known, CP_BOOT_BINDING, "policy process edge is unusable")
        adjacency[edge.from_id].append(edge.to_id)
    reachable = set(roots)
    pending = list(roots)
    while pending:
        node_id = pending.pop()
        for target in adjacency[node_id]:
            if target not in reachable:
                reachable.add(target)
                pending.append(target)
    runtime_files = {node.path for node in policy.images["runtime-policy"].nodes if node.node_type == "file"}
    executable_paths: list[str] = []
    for node in policy.process_nodes:
        if node.kind in ("exec", "interpreter", "dynamic_library"):
            _require(node.id in reachable and _absolute_path(node.path) and node.path in runtime_files, CP_BOOT_BINDING, "policy executable path is unreachable or unusable")
            executable_paths.append(node.path)
    _require(executable_paths, CP_BOOT_BINDING, "policy has no executable confinement paths")
    _require(len(policy.mounts) == 2, CP_BOOT_BINDING, "policy must declare exactly two image mounts")
    mount_images = [mount.image for mount in policy.mounts]
    mount_destinations = [mount.destination for mount in policy.mounts]
    _require(mount_images == ["models", "runtime-policy"] and len(set(mount_destinations)) == 2, CP_BOOT_BINDING, "policy image mount coverage is unusable")
    for mount in policy.mounts:
        _require(mount.unit_id in reachable and _absolute_path(mount.destination) and mount.read_only, CP_BOOT_BINDING, "policy mount identity is unreachable or unusable")
    destinations = {mount.image: mount.destination for mount in policy.mounts}
    return _PolicyRuntimeSnapshot(
        destinations["runtime-policy"], destinations["models"], tuple(sorted(executable_paths)),
    )


def _snapshot_manifest_images(manifest: ProvenanceV2Manifest) -> tuple[_ManifestImageSnapshot, ...]:
    raw_images = manifest.raw["images"]
    return tuple(
        _ManifestImageSnapshot(
            image_id,
            raw_images[image_id]["squashfs_sha256"],
            raw_images[image_id]["squashfs_size_bytes"],
            raw_images[image_id]["hash_device_sha256"],
            raw_images[image_id]["hash_device_size_bytes"],
            raw_images[image_id]["root_hash"],
            raw_images[image_id]["uuid"],
            raw_images[image_id]["salt"],
            raw_images[image_id]["data_block_size"],
            raw_images[image_id]["hash_block_size"],
        )
        for image_id in _IMAGE_ORDER
    )


def _locator(partition: PredictedPartition) -> PartitionLocator:
    return PartitionLocator(
        partition.ordinal, partition.type_guid, partition.partuuid,
        partition.start_lba, partition.end_lba, partition.size_bytes,
    )


def _verity_pair(gpt_plan: PredictedGPTPlan, image_id: str) -> VerityPair:
    candidates = [item for item in gpt_plan.partitions if item.image_id == image_id]
    _require(len(candidates) == 2, CP_BOOT_GPT, "predicted verity pair is incomplete")
    data, hash_partition = candidates
    _require(data.payload == "data" and hash_partition.payload == "hash", CP_BOOT_GPT, "predicted verity pair order is invalid")
    _require(
        (data.root_hash, data.verity_uuid, data.salt, data.data_block_size, data.hash_block_size)
        == (hash_partition.root_hash, hash_partition.verity_uuid, hash_partition.salt, hash_partition.data_block_size, hash_partition.hash_block_size),
        CP_BOOT_GPT,
        "predicted verity pair metadata disagrees",
    )
    return VerityPair(
        image_id, _locator(data), _locator(hash_partition), data.expected_sha256,
        data.expected_bytes, hash_partition.expected_sha256, hash_partition.expected_bytes,
        data.root_hash, data.verity_uuid, data.salt, data.data_block_size, data.hash_block_size,
    )


def _validate_manifest(
    *,
    manifest: ProvenanceV2Manifest,
    lock: Lock,
    policy: Policy,
    inputs: ProvenanceInputs,
    trusted_certificate_bundle_bytes: bytes,
) -> None:
    raw = manifest.raw
    _require(raw["lock_schema"] == lock.schema and raw["lock_sha256"] == inputs.artifact_input_sha256, CP_BOOT_MANIFEST, "manifest lock identity disagrees")
    _require(raw["future_cmdline"] == lock.future_cmdline and raw["base_image_record"] == _base_record(lock), CP_BOOT_MANIFEST, "manifest lock fields disagree")
    _require(raw["inputs"] == [_input_projection(item) for item in sorted(lock.inputs, key=lambda item: item.id)], CP_BOOT_MANIFEST, "manifest inputs disagree")
    _require(raw["inventory"] == {name: _inventory(lock, name) for name in _IMAGE_ORDER}, CP_BOOT_MANIFEST, "manifest inventory disagrees")
    _require(raw["bindings"] == {name: _bindings(policy, name) for name in _IMAGE_ORDER}, CP_BOOT_MANIFEST, "manifest policy bindings disagree")
    _require(raw["policy"] == {"policy_input_id": lock.policy_input_id, "policy_schema": policy.schema, "process_policy_sha256": inputs.policy_sha256}, CP_BOOT_MANIFEST, "manifest policy identity disagrees")
    _require(raw["reproducibility"]["build_epoch"] == derive_build_epoch(bytes.fromhex(inputs.artifact_input_sha256)), CP_BOOT_MANIFEST, "manifest build epoch disagrees")
    for image_id in _IMAGE_ORDER:
        image = raw["images"][image_id]
        _require(image["salt"] == derive_verity_salt(bytes.fromhex(inputs.artifact_input_sha256), image_id) and image["uuid"] == derive_verity_uuid(bytes.fromhex(inputs.artifact_input_sha256), image_id), CP_BOOT_MANIFEST, "manifest verity identity disagrees")
    provenance = raw["provenance"]
    _require(
        provenance["artifact_input_sha256"] == inputs.artifact_input_sha256
        and provenance["execution_provenance_sha256"] == inputs.execution_provenance_sha256
        and provenance["runtime_closure"] == {"sha256": inputs.runtime_closure_sha256, "status": "declared_unverified"}
        and provenance["verity_rules_sha256"] == inputs.verity_rules_sha256
        and provenance["tcb_identity"] == {"sha256": inputs.tcb_identity_sha256, "status": "declared_unverified"}
        and provenance["builder_source_sha256"] == inputs.builder_source_sha256
        and provenance["policy_sha256"] == inputs.policy_sha256,
        CP_BOOT_MANIFEST, "manifest provenance identities disagree",
    )
    bundles = [item for item in lock.inputs if item.role == ROLE_KERNEL_TRUSTED_CERT_BUNDLE]
    _require(len(bundles) == 1, CP_BOOT_BINDING, "lock must have exactly one trusted certificate bundle")
    bundle = bundles[0]
    _require(
        bundle.sha256 == _sha256(trusted_certificate_bundle_bytes)
        and bundle.size_bytes == len(trusted_certificate_bundle_bytes),
        CP_BOOT_BINDING,
        "trusted certificate bundle bytes disagree with the lock input",
    )
    check_authorized_signers_match_bundle(lock, trusted_certificate_bundle_bytes)
    authority = raw["module_authority"]
    signers = tuple(item.certificate_sha256 for item in lock.authorized_module_signers)
    _require(authority["trusted_bundle_input_id"] == bundle.id and tuple(authority["authorized_signer_certificate_sha256"]) == signers, CP_BOOT_MANIFEST, "manifest module signer authority disagrees")
    files = {placement.path: item.sha256 for item in lock.inputs for placement in item.placements if placement.node_type == "file"}
    expected_modules = {path: digest for path, digest in files.items() if path.endswith(".ko")}
    expected_firmware = {path: digest for path, digest in files.items() if "/firmware/" in path}
    observed_modules = {item["path"]: item for item in authority["module_inventory"]}
    observed_firmware = {item["path"]: item for item in authority["firmware_inventory"]}
    _require(set(observed_modules) == set(expected_modules) and set(observed_firmware) == set(expected_firmware), CP_BOOT_MANIFEST, "manifest module or firmware inventory disagrees")
    _require(all(item["sha256"] == expected_modules[path] and item["signer_certificate_sha256"] in signers for path, item in observed_modules.items()) and all(item["sha256"] == expected_firmware[path] for path, item in observed_firmware.items()), CP_BOOT_MANIFEST, "manifest module or firmware identity disagrees")
    inputs_by_id = {item.id: item for item in lock.inputs}
    _require(raw["toolchain"] == [{"tool_id": tool_id, "component": inputs_by_id[tool_id].component, "resolved_path_sha256": inputs_by_id[tool_id].sha256} for tool_id in lock.tool_ids], CP_BOOT_MANIFEST, "manifest toolchain identity disagrees")


def bind_boot_inputs(
    *,
    root_lock_bytes: bytes,
    runtime_closure_bytes: bytes,
    verity_rules_bytes: bytes,
    tcb_identity_bytes: bytes,
    builder_source_bytes: bytes,
    policy_bytes: bytes,
    accepted_manifest_bytes: bytes,
    kernel_feature_contract_bytes: bytes,
    trusted_certificate_bundle_bytes: bytes,
    boot_contract_bytes: bytes,
    module_plan_bytes: bytes,
    gpt_layout_rules_bytes: bytes,
) -> BootBinding:
    """Bind canonical predecessor bytes to one immutable boot transition."""

    source_values = (root_lock_bytes, runtime_closure_bytes, verity_rules_bytes, tcb_identity_bytes, builder_source_bytes, policy_bytes, accepted_manifest_bytes, kernel_feature_contract_bytes, trusted_certificate_bundle_bytes, boot_contract_bytes, module_plan_bytes, gpt_layout_rules_bytes)
    _require(all(type(value) is bytes for value in source_values), CP_BOOT_SCHEMA, "all boot authority inputs must be bytes")
    inputs = derive_inputs(root_lock_bytes=root_lock_bytes, runtime_closure_bytes=runtime_closure_bytes, verity_rules_bytes=verity_rules_bytes, tcb_identity_bytes=tcb_identity_bytes, builder_source_bytes=builder_source_bytes, policy_bytes=policy_bytes)
    lock = parse_lock(root_lock_bytes)
    parse_runtime_closure(runtime_closure_bytes)
    parse_verity_rules(verity_rules_bytes)
    tcb = parse_tcb_identity(tcb_identity_bytes)
    policy = parse_policy(policy_bytes)
    manifest = parse_manifest_v2(accepted_manifest_bytes)
    kfc = parse_kernel_feature_contract(kernel_feature_contract_bytes)
    contract = parse_boot_contract(boot_contract_bytes)
    plan = parse_module_load_plan(module_plan_bytes)
    gpt_rules = parse_gpt_layout_rules(gpt_layout_rules_bytes)
    contract_digest = _sha256(boot_contract_bytes)
    source_digests = {
        "root_lock_sha256": _sha256(root_lock_bytes), "runtime_closure_sha256": _sha256(runtime_closure_bytes),
        "verity_rules_sha256": _sha256(verity_rules_bytes), "tcb_identity_sha256": _sha256(tcb_identity_bytes),
        "builder_source_sha256": _sha256(builder_source_bytes), "policy_sha256": _sha256(policy_bytes),
        "accepted_manifest_sha256": _sha256(accepted_manifest_bytes),
        "kernel_feature_contract_sha256": _sha256(kernel_feature_contract_bytes),
        "trusted_certificate_bundle_sha256": _sha256(trusted_certificate_bundle_bytes),
    }
    _require(dict(contract.predecessor_sha256) == source_digests, CP_BOOT_BINDING, "boot contract predecessor digest set disagrees")
    _require(contract.gpt_layout_rules_sha256 == _sha256(gpt_layout_rules_bytes), CP_BOOT_BINDING, "boot contract GPT rules binding disagrees")
    _require(plan.boot_contract_sha256 == contract_digest, CP_BOOT_MODULE_PLAN, "module plan is not bound to exact boot contract bytes")
    _require(tcb["kernel_feature_contract"] == {"schema": KERNEL_FEATURE_CONTRACT_SCHEMA, "sha256": source_digests["kernel_feature_contract_sha256"]}, CP_BOOT_BINDING, "TCB kernel feature binding disagrees")
    kernel_inputs = [item for item in lock.inputs if item.role == "kernel"]
    _require(len(kernel_inputs) == 1 and kfc.kernel_input_sha256 == kernel_inputs[0].sha256, CP_BOOT_BINDING, "kernel feature contract is not bound to lock kernel input")
    policy_snapshot = _validate_policy_usable(policy)
    _validate_manifest(
        manifest=manifest,
        lock=lock,
        policy=policy,
        inputs=inputs,
        trusted_certificate_bundle_bytes=trusted_certificate_bundle_bytes,
    )
    _validate_module_plan_bound(contract, plan, manifest, lock, contract_digest)
    images = _snapshot_manifest_images(manifest)
    gpt_plan = _derive_gpt_plan(
        source_digests["root_lock_sha256"], _sha256(gpt_layout_rules_bytes), gpt_rules, images,
    )
    runtime = _BootRuntimeSnapshot(
        lock.future_cmdline,
        tuple(_locator(partition) for partition in gpt_plan.partitions),
        _verity_pair(gpt_plan, "runtime-policy"),
        _verity_pair(gpt_plan, "models"),
        policy_snapshot.runtime_policy_destination,
        policy_snapshot.models_destination,
        policy_snapshot.executable_paths,
        contract.tmpfs_mounts,
        plan.entries,
        contract.mutable_control_order,
        kfc.mutable_controls,
    )
    return _register_boot_binding(BootBinding(
        root_lock_bytes, runtime_closure_bytes, verity_rules_bytes, tcb_identity_bytes, builder_source_bytes, policy_bytes,
        accepted_manifest_bytes, kernel_feature_contract_bytes, trusted_certificate_bundle_bytes, boot_contract_bytes, module_plan_bytes, gpt_layout_rules_bytes,
        source_digests["root_lock_sha256"], source_digests["runtime_closure_sha256"], source_digests["verity_rules_sha256"], source_digests["tcb_identity_sha256"], source_digests["builder_source_sha256"], source_digests["policy_sha256"], source_digests["accepted_manifest_sha256"], source_digests["kernel_feature_contract_sha256"], source_digests["trusted_certificate_bundle_sha256"], contract_digest, _sha256(module_plan_bytes), _sha256(gpt_layout_rules_bytes),
        lock, kfc, contract, plan, gpt_rules, gpt_plan, runtime,
    ))


def _validate_module_plan_bound(contract: BootContract, plan: ModuleLoadPlan, manifest: ProvenanceV2Manifest, lock: Lock, contract_digest: str) -> None:
    inventory = tuple(_parse_identity(item, CP_BOOT_MODULE_PLAN) for item in manifest.raw["module_authority"]["module_inventory"])
    inventory_set = set(inventory)
    signer_set = {item.certificate_sha256 for item in lock.authorized_module_signers}
    planned = tuple(item.identity for item in plan.entries)
    non_runtime = contract.non_runtime_loadable_modules
    _require(plan.boot_contract_sha256 == contract_digest, CP_BOOT_MODULE_PLAN, "module plan is not bound to the exact boot contract")
    _require(set(planned).isdisjoint(non_runtime), CP_BOOT_MODULE_PLAN, "planned and non-runtime module sets overlap")
    _require(set(planned) | set(non_runtime) == inventory_set, CP_BOOT_MODULE_PLAN, "module plan is not a closed inventory subset")
    _require(all(item in inventory_set and item.signer_certificate_sha256 in signer_set for item in planned + non_runtime), CP_BOOT_MODULE_PLAN, "module identity or signer is unauthorized")
    _require(set(contract.boot_modules).issubset(set(planned)) and set(contract.serving_modules).issubset(set(planned)), CP_BOOT_MODULE_PLAN, "required boot or serving module is absent from plan")


class BootTransitionState(Enum):
    CMDLINE = "cmdline"
    PCR15_ZERO = "pcr15_zero"
    DISK_LOCATORS = "disk_locators"
    RUNTIME_MAP = "runtime_map"
    RUNTIME_VERIFY = "runtime_verify"
    RUNTIME_MAPPING_IDENTITY = "runtime_mapping_identity"
    MODELS_MAP = "models_map"
    MODELS_VERIFY = "models_verify"
    MODELS_MAPPING_IDENTITY = "models_mapping_identity"
    RUNTIME_MOUNT = "runtime_mount"
    RUNTIME_EXECUTABLE_CONFINEMENT = "runtime_executable_confinement"
    MODELS_MOUNT = "models_mount"
    MUTABLE_ROOTS = "mutable_roots"
    TMPFS = "tmpfs"
    MODULES = "modules"
    MODULES_DISABLED = "modules_disabled"
    MUTABLE_CONTROLS = "mutable_controls"
    PCR15_EXTEND = "pcr15_extend"
    PCR15_READBACK = "pcr15_readback"
    TRANSPORT_CLOSED = "transport_closed"
    SERVING_READY = "serving_ready"
    SERVING = "serving"
    FAILED_NON_SERVING = "failed_non_serving"


@dataclass(frozen=True)
class BootEffect:
    contract_sha256: str


@dataclass(frozen=True)
class BootObservation:
    contract_sha256: str


@dataclass(frozen=True)
class CheckCmdlineEffect(BootEffect):
    cmdline: str


@dataclass(frozen=True)
class CmdlineObservation(BootObservation):
    cmdline: str
    external_companions: tuple[str, ...]


@dataclass(frozen=True)
class ReadPcr15Effect(BootEffect):
    expected_value: bytes


@dataclass(frozen=True)
class Pcr15Readback(BootObservation):
    value: bytes


@dataclass(frozen=True)
class LocateExpectedDiskEffect(BootEffect):
    disk_guid: str
    locators: tuple[PartitionLocator, ...]


@dataclass(frozen=True)
class DiskLocatorsObservation(BootObservation):
    disk_guid: str
    locators: tuple[PartitionLocator, ...]


@dataclass(frozen=True)
class MapVerityEffect(BootEffect):
    pair: VerityPair


@dataclass(frozen=True)
class VerityMappedObservation(BootObservation):
    pair: VerityPair
    mapping_identity: str


@dataclass(frozen=True)
class VerifyVerityEffect(BootEffect):
    pair: VerityPair
    expected_mapping_identity: str


@dataclass(frozen=True)
class VerityVerifiedObservation(BootObservation):
    pair: VerityPair
    mapping_identity: str


@dataclass(frozen=True)
class ReadMappingIdentityEffect(BootEffect):
    pair: VerityPair
    expected_mapping_identity: str


@dataclass(frozen=True)
class MappingIdentityObservation(BootObservation):
    pair: VerityPair
    mapping_identity: str


@dataclass(frozen=True)
class MountImageEffect(BootEffect):
    image_id: str
    destination: str
    flags: tuple[str, ...]


@dataclass(frozen=True)
class MountReadback(BootObservation):
    image_id: str
    destination: str
    flags: tuple[str, ...]


@dataclass(frozen=True)
class ConfineRuntimeExecutablesEffect(BootEffect):
    executable_paths: tuple[str, ...]


@dataclass(frozen=True)
class RuntimeExecutableObservation(BootObservation):
    executable_paths: tuple[str, ...]


@dataclass(frozen=True)
class CheckMutableRootsEffect(BootEffect):
    pass


@dataclass(frozen=True)
class MutableRootsObservation(BootObservation):
    mutable_root_paths: tuple[str, ...]


@dataclass(frozen=True)
class CreateTmpfsEffect(BootEffect):
    mounts: tuple[TmpfsDescription, ...]
    flags: tuple[str, ...]


@dataclass(frozen=True)
class TmpfsReadback(BootObservation):
    mounts: tuple[TmpfsDescription, ...]
    flags: tuple[str, ...]


@dataclass(frozen=True)
class LoadModulesEffect(BootEffect):
    entries: tuple[ModulePlanEntry, ...]


@dataclass(frozen=True)
class ModuleReadback(BootObservation):
    entries: tuple[ModuleIdentity, ...]


@dataclass(frozen=True)
class CloseModulesEffect(BootEffect):
    """Close module loading with the exact kernel.modules_disabled=1 readback."""


class ModulesDisabledStatus(Enum):
    SET_TO_1 = "kernel.modules_disabled=1"


@dataclass(frozen=True)
class ModulesDisabledReadback(BootObservation):
    status: ModulesDisabledStatus


class ControlReadbackStatus(Enum):
    DISABLED = "disabled"
    NOT_APPLICABLE_NONEXISTENT = "not_applicable_nonexistent"


@dataclass(frozen=True)
class CloseMutableControlEffect(BootEffect):
    control: str


@dataclass(frozen=True)
class ControlReadback(BootObservation):
    control: str
    status: ControlReadbackStatus


@dataclass(frozen=True)
class ExtendPcr15Effect(BootEffect):
    measurement: bytes


class Pcr15ExtendOutcome(Enum):
    ACKNOWLEDGED = "acknowledged"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True)
class Pcr15ExtendObservation(BootObservation):
    outcome: Pcr15ExtendOutcome


@dataclass(frozen=True)
class CloseTransportEffect(BootEffect):
    pass


class TransportClosureStatus(Enum):
    CLOSED = "closed"


@dataclass(frozen=True)
class TransportClosedObservation(BootObservation):
    status: TransportClosureStatus


@dataclass(frozen=True)
class ServingReadyEffect(BootEffect):
    """The sole typed authorization for listener, network, service, and upstream use."""


class ServingAuthorizationStatus(Enum):
    AUTHORIZED = "authorized"


@dataclass(frozen=True)
class ServingReadyObservation(BootObservation):
    status: ServingAuthorizationStatus


@dataclass(frozen=True)
class SafeDiagnostic:
    code: str
    stage: str
    contract_prefix: str


@dataclass(frozen=True)
class SafeDiagnosticEffect(BootEffect):
    diagnostic: SafeDiagnostic


@dataclass(frozen=True)
class CloseServingNetworkEffect(BootEffect):
    pass


@dataclass(frozen=True)
class PoweroffEffect(BootEffect):
    pass


class FailureEffectKind(Enum):
    DIAGNOSTIC = "diagnostic"
    CLOSE_SERVING_NETWORK = "close_serving_network"
    POWEROFF = "poweroff"


@dataclass(frozen=True)
class FailureEffectAcknowledgement(BootObservation):
    kind: FailureEffectKind


class BootTransport(Protocol):
    """The sole narrow adapter boundary for the reducer."""

    def execute(self, effect: BootEffect) -> BootObservation:
        ...


@dataclass(frozen=True)
class StateEffectPostcondition:
    state: BootTransitionState
    effect_name: str
    postcondition: str


BOOT_TRANSITION_TABLE: Final = (
    StateEffectPostcondition(BootTransitionState.CMDLINE, "CheckCmdlineEffect", "exact cmdline and no companions"),
    StateEffectPostcondition(BootTransitionState.PCR15_ZERO, "ReadPcr15Effect", "PCR15 is exactly zero"),
    StateEffectPostcondition(BootTransitionState.DISK_LOCATORS, "LocateExpectedDiskEffect", "one expected disk and four exact locators"),
    StateEffectPostcondition(BootTransitionState.RUNTIME_MAP, "MapVerityEffect", "runtime-policy mapped"),
    StateEffectPostcondition(BootTransitionState.RUNTIME_VERIFY, "VerifyVerityEffect", "runtime-policy verified"),
    StateEffectPostcondition(BootTransitionState.RUNTIME_MAPPING_IDENTITY, "ReadMappingIdentityEffect", "runtime-policy mapping identity independently read"),
    StateEffectPostcondition(BootTransitionState.MODELS_MAP, "MapVerityEffect", "models mapped"),
    StateEffectPostcondition(BootTransitionState.MODELS_VERIFY, "VerifyVerityEffect", "models verified"),
    StateEffectPostcondition(BootTransitionState.MODELS_MAPPING_IDENTITY, "ReadMappingIdentityEffect", "models mapping identity independently read"),
    StateEffectPostcondition(BootTransitionState.RUNTIME_MOUNT, "MountImageEffect", "runtime-policy RO,nodev,nosuid"),
    StateEffectPostcondition(BootTransitionState.RUNTIME_EXECUTABLE_CONFINEMENT, "ConfineRuntimeExecutablesEffect", "executable paths equal predecessor graph"),
    StateEffectPostcondition(BootTransitionState.MODELS_MOUNT, "MountImageEffect", "models RO,nodev,nosuid,noexec"),
    StateEffectPostcondition(BootTransitionState.MUTABLE_ROOTS, "CheckMutableRootsEffect", "no extra writable or executable mutable roots"),
    StateEffectPostcondition(BootTransitionState.TMPFS, "CreateTmpfsEffect", "only fixed nosuid,nodev,noexec tmpfs mounts"),
    StateEffectPostcondition(BootTransitionState.MODULES, "LoadModulesEffect", "exact ordered module set loaded"),
    StateEffectPostcondition(BootTransitionState.MODULES_DISABLED, "CloseModulesEffect", "kernel.modules_disabled=1 read back"),
    StateEffectPostcondition(BootTransitionState.MUTABLE_CONTROLS, "CloseMutableControlEffect", "each remaining mutable control closed"),
    StateEffectPostcondition(BootTransitionState.PCR15_EXTEND, "ExtendPcr15Effect", "one global extend request issued"),
    StateEffectPostcondition(BootTransitionState.PCR15_READBACK, "ReadPcr15Effect", "predicted PCR15 read back"),
    StateEffectPostcondition(BootTransitionState.TRANSPORT_CLOSED, "CloseTransportEffect", "transport closed"),
    StateEffectPostcondition(BootTransitionState.SERVING_READY, "ServingReadyEffect", "serving authorization emitted only after closure"),
)


class _PcrExtendLatchState(Enum):
    UNREQUESTED = "unrequested"
    REQUEST_ISSUED = "request_issued"
    ACKNOWLEDGED = "acknowledged"
    AMBIGUOUS = "ambiguous"


_PCR_EXTEND_LATCH_LOCK: Final = threading.Lock()
_PCR_EXTEND_LATCH_STATE = _PcrExtendLatchState.UNREQUESTED


def _issue_extend_request() -> bool:
    global _PCR_EXTEND_LATCH_STATE
    with _PCR_EXTEND_LATCH_LOCK:
        if _PCR_EXTEND_LATCH_STATE is not _PcrExtendLatchState.UNREQUESTED:
            return False
        _PCR_EXTEND_LATCH_STATE = _PcrExtendLatchState.REQUEST_ISSUED
        return True


def _record_extend_outcome(outcome: Pcr15ExtendOutcome) -> None:
    global _PCR_EXTEND_LATCH_STATE
    with _PCR_EXTEND_LATCH_LOCK:
        _PCR_EXTEND_LATCH_STATE = (
            _PcrExtendLatchState.ACKNOWLEDGED
            if outcome is Pcr15ExtendOutcome.ACKNOWLEDGED
            else _PcrExtendLatchState.AMBIGUOUS
        )


class BootTransitionEngine:
    """A monotonic reducer over one immutable ``BootBinding``."""

    def __init__(self, binding: BootBinding) -> None:
        _require(
            _is_issued_boot_binding(binding),
            CP_BOOT_BINDING,
            "boot engine requires a binder-issued sealed binding",
        )
        self.binding = binding
        self.state = BootTransitionState.CMDLINE
        self._pending: BootEffect | None = None
        self._runtime_mapping: str | None = None
        self._models_mapping: str | None = None
        self._control_index = 1
        self._failure_kind = FailureEffectKind.DIAGNOSTIC
        self._failure_code = CP_BOOT_PROTOCOL
        self._failure_stage = self.state.value

    @property
    def contract_sha256(self) -> str:
        return self.binding.boot_contract_sha256

    @property
    def pcr15_measurement(self) -> bytes:
        return hashlib.sha256(b"sol-spp-appliance-manifest-v1" + b"\0" + self.binding.accepted_manifest_bytes).digest()

    @property
    def predicted_pcr15(self) -> bytes:
        return hashlib.sha256(b"\0" * 32 + self.pcr15_measurement).digest()

    def next_effect(self) -> BootEffect | None:
        if self._pending is not None:
            return self._pending
        if self.state is BootTransitionState.SERVING:
            return None
        if self.state is BootTransitionState.FAILED_NON_SERVING:
            return self._failure_effect()
        try:
            effect = self._effect_for_state()
        except ApplianceError:
            raise
        self._pending = effect
        return effect

    def advance(self, transport: BootTransport) -> BootTransitionState:
        effect = self.next_effect()
        _require(effect is not None, CP_BOOT_PROTOCOL, "boot transition has no further effect")
        try:
            observation = transport.execute(effect)
        except Exception as exc:
            if type(effect) is ExtendPcr15Effect:
                # The request was issued before the transport could report the
                # error.  Its only resolution is the next exact PCR readback.
                return self.accept(Pcr15ExtendObservation(self.contract_sha256, Pcr15ExtendOutcome.ERROR))
            self._pending = None
            self._fail(CP_BOOT_PROTOCOL)
            raise ApplianceError(CP_BOOT_PROTOCOL, "typed boot transport failed") from exc
        return self.accept(observation)

    def _effect_for_state(self) -> BootEffect:
        contract = self.contract_sha256
        runtime = self.binding.runtime
        if self.state is BootTransitionState.CMDLINE:
            return CheckCmdlineEffect(contract, runtime.cmdline)
        if self.state is BootTransitionState.PCR15_ZERO:
            return ReadPcr15Effect(contract, b"\0" * 32)
        if self.state is BootTransitionState.DISK_LOCATORS:
            return LocateExpectedDiskEffect(contract, self.binding.gpt_plan.disk_guid, runtime.disk_locators)
        if self.state is BootTransitionState.RUNTIME_MAP:
            return MapVerityEffect(contract, runtime.runtime_policy_verity)
        if self.state is BootTransitionState.RUNTIME_VERIFY:
            return VerifyVerityEffect(contract, runtime.runtime_policy_verity, self._mapping("runtime-policy"))
        if self.state is BootTransitionState.RUNTIME_MAPPING_IDENTITY:
            return ReadMappingIdentityEffect(contract, runtime.runtime_policy_verity, self._mapping("runtime-policy"))
        if self.state is BootTransitionState.MODELS_MAP:
            return MapVerityEffect(contract, runtime.models_verity)
        if self.state is BootTransitionState.MODELS_VERIFY:
            return VerifyVerityEffect(contract, runtime.models_verity, self._mapping("models"))
        if self.state is BootTransitionState.MODELS_MAPPING_IDENTITY:
            return ReadMappingIdentityEffect(contract, runtime.models_verity, self._mapping("models"))
        if self.state is BootTransitionState.RUNTIME_MOUNT:
            return MountImageEffect(contract, "runtime-policy", runtime.runtime_policy_destination, ("ro", "nodev", "nosuid"))
        if self.state is BootTransitionState.RUNTIME_EXECUTABLE_CONFINEMENT:
            return ConfineRuntimeExecutablesEffect(contract, runtime.executable_paths)
        if self.state is BootTransitionState.MODELS_MOUNT:
            return MountImageEffect(contract, "models", runtime.models_destination, ("ro", "nodev", "nosuid", "noexec"))
        if self.state is BootTransitionState.MUTABLE_ROOTS:
            return CheckMutableRootsEffect(contract)
        if self.state is BootTransitionState.TMPFS:
            return CreateTmpfsEffect(contract, runtime.tmpfs_mounts, ("nosuid", "nodev", "noexec"))
        if self.state is BootTransitionState.MODULES:
            return LoadModulesEffect(contract, runtime.module_entries)
        if self.state is BootTransitionState.MODULES_DISABLED:
            return CloseModulesEffect(contract)
        if self.state is BootTransitionState.MUTABLE_CONTROLS:
            return CloseMutableControlEffect(contract, runtime.mutable_control_order[self._control_index])
        if self.state is BootTransitionState.PCR15_EXTEND:
            if not _issue_extend_request():
                self._fail(CP_BOOT_LATCH)
                raise ApplianceError(CP_BOOT_LATCH, "a PCR15 extend request was already issued in this process")
            return ExtendPcr15Effect(contract, self.pcr15_measurement)
        if self.state is BootTransitionState.PCR15_READBACK:
            return ReadPcr15Effect(contract, self.predicted_pcr15)
        if self.state is BootTransitionState.TRANSPORT_CLOSED:
            return CloseTransportEffect(contract)
        if self.state is BootTransitionState.SERVING_READY:
            return ServingReadyEffect(contract)
        self._fail(CP_BOOT_PROTOCOL)
        raise ApplianceError(CP_BOOT_PROTOCOL, "unrecognized boot transition state")

    def _mapping(self, image_id: str) -> str:
        value = self._runtime_mapping if image_id == "runtime-policy" else self._models_mapping
        _require(type(value) is str and value, CP_BOOT_PROTOCOL, "mapping identity was not established")
        return value

    def accept(self, observation: BootObservation) -> BootTransitionState:
        effect = self.next_effect()
        _require(effect is not None, CP_BOOT_PROTOCOL, "terminal boot transition cannot accept observations")
        if self.state is BootTransitionState.FAILED_NON_SERVING:
            return self._accept_failure(observation)
        try:
            _require(type(observation) is self._observation_type(effect), CP_BOOT_OBSERVATION, "observation type does not match requested effect")
            _require(observation.contract_sha256 == self.contract_sha256, CP_BOOT_OBSERVATION, "observation contract digest is stale or wrong")
            self._accept_normal(observation)
            self._pending = None
            return self.state
        except ApplianceError as exc:
            self._pending = None
            self._fail(exc.reason_code)
            raise

    @staticmethod
    def _observation_type(effect: BootEffect) -> type[BootObservation]:
        mapping = {
            CheckCmdlineEffect: CmdlineObservation, ReadPcr15Effect: Pcr15Readback,
            LocateExpectedDiskEffect: DiskLocatorsObservation, MapVerityEffect: VerityMappedObservation,
            VerifyVerityEffect: VerityVerifiedObservation, ReadMappingIdentityEffect: MappingIdentityObservation,
            MountImageEffect: MountReadback, ConfineRuntimeExecutablesEffect: RuntimeExecutableObservation,
            CheckMutableRootsEffect: MutableRootsObservation, CreateTmpfsEffect: TmpfsReadback,
            LoadModulesEffect: ModuleReadback, CloseModulesEffect: ModulesDisabledReadback,
            CloseMutableControlEffect: ControlReadback,
            ExtendPcr15Effect: Pcr15ExtendObservation, CloseTransportEffect: TransportClosedObservation,
            ServingReadyEffect: ServingReadyObservation,
        }
        return mapping[type(effect)]

    def _accept_normal(self, observation: BootObservation) -> None:
        runtime = self.binding.runtime
        state = self.state
        if state is BootTransitionState.CMDLINE:
            value = observation
            _require(type(value.cmdline) is str and value.cmdline == runtime.cmdline and type(value.external_companions) is tuple and value.external_companions == (), CP_BOOT_OBSERVATION, "cmdline or external companion check failed")
            self.state = BootTransitionState.PCR15_ZERO
        elif state is BootTransitionState.PCR15_ZERO:
            self._require_pcr(observation, b"\0" * 32)
            self.state = BootTransitionState.DISK_LOCATORS
        elif state is BootTransitionState.DISK_LOCATORS:
            _require(observation.disk_guid == self.binding.gpt_plan.disk_guid and type(observation.locators) is tuple and observation.locators == runtime.disk_locators and len(set(observation.locators)) == 4, CP_BOOT_OBSERVATION, "expected disk locators are not unique and exact")
            self.state = BootTransitionState.RUNTIME_MAP
        elif state in (BootTransitionState.RUNTIME_MAP, BootTransitionState.MODELS_MAP):
            image_id = "runtime-policy" if state is BootTransitionState.RUNTIME_MAP else "models"
            pair = runtime.runtime_policy_verity if image_id == "runtime-policy" else runtime.models_verity
            _require(observation.pair == pair and type(observation.mapping_identity) is str and observation.mapping_identity, CP_BOOT_OBSERVATION, "verity mapping observation is invalid")
            if image_id == "runtime-policy":
                self._runtime_mapping = observation.mapping_identity
                self.state = BootTransitionState.RUNTIME_VERIFY
            else:
                self._models_mapping = observation.mapping_identity
                self.state = BootTransitionState.MODELS_VERIFY
        elif state in (BootTransitionState.RUNTIME_VERIFY, BootTransitionState.MODELS_VERIFY):
            image_id = "runtime-policy" if state is BootTransitionState.RUNTIME_VERIFY else "models"
            pair = runtime.runtime_policy_verity if image_id == "runtime-policy" else runtime.models_verity
            _require(observation.pair == pair and observation.mapping_identity == self._mapping(image_id), CP_BOOT_OBSERVATION, "verity verification observation is invalid")
            self.state = BootTransitionState.RUNTIME_MAPPING_IDENTITY if image_id == "runtime-policy" else BootTransitionState.MODELS_MAPPING_IDENTITY
        elif state in (BootTransitionState.RUNTIME_MAPPING_IDENTITY, BootTransitionState.MODELS_MAPPING_IDENTITY):
            image_id = "runtime-policy" if state is BootTransitionState.RUNTIME_MAPPING_IDENTITY else "models"
            pair = runtime.runtime_policy_verity if image_id == "runtime-policy" else runtime.models_verity
            _require(observation.pair == pair and observation.mapping_identity == self._mapping(image_id), CP_BOOT_OBSERVATION, "mapping identity readback disagrees")
            self.state = BootTransitionState.MODELS_MAP if image_id == "runtime-policy" else BootTransitionState.RUNTIME_MOUNT
        elif state is BootTransitionState.RUNTIME_MOUNT:
            _require(observation.image_id == "runtime-policy" and observation.destination == runtime.runtime_policy_destination and observation.flags == ("ro", "nodev", "nosuid"), CP_BOOT_OBSERVATION, "runtime-policy mount readback is invalid")
            self.state = BootTransitionState.RUNTIME_EXECUTABLE_CONFINEMENT
        elif state is BootTransitionState.RUNTIME_EXECUTABLE_CONFINEMENT:
            _require(observation.executable_paths == runtime.executable_paths, CP_BOOT_OBSERVATION, "runtime executable confinement disagrees with predecessor graph")
            self.state = BootTransitionState.MODELS_MOUNT
        elif state is BootTransitionState.MODELS_MOUNT:
            _require(observation.image_id == "models" and observation.destination == runtime.models_destination and observation.flags == ("ro", "nodev", "nosuid", "noexec"), CP_BOOT_OBSERVATION, "models mount readback is invalid")
            self.state = BootTransitionState.MUTABLE_ROOTS
        elif state is BootTransitionState.MUTABLE_ROOTS:
            _require(observation.mutable_root_paths == (), CP_BOOT_OBSERVATION, "mutable roots are present")
            self.state = BootTransitionState.TMPFS
        elif state is BootTransitionState.TMPFS:
            _require(observation.mounts == runtime.tmpfs_mounts and observation.flags == ("nosuid", "nodev", "noexec"), CP_BOOT_OBSERVATION, "tmpfs readback is not exact")
            self.state = BootTransitionState.MODULES
        elif state is BootTransitionState.MODULES:
            _require(observation.entries == tuple(item.identity for item in runtime.module_entries), CP_BOOT_OBSERVATION, "module load readback is not exact")
            self.state = BootTransitionState.MODULES_DISABLED
        elif state is BootTransitionState.MODULES_DISABLED:
            _require(
                observation.status is ModulesDisabledStatus.SET_TO_1
                and self._control_support("module_loading") is KernelControlSupport.REQUIRED,
                CP_BOOT_CONTROL,
                "kernel.modules_disabled=1 was not read back",
            )
            self.state = BootTransitionState.MUTABLE_CONTROLS
        elif state is BootTransitionState.MUTABLE_CONTROLS:
            control = runtime.mutable_control_order[self._control_index]
            self._accept_control(observation, control)
            self._control_index += 1
            if self._control_index == len(runtime.mutable_control_order):
                self.state = BootTransitionState.PCR15_EXTEND
        elif state is BootTransitionState.PCR15_EXTEND:
            _require(type(observation.outcome) is Pcr15ExtendOutcome, CP_BOOT_PCR, "PCR extend outcome is invalid")
            _record_extend_outcome(observation.outcome)
            self.state = BootTransitionState.PCR15_READBACK
        elif state is BootTransitionState.PCR15_READBACK:
            self._require_pcr(observation, self.predicted_pcr15)
            self.state = BootTransitionState.TRANSPORT_CLOSED
        elif state is BootTransitionState.TRANSPORT_CLOSED:
            _require(observation.status is TransportClosureStatus.CLOSED, CP_BOOT_OBSERVATION, "transport closure readback is invalid")
            self.state = BootTransitionState.SERVING_READY
        elif state is BootTransitionState.SERVING_READY:
            _require(observation.status is ServingAuthorizationStatus.AUTHORIZED, CP_BOOT_OBSERVATION, "serving authorization is invalid")
            self.state = BootTransitionState.SERVING
        else:
            raise ApplianceError(CP_BOOT_PROTOCOL, "state cannot accept a normal observation")

    def _require_pcr(self, observation: BootObservation, expected: bytes) -> None:
        _require(type(observation.value) is bytes and len(observation.value) == 32 and observation.value == expected, CP_BOOT_PCR, "PCR15 readback disagrees")

    def _accept_control(self, observation: BootObservation, control: str) -> None:
        _require(observation.control == control and type(observation.status) is ControlReadbackStatus, CP_BOOT_CONTROL, "mutable control readback is invalid")
        support = self._control_support(control)
        if observation.status is ControlReadbackStatus.DISABLED:
            return
        _require(support is KernelControlSupport.CONDITIONAL and observation.status is ControlReadbackStatus.NOT_APPLICABLE_NONEXISTENT, CP_BOOT_CONTROL, "control is neither disabled nor conditionally nonexistent")

    def _control_support(self, control: str) -> KernelControlSupport:
        for feature in self.binding.runtime.mutable_controls:
            if feature.name == control:
                return feature.support
        raise ApplianceError(CP_BOOT_CONTROL, "boot binding lacks a mutable control snapshot")

    def _fail(self, code: str) -> None:
        if self.state is not BootTransitionState.FAILED_NON_SERVING:
            self._failure_stage = self.state.value
            self.state = BootTransitionState.FAILED_NON_SERVING
            self._failure_kind = FailureEffectKind.DIAGNOSTIC
            self._failure_code = code

    def _failure_effect(self) -> BootEffect | None:
        if self._failure_kind is FailureEffectKind.DIAGNOSTIC:
            return SafeDiagnosticEffect(self.contract_sha256, SafeDiagnostic(self._failure_code, self._failure_stage, self.contract_sha256[:16]))
        if self._failure_kind is FailureEffectKind.CLOSE_SERVING_NETWORK:
            return CloseServingNetworkEffect(self.contract_sha256)
        if self._failure_kind is FailureEffectKind.POWEROFF:
            return PoweroffEffect(self.contract_sha256)
        return None

    def _accept_failure(self, observation: BootObservation) -> BootTransitionState:
        expected = self._failure_effect()
        _require(expected is not None, CP_BOOT_PROTOCOL, "failure effects are complete")
        _require(type(observation) is FailureEffectAcknowledgement and observation.contract_sha256 == self.contract_sha256 and observation.kind is self._failure_kind, CP_BOOT_OBSERVATION, "failure effect acknowledgement is invalid")
        if self._failure_kind is FailureEffectKind.DIAGNOSTIC:
            self._failure_kind = FailureEffectKind.CLOSE_SERVING_NETWORK
        elif self._failure_kind is FailureEffectKind.CLOSE_SERVING_NETWORK:
            self._failure_kind = FailureEffectKind.POWEROFF
        else:
            self._failure_kind = None  # type: ignore[assignment]
        return self.state
