#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Semantic conjunction and immutable snapshots for SPP boot authority v3.

The v3 contract names its predecessor bytes, but a matching digest is not an
authority decision on its own.  This module deliberately keeps all mutable
parser products local to issuance and returns only frozen projections.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Final

import conf_proc_spp_boot as boot
import conf_proc_spp_boot_v3_tables as tables
from conf_proc_spp_reasons_v3 import (
    ApplianceErrorV3,
    CP_BOOT_V3_BINDING,
    CP_BOOT_V3_LAUNCH_SUPERVISION,
    CP_BOOT_V3_SCHEMA,
)

EXECUTION_CLOSURE_V3_SCHEMA: Final = "conf-proc-spp-execution-closure/v3"
_EXECUTION_CLOSURE_KEYS: Final = frozenset({
    "schema", "startup_kat", "bootstrap", "launch_rows", "import_roots",
    "native_loader_roots", "loader_controls", "eligible_files", "jit_derivations",
    "expected_outputs", "cache_selectors",
})
_ROLE_ORDER: Final = (
    "attestation-broker", "inference", "asr", "gateway", "collector",
)
_KAT_SHA256: Final = "82840888819a980868766f4273456c9c81d0539a6d2642b8af32f4cb30829976"
_OBSERVER_SHA256: Final = "525fa4a1335a95744779ee5e627c150f194ed6e782148553be2547c4d77ee194"
_PYTHON310_SHA256: Final = "d6bca2b84e73c7775a0dd5e6a76899cfe4ee62863d7c8f88513811d1fda23f49"
_OBSERVATION_SHA256: Final = "44b7f117d18e6ec4611dd00b9af69f93125e2c6de468441ff86f2f87ea1b9c4f"
_RAW_STDOUT_SHA256: Final = "3de3c0e7d7b5e5fe9f5644d8216bfcdbc9e0d613fdeaeb82344d0635d966e53d"
_PYTHON_ROOTS: Final = (
    "/usr/lib/python3.10", "/usr/lib/python3.10/lib-dynload", "/usr/lib/spp", "/usr/lib/spp/vendor",
)
_NATIVE_LOADER_ROOTS: Final = (
    "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/usr/lib/spp/lib",
)
_CONTENT_KINDS: Final = frozenset({
    "python_source", "python_bytecode", "elf_executable", "elf_shared_object", "data",
})
_SEMANTIC_TAGS: Final = frozenset({
    "launch_executable", "importable_module", "native_extension", "dynamic_library",
    "compiler", "compiler_source", "model_code", "model_data_no_code", "plugin",
    "python_loading_control", "configuration_no_code", "jit_cache",
})
_OUTPUT_NAME_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ApplianceErrorV3(code, message)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class FrozenJsonObjectV3:
    """An immutable canonical-JSON object representation for staged carriers."""

    items: tuple[tuple[str, "FrozenJsonValueV3"], ...]


FrozenJsonValueV3 = object


def _freeze_json(value: object) -> FrozenJsonValueV3:
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is list:
        return tuple(_freeze_json(item) for item in value)
    if type(value) is dict:
        return FrozenJsonObjectV3(tuple((key, _freeze_json(value[key])) for key in sorted(value)))
    raise ApplianceErrorV3(CP_BOOT_V3_SCHEMA, "execution closure contains an unsupported JSON value")


@dataclass(frozen=True)
class ExecutionClosureV3:
    schema: str
    startup_kat: FrozenJsonObjectV3
    bootstrap: FrozenJsonObjectV3
    launch_rows: tuple[FrozenJsonObjectV3, ...]
    import_roots: tuple[FrozenJsonValueV3, ...]
    native_loader_roots: tuple[FrozenJsonValueV3, ...]
    loader_controls: tuple[FrozenJsonValueV3, ...]
    eligible_files: tuple[FrozenJsonValueV3, ...]
    jit_derivations: tuple[FrozenJsonValueV3, ...]
    expected_outputs: tuple[FrozenJsonValueV3, ...]
    cache_selectors: tuple[FrozenJsonValueV3, ...]


def _path_under(path: str, roots: tuple[str, ...]) -> bool:
    return any(path == root or path.startswith(root + "/") for root in roots)


def _require_sorted_unique_strings(value: object, code: str, message: str) -> tuple[str, ...]:
    _require(type(value) is list and all(type(item) is str for item in value) and value == sorted(value) and len(value) == len(set(value)), code, message)
    return tuple(value)


def _validate_startup_kat_v3(value: object) -> None:
    _require(type(value) is dict and set(value) == {"schema", "binary", "capture", "packages"}, CP_BOOT_V3_SCHEMA, "execution closure startup KAT fields are invalid")
    _require(value["schema"] == "sol-spp-python310-startup-kat/v1" and type(value["packages"]) is list and len(value["packages"]) == 2, CP_BOOT_V3_SCHEMA, "startup KAT receipt is invalid")
    binary = value["binary"]
    capture = value["capture"]
    _require(type(binary) is dict and set(binary) == {"archive_sha256", "path", "sha256", "size"} and type(binary["archive_sha256"]) is str and len(binary["archive_sha256"]) == 64 and all(character in "0123456789abcdef" for character in binary["archive_sha256"]), CP_BOOT_V3_SCHEMA, "startup KAT binary archive identity is invalid")
    _require(type(capture) is dict and set(capture) == {"argv", "native_runtime_basis", "observation", "observation_sha256", "observer"}, CP_BOOT_V3_SCHEMA, "startup KAT capture fields are invalid")
    observation = capture["observation"]
    _require(binary["path"] == "/usr/bin/python3.10" and binary["sha256"] == _PYTHON310_SHA256 and binary["size"] == 5937704, CP_BOOT_V3_SCHEMA, "startup KAT binary is invalid")
    _require(capture["argv"] == ["/usr/bin/python3.10", "-I", "-B", "-S", "/usr/lib/spp/evidence/python310_startup_observer_v1.py"], CP_BOOT_V3_SCHEMA, "startup KAT argv is invalid")
    _require(type(capture["observer"]) is dict and capture["observer"] == {"candidate_path": "/usr/lib/spp/evidence/python310_startup_observer_v1.py", "local_path": "evidence/python310_startup_observer_v1.py", "sha256": _OBSERVER_SHA256} and capture["observation_sha256"] == _OBSERVATION_SHA256, CP_BOOT_V3_SCHEMA, "startup KAT hashes are invalid")
    _require(type(observation) is dict and type(capture["native_runtime_basis"]) is str and capture["native_runtime_basis"], CP_BOOT_V3_SCHEMA, "startup KAT observation is invalid")
    observation_bytes = boot.canonical_dumps(observation)
    _require(len(observation_bytes) == 1165 and _sha256(observation_bytes) == _OBSERVATION_SHA256, CP_BOOT_V3_SCHEMA, "startup KAT observation is invalid")
    _require(len(observation_bytes + b"\n") == 1166 and _sha256(observation_bytes + b"\n") == _RAW_STDOUT_SHA256, CP_BOOT_V3_SCHEMA, "startup KAT stdout framing is invalid")
    _require(observation["flags"] == {"dont_write_bytecode": 1, "ignore_environment": 1, "isolated": 1, "no_site": 1, "no_user_site": 1}, CP_BOOT_V3_SCHEMA, "startup KAT flags are invalid")


def _validate_bootstrap_v3(value: object, rows: object, startup_kat: object) -> None:
    required = {"source_path", "controller_entry", "role_map", "flags", "pre_path", "pre_meta_path", "pre_path_hooks", "pre_importer_cache", "denied_zip", "post_path", "post_meta_path", "post_path_hooks", "post_importer_cache"}
    _require(type(value) is dict and set(value) == required, CP_BOOT_V3_SCHEMA, "execution closure bootstrap fields are invalid")
    _require(value["source_path"] == "/usr/lib/spp/conf_proc_spp_role_bootstrap.py" and value["controller_entry"] == "/usr/lib/spp/conf_proc_spp_init.py", CP_BOOT_V3_SCHEMA, "execution closure bootstrap entries are invalid")
    _require(value["flags"] == {"dont_write_bytecode": 1, "ignore_environment": 1, "isolated": 1, "no_site": 1, "no_user_site": 1}, CP_BOOT_V3_SCHEMA, "bootstrap flags are invalid")
    _require(value["pre_path"] == ["/usr/lib/python310.zip", "/usr/lib/python3.10", "/usr/lib/python3.10/lib-dynload"] and value["denied_zip"] == "/usr/lib/python310.zip", CP_BOOT_V3_SCHEMA, "bootstrap pre-path is invalid")
    _require(value["post_path"] == list(_PYTHON_ROOTS) and value["post_importer_cache"] == [], CP_BOOT_V3_SCHEMA, "bootstrap post-path/cache is invalid")
    _require(value["pre_meta_path"] == ["_frozen_importlib.BuiltinImporter", "_frozen_importlib.FrozenImporter", "_frozen_importlib_external.PathFinder"] and value["post_meta_path"] == value["pre_meta_path"], CP_BOOT_V3_SCHEMA, "bootstrap meta path is invalid")
    _require(type(startup_kat) is dict, CP_BOOT_V3_SCHEMA, "startup KAT is invalid")
    capture = startup_kat.get("capture")
    observation = capture.get("observation") if type(capture) is dict else None
    expected_hooks = observation.get("path_hooks") if type(observation) is dict else None
    _require(type(expected_hooks) is list and len(expected_hooks) == 2, CP_BOOT_V3_SCHEMA, "startup KAT path hooks are invalid")
    _require(
        type(value["pre_path_hooks"]) is list
        and type(value["post_path_hooks"]) is list
        and value["pre_path_hooks"] == expected_hooks
        and value["post_path_hooks"] == [expected_hooks[1]],
        CP_BOOT_V3_SCHEMA,
        "bootstrap path hooks are invalid",
    )
    _require(type(value["pre_importer_cache"]) is list and len(value["pre_importer_cache"]) == 4, CP_BOOT_V3_SCHEMA, "bootstrap importer cache is invalid")
    expected_cache = [
        {"path": "/usr/lib/python3.10", "finder": "_frozen_importlib_external.FileFinder"},
        {"path": "/usr/lib/python3.10/encodings", "finder": "_frozen_importlib_external.FileFinder"},
        {"path": "/usr/lib/python310.zip", "finder": None},
    ]
    _require(value["pre_importer_cache"][:3] == expected_cache and type(value["pre_importer_cache"][3]) is dict and set(value["pre_importer_cache"][3]) == {"path", "finder"} and value["pre_importer_cache"][3]["path"] in (value["source_path"], value["controller_entry"]) and value["pre_importer_cache"][3]["finder"] is None, CP_BOOT_V3_SCHEMA, "bootstrap typed entry-script cache is invalid")
    _require(type(value["role_map"]) is list and len(value["role_map"]) == len(_ROLE_ORDER), CP_BOOT_V3_SCHEMA, "execution closure role map is invalid")
    _require(type(rows) is list and len(rows) == len(_ROLE_ORDER), CP_BOOT_V3_SCHEMA, "execution closure launch rows are invalid")
    for mapping, launch, role, table_row in zip(value["role_map"], rows, _ROLE_ORDER, tables.LAUNCH_ROLE_ROWS_V3, strict=True):
        _require(type(mapping) is dict and set(mapping) == {"role", "source_path"} and mapping == {"role": role, "source_path": table_row.source_path}, CP_BOOT_V3_SCHEMA, "execution closure role map entry is invalid")
        _require(type(launch) is dict and set(launch) == {"role", "source_path"} and launch == mapping, CP_BOOT_V3_SCHEMA, "execution closure launch row is invalid")


def parse_execution_closure_v3(raw: object) -> ExecutionClosureV3:
    """Parse the complete typed execution-closure carrier before predecessor joins."""

    _require(type(raw) is dict and set(raw) == _EXECUTION_CLOSURE_KEYS, CP_BOOT_V3_SCHEMA, "execution closure fields are invalid")
    _require(raw["schema"] == EXECUTION_CLOSURE_V3_SCHEMA, CP_BOOT_V3_SCHEMA, "execution closure schema is invalid")
    _validate_startup_kat_v3(raw["startup_kat"])
    _validate_bootstrap_v3(raw["bootstrap"], raw["launch_rows"], raw["startup_kat"])
    _require(raw["import_roots"] == list(_PYTHON_ROOTS) and raw["native_loader_roots"] == list(_NATIVE_LOADER_ROOTS), CP_BOOT_V3_SCHEMA, "execution closure roots are invalid")
    arrays = ("loader_controls", "eligible_files", "jit_derivations", "expected_outputs", "cache_selectors")
    _require(all(type(raw[key]) is list for key in arrays), CP_BOOT_V3_SCHEMA, "execution closure collection is invalid")
    frozen_startup = _freeze_json(raw["startup_kat"])
    frozen_bootstrap = _freeze_json(raw["bootstrap"])
    assert type(frozen_startup) is FrozenJsonObjectV3 and type(frozen_bootstrap) is FrozenJsonObjectV3
    frozen_rows = tuple(_freeze_json(item) for item in raw["launch_rows"])
    assert all(type(item) is FrozenJsonObjectV3 for item in frozen_rows)
    return ExecutionClosureV3(raw["schema"], frozen_startup, frozen_bootstrap, frozen_rows, tuple(raw["import_roots"]), tuple(raw["native_loader_roots"]), *[tuple(_freeze_json(item) for item in raw[key]) for key in arrays])


def validate_execution_mode_v3(execution_mode: object, cache_policy: object, closure: ExecutionClosureV3) -> None:
    _require(type(execution_mode) is str and type(cache_policy) is str, CP_BOOT_V3_SCHEMA, "execution mode is invalid")
    valid = (
        (execution_mode == "python_no_jit" and cache_policy == "absent")
        or (execution_mode == "python_jit_triton" and cache_policy in ("ephemeral_rebuild", "measured_read_only"))
    )
    _require(valid and closure.schema == EXECUTION_CLOSURE_V3_SCHEMA, CP_BOOT_V3_SCHEMA, "execution mode and cache policy disagree")
    if execution_mode == "python_no_jit":
        _require(not closure.jit_derivations and not closure.expected_outputs and not closure.cache_selectors, CP_BOOT_V3_SCHEMA, "no-JIT closure carries JIT records")


@dataclass(frozen=True)
class SourceDigestsV3:
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


@dataclass(frozen=True)
class PartitionLocatorSnapshotV3:
    ordinal: int
    type_guid: str
    partuuid: str
    start_lba: int
    end_lba: int
    size_bytes: int


@dataclass(frozen=True)
class VerityPairSnapshotV3:
    image_id: str
    data_partition: PartitionLocatorSnapshotV3
    hash_partition: PartitionLocatorSnapshotV3
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
class StorageSnapshotV3:
    disk_guid: str
    disk_locators: tuple[PartitionLocatorSnapshotV3, ...]
    runtime_policy_verity: VerityPairSnapshotV3
    models_verity: VerityPairSnapshotV3
    immutable_mounts: tuple[str, ...]
    tmpfs_mounts: tuple[tuple[str, int, int], ...]
    mount_union: tuple[str, ...]


@dataclass(frozen=True)
class KernelIdentitySnapshotV3:
    kernel_input_sha256: str
    kernel_release: str
    kernel_feature_contract_sha256: str
    mutable_controls: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ModuleEntrySnapshotV3:
    index: int
    path: str
    sha256: str
    signer_certificate_sha256: str
    predecessor_indices: tuple[int, ...]


@dataclass(frozen=True)
class ModuleAuthoritySnapshotV3:
    boot_contract_sha256: str
    entries: tuple[ModuleEntrySnapshotV3, ...]


@dataclass(frozen=True)
class ControlInventorySnapshotV3:
    rows: tuple[tables.ControlInventoryRowV3, ...]


@dataclass(frozen=True)
class LaunchSourceProjectionV3:
    source_input_id: str
    image: str
    path: str
    sha256: str
    size_bytes: int
    mode: int
    content_class: str
    runtime_closure_role: str


@dataclass(frozen=True)
class RoleLaunchSnapshotV3:
    authority: tables.LaunchRoleRowV3
    source: LaunchSourceProjectionV3


@dataclass(frozen=True)
class LaunchProjectionV3:
    roles: tuple[RoleLaunchSnapshotV3, ...]


@dataclass(frozen=True)
class Stage2ControllerSnapshotV3:
    authority: tables.Stage2ControllerRowV3
    source: LaunchSourceProjectionV3
    interpreter_source_input_id: str
    interpreter_sha256: str
    interpreter_size_bytes: int
    interpreter_mode: int


@dataclass(frozen=True)
class EligibleFileSnapshotV3:
    input_id: str
    image: str
    path: str
    sha256: str
    size_bytes: int
    mode: int
    content_kind: str
    semantic_tags: tuple[str, ...]


@dataclass(frozen=True)
class LoaderControlSnapshotV3:
    path: str
    kind: str
    read_only: bool
    contributed_paths: tuple[str, ...]
    imports: tuple[str, ...]
    hooks: tuple[str, ...]


@dataclass(frozen=True)
class JitInputSnapshotV3:
    kind: str
    input_id: str
    image: str
    path: str
    sha256: str
    size_bytes: int
    mode: int


@dataclass(frozen=True)
class JitDerivationSnapshotV3:
    derivation_sha256: str
    compiler_input_id: str
    compiler_sha256: str
    loader_input_id: str
    loader_sha256: str
    compiler_argv: tuple[str, ...]
    loader_argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    inputs: tuple[JitInputSnapshotV3, ...]
    output_name: str
    relative_path: str
    output_sha256: str
    output_size_bytes: int
    output_mode: int
    cache_policy: str


@dataclass(frozen=True)
class CacheSelectorSnapshotV3:
    derivation_sha256: str
    output_name: str
    path: str


@dataclass(frozen=True)
class Predicate5SnapshotV3:
    execution_mode: str
    cache_policy: str
    execution_closure_schema: str
    startup_kat_sha256: str
    observer_sha256: str
    import_roots: tuple[str, ...]
    native_loader_roots: tuple[str, ...]
    bootstrap_source: LaunchSourceProjectionV3
    loader_controls: tuple[LoaderControlSnapshotV3, ...]
    eligible_files: tuple[EligibleFileSnapshotV3, ...]
    jit_derivations: tuple[JitDerivationSnapshotV3, ...]
    cache_selectors: tuple[CacheSelectorSnapshotV3, ...]


@dataclass(frozen=True)
class SemanticSnapshotsV3:
    source_digests: SourceDigestsV3
    storage: StorageSnapshotV3
    kernel_identity: KernelIdentitySnapshotV3
    module_authority: ModuleAuthoritySnapshotV3
    control_inventory: ControlInventorySnapshotV3
    launch_projection: LaunchProjectionV3
    stage2_controller: Stage2ControllerSnapshotV3
    predicate5: Predicate5SnapshotV3


@dataclass(frozen=True)
class ParsedPredecessorsV3:
    """Short-lived parsed predecessors; never retained in a BootBindingV3."""

    lock: object
    runtime_closure: dict
    verity_rules: dict
    tcb_identity: dict
    policy: object
    manifest: object
    kernel_feature_contract: object
    module_plan: object
    gpt_layout_rules: object
    provenance_inputs: object


def parse_predecessors_v3(
    *, root_lock_bytes: bytes, runtime_closure_bytes: bytes, verity_rules_bytes: bytes,
    tcb_identity_bytes: bytes, builder_source_bytes: bytes, policy_bytes: bytes,
    accepted_manifest_bytes: bytes, kernel_feature_contract_bytes: bytes,
    trusted_certificate_bundle_bytes: bytes, module_plan_bytes: bytes,
    gpt_layout_rules_bytes: bytes,
) -> ParsedPredecessorsV3:
    """Canonical-parse every schema-bearing v3 predecessor before issuance."""

    values = (root_lock_bytes, runtime_closure_bytes, verity_rules_bytes, tcb_identity_bytes, builder_source_bytes, policy_bytes, accepted_manifest_bytes, kernel_feature_contract_bytes, trusted_certificate_bundle_bytes, module_plan_bytes, gpt_layout_rules_bytes)
    _require(all(type(value) is bytes for value in values), CP_BOOT_V3_BINDING, "all v3 predecessor values must be bytes")
    _require(bool(builder_source_bytes) and len(builder_source_bytes) <= 16 * 1024 * 1024, CP_BOOT_V3_BINDING, "builder source bytes are invalid")
    _require(bool(trusted_certificate_bundle_bytes) and len(trusted_certificate_bundle_bytes) <= 16 * 1024 * 1024, CP_BOOT_V3_BINDING, "trusted certificate bundle bytes are invalid")
    try:
        inputs = boot.derive_inputs(
            root_lock_bytes=root_lock_bytes, runtime_closure_bytes=runtime_closure_bytes,
            verity_rules_bytes=verity_rules_bytes, tcb_identity_bytes=tcb_identity_bytes,
            builder_source_bytes=builder_source_bytes, policy_bytes=policy_bytes,
        )
        return ParsedPredecessorsV3(
            boot.parse_lock(root_lock_bytes), boot.parse_runtime_closure(runtime_closure_bytes),
            boot.parse_verity_rules(verity_rules_bytes), boot.parse_tcb_identity(tcb_identity_bytes),
            boot.parse_policy(policy_bytes), boot.parse_manifest_v2(accepted_manifest_bytes),
            boot.parse_kernel_feature_contract(kernel_feature_contract_bytes),
            boot.parse_module_load_plan(module_plan_bytes), boot.parse_gpt_layout_rules(gpt_layout_rules_bytes),
            inputs,
        )
    except ApplianceErrorV3:
        raise
    except Exception as error:
        raise ApplianceErrorV3(CP_BOOT_V3_BINDING, "v3 predecessor parsing rejected") from error


def _partition_snapshot(value: object) -> PartitionLocatorSnapshotV3:
    return PartitionLocatorSnapshotV3(value.ordinal, value.type_guid, value.partuuid, value.start_lba, value.end_lba, value.size_bytes)


def _verity_snapshot(value: object) -> VerityPairSnapshotV3:
    return VerityPairSnapshotV3(
        value.image_id, _partition_snapshot(value.data_partition), _partition_snapshot(value.hash_partition),
        value.data_sha256, value.data_size_bytes, value.hash_sha256, value.hash_size_bytes,
        value.root_hash, value.verity_uuid, value.salt, value.data_block_size, value.hash_block_size,
    )


def _validate_module_plan_v3(plan: object, manifest: object, lock: object, contract_digest: str) -> None:
    inventory = tuple(boot._parse_identity(item, boot.CP_BOOT_MODULE_PLAN) for item in manifest.raw["module_authority"]["module_inventory"])
    planned = tuple(item.identity for item in plan.entries)
    signers = {item.certificate_sha256 for item in lock.authorized_module_signers}
    _require(plan.boot_contract_sha256 == contract_digest, CP_BOOT_V3_BINDING, "module plan is not bound to exact v3 contract bytes")
    _require(set(planned) == set(inventory), CP_BOOT_V3_BINDING, "module plan does not close manifest module inventory")
    _require(all(item.signer_certificate_sha256 in signers for item in planned), CP_BOOT_V3_BINDING, "module plan signer is unauthorized")


def _launch_require(condition: bool, message: str) -> None:
    _require(condition, CP_BOOT_V3_LAUNCH_SUPERVISION, message)


def _runtime_source_projection_v3(
    parsed: ParsedPredecessorsV3, *, path: str, label: str,
) -> LaunchSourceProjectionV3:
    """Join one executable source across lock, policy, manifest and runtime closure."""

    lock_matches = [
        (item, placement)
        for item in parsed.lock.inputs
        for placement in item.placements
        if placement.path == path and placement.node_type == "file"
    ]
    _launch_require(len(lock_matches) == 1, f"{label} source placement is not unique")
    lock_input, placement = lock_matches[0]
    _launch_require(lock_input.role == "runtime_tree_input", f"{label} source is not a runtime_tree_input")
    _launch_require(placement.source_input_id == lock_input.id, f"{label} lock source identity disagrees")
    policy_nodes = [node for node in parsed.policy.images["runtime-policy"].nodes if node.path == path]
    _launch_require(len(policy_nodes) == 1, f"{label} runtime policy source is not unique")
    policy_node = policy_nodes[0]
    _launch_require(
        policy_node.node_type == "file"
        and policy_node.source_input_id == lock_input.id
        and policy_node.mode == placement.mode
        and policy_node.content_class == "executable",
        f"{label} runtime policy source disagrees",
    )
    manifest_entries = [item for item in parsed.manifest.raw["inventory"]["runtime-policy"] if item["path"] == path]
    _launch_require(len(manifest_entries) == 1, f"{label} manifest source is not unique")
    manifest_entry = manifest_entries[0]
    _launch_require(
        manifest_entry == {
            "path": path, "node_type": "file", "mode": placement.mode,
            "uid": placement.uid, "gid": placement.gid, "xattrs": list(placement.xattrs),
            "sha256": lock_input.sha256, "size_bytes": lock_input.size_bytes,
            "symlink_target": None, "source_input_id": lock_input.id,
        },
        f"{label} manifest source disagrees",
    )
    closure_entries = [item for item in parsed.runtime_closure["entries"] if item["path"] == path]
    _launch_require(len(closure_entries) == 1, f"{label} runtime closure source is not unique")
    closure = closure_entries[0]
    _launch_require(
        closure["node_type"] == "file"
        and closure["root_lock_input_id"] == lock_input.id
        and closure["logical_role"] == "runtime_tree_input"
        and closure["sha256"] == lock_input.sha256
        and closure["size_bytes"] == lock_input.size_bytes
        and closure["mode"] == placement.mode,
        f"{label} runtime closure source disagrees",
    )
    return LaunchSourceProjectionV3(
        lock_input.id, placement.image, path, lock_input.sha256,
        lock_input.size_bytes, placement.mode, policy_node.content_class, closure["logical_role"],
    )


def _launch_source_projection_v3(
    parsed: ParsedPredecessorsV3, row: tables.LaunchRoleRowV3,
) -> LaunchSourceProjectionV3:
    return _runtime_source_projection_v3(parsed, path=row.source_path, label=row.role)


def _locked_interpreter_v3(parsed: ParsedPredecessorsV3) -> tuple[object, object]:
    matches = [
        (item, placement)
        for item in parsed.lock.inputs
        for placement in item.placements
        if placement.path == "/usr/bin/python3.10" and placement.node_type == "file"
    ]
    _launch_require(len(matches) == 1, "locked target interpreter placement is not unique")
    item, placement = matches[0]
    _launch_require(item.role == "runtime_tree_input" and placement.source_input_id == item.id, "target interpreter is not runtime_tree_input authority")
    policy_nodes = [node for node in parsed.policy.images["runtime-policy"].nodes if node.path == placement.path]
    _launch_require(len(policy_nodes) == 1 and policy_nodes[0].source_input_id == item.id and policy_nodes[0].content_class == "executable" and policy_nodes[0].mode == placement.mode, "target interpreter policy placement disagrees")
    return item, placement


def _launch_projection_v3(parsed: ParsedPredecessorsV3) -> tuple[LaunchProjectionV3, Stage2ControllerSnapshotV3]:
    sources = tuple(_launch_source_projection_v3(parsed, row) for row in tables.LAUNCH_ROLE_ROWS_V3)
    _launch_require(len({item.source_input_id for item in sources}) == len(sources), "service sources share a lock input")
    conf_sources = [item for item in parsed.runtime_closure["entries"] if item["logical_role"] == "conf_proc_source"]
    _launch_require(len(conf_sources) == 1, "runtime closure must retain exactly one distinct conf_proc_source")
    by_id = {node.id: node for node in parsed.policy.process_nodes}
    interpreter_input, interpreter_placement = _locked_interpreter_v3(parsed)
    for row in tables.LAUNCH_ROLE_ROWS_V3:
        node = by_id.get(row.role)
        _launch_require(node is not None, f"{row.role} process node is missing")
        _launch_require(
            node.kind == row.process_kind
            and node.path == row.interpreter_path
            and node.sha256 == interpreter_input.sha256
            and node.argv == row.argv
            and node.network_scope == row.expected_network_scope
            and node.capabilities == row.expected_process_capabilities
            and node.source_input_id == interpreter_input.id,
            f"{row.role} process-node authority disagrees",
        )
        _launch_require(parsed.policy.network_policy.get(row.role) == row.expected_network_scope, f"{row.role} network policy disagrees")
        capability = parsed.policy.capability_policy.get(row.role)
        _launch_require(
            capability is not None
            and capability.capability_bounding_set == row.expected_capability_bounding_set
            and capability.ambient_capabilities == row.expected_ambient_capabilities
            and capability.no_new_privileges is row.expected_no_new_privileges,
            f"{row.role} capability policy disagrees",
        )
    controller = tables.STAGE2_CONTROLLER_ROW_V3
    controller_source = _runtime_source_projection_v3(
        parsed, path=controller.source_path, label="stage2 controller",
    )
    _launch_require(controller.interpreter_path == "/usr/bin/python3.10" and controller.argv[:5] == ("/usr/bin/python3.10", "-I", "-B", "-S", "/usr/lib/spp/conf_proc_spp_init.py"), "stage2 controller interpreter authority disagrees")
    return (
        LaunchProjectionV3(tuple(RoleLaunchSnapshotV3(row, source) for row, source in zip(tables.LAUNCH_ROLE_ROWS_V3, sources, strict=True))),
        Stage2ControllerSnapshotV3(controller, controller_source, interpreter_input.id, interpreter_input.sha256, interpreter_input.size_bytes, interpreter_placement.mode),
    )


def _thaw_json(value: FrozenJsonValueV3) -> object:
    if type(value) is FrozenJsonObjectV3:
        return {key: _thaw_json(item) for key, item in value.items}
    if type(value) is tuple:
        return [_thaw_json(item) for item in value]
    return value


def _frame_v3(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _jit_identity_v3(value: object, name: str) -> dict:
    _require(type(value) is dict and set(value) == {"input_id", "image", "path", "sha256", "size_bytes", "mode"}, CP_BOOT_V3_SCHEMA, f"JIT {name} identity is invalid")
    _require(type(value["input_id"]) is str and type(value["image"]) is str and type(value["path"]) is str and value["path"].startswith("/") and type(value["sha256"]) is str and len(value["sha256"]) == 64 and type(value["size_bytes"]) is int and value["size_bytes"] >= 0 and type(value["mode"]) is int and 0 <= value["mode"] <= 0o7777, CP_BOOT_V3_SCHEMA, f"JIT {name} values are invalid")
    return value


def jit_derivation_sha256_v3(record: object) -> str:
    """Return the v3 framed JIT-output key for one canonical typed record."""

    _require(type(record) is dict and set(record) == {"schema", "compiler", "loader", "argv_env", "inputs", "output", "cache_policy"}, CP_BOOT_V3_SCHEMA, "JIT derivation fields are invalid")
    _require(record["schema"] == "conf-proc-spp-jit-derivation/v3", CP_BOOT_V3_SCHEMA, "JIT derivation schema is invalid")
    compiler = _jit_identity_v3(record["compiler"], "compiler")
    loader = _jit_identity_v3(record["loader"], "loader")
    argv_env = record["argv_env"]
    _require(type(argv_env) is dict and set(argv_env) == {"compiler_argv", "loader_argv", "environment"}, CP_BOOT_V3_SCHEMA, "JIT argv/environment is invalid")
    _require(all(type(argv_env[key]) is list and all(type(item) is str for item in argv_env[key]) for key in ("compiler_argv", "loader_argv")), CP_BOOT_V3_SCHEMA, "JIT argv is invalid")
    _require(type(argv_env["environment"]) is list and all(type(item) is list and len(item) == 2 and all(type(part) is str for part in item) for item in argv_env["environment"]), CP_BOOT_V3_SCHEMA, "JIT environment is invalid")
    inputs = record["inputs"]
    _require(type(inputs) is list and inputs, CP_BOOT_V3_SCHEMA, "JIT inputs are invalid")
    typed_inputs: list[dict] = []
    for item in inputs:
        _require(type(item) is dict and set(item) == {"kind", "input_id", "image", "path", "sha256", "size_bytes", "mode"} and item["kind"] in {"source", "configuration", "model", "native_library"}, CP_BOOT_V3_SCHEMA, "JIT typed input is invalid")
        _jit_identity_v3({key: item[key] for key in ("input_id", "image", "path", "sha256", "size_bytes", "mode")}, "typed input")
        typed_inputs.append(item)
    output = record["output"]
    _require(type(output) is dict and set(output) == {"output_name", "relative_path", "sha256", "size_bytes", "mode"}, CP_BOOT_V3_SCHEMA, "JIT output is invalid")
    _require(type(output["output_name"]) is str and _OUTPUT_NAME_RE.fullmatch(output["output_name"]) is not None and output["relative_path"] == output["output_name"] and type(output["sha256"]) is str and len(output["sha256"]) == 64 and type(output["size_bytes"]) is int and output["size_bytes"] >= 0 and type(output["mode"]) is int and 0 <= output["mode"] <= 0o7777, CP_BOOT_V3_SCHEMA, "JIT output identity is invalid")
    _require(record["cache_policy"] in ("ephemeral_rebuild", "measured_read_only"), CP_BOOT_V3_SCHEMA, "JIT cache policy is invalid")
    material = b"sol-spp-jit-output-v3\0"
    material += _frame_v3(compiler["input_id"].encode("ascii")) + _frame_v3(compiler["sha256"].encode("ascii"))
    material += _frame_v3(loader["input_id"].encode("ascii")) + _frame_v3(loader["sha256"].encode("ascii"))
    material += _frame_v3(boot.canonical_dumps(argv_env))
    material += b"".join(_frame_v3(boot.canonical_dumps(item)) for item in typed_inputs)
    material += _frame_v3(boot.canonical_dumps(output)) + _frame_v3(record["cache_policy"].encode("ascii"))
    return _sha256(material)


def _jit_tag_expectations_v3(raw_derivations: list[object]) -> dict[str, set[str]]:
    """Derive the concrete tag roles named by the typed JIT records."""

    expected: dict[str, set[str]] = {}

    def add(identity: object, *tags: str) -> None:
        if type(identity) is dict and type(identity.get("path")) is str:
            expected.setdefault(identity["path"], set()).update(tags)

    for record in raw_derivations:
        if type(record) is not dict:
            continue
        add(record.get("compiler"), "compiler", "launch_executable")
        add(record.get("loader"), "launch_executable")
        inputs = record.get("inputs")
        if type(inputs) is not list:
            continue
        for item in inputs:
            if type(item) is not dict:
                continue
            kind = item.get("kind")
            if kind == "source":
                add(item, "compiler_source")
            elif kind == "configuration":
                add(item, "configuration_no_code")
            elif kind == "model":
                add(item, "model_code" if str(item.get("path", "")).endswith(".py") else "model_data_no_code")
            elif kind == "native_library":
                add(item, "dynamic_library", "native_extension")
    return expected


def _expected_eligible_tags_v3(
    parsed: ParsedPredecessorsV3, path: str, jit_tags: dict[str, set[str]],
) -> set[str]:
    """Return the complete tag set for the concrete authority paths this lode models."""

    tags = set(jit_tags.get(path, ()))
    launch_paths = {
        *(row.source_path for row in tables.LAUNCH_ROLE_ROWS_V3),
        "/usr/lib/spp/conf_proc_spp_role_bootstrap.py",
        tables.STAGE2_CONTROLLER_ROW_V3.source_path,
        *(edge.origin_path for edge in parsed.policy.process_edges),
        *(node.path for node in parsed.policy.process_nodes),
    }
    runtime_nodes = [node for node in parsed.policy.images["runtime-policy"].nodes if node.path == path and node.node_type == "file"]
    if path in launch_paths or (not path.endswith(".so") and any(node.content_class == "executable" for node in runtime_nodes)):
        tags.add("launch_executable")
    if _path_under(path, _PYTHON_ROOTS) and path.endswith(".py"):
        tags.add("importable_module")
    if path.endswith(".pth"):
        tags.add("python_loading_control")
    if path.endswith("sitecustomize.py"):
        tags.update(("importable_module", "python_loading_control"))
    if path.endswith(".so"):
        tags.update(("native_extension", "dynamic_library"))
    if path.endswith("plugin.so"):
        tags.add("plugin")
    if path.startswith("/usr/lib/spp/jit-cache/"):
        tags.add("jit_cache")
    return tags


def _expected_content_kind_v3(
    parsed: ParsedPredecessorsV3, path: str, tags: set[str],
) -> str | None:
    if path.endswith(".py"):
        return "python_source"
    if path.endswith(".pyc"):
        return "python_bytecode"
    if path.endswith(".so"):
        return "elf_shared_object"
    if path.endswith(".pth") or {"configuration_no_code", "model_data_no_code"} & tags:
        return "data"
    runtime_nodes = [node for node in parsed.policy.images["runtime-policy"].nodes if node.path == path and node.node_type == "file"]
    if any(node.content_class == "executable" for node in runtime_nodes):
        return "elf_executable"
    return None


def _eligible_source_v3(
    parsed: ParsedPredecessorsV3, entry: dict, expected_tags: set[str],
) -> EligibleFileSnapshotV3:
    required = {"input_id", "image", "path", "sha256", "size_bytes", "mode", "content_kind", "semantic_tags"}
    _require(type(entry) is dict and set(entry) == required, CP_BOOT_V3_SCHEMA, "eligible-file fields are invalid")
    _require(type(entry["path"]) is str and entry["path"].startswith("/") and type(entry["input_id"]) is str and type(entry["image"]) is str and type(entry["sha256"]) is str and len(entry["sha256"]) == 64 and type(entry["size_bytes"]) is int and entry["size_bytes"] >= 0 and type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o7777 and entry["content_kind"] in _CONTENT_KINDS, CP_BOOT_V3_SCHEMA, "eligible-file value is invalid")
    tags = _require_sorted_unique_strings(entry["semantic_tags"], CP_BOOT_V3_SCHEMA, "eligible semantic tags are invalid")
    _require(set(tags) <= _SEMANTIC_TAGS, CP_BOOT_V3_SCHEMA, "eligible semantic tag is unknown")
    matches = [(item, place) for item in parsed.lock.inputs for place in item.placements if place.path == entry["path"] and place.node_type == "file"]
    _require(len(matches) == 1, CP_BOOT_V3_BINDING, "eligible file lock identity is not unique")
    lock_input, placement = matches[0]
    policy_nodes = [node for node in parsed.policy.images[entry["image"]].nodes if node.path == entry["path"]]
    manifest_entries = [value for value in parsed.manifest.raw["inventory"][entry["image"]] if value["path"] == entry["path"]]
    closure_entries = [value for value in parsed.runtime_closure["entries"] if value["path"] == entry["path"]]
    _require(len(policy_nodes) == len(manifest_entries) == len(closure_entries) == 1, CP_BOOT_V3_BINDING, "eligible file predecessor projection is incomplete")
    node, manifest, closure = policy_nodes[0], manifest_entries[0], closure_entries[0]
    _require(lock_input.id == entry["input_id"] and placement.image == entry["image"] and lock_input.sha256 == entry["sha256"] and lock_input.size_bytes == entry["size_bytes"] and placement.mode == entry["mode"] and node.node_type == "file" and node.source_input_id == lock_input.id and node.mode == placement.mode and manifest["sha256"] == lock_input.sha256 and manifest["size_bytes"] == lock_input.size_bytes and manifest["mode"] == placement.mode and manifest["source_input_id"] == lock_input.id and closure["sha256"] == lock_input.sha256 and closure["size_bytes"] == lock_input.size_bytes and closure["mode"] == placement.mode and closure["root_lock_input_id"] == lock_input.id, CP_BOOT_V3_BINDING, "eligible file predecessor identities disagree")
    kind = entry["content_kind"]
    path = entry["path"]
    _require(set(tags) == expected_tags, CP_BOOT_V3_BINDING, "eligible semantic tags disagree with executable authority")
    expected_kind = _expected_content_kind_v3(parsed, path, expected_tags)
    _require(expected_kind is None or kind == expected_kind, CP_BOOT_V3_BINDING, "eligible content kind disagrees with executable authority")
    _require(not (entry["mode"] & 0o222) or kind == "data", CP_BOOT_V3_BINDING, "writable executable eligibility is forbidden")
    if path.endswith(".py"):
        _require(kind == "python_source", CP_BOOT_V3_BINDING, "Python source content kind disagrees")
    if path.endswith(".pyc"):
        _require(kind == "python_bytecode", CP_BOOT_V3_BINDING, "Python bytecode content kind disagrees")
    if path.endswith(".so"):
        _require(kind == "elf_shared_object", CP_BOOT_V3_BINDING, "shared-object content kind disagrees")
    if path.endswith(".pth"):
        _require(kind == "data" and "python_loading_control" in tags, CP_BOOT_V3_BINDING, "pth loading control disagrees")
    if "compiler" in tags:
        _require(kind == "elf_executable" and "launch_executable" in tags, CP_BOOT_V3_BINDING, "compiler tag combination disagrees")
    if "compiler_source" in tags:
        _require(kind == "python_source" and "importable_module" in tags, CP_BOOT_V3_BINDING, "compiler-source tag combination disagrees")
    if "native_extension" in tags or "dynamic_library" in tags:
        _require(kind == "elf_shared_object" and {"native_extension", "dynamic_library"} <= set(tags), CP_BOOT_V3_BINDING, "native-library tag combination disagrees")
    if "plugin" in tags:
        _require(kind == "elf_shared_object" and {"native_extension", "dynamic_library"} <= set(tags), CP_BOOT_V3_BINDING, "plugin tag combination disagrees")
    if path.endswith("plugin.so"):
        _require("plugin" in tags, CP_BOOT_V3_BINDING, "plugin shared object is missing plugin authority")
    if "jit_cache" in tags:
        _require(kind == "elf_shared_object" and {"native_extension", "dynamic_library"} <= set(tags), CP_BOOT_V3_BINDING, "JIT cache tag combination disagrees")
    if path.endswith("sitecustomize.py"):
        _require(kind == "python_source" and {"importable_module", "python_loading_control"} <= set(tags), CP_BOOT_V3_BINDING, "sitecustomize authority disagrees")
    return EligibleFileSnapshotV3(entry["input_id"], entry["image"], path, entry["sha256"], entry["size_bytes"], entry["mode"], kind, tags)


def _validate_loader_controls_v3(raw: list[object], eligible: tuple[EligibleFileSnapshotV3, ...]) -> tuple[LoaderControlSnapshotV3, ...]:
    by_path = {item.path: item for item in eligible}
    records: list[LoaderControlSnapshotV3] = []
    for value in raw:
        _require(type(value) is dict and set(value) == {"path", "kind", "read_only", "contributed_paths", "imports", "hooks"} and value["kind"] in ("pth", "namespace_package", "startup_hook") and type(value["read_only"]) is bool, CP_BOOT_V3_SCHEMA, "loader-control fields are invalid")
        paths = _require_sorted_unique_strings(value["contributed_paths"], CP_BOOT_V3_SCHEMA, "loader-control paths are invalid")
        imports = _require_sorted_unique_strings(value["imports"], CP_BOOT_V3_SCHEMA, "loader-control imports are invalid")
        hooks = _require_sorted_unique_strings(value["hooks"], CP_BOOT_V3_SCHEMA, "loader-control hooks are invalid")
        file = by_path.get(value["path"])
        _require(file is not None and value["read_only"] and not (file.mode & 0o222) and "python_loading_control" in file.semantic_tags, CP_BOOT_V3_BINDING, "loader-control file is not measured read-only authority")
        contributions = (*paths, *imports, *hooks)
        _require(all(_path_under(path, _PYTHON_ROOTS + _NATIVE_LOADER_ROOTS) for path in contributions), CP_BOOT_V3_BINDING, "loader-control contribution escapes closed roots")
        _require(
            all(
                path in by_path or any(item.path.startswith(path + "/") for item in eligible)
                for path in contributions
            ),
            CP_BOOT_V3_BINDING,
            "loader-control contribution is not measured authority",
        )
        records.append(LoaderControlSnapshotV3(value["path"], value["kind"], value["read_only"], paths, imports, hooks))
    control_paths = {item.path for item in records}
    _require(len(control_paths) == len(records), CP_BOOT_V3_BINDING, "loader controls are duplicated")
    _require({item.path for item in eligible if "python_loading_control" in item.semantic_tags} == control_paths, CP_BOOT_V3_BINDING, "loading-control eligibility and controls disagree")
    return tuple(records)


def _predicate5_snapshot_v3(
    contract: "BootContractV3", parsed: ParsedPredecessorsV3,
    bootstrap_source: LaunchSourceProjectionV3,
) -> Predicate5SnapshotV3:
    closure = contract.execution_closure
    raw_eligible = _thaw_json(closure.eligible_files)
    raw_controls = _thaw_json(closure.loader_controls)
    raw_derivations = _thaw_json(closure.jit_derivations)
    raw_outputs = _thaw_json(closure.expected_outputs)
    raw_selectors = _thaw_json(closure.cache_selectors)
    assert type(raw_eligible) is list and type(raw_controls) is list and type(raw_derivations) is list and type(raw_outputs) is list and type(raw_selectors) is list
    jit_tags = _jit_tag_expectations_v3(raw_derivations)
    eligible = tuple(
        _eligible_source_v3(parsed, value, _expected_eligible_tags_v3(parsed, value.get("path", ""), jit_tags))
        for value in raw_eligible
        if type(value) is dict
    )
    _require(len(eligible) == len(raw_eligible), CP_BOOT_V3_SCHEMA, "eligible-file record is invalid")
    _require(tuple(item.path for item in eligible) == tuple(sorted(item.path for item in eligible)) and len({item.path for item in eligible}) == len(eligible), CP_BOOT_V3_SCHEMA, "eligible files must be sorted and unique")
    expected_paths = {node.path for node in parsed.policy.images["runtime-policy"].nodes if node.node_type == "file" and node.content_class == "executable"}
    expected_paths.update(edge.origin_path for edge in parsed.policy.process_edges if edge.kind in ("script_interpreter", "elf_interpreter", "dynamic_load"))
    expected_paths.update(entry["path"] for entry in parsed.runtime_closure["entries"] if entry["node_type"] == "file" and _path_under(entry["path"], _PYTHON_ROOTS + _NATIVE_LOADER_ROOTS))
    expected_paths.update(row.source_path for row in tables.LAUNCH_ROLE_ROWS_V3)
    expected_paths.update((bootstrap_source.path, tables.STAGE2_CONTROLLER_ROW_V3.source_path))
    for record in raw_derivations:
        if type(record) is not dict:
            continue
        for identity in (record.get("compiler"), record.get("loader")):
            if type(identity) is dict and type(identity.get("path")) is str:
                expected_paths.add(identity["path"])
        inputs = record.get("inputs")
        if type(inputs) is list:
            expected_paths.update(item["path"] for item in inputs if type(item) is dict and type(item.get("path")) is str)
    _require({item.path for item in eligible} == expected_paths, CP_BOOT_V3_BINDING, "eligible-file denominator disagrees with predecessor closure")
    controls = _validate_loader_controls_v3(raw_controls, eligible)
    tags = {tag for item in eligible for tag in item.semantic_tags}
    if contract.execution_mode == "python_no_jit":
        _require(not ({"compiler", "compiler_source", "jit_cache"} & tags) and not raw_derivations and not raw_outputs and not raw_selectors, CP_BOOT_V3_BINDING, "no-JIT predicate admits compiler or cache authority")
        _require(not any(item.path == "/run/spp-jit" for item in eligible), CP_BOOT_V3_BINDING, "no-JIT predicate admits workspace")
        return Predicate5SnapshotV3(contract.execution_mode, contract.cache_policy, closure.schema, _KAT_SHA256, _OBSERVER_SHA256, _PYTHON_ROOTS, _NATIVE_LOADER_ROOTS, bootstrap_source, controls, eligible, (), ())
    _require({"compiler", "compiler_source"} <= tags and raw_derivations and len(raw_derivations) == len(raw_outputs) and (len(raw_selectors) == len(raw_derivations) if contract.cache_policy == "measured_read_only" else not raw_selectors), CP_BOOT_V3_BINDING, "JIT predicate lacks compiler, source, outputs, or selectors")
    eligible_by_path = {item.path: item for item in eligible}
    snapshots: list[JitDerivationSnapshotV3] = []
    selectors: list[CacheSelectorSnapshotV3] = []
    identities: set[tuple[str, str]] = set()
    selector_values = raw_selectors if contract.cache_policy == "measured_read_only" else [None] * len(raw_derivations)
    for record, output_record, selector_record in zip(raw_derivations, raw_outputs, selector_values, strict=True):
        _require(type(record) is dict, CP_BOOT_V3_SCHEMA, "JIT derivation record is invalid")
        digest = jit_derivation_sha256_v3(record)
        _require(record["cache_policy"] == contract.cache_policy, CP_BOOT_V3_BINDING, "JIT derivation cache policy disagrees with boot contract")
        compiler = _jit_identity_v3(record["compiler"], "compiler")
        loader = _jit_identity_v3(record["loader"], "loader")
        argv_env = record["argv_env"]
        _require(argv_env["compiler_argv"][-2:] == ["--jit-workspace=/run/spp-jit", "--isolated"] and argv_env["loader_argv"][-2:] == ["--jit-workspace=/run/spp-jit", "--isolated"], CP_BOOT_V3_BINDING, "JIT compiler/loader argv is invalid")
        _require(argv_env["environment"] == [["LANG", "C"], ["LC_ALL", "C"], ["PATH", "/nonexistent"], ["PYTHONDONTWRITEBYTECODE", "1"], ["PYTHONNOUSERSITE", "1"]], CP_BOOT_V3_BINDING, "JIT environment is invalid")
        for identity, required_tag in ((compiler, "compiler"), (loader, "launch_executable")):
            item = eligible_by_path.get(identity["path"])
            _require(item is not None and (item.input_id, item.image, item.sha256, item.size_bytes, item.mode) == (identity["input_id"], identity["image"], identity["sha256"], identity["size_bytes"], identity["mode"]) and required_tag in item.semantic_tags, CP_BOOT_V3_BINDING, "JIT compiler/loader predecessor projection disagrees")
        typed: list[JitInputSnapshotV3] = []
        for item in record["inputs"]:
            source = eligible_by_path.get(item["path"])
            _require(source is not None and (source.input_id, source.image, source.sha256, source.size_bytes, source.mode) == (item["input_id"], item["image"], item["sha256"], item["size_bytes"], item["mode"]), CP_BOOT_V3_BINDING, "JIT input predecessor projection disagrees")
            expected_tags = {"source": {"compiler_source"}, "configuration": {"configuration_no_code"}, "model": {"model_code", "model_data_no_code"}, "native_library": {"dynamic_library"}}[item["kind"]]
            _require(expected_tags & set(source.semantic_tags), CP_BOOT_V3_BINDING, "JIT input semantic class disagrees")
            typed.append(JitInputSnapshotV3(item["kind"], item["input_id"], item["image"], item["path"], item["sha256"], item["size_bytes"], item["mode"]))
        required_inputs = {item.path for item in eligible if {"compiler_source", "configuration_no_code", "model_code", "model_data_no_code", "dynamic_library"} & set(item.semantic_tags) and "jit_cache" not in item.semantic_tags}
        _require(tuple(item.path for item in typed) and {item.path for item in typed} == required_inputs and len({item.path for item in typed}) == len(typed), CP_BOOT_V3_BINDING, "JIT typed inputs do not close the measured eligibility set")
        output = record["output"]
        _require(type(output_record) is dict and output_record == {"derivation_sha256": digest, **output}, CP_BOOT_V3_SCHEMA, "JIT expected output does not match derivation")
        identity = (digest, output["output_name"])
        _require(identity not in identities, CP_BOOT_V3_BINDING, "JIT output identity is duplicated")
        identities.add(identity)
        expected_path = "/usr/lib/spp/jit-cache/" + digest + "/" + output["output_name"]
        if contract.cache_policy == "measured_read_only":
            _require(type(selector_record) is dict and selector_record == {"derivation_sha256": digest, "output_name": output["output_name"], "path": expected_path}, CP_BOOT_V3_SCHEMA, "measured cache selector is invalid")
            cached = eligible_by_path.get(expected_path)
            _require(cached is not None and "jit_cache" in cached.semantic_tags and (cached.sha256, cached.size_bytes, cached.mode) == (output["sha256"], output["size_bytes"], output["mode"]), CP_BOOT_V3_BINDING, "measured cache output identity disagrees")
            selectors.append(CacheSelectorSnapshotV3(digest, output["output_name"], expected_path))
        else:
            _require(selector_record is None and expected_path not in eligible_by_path, CP_BOOT_V3_BINDING, "ephemeral JIT admits a preexisting cache output")
        snapshots.append(JitDerivationSnapshotV3(digest, compiler["input_id"], compiler["sha256"], loader["input_id"], loader["sha256"], tuple(argv_env["compiler_argv"]), tuple(argv_env["loader_argv"]), tuple((item[0], item[1]) for item in argv_env["environment"]), tuple(typed), output["output_name"], output["relative_path"], output["sha256"], output["size_bytes"], output["mode"], record["cache_policy"]))
    return Predicate5SnapshotV3(contract.execution_mode, contract.cache_policy, closure.schema, _KAT_SHA256, _OBSERVER_SHA256, _PYTHON_ROOTS, _NATIVE_LOADER_ROOTS, bootstrap_source, controls, eligible, tuple(snapshots), tuple(selectors))


def validate_semantic_conjunction_v3(
    *, contract: "BootContractV3", boot_contract_bytes: bytes, root_lock_bytes: bytes,
    runtime_closure_bytes: bytes, verity_rules_bytes: bytes, tcb_identity_bytes: bytes,
    builder_source_bytes: bytes, policy_bytes: bytes, accepted_manifest_bytes: bytes,
    kernel_feature_contract_bytes: bytes, trusted_certificate_bundle_bytes: bytes,
    module_plan_bytes: bytes, gpt_layout_rules_bytes: bytes,
) -> SemanticSnapshotsV3:
    """Validate the v2-equivalent predecessor conjunction and freeze its effects."""

    parsed = parse_predecessors_v3(
        root_lock_bytes=root_lock_bytes, runtime_closure_bytes=runtime_closure_bytes,
        verity_rules_bytes=verity_rules_bytes, tcb_identity_bytes=tcb_identity_bytes,
        builder_source_bytes=builder_source_bytes, policy_bytes=policy_bytes,
        accepted_manifest_bytes=accepted_manifest_bytes,
        kernel_feature_contract_bytes=kernel_feature_contract_bytes,
        trusted_certificate_bundle_bytes=trusted_certificate_bundle_bytes,
        module_plan_bytes=module_plan_bytes, gpt_layout_rules_bytes=gpt_layout_rules_bytes,
    )
    digests = SourceDigestsV3(
        _sha256(root_lock_bytes), _sha256(runtime_closure_bytes), _sha256(verity_rules_bytes),
        _sha256(tcb_identity_bytes), _sha256(builder_source_bytes), _sha256(policy_bytes),
        _sha256(accepted_manifest_bytes), _sha256(kernel_feature_contract_bytes),
        _sha256(trusted_certificate_bundle_bytes), _sha256(boot_contract_bytes),
        _sha256(module_plan_bytes), _sha256(gpt_layout_rules_bytes),
    )
    try:
        contract_refs = {
            "root_lock_sha256": digests.root_lock_sha256,
            "runtime_closure_sha256": digests.runtime_closure_sha256,
            "verity_rules_sha256": digests.verity_rules_sha256,
            "tcb_identity_sha256": digests.tcb_identity_sha256,
            "builder_source_sha256": digests.builder_source_sha256,
            "policy_sha256": digests.policy_sha256,
            "accepted_manifest_sha256": digests.accepted_manifest_sha256,
            "kernel_feature_contract_sha256": digests.kernel_feature_contract_sha256,
            "trusted_certificate_bundle_sha256": digests.trusted_certificate_bundle_sha256,
            "gpt_layout_rules_sha256": digests.gpt_layout_rules_sha256,
        }
        _require(all(getattr(contract, key) == value for key, value in contract_refs.items()), CP_BOOT_V3_BINDING, "v3 contract predecessor digest set disagrees")
        _require(parsed.module_plan.boot_contract_sha256 == digests.boot_contract_sha256, CP_BOOT_V3_BINDING, "module plan is not bound to exact v3 contract bytes")
        _require(parsed.tcb_identity["kernel_feature_contract"] == {"schema": boot.KERNEL_FEATURE_CONTRACT_SCHEMA, "sha256": digests.kernel_feature_contract_sha256}, CP_BOOT_V3_BINDING, "TCB kernel feature binding disagrees")
        kernel_inputs = [item for item in parsed.lock.inputs if item.role == "kernel"]
        _require(len(kernel_inputs) == 1 and parsed.kernel_feature_contract.kernel_input_sha256 == kernel_inputs[0].sha256, CP_BOOT_V3_BINDING, "kernel feature contract is not bound to lock kernel input")
        policy_runtime = boot._validate_policy_usable(parsed.policy)
        boot._validate_manifest(
            manifest=parsed.manifest, lock=parsed.lock, policy=parsed.policy,
            inputs=parsed.provenance_inputs, trusted_certificate_bundle_bytes=trusted_certificate_bundle_bytes,
        )
        _validate_module_plan_v3(parsed.module_plan, parsed.manifest, parsed.lock, digests.boot_contract_sha256)
        images = boot._snapshot_manifest_images(parsed.manifest)
        gpt_plan = boot._derive_gpt_plan(digests.root_lock_sha256, digests.gpt_layout_rules_sha256, parsed.gpt_layout_rules, images)
        runtime_pair = boot._verity_pair(gpt_plan, "runtime-policy")
        models_pair = boot._verity_pair(gpt_plan, "models")
        tmpfs = (("/run/spp-state", 1048576, 0o755),)
        immutable_mounts = (policy_runtime.runtime_policy_destination, policy_runtime.models_destination)
        _require(all(not boot._paths_overlap(path, immutable) for path, _, _ in tmpfs for immutable in immutable_mounts), CP_BOOT_V3_BINDING, "tmpfs mounts overlap immutable image mount paths")
        module_entries = tuple(ModuleEntrySnapshotV3(entry.index, entry.identity.path, entry.identity.sha256, entry.identity.signer_certificate_sha256, entry.predecessor_indices) for entry in parsed.module_plan.entries)
        storage = StorageSnapshotV3(
            gpt_plan.disk_guid, tuple(_partition_snapshot(boot._locator(item)) for item in gpt_plan.partitions),
            _verity_snapshot(runtime_pair), _verity_snapshot(models_pair), immutable_mounts, tmpfs,
            tuple(sorted((*immutable_mounts, *(path for path, _, _ in tmpfs)))),
        )
        kernel = KernelIdentitySnapshotV3(
            parsed.kernel_feature_contract.kernel_input_sha256, parsed.kernel_feature_contract.kernel_release,
            digests.kernel_feature_contract_sha256,
            tuple((item.name, item.support.value) for item in parsed.kernel_feature_contract.mutable_controls),
        )
        launch_projection, stage2_controller = _launch_projection_v3(parsed)
        bootstrap_source = _runtime_source_projection_v3(
            parsed,
            path="/usr/lib/spp/conf_proc_spp_role_bootstrap.py",
            label="role bootstrap",
        )
        predicate5 = _predicate5_snapshot_v3(contract, parsed, bootstrap_source)
        return SemanticSnapshotsV3(
            digests, storage, kernel,
            ModuleAuthoritySnapshotV3(parsed.module_plan.boot_contract_sha256, module_entries),
            ControlInventorySnapshotV3(tuple(tables.CONTROL_INVENTORY_ROWS_V3)),
            launch_projection,
            stage2_controller,
            predicate5,
        )
    except ApplianceErrorV3:
        raise
    except Exception as error:
        raise ApplianceErrorV3(CP_BOOT_V3_BINDING, "v3 semantic conjunction rejected") from error
