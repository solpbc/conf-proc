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
import posixpath
import re
import unicodedata
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
    "expected_outputs", "cache_selectors", "executable_graph",
})
_ROLE_ORDER: Final = (
    "attestation-broker", "inference", "asr", "gateway", "collector",
)
_KAT_SHA256: Final = "82840888819a980868766f4273456c9c81d0539a6d2642b8af32f4cb30829976"
_KAT_PACKAGE_ROWS_V3: Final = (
    (
        "libpython3.10-minimal", "3.10.12-1~22.04.15",
        "evidence/python310-startup-kat-packages/libpython3.10-minimal_3.10.12-1~22.04.15_amd64.deb",
        "https://launchpadlibrarian.net/850349567/libpython3.10-minimal_3.10.12-1~22.04.15_amd64.deb",
        "d7cfecf69996a03153da25b826b422a27b52c1c4cbcb2fa67bce093c476f0d08",
    ),
    (
        "libpython3.10-stdlib", "3.10.12-1~22.04.15",
        "evidence/python310-startup-kat-packages/libpython3.10-stdlib_3.10.12-1~22.04.15_amd64.deb",
        "https://launchpadlibrarian.net/850349568/libpython3.10-stdlib_3.10.12-1~22.04.15_amd64.deb",
        "5cfe8bd93cde07bf977dc94fdf438e1a5fa70bc79f871147555156b14937c38d",
    ),
)
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
_GRAPH_SCHEMA_V3: Final = "sol-spp-executable-graph/v1"
_GRAPH_SOURCE_SCHEMA_V3: Final = "sol-spp-executable-graph-source/v1"
_GRAPH_KEYS_V3: Final = frozenset({
    "schema", "alias_hop_limit", "entrypoints", "nodes", "aliases", "controls",
    "declarations", "edges",
})
_GRAPH_NODE_KINDS_V3: Final = frozenset({
    "measured_file", "measured_directory", "jit_derivation", "jit_output",
})
_GRAPH_DECLARATION_KINDS_V3: Final = frozenset({
    "python_import", "elf_interpreter", "elf_needed", "elf_search", "dlopen", "jit_invoke",
})
_GRAPH_EDGE_KINDS_V3: Final = frozenset({
    "python_script", "python_import", "elf_interpreter", "elf_needed", "elf_search", "dlopen",
    "jit_invoke", "jit_compiler", "jit_loader", "jit_input", "jit_output",
})
_GRAPH_SOURCE_KINDS_V3: Final = frozenset({
    "startup_receipt", "controller_cache_projection", "role_cache_projection",
    "bootstrap_projection", "runtime_closure", "loader_control", "process_authority",
    "jit_derivation",
})


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
    controller_bootstrap_cache: "ControllerBootstrapCacheProjectionV3"
    role_bootstrap_cache: "RoleBootstrapCacheProjectionV3"
    launch_rows: tuple[FrozenJsonObjectV3, ...]
    import_roots: tuple[FrozenJsonValueV3, ...]
    native_loader_roots: tuple[FrozenJsonValueV3, ...]
    loader_controls: tuple[FrozenJsonValueV3, ...]
    eligible_files: tuple[FrozenJsonValueV3, ...]
    jit_derivations: tuple[FrozenJsonValueV3, ...]
    expected_outputs: tuple[FrozenJsonValueV3, ...]
    cache_selectors: tuple[FrozenJsonValueV3, ...]
    executable_graph: FrozenJsonObjectV3


def _path_under(path: str, roots: tuple[str, ...]) -> bool:
    return any(path == root or path.startswith(root + "/") for root in roots)


def _require_sorted_unique_strings(value: object, code: str, message: str) -> tuple[str, ...]:
    _require(type(value) is list and all(type(item) is str for item in value) and value == sorted(value) and len(value) == len(set(value)), code, message)
    return tuple(value)


@dataclass(frozen=True)
class ControllerBootstrapCacheProjectionV3:
    entry_path: str
    entries: tuple[tuple[str, str | None], ...]


@dataclass(frozen=True)
class RoleBootstrapCacheProjectionV3:
    entry_path: str
    entries: tuple[tuple[str, str | None], ...]


def _validate_startup_kat_v3(frozen_value: object) -> None:
    value = _thaw_json(frozen_value)
    _require(type(value) is dict and set(value) == {"schema", "binary", "capture", "packages"}, CP_BOOT_V3_SCHEMA, "execution closure startup KAT fields are invalid")
    packages = value["packages"]
    _require(value["schema"] == "sol-spp-python310-startup-kat/v1" and type(packages) is list and len(packages) == len(_KAT_PACKAGE_ROWS_V3), CP_BOOT_V3_SCHEMA, "startup KAT receipt is invalid")
    package_rows: list[tuple[str, str, str, str, str]] = []
    for package in packages:
        _require(type(package) is dict and set(package) == {"name", "version", "local_path", "url", "sha256"} and all(type(package[field]) is str for field in ("name", "version", "local_path", "url", "sha256")), CP_BOOT_V3_SCHEMA, "startup KAT package row is invalid")
        package_rows.append((package["name"], package["version"], package["local_path"], package["url"], package["sha256"]))
    _require(tuple(package_rows) == _KAT_PACKAGE_ROWS_V3, CP_BOOT_V3_SCHEMA, "startup KAT package rows are invalid")
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
    kat_bytes = boot.canonical_dumps(value)
    _require(_sha256(kat_bytes + b"\n") == _KAT_SHA256, CP_BOOT_V3_SCHEMA, "startup KAT receipt digest is invalid")


def _bootstrap_cache_projection_v3(
    value: object,
    entry_path: str,
    projection_type: type[ControllerBootstrapCacheProjectionV3] | type[RoleBootstrapCacheProjectionV3],
) -> ControllerBootstrapCacheProjectionV3 | RoleBootstrapCacheProjectionV3:
    expected_cache = (
        ("/usr/lib/python3.10", "_frozen_importlib_external.FileFinder"),
        ("/usr/lib/python3.10/encodings", "_frozen_importlib_external.FileFinder"),
        ("/usr/lib/python310.zip", None),
    )
    _require(type(value) is list and len(value) == 4, CP_BOOT_V3_SCHEMA, "bootstrap importer cache is invalid")
    entries: list[tuple[str, str | None]] = []
    for row in value:
        _require(type(row) is dict and set(row) == {"path", "finder"} and type(row["path"]) is str and (type(row["finder"]) is str or row["finder"] is None), CP_BOOT_V3_SCHEMA, "bootstrap importer cache is invalid")
        entries.append((row["path"], row["finder"]))
    typed_entries = tuple(entries)
    _require(typed_entries[:3] == expected_cache and typed_entries[3] == (entry_path, None), CP_BOOT_V3_SCHEMA, "bootstrap typed entry-script cache is invalid")
    return projection_type(entry_path, typed_entries)


def _validate_bootstrap_v3(
    value: object, rows: object, startup_kat: object,
) -> tuple[ControllerBootstrapCacheProjectionV3, RoleBootstrapCacheProjectionV3]:
    required = {"source_path", "controller_entry", "role_map", "flags", "pre_path", "pre_meta_path", "pre_path_hooks", "controller_pre_importer_cache", "role_pre_importer_cache", "denied_zip", "post_path", "post_meta_path", "post_path_hooks", "post_importer_cache"}
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
    controller_cache = _bootstrap_cache_projection_v3(value["controller_pre_importer_cache"], value["controller_entry"], ControllerBootstrapCacheProjectionV3)
    role_cache = _bootstrap_cache_projection_v3(value["role_pre_importer_cache"], value["source_path"], RoleBootstrapCacheProjectionV3)
    _require(type(value["role_map"]) is list and len(value["role_map"]) == len(_ROLE_ORDER), CP_BOOT_V3_SCHEMA, "execution closure role map is invalid")
    _require(type(rows) is list and len(rows) == len(_ROLE_ORDER), CP_BOOT_V3_SCHEMA, "execution closure launch rows are invalid")
    for mapping, launch, role, table_row in zip(value["role_map"], rows, _ROLE_ORDER, tables.LAUNCH_ROLE_ROWS_V3, strict=True):
        _require(type(mapping) is dict and set(mapping) == {"role", "source_path"} and mapping == {"role": role, "source_path": table_row.source_path}, CP_BOOT_V3_SCHEMA, "execution closure role map entry is invalid")
        _require(type(launch) is dict and set(launch) == {"role", "source_path"} and launch == mapping, CP_BOOT_V3_SCHEMA, "execution closure launch row is invalid")
    return controller_cache, role_cache


def parse_execution_closure_v3(raw: object) -> ExecutionClosureV3:
    """Parse the complete typed execution-closure carrier before predecessor joins."""

    _require(type(raw) is dict and set(raw) == _EXECUTION_CLOSURE_KEYS, CP_BOOT_V3_SCHEMA, "execution closure fields are invalid")
    _require(raw["schema"] == EXECUTION_CLOSURE_V3_SCHEMA, CP_BOOT_V3_SCHEMA, "execution closure schema is invalid")
    frozen_startup = _freeze_json(raw["startup_kat"])
    assert type(frozen_startup) is FrozenJsonObjectV3
    _validate_startup_kat_v3(frozen_startup)
    startup_kat = _thaw_json(frozen_startup)
    controller_cache, role_cache = _validate_bootstrap_v3(raw["bootstrap"], raw["launch_rows"], startup_kat)
    _require(raw["import_roots"] == list(_PYTHON_ROOTS) and raw["native_loader_roots"] == list(_NATIVE_LOADER_ROOTS), CP_BOOT_V3_SCHEMA, "execution closure roots are invalid")
    arrays = ("loader_controls", "eligible_files", "jit_derivations", "expected_outputs", "cache_selectors")
    _require(all(type(raw[key]) is list for key in arrays), CP_BOOT_V3_SCHEMA, "execution closure collection is invalid")
    graph = raw["executable_graph"]
    _require(type(graph) is dict and set(graph) == _GRAPH_KEYS_V3, CP_BOOT_V3_SCHEMA, "executable graph fields are invalid")
    _require(graph["schema"] == _GRAPH_SCHEMA_V3 and type(graph["alias_hop_limit"]) is int and graph["alias_hop_limit"] == 40, CP_BOOT_V3_SCHEMA, "executable graph schema is invalid")
    _require(all(type(graph[key]) is list for key in ("entrypoints", "nodes", "aliases", "controls", "declarations", "edges")), CP_BOOT_V3_SCHEMA, "executable graph collections are invalid")
    frozen_bootstrap = _freeze_json(raw["bootstrap"])
    assert type(frozen_bootstrap) is FrozenJsonObjectV3
    frozen_rows = tuple(_freeze_json(item) for item in raw["launch_rows"])
    assert all(type(item) is FrozenJsonObjectV3 for item in frozen_rows)
    frozen_graph = _freeze_json(graph)
    assert type(frozen_graph) is FrozenJsonObjectV3
    return ExecutionClosureV3(raw["schema"], frozen_startup, frozen_bootstrap, controller_cache, role_cache, frozen_rows, tuple(raw["import_roots"]), tuple(raw["native_loader_roots"]), *[tuple(_freeze_json(item) for item in raw[key]) for key in arrays], frozen_graph)


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
class ProcessAuthoritySnapshotV3:
    boot_roots: tuple[str, ...]
    process_nodes: tuple[tuple[object, ...], ...]
    process_edges: tuple[tuple[str, str, str, str, str], ...]
    network_policy: tuple[tuple[str, str], ...]
    capability_policy: tuple[tuple[str, tuple[str, ...], tuple[str, ...], bool], ...]


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
class ExecutableGraphMeasuredFileNodeSnapshotV3:
    id: str
    kind: str
    image: str
    path: str
    sha256: str
    size_bytes: int
    mode: int
    content_kind: str
    semantic_tags: tuple[str, ...]
    input_id: str


@dataclass(frozen=True)
class ExecutableGraphMeasuredDirectoryNodeSnapshotV3:
    id: str
    kind: str
    image: str
    path: str
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True)
class ExecutableGraphJitDerivationNodeSnapshotV3:
    id: str
    kind: str
    derivation_sha256: str


@dataclass(frozen=True)
class ExecutableGraphJitOutputNodeSnapshotV3:
    id: str
    kind: str
    derivation_sha256: str
    output_name: str
    path: str
    sha256: str
    size_bytes: int
    mode: int


@dataclass(frozen=True)
class ExecutableGraphAliasRowV3:
    image: str
    path: str
    target: str
    resolved_id: str
    hop_count: int
    chain: tuple[str, ...]


@dataclass(frozen=True)
class ExecutableGraphPythonLoaderRowV3:
    loader: str
    suffixes: tuple[str, ...]


@dataclass(frozen=True)
class ExecutableGraphPythonLoaderDetailsSnapshotV3:
    finder: str
    loaders: tuple[ExecutableGraphPythonLoaderRowV3, ...]


@dataclass(frozen=True)
class ExecutableGraphPythonStartupControlRowV3:
    kind: str
    phase: str
    ordinal: int
    identity: str | None
    path: str | None
    path_kind: str | None
    finder: str | None
    loader_details: ExecutableGraphPythonLoaderDetailsSnapshotV3 | None
    declaration_kind: str
    declaration_ref: str


@dataclass(frozen=True)
class ExecutableGraphPythonLoadingControlRowV3:
    kind: str
    phase: str
    ordinal: int
    owner_id: str
    read_only: bool
    contributed_paths: tuple[str, ...]
    imports: tuple[str, ...]
    hooks: tuple[str, ...]
    declaration_kind: str
    declaration_ref: str


@dataclass(frozen=True)
class ExecutableGraphElfControlValueV3:
    requested_path: str
    resolved_id: str
    alias_chain: tuple[str, ...]


@dataclass(frozen=True)
class ExecutableGraphElfControlRowV3:
    kind: str
    owner_id: str
    ordinal: int
    value: ExecutableGraphElfControlValueV3
    declaration_kind: str
    declaration_ref: str


@dataclass(frozen=True)
class ExecutableGraphSourceProjectionV3:
    schema: str
    source_kind: str
    phase: str | None
    kind: str
    ordinal: int
    payload: FrozenJsonValueV3


@dataclass(frozen=True)
class ExecutableGraphDeclarationRowV3:
    id: str
    kind: str
    owner_id: str
    order_group: str
    ordinal: int
    requested_path: str | None
    target_id: str
    alias_chain: tuple[str, ...]


@dataclass(frozen=True)
class ExecutableGraphEdgeRowV3:
    id: str
    kind: str
    from_id: str
    to_id: str
    order_group: str
    ordinal: int
    requested_path: str | None
    resolved_id: str
    alias_chain: tuple[str, ...]
    declaration_kind: str
    declaration_ref: str


@dataclass(frozen=True)
class ExecutableGraphSnapshotV3:
    schema: str
    alias_hop_limit: int
    entrypoints: tuple[str, ...]
    nodes: tuple[object, ...]
    aliases: tuple[ExecutableGraphAliasRowV3, ...]
    controls: tuple[object, ...]
    declarations: tuple[ExecutableGraphDeclarationRowV3, ...]
    edges: tuple[ExecutableGraphEdgeRowV3, ...]
    source_projections: tuple[ExecutableGraphSourceProjectionV3, ...]


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
    controller_bootstrap_cache: ControllerBootstrapCacheProjectionV3
    role_bootstrap_cache: RoleBootstrapCacheProjectionV3
    loader_controls: tuple[LoaderControlSnapshotV3, ...]
    eligible_files: tuple[EligibleFileSnapshotV3, ...]
    jit_derivations: tuple[JitDerivationSnapshotV3, ...]
    cache_selectors: tuple[CacheSelectorSnapshotV3, ...]
    executable_graph: ExecutableGraphSnapshotV3


@dataclass(frozen=True)
class SemanticSnapshotsV3:
    source_digests: SourceDigestsV3
    storage: StorageSnapshotV3
    kernel_identity: KernelIdentitySnapshotV3
    module_authority: ModuleAuthoritySnapshotV3
    control_inventory: ControlInventorySnapshotV3
    launch_projection: LaunchProjectionV3
    stage2_controller: Stage2ControllerSnapshotV3
    process_authority: ProcessAuthoritySnapshotV3
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
    expected_role: str = "runtime_tree_input",
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
    _launch_require(lock_input.role == expected_role, f"{label} source role disagrees")
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
        and closure["logical_role"] == expected_role
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


def _process_node_row_v3(node: object) -> tuple[object, ...]:
    return (
        node.id, node.kind, node.path, node.sha256, node.argv,
        node.network_scope, node.capabilities, node.source_input_id,
    )


def _process_edge_row_v3(edge: object) -> tuple[str, str, str, str, str]:
    return edge.from_id, edge.to_id, edge.kind, edge.origin_path, edge.origin_key


def _process_authority_snapshot_v3(
    parsed: ParsedPredecessorsV3, interpreter_input: object,
    exec_source: LaunchSourceProjectionV3,
) -> ProcessAuthoritySnapshotV3:
    role_nodes = tuple(
        (
            row.role, row.process_kind, row.interpreter_path, interpreter_input.sha256,
            row.argv, row.expected_network_scope, row.expected_process_capabilities,
            interpreter_input.id,
        )
        for row in tables.LAUNCH_ROLE_ROWS_V3
    )
    expected_nodes = tuple(sorted((
        *role_nodes,
        (
            "unit:spp.service", "unit", "spp.service", None, (), "none", (), None,
        ),
        (
            "exec:/usr/bin/spp", "exec", exec_source.path, exec_source.sha256,
            (exec_source.path,), "none", (), exec_source.source_input_id,
        ),
    ), key=lambda row: row[0]))
    expected_edges = tuple(sorted((
        *(
            (
                "unit:spp.service", row.role, "script_interpreter", row.source_path,
                "stage2-launch",
            )
            for row in tables.LAUNCH_ROLE_ROWS_V3
        ),
        (
            "unit:spp.service", "exec:/usr/bin/spp", "unit_exec", "spp.service",
            "ExecStart",
        ),
    )))
    expected_network = tuple(sorted((
        *((row.role, row.expected_network_scope) for row in tables.LAUNCH_ROLE_ROWS_V3),
        ("exec:/usr/bin/spp", "none"),
        ("unit:spp.service", "none"),
    )))
    expected_capability = tuple(sorted(
        (
            row.role, row.expected_capability_bounding_set,
            row.expected_ambient_capabilities, row.expected_no_new_privileges,
        )
        for row in tables.LAUNCH_ROLE_ROWS_V3
    ))
    actual_nodes = tuple(_process_node_row_v3(node) for node in parsed.policy.process_nodes)
    actual_edges = tuple(_process_edge_row_v3(edge) for edge in parsed.policy.process_edges)
    actual_network = tuple(sorted(parsed.policy.network_policy.items()))
    actual_capability = tuple(sorted(
        (
            role, value.capability_bounding_set, value.ambient_capabilities,
            value.no_new_privileges,
        )
        for role, value in parsed.policy.capability_policy.items()
    ))
    _launch_require(len(actual_nodes) == 7, "process-node cardinality disagrees")
    _launch_require(len(actual_edges) == 6, "process-edge cardinality disagrees")
    _launch_require(parsed.policy.boot_roots == ("unit:spp.service",), "process boot roots disagree")
    _launch_require(len(actual_network) == 7, "network-policy cardinality disagrees")
    _launch_require(len(actual_capability) == 5, "capability-policy cardinality disagrees")
    _launch_require(actual_nodes == expected_nodes, "process-node authority disagrees")
    _launch_require(actual_edges == expected_edges, "process-edge authority disagrees")
    _launch_require(actual_network == expected_network, "network-policy authority disagrees")
    _launch_require(actual_capability == expected_capability, "capability-policy authority disagrees")
    return ProcessAuthoritySnapshotV3(
        parsed.policy.boot_roots, actual_nodes, actual_edges, actual_network,
        actual_capability,
    )


def _launch_projection_v3(
    parsed: ParsedPredecessorsV3,
) -> tuple[LaunchProjectionV3, Stage2ControllerSnapshotV3, ProcessAuthoritySnapshotV3]:
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
    exec_source = _runtime_source_projection_v3(
        parsed, path="/usr/bin/spp", label="stage2 executable",
        expected_role="final_systemd_stub",
    )
    process_authority = _process_authority_snapshot_v3(
        parsed, interpreter_input, exec_source,
    )
    return (
        LaunchProjectionV3(tuple(RoleLaunchSnapshotV3(row, source) for row, source in zip(tables.LAUNCH_ROLE_ROWS_V3, sources, strict=True))),
        Stage2ControllerSnapshotV3(controller, controller_source, interpreter_input.id, interpreter_input.sha256, interpreter_input.size_bytes, interpreter_placement.mode),
        process_authority,
    )


def _thaw_json(value: FrozenJsonValueV3) -> object:
    if type(value) is FrozenJsonObjectV3:
        return {key: _thaw_json(item) for key, item in value.items}
    if type(value) is tuple:
        return [_thaw_json(item) for item in value]
    return value


def _frame_v3(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _graph_path_v3(value: object, message: str = "executable graph path is invalid") -> str:
    _require(type(value) is str and unicodedata.normalize("NFC", value) == value and value.startswith("/"), CP_BOOT_V3_SCHEMA, message)
    _require(not any(character in value for character in ("\x00", "\\")) and not any(ord(character) < 32 or ord(character) == 127 for character in value), CP_BOOT_V3_SCHEMA, message)
    _require(value == "/" or (not value.endswith("/") and all(part not in ("", ".", "..") for part in value.split("/")[1:])), CP_BOOT_V3_SCHEMA, message)
    return value


def _graph_sha256_v3(value: object, message: str = "executable graph digest is invalid") -> str:
    _require(type(value) is str and len(value) == 64 and all(character in "0123456789abcdef" for character in value), CP_BOOT_V3_SCHEMA, message)
    return value


def _graph_file_id_v3(image: str, path: str) -> str:
    return f"file:{image}:{path}"


def _graph_directory_id_v3(image: str, path: str) -> str:
    return f"dir:{image}:{path}"


def _graph_derivation_id_v3(derivation_sha256: str) -> str:
    return "derivation:" + derivation_sha256


def _graph_output_id_v3(derivation_sha256: str, output_name: str) -> str:
    return f"jit:{derivation_sha256}:{output_name}"


def _graph_source_projection_digest_v3(
    *, source_kind: str, phase: str | None, kind: str, ordinal: int, payload: object,
) -> str:
    """Frame the acyclic source evidence named by executable-graph references."""

    _require(source_kind in _GRAPH_SOURCE_KINDS_V3 and (phase is None or phase in ("controller_pre", "role_pre", "post_bootstrap")) and type(kind) is str and kind and type(ordinal) is int and ordinal >= 0, CP_BOOT_V3_SCHEMA, "executable graph source projection is invalid")
    material = {
        "schema": _GRAPH_SOURCE_SCHEMA_V3,
        "source_kind": source_kind,
        "phase": phase,
        "kind": kind,
        "ordinal": ordinal,
        "payload": payload,
    }
    return _sha256(b"sol-spp-executable-graph-source/v1\0" + _frame_v3(boot.canonical_dumps(material)))


def _graph_source_projection_v3(
    *, source_kind: str, phase: str | None, kind: str, ordinal: int, payload: object,
) -> ExecutableGraphSourceProjectionV3:
    frozen = _freeze_json(payload)
    return ExecutableGraphSourceProjectionV3(
        _GRAPH_SOURCE_SCHEMA_V3, source_kind, phase, kind, ordinal, frozen,
    )


def _graph_source_ref_v3(value: ExecutableGraphSourceProjectionV3) -> str:
    digest = _graph_source_projection_digest_v3(
        source_kind=value.source_kind, phase=value.phase, kind=value.kind,
        ordinal=value.ordinal, payload=_thaw_json(value.payload),
    )
    return f"source:{value.source_kind}:{digest}"


def _graph_declaration_id_v3(
    *, kind: str, owner_id: str, order_group: str, ordinal: int,
    requested_path: str | None, target_id: str, alias_chain: tuple[str, ...],
) -> str:
    return _sha256(boot.canonical_dumps({
        "kind": kind, "owner_id": owner_id, "order_group": order_group,
        "ordinal": ordinal, "requested_path": requested_path, "target_id": target_id,
        "alias_chain": list(alias_chain),
    }))


def _graph_edge_id_v3(
    *, kind: str, from_id: str, to_id: str, order_group: str, ordinal: int,
    requested_path: str | None, resolved_id: str, alias_chain: tuple[str, ...],
    declaration_kind: str, declaration_ref: str,
) -> str:
    return _sha256(boot.canonical_dumps({
        "kind": kind, "from_id": from_id, "to_id": to_id, "order_group": order_group,
        "ordinal": ordinal, "requested_path": requested_path, "resolved_id": resolved_id,
        "alias_chain": list(alias_chain), "declaration_kind": declaration_kind,
        "declaration_ref": declaration_ref,
    }))


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


def _graph_plain_node_v3(value: object) -> object:
    _require(type(value) is dict and type(value.get("kind")) is str and value["kind"] in _GRAPH_NODE_KINDS_V3, CP_BOOT_V3_SCHEMA, "executable graph node is invalid")
    kind = value["kind"]
    if kind == "measured_file":
        keys = {"id", "kind", "image", "path", "sha256", "size_bytes", "mode", "content_kind", "semantic_tags", "input_id"}
        _require(set(value) == keys and type(value["id"]) is str and type(value["image"]) is str and value["image"] and type(value["input_id"]) is str and value["input_id"] and type(value["size_bytes"]) is int and value["size_bytes"] >= 0 and type(value["mode"]) is int and 0 <= value["mode"] <= 0o7777 and value["content_kind"] in _CONTENT_KINDS, CP_BOOT_V3_SCHEMA, "measured-file graph node is invalid")
        path = _graph_path_v3(value["path"])
        digest = _graph_sha256_v3(value["sha256"])
        tags = _require_sorted_unique_strings(value["semantic_tags"], CP_BOOT_V3_SCHEMA, "measured-file graph tags are invalid")
        _require(set(tags) <= _SEMANTIC_TAGS and value["id"] == _graph_file_id_v3(value["image"], path), CP_BOOT_V3_SCHEMA, "measured-file graph identity is invalid")
        return ExecutableGraphMeasuredFileNodeSnapshotV3(value["id"], kind, value["image"], path, digest, value["size_bytes"], value["mode"], value["content_kind"], tags, value["input_id"])
    if kind == "measured_directory":
        keys = {"id", "kind", "image", "path", "mode", "uid", "gid"}
        _require(set(value) == keys and type(value["id"]) is str and type(value["image"]) is str and value["image"] and type(value["mode"]) is int and 0 <= value["mode"] <= 0o7777 and type(value["uid"]) is int and value["uid"] >= 0 and type(value["gid"]) is int and value["gid"] >= 0, CP_BOOT_V3_SCHEMA, "measured-directory graph node is invalid")
        path = _graph_path_v3(value["path"])
        _require(value["id"] == _graph_directory_id_v3(value["image"], path), CP_BOOT_V3_SCHEMA, "measured-directory graph identity is invalid")
        return ExecutableGraphMeasuredDirectoryNodeSnapshotV3(value["id"], kind, value["image"], path, value["mode"], value["uid"], value["gid"])
    if kind == "jit_derivation":
        _require(set(value) == {"id", "kind", "derivation_sha256"} and type(value["id"]) is str, CP_BOOT_V3_SCHEMA, "JIT derivation graph node is invalid")
        digest = _graph_sha256_v3(value["derivation_sha256"])
        _require(value["id"] == _graph_derivation_id_v3(digest), CP_BOOT_V3_SCHEMA, "JIT derivation graph identity is invalid")
        return ExecutableGraphJitDerivationNodeSnapshotV3(value["id"], kind, digest)
    _require(set(value) == {"id", "kind", "derivation_sha256", "output_name", "path", "sha256", "size_bytes", "mode"} and type(value["id"]) is str and type(value["output_name"]) is str and _OUTPUT_NAME_RE.fullmatch(value["output_name"]) is not None and type(value["size_bytes"]) is int and value["size_bytes"] >= 0 and type(value["mode"]) is int and 0 <= value["mode"] <= 0o7777, CP_BOOT_V3_SCHEMA, "JIT output graph node is invalid")
    digest = _graph_sha256_v3(value["derivation_sha256"])
    path = _graph_path_v3(value["path"])
    output_digest = _graph_sha256_v3(value["sha256"])
    _require(value["id"] == _graph_output_id_v3(digest, value["output_name"]), CP_BOOT_V3_SCHEMA, "JIT output graph identity is invalid")
    return ExecutableGraphJitOutputNodeSnapshotV3(value["id"], kind, digest, value["output_name"], path, output_digest, value["size_bytes"], value["mode"])


def _graph_alias_rows_v3(
    raw: object, parsed: ParsedPredecessorsV3, node_ids: dict[str, object],
) -> tuple[ExecutableGraphAliasRowV3, ...]:
    _require(type(raw) is list, CP_BOOT_V3_SCHEMA, "executable graph aliases are invalid")
    lock_aliases: dict[tuple[str, str], object] = {}
    for item in parsed.lock.inputs:
        for placement in item.placements:
            if placement.node_type == "symlink":
                lock_aliases[(placement.image, placement.path)] = placement
    policy_aliases = {
        (image, node.path): node
        for image, policy_image in parsed.policy.images.items()
        for node in policy_image.nodes if node.node_type == "symlink"
    }
    closure_aliases = {entry["path"]: entry for entry in parsed.runtime_closure["entries"] if entry["node_type"] == "symlink"}
    rows: list[ExecutableGraphAliasRowV3] = []
    by_path: dict[tuple[str, str], ExecutableGraphAliasRowV3] = {}
    for value in raw:
        _require(type(value) is dict and set(value) == {"image", "path", "target", "resolved_id", "hop_count", "chain"} and type(value["image"]) is str and value["image"] and type(value["target"]) is str and value["target"] and type(value["resolved_id"]) is str and type(value["hop_count"]) is int and not isinstance(value["hop_count"], bool) and 1 <= value["hop_count"] <= 40 and type(value["chain"]) is list, CP_BOOT_V3_SCHEMA, "executable graph alias is invalid")
        path = _graph_path_v3(value["path"], "executable graph alias path is invalid")
        _require(unicodedata.normalize("NFC", value["target"]) == value["target"] and not any(character in value["target"] for character in ("\x00", "\\")) and not any(ord(character) < 32 or ord(character) == 127 for character in value["target"]), CP_BOOT_V3_SCHEMA, "executable graph alias target is invalid")
        chain = tuple(_graph_path_v3(item, "executable graph alias chain is invalid") for item in value["chain"])
        _require(chain and chain[0] == path and len(chain) == value["hop_count"] and len(set(chain)) == len(chain), CP_BOOT_V3_SCHEMA, "executable graph alias chain is invalid")
        key = (value["image"], path)
        _require(key not in by_path and key in lock_aliases and key in policy_aliases and path in closure_aliases, CP_BOOT_V3_BINDING, "executable graph alias predecessor is invalid")
        placement = lock_aliases[key]
        policy_node = policy_aliases[key]
        closure = closure_aliases[path]
        _require(placement.target == value["target"] == policy_node.target == closure["symlink_target"] and placement.mode == policy_node.mode == closure["mode"] and placement.uid == policy_node.uid == closure["uid"] and placement.gid == policy_node.gid == closure["gid"] and not (placement.mode & 0o222), CP_BOOT_V3_BINDING, "executable graph alias predecessor disagrees")
        row = ExecutableGraphAliasRowV3(value["image"], path, value["target"], value["resolved_id"], value["hop_count"], chain)
        rows.append(row)
        by_path[key] = row
    _require(tuple((row.image, row.path) for row in rows) == tuple(sorted((row.image, row.path) for row in rows)), CP_BOOT_V3_SCHEMA, "executable graph aliases are not canonical")
    _require(set(by_path) == set(lock_aliases) == set(policy_aliases), CP_BOOT_V3_BINDING, "executable graph aliases do not close predecessor aliases")
    for row in rows:
        current = row.path
        followed: list[str] = []
        for hop in row.chain:
            _require(hop == current, CP_BOOT_V3_BINDING, "executable graph alias chain literal path disagrees")
            followed.append(hop)
            alias = by_path.get((row.image, current))
            _require(alias is not None, CP_BOOT_V3_BINDING, "executable graph alias chain is unlisted")
            target = alias.target if alias.target.startswith("/") else posixpath.join(posixpath.dirname(current), alias.target)
            current = posixpath.normpath(target)
            _graph_path_v3(current, "executable graph alias target escapes")
            if (row.image, current) not in by_path:
                break
        _require(tuple(followed) == row.chain and len(followed) == row.hop_count and (row.image, current) not in by_path, CP_BOOT_V3_BINDING, "executable graph alias chain is cyclic or incomplete")
        terminal = node_ids.get(row.resolved_id)
        _require(terminal is not None and getattr(terminal, "image", row.image) == row.image and getattr(terminal, "path", None) == current and not isinstance(terminal, ExecutableGraphJitOutputNodeSnapshotV3), CP_BOOT_V3_BINDING, "executable graph alias terminal is invalid")
    return tuple(rows)


def _graph_startup_control_values_v3(
    closure: ExecutionClosureV3,
) -> tuple[tuple[ExecutableGraphPythonStartupControlRowV3, ...], tuple[ExecutableGraphSourceProjectionV3, ...]]:
    startup = _thaw_json(closure.startup_kat)
    bootstrap = _thaw_json(closure.bootstrap)
    assert type(startup) is dict and type(bootstrap) is dict
    observation = startup["capture"]["observation"]
    assert type(observation) is dict
    values: list[ExecutableGraphPythonStartupControlRowV3] = []
    sources: list[ExecutableGraphSourceProjectionV3] = []

    def append_row(kind: str, phase: str, ordinal: int, payload: object, declaration_kind: str, *, identity: str | None = None, path: str | None = None, path_kind: str | None = None, finder: str | None = None, details: ExecutableGraphPythonLoaderDetailsSnapshotV3 | None = None) -> None:
        source = _graph_source_projection_v3(source_kind=declaration_kind, phase=phase, kind=kind, ordinal=ordinal, payload=payload)
        sources.append(source)
        values.append(ExecutableGraphPythonStartupControlRowV3(kind, phase, ordinal, identity, path, path_kind, finder, details, declaration_kind, _graph_source_ref_v3(source)))

    def loader_details(value: object) -> ExecutableGraphPythonLoaderDetailsSnapshotV3 | None:
        if value is None:
            return None
        assert type(value) is dict
        return ExecutableGraphPythonLoaderDetailsSnapshotV3(value["finder"], tuple(ExecutableGraphPythonLoaderRowV3(item["loader"], tuple(item["suffixes"])) for item in value["loaders"]))

    for phase, cache_key, source_kind in (
        ("controller_pre", "controller_pre_importer_cache", "controller_cache_projection"),
        ("role_pre", "role_pre_importer_cache", "role_cache_projection"),
    ):
        for ordinal, path in enumerate(observation["path"]):
            append_row("python_search_path", phase, ordinal, {"path": path}, "startup_receipt", path=path, path_kind="denied_zip" if path == "/usr/lib/python310.zip" else "measured_directory")
        for ordinal, identity in enumerate(observation["meta_path"]):
            append_row("python_meta_path", phase, ordinal, {"identity": identity}, "startup_receipt", identity=identity)
        for ordinal, hook in enumerate(observation["path_hooks"]):
            append_row("python_path_hook", phase, ordinal, hook, "startup_receipt", identity=hook["identity"], details=loader_details(hook["loader_details"]))
        for ordinal, cache in enumerate(bootstrap[cache_key]):
            path = cache["path"]
            append_row("python_importer_cache", phase, ordinal, cache, source_kind, path=path, path_kind="denied_zip" if path == "/usr/lib/python310.zip" else ("measured_file" if cache["finder"] is None else "measured_directory"), finder=cache["finder"])
    for ordinal, path in enumerate(bootstrap["post_path"]):
        append_row("python_search_path", "post_bootstrap", ordinal, {"path": path}, "bootstrap_projection", path=path, path_kind="measured_directory")
    for ordinal, identity in enumerate(bootstrap["post_meta_path"]):
        append_row("python_meta_path", "post_bootstrap", ordinal, {"identity": identity}, "bootstrap_projection", identity=identity)
    for ordinal, hook in enumerate(bootstrap["post_path_hooks"]):
        append_row("python_path_hook", "post_bootstrap", ordinal, hook, "bootstrap_projection", identity=hook["identity"], details=loader_details(hook["loader_details"]))
    for ordinal, cache in enumerate(bootstrap["post_importer_cache"]):
        append_row("python_importer_cache", "post_bootstrap", ordinal, cache, "bootstrap_projection", path=cache["path"], path_kind="measured_file" if cache["finder"] is None else "measured_directory", finder=cache["finder"])
    return tuple(values), tuple(sources)


def _graph_startup_control_raw_v3(value: ExecutableGraphPythonStartupControlRowV3) -> dict[str, object]:
    details = None if value.loader_details is None else {
        "finder": value.loader_details.finder,
        "loaders": [{"loader": row.loader, "suffixes": list(row.suffixes)} for row in value.loader_details.loaders],
    }
    return {"kind": value.kind, "phase": value.phase, "ordinal": value.ordinal, "identity": value.identity, "path": value.path, "path_kind": value.path_kind, "finder": value.finder, "loader_details": details, "declaration_kind": value.declaration_kind, "declaration_ref": value.declaration_ref}


def _graph_loading_control_values_v3(
    controls: tuple[LoaderControlSnapshotV3, ...], eligible_by_path: dict[str, EligibleFileSnapshotV3],
) -> tuple[tuple[ExecutableGraphPythonLoadingControlRowV3, ...], tuple[ExecutableGraphSourceProjectionV3, ...]]:
    rows: list[ExecutableGraphPythonLoadingControlRowV3] = []
    sources: list[ExecutableGraphSourceProjectionV3] = []
    for ordinal, control in enumerate(controls):
        source = _graph_source_projection_v3(
            source_kind="loader_control", phase=None, kind=control.kind, ordinal=ordinal,
            payload={"path": control.path, "kind": control.kind, "read_only": control.read_only, "contributed_paths": list(control.contributed_paths), "imports": list(control.imports), "hooks": list(control.hooks)},
        )
        sources.append(source)
        owner = eligible_by_path[control.path]
        rows.append(ExecutableGraphPythonLoadingControlRowV3(
            "python_" + control.kind, "runtime_startup", ordinal,
            _graph_file_id_v3(owner.image, owner.path), control.read_only,
            control.contributed_paths, control.imports, control.hooks,
            "loader_control", _graph_source_ref_v3(source),
        ))
    return tuple(rows), tuple(sources)


def _graph_loading_control_raw_v3(value: ExecutableGraphPythonLoadingControlRowV3) -> dict[str, object]:
    return {"kind": value.kind, "phase": value.phase, "ordinal": value.ordinal, "owner_id": value.owner_id, "read_only": value.read_only, "contributed_paths": list(value.contributed_paths), "imports": list(value.imports), "hooks": list(value.hooks), "declaration_kind": value.declaration_kind, "declaration_ref": value.declaration_ref}


def _graph_node_raw_v3(value: object) -> dict[str, object]:
    if isinstance(value, ExecutableGraphMeasuredFileNodeSnapshotV3):
        return {"id": value.id, "kind": value.kind, "image": value.image, "path": value.path, "sha256": value.sha256, "size_bytes": value.size_bytes, "mode": value.mode, "content_kind": value.content_kind, "semantic_tags": list(value.semantic_tags), "input_id": value.input_id}
    if isinstance(value, ExecutableGraphMeasuredDirectoryNodeSnapshotV3):
        return {"id": value.id, "kind": value.kind, "image": value.image, "path": value.path, "mode": value.mode, "uid": value.uid, "gid": value.gid}
    if isinstance(value, ExecutableGraphJitDerivationNodeSnapshotV3):
        return {"id": value.id, "kind": value.kind, "derivation_sha256": value.derivation_sha256}
    assert isinstance(value, ExecutableGraphJitOutputNodeSnapshotV3)
    return {"id": value.id, "kind": value.kind, "derivation_sha256": value.derivation_sha256, "output_name": value.output_name, "path": value.path, "sha256": value.sha256, "size_bytes": value.size_bytes, "mode": value.mode}


def _graph_expected_nodes_v3(
    parsed: ParsedPredecessorsV3, eligible: tuple[EligibleFileSnapshotV3, ...],
    derivations: tuple[JitDerivationSnapshotV3, ...], selectors: tuple[CacheSelectorSnapshotV3, ...],
) -> tuple[object, ...]:
    required_tags = {
        "launch_executable", "importable_module", "python_loading_control", "native_extension",
        "dynamic_library", "compiler", "compiler_source", "model_code", "plugin", "jit_cache",
    }
    noncode_inputs = {
        item.path for derivation in derivations for item in derivation.inputs
        if item.kind in ("configuration", "model")
    }
    nodes: list[object] = []
    for item in eligible:
        if required_tags & set(item.semantic_tags) or item.path in noncode_inputs:
            nodes.append(ExecutableGraphMeasuredFileNodeSnapshotV3(
                _graph_file_id_v3(item.image, item.path), "measured_file", item.image, item.path,
                item.sha256, item.size_bytes, item.mode, item.content_kind, item.semantic_tags, item.input_id,
            ))
    root_paths = set(_PYTHON_ROOTS + _NATIVE_LOADER_ROOTS)
    for image, policy_image in parsed.policy.images.items():
        for node in policy_image.nodes:
            if node.node_type == "directory" and node.path in root_paths:
                closure_matches = [entry for entry in parsed.runtime_closure["entries"] if entry["path"] == node.path]
                _require(len(closure_matches) == 1, CP_BOOT_V3_BINDING, "executable graph directory closure identity is invalid")
                closure = closure_matches[0]
                _require(closure["node_type"] == "directory" and (node.mode, node.uid, node.gid) == (closure["mode"], closure["uid"], closure["gid"]) and not (node.mode & 0o222), CP_BOOT_V3_BINDING, "executable graph directory is not measured read-only")
                nodes.append(ExecutableGraphMeasuredDirectoryNodeSnapshotV3(_graph_directory_id_v3(image, node.path), "measured_directory", image, node.path, node.mode, node.uid, node.gid))
    selector_by_identity = {(selector.derivation_sha256, selector.output_name): selector for selector in selectors}
    eligible_by_path = {item.path: item for item in eligible}
    for derivation in derivations:
        nodes.append(ExecutableGraphJitDerivationNodeSnapshotV3(_graph_derivation_id_v3(derivation.derivation_sha256), "jit_derivation", derivation.derivation_sha256))
        selector = selector_by_identity.get((derivation.derivation_sha256, derivation.output_name))
        output_path = selector.path if selector is not None else "/run/spp-jit/" + derivation.derivation_sha256 + "/" + derivation.output_name
        if selector is not None:
            cached = eligible_by_path.get(selector.path)
            _require(cached is not None and (cached.sha256, cached.size_bytes, cached.mode) == (derivation.output_sha256, derivation.output_size_bytes, derivation.output_mode), CP_BOOT_V3_BINDING, "executable graph JIT output cache identity disagrees")
        nodes.append(ExecutableGraphJitOutputNodeSnapshotV3(_graph_output_id_v3(derivation.derivation_sha256, derivation.output_name), "jit_output", derivation.derivation_sha256, derivation.output_name, output_path, derivation.output_sha256, derivation.output_size_bytes, derivation.output_mode))
    return tuple(sorted(nodes, key=lambda item: item.id.encode("utf-8")))


def _graph_script_edges_v3(
    eligible_by_path: dict[str, EligibleFileSnapshotV3],
) -> tuple[tuple[ExecutableGraphEdgeRowV3, ...], tuple[ExecutableGraphSourceProjectionV3, ...]]:
    paths = (
        tables.STAGE2_CONTROLLER_ROW_V3.source_path,
        "/usr/lib/spp/conf_proc_spp_role_bootstrap.py",
        *(row.source_path for row in tables.LAUNCH_ROLE_ROWS_V3),
    )
    interpreter = eligible_by_path["/usr/bin/python3.10"]
    edges: list[ExecutableGraphEdgeRowV3] = []
    sources: list[ExecutableGraphSourceProjectionV3] = []
    for ordinal, path in enumerate(paths):
        source = eligible_by_path[path]
        projection = _graph_source_projection_v3(
            source_kind="process_authority", phase=None, kind="python_script", ordinal=ordinal,
            payload={"interpreter_path": interpreter.path, "source_input_id": source.input_id, "source_path": source.path, "source_sha256": source.sha256},
        )
        sources.append(projection)
        source_ref = _graph_source_ref_v3(projection)
        from_id = _graph_file_id_v3(interpreter.image, interpreter.path)
        to_id = _graph_file_id_v3(source.image, source.path)
        group = "python-script:" + source_ref
        edges.append(ExecutableGraphEdgeRowV3(
            _graph_edge_id_v3(kind="python_script", from_id=from_id, to_id=to_id, order_group=group, ordinal=0, requested_path=source.path, resolved_id=to_id, alias_chain=(), declaration_kind="process_authority", declaration_ref=source_ref),
            "python_script", from_id, to_id, group, 0, source.path, to_id, (), "process_authority", source_ref,
        ))
    return tuple(edges), tuple(sources)


def _graph_jit_edges_v3(
    raw_derivations: list[object], derivations: tuple[JitDerivationSnapshotV3, ...],
    eligible_by_path: dict[str, EligibleFileSnapshotV3], selectors: tuple[CacheSelectorSnapshotV3, ...],
) -> tuple[tuple[ExecutableGraphEdgeRowV3, ...], tuple[ExecutableGraphSourceProjectionV3, ...]]:
    edges: list[ExecutableGraphEdgeRowV3] = []
    projections: list[ExecutableGraphSourceProjectionV3] = []
    selectors_by_key = {(item.derivation_sha256, item.output_name): item for item in selectors}
    for record, derivation in zip(raw_derivations, derivations, strict=True):
        assert type(record) is dict
        derivation_id = _graph_derivation_id_v3(derivation.derivation_sha256)

        def add(kind: str, ordinal: int, payload: object, target_id: str, group: str) -> None:
            projection = _graph_source_projection_v3(source_kind="jit_derivation", phase=None, kind=kind, ordinal=ordinal, payload=payload)
            projections.append(projection)
            reference = _graph_source_ref_v3(projection)
            edges.append(ExecutableGraphEdgeRowV3(
                _graph_edge_id_v3(kind=kind, from_id=derivation_id, to_id=target_id, order_group=group, ordinal=ordinal, requested_path=None, resolved_id=target_id, alias_chain=(), declaration_kind="jit_derivation", declaration_ref=reference),
                kind, derivation_id, target_id, group, ordinal, None, target_id, (), "jit_derivation", reference,
            ))

        compiler = record["compiler"]
        loader = record["loader"]
        assert type(compiler) is dict and type(loader) is dict
        add("jit_compiler", 0, compiler, _graph_file_id_v3(compiler["image"], compiler["path"]), "jit-compiler:" + derivation_id)
        add("jit_loader", 0, loader, _graph_file_id_v3(loader["image"], loader["path"]), "jit-loader:" + derivation_id)
        for ordinal, item in enumerate(record["inputs"]):
            assert type(item) is dict
            add("jit_input", ordinal, item, _graph_file_id_v3(item["image"], item["path"]), "jit-input:" + derivation_id)
        output = record["output"]
        assert type(output) is dict
        output_id = _graph_output_id_v3(derivation.derivation_sha256, derivation.output_name)
        add("jit_output", 0, output, output_id, "jit-output:" + derivation_id)
        selector = selectors_by_key.get((derivation.derivation_sha256, derivation.output_name))
        if selector is not None:
            _require(selector.path in eligible_by_path, CP_BOOT_V3_BINDING, "JIT graph cache output is missing eligibility")
    return tuple(edges), tuple(projections)


def _graph_edge_raw_v3(value: ExecutableGraphEdgeRowV3) -> dict[str, object]:
    return {"id": value.id, "kind": value.kind, "from_id": value.from_id, "to_id": value.to_id, "order_group": value.order_group, "ordinal": value.ordinal, "requested_path": value.requested_path, "resolved_id": value.resolved_id, "alias_chain": list(value.alias_chain), "declaration_kind": value.declaration_kind, "declaration_ref": value.declaration_ref}


def _graph_resolve_edge_v3(
    *, requested_path: str | None, resolved_id: str, alias_chain: tuple[str, ...],
    aliases: tuple[ExecutableGraphAliasRowV3, ...], nodes_by_id: dict[str, object],
) -> None:
    _require(resolved_id in nodes_by_id, CP_BOOT_V3_BINDING, "executable graph edge target is unknown")
    if requested_path is None:
        _require(not alias_chain, CP_BOOT_V3_SCHEMA, "derivation graph edge must not carry an alias")
        return
    path = _graph_path_v3(requested_path, "executable graph edge requested path is invalid")
    if not alias_chain:
        _require(getattr(nodes_by_id[resolved_id], "path", None) == path, CP_BOOT_V3_BINDING, "executable graph edge terminal path disagrees")
        return
    matching = [row for row in aliases if row.path == path]
    _require(len(matching) == 1 and matching[0].chain == alias_chain and matching[0].resolved_id == resolved_id, CP_BOOT_V3_BINDING, "executable graph edge alias traversal disagrees")


def _graph_parse_declarations_v3(raw: object) -> tuple[ExecutableGraphDeclarationRowV3, ...]:
    _require(type(raw) is list, CP_BOOT_V3_SCHEMA, "executable graph declarations are invalid")
    rows: list[ExecutableGraphDeclarationRowV3] = []
    for value in raw:
        _require(type(value) is dict and set(value) == {"id", "kind", "owner_id", "order_group", "ordinal", "requested_path", "target_id", "alias_chain"} and type(value["id"]) is str and type(value["kind"]) is str and value["kind"] in _GRAPH_DECLARATION_KINDS_V3 and type(value["owner_id"]) is str and type(value["order_group"]) is str and value["order_group"] and type(value["ordinal"]) is int and not isinstance(value["ordinal"], bool) and value["ordinal"] >= 0 and (value["requested_path"] is None or type(value["requested_path"]) is str) and type(value["target_id"]) is str and type(value["alias_chain"]) is list, CP_BOOT_V3_SCHEMA, "executable graph declaration is invalid")
        requested = None if value["requested_path"] is None else _graph_path_v3(value["requested_path"], "executable graph declaration requested path is invalid")
        chain = tuple(_graph_path_v3(item, "executable graph declaration alias chain is invalid") for item in value["alias_chain"])
        _require(value["id"] == _graph_declaration_id_v3(kind=value["kind"], owner_id=value["owner_id"], order_group=value["order_group"], ordinal=value["ordinal"], requested_path=requested, target_id=value["target_id"], alias_chain=chain), CP_BOOT_V3_SCHEMA, "executable graph declaration digest is invalid")
        rows.append(ExecutableGraphDeclarationRowV3(value["id"], value["kind"], value["owner_id"], value["order_group"], value["ordinal"], requested, value["target_id"], chain))
    _require(tuple(row.id for row in rows) == tuple(sorted((row.id for row in rows), key=lambda item: item.encode("utf-8"))) and len({row.id for row in rows}) == len(rows), CP_BOOT_V3_SCHEMA, "executable graph declarations are not canonical")
    return tuple(rows)


def _graph_parse_edges_v3(raw: object) -> tuple[ExecutableGraphEdgeRowV3, ...]:
    _require(type(raw) is list, CP_BOOT_V3_SCHEMA, "executable graph edges are invalid")
    rows: list[ExecutableGraphEdgeRowV3] = []
    for value in raw:
        _require(type(value) is dict and set(value) == {"id", "kind", "from_id", "to_id", "order_group", "ordinal", "requested_path", "resolved_id", "alias_chain", "declaration_kind", "declaration_ref"} and type(value["id"]) is str and type(value["kind"]) is str and value["kind"] in _GRAPH_EDGE_KINDS_V3 and all(type(value[field]) is str and value[field] for field in ("from_id", "to_id", "order_group", "resolved_id", "declaration_kind", "declaration_ref")) and type(value["ordinal"]) is int and not isinstance(value["ordinal"], bool) and value["ordinal"] >= 0 and (value["requested_path"] is None or type(value["requested_path"]) is str) and type(value["alias_chain"]) is list, CP_BOOT_V3_SCHEMA, "executable graph edge is invalid")
        requested = None if value["requested_path"] is None else _graph_path_v3(value["requested_path"], "executable graph edge requested path is invalid")
        chain = tuple(_graph_path_v3(item, "executable graph edge alias chain is invalid") for item in value["alias_chain"])
        _require(value["id"] == _graph_edge_id_v3(kind=value["kind"], from_id=value["from_id"], to_id=value["to_id"], order_group=value["order_group"], ordinal=value["ordinal"], requested_path=requested, resolved_id=value["resolved_id"], alias_chain=chain, declaration_kind=value["declaration_kind"], declaration_ref=value["declaration_ref"]), CP_BOOT_V3_SCHEMA, "executable graph edge digest is invalid")
        rows.append(ExecutableGraphEdgeRowV3(value["id"], value["kind"], value["from_id"], value["to_id"], value["order_group"], value["ordinal"], requested, value["resolved_id"], chain, value["declaration_kind"], value["declaration_ref"]))
    _require(tuple(row.id for row in rows) == tuple(sorted((row.id for row in rows), key=lambda item: item.encode("utf-8"))) and len({row.id for row in rows}) == len(rows), CP_BOOT_V3_SCHEMA, "executable graph edges are not canonical")
    return tuple(rows)


def _graph_check_ordinals_v3(rows: tuple[object, ...], *, fields: tuple[str, ...], message: str) -> None:
    groups: dict[tuple[object, ...], list[int]] = {}
    for row in rows:
        groups.setdefault(tuple(getattr(row, field) for field in fields), []).append(getattr(row, "ordinal"))
    _require(all(sorted(values) == list(range(len(values))) for values in groups.values()), CP_BOOT_V3_BINDING, message)


def _graph_validate_declarative_edges_v3(
    declarations: tuple[ExecutableGraphDeclarationRowV3, ...], edges: tuple[ExecutableGraphEdgeRowV3, ...],
    nodes_by_id: dict[str, object], aliases: tuple[ExecutableGraphAliasRowV3, ...],
    entrypoints: tuple[str, ...],
) -> None:
    # Candidate/independent-inspector raw-byte agreement is the later gate for declared authority.
    declarations_by_id = {row.id: row for row in declarations}
    graph_edges = [row for row in edges if row.declaration_kind == "executable_graph"]
    _require(len(graph_edges) == len(declarations) and {row.declaration_ref for row in graph_edges} == set(declarations_by_id), CP_BOOT_V3_BINDING, "executable graph declarations and edges disagree")
    for edge in graph_edges:
        declaration = declarations_by_id[edge.declaration_ref]
        _require((edge.kind, edge.from_id, edge.to_id, edge.order_group, edge.ordinal, edge.requested_path, edge.resolved_id, edge.alias_chain) == (declaration.kind, declaration.owner_id, declaration.target_id, declaration.order_group, declaration.ordinal, declaration.requested_path, declaration.target_id, declaration.alias_chain), CP_BOOT_V3_BINDING, "executable graph declaration and edge disagree")
    _graph_check_ordinals_v3(declarations, fields=("order_group",), message="executable graph declaration ordinals are invalid")
    _graph_check_ordinals_v3(edges, fields=("order_group",), message="executable graph edge ordinals are invalid")
    for edge in edges:
        _require(edge.from_id in nodes_by_id and edge.to_id in nodes_by_id and edge.resolved_id == edge.to_id and edge.from_id != edge.to_id, CP_BOOT_V3_BINDING, "executable graph edge endpoints are invalid")
        _graph_resolve_edge_v3(requested_path=edge.requested_path, resolved_id=edge.resolved_id, alias_chain=edge.alias_chain, aliases=aliases, nodes_by_id=nodes_by_id)
        source = nodes_by_id[edge.from_id]
        target = nodes_by_id[edge.to_id]
        if edge.kind == "python_import":
            _require(edge.declaration_kind == "executable_graph" and edge.order_group.startswith("python-import:" + edge.from_id + ":") and edge.order_group.rsplit(":", 1)[1] in ("controller_pre", "role_pre", "post_bootstrap") and isinstance(source, ExecutableGraphMeasuredFileNodeSnapshotV3) and isinstance(target, ExecutableGraphMeasuredFileNodeSnapshotV3) and ("importable_module" in target.semantic_tags or "native_extension" in target.semantic_tags), CP_BOOT_V3_BINDING, "Python import graph edge is invalid")
        elif edge.kind == "elf_interpreter":
            _require(edge.declaration_kind == "executable_graph" and edge.order_group == "elf-interpreter:" + edge.from_id and isinstance(source, ExecutableGraphMeasuredFileNodeSnapshotV3) and isinstance(target, ExecutableGraphMeasuredFileNodeSnapshotV3) and target.content_kind in ("elf_executable", "elf_shared_object"), CP_BOOT_V3_BINDING, "ELF interpreter graph edge is invalid")
        elif edge.kind == "elf_needed":
            _require(edge.declaration_kind == "executable_graph" and edge.order_group == "elf-needed:" + edge.from_id and isinstance(source, ExecutableGraphMeasuredFileNodeSnapshotV3) and isinstance(target, ExecutableGraphMeasuredFileNodeSnapshotV3) and ("dynamic_library" in target.semantic_tags or "native_extension" in target.semantic_tags), CP_BOOT_V3_BINDING, "ELF needed graph edge is invalid")
        elif edge.kind == "elf_search":
            _require(edge.declaration_kind == "executable_graph" and edge.order_group == "elf-search:" + edge.from_id and isinstance(source, ExecutableGraphMeasuredFileNodeSnapshotV3) and isinstance(target, ExecutableGraphMeasuredDirectoryNodeSnapshotV3), CP_BOOT_V3_BINDING, "ELF search graph edge is invalid")
        elif edge.kind == "dlopen":
            _require(edge.declaration_kind == "executable_graph" and edge.order_group == "dlopen:" + edge.from_id and isinstance(source, ExecutableGraphMeasuredFileNodeSnapshotV3) and isinstance(target, ExecutableGraphMeasuredFileNodeSnapshotV3) and ("dynamic_library" in target.semantic_tags or "native_extension" in target.semantic_tags), CP_BOOT_V3_BINDING, "dlopen graph edge is invalid")
        elif edge.kind == "jit_invoke":
            _require(edge.declaration_kind == "executable_graph" and edge.order_group == "jit-invoke:" + edge.from_id and edge.from_id in entrypoints and isinstance(source, ExecutableGraphMeasuredFileNodeSnapshotV3) and isinstance(target, ExecutableGraphJitDerivationNodeSnapshotV3) and edge.requested_path is None and not edge.alias_chain, CP_BOOT_V3_BINDING, "JIT invocation graph edge is invalid")
        elif edge.kind == "python_script":
            _require(edge.declaration_kind == "process_authority", CP_BOOT_V3_BINDING, "Python script graph edge declaration is invalid")
        else:
            _require(edge.declaration_kind == "jit_derivation", CP_BOOT_V3_BINDING, "JIT graph edge declaration is invalid")


def _executable_graph_snapshot_v3(
    *, closure: ExecutionClosureV3, parsed: ParsedPredecessorsV3,
    eligible: tuple[EligibleFileSnapshotV3, ...], controls: tuple[LoaderControlSnapshotV3, ...],
    derivations: tuple[JitDerivationSnapshotV3, ...], selectors: tuple[CacheSelectorSnapshotV3, ...],
    raw_derivations: list[object],
) -> ExecutableGraphSnapshotV3:
    """Parse and bind the graph carrier to the already-derived predicate-5 snapshots."""

    raw = _thaw_json(closure.executable_graph)
    _require(type(raw) is dict and set(raw) == _GRAPH_KEYS_V3 and raw["schema"] == _GRAPH_SCHEMA_V3 and type(raw["alias_hop_limit"]) is int and raw["alias_hop_limit"] == 40, CP_BOOT_V3_SCHEMA, "executable graph carrier is invalid")
    _require(all(type(raw[key]) is list for key in ("entrypoints", "nodes", "aliases", "controls", "declarations", "edges")), CP_BOOT_V3_SCHEMA, "executable graph arrays are invalid")
    eligible_by_path = {item.path: item for item in eligible}
    expected_entry_paths = (
        "/usr/bin/spp", "/usr/bin/python3.10", tables.STAGE2_CONTROLLER_ROW_V3.source_path,
        "/usr/lib/spp/conf_proc_spp_role_bootstrap.py", *(row.source_path for row in tables.LAUNCH_ROLE_ROWS_V3),
    )
    expected_entrypoints = tuple(_graph_file_id_v3(eligible_by_path[path].image, path) for path in expected_entry_paths)
    _require(type(raw["entrypoints"]) is list and tuple(raw["entrypoints"]) == expected_entrypoints and all(type(item) is str for item in raw["entrypoints"]), CP_BOOT_V3_BINDING, "executable graph entrypoints disagree")
    expected_nodes = _graph_expected_nodes_v3(parsed, eligible, derivations, selectors)
    nodes = tuple(_graph_plain_node_v3(value) for value in raw["nodes"])
    _require(tuple(_graph_node_raw_v3(node) for node in nodes) == tuple(_graph_node_raw_v3(node) for node in expected_nodes), CP_BOOT_V3_BINDING, "executable graph node denominator disagrees")
    nodes_by_id = {node.id: node for node in nodes}
    _require(len(nodes_by_id) == len(nodes) and set(expected_entrypoints) <= set(nodes_by_id), CP_BOOT_V3_BINDING, "executable graph node identities are invalid")
    aliases = _graph_alias_rows_v3(raw["aliases"], parsed, nodes_by_id)
    startup_controls, startup_sources = _graph_startup_control_values_v3(closure)
    loading_controls, loading_sources = _graph_loading_control_values_v3(controls, eligible_by_path)
    expected_controls = tuple(_graph_startup_control_raw_v3(row) for row in startup_controls) + tuple(_graph_loading_control_raw_v3(row) for row in loading_controls)
    _require(tuple(raw["controls"]) == expected_controls, CP_BOOT_V3_BINDING, "executable graph controls disagree with predecessor projections")
    declarations = _graph_parse_declarations_v3(raw["declarations"])
    edges = _graph_parse_edges_v3(raw["edges"])
    script_edges, script_sources = _graph_script_edges_v3(eligible_by_path)
    jit_edges, jit_sources = _graph_jit_edges_v3(raw_derivations, derivations, eligible_by_path, selectors)
    source_edges = tuple((*script_edges, *jit_edges))
    source_by_ref = {
        _graph_source_ref_v3(value): value
        for value in (*startup_sources, *loading_sources, *script_sources, *jit_sources)
    }
    _require(len(source_by_ref) == len((*startup_sources, *loading_sources, *script_sources, *jit_sources)), CP_BOOT_V3_BINDING, "executable graph source projections are ambiguous")
    actual_source_edges = tuple(edge for edge in edges if edge.declaration_kind != "executable_graph")
    _require(tuple(sorted((_graph_edge_raw_v3(edge) for edge in actual_source_edges), key=lambda value: value["id"].encode("utf-8"))) == tuple(sorted((_graph_edge_raw_v3(edge) for edge in source_edges), key=lambda value: value["id"].encode("utf-8"))), CP_BOOT_V3_BINDING, "executable graph source-backed edges disagree")
    _require(all(edge.declaration_ref in source_by_ref for edge in actual_source_edges), CP_BOOT_V3_BINDING, "executable graph source reference is unknown")
    _graph_validate_declarative_edges_v3(declarations, edges, nodes_by_id, aliases, expected_entrypoints)
    for control in loading_controls:
        _require(control.owner_id in nodes_by_id and all(path in eligible_by_path or any(isinstance(node, ExecutableGraphMeasuredDirectoryNodeSnapshotV3) and (node.path == path or path.startswith(node.path + "/")) for node in nodes) for path in (*control.contributed_paths, *control.imports, *control.hooks)), CP_BOOT_V3_BINDING, "executable graph loading-control target is unresolved")
    consumed = set(expected_entrypoints)
    consumed.update(edge.from_id for edge in edges)
    consumed.update(edge.to_id for edge in edges)
    consumed.update(control.owner_id for control in loading_controls)
    for control in loading_controls:
        for path in (*control.imports, *control.hooks):
            if path in eligible_by_path:
                file = eligible_by_path[path]
                consumed.add(_graph_file_id_v3(file.image, file.path))
    for control in startup_controls:
        if control.path in eligible_by_path:
            file = eligible_by_path[control.path]
            consumed.add(_graph_file_id_v3(file.image, file.path))
        for node in nodes:
            if isinstance(node, ExecutableGraphMeasuredDirectoryNodeSnapshotV3) and node.path == control.path:
                consumed.add(node.id)
    for output in (node for node in nodes if isinstance(node, ExecutableGraphJitOutputNodeSnapshotV3)):
        for file in (node for node in nodes if isinstance(node, ExecutableGraphMeasuredFileNodeSnapshotV3)):
            if (file.path, file.sha256, file.size_bytes, file.mode) == (output.path, output.sha256, output.size_bytes, output.mode):
                consumed.add(file.id)
    _require(all(isinstance(node, ExecutableGraphMeasuredDirectoryNodeSnapshotV3) or node.id in consumed for node in nodes), CP_BOOT_V3_BINDING, "executable graph contains decorative node authority")
    alias_uses = {chain[0] for edge in edges if edge.alias_chain for chain in (edge.alias_chain,)}
    _require(alias_uses == {row.path for row in aliases}, CP_BOOT_V3_BINDING, "executable graph alias is decorative")
    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        adjacency.setdefault(edge.from_id, set()).add(edge.to_id)
    interpreter_id = _graph_file_id_v3(eligible_by_path["/usr/bin/python3.10"].image, "/usr/bin/python3.10")
    for control in loading_controls:
        adjacency.setdefault(interpreter_id, set()).add(control.owner_id)
        for path in (*control.imports, *control.hooks):
            if path in eligible_by_path:
                target = eligible_by_path[path]
                adjacency.setdefault(control.owner_id, set()).add(_graph_file_id_v3(target.image, target.path))
    for output in (node for node in nodes if isinstance(node, ExecutableGraphJitOutputNodeSnapshotV3)):
        for file in (node for node in nodes if isinstance(node, ExecutableGraphMeasuredFileNodeSnapshotV3)):
            if (file.path, file.sha256, file.size_bytes, file.mode) == (output.path, output.sha256, output.size_bytes, output.mode):
                adjacency.setdefault(output.id, set()).add(file.id)
    reachable = set(expected_entrypoints)
    work = list(expected_entrypoints)
    while work:
        current = work.pop()
        for target in adjacency.get(current, ()):
            if target not in reachable:
                reachable.add(target)
                work.append(target)
    for node in nodes:
        if isinstance(node, ExecutableGraphMeasuredFileNodeSnapshotV3) and (node.content_kind in ("python_source", "python_bytecode", "elf_executable", "elf_shared_object")):
            _require(node.id in reachable, CP_BOOT_V3_BINDING, "executable graph code node is unreachable")
    for derivation in derivations:
        derivation_id = _graph_derivation_id_v3(derivation.derivation_sha256)
        expected_inputs = tuple(_graph_file_id_v3(item.image, item.path) for item in derivation.inputs)
        actual_inputs = tuple(edge.to_id for edge in sorted((edge for edge in edges if edge.kind == "jit_input" and edge.from_id == derivation_id), key=lambda edge: edge.ordinal))
        _require(actual_inputs == expected_inputs, CP_BOOT_V3_BINDING, "executable graph JIT input order disagrees")
        invokes = [edge for edge in edges if edge.kind == "jit_invoke" and edge.to_id == derivation_id]
        _require(len(invokes) == 1, CP_BOOT_V3_BINDING, "executable graph JIT invocation disagrees")
    _require(not derivations or all(any(edge.kind == "jit_output" and edge.from_id == _graph_derivation_id_v3(item.derivation_sha256) for edge in edges) for item in derivations), CP_BOOT_V3_BINDING, "executable graph JIT output is missing")
    return ExecutableGraphSnapshotV3(_GRAPH_SCHEMA_V3, 40, expected_entrypoints, nodes, aliases, tuple((*startup_controls, *loading_controls)), declarations, edges, tuple(source_by_ref[key] for key in sorted(source_by_ref)))


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
        graph = _executable_graph_snapshot_v3(
            closure=closure, parsed=parsed, eligible=eligible, controls=controls, derivations=(), selectors=(),
            raw_derivations=raw_derivations,
        )
        return Predicate5SnapshotV3(contract.execution_mode, contract.cache_policy, closure.schema, _KAT_SHA256, _OBSERVER_SHA256, _PYTHON_ROOTS, _NATIVE_LOADER_ROOTS, bootstrap_source, closure.controller_bootstrap_cache, closure.role_bootstrap_cache, controls, eligible, (), (), graph)
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
    graph = _executable_graph_snapshot_v3(
        closure=closure, parsed=parsed, eligible=eligible, controls=controls,
        derivations=tuple(snapshots), selectors=tuple(selectors), raw_derivations=raw_derivations,
    )
    return Predicate5SnapshotV3(contract.execution_mode, contract.cache_policy, closure.schema, _KAT_SHA256, _OBSERVER_SHA256, _PYTHON_ROOTS, _NATIVE_LOADER_ROOTS, bootstrap_source, closure.controller_bootstrap_cache, closure.role_bootstrap_cache, controls, eligible, tuple(snapshots), tuple(selectors), graph)


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
        launch_projection, stage2_controller, process_authority = _launch_projection_v3(parsed)
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
            process_authority,
            predicate5,
        )
    except ApplianceErrorV3:
        raise
    except Exception as error:
        raise ApplianceErrorV3(CP_BOOT_V3_BINDING, "v3 semantic conjunction rejected") from error
