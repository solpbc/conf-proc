#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Dormant provenance-v2 input contracts and identity derivation.

This module validates the v2 authority inputs without participating in the
live builder or inspector path.  It deliberately reuses the established v1
lock parser for lock-internal structure, then applies the additional v2
authority bindings over the parsed lock and runtime closure.
"""

from __future__ import annotations

import hashlib
import posixpath
from dataclasses import dataclass
from typing import Final

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_lock import Lock, parse_lock
from conf_proc_reasons import (
    CP_EXECUTION_PROVENANCE,
    CP_PROVENANCE_AUTHORITY,
    CP_PROVENANCE_STATUS,
    CP_RUNTIME_CLOSURE_SCHEMA,
    CP_TCB_IDENTITY_SCHEMA,
    CP_VERITY_RULES_SCHEMA,
    ApplianceError,
)


RUNTIME_CLOSURE_SCHEMA: Final = "conf-proc-runtime-closure/v1"
VERITY_RULES_SCHEMA: Final = "conf-proc-verity-rules/v1"
TCB_IDENTITY_SCHEMA: Final = "conf-proc-pre-sandbox-tcb/v1"
EXECUTION_PROVENANCE_SCHEMA: Final = "conf-proc-execution-provenance/v1"
DECLARED_UNVERIFIED: Final = "declared_unverified"

_SHA_KEYS: Final = frozenset("0123456789abcdef")
_CLOSURE_TOP_KEYS: Final = frozenset({"schema", "status", "entries"})
_ENTRY_KEYS: Final = frozenset(
    {
        "path",
        "node_type",
        "mode",
        "uid",
        "gid",
        "size_bytes",
        "sha256",
        "symlink_target",
        "hardlink_group",
        "xattrs",
        "capabilities",
        "logical_role",
        "provenance",
        "root_lock_input_id",
    }
)
_PROVENANCE_KEYS: Final = frozenset({"scheme", "identity", "immutable_ref"})
_XATTR_KEYS: Final = frozenset({"name", "value_sha256"})

_RULES_TOP_KEYS: Final = frozenset(
    {
        "schema",
        "image_ids",
        "hash_algorithm",
        "data_block_size",
        "hash_block_size",
        "image_padding_rule",
        "squashfs",
        "verity",
        "build_epoch",
        "salt",
        "uuid",
    }
)
_SUPPORTED_RULES: Final = {
    "schema": VERITY_RULES_SCHEMA,
    "image_ids": ["models", "runtime-policy"],
    "hash_algorithm": "sha256",
    "data_block_size": 4096,
    "hash_block_size": 4096,
    "image_padding_rule": "zero-to-data-block-boundary",
    "squashfs": {
        "append": False,
        "quiet": True,
        "progress": False,
        "exit_on_error": True,
        "reproducible": True,
        "processors": 1,
        "block_size": 131072,
        "fragments": True,
        "tailends": False,
        "duplicate_data_detection": True,
        "hardlink_detection": True,
        "xattrs": True,
        "export_table": True,
        "sparse_file_detection": True,
        "inode_compression": True,
        "id_table_compression": True,
        "data_compression": True,
        "fragment_compression": True,
        "xattr_compression": True,
        "filesystem_padding_4k": True,
        "output_offset_bytes": 0,
        "gzip": {"compression_level": 9, "window_size": 15, "strategies": ["default"]},
        "all_time_source": "derived-build-epoch",
        "mkfs_time_source": "derived-build-epoch",
        "compression": "gzip",
        "root_mode": 493,
        "root_uid": 0,
        "root_gid": 0,
        "pseudo_file": "required",
    },
    "verity": {
        "format": "veritysetup-format-v1",
        "superblock": True,
        "data_device_offset_bytes": 0,
        "hash_offset_bytes": 0,
        "fec": "disabled",
    },
    "build_epoch": {
        "domain_ascii": "conf-proc/build-clock/v1",
        "preimage_fields": ["domain_ascii", "artifact_input_digest_bytes"],
        "utc_range_start": 946684800,
        "utc_range_end": 4102444799,
        "digest_prefix_bytes": 8,
    },
    "salt": {
        "domain_ascii": "conf-proc/verity-salt/v1",
        "preimage_fields": ["domain_ascii", "image_id_ascii", "artifact_input_digest_bytes"],
        "length_bytes": 32,
        "encoding": "lowercase-hex",
    },
    "uuid": {
        "domain_ascii": "conf-proc/verity-uuid/v1",
        "preimage_fields": ["domain_ascii", "image_id_ascii", "artifact_input_digest_bytes"],
        "digest_prefix_bytes": 16,
        "rfc4122_version": 5,
        "rfc4122_variant": "10",
    },
}

_TCB_TOP_KEYS: Final = frozenset({"schema", "status", "caller", "launcher", "sandbox", "kernel_feature_contract"})
_EXECUTABLE_KEYS: Final = frozenset(
    {"logical_name", "sha256", "linkage", "interpreter_sha256", "loader_sha256", "library_sha256s"}
)
_SANDBOX_KEYS: Final = frozenset({"backend", "executable", "helper"})
_KERNEL_CONTRACT_KEYS: Final = frozenset({"schema", "sha256"})


@dataclass(frozen=True)
class ProvenanceInputs:
    artifact_input_schema: str
    artifact_input_sha256: str
    runtime_closure_sha256: str
    verity_rules_sha256: str
    tcb_identity_sha256: str
    builder_source_sha256: str
    policy_sha256: str
    execution_provenance_sha256: str
    root_lock_bytes: bytes
    runtime_closure_bytes: bytes
    verity_rules_bytes: bytes
    tcb_identity_bytes: bytes
    builder_source_bytes: bytes
    policy_bytes: bytes


def supported_verity_rules_bytes() -> bytes:
    """Return the sole accepted canonical v2 verity-rules document."""

    return canonical_dumps(_SUPPORTED_RULES)


def parse_runtime_closure(data: bytes) -> dict:
    """Validate the declared runtime closure contract."""

    raw = canonical_loads(data)
    _require(
        type(raw) is dict and set(raw) == _CLOSURE_TOP_KEYS,
        CP_RUNTIME_CLOSURE_SCHEMA,
        "unexpected runtime-closure fields",
    )
    _require(raw["schema"] == RUNTIME_CLOSURE_SCHEMA, CP_RUNTIME_CLOSURE_SCHEMA, "unexpected runtime-closure schema")
    _require(raw["status"] == DECLARED_UNVERIFIED, CP_PROVENANCE_STATUS, "runtime closure must remain declared_unverified")

    entries = raw["entries"]
    _require(type(entries) is list and entries, CP_RUNTIME_CLOSURE_SCHEMA, "runtime closure must have a nonempty denominator")

    paths: list[str] = []
    hardlink_groups: dict[str, list[dict]] = {}
    for entry in entries:
        _parse_closure_entry(entry)
        paths.append(entry["path"])
        if entry["hardlink_group"] is not None:
            _require(entry["node_type"] == "file", CP_RUNTIME_CLOSURE_SCHEMA, "only files may join a hardlink group")
            hardlink_groups.setdefault(entry["hardlink_group"], []).append(entry)

    _require(
        paths == sorted(paths) and len(paths) == len(set(paths)),
        CP_RUNTIME_CLOSURE_SCHEMA,
        "runtime paths must be sorted and unique",
    )

    known_paths = set(paths)
    for entry in entries:
        if entry["node_type"] != "symlink":
            continue
        target = entry["symlink_target"]
        resolved = posixpath.normpath(
            target if target.startswith("/") else posixpath.join(posixpath.dirname(entry["path"]), target)
        )
        _require(
            resolved.startswith("/") and resolved in known_paths,
            CP_RUNTIME_CLOSURE_SCHEMA,
            "symlink target escapes or is outside the closed inventory",
        )

    for members in hardlink_groups.values():
        _require(len(members) >= 2, CP_RUNTIME_CLOSURE_SCHEMA, "hardlink group must contain at least two paths")
        identities = {
            (
                item["sha256"],
                item["size_bytes"],
                item["mode"],
                item["uid"],
                item["gid"],
                canonical_dumps(item["xattrs"]),
                tuple(item["capabilities"]),
            )
            for item in members
        }
        _require(len(identities) == 1, CP_RUNTIME_CLOSURE_SCHEMA, "hardlink group content identities disagree")

    return raw


def _parse_closure_entry(entry: object) -> None:
    _require(
        type(entry) is dict and set(entry) == _ENTRY_KEYS,
        CP_RUNTIME_CLOSURE_SCHEMA,
        "runtime entry has unexpected fields",
    )
    _require(_absolute_normal_path(entry["path"]), CP_RUNTIME_CLOSURE_SCHEMA, "runtime path must be absolute and normalized")

    node_type = entry["node_type"]
    _require(node_type in ("file", "directory", "symlink"), CP_RUNTIME_CLOSURE_SCHEMA, "runtime node type is unsupported")
    for key in ("mode", "uid", "gid", "size_bytes"):
        _require(type(entry[key]) is int and entry[key] >= 0, CP_RUNTIME_CLOSURE_SCHEMA, f"runtime {key} must be nonnegative")
    _require(
        entry["mode"] <= 0o7777 and not entry["mode"] & 0o6000,
        CP_RUNTIME_CLOSURE_SCHEMA,
        "privileged runtime mode is forbidden",
    )
    _require(
        type(entry["logical_role"]) is str and entry["logical_role"],
        CP_RUNTIME_CLOSURE_SCHEMA,
        "logical role must be nonempty",
    )
    _require(
        entry["hardlink_group"] is None or _is_sha256(entry["hardlink_group"]),
        CP_RUNTIME_CLOSURE_SCHEMA,
        "hardlink group must be null or a digest",
    )

    if node_type == "file":
        _require(
            _is_sha256(entry["sha256"]) and entry["symlink_target"] is None,
            CP_RUNTIME_CLOSURE_SCHEMA,
            "file content identity is incomplete",
        )
    elif node_type == "directory":
        _require(
            entry["sha256"] is None and entry["symlink_target"] is None and entry["size_bytes"] == 0,
            CP_RUNTIME_CLOSURE_SCHEMA,
            "directory must not claim content",
        )
    else:
        _require(
            entry["sha256"] is None and type(entry["symlink_target"]) is str and entry["symlink_target"],
            CP_RUNTIME_CLOSURE_SCHEMA,
            "symlink target is incomplete",
        )

    xattrs = entry["xattrs"]
    _require(type(xattrs) is list, CP_RUNTIME_CLOSURE_SCHEMA, "xattrs must be an array")
    xattr_names: list[str] = []
    for xattr in xattrs:
        _require(
            type(xattr) is dict and set(xattr) == _XATTR_KEYS,
            CP_RUNTIME_CLOSURE_SCHEMA,
            "xattr has unexpected fields",
        )
        _require(
            type(xattr["name"]) is str and xattr["name"],
            CP_RUNTIME_CLOSURE_SCHEMA,
            "xattr name must be nonempty",
        )
        _require(_is_sha256(xattr["value_sha256"]), CP_RUNTIME_CLOSURE_SCHEMA, "xattr value digest is invalid")
        xattr_names.append(xattr["name"])
    _require(
        xattr_names == sorted(xattr_names) and len(xattr_names) == len(set(xattr_names)),
        CP_RUNTIME_CLOSURE_SCHEMA,
        "xattrs must be sorted and unique",
    )

    capabilities = entry["capabilities"]
    _require(
        type(capabilities) is list and all(type(item) is str and item for item in capabilities),
        CP_RUNTIME_CLOSURE_SCHEMA,
        "capabilities must be strings",
    )
    _require(
        capabilities == sorted(capabilities) and len(capabilities) == len(set(capabilities)),
        CP_RUNTIME_CLOSURE_SCHEMA,
        "capabilities must be sorted and unique",
    )

    provenance = entry["provenance"]
    _require(
        type(provenance) is dict and set(provenance) == _PROVENANCE_KEYS,
        CP_RUNTIME_CLOSURE_SCHEMA,
        "provenance has unexpected fields",
    )
    _require(
        all(type(provenance[key]) is str and provenance[key] for key in _PROVENANCE_KEYS),
        CP_RUNTIME_CLOSURE_SCHEMA,
        "provenance must name immutable bytes",
    )
    _require(
        provenance["immutable_ref"].startswith("sha256:") and _is_sha256(provenance["immutable_ref"][7:]),
        CP_RUNTIME_CLOSURE_SCHEMA,
        "provenance immutable_ref must bind a SHA-256 identity",
    )
    _require(
        entry["root_lock_input_id"] is None
        or type(entry["root_lock_input_id"]) is str
        and entry["root_lock_input_id"],
        CP_RUNTIME_CLOSURE_SCHEMA,
        "root-lock authority must be null or nonempty",
    )


def parse_verity_rules(data: bytes) -> dict:
    """Validate the one accepted v2 verity construction contract."""

    raw = canonical_loads(data)
    _require(
        type(raw) is dict and set(raw) == _RULES_TOP_KEYS,
        CP_VERITY_RULES_SCHEMA,
        "unexpected verity-rules fields",
    )
    _require(raw == _SUPPORTED_RULES, CP_VERITY_RULES_SCHEMA, "verity rules differ from the complete supported construction contract")
    return raw


def parse_tcb_identity(data: bytes) -> dict:
    """Validate the declared pre-sandbox TCB identity contract."""

    raw = canonical_loads(data)
    _require(type(raw) is dict and set(raw) == _TCB_TOP_KEYS, CP_TCB_IDENTITY_SCHEMA, "unexpected TCB identity fields")
    _require(raw["schema"] == TCB_IDENTITY_SCHEMA, CP_TCB_IDENTITY_SCHEMA, "unexpected TCB identity schema")
    _require(raw["status"] == DECLARED_UNVERIFIED, CP_PROVENANCE_STATUS, "TCB identity must remain declared_unverified")

    _parse_executable(raw["caller"])
    _parse_executable(raw["launcher"])
    sandbox = raw["sandbox"]
    _require(
        type(sandbox) is dict and set(sandbox) == _SANDBOX_KEYS,
        CP_TCB_IDENTITY_SCHEMA,
        "sandbox identity has unexpected fields",
    )
    _require(sandbox["backend"] in ("bubblewrap", "unshare"), CP_TCB_IDENTITY_SCHEMA, "sandbox backend is unsupported")
    _parse_executable(sandbox["executable"])
    _require(
        sandbox["helper"] is None or type(sandbox["helper"]) is dict,
        CP_TCB_IDENTITY_SCHEMA,
        "sandbox helper must be null or an executable",
    )
    if sandbox["helper"] is not None:
        _parse_executable(sandbox["helper"])

    kernel = raw["kernel_feature_contract"]
    _require(
        type(kernel) is dict and set(kernel) == _KERNEL_CONTRACT_KEYS,
        CP_TCB_IDENTITY_SCHEMA,
        "kernel contract has unexpected fields",
    )
    _require(
        kernel["schema"] == "conf-proc-kernel-features/v1" and _is_sha256(kernel["sha256"]),
        CP_TCB_IDENTITY_SCHEMA,
        "kernel contract must use the supported schema and bind exact bytes",
    )
    return raw


def _parse_executable(raw: object) -> None:
    _require(
        type(raw) is dict and set(raw) == _EXECUTABLE_KEYS,
        CP_TCB_IDENTITY_SCHEMA,
        "executable identity has unexpected fields",
    )
    _require(
        type(raw["logical_name"]) is str and raw["logical_name"] and _is_sha256(raw["sha256"]),
        CP_TCB_IDENTITY_SCHEMA,
        "executable must bind exact bytes",
    )
    _require(raw["linkage"] in ("static", "dynamic"), CP_TCB_IDENTITY_SCHEMA, "executable linkage must be static or dynamic")
    libraries = raw["library_sha256s"]
    _require(
        type(libraries) is list and all(_is_sha256(item) for item in libraries),
        CP_TCB_IDENTITY_SCHEMA,
        "library identities must be digests",
    )
    _require(
        libraries == sorted(libraries) and len(libraries) == len(set(libraries)),
        CP_TCB_IDENTITY_SCHEMA,
        "library identities must be sorted and unique",
    )
    if raw["linkage"] == "static":
        _require(
            raw["interpreter_sha256"] is None and raw["loader_sha256"] is None and libraries == [],
            CP_TCB_IDENTITY_SCHEMA,
            "static executable must not claim dynamic dependencies",
        )
    else:
        _require(
            _is_sha256(raw["interpreter_sha256"]) and _is_sha256(raw["loader_sha256"]) and libraries,
            CP_TCB_IDENTITY_SCHEMA,
            "dynamic executable closure is incomplete",
        )


def verify_root_lock_authority(
    root_lock_bytes: bytes,
    closure: dict,
    *,
    builder_source_sha256: str,
    policy_sha256: str,
    policy_size_bytes: int,
) -> Lock:
    """Apply v2 authority bindings over a structurally valid v1 lock."""

    try:
        lock = parse_lock(root_lock_bytes)
    except ApplianceError as exc:
        raise ApplianceError(CP_PROVENANCE_AUTHORITY, f"root lock failed structural validation: {exc}") from exc

    root_raw = canonical_loads(root_lock_bytes)
    for input_raw in root_raw["inputs"]:
        _require(
            _relative_normal_path(input_raw["source_local_path"]),
            CP_PROVENANCE_AUTHORITY,
            "root-lock source_local_path must be NUL-free and relative",
        )
        for placement in input_raw["placements"]:
            _require(
                _lock_absolute_path(placement["path"]),
                CP_PROVENANCE_AUTHORITY,
                "root-lock placement path must be NUL-free, absolute, and normalized",
            )

    _require(
        lock.image_specs == {"models": {}, "runtime-policy": {}},
        CP_PROVENANCE_AUTHORITY,
        "root lock image_specs must be the exact empty geometry-free object",
    )

    inputs_by_id = {item.id: item for item in lock.inputs}
    policy_input = inputs_by_id.get(lock.policy_input_id)
    _require(
        policy_input is not None
        and policy_input.sha256 == policy_sha256
        and policy_input.size_bytes == policy_size_bytes,
        CP_PROVENANCE_AUTHORITY,
        "policy bytes disagree with the root-lock authority",
    )

    designated_builder_entries = [entry for entry in closure["entries"] if entry["logical_role"] == "conf_proc_source"]
    _require(
        len(designated_builder_entries) == 1
        and designated_builder_entries[0]["root_lock_input_id"] is not None
        and designated_builder_entries[0]["sha256"] == builder_source_sha256,
        CP_PROVENANCE_AUTHORITY,
        "runtime closure must designate exactly one root-lock-authorized builder source",
    )

    for entry in closure["entries"]:
        input_id = entry["root_lock_input_id"]
        if input_id is None:
            continue
        authority = inputs_by_id.get(input_id)
        _require(authority is not None, CP_PROVENANCE_AUTHORITY, "runtime closure cites an unknown root-lock input")
        provenance = entry["provenance"]
        _require(
            authority.sha256 == entry["sha256"]
            and authority.size_bytes == entry["size_bytes"]
            and authority.role == entry["logical_role"]
            and authority.source_retrieval_scheme == provenance["scheme"]
            and authority.source_retrieval_identity == provenance["identity"]
            and authority.source_retrieval_immutable_ref == provenance["immutable_ref"],
            CP_PROVENANCE_AUTHORITY,
            "runtime closure disagrees with root-lock authority",
        )

    return lock


def derive_inputs(
    *,
    root_lock_bytes: bytes,
    runtime_closure_bytes: bytes,
    verity_rules_bytes: bytes,
    tcb_identity_bytes: bytes,
    builder_source_bytes: bytes,
    policy_bytes: bytes,
) -> ProvenanceInputs:
    """Validate authority inputs and derive artifact and execution identities."""

    closure = parse_runtime_closure(runtime_closure_bytes)
    parse_verity_rules(verity_rules_bytes)
    parse_tcb_identity(tcb_identity_bytes)

    builder_source_sha256 = _digest(builder_source_bytes)
    policy_sha256 = _digest(policy_bytes)
    policy = canonical_loads(policy_bytes)
    _require(
        type(policy) is dict and policy.get("schema") == "conf-proc-policy/v1",
        CP_PROVENANCE_AUTHORITY,
        "policy bytes do not carry the supported canonical policy schema",
    )
    lock = verify_root_lock_authority(
        root_lock_bytes,
        closure,
        builder_source_sha256=builder_source_sha256,
        policy_sha256=policy_sha256,
        policy_size_bytes=len(policy_bytes),
    )

    fields = {
        "schema": EXECUTION_PROVENANCE_SCHEMA,
        "artifact_input_sha256": _digest(root_lock_bytes),
        "runtime_closure_sha256": _digest(runtime_closure_bytes),
        "verity_rules_sha256": _digest(verity_rules_bytes),
        "tcb_identity_sha256": _digest(tcb_identity_bytes),
        "builder_source_sha256": builder_source_sha256,
        "policy_sha256": policy_sha256,
    }
    execution_provenance_sha256 = _digest(canonical_dumps(fields))
    return ProvenanceInputs(
        artifact_input_schema=lock.schema,
        artifact_input_sha256=fields["artifact_input_sha256"],
        runtime_closure_sha256=fields["runtime_closure_sha256"],
        verity_rules_sha256=fields["verity_rules_sha256"],
        tcb_identity_sha256=fields["tcb_identity_sha256"],
        builder_source_sha256=fields["builder_source_sha256"],
        policy_sha256=fields["policy_sha256"],
        execution_provenance_sha256=execution_provenance_sha256,
        root_lock_bytes=root_lock_bytes,
        runtime_closure_bytes=runtime_closure_bytes,
        verity_rules_bytes=verity_rules_bytes,
        tcb_identity_bytes=tcb_identity_bytes,
        builder_source_bytes=builder_source_bytes,
        policy_bytes=policy_bytes,
    )


def _absolute_normal_path(value: object) -> bool:
    return (
        type(value) is str
        and "\x00" not in value
        and value.startswith("/")
        and not value.startswith("//")
        and value != "/"
        and posixpath.normpath(value) == value
    )


def _lock_absolute_path(value: object) -> bool:
    return (
        type(value) is str
        and "\x00" not in value
        and value.startswith("/")
        and not value.startswith("//")
        and not (value != "/" and value.endswith("/"))
        and posixpath.normpath(value) == value
    )


def _relative_normal_path(value: object) -> bool:
    return (
        type(value) is str
        and value
        and "\x00" not in value
        and not value.startswith("/")
        and all(segment not in ("", "..") for segment in value.split("/"))
    )


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA_KEYS


def _digest(data: bytes) -> str:
    if type(data) is not bytes:
        raise ApplianceError(CP_EXECUTION_PROVENANCE, "provenance inputs must be exact bytes")
    return hashlib.sha256(data).hexdigest()


def _require(condition: bool, reason_code: str, message: str) -> None:
    if not condition:
        raise ApplianceError(reason_code, message)
