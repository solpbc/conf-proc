#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent, dormant verifier for the appliance provenance-v2 cutover.

This module intentionally has no builder imports.  It accepts the original
trusted bytes, independently validates the three new canonical contracts,
derives both identities, and checks candidate manifest/SPDX bindings.  The
current v1 builder does not invoke it; it exists first so a later production
cutover cannot ship its own acceptance oracle.

``declared_unverified`` is literal and load-bearing: these documents bind the
candidate's claims, but only the separate capable-host gate can prove closure
completeness, already-running TCB identity, or operating-system isolation.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Final


CP_EXECUTION_PROVENANCE: Final = "CP_EXECUTION_PROVENANCE"
CP_PROVENANCE_AUTHORITY: Final = "CP_PROVENANCE_AUTHORITY"
CP_PROVENANCE_BINDING: Final = "CP_PROVENANCE_BINDING"
CP_PROVENANCE_STATUS: Final = "CP_PROVENANCE_STATUS"
CP_RUNTIME_CLOSURE_SCHEMA: Final = "CP_RUNTIME_CLOSURE_SCHEMA"
CP_TCB_IDENTITY_SCHEMA: Final = "CP_TCB_IDENTITY_SCHEMA"
CP_VERITY_RULES_SCHEMA: Final = "CP_VERITY_RULES_SCHEMA"
CP_JSON_INVALID_UTF8: Final = "CP_JSON_INVALID_UTF8"
CP_JSON_INVALID: Final = "CP_JSON_INVALID"
CP_JSON_NONCANONICAL: Final = "CP_JSON_NONCANONICAL"
CP_JSON_DUPLICATE_KEY: Final = "CP_JSON_DUPLICATE_KEY"
CP_JSON_UNSUPPORTED_NUMBER: Final = "CP_JSON_UNSUPPORTED_NUMBER"
CP_JSON_UNSUPPORTED_TYPE: Final = "CP_JSON_UNSUPPORTED_TYPE"

_JSON_SAFE_INTEGER_MIN: Final = -(2**53 - 1)
_JSON_SAFE_INTEGER_MAX: Final = 2**53 - 1


class ApplianceError(RuntimeError):
    """Self-contained oracle failure with a stable reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


def canonical_dumps(value: object) -> bytes:
    """Encode the oracle's strict RFC 8785-compatible integer subset."""

    return _json_encode_value(value).encode("utf-8")


def canonical_loads(data: bytes) -> object:
    """Decode exact canonical bytes without importing product codecs."""

    if type(data) is not bytes:
        raise ApplianceError(CP_JSON_UNSUPPORTED_TYPE, "canonical JSON input must be bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApplianceError(CP_JSON_INVALID_UTF8, "JSON is not valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_json_object_without_duplicates,
            parse_float=_json_reject_float,
            parse_constant=_json_reject_constant,
        )
    except ApplianceError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise ApplianceError(CP_JSON_INVALID, "invalid JSON") from exc
    if canonical_dumps(value) != data:
        raise ApplianceError(CP_JSON_NONCANONICAL, "JSON is not canonically encoded")
    return value


def _json_object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ApplianceError(CP_JSON_DUPLICATE_KEY, "duplicate JSON object key")
        result[key] = value
    return result


def _json_reject_float(value: str) -> object:
    raise ApplianceError(CP_JSON_UNSUPPORTED_NUMBER, "floating-point JSON is unsupported")


def _json_reject_constant(value: str) -> object:
    raise ApplianceError(CP_JSON_UNSUPPORTED_NUMBER, "non-finite JSON number is unsupported")


def _json_encode_value(value: object) -> str:
    value_type = type(value)
    if value_type is dict:
        keys = list(value)
        if any(type(key) is not str for key in keys):
            raise ApplianceError(CP_JSON_UNSUPPORTED_TYPE, "JSON object keys must be strings")
        ordered = sorted(keys, key=_json_utf16_sort_key)
        return "{" + ",".join(f"{_json_encode_string(key)}:{_json_encode_value(value[key])}" for key in ordered) + "}"
    if value_type is list:
        return "[" + ",".join(_json_encode_value(item) for item in value) + "]"
    if value_type is str:
        return _json_encode_string(value)
    if value_type is bool:
        return "true" if value else "false"
    if value is None:
        return "null"
    if value_type is int:
        if not _JSON_SAFE_INTEGER_MIN <= value <= _JSON_SAFE_INTEGER_MAX:
            raise ApplianceError(CP_JSON_UNSUPPORTED_NUMBER, "integer is outside the safe range")
        return str(value)
    raise ApplianceError(CP_JSON_UNSUPPORTED_TYPE, "unsupported JSON value type")


def _json_utf16_sort_key(value: str) -> bytes:
    _json_validate_unicode(value)
    return value.encode("utf-16-be")


def _json_encode_string(value: str) -> str:
    _json_validate_unicode(value)
    escapes = {"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r", '"': '\\"', "\\": "\\\\"}
    out = ['"']
    for character in value:
        if character in escapes:
            out.append(escapes[character])
        elif ord(character) <= 0x1F:
            out.append(f"\\u{ord(character):04x}")
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def _json_validate_unicode(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ApplianceError(CP_JSON_UNSUPPORTED_TYPE, "string contains an unpaired surrogate")


RUNTIME_CLOSURE_SCHEMA: Final = "conf-proc-runtime-closure/v1"
VERITY_RULES_SCHEMA: Final = "conf-proc-verity-rules/v1"
TCB_IDENTITY_SCHEMA: Final = "conf-proc-pre-sandbox-tcb/v1"
EXECUTION_PROVENANCE_SCHEMA: Final = "conf-proc-execution-provenance/v1"
PROVENANCE_BINDING_SCHEMA: Final = "conf-proc-execution-provenance-binding/v1"
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

_LOCK_TOP_KEYS: Final = frozenset(
    {
        "schema",
        "lock_version",
        "base_image_record",
        "future_cmdline",
        "inputs",
        "authorized_module_signers",
        "image_specs",
        "policy_input_id",
        "tool_ids",
    }
)
_LOCK_BASE_KEYS: Final = frozenset(
    {
        "kind",
        "provider",
        "identity_namespace",
        "identity_name",
        "identity_immutable_revision",
        "content_sha256",
        "content_size_bytes",
        "content_media_type",
        "availability",
        "recorded_retrieval_scheme",
        "recorded_retrieval_identity",
        "recorded_retrieval_immutable_ref",
    }
)
_LOCK_INPUT_KEYS: Final = frozenset(
    {
        "id",
        "role",
        "component",
        "sha256",
        "size_bytes",
        "source_local_path",
        "source_retrieval_scheme",
        "source_retrieval_identity",
        "source_retrieval_immutable_ref",
        "derivation_kind",
        "derivation_recipe_id",
        "derivation_parent_ids",
        "derivation_parameters_sha256",
        "placements",
    }
)
_LOCK_PLACEMENT_KEYS: Final = frozenset(
    {"image", "path", "node_type", "mode", "uid", "gid", "xattrs", "source_input_id", "target"}
)
_LOCK_SIGNER_KEYS: Final = frozenset({"certificate_sha256", "spki_sha256", "subject_sha256", "usage"})
_LOCK_ROLES: Final = frozenset(
    {
        "kernel",
        "kernel_trusted_cert_bundle",
        "final_systemd_stub",
        "final_systemd_unit",
        "nvidia_cc_driver",
        "nvidia_cc_firmware",
        "conf_proc_source",
        "sglang_image",
        "inference_model",
        "asr_model",
        "gateway_dependency_lock",
        "asr_dependency_lock",
        "runtime_tree_input",
        "policy_tree_input",
        "models_tree_input",
        "build_tool",
    }
)
_LOCK_SINGLE_ROLES: Final = frozenset(
    {
        "kernel",
        "kernel_trusted_cert_bundle",
        "final_systemd_stub",
        "final_systemd_unit",
        "nvidia_cc_driver",
        "nvidia_cc_firmware",
        "sglang_image",
        "inference_model",
        "asr_model",
        "gateway_dependency_lock",
        "asr_dependency_lock",
    }
)
_LOCK_TREE_ROLES: Final = frozenset({"runtime_tree_input", "policy_tree_input", "models_tree_input"})
_LOCK_REQUIRED_TOOLS: Final = frozenset({"mksquashfs", "unsquashfs", "veritysetup", "openssl"})
_LOCK_IMAGES: Final = frozenset({"models", "runtime-policy"})

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
        "gzip": {
            "compression_level": 9,
            "window_size": 15,
            "strategies": ["default"],
        },
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

_TCB_TOP_KEYS: Final = frozenset(
    {"schema", "status", "caller", "launcher", "sandbox", "kernel_feature_contract"}
)
_EXECUTABLE_KEYS: Final = frozenset(
    {"logical_name", "sha256", "linkage", "interpreter_sha256", "loader_sha256", "library_sha256s"}
)
_SANDBOX_KEYS: Final = frozenset({"backend", "executable", "helper"})
_KERNEL_CONTRACT_KEYS: Final = frozenset({"schema", "sha256"})

_MANIFEST_TOP_KEYS: Final = frozenset(
    {
        "schema",
        "manifest_version",
        "lock_schema",
        "lock_sha256",
        "reproducibility",
        "base_image_record",
        "future_cmdline",
        "images",
        "inputs",
        "inventory",
        "bindings",
        "policy",
        "module_authority",
        "toolchain",
        "sbom",
        "provenance",
    }
)
_BASE_IMAGE_KEYS: Final = frozenset(
    {
        "kind",
        "provider",
        "identity_namespace",
        "identity_name",
        "identity_immutable_revision",
        "content_sha256",
        "content_size_bytes",
        "content_media_type",
        "availability",
        "recorded_retrieval_scheme",
        "recorded_retrieval_identity",
        "recorded_retrieval_immutable_ref",
    }
)
_IMAGE_KEYS: Final = frozenset(
    {
        "squashfs_sha256",
        "squashfs_size_bytes",
        "hash_device_sha256",
        "hash_device_size_bytes",
        "root_hash",
        "data_block_size",
        "hash_block_size",
        "hash_algorithm",
        "salt",
        "uuid",
    }
)
_MANIFEST_INPUT_KEYS: Final = frozenset(
    {
        "id",
        "role",
        "sha256",
        "size_bytes",
        "source_retrieval_scheme",
        "source_retrieval_identity",
        "source_retrieval_immutable_ref",
        "derivation_kind",
        "derivation_recipe_id",
        "derivation_parent_ids",
        "derivation_parameters_sha256",
        "placements",
    }
)
_PLACEMENT_KEYS: Final = frozenset(
    {"image", "path", "node_type", "mode", "uid", "gid", "xattrs", "source_input_id", "target"}
)
_INVENTORY_KEYS: Final = frozenset(
    {"path", "node_type", "mode", "uid", "gid", "xattrs", "sha256", "size_bytes", "symlink_target", "source_input_id"}
)
_IMAGE_IDS: Final = frozenset({"runtime-policy", "models"})
_BINDING_CATEGORIES: Final = frozenset({"executables", "configs", "models", "runtime_inputs"})
_REPRODUCIBILITY_KEYS: Final = frozenset({"build_epoch", "sort_order", "codec"})
_POLICY_KEYS: Final = frozenset({"policy_input_id", "policy_schema", "process_policy_sha256"})
_MODULE_AUTHORITY_KEYS: Final = frozenset(
    {"trusted_bundle_input_id", "authorized_signer_certificate_sha256", "module_inventory", "firmware_inventory"}
)
_MODULE_INVENTORY_KEYS: Final = frozenset({"path", "sha256", "signer_certificate_sha256"})
_FIRMWARE_INVENTORY_KEYS: Final = frozenset({"path", "sha256"})
_TOOLCHAIN_KEYS: Final = frozenset({"tool_id", "component", "resolved_path_sha256"})
_SBOM_REFERENCE_KEYS: Final = frozenset({"filename", "sha256", "spdx_version", "document_spdx_id"})

_SPDX_TOP_KEYS: Final = frozenset(
    {
        "spdxVersion",
        "dataLicense",
        "SPDXID",
        "name",
        "documentNamespace",
        "creationInfo",
        "packages",
        "files",
        "relationships",
        "documentDescribes",
    }
)
_SPDX_CREATION_KEYS: Final = frozenset({"created", "creators"})
_SPDX_PACKAGE_KEYS: Final = frozenset(
    {
        "SPDXID",
        "name",
        "downloadLocation",
        "licenseConcluded",
        "licenseDeclared",
        "copyrightText",
        "supplier",
        "originator",
        "checksums",
        "primaryPackagePurpose",
    }
)
_SPDX_EXTERNAL_REF_KEYS: Final = frozenset({"referenceCategory", "referenceType", "referenceLocator"})
_SPDX_FILE_KEYS: Final = frozenset({"SPDXID", "fileName", "checksums"})
_SPDX_RELATIONSHIP_KEYS: Final = frozenset({"spdxElementId", "relationshipType", "relatedSpdxElement"})
_SPDX_CHECKSUM_KEYS: Final = frozenset({"algorithm", "checksumValue"})
_SPDX_PACKAGE_PURPOSES: Final = frozenset({"OPERATING-SYSTEM", "APPLICATION", "DEVICE", "FIRMWARE", "FILE"})
_SPDX_RELATIONSHIP_TYPES: Final = frozenset(
    {"CONTAINS", "GENERATED_FROM", "BUILD_TOOL_OF", "RUNTIME_DEPENDENCY_OF"}
)
_SPDX_NAMESPACE_DOMAIN: Final = b"conf-proc/spdx-document-namespace/v1"

_BINDING_KEYS: Final = frozenset(
    {
        "schema",
        "artifact_input_sha256",
        "execution_provenance_sha256",
        "runtime_closure",
        "verity_rules_sha256",
        "tcb_identity",
        "builder_source_sha256",
        "policy_sha256",
    }
)
_STATUS_BINDING_KEYS: Final = frozenset({"sha256", "status"})
_SPDX_REFERENCE_TYPES: Final = (
    "conf-proc-artifact-input",
    "conf-proc-builder-source",
    "conf-proc-execution-provenance",
    "conf-proc-policy",
    "conf-proc-runtime-closure",
    "conf-proc-tcb-identity",
    "conf-proc-verity-rules",
)


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
    """Return the independent verifier's one accepted legacy rules object."""

    return canonical_dumps(_SUPPORTED_RULES)


def parse_runtime_closure(data: bytes) -> dict:
    raw = canonical_loads(data)
    _require(type(raw) is dict and set(raw) == _CLOSURE_TOP_KEYS, CP_RUNTIME_CLOSURE_SCHEMA, "unexpected runtime-closure fields")
    _require(raw["schema"] == RUNTIME_CLOSURE_SCHEMA, CP_RUNTIME_CLOSURE_SCHEMA, "unexpected runtime-closure schema")
    _require(raw["status"] == DECLARED_UNVERIFIED, CP_PROVENANCE_STATUS, "runtime closure must remain declared_unverified")
    entries = raw["entries"]
    _require(type(entries) is list and entries, CP_RUNTIME_CLOSURE_SCHEMA, "runtime closure must have a nonempty denominator")
    paths: list[str] = []
    for entry in entries:
        _parse_closure_entry(entry)
        paths.append(entry["path"])
    _require(paths == sorted(paths) and len(paths) == len(set(paths)), CP_RUNTIME_CLOSURE_SCHEMA, "runtime paths must be sorted and unique")
    known_paths = set(paths)
    hardlinks: dict[str, list[dict]] = {}
    for entry in entries:
        if entry["node_type"] == "symlink":
            target = entry["symlink_target"]
            resolved = posixpath.normpath(
                target if target.startswith("/") else posixpath.join(posixpath.dirname(entry["path"]), target)
            )
            _require(
                resolved.startswith("/") and resolved in known_paths,
                CP_RUNTIME_CLOSURE_SCHEMA,
                "symlink target escapes or is outside the closed inventory",
            )
        if entry["hardlink_group"] is not None:
            _require(entry["node_type"] == "file", CP_RUNTIME_CLOSURE_SCHEMA, "only files may join a hardlink group")
            hardlinks.setdefault(entry["hardlink_group"], []).append(entry)
    for members in hardlinks.values():
        _require(len(members) >= 2, CP_RUNTIME_CLOSURE_SCHEMA, "hardlink group must contain at least two paths")
        _require(
            len(
                {
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
            )
            == 1,
            CP_RUNTIME_CLOSURE_SCHEMA,
            "hardlink group content identities disagree",
        )
    return raw


def _parse_closure_entry(entry: object) -> None:
    _require(type(entry) is dict and set(entry) == _ENTRY_KEYS, CP_RUNTIME_CLOSURE_SCHEMA, "runtime entry has unexpected fields")
    path = entry["path"]
    _require(_absolute_normal_path(path), CP_RUNTIME_CLOSURE_SCHEMA, "runtime path must be absolute and normalized")
    node_type = entry["node_type"]
    _require(node_type in ("file", "directory", "symlink"), CP_RUNTIME_CLOSURE_SCHEMA, "runtime node type is unsupported")
    for key in ("mode", "uid", "gid", "size_bytes"):
        _require(type(entry[key]) is int and entry[key] >= 0, CP_RUNTIME_CLOSURE_SCHEMA, f"runtime {key} must be nonnegative")
    _require(entry["mode"] <= 0o7777 and not entry["mode"] & 0o6000, CP_RUNTIME_CLOSURE_SCHEMA, "privileged runtime mode is forbidden")
    _require(type(entry["logical_role"]) is str and entry["logical_role"], CP_RUNTIME_CLOSURE_SCHEMA, "logical role must be nonempty")
    _require(entry["hardlink_group"] is None or _is_sha256(entry["hardlink_group"]), CP_RUNTIME_CLOSURE_SCHEMA, "hardlink group must be null or a digest")
    if node_type == "file":
        _require(_is_sha256(entry["sha256"]) and entry["symlink_target"] is None, CP_RUNTIME_CLOSURE_SCHEMA, "file content identity is incomplete")
    elif node_type == "directory":
        _require(entry["sha256"] is None and entry["symlink_target"] is None and entry["size_bytes"] == 0, CP_RUNTIME_CLOSURE_SCHEMA, "directory must not claim content")
    else:
        _require(entry["sha256"] is None and type(entry["symlink_target"]) is str and entry["symlink_target"], CP_RUNTIME_CLOSURE_SCHEMA, "symlink target is incomplete")
    xattrs = entry["xattrs"]
    _require(type(xattrs) is list, CP_RUNTIME_CLOSURE_SCHEMA, "xattrs must be an array")
    xattr_names = []
    for xattr in xattrs:
        _require(type(xattr) is dict and set(xattr) == _XATTR_KEYS, CP_RUNTIME_CLOSURE_SCHEMA, "xattr has unexpected fields")
        _require(type(xattr["name"]) is str and xattr["name"], CP_RUNTIME_CLOSURE_SCHEMA, "xattr name must be nonempty")
        _require(_is_sha256(xattr["value_sha256"]), CP_RUNTIME_CLOSURE_SCHEMA, "xattr value digest is invalid")
        xattr_names.append(xattr["name"])
    _require(xattr_names == sorted(xattr_names) and len(xattr_names) == len(set(xattr_names)), CP_RUNTIME_CLOSURE_SCHEMA, "xattrs must be sorted and unique")
    capabilities = entry["capabilities"]
    _require(type(capabilities) is list and all(type(item) is str and item for item in capabilities), CP_RUNTIME_CLOSURE_SCHEMA, "capabilities must be strings")
    _require(capabilities == sorted(capabilities) and len(capabilities) == len(set(capabilities)), CP_RUNTIME_CLOSURE_SCHEMA, "capabilities must be sorted and unique")
    provenance = entry["provenance"]
    _require(type(provenance) is dict and set(provenance) == _PROVENANCE_KEYS, CP_RUNTIME_CLOSURE_SCHEMA, "provenance has unexpected fields")
    _require(all(type(provenance[key]) is str and provenance[key] for key in _PROVENANCE_KEYS), CP_RUNTIME_CLOSURE_SCHEMA, "provenance must name immutable bytes")
    _require(
        provenance["immutable_ref"].startswith("sha256:") and _is_sha256(provenance["immutable_ref"][7:]),
        CP_RUNTIME_CLOSURE_SCHEMA,
        "provenance immutable_ref must bind a SHA-256 identity",
    )
    authority = entry["root_lock_input_id"]
    _require(authority is None or type(authority) is str and authority, CP_RUNTIME_CLOSURE_SCHEMA, "root-lock authority must be null or nonempty")


def parse_verity_rules(data: bytes) -> dict:
    raw = canonical_loads(data)
    _require(type(raw) is dict and set(raw) == _RULES_TOP_KEYS, CP_VERITY_RULES_SCHEMA, "unexpected verity-rules fields")
    _require(raw == _SUPPORTED_RULES, CP_VERITY_RULES_SCHEMA, "verity rules differ from the complete supported construction contract")
    return raw


def parse_tcb_identity(data: bytes) -> dict:
    raw = canonical_loads(data)
    _require(type(raw) is dict and set(raw) == _TCB_TOP_KEYS, CP_TCB_IDENTITY_SCHEMA, "unexpected TCB identity fields")
    _require(raw["schema"] == TCB_IDENTITY_SCHEMA, CP_TCB_IDENTITY_SCHEMA, "unexpected TCB identity schema")
    _require(raw["status"] == DECLARED_UNVERIFIED, CP_PROVENANCE_STATUS, "TCB identity must remain declared_unverified")
    _parse_executable(raw["caller"])
    _parse_executable(raw["launcher"])
    sandbox = raw["sandbox"]
    _require(type(sandbox) is dict and set(sandbox) == _SANDBOX_KEYS, CP_TCB_IDENTITY_SCHEMA, "sandbox identity has unexpected fields")
    _require(sandbox["backend"] in ("bubblewrap", "unshare"), CP_TCB_IDENTITY_SCHEMA, "sandbox backend is unsupported")
    _parse_executable(sandbox["executable"])
    _require(sandbox["helper"] is None or type(sandbox["helper"]) is dict, CP_TCB_IDENTITY_SCHEMA, "sandbox helper must be null or an executable")
    if sandbox["helper"] is not None:
        _parse_executable(sandbox["helper"])
    kernel = raw["kernel_feature_contract"]
    _require(type(kernel) is dict and set(kernel) == _KERNEL_CONTRACT_KEYS, CP_TCB_IDENTITY_SCHEMA, "kernel contract has unexpected fields")
    _require(
        kernel["schema"] == "conf-proc-kernel-features/v1" and _is_sha256(kernel["sha256"]),
        CP_TCB_IDENTITY_SCHEMA,
        "kernel contract must use the supported schema and bind exact bytes",
    )
    return raw


def _parse_executable(raw: object) -> None:
    _require(type(raw) is dict and set(raw) == _EXECUTABLE_KEYS, CP_TCB_IDENTITY_SCHEMA, "executable identity has unexpected fields")
    _require(type(raw["logical_name"]) is str and raw["logical_name"] and _is_sha256(raw["sha256"]), CP_TCB_IDENTITY_SCHEMA, "executable must bind exact bytes")
    _require(raw["linkage"] in ("static", "dynamic"), CP_TCB_IDENTITY_SCHEMA, "executable linkage must be static or dynamic")
    libraries = raw["library_sha256s"]
    _require(type(libraries) is list and all(_is_sha256(item) for item in libraries), CP_TCB_IDENTITY_SCHEMA, "library identities must be digests")
    _require(libraries == sorted(libraries) and len(libraries) == len(set(libraries)), CP_TCB_IDENTITY_SCHEMA, "library identities must be sorted and unique")
    if raw["linkage"] == "static":
        _require(raw["interpreter_sha256"] is None and raw["loader_sha256"] is None and libraries == [], CP_TCB_IDENTITY_SCHEMA, "static executable must not claim dynamic dependencies")
    else:
        _require(_is_sha256(raw["interpreter_sha256"]) and _is_sha256(raw["loader_sha256"]) and libraries, CP_TCB_IDENTITY_SCHEMA, "dynamic executable closure is incomplete")


def derive_inputs(
    *,
    root_lock_bytes: bytes,
    runtime_closure_bytes: bytes,
    verity_rules_bytes: bytes,
    tcb_identity_bytes: bytes,
    builder_source_bytes: bytes,
    policy_bytes: bytes,
) -> ProvenanceInputs:
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
    root_lock = _verify_root_lock_authority(
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
    execution_digest = _digest(canonical_dumps(fields))
    return ProvenanceInputs(
        artifact_input_schema=root_lock["schema"],
        artifact_input_sha256=fields["artifact_input_sha256"],
        runtime_closure_sha256=fields["runtime_closure_sha256"],
        verity_rules_sha256=fields["verity_rules_sha256"],
        tcb_identity_sha256=fields["tcb_identity_sha256"],
        builder_source_sha256=fields["builder_source_sha256"],
        policy_sha256=fields["policy_sha256"],
        execution_provenance_sha256=execution_digest,
        root_lock_bytes=root_lock_bytes,
        runtime_closure_bytes=runtime_closure_bytes,
        verity_rules_bytes=verity_rules_bytes,
        tcb_identity_bytes=tcb_identity_bytes,
        builder_source_bytes=builder_source_bytes,
        policy_bytes=policy_bytes,
    )


def _verify_root_lock_authority(
    root_lock_bytes: bytes,
    closure: dict,
    *,
    builder_source_sha256: str,
    policy_sha256: str,
    policy_size_bytes: int,
) -> dict:
    lock = _parse_root_lock_authority(root_lock_bytes)
    inputs = {item["id"]: item for item in lock["inputs"]}
    policy_input_id = lock["policy_input_id"]
    _require(
        type(policy_input_id) is str
        and policy_input_id in inputs
        and inputs[policy_input_id].get("sha256") == policy_sha256
        and inputs[policy_input_id].get("size_bytes") == policy_size_bytes,
        CP_PROVENANCE_AUTHORITY,
        "policy bytes disagree with the root-lock authority",
    )
    designated_builder_entries = [
        entry for entry in closure["entries"] if entry["logical_role"] == "conf_proc_source"
    ]
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
        _require(input_id in inputs, CP_PROVENANCE_AUTHORITY, "runtime closure cites an unknown root-lock input")
        authority = inputs[input_id]
        provenance = entry["provenance"]
        _require(
            authority.get("sha256") == entry["sha256"]
            and authority.get("size_bytes") == entry["size_bytes"]
            and authority.get("role") == entry["logical_role"]
            and authority.get("source_retrieval_scheme") == provenance["scheme"]
            and authority.get("source_retrieval_identity") == provenance["identity"]
            and authority.get("source_retrieval_immutable_ref") == provenance["immutable_ref"],
            CP_PROVENANCE_AUTHORITY,
            "runtime closure disagrees with root-lock authority",
        )
    return lock


def _parse_root_lock_authority(data: bytes) -> dict:
    raw = canonical_loads(data)
    _require(
        type(raw) is dict and set(raw) == _LOCK_TOP_KEYS,
        CP_PROVENANCE_AUTHORITY,
        "root lock has unexpected top-level fields",
    )
    _require(
        raw["schema"] == "conf-proc-lock/v1"
        and type(raw["lock_version"]) is int
        and raw["lock_version"] == 1,
        CP_PROVENANCE_AUTHORITY,
        "root lock schema or version is unsupported",
    )

    base = raw["base_image_record"]
    _require(
        type(base) is dict and set(base) == _LOCK_BASE_KEYS,
        CP_PROVENANCE_AUTHORITY,
        "root lock base-image record has unexpected fields",
    )
    _require(base["kind"] in ("vhd", "vmi"), CP_PROVENANCE_AUTHORITY, "root lock base-image kind is unsupported")
    for key in (
        "provider",
        "identity_namespace",
        "identity_name",
        "identity_immutable_revision",
        "content_media_type",
        "recorded_retrieval_identity",
        "recorded_retrieval_immutable_ref",
    ):
        _require(type(base[key]) is str and base[key], CP_PROVENANCE_AUTHORITY, "root lock base-image identity is incomplete")
    _require(_is_sha256(base["content_sha256"]), CP_PROVENANCE_AUTHORITY, "root lock base-image digest is invalid")
    _require(
        type(base["content_size_bytes"]) is int and base["content_size_bytes"] >= 0,
        CP_PROVENANCE_AUTHORITY,
        "root lock base-image size is invalid",
    )
    _require(base["availability"] == "record-only", CP_PROVENANCE_AUTHORITY, "root lock base-image availability is unsupported")
    _require(
        base["recorded_retrieval_scheme"] in ("https", "oci", "git", "local-fixture", "other"),
        CP_PROVENANCE_AUTHORITY,
        "root lock base-image retrieval scheme is unsupported",
    )

    cmdline = raw["future_cmdline"]
    _require(
        type(cmdline) is str and cmdline and not any(marker in cmdline for marker in ("${", "{{", "%(")),
        CP_PROVENANCE_AUTHORITY,
        "root lock future cmdline is invalid",
    )

    raw_inputs = raw["inputs"]
    _require(type(raw_inputs) is list and raw_inputs, CP_PROVENANCE_AUTHORITY, "root lock inputs must be nonempty")
    for item in raw_inputs:
        _parse_root_lock_input(item)
    ids = [item["id"] for item in raw_inputs]
    _require(ids == sorted(ids) and len(ids) == len(set(ids)), CP_PROVENANCE_AUTHORITY, "root lock input IDs must be sorted and unique")
    inputs = {item["id"]: item for item in raw_inputs}
    _require(
        all(parent in inputs for item in raw_inputs for parent in item["derivation_parent_ids"]),
        CP_PROVENANCE_AUTHORITY,
        "root lock derivation cites an unknown parent",
    )

    signers = raw["authorized_module_signers"]
    _require(type(signers) is list, CP_PROVENANCE_AUTHORITY, "root lock signers must be an array")
    for signer in signers:
        _require(
            type(signer) is dict and set(signer) == _LOCK_SIGNER_KEYS,
            CP_PROVENANCE_AUTHORITY,
            "root lock signer has unexpected fields",
        )
        _require(
            all(_is_sha256(signer[key]) for key in ("certificate_sha256", "spki_sha256", "subject_sha256"))
            and signer["usage"] == "kernel-module-signing",
            CP_PROVENANCE_AUTHORITY,
            "root lock signer identity is invalid",
        )
    signer_ids = [signer["certificate_sha256"] for signer in signers]
    _require(
        signer_ids == sorted(signer_ids) and len(signer_ids) == len(set(signer_ids)),
        CP_PROVENANCE_AUTHORITY,
        "root lock signers must be sorted and unique",
    )

    _require(
        raw["image_specs"] == {"models": {}, "runtime-policy": {}},
        CP_PROVENANCE_AUTHORITY,
        "root lock image_specs must be the exact empty geometry-free object",
    )
    policy_input_id = raw["policy_input_id"]
    _require(
        type(policy_input_id) is str
        and policy_input_id in inputs
        and inputs[policy_input_id]["role"] == "policy_tree_input",
        CP_PROVENANCE_AUTHORITY,
        "root lock policy authority is invalid",
    )

    tool_ids = raw["tool_ids"]
    build_tool_ids = sorted(item["id"] for item in raw_inputs if item["role"] == "build_tool")
    _require(
        type(tool_ids) is list
        and all(type(item) is str for item in tool_ids)
        and tool_ids == build_tool_ids
        and len(tool_ids) == len(set(tool_ids))
        and all(item in inputs and inputs[item]["role"] == "build_tool" for item in tool_ids),
        CP_PROVENANCE_AUTHORITY,
        "root lock tool IDs must exhaust the build-tool authority",
    )
    role_counts = {role: sum(item["role"] == role for item in raw_inputs) for role in _LOCK_ROLES}
    _require(
        all(role_counts[role] == 1 for role in _LOCK_SINGLE_ROLES)
        and role_counts["conf_proc_source"] >= 1
        and sum(role_counts[role] for role in _LOCK_TREE_ROLES) >= 1,
        CP_PROVENANCE_AUTHORITY,
        "root lock role cardinality is invalid",
    )
    tool_component_list = [inputs[tool_id]["component"] for tool_id in tool_ids]
    _require(
        len(tool_component_list) == len(set(tool_component_list))
        and _LOCK_REQUIRED_TOOLS <= set(tool_component_list),
        CP_PROVENANCE_AUTHORITY,
        "root lock build-tool components must be unique and complete",
    )
    return raw


def _parse_root_lock_input(raw: object) -> None:
    _require(
        type(raw) is dict and set(raw) == _LOCK_INPUT_KEYS,
        CP_PROVENANCE_AUTHORITY,
        "root lock input has unexpected fields",
    )
    input_id = raw["id"]
    _require(
        type(input_id) is str and input_id and input_id.isascii() and not any(character.isspace() for character in input_id),
        CP_PROVENANCE_AUTHORITY,
        "root lock input ID is invalid",
    )
    _require(
        type(raw["role"]) is str and raw["role"] in _LOCK_ROLES,
        CP_PROVENANCE_AUTHORITY,
        "root lock input role is invalid",
    )
    _require(type(raw["component"]) is str and raw["component"], CP_PROVENANCE_AUTHORITY, "root lock component is empty")
    _require(_is_sha256(raw["sha256"]), CP_PROVENANCE_AUTHORITY, "root lock input digest is invalid")
    _require(type(raw["size_bytes"]) is int and raw["size_bytes"] >= 0, CP_PROVENANCE_AUTHORITY, "root lock input size is invalid")
    _require(_relative_normal_path(raw["source_local_path"]), CP_PROVENANCE_AUTHORITY, "root lock source path is invalid")
    _require(
        raw["source_retrieval_scheme"] in ("https", "oci", "git", "local-fixture", "generated", "other"),
        CP_PROVENANCE_AUTHORITY,
        "root lock input retrieval scheme is invalid",
    )
    _require(
        all(type(raw[key]) is str and raw[key] for key in ("source_retrieval_identity", "source_retrieval_immutable_ref", "derivation_recipe_id")),
        CP_PROVENANCE_AUTHORITY,
        "root lock input provenance is incomplete",
    )
    derivation_kind = raw["derivation_kind"]
    _require(derivation_kind in ("fetched", "built", "extracted", "fixture"), CP_PROVENANCE_AUTHORITY, "root lock derivation kind is invalid")
    parents = raw["derivation_parent_ids"]
    _require(
        type(parents) is list
        and all(type(item) is str for item in parents)
        and parents == sorted(parents)
        and len(parents) == len(set(parents)),
        CP_PROVENANCE_AUTHORITY,
        "root lock derivation parents are invalid",
    )
    _require(
        bool(parents) or derivation_kind == "fixture" or raw["role"] == "build_tool",
        CP_PROVENANCE_AUTHORITY,
        "root lock derivation is missing parents",
    )
    _require(_is_sha256(raw["derivation_parameters_sha256"]), CP_PROVENANCE_AUTHORITY, "root lock derivation digest is invalid")
    placements = raw["placements"]
    _require(type(placements) is list, CP_PROVENANCE_AUTHORITY, "root lock placements must be an array")
    for placement in placements:
        _parse_root_lock_placement(placement, input_id)
    placement_keys = [(placement["image"], placement["path"]) for placement in placements]
    _require(
        placement_keys == sorted(placement_keys) and len(placement_keys) == len(set(placement_keys)),
        CP_PROVENANCE_AUTHORITY,
        "root lock placements must be sorted and unique",
    )
    _require(
        bool(placements) or raw["role"] in ("build_tool", "kernel_trusted_cert_bundle"),
        CP_PROVENANCE_AUTHORITY,
        "root lock input is missing a placement",
    )


def _parse_root_lock_placement(raw: object, owning_input_id: str) -> None:
    _require(
        type(raw) is dict and set(raw) == _LOCK_PLACEMENT_KEYS,
        CP_PROVENANCE_AUTHORITY,
        "root lock placement has unexpected fields",
    )
    _require(
        type(raw["image"]) is str and raw["image"] in _LOCK_IMAGES and _lock_absolute_path(raw["path"]),
        CP_PROVENANCE_AUTHORITY,
        "root lock placement path is invalid",
    )
    _require(raw["node_type"] in ("file", "directory", "symlink"), CP_PROVENANCE_AUTHORITY, "root lock placement node type is invalid")
    _require(type(raw["mode"]) is int and 0 <= raw["mode"] <= 0o7777, CP_PROVENANCE_AUTHORITY, "root lock placement mode is invalid")
    _require(type(raw["uid"]) is int and raw["uid"] >= 0 and type(raw["gid"]) is int and raw["gid"] >= 0, CP_PROVENANCE_AUTHORITY, "root lock placement ownership is invalid")
    _require(
        type(raw["xattrs"]) is list
        and all(item in ("system.posix_acl_access", "system.posix_acl_default") for item in raw["xattrs"]),
        CP_PROVENANCE_AUTHORITY,
        "root lock placement xattrs are invalid",
    )
    if raw["node_type"] == "file":
        valid_binding = raw["source_input_id"] == owning_input_id and raw["target"] is None
    elif raw["node_type"] == "symlink":
        valid_binding = raw["source_input_id"] is None and type(raw["target"]) is str and bool(raw["target"])
    else:
        valid_binding = raw["source_input_id"] is None and raw["target"] is None
    _require(valid_binding, CP_PROVENANCE_AUTHORITY, "root lock placement source binding is invalid")


def inspect_bindings(
    *,
    manifest_bytes: bytes,
    sbom_bytes: bytes,
    inputs: ProvenanceInputs,
) -> None:
    rederived = derive_inputs(
        root_lock_bytes=inputs.root_lock_bytes,
        runtime_closure_bytes=inputs.runtime_closure_bytes,
        verity_rules_bytes=inputs.verity_rules_bytes,
        tcb_identity_bytes=inputs.tcb_identity_bytes,
        builder_source_bytes=inputs.builder_source_bytes,
        policy_bytes=inputs.policy_bytes,
    )
    _require(
        inputs == rederived,
        CP_PROVENANCE_AUTHORITY,
        "retained authorities no longer match the derived provenance identity",
    )
    inputs = rederived
    root_lock = _parse_root_lock_authority(inputs.root_lock_bytes)
    policy = canonical_loads(inputs.policy_bytes)
    manifest = canonical_loads(manifest_bytes)
    _validate_manifest_v2_shape(manifest)
    actual = manifest["provenance"]
    expected = _binding(inputs)
    _require(type(actual) is dict and set(actual) == _BINDING_KEYS, CP_PROVENANCE_BINDING, "manifest provenance has unexpected fields")
    _require(actual == expected, CP_PROVENANCE_BINDING, "manifest provenance does not match trusted input derivation")
    _require(
        manifest["lock_schema"] == inputs.artifact_input_schema
        and manifest["lock_sha256"] == inputs.artifact_input_sha256,
        CP_PROVENANCE_BINDING,
        "manifest root-lock identity does not match trusted bytes",
    )
    _verify_manifest_root_authorities(manifest, inputs, root_lock)
    _require(
        manifest["policy"]
        == {
            "policy_input_id": root_lock["policy_input_id"],
            "policy_schema": policy["schema"],
            "process_policy_sha256": inputs.policy_sha256,
        },
        CP_PROVENANCE_BINDING,
        "manifest policy authority does not match trusted bytes",
    )
    _require(
        manifest["reproducibility"]["build_epoch"] == _build_epoch(inputs.artifact_input_sha256),
        CP_PROVENANCE_BINDING,
        "manifest build epoch does not match the artifact-input identity",
    )
    _require(
        manifest["sbom"]["sha256"] == _digest(sbom_bytes),
        CP_PROVENANCE_BINDING,
        "manifest SBOM digest does not match candidate bytes",
    )

    sbom = canonical_loads(sbom_bytes)
    _validate_spdx_v2_shape(sbom)
    appliance = [item for item in sbom["packages"] if type(item) is dict and item.get("SPDXID") == "SPDXRef-Package-appliance"]
    _require(len(appliance) == 1, CP_PROVENANCE_BINDING, "SPDX must contain exactly one appliance package")
    references = appliance[0].get("externalRefs")
    _require(references == _spdx_references(inputs), CP_PROVENANCE_BINDING, "SPDX provenance references do not match trusted input derivation")
    _require(
        appliance[0]["checksums"]
        == [{"algorithm": "SHA256", "checksumValue": inputs.artifact_input_sha256}],
        CP_PROVENANCE_BINDING,
        "SPDX appliance checksum does not match artifact input",
    )
    _require(
        sbom["name"] == f"conf-proc-appliance-{inputs.artifact_input_sha256[:16]}"
        and sbom["documentNamespace"] == _spdx_namespace(inputs.artifact_input_sha256),
        CP_PROVENANCE_BINDING,
        "SPDX name or namespace is not artifact-input-addressed",
    )
    _require(
        sbom["creationInfo"]["created"] == _build_timestamp(inputs.artifact_input_sha256),
        CP_PROVENANCE_BINDING,
        "SPDX creation timestamp does not match artifact-input build epoch",
    )


def _verify_manifest_root_authorities(manifest: dict, inputs: ProvenanceInputs, root: dict) -> None:
    expected_inputs = [
        {key: item[key] for key in _MANIFEST_INPUT_KEYS}
        for item in root["inputs"]
    ]
    expected_inventory = {image_id: [] for image_id in _LOCK_IMAGES}
    for item in root["inputs"]:
        for placement in item["placements"]:
            expected_inventory[placement["image"]].append(
                {
                    "path": placement["path"],
                    "node_type": placement["node_type"],
                    "mode": placement["mode"],
                    "uid": placement["uid"],
                    "gid": placement["gid"],
                    "xattrs": placement["xattrs"],
                    "sha256": item["sha256"] if placement["node_type"] == "file" else None,
                    "size_bytes": item["size_bytes"] if placement["node_type"] == "file" else None,
                    "symlink_target": placement["target"],
                    "source_input_id": placement["source_input_id"],
                }
            )
    for records in expected_inventory.values():
        records.sort(key=lambda record: record["path"])
    root_inputs = {item["id"]: item for item in root["inputs"]}
    expected_toolchain = [
        {
            "tool_id": tool_id,
            "component": root_inputs[tool_id]["component"],
            "resolved_path_sha256": root_inputs[tool_id]["sha256"],
        }
        for tool_id in root["tool_ids"]
    ]
    trusted_bundle_ids = [
        item["id"] for item in root["inputs"] if item["role"] == "kernel_trusted_cert_bundle"
    ]
    _require(
        manifest["base_image_record"] == root["base_image_record"]
        and manifest["future_cmdline"] == root["future_cmdline"]
        and manifest["inputs"] == expected_inputs
        and manifest["inventory"] == expected_inventory
        and manifest["toolchain"] == expected_toolchain,
        CP_PROVENANCE_BINDING,
        "manifest duplicates disagree with root-lock authority",
    )
    module_authority = manifest["module_authority"]
    _require(
        trusted_bundle_ids == [module_authority["trusted_bundle_input_id"]]
        and module_authority["authorized_signer_certificate_sha256"]
        == [signer["certificate_sha256"] for signer in root["authorized_module_signers"]],
        CP_PROVENANCE_BINDING,
        "manifest module authority disagrees with root-lock authority",
    )


def _validate_manifest_v2_shape(raw: object) -> None:
    _require(type(raw) is dict and set(raw) == _MANIFEST_TOP_KEYS, CP_PROVENANCE_BINDING, "manifest v2 has unexpected fields")
    _require(raw["schema"] == "conf-proc-appliance-manifest/v2" and raw["manifest_version"] == 2, CP_PROVENANCE_BINDING, "manifest is not v2")
    _require(type(raw["lock_schema"]) is str and raw["lock_schema"] and _is_sha256(raw["lock_sha256"]), CP_PROVENANCE_BINDING, "manifest lock identity is invalid")
    _require(type(raw["reproducibility"]) is dict and set(raw["reproducibility"]) == _REPRODUCIBILITY_KEYS, CP_PROVENANCE_BINDING, "manifest reproducibility shape is invalid")
    _require(
        _nonnegative_int(raw["reproducibility"]["build_epoch"])
        and raw["reproducibility"]["sort_order"] == "byte-wise-path"
        and raw["reproducibility"]["codec"] == "conf-proc-canonical-json/v1",
        CP_PROVENANCE_BINDING,
        "manifest reproducibility values are invalid",
    )
    _require(type(raw["base_image_record"]) is dict and set(raw["base_image_record"]) == _BASE_IMAGE_KEYS, CP_PROVENANCE_BINDING, "manifest base image shape is invalid")
    base = raw["base_image_record"]
    _require(
        base["kind"] in ("vhd", "vmi")
        and _is_sha256(base["content_sha256"])
        and _nonnegative_int(base["content_size_bytes"])
        and base["availability"] == "record-only"
        and all(type(base[key]) is str and base[key] for key in _BASE_IMAGE_KEYS - {"content_size_bytes"}),
        CP_PROVENANCE_BINDING,
        "manifest base image values are invalid",
    )
    _require(type(raw["future_cmdline"]) is str and raw["future_cmdline"], CP_PROVENANCE_BINDING, "manifest command line is invalid")
    _require(type(raw["images"]) is dict and set(raw["images"]) == _IMAGE_IDS, CP_PROVENANCE_BINDING, "manifest images are incomplete")
    for image in raw["images"].values():
        _require(type(image) is dict and set(image) == _IMAGE_KEYS, CP_PROVENANCE_BINDING, "manifest image shape is invalid")
        _require(
            _is_sha256(image["squashfs_sha256"])
            and _is_sha256(image["hash_device_sha256"])
            and _is_sha256(image["root_hash"])
            and _is_sha256(image["salt"])
            and _positive_int(image["squashfs_size_bytes"])
            and _positive_int(image["hash_device_size_bytes"])
            and image["data_block_size"] == 4096
            and image["hash_block_size"] == 4096
            and image["hash_algorithm"] == "sha256"
            and _valid_v5_uuid(image["uuid"]),
            CP_PROVENANCE_BINDING,
            "manifest image values are invalid",
        )
    _require(type(raw["inputs"]) is list, CP_PROVENANCE_BINDING, "manifest inputs must be an array")
    input_ids = []
    for item in raw["inputs"]:
        _require(type(item) is dict and set(item) == _MANIFEST_INPUT_KEYS, CP_PROVENANCE_BINDING, "manifest input shape is invalid")
        _require(
            all(type(item[key]) is str and item[key] for key in ("id", "role", "source_retrieval_scheme", "source_retrieval_identity", "source_retrieval_immutable_ref", "derivation_kind", "derivation_recipe_id"))
            and _is_sha256(item["sha256"])
            and _is_sha256(item["derivation_parameters_sha256"])
            and _nonnegative_int(item["size_bytes"])
            and type(item["derivation_parent_ids"]) is list
            and all(type(parent_id) is str and parent_id for parent_id in item["derivation_parent_ids"])
            and item["derivation_parent_ids"] == sorted(item["derivation_parent_ids"])
            and len(item["derivation_parent_ids"]) == len(set(item["derivation_parent_ids"])),
            CP_PROVENANCE_BINDING,
            "manifest input values are invalid",
        )
        input_ids.append(item["id"])
        _require(type(item["placements"]) is list, CP_PROVENANCE_BINDING, "manifest placements must be an array")
        placement_keys = []
        for placement in item["placements"]:
            _require(type(placement) is dict and set(placement) == _PLACEMENT_KEYS, CP_PROVENANCE_BINDING, "manifest placement shape is invalid")
            _require(
                type(placement["image"]) is str
                and placement["image"] in _IMAGE_IDS
                and _absolute_normal_path(placement["path"])
                and placement["node_type"] in ("file", "directory", "symlink")
                and all(_nonnegative_int(placement[key]) for key in ("mode", "uid", "gid"))
                and type(placement["xattrs"]) is list,
                CP_PROVENANCE_BINDING,
                "manifest placement values are invalid",
            )
            placement_keys.append((placement["image"], placement["path"]))
        _require(placement_keys == sorted(placement_keys) and len(placement_keys) == len(set(placement_keys)), CP_PROVENANCE_BINDING, "manifest placements must be sorted and unique")
    _require(input_ids == sorted(input_ids) and len(input_ids) == len(set(input_ids)), CP_PROVENANCE_BINDING, "manifest inputs must be sorted and unique")
    _require(type(raw["inventory"]) is dict and set(raw["inventory"]) == _IMAGE_IDS, CP_PROVENANCE_BINDING, "manifest inventory is incomplete")
    for inventory in raw["inventory"].values():
        _require(type(inventory) is list, CP_PROVENANCE_BINDING, "manifest inventory must be arrays")
        inventory_paths = []
        for item in inventory:
            _require(type(item) is dict and set(item) == _INVENTORY_KEYS, CP_PROVENANCE_BINDING, "manifest inventory shape is invalid")
            _require(
                _absolute_normal_path(item["path"])
                and item["node_type"] in ("file", "directory", "symlink")
                and all(_nonnegative_int(item[key]) for key in ("mode", "uid", "gid"))
                and type(item["xattrs"]) is list,
                CP_PROVENANCE_BINDING,
                "manifest inventory values are invalid",
            )
            inventory_paths.append(item["path"])
        _require(inventory_paths == sorted(inventory_paths) and len(inventory_paths) == len(set(inventory_paths)), CP_PROVENANCE_BINDING, "manifest inventory must be sorted and unique")
    _require(type(raw["bindings"]) is dict and set(raw["bindings"]) == _IMAGE_IDS, CP_PROVENANCE_BINDING, "manifest bindings are incomplete")
    for binding in raw["bindings"].values():
        _require(type(binding) is dict and set(binding) == _BINDING_CATEGORIES, CP_PROVENANCE_BINDING, "manifest binding shape is invalid")
        for paths in binding.values():
            _require(
                type(paths) is list
                and all(_absolute_normal_path(path) for path in paths)
                and paths == sorted(paths)
                and len(paths) == len(set(paths)),
                CP_PROVENANCE_BINDING,
                "manifest binding paths are invalid",
            )
    _require(type(raw["policy"]) is dict and set(raw["policy"]) == _POLICY_KEYS and all(type(raw["policy"][key]) is str and raw["policy"][key] for key in ("policy_input_id", "policy_schema")) and _is_sha256(raw["policy"]["process_policy_sha256"]), CP_PROVENANCE_BINDING, "manifest policy shape is invalid")
    _require(type(raw["module_authority"]) is dict and set(raw["module_authority"]) == _MODULE_AUTHORITY_KEYS, CP_PROVENANCE_BINDING, "manifest module authority shape is invalid")
    authority = raw["module_authority"]
    _require(type(authority["trusted_bundle_input_id"]) is str and authority["trusted_bundle_input_id"], CP_PROVENANCE_BINDING, "manifest trusted bundle identity is invalid")
    signers = authority["authorized_signer_certificate_sha256"]
    _require(
        type(signers) is list
        and all(_is_sha256(item) for item in signers)
        and signers == sorted(signers)
        and len(signers) == len(set(signers)),
        CP_PROVENANCE_BINDING,
        "manifest authorized signers are invalid",
    )
    for collection, keys in ((authority["module_inventory"], _MODULE_INVENTORY_KEYS), (authority["firmware_inventory"], _FIRMWARE_INVENTORY_KEYS)):
        _require(type(collection) is list, CP_PROVENANCE_BINDING, "manifest module/firmware inventories must be arrays")
        paths = []
        for item in collection:
            _require(type(item) is dict and set(item) == keys and _absolute_normal_path(item["path"]) and _is_sha256(item["sha256"]), CP_PROVENANCE_BINDING, "manifest module/firmware inventory is invalid")
            if "signer_certificate_sha256" in item:
                _require(_is_sha256(item["signer_certificate_sha256"]), CP_PROVENANCE_BINDING, "manifest module signer digest is invalid")
            paths.append(item["path"])
        _require(paths == sorted(paths) and len(paths) == len(set(paths)), CP_PROVENANCE_BINDING, "manifest module/firmware paths must be sorted and unique")
    _require(type(raw["toolchain"]) is list, CP_PROVENANCE_BINDING, "manifest toolchain must be an array")
    tool_ids = []
    for item in raw["toolchain"]:
        _require(type(item) is dict and set(item) == _TOOLCHAIN_KEYS and all(type(item[key]) is str and item[key] for key in ("tool_id", "component")) and _is_sha256(item["resolved_path_sha256"]), CP_PROVENANCE_BINDING, "manifest toolchain shape is invalid")
        tool_ids.append(item["tool_id"])
    _require(tool_ids == sorted(tool_ids) and len(tool_ids) == len(set(tool_ids)), CP_PROVENANCE_BINDING, "manifest toolchain must be sorted and unique")
    _require(type(raw["sbom"]) is dict and set(raw["sbom"]) == _SBOM_REFERENCE_KEYS and raw["sbom"]["filename"] == "appliance.spdx.json" and _is_sha256(raw["sbom"]["sha256"]) and raw["sbom"]["spdx_version"] == "SPDX-2.3" and raw["sbom"]["document_spdx_id"] == "SPDXRef-DOCUMENT", CP_PROVENANCE_BINDING, "manifest SBOM reference is invalid")


def _validate_spdx_v2_shape(raw: object) -> None:
    _require(type(raw) is dict and set(raw) == _SPDX_TOP_KEYS, CP_PROVENANCE_BINDING, "SPDX document has unexpected fields")
    _require(raw["spdxVersion"] == "SPDX-2.3" and raw["dataLicense"] == "CC0-1.0" and raw["SPDXID"] == "SPDXRef-DOCUMENT", CP_PROVENANCE_BINDING, "SPDX document identity is invalid")
    _require(type(raw["name"]) is str and raw["name"] and _valid_uuid_urn(raw["documentNamespace"]), CP_PROVENANCE_BINDING, "SPDX name or namespace is invalid")
    _require(type(raw["creationInfo"]) is dict and set(raw["creationInfo"]) == _SPDX_CREATION_KEYS, CP_PROVENANCE_BINDING, "SPDX creationInfo shape is invalid")
    _require(_valid_timestamp(raw["creationInfo"]["created"]) and raw["creationInfo"]["creators"] == ["Tool: conf-proc-sbom-v1"], CP_PROVENANCE_BINDING, "SPDX creationInfo is invalid")
    _require(type(raw["packages"]) is list and raw["packages"], CP_PROVENANCE_BINDING, "SPDX packages are missing")
    package_ids = []
    for package in raw["packages"]:
        _require(type(package) is dict, CP_PROVENANCE_BINDING, "SPDX package must be an object")
        expected_keys = _SPDX_PACKAGE_KEYS | ({"externalRefs"} if package.get("SPDXID") == "SPDXRef-Package-appliance" else set())
        _require(set(package) == expected_keys, CP_PROVENANCE_BINDING, "SPDX package shape is invalid")
        _require(
            _valid_spdx_id(package["SPDXID"])
            and all(type(package[key]) is str and package[key] for key in ("name", "downloadLocation", "licenseConcluded", "licenseDeclared", "copyrightText", "supplier", "originator"))
            and type(package["primaryPackagePurpose"]) is str
            and package["primaryPackagePurpose"] in _SPDX_PACKAGE_PURPOSES,
            CP_PROVENANCE_BINDING,
            "SPDX package values are invalid",
        )
        _validate_spdx_checksum(package["checksums"])
        package_ids.append(package["SPDXID"])
        if "externalRefs" in package:
            _require(type(package["externalRefs"]) is list, CP_PROVENANCE_BINDING, "SPDX externalRefs must be an array")
            for reference in package["externalRefs"]:
                _require(type(reference) is dict and set(reference) == _SPDX_EXTERNAL_REF_KEYS, CP_PROVENANCE_BINDING, "SPDX externalRef shape is invalid")
                _require(reference["referenceCategory"] == "OTHER" and type(reference["referenceType"]) is str and reference["referenceType"] and type(reference["referenceLocator"]) is str and reference["referenceLocator"].startswith("sha256:") and _is_sha256(reference["referenceLocator"][7:]), CP_PROVENANCE_BINDING, "SPDX externalRef value is invalid")
    _require(package_ids == sorted(package_ids) and len(package_ids) == len(set(package_ids)), CP_PROVENANCE_BINDING, "SPDX package IDs must be sorted and unique")
    _require(package_ids.count("SPDXRef-Package-appliance") == 1, CP_PROVENANCE_BINDING, "SPDX appliance package is not unique")
    _require(type(raw["files"]) is list and type(raw["relationships"]) is list, CP_PROVENANCE_BINDING, "SPDX files and relationships must be arrays")
    file_ids = []
    file_names = []
    for item in raw["files"]:
        _require(type(item) is dict and set(item) == _SPDX_FILE_KEYS, CP_PROVENANCE_BINDING, "SPDX file shape is invalid")
        _require(_valid_spdx_id(item["SPDXID"]) and type(item["fileName"]) is str and item["fileName"] and "\x00" not in item["fileName"], CP_PROVENANCE_BINDING, "SPDX file values are invalid")
        _validate_spdx_checksum(item["checksums"])
        file_ids.append(item["SPDXID"])
        file_names.append(item["fileName"])
    _require(file_names == sorted(file_names) and len(file_ids) == len(set(file_ids)), CP_PROVENANCE_BINDING, "SPDX files must be sorted with unique IDs")
    known_ids = set(package_ids) | set(file_ids)
    relationship_keys = []
    for item in raw["relationships"]:
        _require(type(item) is dict and set(item) == _SPDX_RELATIONSHIP_KEYS, CP_PROVENANCE_BINDING, "SPDX relationship shape is invalid")
        key = (item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"])
        _require(
            all(type(value) is str for value in key)
            and item["spdxElementId"] in known_ids
            and item["relatedSpdxElement"] in known_ids
            and item["relationshipType"] in _SPDX_RELATIONSHIP_TYPES,
            CP_PROVENANCE_BINDING,
            "SPDX relationship value is invalid",
        )
        relationship_keys.append(key)
    _require(relationship_keys == sorted(relationship_keys) and len(relationship_keys) == len(set(relationship_keys)), CP_PROVENANCE_BINDING, "SPDX relationships must be sorted and unique")
    _require(raw["documentDescribes"] == ["SPDXRef-Package-appliance"], CP_PROVENANCE_BINDING, "SPDX documentDescribes is invalid")


def _validate_spdx_checksum(raw: object) -> None:
    _require(type(raw) is list and len(raw) == 1 and type(raw[0]) is dict and set(raw[0]) == _SPDX_CHECKSUM_KEYS, CP_PROVENANCE_BINDING, "SPDX checksum shape is invalid")
    _require(raw[0]["algorithm"] == "SHA256" and _is_sha256(raw[0]["checksumValue"]), CP_PROVENANCE_BINDING, "SPDX checksum is invalid")


def _binding(inputs: ProvenanceInputs) -> dict:
    return {
        "schema": PROVENANCE_BINDING_SCHEMA,
        "artifact_input_sha256": inputs.artifact_input_sha256,
        "execution_provenance_sha256": inputs.execution_provenance_sha256,
        "runtime_closure": {"sha256": inputs.runtime_closure_sha256, "status": DECLARED_UNVERIFIED},
        "verity_rules_sha256": inputs.verity_rules_sha256,
        "tcb_identity": {"sha256": inputs.tcb_identity_sha256, "status": DECLARED_UNVERIFIED},
        "builder_source_sha256": inputs.builder_source_sha256,
        "policy_sha256": inputs.policy_sha256,
    }


def _spdx_references(inputs: ProvenanceInputs) -> list[dict]:
    values = {
        "conf-proc-artifact-input": inputs.artifact_input_sha256,
        "conf-proc-builder-source": inputs.builder_source_sha256,
        "conf-proc-execution-provenance": inputs.execution_provenance_sha256,
        "conf-proc-policy": inputs.policy_sha256,
        "conf-proc-runtime-closure": inputs.runtime_closure_sha256,
        "conf-proc-tcb-identity": inputs.tcb_identity_sha256,
        "conf-proc-verity-rules": inputs.verity_rules_sha256,
    }
    return [
        {"referenceCategory": "OTHER", "referenceType": kind, "referenceLocator": f"sha256:{values[kind]}"}
        for kind in _SPDX_REFERENCE_TYPES
    ]


def _build_epoch(artifact_input_sha256: str) -> int:
    start = 946684800
    end = 4102444799
    digest = hashlib.sha256(b"conf-proc/build-clock/v1" + bytes.fromhex(artifact_input_sha256)).digest()
    return start + int.from_bytes(digest[:8], "big") % (end - start)


def _build_timestamp(artifact_input_sha256: str) -> str:
    return datetime.fromtimestamp(_build_epoch(artifact_input_sha256), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _spdx_namespace(execution_provenance_sha256: str) -> str:
    digest = bytearray(
        hashlib.sha256(_SPDX_NAMESPACE_DOMAIN + bytes.fromhex(execution_provenance_sha256)).digest()[:16]
    )
    digest[6] = (digest[6] & 0x0F) | 0x50
    digest[8] = (digest[8] & 0x3F) | 0x80
    return f"urn:uuid:{uuid.UUID(bytes=bytes(digest))}"


def _nonnegative_int(value: object) -> bool:
    return type(value) is int and value >= 0


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _valid_v5_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return str(parsed) == value and parsed.version == 5 and parsed.variant == uuid.RFC_4122


def _valid_uuid_urn(value: object) -> bool:
    if type(value) is not str or not value.startswith("urn:uuid:"):
        return False
    try:
        return f"urn:uuid:{uuid.UUID(value[9:])}" == value
    except ValueError:
        return False


def _valid_timestamp(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value


def _valid_spdx_id(value: object) -> bool:
    allowed = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-")
    return type(value) is str and value.startswith("SPDXRef-") and len(value) > 8 and set(value[8:]) <= allowed


def _absolute_normal_path(value: object) -> bool:
    return (
        type(value) is str
        and "\x00" not in value
        and value.startswith("/")
        and value != "/"
        and posixpath.normpath(value) == value
    )


def _lock_absolute_path(value: object) -> bool:
    return (
        type(value) is str
        and "\x00" not in value
        and value.startswith("/")
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
