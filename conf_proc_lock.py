#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Structural schema and validator for the conf-proc-lock/v1 lock file.

This module only validates the shape of the lock JSON itself (roles,
cross-references, cardinality). It never reads the files an input
references from disk -- that belongs to the builder/inspector tree-walk
phases, which consume this parsed ``Lock`` as a trusted starting point.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from conf_proc_json import canonical_loads
from conf_proc_reasons import (
    CP_LOCK_BASE_IMAGE_RECORD,
    CP_LOCK_DUPLICATE_ID,
    CP_LOCK_INPUT_MISSING,
    CP_LOCK_INPUT_PATH_ESCAPE,
    CP_LOCK_PROVENANCE,
    CP_LOCK_ROLE,
    CP_LOCK_SCHEMA,
    ApplianceError,
)


LOCK_SCHEMA_ID: Final = "conf-proc-lock/v1"
LOCK_VERSION: Final = 1

ROLE_KERNEL: Final = "kernel"
ROLE_KERNEL_TRUSTED_CERT_BUNDLE: Final = "kernel_trusted_cert_bundle"
ROLE_FINAL_SYSTEMD_STUB: Final = "final_systemd_stub"
ROLE_FINAL_SYSTEMD_UNIT: Final = "final_systemd_unit"
ROLE_NVIDIA_CC_DRIVER: Final = "nvidia_cc_driver"
ROLE_NVIDIA_CC_FIRMWARE: Final = "nvidia_cc_firmware"
ROLE_CONF_PROC_SOURCE: Final = "conf_proc_source"
ROLE_SGLANG_IMAGE: Final = "sglang_image"
ROLE_INFERENCE_MODEL: Final = "inference_model"
ROLE_ASR_MODEL: Final = "asr_model"
ROLE_GATEWAY_DEPENDENCY_LOCK: Final = "gateway_dependency_lock"
ROLE_ASR_DEPENDENCY_LOCK: Final = "asr_dependency_lock"
ROLE_RUNTIME_TREE_INPUT: Final = "runtime_tree_input"
ROLE_POLICY_TREE_INPUT: Final = "policy_tree_input"
ROLE_MODELS_TREE_INPUT: Final = "models_tree_input"
ROLE_BUILD_TOOL: Final = "build_tool"

LOCK_ROLES: Final = (
    ROLE_KERNEL,
    ROLE_KERNEL_TRUSTED_CERT_BUNDLE,
    ROLE_FINAL_SYSTEMD_STUB,
    ROLE_FINAL_SYSTEMD_UNIT,
    ROLE_NVIDIA_CC_DRIVER,
    ROLE_NVIDIA_CC_FIRMWARE,
    ROLE_CONF_PROC_SOURCE,
    ROLE_SGLANG_IMAGE,
    ROLE_INFERENCE_MODEL,
    ROLE_ASR_MODEL,
    ROLE_GATEWAY_DEPENDENCY_LOCK,
    ROLE_ASR_DEPENDENCY_LOCK,
    ROLE_RUNTIME_TREE_INPUT,
    ROLE_POLICY_TREE_INPUT,
    ROLE_MODELS_TREE_INPUT,
    ROLE_BUILD_TOOL,
)

_SINGLE_CARDINALITY_ROLES: Final = (
    ROLE_KERNEL,
    ROLE_KERNEL_TRUSTED_CERT_BUNDLE,
    ROLE_FINAL_SYSTEMD_STUB,
    ROLE_FINAL_SYSTEMD_UNIT,
    ROLE_NVIDIA_CC_DRIVER,
    ROLE_NVIDIA_CC_FIRMWARE,
    ROLE_SGLANG_IMAGE,
    ROLE_INFERENCE_MODEL,
    ROLE_ASR_MODEL,
    ROLE_GATEWAY_DEPENDENCY_LOCK,
    ROLE_ASR_DEPENDENCY_LOCK,
)
_TREE_INPUT_ROLES: Final = (ROLE_RUNTIME_TREE_INPUT, ROLE_MODELS_TREE_INPUT, ROLE_POLICY_TREE_INPUT)
_REQUIRED_BUILD_TOOL_COMPONENTS: Final = ("mksquashfs", "unsquashfs", "veritysetup", "openssl")
_ALLOWED_XATTRS: Final = ("system.posix_acl_access", "system.posix_acl_default")
_IMAGES: Final = ("runtime-policy", "models")
_BASE_IMAGE_KINDS: Final = ("vhd", "vmi")
_RETRIEVAL_SCHEMES: Final = ("https", "oci", "git", "local-fixture", "other")
_SOURCE_RETRIEVAL_SCHEMES: Final = ("https", "oci", "git", "local-fixture", "generated", "other")
_DERIVATION_KINDS: Final = ("fetched", "built", "extracted", "fixture")
_NODE_TYPES: Final = ("file", "directory", "symlink")
_RUNTIME_SUBSTITUTION_MARKERS: Final = ("${", "{{", "%(")

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
_INPUT_KEYS: Final = frozenset(
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
_PLACEMENT_KEYS: Final = frozenset(
    {"image", "path", "node_type", "mode", "uid", "gid", "xattrs", "source_input_id", "target"}
)
_SIGNER_KEYS: Final = frozenset({"certificate_sha256", "spki_sha256", "subject_sha256", "usage"})


@dataclass(frozen=True)
class BaseImageRecord:
    kind: str
    provider: str
    identity_namespace: str
    identity_name: str
    identity_immutable_revision: str
    content_sha256: str
    content_size_bytes: int
    content_media_type: str
    availability: str
    recorded_retrieval_scheme: str
    recorded_retrieval_identity: str
    recorded_retrieval_immutable_ref: str


@dataclass(frozen=True)
class Placement:
    image: str
    path: str
    node_type: str
    mode: int
    uid: int
    gid: int
    xattrs: tuple[str, ...]
    source_input_id: str | None
    target: str | None


@dataclass(frozen=True)
class LockInput:
    id: str
    role: str
    component: str
    sha256: str
    size_bytes: int
    source_local_path: str
    source_retrieval_scheme: str
    source_retrieval_identity: str
    source_retrieval_immutable_ref: str
    derivation_kind: str
    derivation_recipe_id: str
    derivation_parent_ids: tuple[str, ...]
    derivation_parameters_sha256: str
    placements: tuple[Placement, ...]


@dataclass(frozen=True)
class AuthorizedModuleSigner:
    certificate_sha256: str
    spki_sha256: str
    subject_sha256: str
    usage: str


@dataclass(frozen=True)
class Lock:
    schema: str
    lock_version: int
    base_image_record: BaseImageRecord
    future_cmdline: str
    inputs: tuple[LockInput, ...]
    authorized_module_signers: tuple[AuthorizedModuleSigner, ...]
    image_specs: dict
    policy_input_id: str
    tool_ids: tuple[str, ...]


def parse_lock(data: bytes) -> Lock:
    """Parse and structurally validate a conf-proc-lock/v1 document."""

    raw = canonical_loads(data)
    _require(type(raw) is dict, CP_LOCK_SCHEMA, "lock document must be a JSON object")
    _require(set(raw) == _LOCK_TOP_KEYS, CP_LOCK_SCHEMA, "lock document has unexpected top-level fields")
    _require(raw["schema"] == LOCK_SCHEMA_ID, CP_LOCK_SCHEMA, "unexpected lock schema identifier")
    _require(raw["lock_version"] == LOCK_VERSION, CP_LOCK_SCHEMA, "unexpected lock version")

    base_image_record = _parse_base_image_record(raw["base_image_record"])

    future_cmdline = raw["future_cmdline"]
    _require(type(future_cmdline) is str and future_cmdline, CP_LOCK_SCHEMA, "future_cmdline must be nonempty")
    _require(
        not any(marker in future_cmdline for marker in _RUNTIME_SUBSTITUTION_MARKERS),
        CP_LOCK_SCHEMA,
        "future_cmdline must not contain a runtime substitution marker",
    )

    raw_inputs = raw["inputs"]
    _require(type(raw_inputs) is list and raw_inputs, CP_LOCK_SCHEMA, "inputs must be a nonempty array")
    inputs = [_parse_input(entry) for entry in raw_inputs]
    ids = [entry.id for entry in inputs]
    if len(ids) != len(set(ids)):
        raise ApplianceError(CP_LOCK_DUPLICATE_ID, "duplicate lock input id")
    if ids != sorted(ids):
        raise ApplianceError(CP_LOCK_SCHEMA, "inputs must be sorted by id")
    known_ids = set(ids)
    inputs_by_id = {entry.id: entry for entry in inputs}
    for entry in inputs:
        for parent_id in entry.derivation_parent_ids:
            if parent_id not in known_ids:
                raise ApplianceError(
                    CP_LOCK_INPUT_MISSING, f"input {entry.id!r} references unknown parent id {parent_id!r}"
                )

    raw_signers = raw["authorized_module_signers"]
    _require(type(raw_signers) is list, CP_LOCK_SCHEMA, "authorized_module_signers must be an array")
    signers = [_parse_signer(entry) for entry in raw_signers]
    signer_hashes = [entry.certificate_sha256 for entry in signers]
    if len(signer_hashes) != len(set(signer_hashes)):
        raise ApplianceError(CP_LOCK_SCHEMA, "duplicate authorized module signer certificate")
    if signer_hashes != sorted(signer_hashes):
        raise ApplianceError(CP_LOCK_SCHEMA, "authorized_module_signers must be sorted by certificate_sha256")

    image_specs = raw["image_specs"]
    _require(type(image_specs) is dict and set(image_specs) == set(_IMAGES), CP_LOCK_SCHEMA, "image_specs must cover exactly runtime-policy and models")

    policy_input_id = raw["policy_input_id"]
    _require(type(policy_input_id) is str, CP_LOCK_SCHEMA, "policy_input_id must be a string")
    if policy_input_id not in known_ids:
        raise ApplianceError(CP_LOCK_INPUT_MISSING, "policy_input_id references an unknown input")
    if inputs_by_id[policy_input_id].role != ROLE_POLICY_TREE_INPUT:
        raise ApplianceError(CP_LOCK_ROLE, "policy_input_id must reference a policy_tree_input")

    raw_tool_ids = raw["tool_ids"]
    _require(type(raw_tool_ids) is list, CP_LOCK_SCHEMA, "tool_ids must be an array")
    _require(all(type(item) is str for item in raw_tool_ids), CP_LOCK_SCHEMA, "tool_ids must be strings")
    if list(raw_tool_ids) != sorted(raw_tool_ids) or len(raw_tool_ids) != len(set(raw_tool_ids)):
        raise ApplianceError(CP_LOCK_SCHEMA, "tool_ids must be sorted and unique")
    for tool_id in raw_tool_ids:
        if tool_id not in known_ids:
            raise ApplianceError(CP_LOCK_INPUT_MISSING, "tool_ids references an unknown input")
        if inputs_by_id[tool_id].role != ROLE_BUILD_TOOL:
            raise ApplianceError(CP_LOCK_ROLE, "tool_ids must reference build_tool inputs")

    _check_cardinality(inputs)

    return Lock(
        schema=raw["schema"],
        lock_version=raw["lock_version"],
        base_image_record=base_image_record,
        future_cmdline=future_cmdline,
        inputs=tuple(inputs),
        authorized_module_signers=tuple(signers),
        image_specs=image_specs,
        policy_input_id=policy_input_id,
        tool_ids=tuple(raw_tool_ids),
    )


def _check_cardinality(inputs: list[LockInput]) -> None:
    role_counts: dict[str, int] = {}
    for entry in inputs:
        role_counts[entry.role] = role_counts.get(entry.role, 0) + 1

    for role in _SINGLE_CARDINALITY_ROLES:
        if role_counts.get(role, 0) != 1:
            raise ApplianceError(CP_LOCK_PROVENANCE, f"lock must contain exactly one {role} input")

    if role_counts.get(ROLE_CONF_PROC_SOURCE, 0) < 1:
        raise ApplianceError(CP_LOCK_PROVENANCE, "lock must contain at least one conf_proc_source input")

    if sum(role_counts.get(role, 0) for role in _TREE_INPUT_ROLES) < 1:
        raise ApplianceError(CP_LOCK_PROVENANCE, "lock must contain at least one tree-input role")

    tool_components = {entry.component for entry in inputs if entry.role == ROLE_BUILD_TOOL}
    missing = [name for name in _REQUIRED_BUILD_TOOL_COMPONENTS if name not in tool_components]
    if missing:
        raise ApplianceError(CP_LOCK_PROVENANCE, f"lock is missing required build tools: {missing}")


def _parse_base_image_record(raw: object) -> BaseImageRecord:
    _require(type(raw) is dict, CP_LOCK_BASE_IMAGE_RECORD, "base_image_record must be a JSON object")
    _require(set(raw) == _BASE_IMAGE_KEYS, CP_LOCK_BASE_IMAGE_RECORD, "base_image_record has unexpected fields")
    _require(raw["kind"] in _BASE_IMAGE_KINDS, CP_LOCK_BASE_IMAGE_RECORD, "base_image_record.kind must be vhd or vmi")
    for key in (
        "provider",
        "identity_namespace",
        "identity_name",
        "identity_immutable_revision",
        "content_media_type",
        "recorded_retrieval_identity",
        "recorded_retrieval_immutable_ref",
    ):
        _require(type(raw[key]) is str and raw[key], CP_LOCK_BASE_IMAGE_RECORD, f"base_image_record.{key} must be nonempty")
    _require(_is_sha256(raw["content_sha256"]), CP_LOCK_BASE_IMAGE_RECORD, "base_image_record.content_sha256 must be 64 lowercase hex characters")
    _require(
        type(raw["content_size_bytes"]) is int and raw["content_size_bytes"] >= 0,
        CP_LOCK_BASE_IMAGE_RECORD,
        "base_image_record.content_size_bytes must be a nonnegative integer",
    )
    _require(raw["availability"] == "record-only", CP_LOCK_BASE_IMAGE_RECORD, "base_image_record.availability must be record-only")
    _require(
        raw["recorded_retrieval_scheme"] in _RETRIEVAL_SCHEMES,
        CP_LOCK_BASE_IMAGE_RECORD,
        "base_image_record.recorded_retrieval_scheme is not a recognized scheme",
    )
    return BaseImageRecord(**raw)


def _parse_input(raw: object) -> LockInput:
    _require(type(raw) is dict, CP_LOCK_SCHEMA, "lock input must be a JSON object")
    _require(set(raw) == _INPUT_KEYS, CP_LOCK_SCHEMA, "lock input has unexpected fields")

    input_id = raw["id"]
    _require(
        type(input_id) is str and input_id and input_id.isascii() and not any(ch.isspace() for ch in input_id),
        CP_LOCK_SCHEMA,
        "lock input id must be a nonempty ASCII string with no whitespace",
    )

    role = raw["role"]
    if role not in LOCK_ROLES:
        raise ApplianceError(CP_LOCK_ROLE, f"unknown lock input role: {role!r}")

    _require(type(raw["component"]) is str and raw["component"], CP_LOCK_SCHEMA, "component must be nonempty")
    _require(_is_sha256(raw["sha256"]), CP_LOCK_SCHEMA, "sha256 must be 64 lowercase hex characters")
    _require(type(raw["size_bytes"]) is int and raw["size_bytes"] >= 0, CP_LOCK_SCHEMA, "size_bytes must be a nonnegative integer")

    source_local_path = raw["source_local_path"]
    _require(type(source_local_path) is str, CP_LOCK_SCHEMA, "source_local_path must be a string")
    _validate_relative_path(source_local_path)

    _require(
        raw["source_retrieval_scheme"] in _SOURCE_RETRIEVAL_SCHEMES,
        CP_LOCK_SCHEMA,
        "source_retrieval_scheme is not a recognized scheme",
    )
    for key in ("source_retrieval_identity", "source_retrieval_immutable_ref", "derivation_recipe_id"):
        _require(type(raw[key]) is str and raw[key], CP_LOCK_SCHEMA, f"{key} must be nonempty")

    derivation_kind = raw["derivation_kind"]
    _require(derivation_kind in _DERIVATION_KINDS, CP_LOCK_SCHEMA, "derivation_kind is not recognized")

    raw_parent_ids = raw["derivation_parent_ids"]
    _require(type(raw_parent_ids) is list and all(type(item) is str for item in raw_parent_ids), CP_LOCK_SCHEMA, "derivation_parent_ids must be an array of strings")
    if list(raw_parent_ids) != sorted(raw_parent_ids) or len(raw_parent_ids) != len(set(raw_parent_ids)):
        raise ApplianceError(CP_LOCK_SCHEMA, "derivation_parent_ids must be sorted and unique")
    if not raw_parent_ids and not (derivation_kind == "fixture" or role == ROLE_BUILD_TOOL):
        raise ApplianceError(CP_LOCK_PROVENANCE, "derivation_parent_ids may only be empty for a fixture or build_tool input")

    _require(_is_sha256(raw["derivation_parameters_sha256"]), CP_LOCK_SCHEMA, "derivation_parameters_sha256 must be 64 lowercase hex characters")

    raw_placements = raw["placements"]
    _require(type(raw_placements) is list, CP_LOCK_SCHEMA, "placements must be an array")
    placements = [_parse_placement(entry, input_id) for entry in raw_placements]
    keys = [(entry.image, entry.path) for entry in placements]
    if keys != sorted(keys):
        raise ApplianceError(CP_LOCK_SCHEMA, "placements must be sorted by (image, path)")
    if len(keys) != len(set(keys)):
        raise ApplianceError(CP_LOCK_SCHEMA, "placements must not repeat (image, path)")
    if not placements and role not in (ROLE_BUILD_TOOL, ROLE_KERNEL_TRUSTED_CERT_BUNDLE):
        raise ApplianceError(CP_LOCK_PROVENANCE, "placements may only be empty for build_tool or kernel_trusted_cert_bundle inputs")

    return LockInput(
        id=input_id,
        role=role,
        component=raw["component"],
        sha256=raw["sha256"],
        size_bytes=raw["size_bytes"],
        source_local_path=source_local_path,
        source_retrieval_scheme=raw["source_retrieval_scheme"],
        source_retrieval_identity=raw["source_retrieval_identity"],
        source_retrieval_immutable_ref=raw["source_retrieval_immutable_ref"],
        derivation_kind=derivation_kind,
        derivation_recipe_id=raw["derivation_recipe_id"],
        derivation_parent_ids=tuple(raw_parent_ids),
        derivation_parameters_sha256=raw["derivation_parameters_sha256"],
        placements=tuple(placements),
    )


def _parse_placement(raw: object, owning_input_id: str) -> Placement:
    _require(type(raw) is dict, CP_LOCK_SCHEMA, "placement must be a JSON object")
    _require(set(raw) == _PLACEMENT_KEYS, CP_LOCK_SCHEMA, "placement has unexpected fields")
    _require(raw["image"] in _IMAGES, CP_LOCK_SCHEMA, "placement.image must be runtime-policy or models")

    path = raw["path"]
    _require(type(path) is str, CP_LOCK_SCHEMA, "placement.path must be a string")
    _validate_absolute_path(path)

    node_type = raw["node_type"]
    _require(node_type in _NODE_TYPES, CP_LOCK_SCHEMA, "placement.node_type is not recognized")
    _require(type(raw["mode"]) is int and 0 <= raw["mode"] <= 0o7777, CP_LOCK_SCHEMA, "placement.mode must be 0-0o7777")
    _require(type(raw["uid"]) is int and raw["uid"] >= 0, CP_LOCK_SCHEMA, "placement.uid must be nonnegative")
    _require(type(raw["gid"]) is int and raw["gid"] >= 0, CP_LOCK_SCHEMA, "placement.gid must be nonnegative")

    xattrs = raw["xattrs"]
    _require(type(xattrs) is list and all(item in _ALLOWED_XATTRS for item in xattrs), CP_LOCK_SCHEMA, "placement.xattrs contains an unsupported xattr name")

    source_input_id = raw["source_input_id"]
    target = raw["target"]
    if node_type == "file":
        _require(source_input_id == owning_input_id, CP_LOCK_SCHEMA, "file placement source_input_id must equal its owning input id")
        _require(target is None, CP_LOCK_SCHEMA, "file placement must not declare a symlink target")
    elif node_type == "symlink":
        _require(source_input_id is None, CP_LOCK_SCHEMA, "symlink placement must not declare source_input_id")
        _require(type(target) is str and target, CP_LOCK_SCHEMA, "symlink placement requires a nonempty target")
    else:
        _require(source_input_id is None and target is None, CP_LOCK_SCHEMA, "directory placement must not declare source_input_id or target")

    return Placement(
        image=raw["image"],
        path=path,
        node_type=node_type,
        mode=raw["mode"],
        uid=raw["uid"],
        gid=raw["gid"],
        xattrs=tuple(xattrs),
        source_input_id=source_input_id,
        target=target,
    )


def _parse_signer(raw: object) -> AuthorizedModuleSigner:
    _require(type(raw) is dict, CP_LOCK_SCHEMA, "authorized module signer must be a JSON object")
    _require(set(raw) == _SIGNER_KEYS, CP_LOCK_SCHEMA, "authorized module signer has unexpected fields")
    for key in ("certificate_sha256", "spki_sha256", "subject_sha256"):
        _require(_is_sha256(raw[key]), CP_LOCK_SCHEMA, f"{key} must be 64 lowercase hex characters")
    _require(raw["usage"] == "kernel-module-signing", CP_LOCK_SCHEMA, "authorized module signer usage must be kernel-module-signing")
    return AuthorizedModuleSigner(**raw)


def _validate_relative_path(path: str) -> None:
    if not path or path.startswith("/"):
        raise ApplianceError(CP_LOCK_INPUT_PATH_ESCAPE, "source_local_path must be a nonempty relative path")
    segments = path.split("/")
    if any(segment in ("", "..") for segment in segments):
        raise ApplianceError(CP_LOCK_INPUT_PATH_ESCAPE, "source_local_path must not contain empty or .. segments")


def _validate_absolute_path(path: str) -> None:
    if not path.startswith("/"):
        raise ApplianceError(CP_LOCK_INPUT_PATH_ESCAPE, "placement path must be absolute")
    if path != "/" and path.endswith("/"):
        raise ApplianceError(CP_LOCK_INPUT_PATH_ESCAPE, "placement path must not end with a trailing slash")
    segments = path.split("/")[1:]
    if path != "/" and any(segment in ("", "..") for segment in segments):
        raise ApplianceError(CP_LOCK_INPUT_PATH_ESCAPE, "placement path must not contain empty or .. segments")


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and value == value.lower() and all(c in "0123456789abcdef" for c in value)


def _require(condition: bool, reason_code: str, message: str) -> None:
    if not condition:
        raise ApplianceError(reason_code, message)
