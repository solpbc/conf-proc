#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Structural schema for the conf-proc-appliance-manifest/v1 document.

The schema is a strict field whitelist: fields for final UKI bytes,
runtime secrets, IP/DNS values, expiring certificates, machine identity,
SSH material, or owner identifiers simply have no place to go, and any
unexpected top-level or nested field is rejected outright. A defensive
content scan also rejects IPv4/IPv6-shaped strings and PEM markers
anywhere in the document, in case one is smuggled into an otherwise
schema-shaped field.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from conf_proc_json import canonical_loads
from conf_proc_reasons import CP_MANIFEST_FORBIDDEN_FIELD, CP_MANIFEST_SCHEMA, ApplianceError


MANIFEST_SCHEMA_ID: Final = "conf-proc-appliance-manifest/v1"
MANIFEST_VERSION: Final = 1

_IMAGES: Final = ("runtime-policy", "models")
_BINDING_CATEGORIES: Final = ("executables", "configs", "models", "runtime_inputs")

_TOP_KEYS: Final = frozenset(
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
_INVENTORY_RECORD_KEYS: Final = frozenset(
    {"path", "node_type", "mode", "uid", "gid", "xattrs", "sha256", "size_bytes", "symlink_target", "source_input_id"}
)
_POLICY_BINDING_KEYS: Final = frozenset({"policy_input_id", "policy_schema", "process_policy_sha256"})
_MODULE_AUTHORITY_KEYS: Final = frozenset(
    {"trusted_bundle_input_id", "authorized_signer_certificate_sha256", "module_inventory", "firmware_inventory"}
)
_MODULE_INVENTORY_ENTRY_KEYS: Final = frozenset({"path", "sha256", "signer_certificate_sha256"})
_FIRMWARE_INVENTORY_ENTRY_KEYS: Final = frozenset({"path", "sha256"})
_TOOLCHAIN_ENTRY_KEYS: Final = frozenset({"tool_id", "component", "resolved_path_sha256"})
_SBOM_KEYS: Final = frozenset({"filename", "sha256", "spdx_version", "document_spdx_id"})
_REPRODUCIBILITY_KEYS: Final = frozenset({"build_epoch", "sort_order", "codec"})

_IPV4_PATTERN: Final = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_PEM_MARKERS: Final = ("-----BEGIN ", "ssh-rsa ", "ssh-ed25519 ")


@dataclass(frozen=True)
class Manifest:
    raw: dict


def parse_manifest(data: bytes) -> Manifest:
    """Structurally validate a manifest document; never trust its content
    as ground truth -- callers must independently re-derive every field
    and compare (see conf_proc_inspect_manifest.py)."""

    raw = canonical_loads(data)
    _require(type(raw) is dict, CP_MANIFEST_SCHEMA, "manifest must be a JSON object")
    _require(set(raw) == _TOP_KEYS, CP_MANIFEST_SCHEMA, "manifest has unexpected top-level fields")
    _require(raw["schema"] == MANIFEST_SCHEMA_ID, CP_MANIFEST_SCHEMA, "unexpected manifest schema identifier")
    _require(raw["manifest_version"] == MANIFEST_VERSION, CP_MANIFEST_SCHEMA, "unexpected manifest version")
    _require(type(raw["lock_schema"]) is str and raw["lock_schema"], CP_MANIFEST_SCHEMA, "lock_schema must be nonempty")
    _require(_is_sha256(raw["lock_sha256"]), CP_MANIFEST_SCHEMA, "lock_sha256 must be 64 lowercase hex characters")

    reproducibility = raw["reproducibility"]
    _require(type(reproducibility) is dict and set(reproducibility) == _REPRODUCIBILITY_KEYS, CP_MANIFEST_SCHEMA, "reproducibility has unexpected fields")
    _require(type(reproducibility["build_epoch"]) is int, CP_MANIFEST_SCHEMA, "reproducibility.build_epoch must be an integer")

    _require(type(raw["future_cmdline"]) is str and raw["future_cmdline"], CP_MANIFEST_SCHEMA, "future_cmdline must be nonempty")

    images = raw["images"]
    _require(type(images) is dict and set(images) == set(_IMAGES), CP_MANIFEST_SCHEMA, "images must cover exactly runtime-policy and models")
    for image_id, entry in images.items():
        _require(type(entry) is dict and set(entry) == _IMAGE_KEYS, CP_MANIFEST_SCHEMA, f"images.{image_id} has unexpected fields")
        _require(_is_sha256(entry["squashfs_sha256"]), CP_MANIFEST_SCHEMA, f"images.{image_id}.squashfs_sha256 must be 64 lowercase hex characters")
        _require(_is_sha256(entry["hash_device_sha256"]), CP_MANIFEST_SCHEMA, f"images.{image_id}.hash_device_sha256 must be 64 lowercase hex characters")
        _require(_is_hex(entry["root_hash"]), CP_MANIFEST_SCHEMA, f"images.{image_id}.root_hash must be lowercase hex")

    raw_inputs = raw["inputs"]
    _require(type(raw_inputs) is list, CP_MANIFEST_SCHEMA, "inputs must be an array")

    raw_inventory = raw["inventory"]
    _require(type(raw_inventory) is dict and set(raw_inventory) == set(_IMAGES), CP_MANIFEST_SCHEMA, "inventory must cover exactly runtime-policy and models")
    for image_id, records in raw_inventory.items():
        _require(type(records) is list, CP_MANIFEST_SCHEMA, f"inventory.{image_id} must be an array")
        for record in records:
            _require(type(record) is dict and set(record) == _INVENTORY_RECORD_KEYS, CP_MANIFEST_SCHEMA, f"inventory.{image_id} record has unexpected fields")

    raw_bindings = raw["bindings"]
    _require(type(raw_bindings) is dict and set(raw_bindings) == set(_IMAGES), CP_MANIFEST_SCHEMA, "bindings must cover exactly runtime-policy and models")
    for image_id, categories in raw_bindings.items():
        _require(type(categories) is dict and set(categories) == set(_BINDING_CATEGORIES), CP_MANIFEST_SCHEMA, f"bindings.{image_id} has unexpected categories")

    policy = raw["policy"]
    _require(type(policy) is dict and set(policy) == _POLICY_BINDING_KEYS, CP_MANIFEST_SCHEMA, "policy has unexpected fields")
    _require(_is_sha256(policy["process_policy_sha256"]), CP_MANIFEST_SCHEMA, "policy.process_policy_sha256 must be 64 lowercase hex characters")

    module_authority = raw["module_authority"]
    _require(type(module_authority) is dict and set(module_authority) == _MODULE_AUTHORITY_KEYS, CP_MANIFEST_SCHEMA, "module_authority has unexpected fields")

    toolchain = raw["toolchain"]
    _require(type(toolchain) is list, CP_MANIFEST_SCHEMA, "toolchain must be an array")
    for entry in toolchain:
        _require(type(entry) is dict and set(entry) == _TOOLCHAIN_ENTRY_KEYS, CP_MANIFEST_SCHEMA, "toolchain entry has unexpected fields")

    sbom = raw["sbom"]
    _require(type(sbom) is dict and set(sbom) == _SBOM_KEYS, CP_MANIFEST_SCHEMA, "sbom has unexpected fields")
    _require(_is_sha256(sbom["sha256"]), CP_MANIFEST_SCHEMA, "sbom.sha256 must be 64 lowercase hex characters")

    _scan_for_forbidden_content(raw)

    return Manifest(raw=raw)


def _scan_for_forbidden_content(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _scan_for_forbidden_content(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_for_forbidden_content(item, f"{path}[{index}]")
    elif isinstance(value, str):
        if _IPV4_PATTERN.search(value):
            raise ApplianceError(CP_MANIFEST_FORBIDDEN_FIELD, f"{path}: value looks like an IPv4 address: {value!r}")
        if ":" in value and value.count(":") >= 4 and all(c in "0123456789abcdefABCDEF:" for c in value):
            raise ApplianceError(CP_MANIFEST_FORBIDDEN_FIELD, f"{path}: value looks like an IPv6 address: {value!r}")
        if any(marker in value for marker in _PEM_MARKERS):
            raise ApplianceError(CP_MANIFEST_FORBIDDEN_FIELD, f"{path}: value contains embedded key/certificate material")


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and value == value.lower() and all(c in "0123456789abcdef" for c in value)


def _is_hex(value: object) -> bool:
    return type(value) is str and len(value) > 0 and value == value.lower() and all(c in "0123456789abcdef" for c in value)


def _require(condition: bool, reason_code: str, message: str) -> None:
    if not condition:
        raise ApplianceError(reason_code, message)
