#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Strict schema for dormant provenance-v2 appliance manifests."""

from __future__ import annotations

from dataclasses import dataclass
import posixpath
from typing import Final
import uuid

from conf_proc_json import canonical_loads
from conf_proc_reasons import (
    CP_PROVENANCE_V2_MANIFEST_FORBIDDEN_FIELD,
    CP_PROVENANCE_V2_MANIFEST_PRODUCTION,
    ApplianceError,
)


MANIFEST_V2_SCHEMA_ID: Final = "conf-proc-appliance-manifest/v2"
MANIFEST_V2_VERSION: Final = 2
IMAGE_IDS: Final = frozenset({"models", "runtime-policy"})
BINDING_CATEGORIES: Final = frozenset({"executables", "configs", "models", "runtime_inputs"})
PROVENANCE_BINDING_SCHEMA: Final = "conf-proc-execution-provenance-binding/v1"
DECLARED_UNVERIFIED: Final = "declared_unverified"

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
_REPRODUCIBILITY_KEYS: Final = frozenset({"build_epoch", "sort_order", "codec"})
_POLICY_KEYS: Final = frozenset({"policy_input_id", "policy_schema", "process_policy_sha256"})
_MODULE_AUTHORITY_KEYS: Final = frozenset(
    {"trusted_bundle_input_id", "authorized_signer_certificate_sha256", "module_inventory", "firmware_inventory"}
)
_MODULE_INVENTORY_KEYS: Final = frozenset({"path", "sha256", "signer_certificate_sha256"})
_FIRMWARE_INVENTORY_KEYS: Final = frozenset({"path", "sha256"})
_TOOLCHAIN_KEYS: Final = frozenset({"tool_id", "component", "resolved_path_sha256"})
_SBOM_KEYS: Final = frozenset({"filename", "sha256", "spdx_version", "document_spdx_id"})
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
_SHA_KEYS: Final = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class ProvenanceV2Manifest:
    raw: dict


def parse_manifest_v2(data: bytes) -> ProvenanceV2Manifest:
    """Parse the exact dormant provenance-v2 manifest shape."""

    raw = canonical_loads(data)
    _require(type(raw) is dict, "manifest must be an object")
    _require_keys(raw, _TOP_KEYS, "manifest")
    _require(
        raw["schema"] == MANIFEST_V2_SCHEMA_ID and raw["manifest_version"] == MANIFEST_V2_VERSION,
        "manifest schema or version is invalid",
    )
    _require(type(raw["lock_schema"]) is str and raw["lock_schema"], "manifest lock schema is invalid")
    _require(_is_sha256(raw["lock_sha256"]), "manifest lock digest is invalid")
    _validate_reproducibility(raw["reproducibility"])
    _validate_base_image_record(raw["base_image_record"])
    _require(type(raw["future_cmdline"]) is str and raw["future_cmdline"], "manifest command line is invalid")
    _validate_images(raw["images"])
    _validate_inputs(raw["inputs"])
    _validate_inventory(raw["inventory"])
    _validate_bindings(raw["bindings"])
    _validate_policy(raw["policy"])
    _validate_module_authority(raw["module_authority"])
    _validate_toolchain(raw["toolchain"])
    _validate_sbom(raw["sbom"])
    _validate_provenance(raw["provenance"])
    return ProvenanceV2Manifest(raw=raw)


def _validate_reproducibility(value: object) -> None:
    _require(type(value) is dict, "manifest reproducibility is invalid")
    _require_keys(value, _REPRODUCIBILITY_KEYS, "manifest reproducibility")
    _require(
        _nonnegative_int(value["build_epoch"])
        and value["sort_order"] == "byte-wise-path"
        and value["codec"] == "conf-proc-canonical-json/v1",
        "manifest reproducibility values are invalid",
    )


def _validate_base_image_record(value: object) -> None:
    _require(type(value) is dict, "manifest base image record is invalid")
    _require_keys(value, _BASE_IMAGE_KEYS, "manifest base image record")
    _require(
        value["kind"] in ("vhd", "vmi")
        and _is_sha256(value["content_sha256"])
        and _nonnegative_int(value["content_size_bytes"])
        and value["availability"] == "record-only"
        and all(type(value[key]) is str and value[key] for key in _BASE_IMAGE_KEYS - {"content_size_bytes"}),
        "manifest base image values are invalid",
    )


def _validate_images(value: object) -> None:
    _require(type(value) is dict and set(value) == IMAGE_IDS, "manifest images are incomplete")
    for image in value.values():
        _require(type(image) is dict, "manifest image is invalid")
        _require_keys(image, _IMAGE_KEYS, "manifest image")
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
            "manifest image values are invalid",
        )


def _validate_inputs(value: object) -> None:
    _require(type(value) is list, "manifest inputs must be an array")
    input_ids: list[str] = []
    for item in value:
        _require(type(item) is dict, "manifest input is invalid")
        _require_keys(item, _MANIFEST_INPUT_KEYS, "manifest input")
        _require(
            all(
                type(item[key]) is str and item[key]
                for key in (
                    "id",
                    "role",
                    "source_retrieval_scheme",
                    "source_retrieval_identity",
                    "source_retrieval_immutable_ref",
                    "derivation_kind",
                    "derivation_recipe_id",
                )
            )
            and _is_sha256(item["sha256"])
            and _is_sha256(item["derivation_parameters_sha256"])
            and _nonnegative_int(item["size_bytes"])
            and type(item["derivation_parent_ids"]) is list
            and all(type(parent) is str and parent for parent in item["derivation_parent_ids"])
            and item["derivation_parent_ids"] == sorted(item["derivation_parent_ids"])
            and len(item["derivation_parent_ids"]) == len(set(item["derivation_parent_ids"])),
            "manifest input values are invalid",
        )
        _validate_placements(item["placements"])
        input_ids.append(item["id"])
    _require(
        input_ids == sorted(input_ids) and len(input_ids) == len(set(input_ids)),
        "manifest input IDs must be sorted and unique",
    )


def _validate_placements(value: object) -> None:
    _require(type(value) is list, "manifest placements must be an array")
    keys: list[tuple[str, str]] = []
    for placement in value:
        _require(type(placement) is dict, "manifest placement is invalid")
        _require_keys(placement, _PLACEMENT_KEYS, "manifest placement")
        _require(
            placement["image"] in IMAGE_IDS
            and _absolute_normal_path(placement["path"])
            and placement["node_type"] in ("file", "directory", "symlink")
            and all(_nonnegative_int(placement[key]) for key in ("mode", "uid", "gid"))
            and type(placement["xattrs"]) is list,
            "manifest placement values are invalid",
        )
        keys.append((placement["image"], placement["path"]))
    _require(keys == sorted(keys) and len(keys) == len(set(keys)), "manifest placements must be sorted and unique")


def _validate_inventory(value: object) -> None:
    _require(type(value) is dict and set(value) == IMAGE_IDS, "manifest inventory is incomplete")
    for records in value.values():
        _require(type(records) is list, "manifest inventory must be an array")
        paths: list[str] = []
        for item in records:
            _require(type(item) is dict, "manifest inventory record is invalid")
            _require_keys(item, _INVENTORY_KEYS, "manifest inventory record")
            _require(
                _absolute_normal_path(item["path"])
                and item["node_type"] in ("file", "directory", "symlink")
                and all(_nonnegative_int(item[key]) for key in ("mode", "uid", "gid"))
                and type(item["xattrs"]) is list,
                "manifest inventory values are invalid",
            )
            paths.append(item["path"])
        _require(paths == sorted(paths) and len(paths) == len(set(paths)), "manifest inventory paths must be sorted and unique")


def _validate_bindings(value: object) -> None:
    _require(type(value) is dict and set(value) == IMAGE_IDS, "manifest bindings are incomplete")
    for categories in value.values():
        _require(type(categories) is dict, "manifest binding is invalid")
        _require_keys(categories, BINDING_CATEGORIES, "manifest binding")
        for paths in categories.values():
            _require(
                type(paths) is list
                and all(_absolute_normal_path(path) for path in paths)
                and paths == sorted(paths)
                and len(paths) == len(set(paths)),
                "manifest binding paths are invalid",
            )


def _validate_policy(value: object) -> None:
    _require(type(value) is dict, "manifest policy is invalid")
    _require_keys(value, _POLICY_KEYS, "manifest policy")
    _require(
        type(value["policy_input_id"]) is str
        and value["policy_input_id"]
        and type(value["policy_schema"]) is str
        and value["policy_schema"]
        and _is_sha256(value["process_policy_sha256"]),
        "manifest policy values are invalid",
    )


def _validate_module_authority(value: object) -> None:
    _require(type(value) is dict, "manifest module authority is invalid")
    _require_keys(value, _MODULE_AUTHORITY_KEYS, "manifest module authority")
    _require(
        type(value["trusted_bundle_input_id"]) is str and value["trusted_bundle_input_id"],
        "manifest trusted bundle identity is invalid",
    )
    signers = value["authorized_signer_certificate_sha256"]
    _require(
        type(signers) is list
        and all(_is_sha256(item) for item in signers)
        and signers == sorted(signers)
        and len(signers) == len(set(signers)),
        "manifest authorized signers are invalid",
    )
    _validate_module_inventory(value["module_inventory"], _MODULE_INVENTORY_KEYS)
    _validate_module_inventory(value["firmware_inventory"], _FIRMWARE_INVENTORY_KEYS)


def _validate_module_inventory(value: object, expected_keys: frozenset[str]) -> None:
    _require(type(value) is list, "manifest module inventory must be an array")
    paths: list[str] = []
    for item in value:
        _require(type(item) is dict, "manifest module inventory record is invalid")
        _require_keys(item, expected_keys, "manifest module inventory record")
        _require(
            _absolute_normal_path(item["path"]) and _is_sha256(item["sha256"]),
            "manifest module inventory values are invalid",
        )
        if "signer_certificate_sha256" in item:
            _require(_is_sha256(item["signer_certificate_sha256"]), "manifest module signer digest is invalid")
        paths.append(item["path"])
    _require(paths == sorted(paths) and len(paths) == len(set(paths)), "manifest module inventory paths must be sorted and unique")


def _validate_toolchain(value: object) -> None:
    _require(type(value) is list, "manifest toolchain must be an array")
    tool_ids: list[str] = []
    for item in value:
        _require(type(item) is dict, "manifest toolchain entry is invalid")
        _require_keys(item, _TOOLCHAIN_KEYS, "manifest toolchain entry")
        _require(
            type(item["tool_id"]) is str
            and item["tool_id"]
            and type(item["component"]) is str
            and item["component"]
            and _is_sha256(item["resolved_path_sha256"]),
            "manifest toolchain values are invalid",
        )
        tool_ids.append(item["tool_id"])
    _require(tool_ids == sorted(tool_ids) and len(tool_ids) == len(set(tool_ids)), "manifest toolchain IDs must be sorted and unique")


def _validate_sbom(value: object) -> None:
    _require(type(value) is dict, "manifest SBOM reference is invalid")
    _require_keys(value, _SBOM_KEYS, "manifest SBOM reference")
    _require(
        value["filename"] == "appliance.spdx.json"
        and _is_sha256(value["sha256"])
        and value["spdx_version"] == "SPDX-2.3"
        and value["document_spdx_id"] == "SPDXRef-DOCUMENT",
        "manifest SBOM reference values are invalid",
    )


def _validate_provenance(value: object) -> None:
    _require(type(value) is dict, "manifest provenance is invalid")
    _require_keys(value, _BINDING_KEYS, "manifest provenance")
    _require(
        value["schema"] == PROVENANCE_BINDING_SCHEMA
        and all(
            _is_sha256(value[key])
            for key in (
                "artifact_input_sha256",
                "execution_provenance_sha256",
                "verity_rules_sha256",
                "builder_source_sha256",
                "policy_sha256",
            )
        ),
        "manifest provenance values are invalid",
    )
    for key in ("runtime_closure", "tcb_identity"):
        status = value[key]
        _require(type(status) is dict, "manifest provenance status is invalid")
        _require_keys(status, _STATUS_BINDING_KEYS, "manifest provenance status")
        _require(
            _is_sha256(status["sha256"]) and status["status"] == DECLARED_UNVERIFIED,
            "manifest provenance status values are invalid",
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


def _nonnegative_int(value: object) -> bool:
    return type(value) is int and value >= 0


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA_KEYS


def _valid_v5_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return str(parsed) == value and parsed.version == 5 and parsed.variant == uuid.RFC_4122


def _require_keys(value: dict, expected: frozenset[str], label: str) -> None:
    if set(value) != expected:
        raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_FORBIDDEN_FIELD, f"{label} has unexpected fields")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, message)
