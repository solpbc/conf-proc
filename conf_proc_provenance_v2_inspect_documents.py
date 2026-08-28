#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent provenance-v2 document derivation for the dormant inspector.

This module deliberately derives the expected manifest and SPDX documents from
the six trusted authorities and inspector evidence.  It does not use the v2
producer, v2 document parsers, or the sealed provenance oracle.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final

from conf_proc_geometry import (
    VERITY_DATA_BLOCK_SIZE,
    VERITY_HASH_ALGORITHM,
    VERITY_HASH_BLOCK_SIZE,
    derive_build_epoch,
    derive_verity_salt,
    derive_verity_uuid,
)
from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_lock import Lock, parse_lock
from conf_proc_policy import Policy, parse_policy
from conf_proc_reasons import (
    CP_PROVENANCE_AUTHORITY,
    CP_PROVENANCE_STATUS,
    CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH,
    CP_RUNTIME_CLOSURE_SCHEMA,
    CP_TCB_IDENTITY_SCHEMA,
    CP_VERITY_RULES_SCHEMA,
    ApplianceError,
)


_RUNTIME_CLOSURE_SCHEMA: Final = "conf-proc-runtime-closure/v1"
_VERITY_RULES_SCHEMA: Final = "conf-proc-verity-rules/v1"
_TCB_IDENTITY_SCHEMA: Final = "conf-proc-pre-sandbox-tcb/v1"
_EXECUTION_PROVENANCE_SCHEMA: Final = "conf-proc-execution-provenance/v1"
_DECLARED_UNVERIFIED: Final = "declared_unverified"
_MANIFEST_SCHEMA: Final = "conf-proc-appliance-manifest/v2"
_MANIFEST_VERSION: Final = 2
_BINDING_SCHEMA: Final = "conf-proc-execution-provenance-binding/v1"
_IMAGE_IDS: Final = ("models", "runtime-policy")
_BINDING_CATEGORIES: Final = ("configs", "executables", "models", "runtime_inputs")
_BINDING_CONTENT_CLASS_TO_CATEGORY: Final = {
    "executable": "executables",
    "config": "configs",
    "model": "models",
    "runtime_data": "runtime_inputs",
}
_RUNTIME_DEPENDENCY_ROLES: Final = frozenset(
    {"sglang_image", "inference_model", "asr_model", "gateway_dependency_lock", "asr_dependency_lock"}
)
_PACKAGE_PURPOSE_BY_ROLE: Final = {
    "kernel": "OPERATING-SYSTEM",
    "kernel_trusted_cert_bundle": "FILE",
    "final_systemd_stub": "APPLICATION",
    "final_systemd_unit": "APPLICATION",
    "nvidia_cc_driver": "DEVICE",
    "nvidia_cc_firmware": "FIRMWARE",
    "conf_proc_source": "FILE",
    "sglang_image": "APPLICATION",
    "inference_model": "APPLICATION",
    "asr_model": "APPLICATION",
    "gateway_dependency_lock": "APPLICATION",
    "asr_dependency_lock": "APPLICATION",
    "runtime_tree_input": "FILE",
    "policy_tree_input": "FILE",
    "models_tree_input": "FILE",
    "build_tool": "APPLICATION",
}
_SPDX_REFERENCE_TYPES: Final = (
    "conf-proc-artifact-input",
    "conf-proc-builder-source",
    "conf-proc-execution-provenance",
    "conf-proc-policy",
    "conf-proc-runtime-closure",
    "conf-proc-tcb-identity",
    "conf-proc-verity-rules",
)
_SPDX_SYMLINK_DOMAIN: Final = b"conf-proc/spdx-symlink-checksum/v1"
_SPDX_NAMESPACE_DOMAIN: Final = b"conf-proc/spdx-document-namespace/v1"
_SANITIZE_RE: Final = re.compile(r"[^A-Za-z0-9.-]")

_SUPPORTED_VERITY_RULES: Final = {
    "schema": _VERITY_RULES_SCHEMA,
    "image_ids": ["models", "runtime-policy"],
    "hash_algorithm": "sha256",
    "data_block_size": 4096,
    "hash_block_size": 4096,
    "image_padding_rule": "zero-to-data-block-boundary",
    "squashfs": {
        "append": False, "quiet": True, "progress": False, "exit_on_error": True,
        "reproducible": True, "processors": 1, "block_size": 131072,
        "fragments": True, "tailends": False, "duplicate_data_detection": True,
        "hardlink_detection": True, "xattrs": True, "export_table": True,
        "sparse_file_detection": True, "inode_compression": True,
        "id_table_compression": True, "data_compression": True,
        "fragment_compression": True, "xattr_compression": True,
        "filesystem_padding_4k": True, "output_offset_bytes": 0,
        "gzip": {"compression_level": 9, "window_size": 15, "strategies": ["default"]},
        "all_time_source": "derived-build-epoch", "mkfs_time_source": "derived-build-epoch",
        "compression": "gzip", "root_mode": 493, "root_uid": 0, "root_gid": 0,
        "pseudo_file": "required",
    },
    "verity": {
        "format": "veritysetup-format-v1", "superblock": True,
        "data_device_offset_bytes": 0, "hash_offset_bytes": 0, "fec": "disabled",
    },
    "build_epoch": {
        "domain_ascii": "conf-proc/build-clock/v1",
        "preimage_fields": ["domain_ascii", "artifact_input_digest_bytes"],
        "utc_range_start": 946684800, "utc_range_end": 4102444799, "digest_prefix_bytes": 8,
    },
    "salt": {
        "domain_ascii": "conf-proc/verity-salt/v1",
        "preimage_fields": ["domain_ascii", "image_id_ascii", "artifact_input_digest_bytes"],
        "length_bytes": 32, "encoding": "lowercase-hex",
    },
    "uuid": {
        "domain_ascii": "conf-proc/verity-uuid/v1",
        "preimage_fields": ["domain_ascii", "image_id_ascii", "artifact_input_digest_bytes"],
        "digest_prefix_bytes": 16, "rfc4122_version": 5, "rfc4122_variant": "10",
    },
}


@dataclass(frozen=True)
class InspectionInputs:
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
    lock: Lock
    policy: Policy


def derive_inspection_inputs(
    *,
    root_lock_bytes: bytes,
    runtime_closure_bytes: bytes,
    verity_rules_bytes: bytes,
    tcb_identity_bytes: bytes,
    builder_source_bytes: bytes,
    policy_bytes: bytes,
) -> InspectionInputs:
    """Validate authorities and independently bind their two v2 identities."""

    try:
        closure = _parse_runtime_closure(runtime_closure_bytes)
        _parse_verity_rules(verity_rules_bytes)
        _parse_tcb_identity(tcb_identity_bytes)
        policy_raw = canonical_loads(policy_bytes)
        _require(
            type(policy_raw) is dict and policy_raw.get("schema") == "conf-proc-policy/v1",
            CP_PROVENANCE_AUTHORITY,
            "policy authority has an unsupported schema",
        )
        policy = parse_policy(policy_bytes)
        lock = parse_lock(root_lock_bytes)
        builder_digest = _digest(builder_source_bytes)
        policy_digest = _digest(policy_bytes)
        _verify_authority_binding(lock, closure, builder_digest, policy_digest, len(policy_bytes))
    except ApplianceError:
        raise
    except (TypeError, ValueError) as exc:
        raise ApplianceError(CP_PROVENANCE_AUTHORITY, "provenance authorities are invalid") from exc

    fields = {
        "schema": _EXECUTION_PROVENANCE_SCHEMA,
        "artifact_input_sha256": _digest(root_lock_bytes),
        "runtime_closure_sha256": _digest(runtime_closure_bytes),
        "verity_rules_sha256": _digest(verity_rules_bytes),
        "tcb_identity_sha256": _digest(tcb_identity_bytes),
        "builder_source_sha256": builder_digest,
        "policy_sha256": policy_digest,
    }
    return InspectionInputs(
        artifact_input_schema=lock.schema,
        artifact_input_sha256=fields["artifact_input_sha256"],
        runtime_closure_sha256=fields["runtime_closure_sha256"],
        verity_rules_sha256=fields["verity_rules_sha256"],
        tcb_identity_sha256=fields["tcb_identity_sha256"],
        builder_source_sha256=builder_digest,
        policy_sha256=policy_digest,
        execution_provenance_sha256=_digest(canonical_dumps(fields)),
        root_lock_bytes=root_lock_bytes,
        runtime_closure_bytes=runtime_closure_bytes,
        verity_rules_bytes=verity_rules_bytes,
        tcb_identity_bytes=tcb_identity_bytes,
        builder_source_bytes=builder_source_bytes,
        policy_bytes=policy_bytes,
        lock=lock,
        policy=policy,
    )


def check_documents(*, manifest_bytes: bytes, spdx_bytes: bytes, inputs: InspectionInputs, evidence: dict) -> None:
    """Require canonical documents to equal the independently derived population."""

    try:
        manifest = canonical_loads(manifest_bytes)
        spdx = canonical_loads(spdx_bytes)
        expected_spdx = _expected_spdx(inputs)
        expected_manifest = _expected_manifest(inputs, evidence, canonical_dumps(expected_spdx))
        _require(manifest == expected_manifest, CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "manifest disagrees with independent evidence")
        _require(spdx == expected_spdx, CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "SPDX disagrees with independent evidence")
    except ApplianceError as exc:
        if exc.reason_code == CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH:
            raise
        raise ApplianceError(
            CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH,
            "independent document validation failed",
        ) from exc
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ApplianceError(
            CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH,
            "independent document validation failed",
        ) from exc


def _expected_manifest(inputs: InspectionInputs, evidence: dict, expected_spdx_bytes: bytes) -> dict:
    lock = inputs.lock
    images = _images_from_evidence(inputs, evidence)
    inventory = {image: _inventory_for_image(lock, image) for image in _IMAGE_IDS}
    _validate_inventory_evidence(evidence, inventory)
    modules, firmware = _module_inventory_from_evidence(lock, evidence)
    trusted_bundle = next(item.id for item in lock.inputs if item.role == "kernel_trusted_cert_bundle")
    inputs_by_id = {item.id: item for item in lock.inputs}
    digest_bytes = bytes.fromhex(inputs.artifact_input_sha256)
    return {
        "schema": _MANIFEST_SCHEMA,
        "manifest_version": _MANIFEST_VERSION,
        "lock_schema": lock.schema,
        "lock_sha256": inputs.artifact_input_sha256,
        "reproducibility": {
            "build_epoch": derive_build_epoch(digest_bytes),
            "sort_order": "byte-wise-path",
            "codec": "conf-proc-canonical-json/v1",
        },
        "base_image_record": _base_image_record(lock),
        "future_cmdline": lock.future_cmdline,
        "images": images,
        "inputs": [_input_projection(item) for item in lock.inputs],
        "inventory": inventory,
        "bindings": {image: _bindings_for_image(inputs.policy, image) for image in _IMAGE_IDS},
        "policy": {
            "policy_input_id": lock.policy_input_id,
            "policy_schema": inputs.policy.schema,
            "process_policy_sha256": inputs.policy_sha256,
        },
        "module_authority": {
            "trusted_bundle_input_id": trusted_bundle,
            "authorized_signer_certificate_sha256": [
                signer.certificate_sha256 for signer in lock.authorized_module_signers
            ],
            "module_inventory": modules,
            "firmware_inventory": firmware,
        },
        "toolchain": [
            {"tool_id": tool_id, "component": inputs_by_id[tool_id].component,
             "resolved_path_sha256": inputs_by_id[tool_id].sha256}
            for tool_id in lock.tool_ids
        ],
        "sbom": {
            "filename": "appliance.spdx.json",
            "sha256": _digest(expected_spdx_bytes),
            "spdx_version": "SPDX-2.3",
            "document_spdx_id": "SPDXRef-DOCUMENT",
        },
        "provenance": {
            "schema": _BINDING_SCHEMA,
            "artifact_input_sha256": inputs.artifact_input_sha256,
            "execution_provenance_sha256": inputs.execution_provenance_sha256,
            "runtime_closure": {"sha256": inputs.runtime_closure_sha256, "status": _DECLARED_UNVERIFIED},
            "verity_rules_sha256": inputs.verity_rules_sha256,
            "tcb_identity": {"sha256": inputs.tcb_identity_sha256, "status": _DECLARED_UNVERIFIED},
            "builder_source_sha256": inputs.builder_source_sha256,
            "policy_sha256": inputs.policy_sha256,
        },
    }


def _expected_spdx(inputs: InspectionInputs) -> dict:
    lock = inputs.lock
    lock_digest = bytes.fromhex(inputs.artifact_input_sha256)
    packages = [_appliance_package(inputs)]
    files: list[dict] = []
    relationships: list[dict] = []
    file_ids: set[str] = set()
    file_names: set[str] = set()
    for item in lock.inputs:
        package = _package_id(item.id)
        packages.append({
            "SPDXID": package, "name": item.component, "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION", "supplier": "NOASSERTION", "originator": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": item.sha256}],
            "primaryPackagePurpose": _PACKAGE_PURPOSE_BY_ROLE[item.role],
        })
        relationships.append({
            "spdxElementId": package,
            "relationshipType": _package_relationship(item.role),
            "relatedSpdxElement": "SPDXRef-Package-appliance",
        })
        for placement in item.placements:
            if placement.node_type == "directory":
                continue
            entry_id = _file_id(placement.image, placement.path)
            filename = f"{placement.image}{placement.path}"
            _require(entry_id not in file_ids and filename not in file_names,
                     CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "SPDX identity collision")
            file_ids.add(entry_id)
            file_names.add(filename)
            checksum = item.sha256 if placement.node_type == "file" else _symlink_checksum(placement.target or "")
            files.append({
                "SPDXID": entry_id, "fileName": filename,
                "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}],
            })
            relationships.extend((
                {"spdxElementId": "SPDXRef-Package-appliance", "relationshipType": "CONTAINS", "relatedSpdxElement": entry_id},
                {"spdxElementId": entry_id, "relationshipType": "GENERATED_FROM", "relatedSpdxElement": package},
            ))
    packages.sort(key=lambda row: row["SPDXID"])
    files.sort(key=lambda row: row["fileName"])
    relationships.sort(key=lambda row: (row["spdxElementId"], row["relationshipType"], row["relatedSpdxElement"]))
    _require(len(relationships) == len({(r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"]) for r in relationships}),
             CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "SPDX relationship collision")
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"conf-proc-appliance-{lock_digest.hex()[:16]}",
        "documentNamespace": _document_namespace(lock_digest),
        "creationInfo": {
            "created": datetime.fromtimestamp(derive_build_epoch(lock_digest), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: conf-proc-sbom-v1"],
        },
        "packages": packages, "files": files, "relationships": relationships,
        "documentDescribes": ["SPDXRef-Package-appliance"],
    }


def _images_from_evidence(inputs: InspectionInputs, evidence: dict) -> dict:
    images = _mapping(evidence.get("images"), "image evidence")
    _require(set(images) == set(_IMAGE_IDS), CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "image evidence is incomplete")
    digest = bytes.fromhex(inputs.artifact_input_sha256)
    expected: dict[str, dict] = {}
    for image in _IMAGE_IDS:
        record = _mapping(images[image], "image evidence record")
        _require(set(record) == {"squashfs_sha256", "squashfs_size_bytes", "hash_device_sha256", "hash_device_size_bytes", "root_hash"},
                 CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "image evidence has unexpected fields")
        _require(
            all(_sha256(record[key]) for key in ("squashfs_sha256", "hash_device_sha256", "root_hash"))
            and type(record["squashfs_size_bytes"]) is int and record["squashfs_size_bytes"] > 0
            and type(record["hash_device_size_bytes"]) is int and record["hash_device_size_bytes"] > 0
            and record["squashfs_size_bytes"] % VERITY_DATA_BLOCK_SIZE == 0
            and record["hash_device_size_bytes"] % VERITY_HASH_BLOCK_SIZE == 0,
            CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH,
            "image evidence geometry is invalid",
        )
        expected[image] = {
            **record,
            "data_block_size": VERITY_DATA_BLOCK_SIZE,
            "hash_block_size": VERITY_HASH_BLOCK_SIZE,
            "hash_algorithm": VERITY_HASH_ALGORITHM,
            "salt": derive_verity_salt(digest, image),
            "uuid": derive_verity_uuid(digest, image),
        }
    return expected


def _inventory_for_image(lock: Lock, image: str) -> list[dict]:
    rows: list[dict] = []
    for item in lock.inputs:
        for placement in item.placements:
            if placement.image == image:
                rows.append({
                    "path": placement.path, "node_type": placement.node_type, "mode": placement.mode,
                    "uid": placement.uid, "gid": placement.gid, "xattrs": list(placement.xattrs),
                    "sha256": item.sha256 if placement.node_type == "file" else None,
                    "size_bytes": item.size_bytes if placement.node_type == "file" else None,
                    "symlink_target": placement.target, "source_input_id": placement.source_input_id,
                })
    rows.sort(key=lambda row: row["path"])
    _require(len(rows) == len({row["path"] for row in rows}), CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "inventory path collision")
    return rows


def _validate_inventory_evidence(evidence: dict, expected: dict[str, list[dict]]) -> None:
    inventories = _mapping(evidence.get("inventories"), "inventory evidence")
    _require(set(inventories) == set(_IMAGE_IDS), CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "inventory evidence is incomplete")
    for image, rows in expected.items():
        actual = _mapping(inventories[image], "inventory image evidence")
        _require(set(actual) == {row["path"] for row in rows}, CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "inventory evidence paths disagree")
        for row in rows:
            node = actual[row["path"]]
            values = {
                "node_type": getattr(node, "node_type", None), "mode": getattr(node, "mode", None),
                "uid": getattr(node, "uid", None), "gid": getattr(node, "gid", None),
                "xattrs": list(getattr(node, "xattrs", ())), "sha256": getattr(node, "sha256", None),
                "size_bytes": getattr(node, "size", None) if row["node_type"] == "file" else None,
                "symlink_target": getattr(node, "symlink_target", None),
            }
            for key in values:
                _require(values[key] == row[key], CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "inventory evidence disagrees with authority")


def _module_inventory_from_evidence(lock: Lock, evidence: dict) -> tuple[list[dict], list[dict]]:
    modules = evidence.get("module_inventory")
    firmware = evidence.get("firmware_inventory")
    _require(type(modules) is list and type(firmware) is list, CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "module evidence is invalid")
    expected_modules: dict[str, str] = {}
    expected_firmware: dict[str, str] = {}
    for item in lock.inputs:
        for placement in item.placements:
            if placement.node_type != "file":
                continue
            if placement.path.endswith(".ko"):
                expected_modules[placement.path] = item.sha256
            elif "/firmware/" in placement.path:
                expected_firmware[placement.path] = item.sha256
    _require([row.get("path") for row in modules if type(row) is dict] == sorted(expected_modules),
             CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "module evidence coverage disagrees")
    _require([row.get("path") for row in firmware if type(row) is dict] == sorted(expected_firmware),
             CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "firmware evidence coverage disagrees")
    authorized = {item.certificate_sha256 for item in lock.authorized_module_signers}
    for row in modules:
        _require(type(row) is dict and set(row) == {"path", "sha256", "signer_certificate_sha256"}
                 and row["sha256"] == expected_modules.get(row["path"])
                 and row["signer_certificate_sha256"] in authorized,
                 CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "module evidence is unauthorized")
    for row in firmware:
        _require(type(row) is dict and set(row) == {"path", "sha256"}
                 and row["sha256"] == expected_firmware.get(row["path"]),
                 CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "firmware evidence is invalid")
    return modules, firmware


def _base_image_record(lock: Lock) -> dict:
    row = lock.base_image_record
    return {
        "kind": row.kind, "provider": row.provider, "identity_namespace": row.identity_namespace,
        "identity_name": row.identity_name, "identity_immutable_revision": row.identity_immutable_revision,
        "content_sha256": row.content_sha256, "content_size_bytes": row.content_size_bytes,
        "content_media_type": row.content_media_type, "availability": row.availability,
        "recorded_retrieval_scheme": row.recorded_retrieval_scheme,
        "recorded_retrieval_identity": row.recorded_retrieval_identity,
        "recorded_retrieval_immutable_ref": row.recorded_retrieval_immutable_ref,
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
            {"image": p.image, "path": p.path, "node_type": p.node_type, "mode": p.mode,
             "uid": p.uid, "gid": p.gid, "xattrs": list(p.xattrs), "source_input_id": p.source_input_id,
             "target": p.target}
            for p in sorted(item.placements, key=lambda p: (p.image, p.path))
        ],
    }


def _bindings_for_image(policy: Policy, image: str) -> dict[str, list[str]]:
    values = {name: [] for name in _BINDING_CATEGORIES}
    image_policy = policy.images.get(image)
    if image_policy is not None:
        for node in image_policy.nodes:
            if node.node_type == "file" and node.content_class is not None:
                values[_BINDING_CONTENT_CLASS_TO_CATEGORY[node.content_class]].append(node.path)
    for paths in values.values():
        paths.sort()
    return values


def _appliance_package(inputs: InspectionInputs) -> dict:
    digests = {
        "conf-proc-artifact-input": inputs.artifact_input_sha256,
        "conf-proc-builder-source": inputs.builder_source_sha256,
        "conf-proc-execution-provenance": inputs.execution_provenance_sha256,
        "conf-proc-policy": inputs.policy_sha256,
        "conf-proc-runtime-closure": inputs.runtime_closure_sha256,
        "conf-proc-tcb-identity": inputs.tcb_identity_sha256,
        "conf-proc-verity-rules": inputs.verity_rules_sha256,
    }
    return {
        "SPDXID": "SPDXRef-Package-appliance", "name": "conf-proc-appliance",
        "downloadLocation": "NOASSERTION", "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
        "supplier": "NOASSERTION", "originator": "NOASSERTION",
        "checksums": [{"algorithm": "SHA256", "checksumValue": inputs.artifact_input_sha256}],
        "primaryPackagePurpose": "APPLICATION",
        "externalRefs": [
            {"referenceCategory": "OTHER", "referenceType": name, "referenceLocator": f"sha256:{digests[name]}"}
            for name in _SPDX_REFERENCE_TYPES
        ],
    }


def _package_relationship(role: str) -> str:
    if role == "build_tool":
        return "BUILD_TOOL_OF"
    if role in _RUNTIME_DEPENDENCY_ROLES:
        return "RUNTIME_DEPENDENCY_OF"
    return "CONTAINS"


def _package_id(input_id: str) -> str:
    return f"SPDXRef-Package-{_SANITIZE_RE.sub('-', input_id)}"


def _file_id(image: str, path: str) -> str:
    return f"SPDXRef-File-{_SANITIZE_RE.sub('-', image)}-{_SANITIZE_RE.sub('-', path)}"


def _symlink_checksum(target: str) -> str:
    return hashlib.sha256(_SPDX_SYMLINK_DOMAIN + target.encode("utf-8")).hexdigest()


def _document_namespace(lock_digest: bytes) -> str:
    value = bytearray(hashlib.sha256(_SPDX_NAMESPACE_DOMAIN + lock_digest).digest()[:16])
    value[6] = (value[6] & 0x0F) | 0x50
    value[8] = (value[8] & 0x3F) | 0x80
    return f"urn:uuid:{uuid.UUID(bytes=bytes(value))}"


def _parse_runtime_closure(data: bytes) -> dict:
    raw = canonical_loads(data)
    _require(type(raw) is dict and set(raw) == {"schema", "status", "entries"}, CP_RUNTIME_CLOSURE_SCHEMA, "runtime closure fields are invalid")
    _require(raw["schema"] == _RUNTIME_CLOSURE_SCHEMA and raw["status"] == _DECLARED_UNVERIFIED,
             CP_RUNTIME_CLOSURE_SCHEMA, "runtime closure identity is invalid")
    _require(type(raw["entries"]) is list and raw["entries"], CP_RUNTIME_CLOSURE_SCHEMA, "runtime closure entries are invalid")
    for entry in raw["entries"]:
        _require(type(entry) is dict and {"path", "node_type", "mode", "uid", "gid", "size_bytes", "sha256", "symlink_target", "hardlink_group", "xattrs", "capabilities", "logical_role", "provenance", "root_lock_input_id"} == set(entry),
                 CP_RUNTIME_CLOSURE_SCHEMA, "runtime closure entry is invalid")
        _require(type(entry["logical_role"]) is str and entry["logical_role"], CP_RUNTIME_CLOSURE_SCHEMA, "runtime closure role is invalid")
        _require(type(entry["root_lock_input_id"]) is str or entry["root_lock_input_id"] is None,
                 CP_RUNTIME_CLOSURE_SCHEMA, "runtime closure binding is invalid")
    return raw


def _parse_verity_rules(data: bytes) -> None:
    _require(canonical_loads(data) == _SUPPORTED_VERITY_RULES, CP_VERITY_RULES_SCHEMA, "verity rules differ from the supported contract")


def _parse_tcb_identity(data: bytes) -> None:
    raw = canonical_loads(data)
    _require(type(raw) is dict and set(raw) == {"schema", "status", "caller", "launcher", "sandbox", "kernel_feature_contract"},
             CP_TCB_IDENTITY_SCHEMA, "TCB identity fields are invalid")
    _require(raw["schema"] == _TCB_IDENTITY_SCHEMA and raw["status"] == _DECLARED_UNVERIFIED,
             CP_TCB_IDENTITY_SCHEMA, "TCB identity status is invalid")
    for item in (raw["caller"], raw["launcher"], raw["sandbox"].get("executable") if type(raw["sandbox"]) is dict else None):
        _require(type(item) is dict and _sha256(item.get("sha256")), CP_TCB_IDENTITY_SCHEMA, "TCB executable identity is invalid")


def _verify_authority_binding(lock: Lock, closure: dict, builder_digest: str, policy_digest: str, policy_size: int) -> None:
    _require(lock.image_specs == {"models": {}, "runtime-policy": {}}, CP_PROVENANCE_AUTHORITY, "lock image geometry is invalid")
    inputs = {item.id: item for item in lock.inputs}
    policy_input = inputs.get(lock.policy_input_id)
    _require(policy_input is not None and policy_input.sha256 == policy_digest and policy_input.size_bytes == policy_size,
             CP_PROVENANCE_AUTHORITY, "policy does not match root lock")
    builder = [entry for entry in closure["entries"] if entry["logical_role"] == "conf_proc_source"]
    _require(len(builder) == 1 and builder[0]["root_lock_input_id"] is not None and builder[0].get("sha256") == builder_digest,
             CP_PROVENANCE_AUTHORITY, "runtime closure does not bind builder source")
    for entry in closure["entries"]:
        input_id = entry["root_lock_input_id"]
        if input_id is None:
            continue
        authority = inputs.get(input_id)
        provenance = entry.get("provenance")
        _require(authority is not None and type(provenance) is dict
                 and authority.sha256 == entry.get("sha256") and authority.size_bytes == entry.get("size_bytes")
                 and authority.role == entry.get("logical_role")
                 and authority.source_retrieval_scheme == provenance.get("scheme")
                 and authority.source_retrieval_identity == provenance.get("identity")
                 and authority.source_retrieval_immutable_ref == provenance.get("immutable_ref"),
                 CP_PROVENANCE_AUTHORITY, "runtime closure disagrees with root lock")


def _mapping(value: object, message: str) -> dict:
    _require(type(value) is dict, CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, message)
    return value


def _sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _digest(data: bytes) -> str:
    _require(type(data) is bytes, CP_PROVENANCE_AUTHORITY, "authority inputs must be bytes")
    return hashlib.sha256(data).hexdigest()


def _require(condition: bool, reason_code: str, message: str) -> None:
    if not condition:
        raise ApplianceError(reason_code, message)
