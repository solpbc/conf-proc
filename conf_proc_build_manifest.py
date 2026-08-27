#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Builder-side canonical appliance manifest assembly.

Builds the manifest dict from the builder's own already-validated
components (Lock, Policy, built ImageArtifacts, toolchain, module
authority, SBOM reference) and emits canonical JSON bytes. The inspector's
independent validation/diff lives in conf_proc_inspect_manifest.py and
does not import this module.
"""

from __future__ import annotations

from conf_proc_build_images import ImageArtifact
from conf_proc_geometry import derive_build_epoch
from conf_proc_json import canonical_dumps
from conf_proc_lock import Lock
from conf_proc_manifest import MANIFEST_SCHEMA_ID, MANIFEST_VERSION, parse_manifest
from conf_proc_policy import Policy


_BINDING_CONTENT_CLASS_TO_CATEGORY = {
    "executable": "executables",
    "config": "configs",
    "model": "models",
    "runtime_data": "runtime_inputs",
}


def build_manifest_bytes(
    *,
    lock: Lock,
    lock_digest: bytes,
    policy: Policy,
    policy_sha256: str,
    images: dict[str, ImageArtifact],
    toolchain: list[dict],
    module_authority: dict,
    sbom_reference: dict,
) -> bytes:
    """Assemble and canonically encode the appliance manifest."""

    raw = {
        "schema": MANIFEST_SCHEMA_ID,
        "manifest_version": MANIFEST_VERSION,
        "lock_schema": lock.schema,
        "lock_sha256": lock_digest.hex(),
        "reproducibility": {
            "build_epoch": derive_build_epoch(lock_digest),
            "sort_order": "byte-wise-path",
            "codec": "conf-proc-canonical-json/v1",
        },
        "base_image_record": _base_image_record_dict(lock),
        "future_cmdline": lock.future_cmdline,
        "images": {image_id: _image_dict(artifact) for image_id, artifact in images.items()},
        "inputs": [_input_dict(lock_input) for lock_input in sorted(lock.inputs, key=lambda entry: entry.id)],
        "inventory": {
            image_id: _inventory_for_image(lock, image_id) for image_id in ("runtime-policy", "models")
        },
        "bindings": {
            image_id: _bindings_for_image(lock, policy, image_id) for image_id in ("runtime-policy", "models")
        },
        "policy": {
            "policy_input_id": lock.policy_input_id,
            "policy_schema": policy.schema,
            "process_policy_sha256": policy_sha256,
        },
        "module_authority": module_authority,
        "toolchain": sorted(toolchain, key=lambda entry: entry["tool_id"]),
        "sbom": sbom_reference,
    }
    data = canonical_dumps(raw)
    parse_manifest(data)
    return data


def _base_image_record_dict(lock: Lock) -> dict:
    record = lock.base_image_record
    return {
        "kind": record.kind,
        "provider": record.provider,
        "identity_namespace": record.identity_namespace,
        "identity_name": record.identity_name,
        "identity_immutable_revision": record.identity_immutable_revision,
        "content_sha256": record.content_sha256,
        "content_size_bytes": record.content_size_bytes,
        "content_media_type": record.content_media_type,
        "availability": record.availability,
        "recorded_retrieval_scheme": record.recorded_retrieval_scheme,
        "recorded_retrieval_identity": record.recorded_retrieval_identity,
        "recorded_retrieval_immutable_ref": record.recorded_retrieval_immutable_ref,
    }


def _image_dict(artifact: ImageArtifact) -> dict:
    return {
        "squashfs_sha256": artifact.squashfs_sha256,
        "squashfs_size_bytes": artifact.squashfs_size,
        "hash_device_sha256": artifact.hash_device_sha256,
        "hash_device_size_bytes": artifact.hash_device_size,
        "root_hash": artifact.root_hash,
        "data_block_size": artifact.data_block_size,
        "hash_block_size": artifact.hash_block_size,
        "hash_algorithm": artifact.hash_algorithm,
        "salt": artifact.salt,
        "uuid": artifact.uuid,
    }


def _input_dict(lock_input) -> dict:
    return {
        "id": lock_input.id,
        "role": lock_input.role,
        "sha256": lock_input.sha256,
        "size_bytes": lock_input.size_bytes,
        "source_retrieval_scheme": lock_input.source_retrieval_scheme,
        "source_retrieval_identity": lock_input.source_retrieval_identity,
        "source_retrieval_immutable_ref": lock_input.source_retrieval_immutable_ref,
        "derivation_kind": lock_input.derivation_kind,
        "derivation_recipe_id": lock_input.derivation_recipe_id,
        "derivation_parent_ids": list(lock_input.derivation_parent_ids),
        "derivation_parameters_sha256": lock_input.derivation_parameters_sha256,
        "placements": [
            {
                "image": placement.image,
                "path": placement.path,
                "node_type": placement.node_type,
                "mode": placement.mode,
                "uid": placement.uid,
                "gid": placement.gid,
                "xattrs": list(placement.xattrs),
                "source_input_id": placement.source_input_id,
                "target": placement.target,
            }
            for placement in sorted(lock_input.placements, key=lambda p: (p.image, p.path))
        ],
    }


def _inventory_for_image(lock: Lock, image_id: str) -> list[dict]:
    records = []
    for lock_input in lock.inputs:
        for placement in lock_input.placements:
            if placement.image != image_id:
                continue
            records.append(
                {
                    "path": placement.path,
                    "node_type": placement.node_type,
                    "mode": placement.mode,
                    "uid": placement.uid,
                    "gid": placement.gid,
                    "xattrs": list(placement.xattrs),
                    "sha256": lock_input.sha256 if placement.node_type == "file" else None,
                    "size_bytes": lock_input.size_bytes if placement.node_type == "file" else None,
                    "symlink_target": placement.target,
                    "source_input_id": placement.source_input_id,
                }
            )
    return sorted(records, key=lambda record: record["path"])


def _bindings_for_image(lock: Lock, policy: Policy, image_id: str) -> dict[str, list[str]]:
    categories: dict[str, list[str]] = {name: [] for name in _BINDING_CONTENT_CLASS_TO_CATEGORY.values()}
    image_policy = policy.images.get(image_id)
    if image_policy is None:
        return categories
    for node in image_policy.nodes:
        if node.node_type != "file" or node.content_class is None:
            continue
        category = _BINDING_CONTENT_CLASS_TO_CATEGORY[node.content_class]
        categories[category].append(node.path)
    for name in categories:
        categories[name].sort()
    return categories
