#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent inspector-side manifest validation and diff.

Deliberately does NOT import conf_proc_build_manifest.py. Every expected
field below is re-derived here, independently, from the caller's own
trusted Lock/Policy and from this module's own image/tree re-derivation
results -- the emitted manifest is parsed only for its literal bytes and
then treated as an unverified claim to be checked field by field.
"""

from __future__ import annotations

from conf_proc_geometry import derive_build_epoch
from conf_proc_lock import Lock
from conf_proc_manifest import Manifest
from conf_proc_policy import Policy
from conf_proc_reasons import CP_MANIFEST_DIFF, ApplianceError


def compare_manifest(
    manifest: Manifest,
    *,
    lock: Lock,
    lock_digest: bytes,
    policy: Policy,
    policy_sha256: str,
    rederived_images: dict[str, dict],
    inventories: dict[str, dict],
) -> None:
    """Compare every manifest field against an independently derived value.

    ``rederived_images`` maps image id to a dict with the keys
    ``squashfs_sha256``, ``squashfs_size_bytes``, ``hash_device_sha256``,
    ``hash_device_size_bytes``, ``root_hash``, ``data_block_size``,
    ``hash_block_size``, ``hash_algorithm``, ``salt``, ``uuid`` --
    obtained independently via conf_proc_inspect_images. ``inventories``
    maps image id to the dict[path, InventoryNode] obtained independently
    via conf_proc_inspect_tree.build_inventory.
    """

    raw = manifest.raw
    _check(raw["lock_sha256"] == lock_digest.hex(), "lock_sha256")
    _check(raw["lock_schema"] == lock.schema, "lock_schema")
    _check(raw["future_cmdline"] == lock.future_cmdline, "future_cmdline")
    _check(raw["reproducibility"]["build_epoch"] == derive_build_epoch(lock_digest), "reproducibility.build_epoch")

    expected_base = _expected_base_image_record(lock)
    _check(raw["base_image_record"] == expected_base, "base_image_record")

    for image_id, expected in rederived_images.items():
        actual = raw["images"][image_id]
        for field in (
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
        ):
            _check(actual[field] == expected[field], f"images.{image_id}.{field}")

    expected_inputs = _expected_inputs(lock)
    _check(raw["inputs"] == expected_inputs, "inputs")

    for image_id, inventory in inventories.items():
        expected_records = _expected_inventory(lock, image_id)
        actual_records = raw["inventory"][image_id]
        actual_by_path = {record["path"]: record for record in actual_records}
        expected_by_path = {record["path"]: record for record in expected_records}

        for path in inventory:
            if path not in actual_by_path:
                raise ApplianceError(CP_MANIFEST_DIFF, f"inventory.{image_id}: {path} is missing from the emitted manifest")
        for path, expected_record in expected_by_path.items():
            if path not in actual_by_path:
                raise ApplianceError(CP_MANIFEST_DIFF, f"inventory.{image_id}: {path} is missing from the emitted manifest")
            if actual_by_path[path] != expected_record:
                raise ApplianceError(CP_MANIFEST_DIFF, f"inventory.{image_id}.{path}: does not match the independently derived record")
        if set(actual_by_path) != set(expected_by_path):
            extra = set(actual_by_path) - set(expected_by_path)
            raise ApplianceError(CP_MANIFEST_DIFF, f"inventory.{image_id}: emitted manifest lists undeclared paths {sorted(extra)}")

    _check(raw["policy"]["policy_input_id"] == lock.policy_input_id, "policy.policy_input_id")
    _check(raw["policy"]["policy_schema"] == policy.schema, "policy.policy_schema")
    _check(raw["policy"]["process_policy_sha256"] == policy_sha256, "policy.process_policy_sha256")


def _check(condition: bool, field: str) -> None:
    if not condition:
        raise ApplianceError(CP_MANIFEST_DIFF, f"emitted manifest field {field!r} does not match independent re-derivation")


def _expected_base_image_record(lock: Lock) -> dict:
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


def _expected_inputs(lock: Lock) -> list[dict]:
    result = []
    for lock_input in sorted(lock.inputs, key=lambda entry: entry.id):
        placements = sorted(lock_input.placements, key=lambda p: (p.image, p.path))
        result.append(
            {
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
                        "image": p.image,
                        "path": p.path,
                        "node_type": p.node_type,
                        "mode": p.mode,
                        "uid": p.uid,
                        "gid": p.gid,
                        "xattrs": list(p.xattrs),
                        "source_input_id": p.source_input_id,
                        "target": p.target,
                    }
                    for p in placements
                ],
            }
        )
    return result


def _expected_inventory(lock: Lock, image_id: str) -> list[dict]:
    out = []
    for lock_input in lock.inputs:
        for placement in lock_input.placements:
            if placement.image != image_id:
                continue
            out.append(
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
    return sorted(out, key=lambda record: record["path"])
