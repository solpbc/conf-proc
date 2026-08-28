#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Dormant provenance-v2 manifest and SPDX production entrypoint."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

import conf_proc_provenance_v2
from conf_proc_geometry import (
    VERITY_DATA_BLOCK_SIZE,
    VERITY_HASH_ALGORITHM,
    VERITY_HASH_BLOCK_SIZE,
    derive_build_epoch,
    derive_verity_salt,
    derive_verity_uuid,
)
from conf_proc_json import canonical_dumps
from conf_proc_lock import Lock, parse_lock
from conf_proc_policy import Policy, parse_policy
from conf_proc_provenance_v2_build_spdx import _build_spdx_v2_bytes
from conf_proc_provenance_v2_manifest import (
    BINDING_CATEGORIES,
    DECLARED_UNVERIFIED,
    MANIFEST_V2_SCHEMA_ID,
    MANIFEST_V2_VERSION,
    PROVENANCE_BINDING_SCHEMA,
    parse_manifest_v2,
)
from conf_proc_provenance_v2_spdx import parse_spdx_v2
from conf_proc_reasons import (
    CP_MODULE_COMPRESSED_UNSUPPORTED,
    CP_MODULE_SIGNER,
    CP_PROVENANCE_V2_IMAGE_GEOMETRY,
    CP_PROVENANCE_V2_MANIFEST_PRODUCTION,
    CP_PROVENANCE_V2_MANIFEST_SELFCHECK,
    CP_PROVENANCE_V2_SPDX_SELFCHECK,
    ApplianceError,
)


_BINDING_CONTENT_CLASS_TO_CATEGORY: Final = {
    "executable": "executables",
    "config": "configs",
    "model": "models",
    "runtime_data": "runtime_inputs",
}
_IMAGE_IDS: Final = frozenset({"models", "runtime-policy"})
_SHA_KEYS: Final = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class ProvenanceV2ImageRecord:
    image_id: str
    squashfs_sha256: str
    squashfs_size_bytes: int
    hash_device_sha256: str
    hash_device_size_bytes: int
    root_hash: str


@dataclass(frozen=True)
class ProvenanceV2ModuleObservation:
    path: str
    sha256: str
    signer_certificate_sha256: str


@dataclass(frozen=True)
class ProvenanceV2FirmwareObservation:
    path: str
    sha256: str


@dataclass(frozen=True)
class ProvenanceV2Artifacts:
    manifest_bytes: bytes
    spdx_bytes: bytes


@dataclass(frozen=True)
class _QualifiedPlacement:
    path: str
    image_id: str
    owning_input_id: str
    expected_sha256: str
    category: str


def produce_provenance_v2(
    *,
    root_lock_bytes: bytes,
    runtime_closure_bytes: bytes,
    verity_rules_bytes: bytes,
    tcb_identity_bytes: bytes,
    builder_source_bytes: bytes,
    policy_bytes: bytes,
    images: tuple[ProvenanceV2ImageRecord, ProvenanceV2ImageRecord],
    module_observations: tuple[ProvenanceV2ModuleObservation, ...],
    firmware_observations: tuple[ProvenanceV2FirmwareObservation, ...],
) -> ProvenanceV2Artifacts:
    """Produce canonical dormant provenance-v2 manifest and SPDX bytes."""

    inputs = conf_proc_provenance_v2.derive_inputs(
        root_lock_bytes=root_lock_bytes,
        runtime_closure_bytes=runtime_closure_bytes,
        verity_rules_bytes=verity_rules_bytes,
        tcb_identity_bytes=tcb_identity_bytes,
        builder_source_bytes=builder_source_bytes,
        policy_bytes=policy_bytes,
    )
    lock = parse_lock(root_lock_bytes)
    policy = parse_policy(policy_bytes)
    image_records = _validate_image_records(images, inputs.artifact_input_sha256)
    module_inventory, firmware_inventory = _validate_observations(
        lock,
        module_observations=module_observations,
        firmware_observations=firmware_observations,
    )
    spdx_bytes = _build_spdx_v2_bytes(lock=lock, inputs=inputs)
    manifest_bytes = _build_manifest_bytes(
        lock=lock,
        policy=policy,
        inputs=inputs,
        image_records=image_records,
        module_inventory=module_inventory,
        firmware_inventory=firmware_inventory,
        spdx_bytes=spdx_bytes,
    )
    _selfcheck(
        manifest_bytes=manifest_bytes,
        spdx_bytes=spdx_bytes,
        root_lock_bytes=root_lock_bytes,
        runtime_closure_bytes=runtime_closure_bytes,
        verity_rules_bytes=verity_rules_bytes,
        tcb_identity_bytes=tcb_identity_bytes,
        builder_source_bytes=builder_source_bytes,
        policy_bytes=policy_bytes,
        images=images,
        module_observations=module_observations,
        firmware_observations=firmware_observations,
        initial_inputs=inputs,
    )
    return ProvenanceV2Artifacts(manifest_bytes=manifest_bytes, spdx_bytes=spdx_bytes)


def _selfcheck(
    *,
    manifest_bytes: bytes,
    spdx_bytes: bytes,
    root_lock_bytes: bytes,
    runtime_closure_bytes: bytes,
    verity_rules_bytes: bytes,
    tcb_identity_bytes: bytes,
    builder_source_bytes: bytes,
    policy_bytes: bytes,
    images: tuple[ProvenanceV2ImageRecord, ProvenanceV2ImageRecord],
    module_observations: tuple[ProvenanceV2ModuleObservation, ...],
    firmware_observations: tuple[ProvenanceV2FirmwareObservation, ...],
    initial_inputs: conf_proc_provenance_v2.ProvenanceInputs,
) -> None:
    try:
        parse_spdx_v2(spdx_bytes)
    except ApplianceError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_SPDX_SELFCHECK, "emitted SPDX failed structural validation") from exc
    try:
        parse_manifest_v2(manifest_bytes)
    except ApplianceError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_SELFCHECK, "emitted manifest failed structural validation") from exc

    fresh_inputs = conf_proc_provenance_v2.derive_inputs(
        root_lock_bytes=root_lock_bytes,
        runtime_closure_bytes=runtime_closure_bytes,
        verity_rules_bytes=verity_rules_bytes,
        tcb_identity_bytes=tcb_identity_bytes,
        builder_source_bytes=builder_source_bytes,
        policy_bytes=policy_bytes,
    )
    fresh_lock = parse_lock(root_lock_bytes)
    fresh_policy = parse_policy(policy_bytes)
    if fresh_inputs != initial_inputs:
        raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_SELFCHECK, "fresh provenance derivation changed")
    fresh_images = _validate_image_records(images, fresh_inputs.artifact_input_sha256)
    fresh_modules, fresh_firmware = _validate_observations(
        fresh_lock,
        module_observations=module_observations,
        firmware_observations=firmware_observations,
    )
    expected_spdx = _build_spdx_v2_bytes(lock=fresh_lock, inputs=fresh_inputs)
    if expected_spdx != spdx_bytes:
        raise ApplianceError(CP_PROVENANCE_V2_SPDX_SELFCHECK, "emitted SPDX does not match fresh derivation")
    expected_manifest = _build_manifest_bytes(
        lock=fresh_lock,
        policy=fresh_policy,
        inputs=fresh_inputs,
        image_records=fresh_images,
        module_inventory=fresh_modules,
        firmware_inventory=fresh_firmware,
        spdx_bytes=expected_spdx,
    )
    if expected_manifest != manifest_bytes:
        raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_SELFCHECK, "emitted manifest does not match fresh derivation")


def _validate_image_records(
    images: tuple[ProvenanceV2ImageRecord, ProvenanceV2ImageRecord], artifact_input_sha256: str
) -> dict[str, dict]:
    if type(images) is not tuple or len(images) != 2:
        raise ApplianceError(CP_PROVENANCE_V2_IMAGE_GEOMETRY, "exactly two image records are required")
    if tuple(record.image_id for record in images if type(record) is ProvenanceV2ImageRecord) != tuple(sorted(_IMAGE_IDS)):
        raise ApplianceError(CP_PROVENANCE_V2_IMAGE_GEOMETRY, "image records must be canonically ordered")
    records: dict[str, dict] = {}
    lock_digest = bytes.fromhex(artifact_input_sha256)
    for record in images:
        if type(record) is not ProvenanceV2ImageRecord:
            raise ApplianceError(CP_PROVENANCE_V2_IMAGE_GEOMETRY, "image record type is invalid")
        if record.image_id not in _IMAGE_IDS or record.image_id in records:
            raise ApplianceError(CP_PROVENANCE_V2_IMAGE_GEOMETRY, "image record identity is invalid")
        if not (
            _is_sha256(record.squashfs_sha256)
            and _is_sha256(record.hash_device_sha256)
            and _is_sha256(record.root_hash)
            and _positive_int(record.squashfs_size_bytes)
            and _positive_int(record.hash_device_size_bytes)
            and record.squashfs_size_bytes % VERITY_DATA_BLOCK_SIZE == 0
            and record.hash_device_size_bytes % VERITY_HASH_BLOCK_SIZE == 0
        ):
            raise ApplianceError(CP_PROVENANCE_V2_IMAGE_GEOMETRY, "image record geometry is invalid")
        records[record.image_id] = {
            "squashfs_sha256": record.squashfs_sha256,
            "squashfs_size_bytes": record.squashfs_size_bytes,
            "hash_device_sha256": record.hash_device_sha256,
            "hash_device_size_bytes": record.hash_device_size_bytes,
            "root_hash": record.root_hash,
            "data_block_size": VERITY_DATA_BLOCK_SIZE,
            "hash_block_size": VERITY_HASH_BLOCK_SIZE,
            "hash_algorithm": VERITY_HASH_ALGORITHM,
            "salt": derive_verity_salt(lock_digest, record.image_id),
            "uuid": derive_verity_uuid(lock_digest, record.image_id),
        }
    if set(records) != _IMAGE_IDS:
        raise ApplianceError(CP_PROVENANCE_V2_IMAGE_GEOMETRY, "image record coverage is incomplete")
    return records


def _validate_observations(
    lock: Lock,
    *,
    module_observations: tuple[ProvenanceV2ModuleObservation, ...],
    firmware_observations: tuple[ProvenanceV2FirmwareObservation, ...],
) -> tuple[list[dict], list[dict]]:
    if type(module_observations) is not tuple or type(firmware_observations) is not tuple:
        raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "module observations must be tuples")
    qualified = _qualifying_placements(lock)
    modules = {item.path: item for item in qualified if item.category == "module"}
    firmware = {item.path: item for item in qualified if item.category == "firmware"}
    observed_modules = _index_module_observations(module_observations)
    observed_firmware = _index_firmware_observations(firmware_observations)
    if set(observed_modules) != set(modules) or set(observed_firmware) != set(firmware):
        raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "module observations disagree with lock placements")

    authorized = {signer.certificate_sha256 for signer in lock.authorized_module_signers}
    module_inventory = []
    for path, expected in modules.items():
        observed = observed_modules[path]
        if observed.sha256 != expected.expected_sha256:
            raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "module observation digest disagrees with lock")
        if observed.signer_certificate_sha256 not in authorized:
            raise ApplianceError(CP_MODULE_SIGNER, "module observation signer is unauthorized")
        module_inventory.append(
            {
                "path": path,
                "sha256": observed.sha256,
                "signer_certificate_sha256": observed.signer_certificate_sha256,
            }
        )

    firmware_inventory = []
    for path, expected in firmware.items():
        observed = observed_firmware[path]
        if observed.sha256 != expected.expected_sha256:
            raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "firmware observation digest disagrees with lock")
        firmware_inventory.append({"path": path, "sha256": observed.sha256})
    module_inventory.sort(key=lambda item: item["path"])
    firmware_inventory.sort(key=lambda item: item["path"])
    return module_inventory, firmware_inventory


def _qualifying_placements(lock: Lock) -> list[_QualifiedPlacement]:
    qualified: list[_QualifiedPlacement] = []
    seen_paths: set[str] = set()
    for lock_input in lock.inputs:
        for placement in lock_input.placements:
            if placement.node_type != "file":
                continue
            if placement.path.endswith(".ko.zst"):
                raise ApplianceError(CP_MODULE_COMPRESSED_UNSUPPORTED, "compressed kernel module is unsupported")
            if placement.path.endswith(".ko"):
                category = "module"
            elif "/firmware/" in placement.path:
                category = "firmware"
            else:
                continue
            if placement.path in seen_paths:
                raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "module or firmware placement path collides")
            seen_paths.add(placement.path)
            qualified.append(
                _QualifiedPlacement(
                    path=placement.path,
                    image_id=placement.image,
                    owning_input_id=lock_input.id,
                    expected_sha256=lock_input.sha256,
                    category=category,
                )
            )
    return qualified


def _index_module_observations(
    observations: tuple[ProvenanceV2ModuleObservation, ...],
) -> dict[str, ProvenanceV2ModuleObservation]:
    result: dict[str, ProvenanceV2ModuleObservation] = {}
    paths: list[str] = []
    for observation in observations:
        if type(observation) is not ProvenanceV2ModuleObservation or not _observation_path(observation.path):
            raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "module observation is invalid")
        if observation.path in result:
            raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "module observation path is duplicated")
        result[observation.path] = observation
        paths.append(observation.path)
    if paths != sorted(paths):
        raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "module observations must be canonically ordered")
    return result


def _index_firmware_observations(
    observations: tuple[ProvenanceV2FirmwareObservation, ...],
) -> dict[str, ProvenanceV2FirmwareObservation]:
    result: dict[str, ProvenanceV2FirmwareObservation] = {}
    paths: list[str] = []
    for observation in observations:
        if type(observation) is not ProvenanceV2FirmwareObservation or not _observation_path(observation.path):
            raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "firmware observation is invalid")
        if observation.path in result:
            raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "firmware observation path is duplicated")
        result[observation.path] = observation
        paths.append(observation.path)
    if paths != sorted(paths):
        raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "firmware observations must be canonically ordered")
    return result


def _build_manifest_bytes(
    *,
    lock: Lock,
    policy: Policy,
    inputs: conf_proc_provenance_v2.ProvenanceInputs,
    image_records: dict[str, dict],
    module_inventory: list[dict],
    firmware_inventory: list[dict],
    spdx_bytes: bytes,
) -> bytes:
    lock_digest = bytes.fromhex(inputs.artifact_input_sha256)
    trusted_bundle_input_id = next(
        item.id for item in lock.inputs if item.role == "kernel_trusted_cert_bundle"
    )
    root_inputs = {item.id: item for item in lock.inputs}
    raw = {
        "schema": MANIFEST_V2_SCHEMA_ID,
        "manifest_version": MANIFEST_V2_VERSION,
        "lock_schema": lock.schema,
        "lock_sha256": inputs.artifact_input_sha256,
        "reproducibility": {
            "build_epoch": derive_build_epoch(lock_digest),
            "sort_order": "byte-wise-path",
            "codec": "conf-proc-canonical-json/v1",
        },
        "base_image_record": _base_image_record(lock),
        "future_cmdline": lock.future_cmdline,
        "images": image_records,
        "inputs": [_input_projection(item) for item in sorted(lock.inputs, key=lambda item: item.id)],
        "inventory": {image_id: _inventory_for_image(lock, image_id) for image_id in ("models", "runtime-policy")},
        "bindings": {image_id: _bindings_for_image(policy, image_id) for image_id in ("models", "runtime-policy")},
        "policy": {
            "policy_input_id": lock.policy_input_id,
            "policy_schema": policy.schema,
            "process_policy_sha256": inputs.policy_sha256,
        },
        "module_authority": {
            "trusted_bundle_input_id": trusted_bundle_input_id,
            "authorized_signer_certificate_sha256": [
                signer.certificate_sha256 for signer in lock.authorized_module_signers
            ],
            "module_inventory": module_inventory,
            "firmware_inventory": firmware_inventory,
        },
        "toolchain": [
            {
                "tool_id": tool_id,
                "component": root_inputs[tool_id].component,
                "resolved_path_sha256": root_inputs[tool_id].sha256,
            }
            for tool_id in lock.tool_ids
        ],
        "sbom": {
            "filename": "appliance.spdx.json",
            "sha256": hashlib.sha256(spdx_bytes).hexdigest(),
            "spdx_version": "SPDX-2.3",
            "document_spdx_id": "SPDXRef-DOCUMENT",
        },
        "provenance": _binding(inputs),
    }
    return canonical_dumps(raw)


def _base_image_record(lock: Lock) -> dict:
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


def _input_projection(lock_input) -> dict:
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
            for placement in sorted(lock_input.placements, key=lambda placement: (placement.image, placement.path))
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
    records.sort(key=lambda item: item["path"])
    if len({item["path"] for item in records}) != len(records):
        raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "manifest inventory path collides")
    return records


def _bindings_for_image(policy: Policy, image_id: str) -> dict[str, list[str]]:
    categories: dict[str, list[str]] = {name: [] for name in BINDING_CATEGORIES}
    image_policy = policy.images.get(image_id)
    if image_policy is None:
        return categories
    for node in image_policy.nodes:
        if node.node_type == "file" and node.content_class is not None:
            categories[_BINDING_CONTENT_CLASS_TO_CATEGORY[node.content_class]].append(node.path)
    for paths in categories.values():
        paths.sort()
    return categories


def _binding(inputs: conf_proc_provenance_v2.ProvenanceInputs) -> dict:
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


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA_KEYS


def _observation_path(value: object) -> bool:
    return type(value) is str and value.startswith("/") and "\x00" not in value
