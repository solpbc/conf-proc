#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent semantic KAT for the dormant provenance-v2 producer."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_provenance_v2_build_manifest as producer  # noqa: E402


_MANIFEST_SHA256 = "673bd9159bc90274486a05ed80efa7b085b6cd5778cb64ba92659cb3699291e4"
_SPDX_SHA256 = "64312bccd907873fe8b8a627618d931ae0bcd38f8ccd8fd392f4e39793738cc7"
_SIGNER = format(401, "064x")
_IMAGE_IDS = ("models", "runtime-policy")
_REFERENCE_TYPES = (
    "conf-proc-artifact-input",
    "conf-proc-builder-source",
    "conf-proc-execution-provenance",
    "conf-proc-policy",
    "conf-proc-runtime-closure",
    "conf-proc-tcb-identity",
    "conf-proc-verity-rules",
)
_PURPOSES = {
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
_RUNTIME_DEPENDENCIES = {
    "sglang_image",
    "inference_model",
    "asr_model",
    "gateway_dependency_lock",
    "asr_dependency_lock",
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _load(data: bytes) -> object:
    return json.loads(data.decode("utf-8"))


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha(value: int) -> str:
    return format(value, "064x")


def _derived_uuid(domain: bytes, artifact_digest: bytes, image_id: str | None = None) -> str:
    preimage = domain + (b"" if image_id is None else image_id.encode("ascii")) + artifact_digest
    value = bytearray(hashlib.sha256(preimage).digest()[:16])
    value[6] = (value[6] & 0x0F) | 0x50
    value[8] = (value[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(value)))


def _epoch(artifact_digest: bytes) -> int:
    start = 946684800
    end = 4102444799
    offset = int.from_bytes(hashlib.sha256(b"conf-proc/build-clock/v1" + artifact_digest).digest()[:8], "big")
    return start + offset % (end - start)


def _sanitize(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]", "-", value)


def _placement(input_id: str, image: str, path: str, node_type: str = "file", target: str | None = None) -> dict:
    return {
        "image": image,
        "path": path,
        "node_type": node_type,
        "mode": 0o755 if node_type == "directory" else 0o644,
        "uid": 0,
        "gid": 0,
        "xattrs": [],
        "source_input_id": input_id if node_type == "file" else None,
        "target": target,
    }


def _lock_input(
    input_id: str,
    role: str,
    digest: str,
    size: int,
    placements: list[dict],
    *,
    component: str | None = None,
    identity: str | None = None,
) -> dict:
    return {
        "id": input_id,
        "role": role,
        "component": component or input_id,
        "sha256": digest,
        "size_bytes": size,
        "source_local_path": f"fixture/{input_id}",
        "source_retrieval_scheme": "local-fixture",
        "source_retrieval_identity": identity or f"fixture:{input_id}",
        "source_retrieval_immutable_ref": f"sha256:{digest}",
        "derivation_kind": "fixture",
        "derivation_recipe_id": "fixture-recipe-v1",
        "derivation_parent_ids": [],
        "derivation_parameters_sha256": _sha(800),
        "placements": sorted(placements, key=lambda item: (item["image"], item["path"])),
    }


def _policy() -> dict:
    def node(path: str, node_type: str, content_class: str | None, source: str | None, target: str | None = None) -> dict:
        return {
            "path": path,
            "node_type": node_type,
            "mode": 0o755 if node_type == "directory" else 0o644,
            "uid": 0,
            "gid": 0,
            "xattrs": [],
            "source_input_id": source,
            "target": target,
            "content_class": content_class,
        }

    models = [
        node("/models/model.bin", "file", "model", "model"),
        node("/models/model.link", "symlink", None, None, "/models/model.bin"),
        node("/models/objects", "directory", None, None),
    ]
    runtime = [
        node("/etc/spp/policy.json", "file", "config", "policy"),
        node("/usr/bin/runtime", "file", "executable", "sglang_image"),
        node("/var/lib/fixture.data", "file", "runtime_data", "gateway_lock"),
    ]
    return {
        "schema": "conf-proc-policy/v1",
        "policy_version": 1,
        "images": {
            "models": {"nodes": sorted(models, key=lambda item: item["path"])},
            "runtime-policy": {"nodes": sorted(runtime, key=lambda item: item["path"])},
        },
        "boot_roots": [],
        "process_nodes": [],
        "process_edges": [],
        "mounts": [],
        "network_policy": {},
        "capability_policy": {},
    }


def _verity_rules() -> dict:
    return {
        "schema": "conf-proc-verity-rules/v1",
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


def _fixture() -> dict:
    builder_bytes = b"independent-vpe-builder-fixture"
    policy = _policy()
    policy_bytes = _canonical(policy)
    builder_digest = _digest(builder_bytes)
    policy_digest = _digest(policy_bytes)
    input_specs = (
        ("asr_lock", "asr_dependency_lock", _sha(11), [_placement("asr_lock", "runtime-policy", "/opt/asr/requirements.lock")], None),
        ("asr_model", "asr_model", _sha(12), [_placement("asr_model", "models", "/models/asr.bin")], None),
        ("builder", "conf_proc_source", builder_digest, [_placement("builder", "runtime-policy", "/opt/conf-proc/main.py")], "conf-proc-source"),
        ("bundle", "kernel_trusted_cert_bundle", _sha(14), [], None),
        ("driver", "nvidia_cc_driver", _sha(15), [_placement("driver", "runtime-policy", "/usr/lib/modules/fixture.ko")], None),
        ("firmware", "nvidia_cc_firmware", _sha(16), [_placement("firmware", "runtime-policy", "/usr/lib/firmware/fixture.bin")], None),
        ("gateway_lock", "gateway_dependency_lock", _sha(17), [_placement("gateway_lock", "runtime-policy", "/opt/gateway/requirements.lock")], None),
        ("kernel", "kernel", _sha(18), [_placement("kernel", "runtime-policy", "/boot/vmlinuz")], None),
        ("model", "inference_model", _sha(19), [_placement("model", "models", "/models/model.bin")], None),
        ("models_tree", "models_tree_input", _sha(20), [_placement("models_tree", "models", "/models/config.json")], None),
        ("policy", "policy_tree_input", policy_digest, [_placement("policy", "runtime-policy", "/etc/spp/policy.json")], "process-policy"),
        ("runtime_tree", "runtime_tree_input", _sha(24), [_placement("runtime_tree", "runtime-policy", "/opt/runtime/tree.dat")], None),
        ("sglang_image", "sglang_image", _sha(21), [_placement("sglang_image", "runtime-policy", "/usr/bin/runtime")], None),
        ("stub", "final_systemd_stub", _sha(22), [_placement("stub", "runtime-policy", "/usr/lib/systemd/boot/efi/linuxx64.efi.stub")], None),
        (
            "unit",
            "final_systemd_unit",
            _sha(23),
            [
                _placement("unit", "runtime-policy", "/etc/systemd/system/fixture.service"),
                _placement("unit", "runtime-policy", "/opt/fixture", "directory"),
                _placement("unit", "runtime-policy", "/opt/fixture/unit-link", "symlink", "/etc/systemd/system/fixture.service"),
            ],
            None,
        ),
    )
    inputs = []
    for input_id, role, digest, placements, component in input_specs:
        identity = "fixture:owner-journal-203.0.113.7" if input_id == "kernel" else None
        size = len(builder_bytes) if input_id == "builder" else len(policy_bytes) if input_id == "policy" else 1
        inputs.append(_lock_input(input_id, role, digest, size, placements, component=component, identity=identity))
    for index, component in enumerate(("mksquashfs", "openssl", "unsquashfs", "veritysetup"), start=30):
        input_id = f"tool_{component}"
        inputs.append(_lock_input(input_id, "build_tool", _sha(index), 1, [], component=component))
    inputs.sort(key=lambda item: item["id"])
    root_lock = {
        "schema": "conf-proc-lock/v1",
        "lock_version": 1,
        "base_image_record": {
            "kind": "vhd",
            "provider": "fixture",
            "identity_namespace": "fixture",
            "identity_name": "base",
            "identity_immutable_revision": "fixture-revision",
            "content_sha256": _sha(60),
            "content_size_bytes": 8192,
            "content_media_type": "application/octet-stream",
            "availability": "record-only",
            "recorded_retrieval_scheme": "local-fixture",
            "recorded_retrieval_identity": "fixture:base",
            "recorded_retrieval_immutable_ref": "fixture:base-revision",
        },
        "future_cmdline": "console=ttyS0 ro rd.verity=1",
        "inputs": inputs,
        "authorized_module_signers": [
            {
                "certificate_sha256": _SIGNER,
                "spki_sha256": _sha(402),
                "subject_sha256": _sha(403),
                "usage": "kernel-module-signing",
            }
        ],
        "image_specs": {"models": {}, "runtime-policy": {}},
        "policy_input_id": "policy",
        "tool_ids": sorted(f"tool_{name}" for name in ("mksquashfs", "openssl", "unsquashfs", "veritysetup")),
    }
    closure = {
        "schema": "conf-proc-runtime-closure/v1",
        "status": "declared_unverified",
        "entries": [
            {
                "path": "/opt/conf-proc/main.py",
                "node_type": "file",
                "mode": 0o644,
                "uid": 0,
                "gid": 0,
                "size_bytes": len(builder_bytes),
                "sha256": builder_digest,
                "symlink_target": None,
                "hardlink_group": None,
                "xattrs": [],
                "capabilities": [],
                "logical_role": "conf_proc_source",
                "provenance": {
                    "scheme": "local-fixture",
                    "identity": "fixture:builder",
                    "immutable_ref": f"sha256:{builder_digest}",
                },
                "root_lock_input_id": "builder",
            }
        ],
    }
    executable = lambda name, digest: {
        "logical_name": name,
        "sha256": digest,
        "linkage": "static",
        "interpreter_sha256": None,
        "loader_sha256": None,
        "library_sha256s": [],
    }
    tcb = {
        "schema": "conf-proc-pre-sandbox-tcb/v1",
        "status": "declared_unverified",
        "caller": executable("caller", _sha(70)),
        "launcher": executable("launcher", _sha(71)),
        "sandbox": {"backend": "bubblewrap", "executable": executable("bwrap", _sha(72)), "helper": None},
        "kernel_feature_contract": {"schema": "conf-proc-kernel-features/v1", "sha256": _sha(73)},
    }
    return {
        "root_lock": root_lock,
        "policy": policy,
        "root_lock_bytes": _canonical(root_lock),
        "runtime_closure_bytes": _canonical(closure),
        "verity_rules_bytes": _canonical(_verity_rules()),
        "tcb_identity_bytes": _canonical(tcb),
        "builder_source_bytes": builder_bytes,
        "policy_bytes": policy_bytes,
        "images": [
            {"image_id": "models", "squashfs_sha256": _sha(501), "squashfs_size_bytes": 8192, "hash_device_sha256": _sha(502), "hash_device_size_bytes": 4096, "root_hash": _sha(503)},
            {"image_id": "runtime-policy", "squashfs_sha256": _sha(504), "squashfs_size_bytes": 12288, "hash_device_sha256": _sha(505), "hash_device_size_bytes": 4096, "root_hash": _sha(506)},
        ],
        "modules": [{"path": "/usr/lib/modules/fixture.ko", "sha256": _sha(15), "signer_certificate_sha256": _SIGNER}],
        "firmware": [{"path": "/usr/lib/firmware/fixture.bin", "sha256": _sha(16)}],
    }


def _identities(fixture: dict) -> dict[str, str]:
    values = {
        "artifact_input_sha256": _digest(fixture["root_lock_bytes"]),
        "runtime_closure_sha256": _digest(fixture["runtime_closure_bytes"]),
        "verity_rules_sha256": _digest(fixture["verity_rules_bytes"]),
        "tcb_identity_sha256": _digest(fixture["tcb_identity_bytes"]),
        "builder_source_sha256": _digest(fixture["builder_source_bytes"]),
        "policy_sha256": _digest(fixture["policy_bytes"]),
    }
    binding = {"schema": "conf-proc-execution-provenance/v1", **values}
    values["execution_provenance_sha256"] = _digest(_canonical(binding))
    return values


def _expected_spdx(fixture: dict, identities: dict[str, str]) -> dict:
    appliance_id = "SPDXRef-Package-appliance"
    references_by_type = {
        "conf-proc-artifact-input": identities["artifact_input_sha256"],
        "conf-proc-builder-source": identities["builder_source_sha256"],
        "conf-proc-execution-provenance": identities["execution_provenance_sha256"],
        "conf-proc-policy": identities["policy_sha256"],
        "conf-proc-runtime-closure": identities["runtime_closure_sha256"],
        "conf-proc-tcb-identity": identities["tcb_identity_sha256"],
        "conf-proc-verity-rules": identities["verity_rules_sha256"],
    }
    packages = [
        {
            "SPDXID": appliance_id,
            "name": "conf-proc-appliance",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
            "originator": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": identities["artifact_input_sha256"]}],
            "primaryPackagePurpose": "APPLICATION",
            "externalRefs": [
                {"referenceCategory": "OTHER", "referenceType": name, "referenceLocator": f"sha256:{references_by_type[name]}"}
                for name in _REFERENCE_TYPES
            ],
        }
    ]
    files = []
    relationships = []
    for item in fixture["root_lock"]["inputs"]:
        package_id = f"SPDXRef-Package-{_sanitize(item['id'])}"
        packages.append(
            {
                "SPDXID": package_id,
                "name": item["component"],
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "supplier": "NOASSERTION",
                "originator": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": item["sha256"]}],
                "primaryPackagePurpose": _PURPOSES[item["role"]],
            }
        )
        relationship_type = "BUILD_TOOL_OF" if item["role"] == "build_tool" else "RUNTIME_DEPENDENCY_OF" if item["role"] in _RUNTIME_DEPENDENCIES else "CONTAINS"
        relationships.append({"spdxElementId": package_id, "relationshipType": relationship_type, "relatedSpdxElement": appliance_id})
        for placement in item["placements"]:
            if placement["node_type"] == "directory":
                continue
            file_id = f"SPDXRef-File-{_sanitize(placement['image'])}-{_sanitize(placement['path'])}"
            file_name = f"{placement['image']}{placement['path']}"
            checksum = item["sha256"]
            if placement["node_type"] == "symlink":
                checksum = _digest(b"conf-proc/spdx-symlink-checksum/v1" + placement["target"].encode("utf-8"))
            files.append({"SPDXID": file_id, "fileName": file_name, "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}]})
            relationships.extend(
                (
                    {"spdxElementId": appliance_id, "relationshipType": "CONTAINS", "relatedSpdxElement": file_id},
                    {"spdxElementId": file_id, "relationshipType": "GENERATED_FROM", "relatedSpdxElement": package_id},
                )
            )
    artifact_digest = bytes.fromhex(identities["artifact_input_sha256"])
    created = datetime.fromtimestamp(_epoch(artifact_digest), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"conf-proc-appliance-{identities['artifact_input_sha256'][:16]}",
        "documentNamespace": "urn:uuid:" + _derived_uuid(b"conf-proc/spdx-document-namespace/v1", artifact_digest),
        "creationInfo": {"created": created, "creators": ["Tool: conf-proc-sbom-v1"]},
        "packages": sorted(packages, key=lambda item: item["SPDXID"]),
        "files": sorted(files, key=lambda item: item["fileName"]),
        "relationships": sorted(relationships, key=lambda item: (item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"])),
        "documentDescribes": [appliance_id],
    }


def _expected_manifest(fixture: dict, identities: dict[str, str], spdx: dict) -> dict:
    root = fixture["root_lock"]
    artifact_digest = bytes.fromhex(identities["artifact_input_sha256"])
    images = {}
    for record in fixture["images"]:
        image_id = record["image_id"]
        images[image_id] = {
            **{key: value for key, value in record.items() if key != "image_id"},
            "data_block_size": 4096,
            "hash_block_size": 4096,
            "hash_algorithm": "sha256",
            "salt": _digest(b"conf-proc/verity-salt/v1" + image_id.encode("ascii") + artifact_digest),
            "uuid": _derived_uuid(b"conf-proc/verity-uuid/v1", artifact_digest, image_id),
        }
    input_keys = (
        "id", "role", "sha256", "size_bytes", "source_retrieval_scheme", "source_retrieval_identity",
        "source_retrieval_immutable_ref", "derivation_kind", "derivation_recipe_id", "derivation_parent_ids",
        "derivation_parameters_sha256", "placements",
    )
    projected_inputs = [{key: copy.deepcopy(item[key]) for key in input_keys} for item in root["inputs"]]
    inventory = {image_id: [] for image_id in _IMAGE_IDS}
    for item in root["inputs"]:
        for placement in item["placements"]:
            inventory[placement["image"]].append(
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
    for records in inventory.values():
        records.sort(key=lambda item: item["path"])
    category = {"executable": "executables", "config": "configs", "model": "models", "runtime_data": "runtime_inputs"}
    bindings = {}
    for image_id in _IMAGE_IDS:
        values = {name: [] for name in ("executables", "configs", "models", "runtime_inputs")}
        for node in fixture["policy"]["images"][image_id]["nodes"]:
            if node["node_type"] == "file" and node["content_class"] is not None:
                values[category[node["content_class"]]].append(node["path"])
        bindings[image_id] = values
    root_by_id = {item["id"]: item for item in root["inputs"]}
    spdx_bytes = _canonical(spdx)
    return {
        "schema": "conf-proc-appliance-manifest/v2",
        "manifest_version": 2,
        "lock_schema": root["schema"],
        "lock_sha256": identities["artifact_input_sha256"],
        "reproducibility": {"build_epoch": _epoch(artifact_digest), "sort_order": "byte-wise-path", "codec": "conf-proc-canonical-json/v1"},
        "base_image_record": copy.deepcopy(root["base_image_record"]),
        "future_cmdline": root["future_cmdline"],
        "images": images,
        "inputs": projected_inputs,
        "inventory": inventory,
        "bindings": bindings,
        "policy": {"policy_input_id": root["policy_input_id"], "policy_schema": fixture["policy"]["schema"], "process_policy_sha256": identities["policy_sha256"]},
        "module_authority": {
            "trusted_bundle_input_id": "bundle",
            "authorized_signer_certificate_sha256": [_SIGNER],
            "module_inventory": copy.deepcopy(fixture["modules"]),
            "firmware_inventory": copy.deepcopy(fixture["firmware"]),
        },
        "toolchain": [
            {"tool_id": tool_id, "component": root_by_id[tool_id]["component"], "resolved_path_sha256": root_by_id[tool_id]["sha256"]}
            for tool_id in root["tool_ids"]
        ],
        "sbom": {"filename": "appliance.spdx.json", "sha256": _digest(spdx_bytes), "spdx_version": "SPDX-2.3", "document_spdx_id": "SPDXRef-DOCUMENT"},
        "provenance": {
            "schema": "conf-proc-execution-provenance-binding/v1",
            "artifact_input_sha256": identities["artifact_input_sha256"],
            "execution_provenance_sha256": identities["execution_provenance_sha256"],
            "runtime_closure": {"sha256": identities["runtime_closure_sha256"], "status": "declared_unverified"},
            "verity_rules_sha256": identities["verity_rules_sha256"],
            "tcb_identity": {"sha256": identities["tcb_identity_sha256"], "status": "declared_unverified"},
            "builder_source_sha256": identities["builder_source_sha256"],
            "policy_sha256": identities["policy_sha256"],
        },
    }


def _call_producer(fixture: dict, *, modules: list[dict] | None = None, firmware: list[dict] | None = None):
    return producer.produce_provenance_v2(
        root_lock_bytes=fixture["root_lock_bytes"],
        runtime_closure_bytes=fixture["runtime_closure_bytes"],
        verity_rules_bytes=fixture["verity_rules_bytes"],
        tcb_identity_bytes=fixture["tcb_identity_bytes"],
        builder_source_bytes=fixture["builder_source_bytes"],
        policy_bytes=fixture["policy_bytes"],
        images=tuple(producer.ProvenanceV2ImageRecord(**item) for item in fixture["images"]),
        module_observations=tuple(producer.ProvenanceV2ModuleObservation(**item) for item in (fixture["modules"] if modules is None else modules)),
        firmware_observations=tuple(producer.ProvenanceV2FirmwareObservation(**item) for item in (fixture["firmware"] if firmware is None else firmware)),
    )


def _semantic_verify(manifest: dict, spdx: dict, expected_manifest: dict, expected_spdx: dict) -> None:
    if spdx != expected_spdx:
        raise AssertionError("SPDX semantics differ from the independent expectation")
    if manifest != expected_manifest:
        raise AssertionError("manifest semantics differ from the independent expectation")


def _adapter_result(fixture: dict, manifest: dict, spdx: dict) -> tuple[int, dict]:
    payloads = {
        "root-lock.json": fixture["root_lock_bytes"],
        "runtime-closure.json": fixture["runtime_closure_bytes"],
        "verity-rules.json": fixture["verity_rules_bytes"],
        "tcb-identity.json": fixture["tcb_identity_bytes"],
        "builder-source.py": fixture["builder_source_bytes"],
        "policy.json": fixture["policy_bytes"],
        "manifest.json": _canonical(manifest),
        "sbom.json": _canonical(spdx),
    }
    with tempfile.TemporaryDirectory(prefix="conf-proc-provenance-kat-") as base:
        base_path = Path(base)
        for name, data in payloads.items():
            (base_path / name).write_bytes(data)
        command = [
            sys.executable,
            str(ROOT / "conf_proc_inspect_provenance_cli.py"),
            "--root-lock", str(base_path / "root-lock.json"),
            "--runtime-closure", str(base_path / "runtime-closure.json"),
            "--verity-rules", str(base_path / "verity-rules.json"),
            "--tcb-identity", str(base_path / "tcb-identity.json"),
            "--builder-source", str(base_path / "builder-source.py"),
            "--policy", str(base_path / "policy.json"),
            "--manifest", str(base_path / "manifest.json"),
            "--sbom", str(base_path / "sbom.json"),
        ]
        completed = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, timeout=30)
    return completed.returncode, json.loads(completed.stdout.decode("utf-8"))


class ProvenanceV2ProducerKatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = _fixture()
        cls.identities = _identities(cls.fixture)
        cls.expected_spdx = _expected_spdx(cls.fixture, cls.identities)
        cls.expected_manifest = _expected_manifest(cls.fixture, cls.identities, cls.expected_spdx)
        cls.artifacts = _call_producer(cls.fixture)
        cls.actual_manifest = _load(cls.artifacts.manifest_bytes)
        cls.actual_spdx = _load(cls.artifacts.spdx_bytes)

    def assert_reason(self, callback, reason_code: str) -> None:
        with self.assertRaises(Exception) as context:
            callback()
        self.assertEqual(getattr(context.exception, "reason_code", None), reason_code)

    def assert_adapter_rejects(self, manifest: dict, spdx: dict) -> None:
        return_code, result = _adapter_result(self.fixture, manifest, spdx)
        self.assertNotEqual(return_code, 0)
        self.assertEqual(result.get("reason_code"), "CP_PROVENANCE_BINDING")

    def test_exact_semantics_precede_and_support_pinned_bytes(self) -> None:
        _semantic_verify(self.actual_manifest, self.actual_spdx, self.expected_manifest, self.expected_spdx)
        self.assertEqual(_digest(self.artifacts.manifest_bytes), _MANIFEST_SHA256)
        self.assertEqual(_digest(self.artifacts.spdx_bytes), _SPDX_SHA256)

    def test_pinned_adapter_accepts_exact_candidate(self) -> None:
        return_code, result = _adapter_result(self.fixture, self.actual_manifest, self.actual_spdx)
        self.assertEqual((return_code, result.get("accepted")), (0, True))
        self.assertEqual(result["artifact_input_sha256"], self.identities["artifact_input_sha256"])
        self.assertEqual(result["execution_provenance_sha256"], self.identities["execution_provenance_sha256"])

    def test_output_is_stable_across_cwd_locale_timezone_and_umask(self) -> None:
        original_cwd = Path.cwd()
        original_environment = {name: os.environ.get(name) for name in ("LANG", "LC_ALL", "TZ")}
        original_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory(prefix="conf-proc-provenance-context-") as base:
                os.chdir(base)
                os.environ.update({"LANG": "C", "LC_ALL": "C", "TZ": "Pacific/Kiritimati"})
                time.tzset()
                repeated = _call_producer(self.fixture)
        finally:
            os.chdir(original_cwd)
            os.umask(original_umask)
            for name, value in original_environment.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
            time.tzset()
        self.assertEqual(repeated, self.artifacts)

    def test_each_manifest_provenance_binding_is_independently_rejected(self) -> None:
        paths = (
            ("artifact_input_sha256",),
            ("execution_provenance_sha256",),
            ("runtime_closure", "sha256"),
            ("verity_rules_sha256",),
            ("tcb_identity", "sha256"),
            ("builder_source_sha256",),
            ("policy_sha256",),
        )
        for path in paths:
            with self.subTest(path=path):
                manifest = copy.deepcopy(self.actual_manifest)
                target = manifest["provenance"]
                for name in path[:-1]:
                    target = target[name]
                target[path[-1]] = _sha(999)
                self.assert_adapter_rejects(manifest, self.actual_spdx)

    def test_each_spdx_reference_is_independently_rejected(self) -> None:
        for reference_type in _REFERENCE_TYPES:
            with self.subTest(reference_type=reference_type):
                spdx = copy.deepcopy(self.actual_spdx)
                appliance = next(item for item in spdx["packages"] if item["SPDXID"] == "SPDXRef-Package-appliance")
                next(item for item in appliance["externalRefs"] if item["referenceType"] == reference_type)["referenceLocator"] = f"sha256:{_sha(999)}"
                manifest = copy.deepcopy(self.actual_manifest)
                manifest["sbom"]["sha256"] = _digest(_canonical(spdx))
                self.assert_adapter_rejects(manifest, spdx)

    def test_coherent_artifact_execution_identity_swap_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.actual_manifest)
        spdx = copy.deepcopy(self.actual_spdx)
        artifact = self.identities["artifact_input_sha256"]
        execution = self.identities["execution_provenance_sha256"]
        manifest["lock_sha256"] = execution
        manifest["provenance"]["artifact_input_sha256"] = execution
        manifest["provenance"]["execution_provenance_sha256"] = artifact
        execution_bytes = bytes.fromhex(execution)
        manifest["reproducibility"]["build_epoch"] = _epoch(execution_bytes)
        for image_id, image in manifest["images"].items():
            image["salt"] = _digest(b"conf-proc/verity-salt/v1" + image_id.encode("ascii") + execution_bytes)
            image["uuid"] = _derived_uuid(b"conf-proc/verity-uuid/v1", execution_bytes, image_id)
        appliance = next(item for item in spdx["packages"] if item["SPDXID"] == "SPDXRef-Package-appliance")
        appliance["checksums"][0]["checksumValue"] = execution
        references = {item["referenceType"]: item for item in appliance["externalRefs"]}
        references["conf-proc-artifact-input"]["referenceLocator"] = f"sha256:{execution}"
        references["conf-proc-execution-provenance"]["referenceLocator"] = f"sha256:{artifact}"
        spdx["name"] = f"conf-proc-appliance-{execution[:16]}"
        spdx["documentNamespace"] = "urn:uuid:" + _derived_uuid(b"conf-proc/spdx-document-namespace/v1", execution_bytes)
        spdx["creationInfo"]["created"] = datetime.fromtimestamp(_epoch(execution_bytes), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        manifest["sbom"]["sha256"] = _digest(_canonical(spdx))
        self.assert_adapter_rejects(manifest, spdx)

    def test_semantic_deletions_are_caught_and_adapter_limit_is_recorded(self) -> None:
        mutations = {}
        spdx = copy.deepcopy(self.actual_spdx)
        removed_package = next(item for item in spdx["packages"] if item["SPDXID"] != "SPDXRef-Package-appliance")
        spdx["packages"].remove(removed_package)
        spdx["relationships"] = [item for item in spdx["relationships"] if removed_package["SPDXID"] not in (item["spdxElementId"], item["relatedSpdxElement"])]
        mutations["package"] = (copy.deepcopy(self.actual_manifest), spdx)
        spdx = copy.deepcopy(self.actual_spdx)
        removed_file = spdx["files"].pop(0)
        spdx["relationships"] = [item for item in spdx["relationships"] if removed_file["SPDXID"] not in (item["spdxElementId"], item["relatedSpdxElement"])]
        mutations["file"] = (copy.deepcopy(self.actual_manifest), spdx)
        spdx = copy.deepcopy(self.actual_spdx)
        spdx["relationships"].pop(0)
        mutations["relationship"] = (copy.deepcopy(self.actual_manifest), spdx)
        manifest = copy.deepcopy(self.actual_manifest)
        manifest["module_authority"]["module_inventory"].pop()
        mutations["module_inventory"] = (manifest, copy.deepcopy(self.actual_spdx))
        manifest = copy.deepcopy(self.actual_manifest)
        manifest["module_authority"]["firmware_inventory"].pop()
        mutations["firmware_inventory"] = (manifest, copy.deepcopy(self.actual_spdx))
        manifest = copy.deepcopy(self.actual_manifest)
        manifest["inputs"].pop(0)
        mutations["root_duplicate"] = (manifest, copy.deepcopy(self.actual_spdx))
        expected_adapter_rejection = {
            "package": False,
            "file": False,
            "relationship": False,
            "module_inventory": False,
            "firmware_inventory": False,
            "root_duplicate": True,
        }
        for name, (manifest, spdx) in mutations.items():
            with self.subTest(name=name):
                manifest["sbom"]["sha256"] = _digest(_canonical(spdx))
                with self.assertRaises(AssertionError):
                    _semantic_verify(manifest, spdx, self.expected_manifest, self.expected_spdx)
                return_code, result = _adapter_result(self.fixture, manifest, spdx)
                self.assertEqual(return_code != 0, expected_adapter_rejection[name], result)

    def test_module_and_firmware_observation_denominators_are_exact(self) -> None:
        module = self.fixture["modules"][0]
        firmware = self.fixture["firmware"][0]
        module_cases = (
            [],
            [module, {"path": "/usr/lib/modules/extra.ko", "sha256": _sha(90), "signer_certificate_sha256": _SIGNER}],
            [{**module, "path": "/usr/lib/modules/renamed.ko"}],
            [{**module, "sha256": _sha(90)}],
        )
        firmware_cases = (
            [],
            [firmware, {"path": "/usr/lib/firmware/extra.bin", "sha256": _sha(91)}],
            [{**firmware, "path": "/usr/lib/firmware/renamed.bin"}],
            [{**firmware, "sha256": _sha(91)}],
        )
        for observations in module_cases:
            with self.subTest(kind="module", observations=observations):
                self.assert_reason(lambda observations=observations: _call_producer(self.fixture, modules=observations), "CP_PROVENANCE_V2_MANIFEST_PRODUCTION")
        for observations in firmware_cases:
            with self.subTest(kind="firmware", observations=observations):
                self.assert_reason(lambda observations=observations: _call_producer(self.fixture, firmware=observations), "CP_PROVENANCE_V2_MANIFEST_PRODUCTION")
        unauthorized = [{**module, "signer_certificate_sha256": _sha(999)}]
        self.assert_reason(lambda: _call_producer(self.fixture, modules=unauthorized), "CP_MODULE_SIGNER")


if __name__ == "__main__":
    unittest.main(verbosity=2)
