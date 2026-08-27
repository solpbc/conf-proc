#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftests for canonical manifest assembly, schema validation, and the
independent inspector-side diff engine."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_build_manifest as build_manifest  # noqa: E402
import conf_proc_inspect_manifest as inspect_manifest  # noqa: E402
import conf_proc_json as cj  # noqa: E402
import conf_proc_manifest as manifest_schema  # noqa: E402
from conf_proc_build_images import ImageArtifact  # noqa: E402
from conf_proc_lock import BaseImageRecord, Lock, LockInput, Placement  # noqa: E402
from conf_proc_policy import ImagePolicy, Policy, TreeNodePolicy  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha(n: int) -> str:
    return format(n, "064x")


def _placement(image, path, node_type, mode, uid, gid, *, source_input_id=None, target=None):
    return Placement(image=image, path=path, node_type=node_type, mode=mode, uid=uid, gid=gid, xattrs=(), source_input_id=source_input_id, target=target)


def _make_lock() -> Lock:
    conf_input = LockInput(
        id="conf-1", role="runtime_tree_input", component="config", sha256=_sha(1), size_bytes=10,
        source_local_path="spp.conf", source_retrieval_scheme="local-fixture", source_retrieval_identity="fixture:conf",
        source_retrieval_immutable_ref="v1", derivation_kind="fixture", derivation_recipe_id="r1",
        derivation_parent_ids=(), derivation_parameters_sha256=_sha(2),
        placements=(_placement("runtime-policy", "/etc/spp.conf", "file", 0o644, 0, 0, source_input_id="conf-1"),),
    )
    dir_input = LockInput(
        id="dirs-1", role="runtime_tree_input", component="dirs", sha256=_sha(3), size_bytes=0,
        source_local_path="spp.conf", source_retrieval_scheme="local-fixture", source_retrieval_identity="fixture:dirs",
        source_retrieval_immutable_ref="v1", derivation_kind="fixture", derivation_recipe_id="r1",
        derivation_parent_ids=(), derivation_parameters_sha256=_sha(2),
        placements=(_placement("runtime-policy", "/etc", "directory", 0o755, 0, 0),),
    )
    base_image_record = BaseImageRecord(
        kind="vhd", provider="fixture", identity_namespace="fixture-ns", identity_name="fixture-image",
        identity_immutable_revision="1.0.0", content_sha256=_sha(4), content_size_bytes=100,
        content_media_type="application/octet-stream", availability="record-only",
        recorded_retrieval_scheme="local-fixture", recorded_retrieval_identity="fixture:base-image",
        recorded_retrieval_immutable_ref="v1",
    )
    return Lock(
        schema="conf-proc-lock/v1", lock_version=1, base_image_record=base_image_record,
        future_cmdline="console=ttyS0", inputs=(conf_input, dir_input), authorized_module_signers=(),
        image_specs={"runtime-policy": {}, "models": {}}, policy_input_id="policy-1", tool_ids=(),
    )


def _make_policy() -> Policy:
    node = TreeNodePolicy(
        path="/etc/spp.conf", node_type="file", mode=0o644, uid=0, gid=0, xattrs=(),
        source_input_id="conf-1", target=None, content_class="config",
    )
    return Policy(
        schema="conf-proc-policy/v1", policy_version=1,
        images={"runtime-policy": ImagePolicy(nodes=(node,)), "models": ImagePolicy(nodes=())},
        boot_roots=(), process_nodes=(), process_edges=(), mounts=(), network_policy={}, capability_policy={},
    )


def _make_images() -> dict[str, ImageArtifact]:
    images = {}
    for index, image_id in enumerate(("runtime-policy", "models")):
        images[image_id] = ImageArtifact(
            image_id=image_id, squashfs_path=f"/tmp/{image_id}.squashfs", squashfs_sha256=_sha(10 + index),
            squashfs_size=4096, hash_device_path=f"/tmp/{image_id}.verity", hash_device_sha256=_sha(20 + index),
            hash_device_size=4096, root_hash=_sha(30 + index), data_block_size=4096, hash_block_size=4096,
            hash_algorithm="sha256", salt=_sha(40 + index), uuid="00000000-0000-5000-8000-000000000000",
            build_epoch=1700000000,
        )
    return images


class ManifestBuildAndCompareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = _make_lock()
        self.policy = _make_policy()
        self.lock_digest = hashlib.sha256(b"fixture-lock-digest").digest()
        self.policy_sha256 = _sha(99)
        self.images = _make_images()
        self.toolchain = [{"tool_id": "tool-mksquashfs", "component": "mksquashfs", "resolved_path_sha256": _sha(50)}]
        self.module_authority = {
            "trusted_bundle_input_id": "n/a",
            "authorized_signer_certificate_sha256": [],
            "module_inventory": [],
            "firmware_inventory": [],
        }
        self.sbom_reference = {"filename": "appliance.spdx.json", "sha256": _sha(60), "spdx_version": "SPDX-2.3", "document_spdx_id": "SPDXRef-DOCUMENT"}

    def _build(self) -> bytes:
        return build_manifest.build_manifest_bytes(
            lock=self.lock, lock_digest=self.lock_digest, policy=self.policy, policy_sha256=self.policy_sha256,
            images=self.images, toolchain=self.toolchain, module_authority=self.module_authority,
            sbom_reference=self.sbom_reference,
        )

    def _rederived_images(self) -> dict[str, dict]:
        return {
            image_id: {
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
            for image_id, artifact in self.images.items()
        }

    def test_build_produces_valid_canonical_manifest(self) -> None:
        data = self._build()
        parsed = manifest_schema.parse_manifest(data)
        self.assertEqual(parsed.raw["schema"], "conf-proc-appliance-manifest/v1")
        # Canonical JSON must round-trip byte-for-byte.
        self.assertEqual(cj.canonical_dumps(cj.canonical_loads(data)), data)

    def test_independent_compare_succeeds_on_genuine_manifest(self) -> None:
        data = self._build()
        parsed = manifest_schema.parse_manifest(data)
        inspect_manifest.compare_manifest(
            parsed, lock=self.lock, lock_digest=self.lock_digest, policy=self.policy,
            policy_sha256=self.policy_sha256, rederived_images=self._rederived_images(), inventories={"runtime-policy": {}, "models": {}},
        )

    def test_reject_tampered_root_hash_field(self) -> None:
        data = self._build()
        raw = json.loads(data)
        raw["images"]["runtime-policy"]["root_hash"] = _sha(999)
        tampered = cj.canonical_dumps(raw)
        parsed = manifest_schema.parse_manifest(tampered)
        with self.assertRaises(ApplianceError) as ctx:
            inspect_manifest.compare_manifest(
                parsed, lock=self.lock, lock_digest=self.lock_digest, policy=self.policy,
                policy_sha256=self.policy_sha256, rederived_images=self._rederived_images(), inventories={"runtime-policy": {}, "models": {}},
            )
        self.assertEqual(ctx.exception.reason_code, "CP_MANIFEST_DIFF")

    def test_reject_coherent_rewrite_of_lock_digest_and_manifest(self) -> None:
        # A "coherent" tamper: the emitted manifest is internally
        # consistent with itself (still schema-valid, still
        # self-referentially plausible) but claims a different lock
        # digest than the caller's own trusted lock. AC7 requires this to
        # still be caught since the inspector trusts its own lock, not the
        # manifest's self-description.
        data = self._build()
        raw = json.loads(data)
        raw["lock_sha256"] = hashlib.sha256(b"a-different-lock-entirely").hexdigest()
        tampered = cj.canonical_dumps(raw)
        parsed = manifest_schema.parse_manifest(tampered)
        with self.assertRaises(ApplianceError) as ctx:
            inspect_manifest.compare_manifest(
                parsed, lock=self.lock, lock_digest=self.lock_digest, policy=self.policy,
                policy_sha256=self.policy_sha256, rederived_images=self._rederived_images(), inventories={"runtime-policy": {}, "models": {}},
            )
        self.assertEqual(ctx.exception.reason_code, "CP_MANIFEST_DIFF")

    def test_reject_extra_undeclared_inventory_path(self) -> None:
        data = self._build()
        raw = json.loads(data)
        raw["inventory"]["runtime-policy"].append(
            {
                "path": "/etc/undeclared-extra",
                "node_type": "file",
                "mode": 0o644,
                "uid": 0,
                "gid": 0,
                "xattrs": [],
                "sha256": _sha(777),
                "size_bytes": 5,
                "symlink_target": None,
                "source_input_id": "conf-1",
            }
        )
        tampered = cj.canonical_dumps(raw)
        parsed = manifest_schema.parse_manifest(tampered)
        with self.assertRaises(ApplianceError) as ctx:
            inspect_manifest.compare_manifest(
                parsed, lock=self.lock, lock_digest=self.lock_digest, policy=self.policy,
                policy_sha256=self.policy_sha256, rederived_images=self._rederived_images(), inventories={"runtime-policy": {}, "models": {}},
            )
        self.assertEqual(ctx.exception.reason_code, "CP_MANIFEST_DIFF")

    def test_reject_unknown_top_level_field(self) -> None:
        data = self._build()
        raw = json.loads(data)
        raw["owner_identity"] = "someone"
        tampered = cj.canonical_dumps(raw)
        with self.assertRaises(ApplianceError) as ctx:
            manifest_schema.parse_manifest(tampered)
        self.assertEqual(ctx.exception.reason_code, "CP_MANIFEST_SCHEMA")

    def test_reject_embedded_ip_address(self) -> None:
        data = self._build()
        raw = json.loads(data)
        raw["future_cmdline"] = "console=ttyS0 ip=10.0.0.5"
        tampered = cj.canonical_dumps(raw)
        with self.assertRaises(ApplianceError) as ctx:
            manifest_schema.parse_manifest(tampered)
        self.assertEqual(ctx.exception.reason_code, "CP_MANIFEST_FORBIDDEN_FIELD")

    def test_reject_embedded_pem_material(self) -> None:
        data = self._build()
        raw = json.loads(data)
        raw["toolchain"][0]["component"] = "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----"
        tampered = cj.canonical_dumps(raw)
        with self.assertRaises(ApplianceError) as ctx:
            manifest_schema.parse_manifest(tampered)
        self.assertEqual(ctx.exception.reason_code, "CP_MANIFEST_FORBIDDEN_FIELD")


if __name__ == "__main__":
    unittest.main(verbosity=2)
