#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftests for real squashfs + dm-verity construction and independent
inspector re-derivation. Exercises actual veritysetup/mksquashfs/unsquashfs
binaries -- no fakes, per AC5."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_build_images as build_images  # noqa: E402
import conf_proc_inspect_images as inspect_images  # noqa: E402
from conf_proc_guard import HermeticGuard, ToolDeclaration  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _find_tool(*candidates: str) -> str:
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    raise unittest.SkipTest(f"none of {candidates} present on this host")


MKSQUASHFS = _find_tool("/usr/bin/mksquashfs", "/sbin/mksquashfs")
UNSQUASHFS = _find_tool("/usr/bin/unsquashfs", "/sbin/unsquashfs")
VERITYSETUP = _find_tool("/usr/sbin/veritysetup", "/sbin/veritysetup")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _make_guard(extra_reads: frozenset[str] = frozenset()) -> HermeticGuard:
    tools = {
        MKSQUASHFS: ToolDeclaration(MKSQUASHFS, _sha256_file(MKSQUASHFS)),
        UNSQUASHFS: ToolDeclaration(UNSQUASHFS, _sha256_file(UNSQUASHFS)),
        VERITYSETUP: ToolDeclaration(VERITYSETUP, _sha256_file(VERITYSETUP)),
    }
    return HermeticGuard(
        allowed_reads=frozenset({MKSQUASHFS, UNSQUASHFS, VERITYSETUP}) | extra_reads,
        tools=tools,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"},
        build_epoch=1700000000,
    )


def _make_tree(base: str, variant: str) -> str:
    tree = os.path.join(base, f"tree-{variant}")
    os.makedirs(os.path.join(tree, "usr", "bin"), exist_ok=True)
    os.makedirs(os.path.join(tree, "etc"), exist_ok=True)
    with open(os.path.join(tree, "usr", "bin", "spp-systemd-stub"), "wb") as handle:
        handle.write(b"#!/bin/sh\necho fixture-systemd-stub\n")
    with open(os.path.join(tree, "etc", "spp.conf"), "wb") as handle:
        handle.write(b"fixture configuration\n")
    return tree


def _deterministic_low_compressibility_blob(size: int) -> bytes:
    out = bytearray()
    block = b"conf-proc-fixture-seed"
    while len(out) < size:
        block = hashlib.sha256(block).digest()
        out.extend(block)
    return bytes(out[:size])


def _make_large_tree(base: str, variant: str) -> str:
    tree = _make_tree(base, variant)
    with open(os.path.join(tree, "usr", "bin", "large-model-fixture.bin"), "wb") as handle:
        handle.write(_deterministic_low_compressibility_blob(256 * 1024))
    return tree


class ImageBuildAndInspectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.lock_digest = hashlib.sha256(b"fixture-lock-digest").digest()

    def test_build_and_independent_rederivation_agree(self) -> None:
        tree = _make_tree(self.base, "a")
        guard = _make_guard()
        artifact = build_images.build_image(
            guard,
            mksquashfs_path=MKSQUASHFS,
            veritysetup_path=VERITYSETUP,
            tree_dir=tree,
            image_id="runtime-policy",
            lock_digest=self.lock_digest,
            staging_dir=self.base,
        )
        self.assertEqual(artifact.data_block_size, 4096)
        self.assertEqual(artifact.squashfs_size % 4096, 0)

        rederivation = inspect_images.rederive_verity(
            guard,
            veritysetup_path=VERITYSETUP,
            candidate_squashfs_path=artifact.squashfs_path,
            image_id="runtime-policy",
            lock_digest=self.lock_digest,
            work_dir=self.base,
        )
        self.assertEqual(rederivation.expected_salt, artifact.salt)
        self.assertEqual(rederivation.expected_uuid, artifact.uuid)
        inspect_images.compare_against_candidate(
            rederivation,
            claimed_root_hash=artifact.root_hash,
            candidate_hash_device_path=artifact.hash_device_path,
        )
        inspect_images.verify_candidate_pair(
            guard,
            veritysetup_path=VERITYSETUP,
            candidate_squashfs_path=artifact.squashfs_path,
            candidate_hash_device_path=artifact.hash_device_path,
            claimed_root_hash=artifact.root_hash,
            image_id="runtime-policy",
            work_dir=self.base,
        )

    def test_reproducible_across_different_trees_and_umasks(self) -> None:
        tree_a = _make_tree(self.base, "a")
        tree_b = _make_tree(self.base, "b")
        guard = _make_guard()

        stage_a = os.path.join(self.base, "stage-a")
        stage_b = os.path.join(self.base, "stage-b")
        os.makedirs(stage_a, exist_ok=True)
        os.makedirs(stage_b, exist_ok=True)

        old_umask = os.umask(0o077)
        try:
            artifact_a = build_images.build_image(
                guard,
                mksquashfs_path=MKSQUASHFS,
                veritysetup_path=VERITYSETUP,
                tree_dir=tree_a,
                image_id="models",
                lock_digest=self.lock_digest,
                staging_dir=stage_a,
            )
        finally:
            os.umask(old_umask)

        os.umask(0o022)
        try:
            artifact_b = build_images.build_image(
                guard,
                mksquashfs_path=MKSQUASHFS,
                veritysetup_path=VERITYSETUP,
                tree_dir=tree_b,
                image_id="models",
                lock_digest=self.lock_digest,
                staging_dir=stage_b,
            )
        finally:
            os.umask(old_umask)

        self.assertEqual(artifact_a.squashfs_sha256, artifact_b.squashfs_sha256)
        self.assertEqual(artifact_a.hash_device_sha256, artifact_b.hash_device_sha256)
        self.assertEqual(artifact_a.root_hash, artifact_b.root_hash)

    def test_flipped_data_byte_is_detected(self) -> None:
        tree = _make_tree(self.base, "a")
        guard = _make_guard()
        artifact = build_images.build_image(
            guard,
            mksquashfs_path=MKSQUASHFS,
            veritysetup_path=VERITYSETUP,
            tree_dir=tree,
            image_id="runtime-policy",
            lock_digest=self.lock_digest,
            staging_dir=self.base,
        )
        with open(artifact.squashfs_path, "r+b") as handle:
            handle.seek(0)
            byte = handle.read(1)
            handle.seek(0)
            handle.write(bytes([byte[0] ^ 0xFF]))

        rederivation = inspect_images.rederive_verity(
            guard,
            veritysetup_path=VERITYSETUP,
            candidate_squashfs_path=artifact.squashfs_path,
            image_id="runtime-policy",
            lock_digest=self.lock_digest,
            work_dir=self.base,
        )
        with self.assertRaises(ApplianceError) as ctx:
            inspect_images.compare_against_candidate(
                rederivation,
                claimed_root_hash=artifact.root_hash,
                candidate_hash_device_path=artifact.hash_device_path,
            )
        self.assertEqual(ctx.exception.reason_code, "CP_VERITY_ROOT_MISMATCH")

        with self.assertRaises(ApplianceError) as ctx:
            inspect_images.verify_candidate_pair(
                guard,
                veritysetup_path=VERITYSETUP,
                candidate_squashfs_path=artifact.squashfs_path,
                candidate_hash_device_path=artifact.hash_device_path,
                claimed_root_hash=artifact.root_hash,
                image_id="runtime-policy",
                work_dir=self.base,
            )
        self.assertEqual(ctx.exception.reason_code, "CP_VERITY_VERIFY")

    def test_flipped_hash_tree_byte_is_detected(self) -> None:
        # A tiny image collapses to a single verity data block with no real
        # tree entries beyond the superblock, so trailing bytes are unused
        # padding a flip there would not detect. Use a large, low-
        # compressibility tree so a real multi-block hash tree exists.
        tree = _make_large_tree(self.base, "a")
        guard = _make_guard()
        artifact = build_images.build_image(
            guard,
            mksquashfs_path=MKSQUASHFS,
            veritysetup_path=VERITYSETUP,
            tree_dir=tree,
            image_id="runtime-policy",
            lock_digest=self.lock_digest,
            staging_dir=self.base,
        )
        self.assertGreater(artifact.hash_device_size, 4096, "fixture must produce a real multi-block hash tree")
        with open(artifact.hash_device_path, "r+b") as handle:
            offset = artifact.hash_device_size // 2
            handle.seek(offset)
            byte = handle.read(1)
            handle.seek(offset)
            handle.write(bytes([byte[0] ^ 0xFF]))

        rederivation = inspect_images.rederive_verity(
            guard,
            veritysetup_path=VERITYSETUP,
            candidate_squashfs_path=artifact.squashfs_path,
            image_id="runtime-policy",
            lock_digest=self.lock_digest,
            work_dir=self.base,
        )
        with self.assertRaises(ApplianceError) as ctx:
            inspect_images.compare_against_candidate(
                rederivation,
                claimed_root_hash=artifact.root_hash,
                candidate_hash_device_path=artifact.hash_device_path,
            )
        self.assertEqual(ctx.exception.reason_code, "CP_IMAGE_DIGEST_MISMATCH")

        with self.assertRaises(ApplianceError) as ctx:
            inspect_images.verify_candidate_pair(
                guard,
                veritysetup_path=VERITYSETUP,
                candidate_squashfs_path=artifact.squashfs_path,
                candidate_hash_device_path=artifact.hash_device_path,
                claimed_root_hash=artifact.root_hash,
                image_id="runtime-policy",
                work_dir=self.base,
            )
        self.assertEqual(ctx.exception.reason_code, "CP_VERITY_VERIFY")

    def test_extract_image_recovers_original_content(self) -> None:
        tree = _make_tree(self.base, "a")
        guard = _make_guard()
        artifact = build_images.build_image(
            guard,
            mksquashfs_path=MKSQUASHFS,
            veritysetup_path=VERITYSETUP,
            tree_dir=tree,
            image_id="runtime-policy",
            lock_digest=self.lock_digest,
            staging_dir=self.base,
        )
        dest = os.path.join(self.base, "extracted")
        inspect_images.extract_image(
            guard,
            unsquashfs_path=UNSQUASHFS,
            squashfs_path=artifact.squashfs_path,
            dest_dir=dest,
            work_dir=self.base,
        )
        extracted_conf = Path(dest, "etc", "spp.conf").read_bytes()
        self.assertEqual(extracted_conf, b"fixture configuration\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
