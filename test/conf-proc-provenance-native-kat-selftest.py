#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Pinned native-tool known-answer gate for dormant provenance-v2 argv.

This is deliberately separate from Hopper's pure renderer tests.  It executes
the exact pinned native binaries, checks frozen output bytes, and independently
extracts the filesystem inventory.  Tool absence or byte drift is a hard
failure, never a skip.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_inspect_tree as inspect_tree  # noqa: E402
import conf_proc_provenance_render as renderer  # noqa: E402
import conf_proc_provenance_v2 as provenance  # noqa: E402
from conf_proc_geometry import pad_file_to_block_size  # noqa: E402
from conf_proc_guard import HermeticGuard, ToolDeclaration  # noqa: E402


MKSQUASHFS = "/usr/bin/mksquashfs"
VERITYSETUP = "/usr/sbin/veritysetup"
UNSQUASHFS = "/usr/bin/unsquashfs"

PINNED_TOOL_SHA256 = {
    MKSQUASHFS: "47d5c1af3da11864e64c9dc6bb4e568719dcc315e6a744e79381ce3374fb7393",
    VERITYSETUP: "95659d771286250ebdb04c831c198711bb8f6b5e569a39e88d35b3f619cd4faf",
    UNSQUASHFS: "b305985eb764b6d0ef757571e3e44044ebf71c827c4263efe576e9e14b4abcfb",
}

ARTIFACT_INPUT_SHA256 = "fa7c7bdf2d900a9cf3d83a75bce2a3a8abe3742cff75cf6cd322c271975178d5"
EXPECTED_BUILD_EPOCH = 3157307227

STUB_BYTES = b"#!/bin/sh\necho fixture-systemd-stub\n"
CONF_BYTES = b"fixture configuration\n"
PSEUDO_BYTES = (
    b"/etc m 0755 0 0\n"
    b"/etc/spp.conf m 0644 0 0\n"
    b"/usr m 0755 0 0\n"
    b"/usr/bin m 0755 0 0\n"
    b"/usr/bin/spp-systemd-stub m 0755 0 0\n"
)

EXPECTED = {
    "runtime-policy": {
        "salt": "6264054e5d018c2ac028cb220f426fcc86516e93e6eeecc18ceb8a55aad24cf6",
        "uuid": "140be099-97dd-5845-9c61-6755ce1976b6",
        "squashfs_sha256": "dd3c8464117fbfa574d82eb20e89f5a45fd057893d17d7ce9bb0382ee1227b04",
        "verity_sha256": "9aa87900d94cd1fdfe31bc1a76daee623d4c7982c6b411ce3482e93370bd4646",
        "root_hash": "d540fa9c6c5507d41346d40aa169a56a0d4f05c47a37faf9d18b756661968aef",
    },
    "models": {
        "salt": "653164b98d60decf1523fe68b05b3f3f7cf63593a0834a728800a372fcd37d17",
        "uuid": "a5640a08-4b9c-529b-9591-a86493dc41cd",
        "squashfs_sha256": "dd3c8464117fbfa574d82eb20e89f5a45fd057893d17d7ce9bb0382ee1227b04",
        "verity_sha256": "eeab0cc720b83772bde820c2863694f6f6d59198abdf48c7a3dbd9f6456a3f0f",
        "root_hash": "aaa2d34eaf4e3149b3b7014b1d590f60a395b6bc33ca0d2ba6596710be54badf",
    },
}

_ROOT_HASH_LINE = re.compile(rb"^Root hash:\s+([0-9a-f]{64})$", re.MULTILINE)


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pinned_guard() -> HermeticGuard:
    for path, expected in PINNED_TOOL_SHA256.items():
        if not os.path.isfile(path):
            raise AssertionError(f"required pinned native tool is missing: {path}")
        actual = _sha256_file(path)
        if actual != expected:
            raise AssertionError(f"pinned native tool digest mismatch: {path}: {actual} != {expected}")
    return HermeticGuard(
        allowed_reads=frozenset(PINNED_TOOL_SHA256),
        tools={path: ToolDeclaration(path, digest) for path, digest in PINNED_TOOL_SHA256.items()},
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
        build_epoch=EXPECTED_BUILD_EPOCH,
    )


def _make_tree(base: Path) -> tuple[Path, Path]:
    tree = base / "tree"
    (tree / "usr" / "bin").mkdir(parents=True)
    (tree / "etc").mkdir()
    (tree / "usr" / "bin" / "spp-systemd-stub").write_bytes(STUB_BYTES)
    (tree / "etc" / "spp.conf").write_bytes(CONF_BYTES)
    (tree / "usr" / "bin" / "spp-systemd-stub").chmod(0o755)
    (tree / "etc" / "spp.conf").chmod(0o644)
    for directory in (tree / "etc", tree / "usr", tree / "usr" / "bin"):
        directory.chmod(0o755)
    pseudo = base / "tree.pseudo"
    pseudo.write_bytes(PSEUDO_BYTES)
    return tree, pseudo


def _root_hash(stdout: bytes) -> str:
    match = _ROOT_HASH_LINE.search(stdout)
    if match is None:
        raise AssertionError(f"veritysetup format omitted root hash: {stdout!r}")
    return match.group(1).decode("ascii")


class ProvenanceNativeKatTests(unittest.TestCase):
    def test_pinned_renderer_produces_exact_native_bytes_and_inventory(self) -> None:
        guard = _pinned_guard()
        rules = provenance.supported_verity_rules_bytes()
        with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
            base = Path(temporary)
            tree, pseudo = _make_tree(base)

            for image_id, expected in EXPECTED.items():
                stage = base / image_id
                stage.mkdir()
                squashfs = stage / f"{image_id}.squashfs"
                verity = stage / f"{image_id}.verity"
                build = renderer.render_build_stage(
                    rules,
                    artifact_input_sha256=ARTIFACT_INPUT_SHA256,
                    image_id=image_id,
                    mksquashfs_path=MKSQUASHFS,
                    veritysetup_path=VERITYSETUP,
                    tree_dir=str(tree),
                    squashfs_path=str(squashfs),
                    hash_device_path=str(verity),
                    pseudo_file_path=str(pseudo),
                )
                self.assertEqual(build.build_epoch, EXPECTED_BUILD_EPOCH)
                self.assertEqual(build.salt, expected["salt"])
                self.assertEqual(build.uuid, expected["uuid"])

                guard.run_tool(list(build.mksquashfs_argv), cwd=str(stage))
                pad_file_to_block_size(str(squashfs))
                formatted = guard.run_tool(list(build.veritysetup_format_argv), cwd=str(stage))
                root_hash = _root_hash(formatted.stdout)
                verify = renderer.render_verify_stage(
                    rules,
                    artifact_input_sha256=ARTIFACT_INPUT_SHA256,
                    image_id=image_id,
                    veritysetup_path=VERITYSETUP,
                    squashfs_path=str(squashfs),
                    hash_device_path=str(verity),
                    root_hash=root_hash,
                )
                self.assertEqual(verify.build_epoch, EXPECTED_BUILD_EPOCH)
                self.assertEqual(verify.salt, expected["salt"])
                self.assertEqual(verify.uuid, expected["uuid"])
                guard.run_tool(list(verify.veritysetup_verify_argv), cwd=str(stage))

                self.assertEqual(squashfs.stat().st_size, 4096)
                self.assertEqual(verity.stat().st_size, 4096)
                self.assertEqual(_sha256_file(squashfs), expected["squashfs_sha256"])
                self.assertEqual(_sha256_file(verity), expected["verity_sha256"])
                self.assertEqual(root_hash, expected["root_hash"])

                inventory = inspect_tree.build_inventory(
                    guard,
                    unsquashfs_path=UNSQUASHFS,
                    squashfs_path=str(squashfs),
                    extract_dir=str(stage / "extracted"),
                    work_dir=str(stage),
                )
                self.assertEqual(
                    set(inventory),
                    {"/etc", "/etc/spp.conf", "/usr", "/usr/bin", "/usr/bin/spp-systemd-stub"},
                )
                for path in ("/etc", "/usr", "/usr/bin"):
                    node = inventory[path]
                    self.assertEqual((node.node_type, node.mode, node.uid, node.gid), ("directory", 0o755, 0, 0))
                conf = inventory["/etc/spp.conf"]
                self.assertEqual((conf.node_type, conf.mode, conf.uid, conf.gid), ("file", 0o644, 0, 0))
                self.assertEqual(conf.size, len(CONF_BYTES))
                self.assertEqual(conf.sha256, hashlib.sha256(CONF_BYTES).hexdigest())
                stub = inventory["/usr/bin/spp-systemd-stub"]
                self.assertEqual((stub.node_type, stub.mode, stub.uid, stub.gid), ("file", 0o755, 0, 0))
                self.assertEqual(stub.size, len(STUB_BYTES))
                self.assertEqual(stub.sha256, hashlib.sha256(STUB_BYTES).hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
