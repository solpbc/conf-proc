#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftests for tree rule predicates and the builder/inspector tree
round trip through real mksquashfs/unsquashfs."""

from __future__ import annotations

import dataclasses
import hashlib
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_build_images as build_images  # noqa: E402
import conf_proc_build_tree as build_tree  # noqa: E402
import conf_proc_inspect_tree as inspect_tree  # noqa: E402
import conf_proc_tree_rules as tree_rules  # noqa: E402
from conf_proc_guard import HermeticGuard, ToolDeclaration  # noqa: E402
from conf_proc_lock import Lock, LockInput, Placement  # noqa: E402
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


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TreeRulesTests(unittest.TestCase):
    def test_classify_regular_directory_symlink(self) -> None:
        self.assertEqual(tree_rules.classify_node_type(stat.S_IFREG | 0o644), tree_rules.NODE_TYPE_FILE)
        self.assertEqual(tree_rules.classify_node_type(stat.S_IFDIR | 0o755), tree_rules.NODE_TYPE_DIRECTORY)
        self.assertEqual(tree_rules.classify_node_type(stat.S_IFLNK | 0o777), tree_rules.NODE_TYPE_SYMLINK)

    def test_reject_device_fifo_socket_nodes(self) -> None:
        for kind_mode in (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
            with self.assertRaises(ApplianceError) as ctx:
                tree_rules.classify_node_type(kind_mode | 0o644)
            self.assertEqual(ctx.exception.reason_code, "CP_TREE_UNSUPPORTED_NODE")

    def test_reject_setuid_setgid(self) -> None:
        for special_bit in (stat.S_ISUID, stat.S_ISGID):
            with self.assertRaises(ApplianceError) as ctx:
                tree_rules.validate_node_metadata(
                    "/usr/bin/x", mode=stat.S_IFREG | 0o755 | special_bit, node_type=tree_rules.NODE_TYPE_FILE, nlink=1
                )
            self.assertEqual(ctx.exception.reason_code, "CP_TREE_METADATA")

    def test_reject_hard_links(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            tree_rules.validate_node_metadata(
                "/usr/bin/x", mode=stat.S_IFREG | 0o644, node_type=tree_rules.NODE_TYPE_FILE, nlink=2
            )
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_UNSUPPORTED_NODE")

    def test_reject_capability_and_undeclared_xattr(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            tree_rules.validate_xattr_names("/usr/bin/x", ["security.capability"])
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_XATTR")
        with self.assertRaises(ApplianceError) as ctx:
            tree_rules.validate_xattr_names("/usr/bin/x", ["user.whatever"])
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_XATTR")
        tree_rules.validate_xattr_names("/usr/bin/x", ["system.posix_acl_access"])

    def test_reject_bad_symlink_targets(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            tree_rules.validate_symlink_target("/usr/bin/x", "")
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_SYMLINK")
        with self.assertRaises(ApplianceError) as ctx:
            tree_rules.validate_symlink_target("/usr/bin/x", "../../etc/passwd")
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_SYMLINK")
        tree_rules.validate_symlink_target("/usr/bin/x", "/usr/bin/y")


def _placement(image, path, node_type, mode, uid, gid, *, source_input_id=None, target=None, xattrs=()):
    return Placement(
        image=image, path=path, node_type=node_type, mode=mode, uid=uid, gid=gid,
        xattrs=tuple(xattrs), source_input_id=source_input_id, target=target,
    )


class TreeBuildAndInspectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.input_root = os.path.join(self.base, "inputs")
        os.makedirs(self.input_root)

        self.stub_bytes = b"#!/bin/sh\necho fixture-systemd-stub\n"
        self.conf_bytes = b"fixture configuration\n"
        with open(os.path.join(self.input_root, "spp-systemd-stub"), "wb") as handle:
            handle.write(self.stub_bytes)
        with open(os.path.join(self.input_root, "spp.conf"), "wb") as handle:
            handle.write(self.conf_bytes)

        stub_input = LockInput(
            id="stub-1", role="final_systemd_stub", component="systemd", sha256=_sha256_bytes(self.stub_bytes),
            size_bytes=len(self.stub_bytes), source_local_path="spp-systemd-stub",
            source_retrieval_scheme="local-fixture", source_retrieval_identity="fixture:stub",
            source_retrieval_immutable_ref="v1", derivation_kind="fixture", derivation_recipe_id="r1",
            derivation_parent_ids=(), derivation_parameters_sha256=_sha256_bytes(b"params"),
            placements=(_placement("runtime-policy", "/usr/bin/spp-systemd-stub", "file", 0o755, 0, 0, source_input_id="stub-1"),),
        )
        conf_input = LockInput(
            id="conf-1", role="runtime_tree_input", component="config", sha256=_sha256_bytes(self.conf_bytes),
            size_bytes=len(self.conf_bytes), source_local_path="spp.conf",
            source_retrieval_scheme="local-fixture", source_retrieval_identity="fixture:conf",
            source_retrieval_immutable_ref="v1", derivation_kind="fixture", derivation_recipe_id="r1",
            derivation_parent_ids=(), derivation_parameters_sha256=_sha256_bytes(b"params"),
            placements=(_placement("runtime-policy", "/etc/spp.conf", "file", 0o644, 0, 0, source_input_id="conf-1"),),
        )
        dirs_input = LockInput(
            id="dirs-1", role="runtime_tree_input", component="dirs", sha256=_sha256_bytes(b"n/a"),
            size_bytes=0, source_local_path="spp.conf",
            source_retrieval_scheme="local-fixture", source_retrieval_identity="fixture:dirs",
            source_retrieval_immutable_ref="v1", derivation_kind="fixture", derivation_recipe_id="r1",
            derivation_parent_ids=(), derivation_parameters_sha256=_sha256_bytes(b"params"),
            placements=(
                _placement("runtime-policy", "/etc", "directory", 0o755, 0, 0),
                _placement("runtime-policy", "/usr", "directory", 0o755, 0, 0),
                _placement("runtime-policy", "/usr/bin", "directory", 0o755, 0, 0),
            ),
        )
        link_input = LockInput(
            id="link-1", role="runtime_tree_input", component="link", sha256=_sha256_bytes(b"n/a"),
            size_bytes=0, source_local_path="spp.conf",
            source_retrieval_scheme="local-fixture", source_retrieval_identity="fixture:link",
            source_retrieval_immutable_ref="v1", derivation_kind="fixture", derivation_recipe_id="r1",
            derivation_parent_ids=(), derivation_parameters_sha256=_sha256_bytes(b"params"),
            placements=(_placement("runtime-policy", "/usr/bin/stub-link", "symlink", 0o777, 0, 0, target="/usr/bin/spp-systemd-stub"),),
        )

        self.lock = Lock(
            schema="conf-proc-lock/v1", lock_version=1, base_image_record=None, future_cmdline="console=ttyS0",
            inputs=(conf_input, dirs_input, link_input, stub_input), authorized_module_signers=(),
            image_specs={"runtime-policy": {}, "models": {}}, policy_input_id="n/a", tool_ids=(),
        )

        self.tools = {
            MKSQUASHFS: ToolDeclaration(MKSQUASHFS, _sha256_file(MKSQUASHFS)),
            UNSQUASHFS: ToolDeclaration(UNSQUASHFS, _sha256_file(UNSQUASHFS)),
            VERITYSETUP: ToolDeclaration(VERITYSETUP, _sha256_file(VERITYSETUP)),
        }
        self.guard = HermeticGuard(
            allowed_reads=frozenset(
                {MKSQUASHFS, UNSQUASHFS, VERITYSETUP, os.path.join(self.input_root, "spp-systemd-stub"), os.path.join(self.input_root, "spp.conf")}
            ),
            tools=self.tools,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"},
            build_epoch=1700000000,
        )
        self.lock_digest = hashlib.sha256(b"fixture-lock-digest").digest()

    def _build_and_inspect(self, lock: Lock) -> dict:
        staging = os.path.join(self.base, "staging")
        pseudo_lines = build_tree.assemble_tree(self.guard, lock, image="runtime-policy", input_root=self.input_root, staging_root=staging)
        pseudo_path = os.path.join(self.base, "pseudo.def")
        with open(pseudo_path, "w") as handle:
            handle.write("\n".join(pseudo_lines) + "\n")

        artifact = build_images.build_image(
            self.guard, mksquashfs_path=MKSQUASHFS, veritysetup_path=VERITYSETUP, tree_dir=staging,
            image_id="runtime-policy", lock_digest=self.lock_digest, staging_dir=self.base, pseudo_file_path=pseudo_path,
        )
        inventory = inspect_tree.build_inventory(
            self.guard, unsquashfs_path=UNSQUASHFS, squashfs_path=artifact.squashfs_path,
            extract_dir=os.path.join(self.base, "extracted"), work_dir=self.base,
        )
        return inventory

    def test_build_and_inspect_agree(self) -> None:
        inventory = self._build_and_inspect(self.lock)
        inspect_tree.compare_against_lock(inventory, self.lock, image="runtime-policy")
        self.assertEqual(inventory["/etc/spp.conf"].sha256, _sha256_bytes(self.conf_bytes))
        self.assertEqual(inventory["/usr/bin/spp-systemd-stub"].mode, 0o755)
        self.assertEqual(inventory["/usr/bin/stub-link"].symlink_target, "/usr/bin/spp-systemd-stub")

    def test_undeclared_path_in_image_is_rejected(self) -> None:
        inventory = self._build_and_inspect(self.lock)
        # Drop a real, present placement from the trusted lock copy used for
        # comparison: the image still contains it, so it becomes "present
        # but undeclared" from the inspector's point of view.
        trimmed_inputs = tuple(inp for inp in self.lock.inputs if inp.id != "conf-1")
        trimmed_lock = dataclasses.replace(self.lock, inputs=trimmed_inputs)
        with self.assertRaises(ApplianceError) as ctx:
            inspect_tree.compare_against_lock(inventory, trimmed_lock, image="runtime-policy")
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_UNEXPECTED")

    def test_missing_declared_path_is_rejected(self) -> None:
        inventory = self._build_and_inspect(self.lock)
        del inventory["/etc/spp.conf"]
        with self.assertRaises(ApplianceError) as ctx:
            inspect_tree.compare_against_lock(inventory, self.lock, image="runtime-policy")
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_MISSING")

    def test_digest_mismatch_is_rejected(self) -> None:
        inventory = self._build_and_inspect(self.lock)
        conf_input = next(inp for inp in self.lock.inputs if inp.id == "conf-1")
        tampered = dataclasses.replace(conf_input, sha256="0" * 64)
        new_inputs = tuple(tampered if inp.id == "conf-1" else inp for inp in self.lock.inputs)
        tampered_lock = dataclasses.replace(self.lock, inputs=new_inputs)
        with self.assertRaises(ApplianceError) as ctx:
            inspect_tree.compare_against_lock(inventory, tampered_lock, image="runtime-policy")
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_SOURCE_BINDING")

    def test_metadata_mismatch_is_rejected(self) -> None:
        inventory = self._build_and_inspect(self.lock)
        conf_input = next(inp for inp in self.lock.inputs if inp.id == "conf-1")
        tampered_placement = dataclasses.replace(conf_input.placements[0], mode=0o600)
        tampered_input = dataclasses.replace(conf_input, placements=(tampered_placement,))
        new_inputs = tuple(tampered_input if inp.id == "conf-1" else inp for inp in self.lock.inputs)
        tampered_lock = dataclasses.replace(self.lock, inputs=new_inputs)
        with self.assertRaises(ApplianceError) as ctx:
            inspect_tree.compare_against_lock(inventory, tampered_lock, image="runtime-policy")
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_METADATA")

    def test_symlink_target_mismatch_is_rejected(self) -> None:
        inventory = self._build_and_inspect(self.lock)
        link_input = next(inp for inp in self.lock.inputs if inp.id == "link-1")
        tampered_placement = dataclasses.replace(link_input.placements[0], target="/usr/bin/somewhere-else")
        tampered_input = dataclasses.replace(link_input, placements=(tampered_placement,))
        new_inputs = tuple(tampered_input if inp.id == "link-1" else inp for inp in self.lock.inputs)
        tampered_lock = dataclasses.replace(self.lock, inputs=new_inputs)
        with self.assertRaises(ApplianceError) as ctx:
            inspect_tree.compare_against_lock(inventory, tampered_lock, image="runtime-policy")
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_SYMLINK")

    def test_undeclared_intermediate_directory_fails_loud(self) -> None:
        dirs_input = next(inp for inp in self.lock.inputs if inp.id == "dirs-1")
        trimmed_placements = tuple(p for p in dirs_input.placements if p.path != "/usr/bin")
        trimmed_dirs_input = dataclasses.replace(dirs_input, placements=trimmed_placements)
        new_inputs = tuple(trimmed_dirs_input if inp.id == "dirs-1" else inp for inp in self.lock.inputs)
        broken_lock = dataclasses.replace(self.lock, inputs=new_inputs)
        with self.assertRaises(ApplianceError) as ctx:
            self._build_and_inspect(broken_lock)
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_UNEXPECTED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
