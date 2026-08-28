#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Tree correspondence and placement-preflight checks for dormant H3."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_provenance_v2_assemble as assembler  # noqa: E402
from conf_proc_lock import LockInput, Placement  # noqa: E402
from conf_proc_policy import ImagePolicy, TreeNodePolicy  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _input(input_id: str, placement: Placement, data: bytes = b"tree") -> LockInput:
    return LockInput(
        id=input_id,
        role="runtime_tree_input",
        component=input_id,
        sha256=_sha(data),
        size_bytes=len(data),
        source_local_path=input_id,
        source_retrieval_scheme="local-fixture",
        source_retrieval_identity=input_id,
        source_retrieval_immutable_ref="sha256:" + _sha(data),
        derivation_kind="fixture",
        derivation_recipe_id="fixture-v1",
        derivation_parent_ids=(),
        derivation_parameters_sha256=_sha(b"parameters"),
        placements=(placement,),
    )


def _placement(image: str, path: str, node_type: str = "file", *, target: str | None = None) -> Placement:
    return Placement(
        image=image,
        path=path,
        node_type=node_type,
        mode=0o644,
        uid=os.geteuid(),
        gid=os.getegid(),
        xattrs=(),
        source_input_id="source" if node_type == "file" else None,
        target=target,
    )


class H3TreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)

    def test_policy_tree_correspondence_requires_exact_paths(self) -> None:
        tree = os.path.join(self.base, "tree")
        os.makedirs(tree)
        Path(os.path.join(tree, "payload")).write_bytes(b"tree")
        placement = _placement("models", "/payload")
        source = _input("source", placement)
        policy = SimpleNamespace(
            images={
                "models": ImagePolicy(
                    nodes=(
                        TreeNodePolicy("/payload", "file", 0o644, os.geteuid(), os.getegid(), (), "source", None, "model"),
                        TreeNodePolicy("/unexpected", "file", 0o644, os.geteuid(), os.getegid(), (), "source", None, "model"),
                    )
                )
            }
        )
        closure = {
            "entries": [
                {
                    "path": "/payload", "node_type": "file", "mode": 0o644, "uid": os.geteuid(), "gid": os.getegid(),
                    "size_bytes": 4, "sha256": _sha(b"tree"), "symlink_target": None, "xattrs": [],
                }
            ]
        }
        with self.assertRaises(ApplianceError) as context:
            assembler._validate_tree_authorities(SimpleNamespace(inputs=(source,)), policy, closure, "models", tree)
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")

    def test_duplicate_placement_and_inventory_preflights(self) -> None:
        duplicate = _placement("models", "/same")
        other_image = _placement("runtime-policy", "/same")
        first = _input("same-input", duplicate)
        second = _input("same-input", other_image)
        with self.assertRaises(ApplianceError) as context:
            assembler._preflight_placements(SimpleNamespace(inputs=(first, second)))
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")

        module = _input("module", _placement("models", "/lib/driver.ko"))
        module_other = _input("module-other", _placement("runtime-policy", "/lib/driver.ko"))
        with self.assertRaises(ApplianceError) as context:
            assembler._preflight_placements(SimpleNamespace(inputs=(module, module_other)))
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_MANIFEST_PRODUCTION")

    def test_symlink_rules_and_frozen_snapshot(self) -> None:
        for image, path, target in (
            ("models", "/link", "/target"),
            ("runtime-policy", "/link", "/target"),
            ("models", "/link", "target"),
            ("runtime-policy", "/dir/link", "../../.."),
        ):
            with self.assertRaises(ApplianceError) as context:
                assembler._validate_image_symlink(image, path, target)
            self.assertEqual(context.exception.reason_code, "CP_TREE_SYMLINK")

        tree = os.path.join(self.base, "frozen")
        os.makedirs(tree)
        payload = os.path.join(tree, "payload")
        Path(payload).write_bytes(b"before")
        assembler._freeze_trees((tree,))
        snapshots = {"models": assembler._tree_snapshot(tree)}
        os.chmod(tree, 0o755)
        os.chmod(payload, 0o644)
        Path(payload).write_bytes(b"after!")
        with self.assertRaises(ApplianceError) as context:
            assembler._assert_tree_snapshots({"models": tree}, snapshots)
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
