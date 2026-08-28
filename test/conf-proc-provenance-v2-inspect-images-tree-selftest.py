#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""H4 image integrity and lock-inventory mismatch checks."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "test")]

import conf_proc_provenance_v2_inspect as inspector  # noqa: E402
from conf_proc_inspect_tree import compare_against_lock  # noqa: E402
from conf_proc_lock import parse_lock  # noqa: E402
from conf_proc_provenance_v2_inspect_fixture import build_positive_fixture  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


class H4InspectorImageTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = build_positive_fixture()
        self.addCleanup(self.fixture.cleanup)

    def _mutate(self, name: str, mutation) -> str:
        bundle = self.fixture.clone_bundle(name)
        os.chmod(bundle, 0o755)
        for child in Path(bundle).iterdir():
            if child.is_file():
                os.chmod(child, 0o644)
        mutation(Path(bundle))
        for child in Path(bundle).iterdir():
            if child.is_file():
                os.chmod(child, 0o444)
        os.chmod(bundle, 0o555)
        return bundle

    def _rejects(self, bundle: str) -> None:
        with self.assertRaises(ApplianceError):
            inspector.inspect_bundle(**{**self.fixture.inspect_kwargs(), "bundle": bundle})

    def test_one_byte_truncation_extension_and_swap_are_rejected(self) -> None:
        mutations = {
            "flip": lambda root: root.joinpath("models.squashfs").write_bytes(
                bytes([root.joinpath("models.squashfs").read_bytes()[0] ^ 1]) + root.joinpath("models.squashfs").read_bytes()[1:]
            ),
            "truncate": lambda root: root.joinpath("models.verity").write_bytes(root.joinpath("models.verity").read_bytes()[:-1]),
            "extend": lambda root: root.joinpath("runtime-policy.squashfs").write_bytes(root.joinpath("runtime-policy.squashfs").read_bytes() + b"x"),
            "swap": lambda root: _swap(root / "models.squashfs", root / "runtime-policy.squashfs"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self._rejects(self._mutate(name, mutate))

    def test_manifest_root_claim_and_inventory_mismatch_are_rejected(self) -> None:
        bundle = self._mutate("root", lambda root: root.joinpath("appliance.manifest.json").write_bytes(
            root.joinpath("appliance.manifest.json").read_bytes().replace(b'"root_hash":"', b'"root_hash":"0', 1)
        ))
        self._rejects(bundle)
        lock = parse_lock(Path(self.fixture.h3.lock_path).read_bytes())
        with self.assertRaises(ApplianceError) as context:
            compare_against_lock({}, lock, image="models")
        self.assertEqual(context.exception.reason_code, "CP_TREE_MISSING")


def _swap(left: Path, right: Path) -> None:
    left_bytes = left.read_bytes()
    right_bytes = right.read_bytes()
    left.write_bytes(right_bytes)
    right.write_bytes(left_bytes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
