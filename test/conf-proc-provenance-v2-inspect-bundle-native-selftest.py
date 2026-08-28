#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""H4 candidate-shape and required-native-tool checks."""

from __future__ import annotations

import os
import shutil
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "test")]

import conf_proc_provenance_v2_inspect as inspector  # noqa: E402
from conf_proc_provenance_v2_inspect_fixture import build_positive_fixture  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


class H4InspectorBundleNativeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = build_positive_fixture()
        self.addCleanup(self.fixture.cleanup)

    def _fails(self, bundle: str) -> str:
        with self.assertRaises(ApplianceError) as context:
            inspector.inspect_bundle(**{**self.fixture.inspect_kwargs(), "bundle": bundle})
        return context.exception.reason_code

    def test_exact_readonly_bundle_shape_is_required(self) -> None:
        candidate = self.fixture.clone_bundle()
        os.chmod(candidate, 0o755)
        Path(candidate, "unexpected").write_bytes(b"x")
        os.chmod(candidate, 0o555)
        self.assertEqual(self._fails(candidate), "CP_PROVENANCE_V2_BUNDLE_SHAPE")
        os.chmod(candidate, 0o755)
        shutil.rmtree(candidate)
        candidate = self.fixture.clone_bundle("wrong-mode")
        leaf = Path(candidate, "models.squashfs")
        os.chmod(candidate, 0o755)
        os.chmod(leaf, 0o644)
        os.chmod(candidate, 0o555)
        self.assertEqual(self._fails(candidate), "CP_PROVENANCE_V2_BUNDLE_READONLY")

    def test_symlink_and_post_check_substitution_fail(self) -> None:
        candidate = self.fixture.clone_bundle("symlink")
        os.chmod(candidate, 0o755)
        target = Path(candidate, "models.verity")
        replacement = Path(candidate, "replacement")
        replacement.write_bytes(target.read_bytes())
        os.chmod(replacement, 0o444)
        target.unlink()
        target.symlink_to(replacement.name)
        os.chmod(candidate, 0o555)
        self.assertEqual(self._fails(candidate), "CP_PROVENANCE_V2_BUNDLE_SHAPE")
        candidate = self.fixture.clone_bundle("race")
        with self.assertRaises(ApplianceError) as context:
            with inspector._pinned_bundle_files(candidate):
                os.chmod(candidate, 0o755)
                os.replace(Path(candidate, "models.verity"), Path(candidate, "moved.verity"))
                os.chmod(candidate, 0o555)
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION")

    def test_missing_native_tool_is_hard_failure(self) -> None:
        empty = Path(self.fixture.base, "empty-tools")
        empty.mkdir()
        with self.assertRaises(ApplianceError) as context:
            inspector.inspect_bundle(**{**self.fixture.inspect_kwargs(), "tool_root": str(empty)})
        self.assertEqual(context.exception.reason_code, "CP_TOOL_MISSING")

    def test_oversized_candidate_document_fails_before_native_inspection(self) -> None:
        candidate = self.fixture.clone_bundle("oversized-document")
        document = Path(candidate, "appliance.manifest.json")
        os.chmod(candidate, 0o755)
        os.chmod(document, 0o600)
        with document.open("wb") as handle:
            handle.seek(inspector.MAX_INPUT_BYTES)
            handle.write(b"x")
        os.chmod(document, 0o444)
        os.chmod(candidate, 0o555)
        self.assertEqual(self._fails(candidate), "CP_PROVENANCE_INPUT_SIZE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
