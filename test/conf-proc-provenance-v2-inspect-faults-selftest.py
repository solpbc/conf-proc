#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""H4 cleanup, immutability, status, and reason-code fault checks."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "test")]

import conf_proc_provenance_v2_inspect as inspector  # noqa: E402
from conf_proc_provenance_v2_inspect_fixture import build_positive_fixture  # noqa: E402
from conf_proc_reasons import ALL_REASON_CODES, ApplianceError  # noqa: E402


class H4InspectorFaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = build_positive_fixture()
        self.addCleanup(self.fixture.cleanup)

    def test_candidate_mutation_is_detected_and_original_bundle_is_unchanged(self) -> None:
        candidate = self.fixture.clone_bundle("race")
        with self.assertRaises(ApplianceError) as context:
            with inspector._pinned_bundle_files(candidate):
                os.chmod(candidate, 0o755)
                Path(candidate, "appliance.spdx.json").rename(Path(candidate, "moved.spdx"))
                os.chmod(candidate, 0o555)
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION")
        before = {path.name: (path.stat().st_mode, path.stat().st_mtime_ns) for path in Path(self.fixture.bundle).iterdir()}
        result = inspector.inspect_bundle(**self.fixture.inspect_kwargs())
        after = {path.name: (path.stat().st_mode, path.stat().st_mtime_ns) for path in Path(self.fixture.bundle).iterdir()}
        self.assertEqual(before, after)
        self.assertEqual(result.state, "artifact_consistent")

    def test_temporary_work_roots_are_removed_and_success_values_are_not_overclaimed(self) -> None:
        before = set(Path("/var/tmp").glob("conf-proc-h4-*"))
        result = inspector.inspect_bundle(**self.fixture.inspect_kwargs())
        self.assertEqual(before, set(Path("/var/tmp").glob("conf-proc-h4-*")))
        forbidden = {"verified", "promoted", "qualified", "release_candidate", "bootable", "accepted", "ready"}
        self.assertFalse(forbidden & set(result.__dict__.values()))

    def test_failure_categories_use_registered_codes(self) -> None:
        expected = {
            "CP_PROVENANCE_AUTHORITY", "CP_PROVENANCE_V2_BUNDLE_SHAPE", "CP_TOOL_MISSING",
            "CP_VERITY_VERIFY", "CP_SQUASHFS_EXTRACT", "CP_TREE_MISSING",
            "CP_PROVENANCE_V2_INSPECT_PROHIBITED_SURFACE", "CP_POLICY_GRAPH_MISMATCH",
            "CP_MODULE_SIGNER", "CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH",
            "CP_PROVENANCE_V2_INSPECT_SEALED_BINDING", "CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION",
        }
        self.assertTrue(expected <= ALL_REASON_CODES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
