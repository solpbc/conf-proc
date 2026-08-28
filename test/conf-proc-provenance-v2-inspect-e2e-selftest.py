#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""End-to-end proof that H4 accepts one real H3-produced bundle."""

from __future__ import annotations

import hashlib
import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

import conf_proc_provenance_v2_inspect as inspector  # noqa: E402
from conf_proc_provenance_v2_inspect_documents import derive_inspection_inputs  # noqa: E402
from conf_proc_provenance_v2_inspect_fixture import build_positive_fixture  # noqa: E402


class H4InspectorEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = build_positive_fixture()
        self.addCleanup(self.fixture.cleanup)

    def test_real_h3_bundle_is_artifact_consistent(self) -> None:
        self.assertEqual(os.stat(self.fixture.bundle).st_dev, os.stat("/var/tmp").st_dev)
        result = inspector.inspect_bundle(**self.fixture.inspect_kwargs())
        self.assertEqual(set(result.__dataclass_fields__), {
            "state", "hardware_qualification", "artifact_input_sha256", "execution_provenance_sha256",
            "models_squashfs_sha256", "models_verity_sha256", "runtime_policy_squashfs_sha256",
            "runtime_policy_verity_sha256", "manifest_sha256", "spdx_sha256", "evidence_ceiling",
        })
        self.assertEqual(result.state, "artifact_consistent")
        self.assertEqual(result.hardware_qualification, "not_qualified")
        self.assertIn("UKI", result.evidence_ceiling)
        self.assertIn("TPM", result.evidence_ceiling)
        self.assertIn("Azure", result.evidence_ceiling)
        for field, filename in {
            "models_squashfs_sha256": "models.squashfs",
            "models_verity_sha256": "models.verity",
            "runtime_policy_squashfs_sha256": "runtime-policy.squashfs",
            "runtime_policy_verity_sha256": "runtime-policy.verity",
            "manifest_sha256": "appliance.manifest.json",
            "spdx_sha256": "appliance.spdx.json",
        }.items():
            self.assertEqual(getattr(result, field), hashlib.sha256(Path(self.fixture.bundle, filename).read_bytes()).hexdigest())
        expected = derive_inspection_inputs(
            root_lock_bytes=Path(self.fixture.h3.lock_path).read_bytes(),
            runtime_closure_bytes=Path(self.fixture.h3.closure_path).read_bytes(),
            verity_rules_bytes=Path(self.fixture.h3.rules_path).read_bytes(),
            tcb_identity_bytes=Path(self.fixture.h3.tcb_path).read_bytes(),
            builder_source_bytes=Path(self.fixture.h3._input("source.py")).read_bytes(),
            policy_bytes=Path(self.fixture.h3.policy_path).read_bytes(),
        )
        self.assertEqual(result.artifact_input_sha256, expected.artifact_input_sha256)
        self.assertEqual(result.execution_provenance_sha256, expected.execution_provenance_sha256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
