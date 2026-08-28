#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""H4 activation grammar, graph, and module-authority checks."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "test")]

from conf_proc_graph_compare import compare_graph_to_policy  # noqa: E402
from conf_proc_inspect_graph import extract_graph  # noqa: E402
from conf_proc_inspect_modules import compare_module_authority  # noqa: E402
from conf_proc_policy import parse_policy  # noqa: E402
from conf_proc_provenance_v2_inspect_fixture import build_positive_fixture  # noqa: E402
from conf_proc_provenance_v2_inspect_surface import check_extracted_surfaces  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


class H4InspectorSurfaceGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = build_positive_fixture()
        self.addCleanup(self.fixture.cleanup)
        self.policy = parse_policy(Path(self.fixture.h3.policy_path).read_bytes())

    def _surface_fails(self, relative: str, content: bytes = b"x", *, mode: int = 0o644) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as root:
            models = Path(root, "models")
            runtime = Path(root, "runtime")
            models.mkdir()
            target = runtime / relative
            target.parent.mkdir(parents=True)
            target.write_bytes(content)
            os.chmod(target, mode)
            with self.assertRaises(ApplianceError) as context:
                check_extracted_surfaces(runtime_policy_root=str(runtime), models_root=str(models), policy=self.policy, graph_nodes=[])
            self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_INSPECT_PROHIBITED_SURFACE")

    def test_prohibited_activation_and_runtime_surface_categories(self) -> None:
        cases = (
            ("etc/systemd/system/h4.service.d/drop.conf", b"[Service]\nExecStart=/bin/true\n", 0o644),
            ("etc/systemd/system/h4.socket", b"[Socket]\nListenStream=1\n", 0o644),
            ("usr/lib/systemd/system-generators/h4", b"#!/bin/sh\n", 0o755),
            ("etc/dbus-1/system-services/h4.service", b"[D-BUS Service]\nExec=/bin/sh -c x\n", 0o644),
            ("etc/udev/rules.d/h4.rules", b'ACTION=="add", ENV{SYSTEMD_WANTS}="h4.service"\n', 0o644),
            ("etc/cron.d/h4", b"* * * * * root /bin/true\n", 0o644),
            ("opt/azure-runcommand", b"x", 0o644),
            ("etc/systemd/journald.conf", b"[Journal]\nStorage=persistent\n", 0o644),
        )
        for relative, content, mode in cases:
            with self.subTest(relative=relative):
                self._surface_fails(relative, content, mode=mode)
        with tempfile.TemporaryDirectory(dir="/var/tmp") as root:
            models = Path(root, "models")
            runtime = Path(root, "runtime")
            models.mkdir()
            target = runtime / "opt/bin/runner"
            target.parent.mkdir(parents=True)
            os.chmod(target.parent, 0o777)
            target.write_bytes(b"x")
            os.chmod(target, 0o755)
            with self.assertRaises(ApplianceError):
                check_extracted_surfaces(runtime_policy_root=str(runtime), models_root=str(models), policy=self.policy, graph_nodes=[])

    def test_graph_and_module_authority_mismatches_are_red(self) -> None:
        with self.assertRaises(ApplianceError):
            compare_graph_to_policy([], [], self.policy)
        with tempfile.TemporaryDirectory(dir="/var/tmp") as root:
            unit = Path(root, "etc/systemd/system/bad.service")
            unit.parent.mkdir(parents=True)
            unit.write_text("[Service]\nExecStart=/bin/true\n")
            with self.assertRaises(ApplianceError):
                extract_graph(root)
        with self.assertRaises(ApplianceError):
            compare_module_authority(([], []), {"module_inventory": [{"path": "/bad.ko"}], "firmware_inventory": []})


if __name__ == "__main__":
    unittest.main(verbosity=2)
