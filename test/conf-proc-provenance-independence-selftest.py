#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Policy checks for sealed provenance-code independence."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEALED_NAMES = ("conf_proc_inspect_provenance", "conf_proc_inspect_provenance_cli")
THIS_FILE = Path(__file__).name
EXEMPT_FILES = {"conf_proc_inspect_provenance_cli.py", "conf-proc-provenance-oracle-selftest.py"}


def _candidate_files() -> list[Path]:
    return sorted(ROOT.glob("*.py")) + sorted((ROOT / "test").glob("*.py"))


class ProvenanceIndependenceTests(unittest.TestCase):
    def test_no_stray_references_to_sealed_provenance_files(self) -> None:
        for path in _candidate_files():
            if path.name == THIS_FILE or path.name in EXEMPT_FILES:
                continue
            source = path.read_text()
            relative_path = path.relative_to(ROOT)
            for name in SEALED_NAMES:
                self.assertNotIn(
                    name,
                    source,
                    f"{relative_path} must not reference sealed provenance module {name!r}",
                )
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = {alias.name for alias in node.names}
                elif isinstance(node, ast.ImportFrom):
                    imported = {node.module} if node.module is not None else set()
                else:
                    continue
                self.assertTrue(
                    imported.isdisjoint(SEALED_NAMES),
                    f"{relative_path} imports sealed provenance code",
                )

    def test_exemption_allowlist_is_exact_and_present(self) -> None:
        self.assertEqual(
            EXEMPT_FILES,
            {"conf_proc_inspect_provenance_cli.py", "conf-proc-provenance-oracle-selftest.py"},
        )
        self.assertEqual(len(EXEMPT_FILES), 2)
        cli_path = ROOT / "conf_proc_inspect_provenance_cli.py"
        oracle_test_path = ROOT / "test" / "conf-proc-provenance-oracle-selftest.py"
        self.assertTrue(cli_path.is_file())
        self.assertTrue(oracle_test_path.is_file())

        cli_source = cli_path.read_text()
        self.assertIn(SEALED_NAMES[0], cli_source)
        oracle_test_source = oracle_test_path.read_text()
        for name in SEALED_NAMES:
            self.assertIn(name, oracle_test_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
