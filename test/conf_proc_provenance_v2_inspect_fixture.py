#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Shared real-H3 fixture construction for dormant H4 inspector tests."""

from __future__ import annotations

import importlib.util
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
_H3_E2E_PATH = ROOT / "test" / "conf-proc-provenance-v2-assemble-e2e-selftest.py"
_SPEC = importlib.util.spec_from_file_location("_h3_assemble_e2e_fixture", _H3_E2E_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("could not load H3 fixture builder")
_H3_E2E = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_H3_E2E)


@dataclass
class H4Fixture:
    """One real H3-produced bundle and its six independent authorities."""

    base: str
    h3: object
    assembly: object

    @property
    def bundle(self) -> str:
        return self.assembly.bundle_path

    def inspect_kwargs(self) -> dict[str, str]:
        return {
            "root_lock_path": self.h3.lock_path,
            "runtime_closure_path": self.h3.closure_path,
            "verity_rules_path": self.h3.rules_path,
            "tcb_identity_path": self.h3.tcb_path,
            "builder_source_path": self.h3._input("source.py"),
            "policy_path": self.h3.policy_path,
            "input_root": self.h3.input_root,
            "tool_root": self.h3.tool_root,
            "bundle": self.bundle,
        }

    def clone_bundle(self, name: str = "candidate-copy") -> str:
        """Return a disposable exact copy that callers may mutate."""

        target = Path(self.base, name)
        shutil.copytree(self.bundle, target, copy_function=shutil.copy2)
        return str(target)

    def cleanup(self) -> None:
        shutil.rmtree(self.base, ignore_errors=True)


def build_positive_fixture() -> H4Fixture:
    """Build the positive candidate with H3 itself; never synthesize a bundle."""

    base = tempfile.mkdtemp(dir="/var/tmp", prefix="conf-proc-h4-test-")
    try:
        h3 = _H3_E2E._Fixture(base)
        assembly = h3.assemble()
        return H4Fixture(base=base, h3=h3, assembly=assembly)
    except Exception:
        shutil.rmtree(base, ignore_errors=True)
        raise
