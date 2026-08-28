#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""H4 authority identity and bounded-pinning checks."""

from __future__ import annotations

import sys
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "test")]

import conf_proc_provenance_v2_inspect as inspector  # noqa: E402
import conf_proc_json as cj  # noqa: E402
from conf_proc_provenance_v2_inspect_documents import derive_inspection_inputs  # noqa: E402
from conf_proc_provenance_v2_inspect_fixture import build_positive_fixture  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


class H4InspectorInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = build_positive_fixture()
        self.addCleanup(self.fixture.cleanup)

    def _bytes(self) -> dict[str, bytes]:
        h3 = self.fixture.h3
        return {
            "root_lock_bytes": Path(h3.lock_path).read_bytes(),
            "runtime_closure_bytes": Path(h3.closure_path).read_bytes(),
            "verity_rules_bytes": Path(h3.rules_path).read_bytes(),
            "tcb_identity_bytes": Path(h3.tcb_path).read_bytes(),
            "builder_source_bytes": Path(h3._input("source.py")).read_bytes(),
            "policy_bytes": Path(h3.policy_path).read_bytes(),
        }

    def test_identity_derivation_is_exact_bytes_and_authorities_reject_bad_json(self) -> None:
        exact = self._bytes()
        inputs = derive_inspection_inputs(**exact)
        changed = dict(exact)
        changed["builder_source_bytes"] += b"changed"
        with self.assertRaises(ApplianceError):
            derive_inspection_inputs(**changed)
        skeletal = dict(exact)
        skeletal["root_lock_bytes"] = b"{}"
        with self.assertRaises(ApplianceError):
            derive_inspection_inputs(**skeletal)
        for bad in (b"{", b'{"schema":"conf-proc-policy/v1","schema":"conf-proc-policy/v1"}', b"\xff"):
            mutated = dict(exact)
            mutated["policy_bytes"] = bad
            with self.assertRaises(ApplianceError):
                derive_inspection_inputs(**mutated)
        disagreement = dict(exact)
        policy = cj.canonical_loads(disagreement["policy_bytes"])
        policy["boot_roots"] = ["/independent-disagreement"]
        disagreement["policy_bytes"] = cj.canonical_dumps(policy)
        with self.assertRaises(ApplianceError):
            derive_inspection_inputs(**disagreement)
        self.assertEqual(inputs.artifact_input_sha256, derive_inspection_inputs(**exact).artifact_input_sha256)

    def test_authority_pin_detects_post_read_mutation_and_no_host_fallback(self) -> None:
        h3 = self.fixture.h3
        paths = {
            "root_lock": h3.lock_path,
            "runtime_closure": h3.closure_path,
            "verity_rules": h3.rules_path,
            "tcb_identity": h3.tcb_path,
            "builder_source": h3._input("source.py"),
            "policy": h3.policy_path,
        }
        with self.assertRaises(ApplianceError):
            inspector.inspect_bundle(**{**self.fixture.inspect_kwargs(), "input_root": "/nonexistent-h4-input-root"})
        with self.assertRaises(ApplianceError) as context:
            with inspector._pinned_authorities(paths):
                Path(paths["builder_source"]).write_bytes(b"mutated during inspection")
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION")

    def test_runtime_closure_structure_is_independently_validated(self) -> None:
        exact = self._bytes()

        def closure_mutation(mutator) -> ApplianceError:
            changed = dict(exact)
            closure = cj.canonical_loads(changed["runtime_closure_bytes"])
            mutator(closure)
            changed["runtime_closure_bytes"] = cj.canonical_dumps(closure)
            with self.assertRaises(ApplianceError) as context:
                derive_inspection_inputs(**changed)
            return context.exception

        with self.subTest("unsorted paths"):
            error = closure_mutation(lambda closure: closure.update(entries=list(reversed(closure["entries"]))))
            self.assertEqual(error.reason_code, "CP_RUNTIME_CLOSURE_SCHEMA")

        with self.subTest("single-member hardlink group"):
            def single_hardlink(closure):
                next(entry for entry in closure["entries"] if entry["node_type"] == "file")["hardlink_group"] = "a" * 64

            error = closure_mutation(single_hardlink)
            self.assertEqual(error.reason_code, "CP_RUNTIME_CLOSURE_SCHEMA")

        with self.subTest("escaping symlink"):
            def escaping_symlink(closure):
                entry = next(entry for entry in closure["entries"] if entry["node_type"] == "file")
                entry.update(node_type="symlink", sha256=None, symlink_target="/outside-the-closure", hardlink_group=None)

            error = closure_mutation(escaping_symlink)
            self.assertEqual(error.reason_code, "CP_RUNTIME_CLOSURE_SCHEMA")

        with self.subTest("file symlink target"):
            def file_symlink_target(closure):
                next(entry for entry in closure["entries"] if entry["node_type"] == "file")["symlink_target"] = "/not-used"

            error = closure_mutation(file_symlink_target)
            self.assertEqual(error.reason_code, "CP_RUNTIME_CLOSURE_SCHEMA")

        with self.subTest("TCB executable shape"):
            changed = dict(exact)
            tcb = deepcopy(cj.canonical_loads(changed["tcb_identity_bytes"]))
            del tcb["caller"]["linkage"]
            changed["tcb_identity_bytes"] = cj.canonical_dumps(tcb)
            with self.assertRaises(ApplianceError) as context:
                derive_inspection_inputs(**changed)
            self.assertEqual(context.exception.reason_code, "CP_TCB_IDENTITY_SCHEMA")


if __name__ == "__main__":
    unittest.main(verbosity=2)
