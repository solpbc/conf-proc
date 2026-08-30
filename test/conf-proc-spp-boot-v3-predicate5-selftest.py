#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Focused KATs for v3 closed executable provenance and JIT authority."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

from conf_proc_json import canonical_dumps, canonical_loads
import conf_proc_spp_boot_v3 as boot
from conf_proc_spp_boot_v3_fixture import build_v3_fixture, refresh_v3_contract_bindings
from conf_proc_spp_reasons_v3 import ApplianceErrorV3, CP_BOOT_V3_BINDING, CP_BOOT_V3_SCHEMA
from conf_proc_spp_boot_v3_semantics import jit_derivation_sha256_v3


def _mutated_docs(*, execution_mode: str = "python_jit_triton", cache_policy: str = "ephemeral_rebuild") -> tuple[dict[str, bytes], object]:
    docs, _ = build_v3_fixture(execution_mode=execution_mode, cache_policy=cache_policy)
    return docs, canonical_loads(docs["boot_contract_bytes"])


def _commit_contract(docs: dict[str, bytes], contract: dict) -> None:
    docs["boot_contract_bytes"] = canonical_dumps(contract)
    refresh_v3_contract_bindings(docs)


def _parsed_contract(docs: dict[str, bytes]) -> object:
    return boot.parse_boot_contract_v3(docs["boot_contract_bytes"])


class BootV3Predicate5Selftest(unittest.TestCase):
    def test_closed_no_jit_and_two_jit_cache_modes_bind(self) -> None:
        for kwargs, expected_derivations in (
            ({}, 0),
            ({"execution_mode": "python_jit_triton", "cache_policy": "ephemeral_rebuild"}, 1),
            ({"execution_mode": "python_jit_triton", "cache_policy": "measured_read_only"}, 1),
        ):
            docs, contract = build_v3_fixture(**kwargs)
            binding = boot.bind_boot_inputs_v3(contract=contract, **docs)
            with self.subTest(kwargs=kwargs):
                self.assertEqual(len(binding.predicate5.jit_derivations), expected_derivations)
                self.assertEqual(binding.predicate5.startup_kat_sha256, "82840888819a980868766f4273456c9c81d0539a6d2642b8af32f4cb30829976")

    def test_static_kat_is_read_from_the_byte_exact_fixture_files(self) -> None:
        kat = ROOT / "test/fixtures/spp-v3/python310-startup-kat-v1.json"
        observer = ROOT / "test/fixtures/spp-v3/python310_startup_observer_v1.py"
        self.assertEqual((len(kat.read_bytes()), hashlib.sha256(kat.read_bytes()).hexdigest()), (2836, "82840888819a980868766f4273456c9c81d0539a6d2642b8af32f4cb30829976"))
        self.assertEqual((len(observer.read_bytes()), hashlib.sha256(observer.read_bytes()).hexdigest()), (1871, "525fa4a1335a95744779ee5e627c150f194ed6e782148553be2547c4d77ee194"))
        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        raw["execution_closure"]["bootstrap"]["pre_importer_cache"].reverse()
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            _commit_contract(docs, raw)
            _parsed_contract(docs)

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        raw["execution_closure"]["startup_kat"]["binary"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            _commit_contract(docs, raw)
            _parsed_contract(docs)

    def test_bootstrap_and_loader_control_escapes_are_rejected(self) -> None:
        docs, raw = _mutated_docs()
        raw["execution_closure"]["bootstrap"]["post_path"].append("/tmp")
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            _commit_contract(docs, raw)
            _parsed_contract(docs)

        docs, raw = _mutated_docs()
        raw["execution_closure"]["loader_controls"][0]["contributed_paths"] = ["/outside"]
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

    def test_overlap_tags_and_no_jit_compiler_injection_are_closed(self) -> None:
        docs, raw = _mutated_docs()
        entries = {entry["path"]: entry for entry in raw["execution_closure"]["eligible_files"]}
        self.assertEqual(entries["/usr/lib/spp/vendor/spp_jit.pth"]["semantic_tags"], ["python_loading_control"])
        self.assertEqual(entries["/usr/lib/spp/vendor/sitecustomize.py"]["semantic_tags"], ["importable_module", "python_loading_control"])
        self.assertEqual(entries["/usr/lib/spp/lib/plugin.so"]["semantic_tags"], ["dynamic_library", "native_extension", "plugin"])
        self.assertEqual(entries["/usr/lib/spp/bin/triton-compile"]["semantic_tags"], ["compiler", "launch_executable"])
        self.assertEqual(entries["/usr/lib/spp/vendor/triton_kernel.py"]["semantic_tags"], ["compiler_source", "importable_module"])
        measured_docs, measured_contract = build_v3_fixture(execution_mode="python_jit_triton", cache_policy="measured_read_only")
        measured = boot.bind_boot_inputs_v3(contract=measured_contract, **measured_docs)
        self.assertEqual([item.semantic_tags for item in measured.predicate5.eligible_files if "/jit-cache/" in item.path], [("dynamic_library", "jit_cache", "native_extension")])
        self.assertNotIn("/etc/spp/policy.json", {item.path for item in measured.predicate5.eligible_files})
        entries["/usr/lib/spp/lib/plugin.so"]["semantic_tags"].remove("plugin")
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        raw["execution_closure"]["eligible_files"][0]["semantic_tags"].append("compiler")
        raw["execution_closure"]["eligible_files"][0]["semantic_tags"].sort()
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

    def test_derivation_key_is_framed_and_output_cache_identity_is_closed(self) -> None:
        docs, raw = _mutated_docs()
        record = raw["execution_closure"]["jit_derivations"][0]
        known = jit_derivation_sha256_v3(record)
        self.assertEqual(raw["execution_closure"]["expected_outputs"][0]["derivation_sha256"], known)
        record["inputs"] = list(reversed(record["inputs"]))
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

        docs, raw = _mutated_docs(execution_mode="python_jit_triton", cache_policy="measured_read_only")
        raw["execution_closure"]["cache_selectors"][0]["path"] = "/usr/lib/spp/jit-cache/not-derived/kernel.so"
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

    def test_output_name_traversal_and_predecessor_digest_substitution_fail(self) -> None:
        docs, raw = _mutated_docs()
        raw["execution_closure"]["jit_derivations"][0]["output"]["output_name"] = "../kernel.so"
        raw["execution_closure"]["jit_derivations"][0]["output"]["relative_path"] = "../kernel.so"
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

        docs, raw = _mutated_docs()
        raw["execution_closure"]["eligible_files"][0]["sha256"] = "0" * 64
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=contract, **docs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
