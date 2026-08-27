#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftests for SPDX 2.3 SBOM assembly, schema validation, and the
independent inspector-side diff engine."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_build_sbom as build_sbom  # noqa: E402
import conf_proc_inspect_sbom as inspect_sbom  # noqa: E402
import conf_proc_json as cj  # noqa: E402
import conf_proc_sbom as sbom_schema  # noqa: E402
from conf_proc_lock import Lock, LockInput, Placement  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha(n: int) -> str:
    return format(n, "064x")


def _placement(image, path, node_type, mode, uid, gid, *, source_input_id=None, target=None):
    return Placement(image=image, path=path, node_type=node_type, mode=mode, uid=uid, gid=gid, xattrs=(), source_input_id=source_input_id, target=target)


def _make_lock() -> Lock:
    conf_input = LockInput(
        id="conf-1", role="runtime_tree_input", component="config", sha256=_sha(1), size_bytes=10,
        source_local_path="spp.conf", source_retrieval_scheme="local-fixture", source_retrieval_identity="fixture:conf",
        source_retrieval_immutable_ref="v1", derivation_kind="fixture", derivation_recipe_id="r1",
        derivation_parent_ids=(), derivation_parameters_sha256=_sha(2),
        placements=(_placement("runtime-policy", "/etc/spp.conf", "file", 0o644, 0, 0, source_input_id="conf-1"),),
    )
    link_input = LockInput(
        id="link-1", role="runtime_tree_input", component="link", sha256=_sha(3), size_bytes=0,
        source_local_path="spp.conf", source_retrieval_scheme="local-fixture", source_retrieval_identity="fixture:link",
        source_retrieval_immutable_ref="v1", derivation_kind="fixture", derivation_recipe_id="r1",
        derivation_parent_ids=(), derivation_parameters_sha256=_sha(2),
        placements=(_placement("runtime-policy", "/usr/bin/stub-link", "symlink", 0o777, 0, 0, target="/usr/bin/stub"),),
    )
    tool_input = LockInput(
        id="tool-mksquashfs", role="build_tool", component="mksquashfs", sha256=_sha(4), size_bytes=100,
        source_local_path="tool", source_retrieval_scheme="local-fixture", source_retrieval_identity="fixture:tool",
        source_retrieval_immutable_ref="v1", derivation_kind="fixture", derivation_recipe_id="r1",
        derivation_parent_ids=(), derivation_parameters_sha256=_sha(2), placements=(),
    )
    model_input = LockInput(
        id="model-1", role="inference_model", component="qwen-fixture", sha256=_sha(5), size_bytes=100,
        source_local_path="model", source_retrieval_scheme="local-fixture", source_retrieval_identity="fixture:model",
        source_retrieval_immutable_ref="v1", derivation_kind="fixture", derivation_recipe_id="r1",
        derivation_parent_ids=(), derivation_parameters_sha256=_sha(2),
        placements=(_placement("models", "/models/fixture.bin", "file", 0o644, 0, 0, source_input_id="model-1"),),
    )
    return Lock(
        schema="conf-proc-lock/v1", lock_version=1, base_image_record=None, future_cmdline="console=ttyS0",
        inputs=(conf_input, link_input, tool_input, model_input), authorized_module_signers=(),
        image_specs={"runtime-policy": {}, "models": {}}, policy_input_id="p", tool_ids=("tool-mksquashfs",),
    )


class SbomBuildAndCompareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = _make_lock()
        self.lock_digest = hashlib.sha256(b"fixture-lock-digest").digest()

    def _build(self) -> bytes:
        return build_sbom.build_sbom_bytes(self.lock, self.lock_digest)

    def test_build_produces_valid_spdx_document(self) -> None:
        data = self._build()
        parsed = sbom_schema.parse_sbom(data)
        self.assertEqual(parsed.raw["spdxVersion"], "SPDX-2.3")
        self.assertEqual(cj.canonical_dumps(cj.canonical_loads(data)), data)
        # One package per lock input plus the appliance package itself.
        self.assertEqual(len(parsed.raw["packages"]), len(self.lock.inputs) + 1)
        # One file per non-directory placement (conf, symlink, model).
        self.assertEqual(len(parsed.raw["files"]), 3)

    def test_independent_compare_succeeds_on_genuine_sbom(self) -> None:
        data = self._build()
        parsed = sbom_schema.parse_sbom(data)
        inspect_sbom.compare_sbom(parsed, self.lock)

    def test_reject_missing_package(self) -> None:
        data = self._build()
        raw = json.loads(data)
        model_pkg_id = build_sbom.package_id("model-1")
        raw["packages"] = [p for p in raw["packages"] if p["SPDXID"] != model_pkg_id]
        # Also drop every relationship mentioning the removed package (in
        # either position) so the schema's own referential-integrity check
        # doesn't reject this before compare_sbom gets a chance to report
        # the more specific "missing package" diff.
        raw["relationships"] = [
            r for r in raw["relationships"]
            if model_pkg_id not in (r["spdxElementId"], r["relatedSpdxElement"])
        ]
        tampered = cj.canonical_dumps(raw)
        parsed = sbom_schema.parse_sbom(tampered)
        with self.assertRaises(ApplianceError) as ctx:
            inspect_sbom.compare_sbom(parsed, self.lock)
        self.assertEqual(ctx.exception.reason_code, "CP_SBOM_DIFF")

    def test_reject_missing_file(self) -> None:
        data = self._build()
        raw = json.loads(data)
        removed_file_ids = {f["SPDXID"] for f in raw["files"] if "spp.conf" in f["fileName"]}
        raw["files"] = [f for f in raw["files"] if f["SPDXID"] not in removed_file_ids]
        raw["relationships"] = [
            r for r in raw["relationships"]
            if r["spdxElementId"] not in removed_file_ids and r["relatedSpdxElement"] not in removed_file_ids
        ]
        tampered = cj.canonical_dumps(raw)
        parsed = sbom_schema.parse_sbom(tampered)
        with self.assertRaises(ApplianceError) as ctx:
            inspect_sbom.compare_sbom(parsed, self.lock)
        self.assertEqual(ctx.exception.reason_code, "CP_SBOM_DIFF")

    def test_reject_missing_transitive_dependency_relationship(self) -> None:
        data = self._build()
        raw = json.loads(data)
        model_pkg_id = build_sbom.package_id("model-1")
        raw["relationships"] = [
            r for r in raw["relationships"]
            if not (r["spdxElementId"] == model_pkg_id and r["relationshipType"] == "RUNTIME_DEPENDENCY_OF")
        ]
        tampered = cj.canonical_dumps(raw)
        parsed = sbom_schema.parse_sbom(tampered)
        with self.assertRaises(ApplianceError) as ctx:
            inspect_sbom.compare_sbom(parsed, self.lock)
        self.assertEqual(ctx.exception.reason_code, "CP_SBOM_DIFF")

    def test_reject_corrupted_package_checksum(self) -> None:
        data = self._build()
        raw = json.loads(data)
        conf_pkg_id = build_sbom.package_id("conf-1")
        for pkg in raw["packages"]:
            if pkg["SPDXID"] == conf_pkg_id:
                pkg["checksums"][0]["checksumValue"] = _sha(999)
        tampered = cj.canonical_dumps(raw)
        parsed = sbom_schema.parse_sbom(tampered)
        with self.assertRaises(ApplianceError) as ctx:
            inspect_sbom.compare_sbom(parsed, self.lock)
        self.assertEqual(ctx.exception.reason_code, "CP_SBOM_DIFF")

    def test_reject_duplicate_package_id(self) -> None:
        data = self._build()
        raw = json.loads(data)
        raw["packages"].append(dict(raw["packages"][0]))
        raw["packages"].sort(key=lambda p: p["SPDXID"])
        tampered = cj.canonical_dumps(raw)
        with self.assertRaises(ApplianceError) as ctx:
            sbom_schema.parse_sbom(tampered)
        self.assertEqual(ctx.exception.reason_code, "CP_SBOM_SCHEMA")

    def test_reject_unsorted_files(self) -> None:
        data = self._build()
        raw = json.loads(data)
        raw["files"].reverse()
        tampered = cj.canonical_dumps(raw)
        with self.assertRaises(ApplianceError) as ctx:
            sbom_schema.parse_sbom(tampered)
        self.assertEqual(ctx.exception.reason_code, "CP_SBOM_SCHEMA")


if __name__ == "__main__":
    unittest.main(verbosity=2)
