#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exhaustive H4 document population and required sealed-binding tests."""

from __future__ import annotations

import copy
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "test")]

import conf_proc_json as cj  # noqa: E402
import conf_proc_provenance_v2_inspect as inspector  # noqa: E402
from conf_proc_provenance_v2_inspect_documents import check_documents, derive_inspection_inputs  # noqa: E402
from conf_proc_provenance_v2_inspect_fixture import build_positive_fixture  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


class H4InspectorDocumentsSealedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = build_positive_fixture()
        self.addCleanup(self.fixture.cleanup)
        h3 = self.fixture.h3
        self.inputs = derive_inspection_inputs(
            root_lock_bytes=Path(h3.lock_path).read_bytes(),
            runtime_closure_bytes=Path(h3.closure_path).read_bytes(),
            verity_rules_bytes=Path(h3.rules_path).read_bytes(),
            tcb_identity_bytes=Path(h3.tcb_path).read_bytes(),
            builder_source_bytes=Path(h3._input("source.py")).read_bytes(),
            policy_bytes=Path(h3.policy_path).read_bytes(),
        )
        self.manifest_bytes = Path(self.fixture.bundle, "appliance.manifest.json").read_bytes()
        self.spdx_bytes = Path(self.fixture.bundle, "appliance.spdx.json").read_bytes()
        self.manifest = cj.canonical_loads(self.manifest_bytes)
        self.spdx = cj.canonical_loads(self.spdx_bytes)
        self.evidence = _evidence(self.inputs.lock, self.manifest)

    def _document_rejects(self, manifest_bytes: bytes, spdx_bytes: bytes) -> None:
        with self.assertRaises(ApplianceError) as context:
            check_documents(manifest_bytes=manifest_bytes, spdx_bytes=spdx_bytes, inputs=self.inputs, evidence=self.evidence)
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH")

    def test_each_deleted_spdx_relationship_is_shape_accepted_but_h4_rejected(self) -> None:
        self.assertTrue(self.spdx["relationships"])
        for index in range(len(self.spdx["relationships"])):
            with self.subTest(index=index):
                mutated = copy.deepcopy(self.spdx)
                del mutated["relationships"][index]
                bytes_ = cj.canonical_dumps(mutated)
                coherent_manifest = copy.deepcopy(self.manifest)
                coherent_manifest["sbom"]["sha256"] = hashlib.sha256(bytes_).hexdigest()
                manifest_bytes = cj.canonical_dumps(coherent_manifest)
                self.assertTrue(_sealed_accepts(self.fixture, manifest_bytes, bytes_))
                self._document_rejects(manifest_bytes, bytes_)

    def test_empty_stale_missing_and_extra_document_fields_are_rejected(self) -> None:
        self._document_rejects(b"{}", self.spdx_bytes)
        stale = copy.deepcopy(self.spdx)
        stale["name"] = "stale"
        self._document_rejects(self.manifest_bytes, cj.canonical_dumps(stale))
        missing = copy.deepcopy(self.manifest)
        del missing["provenance"]
        self._document_rejects(cj.canonical_dumps(missing), self.spdx_bytes)
        extra = copy.deepcopy(self.manifest)
        extra["unexpected"] = True
        self._document_rejects(cj.canonical_dumps(extra), self.spdx_bytes)

    def test_overall_inspection_requires_sealed_adapter_in_addition_to_documents(self) -> None:
        def reject(*args, **kwargs) -> None:
            raise ApplianceError("CP_PROVENANCE_V2_INSPECT_SEALED_BINDING", "test rejection")

        with patch.object(inspector, "_require_sealed_binding", reject):
            with self.assertRaises(ApplianceError) as context:
                inspector.inspect_bundle(**self.fixture.inspect_kwargs())
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_INSPECT_SEALED_BINDING")


def _evidence(lock, manifest: dict) -> dict:
    inventories = {"models": {}, "runtime-policy": {}}
    for item in lock.inputs:
        for placement in item.placements:
            inventories[placement.image][placement.path] = SimpleNamespace(
                node_type=placement.node_type,
                mode=placement.mode,
                uid=placement.uid,
                gid=placement.gid,
                xattrs=placement.xattrs,
                sha256=item.sha256 if placement.node_type == "file" else None,
                size=item.size_bytes if placement.node_type == "file" else 0,
                symlink_target=placement.target,
            )
    return {
        "images": {
            image: {key: manifest["images"][image][key] for key in (
                "squashfs_sha256", "squashfs_size_bytes", "hash_device_sha256", "hash_device_size_bytes", "root_hash"
            )}
            for image in ("models", "runtime-policy")
        },
        "inventories": inventories,
        "module_inventory": manifest["module_authority"]["module_inventory"],
        "firmware_inventory": manifest["module_authority"]["firmware_inventory"],
        "graph_nodes": [],
        "graph_edges": [],
    }


def _sealed_accepts(fixture, manifest_bytes: bytes, spdx_bytes: bytes) -> bool:
    with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
        manifest_path = Path(directory, "appliance.manifest.json")
        spdx_path = Path(directory, "appliance.spdx.json")
        manifest_path.write_bytes(manifest_bytes)
        spdx_path.write_bytes(spdx_bytes)
        h3 = fixture.h3
        completed = subprocess.run(
            [
                sys.executable, str(ROOT / "conf_proc_inspect_provenance_cli.py"),
                "--root-lock", h3.lock_path, "--runtime-closure", h3.closure_path,
                "--verity-rules", h3.rules_path, "--tcb-identity", h3.tcb_path,
                "--builder-source", h3._input("source.py"), "--policy", h3.policy_path,
                "--manifest", str(manifest_path), "--sbom", str(spdx_path),
            ],
            check=False,
            capture_output=True,
        )
        output = completed.stdout[:-1] if completed.stdout.endswith(b"\n") else completed.stdout
        return completed.returncode == 0 and cj.canonical_loads(output).get("accepted") is True


if __name__ == "__main__":
    unittest.main(verbosity=2)
