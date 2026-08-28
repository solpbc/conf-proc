#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""H2 document production and H3 local-gate checks."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_json as cj  # noqa: E402
import conf_proc_provenance_v2 as provenance  # noqa: E402
import conf_proc_provenance_v2_assemble as assembler  # noqa: E402
from conf_proc_provenance_v2_build_manifest import (  # noqa: E402
    ProvenanceV2ImageRecord,
    produce_provenance_v2,
)
from conf_proc_reasons import ApplianceError  # noqa: E402


EXPECTED_MANIFEST_SHA256 = "0bde9aae93aad4d69fb90fa26f3ad1c362c40150118c98f8bee1073698064a33"
EXPECTED_SPDX_SHA256 = "c0118819a897acd5128f4125d8c64d82aedc972e5768d225903933a499415241"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tcb() -> bytes:
    def executable(name: str, marker: int) -> dict:
        return {"logical_name": name, "sha256": format(marker, "064x"), "linkage": "static", "interpreter_sha256": None, "loader_sha256": None, "library_sha256s": []}
    return cj.canonical_dumps({
        "schema": "conf-proc-pre-sandbox-tcb/v1", "status": "declared_unverified",
        "caller": executable("caller", 1), "launcher": executable("launcher", 2),
        "sandbox": {"backend": "bubblewrap", "executable": executable("sandbox", 3), "helper": None},
        "kernel_feature_contract": {"schema": "conf-proc-kernel-features/v1", "sha256": format(4, "064x")},
    })


def _fixture() -> tuple[object, list[ProvenanceV2ImageRecord], dict[str, bytes]]:
    roles = (
        "kernel", "kernel_trusted_cert_bundle", "final_systemd_stub", "final_systemd_unit", "nvidia_cc_driver",
        "nvidia_cc_firmware", "conf_proc_source", "sglang_image", "inference_model", "asr_model",
        "gateway_dependency_lock", "asr_dependency_lock", "runtime_tree_input", "policy_tree_input",
    )
    identifiers = ["policy" if role == "policy_tree_input" else "input" + str(index) for index, role in enumerate(roles)]
    nodes = [
        {"path": "/" + input_id, "node_type": "file", "mode": 0o644, "uid": 0, "gid": 0, "xattrs": [], "source_input_id": input_id, "target": None, "content_class": "runtime_data"}
        for input_id, role in zip(identifiers, roles) if role != "kernel_trusted_cert_bundle"
    ]
    policy = cj.canonical_dumps({
        "schema": "conf-proc-policy/v1", "policy_version": 1,
        "images": {"models": {"nodes": sorted(nodes, key=lambda item: item["path"])}, "runtime-policy": {"nodes": []}},
        "boot_roots": [], "process_nodes": [], "process_edges": [], "mounts": [], "network_policy": {}, "capability_policy": {},
    })
    contents = {input_id: (policy if role == "policy_tree_input" else (b"builder" if role == "conf_proc_source" else input_id.encode("ascii"))) for input_id, role in zip(identifiers, roles)}
    inputs, closure = [], []
    for input_id, role in zip(identifiers, roles):
        data = contents[input_id]
        placements = []
        if role != "kernel_trusted_cert_bundle":
            placements = [{"image": "models", "path": "/" + input_id, "node_type": "file", "mode": 0o644, "uid": 0, "gid": 0, "xattrs": [], "source_input_id": input_id, "target": None}]
            closure.append({"path": "/" + input_id, "node_type": "file", "mode": 0o644, "uid": 0, "gid": 0, "size_bytes": len(data), "sha256": _sha(data), "symlink_target": None, "hardlink_group": None, "xattrs": [], "capabilities": [], "logical_role": role, "provenance": {"scheme": "local-fixture", "identity": input_id, "immutable_ref": "sha256:" + _sha(data)}, "root_lock_input_id": input_id})
        inputs.append({"id": input_id, "role": role, "component": input_id, "sha256": _sha(data), "size_bytes": len(data), "source_local_path": input_id, "source_retrieval_scheme": "local-fixture", "source_retrieval_identity": input_id, "source_retrieval_immutable_ref": "sha256:" + _sha(data), "derivation_kind": "fixture", "derivation_recipe_id": "fixture-v1", "derivation_parent_ids": [], "derivation_parameters_sha256": _sha(b"params"), "placements": placements})
    tool_ids = []
    for component in ("mksquashfs", "unsquashfs", "veritysetup", "openssl"):
        input_id = "tool-" + component
        tool_ids.append(input_id)
        inputs.append({"id": input_id, "role": "build_tool", "component": component, "sha256": _sha(component.encode()), "size_bytes": len(component), "source_local_path": "tools/" + component, "source_retrieval_scheme": "local-fixture", "source_retrieval_identity": component, "source_retrieval_immutable_ref": "sha256:" + _sha(component.encode()), "derivation_kind": "fixture", "derivation_recipe_id": "fixture-v1", "derivation_parent_ids": [], "derivation_parameters_sha256": _sha(b"params"), "placements": []})
    lock = cj.canonical_dumps({
        "schema": "conf-proc-lock/v1", "lock_version": 1,
        "base_image_record": {"kind": "vhd", "provider": "fixture", "identity_namespace": "fixture", "identity_name": "documents", "identity_immutable_revision": "1", "content_sha256": _sha(b"base"), "content_size_bytes": 4, "content_media_type": "application/octet-stream", "availability": "record-only", "recorded_retrieval_scheme": "local-fixture", "recorded_retrieval_identity": "base", "recorded_retrieval_immutable_ref": "sha256:" + _sha(b"base")},
        "future_cmdline": "console=ttyS0", "inputs": sorted(inputs, key=lambda item: item["id"]), "authorized_module_signers": [],
        "image_specs": {"models": {}, "runtime-policy": {}}, "policy_input_id": "policy", "tool_ids": sorted(tool_ids),
    })
    inputs_value = provenance.derive_inputs(root_lock_bytes=lock, runtime_closure_bytes=cj.canonical_dumps({"schema": "conf-proc-runtime-closure/v1", "status": "declared_unverified", "entries": sorted(closure, key=lambda item: item["path"])}), verity_rules_bytes=provenance.supported_verity_rules_bytes(), tcb_identity_bytes=_tcb(), builder_source_bytes=b"builder", policy_bytes=policy)
    payloads = {
        "models.squashfs": b"m" * 4096, "models.verity": b"v" * 4096,
        "runtime-policy.squashfs": b"r" * 4096, "runtime-policy.verity": b"h" * 4096,
    }
    records = [
        ProvenanceV2ImageRecord("models", _sha(payloads["models.squashfs"]), 4096, _sha(payloads["models.verity"]), 4096, "1" * 64),
        ProvenanceV2ImageRecord("runtime-policy", _sha(payloads["runtime-policy.squashfs"]), 4096, _sha(payloads["runtime-policy.verity"]), 4096, "2" * 64),
    ]
    return inputs_value, records, payloads


class H3DocumentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.inputs, self.records, self.payloads = _fixture()

    def _artifacts(self):
        return produce_provenance_v2(
            root_lock_bytes=self.inputs.root_lock_bytes, runtime_closure_bytes=self.inputs.runtime_closure_bytes,
            verity_rules_bytes=self.inputs.verity_rules_bytes, tcb_identity_bytes=self.inputs.tcb_identity_bytes,
            builder_source_bytes=self.inputs.builder_source_bytes, policy_bytes=self.inputs.policy_bytes,
            images=tuple(self.records), module_observations=(), firmware_observations=(),
        )

    def _stage(self) -> tuple[str, object]:
        artifacts = self._artifacts()
        stage = os.path.join(self.base, "stage")
        os.mkdir(stage)
        for name, data in self.payloads.items():
            Path(os.path.join(stage, name)).write_bytes(data)
        Path(os.path.join(stage, "appliance.manifest.json")).write_bytes(artifacts.manifest_bytes)
        Path(os.path.join(stage, "appliance.spdx.json")).write_bytes(artifacts.spdx_bytes)
        return stage, artifacts

    def test_h2_documents_match_independent_fixed_expectations(self) -> None:
        artifacts = self._artifacts()
        self.assertEqual(_sha(artifacts.manifest_bytes), EXPECTED_MANIFEST_SHA256)
        self.assertEqual(_sha(artifacts.spdx_bytes), EXPECTED_SPDX_SHA256)
        manifest = cj.canonical_loads(artifacts.manifest_bytes)
        self.assertEqual(manifest["images"]["models"]["squashfs_sha256"], self.records[0].squashfs_sha256)
        self.assertEqual(manifest["provenance"]["artifact_input_sha256"], self.inputs.artifact_input_sha256)

    def test_local_gate_catches_each_document_binding_tamper(self) -> None:
        stage, artifacts = self._stage()
        manifest = cj.canonical_loads(artifacts.manifest_bytes)
        manifest["sbom"]["sha256"] = "0" * 64
        Path(os.path.join(stage, "appliance.manifest.json")).write_bytes(cj.canonical_dumps(manifest))
        with self.assertRaises(ApplianceError) as context:
            assembler._local_gate(stage, self.inputs, self.records)
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_LOCAL_GATE")

        Path(os.path.join(stage, "appliance.manifest.json")).write_bytes(artifacts.manifest_bytes)
        manifest = cj.canonical_loads(artifacts.manifest_bytes)
        manifest["images"]["models"]["squashfs_sha256"] = "0" * 64
        Path(os.path.join(stage, "appliance.manifest.json")).write_bytes(cj.canonical_dumps(manifest))
        with self.assertRaises(ApplianceError) as context:
            assembler._local_gate(stage, self.inputs, self.records)
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_LOCAL_GATE")

        Path(os.path.join(stage, "appliance.manifest.json")).write_bytes(artifacts.manifest_bytes)
        manifest = cj.canonical_loads(artifacts.manifest_bytes)
        manifest["provenance"]["artifact_input_sha256"] = "0" * 64
        Path(os.path.join(stage, "appliance.manifest.json")).write_bytes(cj.canonical_dumps(manifest))
        with self.assertRaises(ApplianceError) as context:
            assembler._local_gate(stage, self.inputs, self.records)
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_LOCAL_GATE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
