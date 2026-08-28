#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded authority-input checks for the dormant H3 assembler."""

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
from conf_proc_lock import (  # noqa: E402
    ROLE_BUILD_TOOL,
    ROLE_CONF_PROC_SOURCE,
    ROLE_KERNEL_TRUSTED_CERT_BUNDLE,
    ROLE_POLICY_TREE_INPUT,
)
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tcb() -> bytes:
    def executable(name: str, marker: int) -> dict:
        return {
            "logical_name": name,
            "sha256": format(marker, "064x"),
            "linkage": "static",
            "interpreter_sha256": None,
            "loader_sha256": None,
            "library_sha256s": [],
        }

    return cj.canonical_dumps(
        {
            "schema": "conf-proc-pre-sandbox-tcb/v1",
            "status": "declared_unverified",
            "caller": executable("caller", 1),
            "launcher": executable("launcher", 2),
            "sandbox": {"backend": "bubblewrap", "executable": executable("sandbox", 3), "helper": None},
            "kernel_feature_contract": {"schema": "conf-proc-kernel-features/v1", "sha256": format(4, "064x")},
        }
    )


def _authority_bundle() -> dict[str, bytes]:
    roles = (
        "kernel",
        ROLE_KERNEL_TRUSTED_CERT_BUNDLE,
        "final_systemd_stub",
        "final_systemd_unit",
        "nvidia_cc_driver",
        "nvidia_cc_firmware",
        ROLE_CONF_PROC_SOURCE,
        "sglang_image",
        "inference_model",
        "asr_model",
        "gateway_dependency_lock",
        "asr_dependency_lock",
        "runtime_tree_input",
        ROLE_POLICY_TREE_INPUT,
    )
    policy = cj.canonical_dumps({"schema": "conf-proc-policy/v1"})
    records: list[dict] = []
    closure_entries: list[dict] = []
    for index, role in enumerate(roles):
        input_id = "policy" if role == ROLE_POLICY_TREE_INPUT else "input-" + str(index)
        data = policy if role == ROLE_POLICY_TREE_INPUT else (role + " bytes").encode("ascii")
        digest = _sha(data)
        placements = []
        if role != ROLE_KERNEL_TRUSTED_CERT_BUNDLE:
            path = "/authority/" + input_id
            placements = [
                {
                    "image": "models",
                    "path": path,
                    "node_type": "file",
                    "mode": 0o644,
                    "uid": 0,
                    "gid": 0,
                    "xattrs": [],
                    "source_input_id": input_id,
                    "target": None,
                }
            ]
            closure_entries.append(
                {
                    "path": path,
                    "node_type": "file",
                    "mode": 0o644,
                    "uid": 0,
                    "gid": 0,
                    "size_bytes": len(data),
                    "sha256": digest,
                    "symlink_target": None,
                    "hardlink_group": None,
                    "xattrs": [],
                    "capabilities": [],
                    "logical_role": role,
                    "provenance": {"scheme": "local-fixture", "identity": input_id, "immutable_ref": "sha256:" + digest},
                    "root_lock_input_id": input_id,
                }
            )
        records.append(
            {
                "id": input_id,
                "role": role,
                "component": input_id,
                "sha256": digest,
                "size_bytes": len(data),
                "source_local_path": input_id,
                "source_retrieval_scheme": "local-fixture",
                "source_retrieval_identity": input_id,
                "source_retrieval_immutable_ref": "sha256:" + digest,
                "derivation_kind": "fixture",
                "derivation_recipe_id": "fixture-v1",
                "derivation_parent_ids": [],
                "derivation_parameters_sha256": _sha(b"parameters"),
                "placements": placements,
            }
        )
    tool_ids = []
    for component in ("mksquashfs", "unsquashfs", "veritysetup", "openssl"):
        input_id = "tool-" + component
        tool_ids.append(input_id)
        records.append(
            {
                "id": input_id,
                "role": ROLE_BUILD_TOOL,
                "component": component,
                "sha256": _sha(component.encode("ascii")),
                "size_bytes": len(component),
                "source_local_path": "tools/" + component,
                "source_retrieval_scheme": "local-fixture",
                "source_retrieval_identity": component,
                "source_retrieval_immutable_ref": "sha256:" + _sha(component.encode("ascii")),
                "derivation_kind": "fixture",
                "derivation_recipe_id": "fixture-v1",
                "derivation_parent_ids": [],
                "derivation_parameters_sha256": _sha(b"parameters"),
                "placements": [],
            }
        )
    lock = {
        "schema": "conf-proc-lock/v1",
        "lock_version": 1,
        "base_image_record": {
            "kind": "vhd", "provider": "fixture", "identity_namespace": "fixture", "identity_name": "input",
            "identity_immutable_revision": "1", "content_sha256": _sha(b"base"), "content_size_bytes": 4,
            "content_media_type": "application/octet-stream", "availability": "record-only",
            "recorded_retrieval_scheme": "local-fixture", "recorded_retrieval_identity": "base",
            "recorded_retrieval_immutable_ref": "sha256:" + _sha(b"base"),
        },
        "future_cmdline": "console=ttyS0",
        "inputs": sorted(records, key=lambda item: item["id"]),
        "authorized_module_signers": [],
        "image_specs": {"models": {}, "runtime-policy": {}},
        "policy_input_id": "policy",
        "tool_ids": sorted(tool_ids),
    }
    source_entry = next(item for item in closure_entries if item["logical_role"] == ROLE_CONF_PROC_SOURCE)
    builder_source = (ROLE_CONF_PROC_SOURCE + " bytes").encode("ascii")
    assert source_entry["sha256"] == _sha(builder_source)
    return {
        "root_lock": cj.canonical_dumps(lock),
        "runtime_closure": cj.canonical_dumps(
            {"schema": "conf-proc-runtime-closure/v1", "status": "declared_unverified", "entries": sorted(closure_entries, key=lambda item: item["path"])}
        ),
        "verity_rules": provenance.supported_verity_rules_bytes(),
        "tcb_identity": _tcb(),
        "builder_source": builder_source,
        "policy": policy,
    }


class H3AuthorityInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)

    def test_bounded_reader_rejects_symlink_and_nonregular_input(self) -> None:
        regular = os.path.join(self.base, "regular")
        Path(regular).write_bytes(b"authority")
        symlink = os.path.join(self.base, "symlink")
        os.symlink(regular, symlink)
        with self.assertRaises(ApplianceError) as context:
            assembler._read_bounded(symlink, assembler._ReadBudget(assembler.MAX_TOTAL_INPUT_BYTES))
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_INPUT_READ")
        with self.assertRaises(ApplianceError) as context:
            assembler._read_bounded(self.base, assembler._ReadBudget(assembler.MAX_TOTAL_INPUT_BYTES))
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_INPUT_SIZE")

    def test_bounded_reader_detects_identity_change(self) -> None:
        path = os.path.join(self.base, "authority")
        Path(path).write_bytes(b"before")
        original_read = assembler.os.read
        changed = False

        def mutate_after_first_read(descriptor: int, size: int) -> bytes:
            nonlocal changed
            value = original_read(descriptor, size)
            if not changed:
                changed = True
                Path(path).write_bytes(b"after!")
            return value

        assembler.os.read = mutate_after_first_read
        try:
            with self.assertRaises(ApplianceError) as context:
                assembler._read_bounded(path, assembler._ReadBudget(assembler.MAX_TOTAL_INPUT_BYTES))
        finally:
            assembler.os.read = original_read
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_INPUT_CHANGED")

    def test_authority_schema_and_cross_binding_fail_before_output(self) -> None:
        authorities = _authority_bundle()
        output = os.path.join(self.base, "output")
        with self.assertRaises(ApplianceError) as context:
            assembler.assemble(
                root_lock_path=os.path.join(self.base, "missing-root-lock"),
                runtime_closure_path=os.path.join(self.base, "missing-closure"),
                verity_rules_path=os.path.join(self.base, "missing-rules"),
                tcb_identity_path=os.path.join(self.base, "missing-tcb"),
                builder_source_path=os.path.join(self.base, "missing-source"),
                policy_path=os.path.join(self.base, "missing-policy"),
                input_root=self.base,
                tool_root=self.base,
                output=output,
            )
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_INPUT_READ")
        self.assertFalse(os.path.exists(output))
        with self.assertRaises(ApplianceError) as context:
            provenance.derive_inputs(
                root_lock_bytes=authorities["root_lock"],
                runtime_closure_bytes=authorities["runtime_closure"],
                verity_rules_bytes=authorities["verity_rules"],
                tcb_identity_bytes=authorities["tcb_identity"],
                builder_source_bytes=b"substituted source",
                policy_bytes=authorities["policy"],
            )
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_AUTHORITY")
        with self.assertRaises(ApplianceError) as context:
            provenance.parse_runtime_closure(b"{}")
        self.assertEqual(context.exception.reason_code, "CP_RUNTIME_CLOSURE_SCHEMA")
        noncanonical = (
            b'{"status":"declared_unverified", "schema":"conf-proc-runtime-closure/v1",'
            b'"entries":[]}'
        )
        with self.assertRaises(ApplianceError) as context:
            provenance.parse_runtime_closure(noncanonical)
        self.assertEqual(context.exception.reason_code, "CP_JSON_NONCANONICAL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
