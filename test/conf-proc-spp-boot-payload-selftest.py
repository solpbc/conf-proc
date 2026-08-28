#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Focused producer tests for the direct SPP boot-payload compiler."""

from __future__ import annotations

import hashlib
import os
import runpy
import shutil
import sys
import tempfile
import unittest
from dataclasses import asdict, fields
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import conf_proc_prohibited as prohibited
import conf_proc_spp_boot as boot
import conf_proc_spp_boot_payload as payload
import conf_proc_provenance_v2_inspect as inspector
from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_reasons import ApplianceError, CP_SPP_PAYLOAD_ADDRESS, CP_SPP_PAYLOAD_AUTHORITY, CP_SPP_PAYLOAD_PLAN, CP_SPP_PAYLOAD_SOURCE


_BOOT_TEST = runpy.run_path(str(ROOT / "test" / "conf-proc-spp-boot-selftest.py"))


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _inspection(binding: boot.BootBinding) -> inspector.InspectionResult:
    values = {
        "state": "artifact_consistent",
        "hardware_qualification": "not_qualified",
        "artifact_input_sha256": _digest("artifact"),
        "execution_provenance_sha256": _digest("execution"),
        "models_squashfs_sha256": _digest("models-sq"),
        "models_verity_sha256": _digest("models-ve"),
        "runtime_policy_squashfs_sha256": _digest("runtime-sq"),
        "runtime_policy_verity_sha256": _digest("runtime-ve"),
        "manifest_sha256": binding.accepted_manifest_sha256,
        "spdx_sha256": _digest("spdx"),
        "evidence_ceiling": "No additional proof.",
    }
    with patch.object(inspector, "_inspect_values", return_value=values):
        return inspector.inspect_bundle(
            root_lock_path="unused", runtime_closure_path="unused", verity_rules_path="unused",
            tcb_identity_path="unused", builder_source_path="unused", policy_path="unused",
            input_root="unused", tool_root="unused", bundle="unused",
        )


def _plan(binding: boot.BootBinding, source_paths: list[str]) -> bytes:
    return canonical_dumps({
        "schema": "conf-proc-spp-boot-payload-plan/v1",
        "boot_contract_sha256": binding.boot_contract_sha256,
        "module_plan_sha256": binding.module_plan_sha256,
        "sources": [
            {"archive_path": authority.archive_path, "source_path": source_path}
            for authority, source_path in zip(payload.BOOT_PAYLOAD_SOURCE_AUTHORITY, source_paths, strict=True)
        ],
    })


class BootPayloadSelftest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.binding = boot.bind_boot_inputs(**_BOOT_TEST["build_compact_fixture"]())

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/var/tmp")
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.source_root = base / "source"
        self.output_root = base / "output"
        self.source_root.mkdir(mode=0o700)
        self.output_root.mkdir(mode=0o700)
        self.source_paths: list[str] = []
        for index, authority in enumerate(payload.BOOT_PAYLOAD_SOURCE_AUTHORITY):
            source_path = f"input-{index}.py"
            shutil.copyfile(ROOT / Path(authority.archive_path).name, self.source_root / source_path)
            os.chmod(self.source_root / source_path, 0o600)
            self.source_paths.append(source_path)
        self.inspection = _inspection(self.binding)
        self.plan = _plan(self.binding, self.source_paths)

    def _compile(self) -> payload.BootPayloadResult:
        return payload.compile_boot_payload(
            inspection=self.inspection, binding=self.binding, plan_bytes=self.plan,
            source_root=str(self.source_root), output_root=str(self.output_root),
        )

    def test_positive_shape_authority_and_deterministic_idempotence(self) -> None:
        first = self._compile()
        cpio = Path(first.output_path, "spp-boot-payload.cpio").read_bytes()
        package = Path(first.output_path, "spp-boot-payload.package.json").read_bytes()
        self.assertEqual(first.state, "built_unqualified")
        self.assertEqual(len(payload._parse_newc(cpio)), 21)
        self.assertEqual(hashlib.sha256(cpio).hexdigest(), first.cpio_sha256)
        self.assertEqual(hashlib.sha256(package).hexdigest(), first.package_sha256)
        self.assertEqual(canonical_loads(package)["entries"].count(canonical_loads(package)["entries"][0]), 1)
        self.assertNotIn(b"conf-proc-spp-boot-payload-plan", cpio + package)
        self.assertEqual(stat_mode(Path(first.output_path)), 0o555)
        for name in ("spp-boot-payload.cpio", "spp-boot-payload.package.json"):
            self.assertEqual(stat_mode(Path(first.output_path, name)), 0o444)
        second = self._compile()
        self.assertEqual(second, first)

    def test_h4_h5_exact_instance_seals_fail_before_source_io(self) -> None:
        copied_inspection = inspector.InspectionResult(**asdict(self.inspection))
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_AUTHORITY):
            payload.compile_boot_payload(
                inspection=copied_inspection, binding=self.binding, plan_bytes=self.plan,
                source_root="/does-not-exist", output_root="/does-not-exist",
            )
        forged_binding = boot.BootBinding(**{field.name: getattr(self.binding, field.name) for field in fields(boot.BootBinding)})
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_AUTHORITY):
            payload.compile_boot_payload(
                inspection=self.inspection, binding=forged_binding, plan_bytes=self.plan,
                source_root="/does-not-exist", output_root="/does-not-exist",
            )

    def test_plan_schema_order_and_type_rejections(self) -> None:
        decoded = canonical_loads(self.plan)
        decoded["sources"][0], decoded["sources"][1] = decoded["sources"][1], decoded["sources"][0]
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_PLAN):
            payload.compile_boot_payload(inspection=self.inspection, binding=self.binding, plan_bytes=canonical_dumps(decoded), source_root=str(self.source_root), output_root=str(self.output_root))
        decoded = canonical_loads(self.plan)
        decoded["sources"][0]["source_path"] = 1
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_PLAN):
            payload.compile_boot_payload(inspection=self.inspection, binding=self.binding, plan_bytes=canonical_dumps(decoded), source_root=str(self.source_root), output_root=str(self.output_root))

    def test_source_digest_and_scanner_errors_are_sanitized(self) -> None:
        Path(self.source_root, self.source_paths[0]).write_bytes(b"changed")
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_SOURCE):
            self._compile()
        authority = payload.BOOT_PAYLOAD_SOURCE_AUTHORITY[0]
        fake = payload._FrozenSource(authority, "input.py", -1, "input.py", -1, payload._Identity(0, 0, 0, 0, 0, 1, 0, 0, 0), b"")
        for marker in prohibited._CONTENT_MARKERS:
            object.__setattr__(fake, "data", b"prefix " + marker + b" suffix")
            with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_SOURCE) as caught:
                payload._check_source_content(fake)
            self.assertNotIn(authority.archive_path, str(caught.exception))
            self.assertIn(authority.sha256[:16], str(caught.exception))
        object.__setattr__(fake, "data", b"ssh-ed25519x ")
        payload._check_source_content(fake)

    def test_existing_address_must_be_exact(self) -> None:
        result = self._compile()
        address = Path(result.output_path)
        os.chmod(address, 0o700)
        Path(address, "unexpected").write_bytes(b"x")
        os.chmod(address, 0o555)
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_ADDRESS):
            self._compile()

    def test_builder_parser_has_direct_consistency_coverage(self) -> None:
        with self.assertRaises(ApplianceError):
            payload._parse_newc(b"not-a-cpio")


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o7777


if __name__ == "__main__":
    unittest.main(verbosity=2)
