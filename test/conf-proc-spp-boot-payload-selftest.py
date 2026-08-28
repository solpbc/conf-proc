#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Focused producer tests for the direct SPP boot-payload compiler."""

from __future__ import annotations

import errno
import hashlib
import os
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
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

import conf_proc_prohibited as prohibited
import conf_proc_spp_boot as boot
import conf_proc_spp_boot_payload as payload
import conf_proc_provenance_v2_inspect as inspector
from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_reasons import (
    ApplianceError,
    CP_SPP_PAYLOAD_ADDRESS,
    CP_SPP_PAYLOAD_ARCHIVE,
    CP_SPP_PAYLOAD_AUTHORITY,
    CP_SPP_PAYLOAD_PLAN,
    CP_SPP_PAYLOAD_POLICY,
    CP_SPP_PAYLOAD_SOURCE,
)
from conf_proc_spp_boot_payload_fixture import matching_h4_h5, plan_bytes


class BootPayloadSelftest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.h4_fixture, cls.inspection, cls.binding = matching_h4_h5()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.h4_fixture.cleanup()

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
        self.plan = plan_bytes(self.binding, self.source_paths)

    def _compile(self) -> payload.BootPayloadResult:
        return self._compile_plan(self.plan)

    def _compile_plan(self, plan_bytes: bytes) -> payload.BootPayloadResult:
        return payload.compile_boot_payload(
            inspection=self.inspection, binding=self.binding, plan_bytes=plan_bytes,
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
        package_value = canonical_loads(package)
        self.assertEqual(
            set(package_value),
            {
                "schema", "package_version", "status", "boot_qualification", "runtime_closure",
                "activation_closure", "directory_closure", "h4_artifact_input_sha256",
                "h4_execution_provenance_sha256", "boot_contract_sha256", "module_plan_sha256",
                "cpio_sha256", "entries", "external_imports_declared_unresolved",
            },
        )
        self.assertEqual(package_value["schema"], "conf-proc-spp-boot-payload-package/v1")
        self.assertEqual(package_value["package_version"], 1)
        self.assertEqual(package_value["status"], "built_unqualified")
        self.assertEqual(package_value["boot_qualification"], "not_qualified")
        self.assertEqual(
            (package_value["runtime_closure"], package_value["activation_closure"], package_value["directory_closure"]),
            ("unresolved", "unresolved", "unresolved"),
        )
        self.assertEqual(package_value["entries"].count(package_value["entries"][0]), 1)
        self.assertEqual(package_value["cpio_sha256"], first.cpio_sha256)
        self.assertEqual(package_value["boot_contract_sha256"], self.binding.boot_contract_sha256)
        self.assertEqual(package_value["module_plan_sha256"], self.binding.module_plan_sha256)
        self.assertEqual(
            set(package_value["entries"][0]),
            {"path", "role", "mode", "size_bytes", "sha256"},
        )
        self.assertEqual(Path(first.output_path).name, first.package_sha256)
        self.assertEqual(Path(first.output_path).parent.name, first.cpio_sha256)
        self.assertEqual(Path(first.output_path).parent.parent.name, self.binding.boot_contract_sha256)
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
        decoded["entries"][0], decoded["entries"][1] = decoded["entries"][1], decoded["entries"][0]
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_PLAN):
            self._compile_plan(canonical_dumps(decoded))
        decoded = canonical_loads(self.plan)
        decoded["entries"][0]["source_path"] = 1
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_PLAN):
            self._compile_plan(canonical_dumps(decoded))
        decoded = canonical_loads(self.plan)
        decoded["schema"] = "conf-proc-spp-boot-payload-plan/v0"
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_PLAN):
            self._compile_plan(canonical_dumps(decoded))
        decoded = canonical_loads(self.plan)
        decoded["plan_version"] = True
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_PLAN):
            self._compile_plan(canonical_dumps(decoded))
        for field in ("boot_contract_sha256", "module_plan_sha256"):
            decoded = canonical_loads(self.plan)
            decoded[field] = "0" * 64
            with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_PLAN):
                self._compile_plan(canonical_dumps(decoded))
        decoded = canonical_loads(self.plan)
        decoded["entries"][0]["source_path"] = "nested"
        decoded["entries"][1]["source_path"] = "nested/child.py"
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_PLAN):
            self._compile_plan(canonical_dumps(decoded))

    def test_literal_authority_validator_rejects_malformed_or_replaced_map(self) -> None:
        with patch.object(payload, "BOOT_PAYLOAD_SOURCE_AUTHORITY", (object(),) * 9):
            with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_AUTHORITY):
                payload._validate_literal_authority()
        rows = list(payload.BOOT_PAYLOAD_SOURCE_AUTHORITY)
        item = rows[0]
        rows[0] = payload._SourceAuthority(item.archive_path, item.role, item.mode, item.size_bytes + 1, item.sha256)
        with patch.object(payload, "BOOT_PAYLOAD_SOURCE_AUTHORITY", tuple(rows)):
            with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_AUTHORITY):
                payload._validate_literal_authority()

    def test_source_digest_and_scanner_errors_are_sanitized(self) -> None:
        Path(self.source_root, self.source_paths[0]).write_bytes(b"changed")
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_SOURCE):
            self._compile()
        authority = payload.BOOT_PAYLOAD_SOURCE_AUTHORITY[0]
        fake = payload._FrozenSource(
            authority=authority,
            relative_path="input.py",
            parent_fd=-1,
            parent_identity=payload._Identity(0, 0, 0, 0, 0, 1, 0, 0, 0),
            leaf_name="input.py",
            descriptor=-1,
            identity=payload._Identity(0, 0, 0, 0, 0, 1, 0, 0, 0),
            data=b"",
        )
        for marker in prohibited._CONTENT_MARKERS:
            object.__setattr__(fake, "data", b"prefix " + marker + b" suffix")
            with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_POLICY) as caught:
                payload._check_source_content(fake)
            self.assertNotIn(authority.archive_path, str(caught.exception))
            self.assertIn(authority.sha256[:16], str(caught.exception))
        object.__setattr__(fake, "data", b"ssh-ed25519x ")
        payload._check_source_content(fake)

    def test_public_error_severs_private_exception_context(self) -> None:
        private_path = "/private/owner-content/secret"
        with patch.object(payload, "_open_pinned_root", side_effect=OSError(errno.EIO, private_path)):
            with self.assertRaises(ApplianceError) as caught:
                self._compile()
        self.assertNotIn(private_path, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_fifo_source_is_rejected_without_reading(self) -> None:
        source = Path(self.source_root, self.source_paths[0])
        source.unlink()
        os.mkfifo(source, 0o600)
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_SOURCE):
            self._compile()

    def test_final_source_revalidation_refuses_changed_frozen_leaf(self) -> None:
        source_pin = payload._open_pinned_root(str(self.source_root))
        output_pin = payload._open_pinned_root(str(self.output_root))
        sources: list[payload._FrozenSource] = []
        try:
            for authority, source_path in zip(payload.BOOT_PAYLOAD_SOURCE_AUTHORITY, self.source_paths, strict=True):
                sources.append(payload._read_source(source_pin, authority, source_path))
            frozen = tuple(sources)
            members = payload._members(frozen, self.binding)
            cpio = payload._newc_archive(members)
            package = payload._package_bytes(self.inspection, self.binding, cpio, members, payload._import_closure(frozen))
            address = payload._payload_address(self.binding, cpio, package)
            Path(self.source_root, self.source_paths[0]).write_bytes(b"changed after freeze")
            with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_SOURCE):
                payload._publish(source_pin, frozen, output_pin, self.binding, cpio, package, address)
        finally:
            for source in reversed(sources):
                source.close()
            output_pin.close()
            source_pin.close()

    def test_existing_address_must_be_exact(self) -> None:
        result = self._compile()
        address = Path(result.output_path)
        os.chmod(address, 0o700)
        Path(address, "unexpected").write_bytes(b"x")
        os.chmod(address, 0o555)
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_ADDRESS):
            self._compile()

    def test_builder_parser_has_direct_consistency_coverage(self) -> None:
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_ARCHIVE):
            payload._parse_newc(b"not-a-cpio")


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o7777


if __name__ == "__main__":
    unittest.main(verbosity=2)
