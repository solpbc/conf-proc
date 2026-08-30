#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Focused producer and inspector tests for the SPP boot v3 payload."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from dataclasses import asdict, fields
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_provenance_v2_inspect import InspectionResult
import conf_proc_spp_boot_payload_v3 as payload
import conf_proc_spp_boot_payload_v3_inspect as independent
from conf_proc_spp_boot_v3 import BootBindingV3
from conf_proc_spp_reasons_v3 import (
    ApplianceErrorV3,
    CP_SPP_PAYLOAD_V3_AUTHORITY,
    CP_SPP_PAYLOAD_V3_PLAN,
)
from conf_proc_spp_boot_payload_v3_fixture import (
    SOURCE_ARCHIVE_PATHS_V3,
    matching_h4_h5_v3,
    plan_bytes_v3,
)


class BootPayloadV3Selftest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.h4_fixture, cls.inspection, cls.binding = matching_h4_h5_v3()

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
        for index, archive_path in enumerate(SOURCE_ARCHIVE_PATHS_V3):
            source_path = f"source-{index}.py"
            shutil.copyfile(ROOT / Path(archive_path).name, self.source_root / source_path)
            os.chmod(self.source_root / source_path, 0o600)
            self.source_paths.append(source_path)
        self.plan = plan_bytes_v3(self.binding, self.source_paths)

    def _compile(self, plan: bytes | None = None):
        return payload.compile_boot_payload_v3(
            inspection=self.inspection,
            binding=self.binding,
            plan_bytes=self.plan if plan is None else plan,
            source_root=str(self.source_root),
            output_root=str(self.output_root),
        )

    def test_compile_and_independent_inspection_round_trip(self) -> None:
        result = self._compile()
        output = Path(result.output_path)
        cpio = (output / "spp-boot-payload.cpio").read_bytes()
        package = (output / "spp-boot-payload.package.json").read_bytes()
        self.assertEqual(result.state, "built_unqualified")
        self.assertEqual(len(payload._parse_newc(cpio)), 29)
        self.assertEqual(hashlib.sha256(cpio).hexdigest(), result.cpio_sha256)
        self.assertEqual(hashlib.sha256(package).hexdigest(), result.package_sha256)
        inspected = independent.inspect_boot_payload_v3(
            inspection=self.inspection,
            binding=self.binding,
            cpio_bytes=cpio,
            package_bytes=package,
            output_path=str(output),
        )
        self.assertEqual(inspected.state, "artifact_consistent")
        self.assertEqual(inspected.cpio_sha256, result.cpio_sha256)
        self.assertEqual(self._compile(), result)

    def test_issued_authority_and_plan_rejections(self) -> None:
        with self.assertRaisesRegex(ApplianceErrorV3, CP_SPP_PAYLOAD_V3_AUTHORITY):
            payload.compile_boot_payload_v3(
                inspection=self.inspection,
                binding=object(),
                plan_bytes=self.plan,
                source_root="/does-not-exist",
                output_root="/does-not-exist",
            )
        copied_inspection = InspectionResult(**asdict(self.inspection))
        with self.assertRaisesRegex(ApplianceErrorV3, CP_SPP_PAYLOAD_V3_AUTHORITY):
            payload.compile_boot_payload_v3(
                inspection=copied_inspection,
                binding=self.binding,
                plan_bytes=self.plan,
                source_root="/does-not-exist",
                output_root="/does-not-exist",
            )
        forged_binding = BootBindingV3(**{field.name: getattr(self.binding, field.name) for field in fields(BootBindingV3)})
        with self.assertRaisesRegex(ApplianceErrorV3, CP_SPP_PAYLOAD_V3_AUTHORITY):
            payload.compile_boot_payload_v3(
                inspection=self.inspection,
                binding=forged_binding,
                plan_bytes=self.plan,
                source_root="/does-not-exist",
                output_root="/does-not-exist",
            )
        for field, replacement in (("schema", "conf-proc-spp-boot-payload-plan/v2"), ("boot_contract_sha256", "0" * 64), ("module_plan_sha256", "0" * 64)):
            plan = canonical_loads(self.plan)
            plan[field] = replacement
            with self.assertRaisesRegex(ApplianceErrorV3, CP_SPP_PAYLOAD_V3_PLAN):
                self._compile(canonical_dumps(plan))

    def test_inspector_rejects_tampered_package_archive_and_address(self) -> None:
        result = self._compile()
        output = Path(result.output_path)
        cpio = (output / "spp-boot-payload.cpio").read_bytes()
        package = (output / "spp-boot-payload.package.json").read_bytes()

        def rejected(*, cpio_bytes: bytes = cpio, package_bytes: bytes = package, address: str = str(output)) -> None:
            with self.assertRaises(ApplianceErrorV3):
                independent.inspect_boot_payload_v3(
                    inspection=self.inspection,
                    binding=self.binding,
                    cpio_bytes=cpio_bytes,
                    package_bytes=package_bytes,
                    output_path=address,
                )

        value = canonical_loads(package)
        value["cpio_sha256"] = "0" * 64
        rejected(package_bytes=canonical_dumps(value))
        value = canonical_loads(package)
        value["schema"] = "conf-proc-spp-boot-payload-package/v2"
        rejected(package_bytes=canonical_dumps(value))
        rejected(cpio_bytes=cpio[:-128])
        rejected(address=str(output.parent / ("0" * 64)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
