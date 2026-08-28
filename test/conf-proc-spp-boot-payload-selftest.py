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
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

import conf_proc_prohibited as prohibited
import conf_proc_spp_boot as boot
import conf_proc_spp_boot_payload as payload
import conf_proc_provenance_v2_inspect as inspector
from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_provenance_v2_inspect_fixture import build_positive_fixture
from conf_proc_reasons import ApplianceError, CP_SPP_PAYLOAD_ADDRESS, CP_SPP_PAYLOAD_AUTHORITY, CP_SPP_PAYLOAD_PLAN, CP_SPP_PAYLOAD_SOURCE


_BOOT_TEST = runpy.run_path(str(ROOT / "test" / "conf-proc-spp-boot-selftest.py"))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _matching_h4_h5() -> tuple[object, inspector.InspectionResult, boot.BootBinding]:
    """Build a real H3 bundle that is also a fresh H5 binding predecessor."""

    fixture = build_positive_fixture()
    h3 = fixture.h3
    policy = canonical_loads(h3.policy_bytes)
    policy["boot_roots"] = ["unit:h3.service"]
    policy["mounts"] = [
        {"unit_id": "unit:h3.service", "image": "models", "destination": "/mnt/spp-models", "fs_type": "squashfs", "read_only": True},
        {"unit_id": "unit:h3.service", "image": "runtime-policy", "destination": "/mnt/spp-runtime", "fs_type": "squashfs", "read_only": True},
    ]
    serve_path = "/usr/lib/modules/h3/serve.ko"
    policy["images"]["runtime-policy"]["nodes"].append(
        {
            "path": serve_path,
            "node_type": "file",
            "mode": 0o644,
            "uid": h3.uid,
            "gid": h3.gid,
            "xattrs": [],
            "source_input_id": "driver",
            "target": None,
            "content_class": "runtime_data",
        }
    )
    policy["images"]["runtime-policy"]["nodes"].sort(key=lambda item: item["path"])
    h3.policy_bytes = canonical_dumps(policy)
    Path(h3.policy_path).write_bytes(h3.policy_bytes)
    h3.contents["policy-copy.json"] = h3.policy_bytes
    Path(h3._input("policy-copy.json")).write_bytes(h3.policy_bytes)
    h3.placements.append(
        {
            "image": "runtime-policy",
            "path": serve_path,
            "node_type": "file",
            "mode": 0o644,
            "uid": h3.uid,
            "gid": h3.gid,
            "xattrs": [],
            "source_input_id": "driver",
            "target": None,
        }
    )
    h3.placements.sort(key=lambda item: (item["image"], item["path"]))
    h3._write_lock(False)

    lock = canonical_loads(Path(h3.lock_path).read_bytes())
    kernel_sha256 = next(item["sha256"] for item in lock["inputs"] if item["role"] == "kernel")
    kernel_feature_contract_bytes = canonical_dumps(
        {
            "schema": "conf-proc-kernel-features/v1",
            "kernel_input_sha256": kernel_sha256,
            "kernel_release": "h3-fixture",
            "mutable_controls": [{"name": name, "support": "required"} for name in sorted(boot._CONTROL_ORDER)],
        }
    )
    tcb = canonical_loads(Path(h3.tcb_path).read_bytes())
    tcb["kernel_feature_contract"]["sha256"] = _sha256(kernel_feature_contract_bytes)
    Path(h3.tcb_path).write_bytes(canonical_dumps(tcb))

    assembly = h3.assemble()
    inspection_kwargs = fixture.inspect_kwargs()
    inspection_kwargs["bundle"] = assembly.bundle_path
    inspection = inspector.inspect_bundle(**inspection_kwargs)
    manifest_bytes = Path(assembly.bundle_path, "appliance.manifest.json").read_bytes()
    manifest = canonical_loads(manifest_bytes)
    identities = sorted(
        (
            {
                "path": item["path"],
                "sha256": item["sha256"],
                "signer_certificate_sha256": item["signer_certificate_sha256"],
            }
            for item in manifest["module_authority"]["module_inventory"]
        ),
        key=lambda item: item["path"],
    )
    if len(identities) != 2:
        raise AssertionError("real H3 fixture did not produce the required two-module H5 inventory")
    compact = _BOOT_TEST["build_compact_fixture"]()
    source_bytes = {
        "root_lock_bytes": Path(h3.lock_path).read_bytes(),
        "runtime_closure_bytes": Path(h3.closure_path).read_bytes(),
        "verity_rules_bytes": Path(h3.rules_path).read_bytes(),
        "tcb_identity_bytes": Path(h3.tcb_path).read_bytes(),
        "builder_source_bytes": Path(h3._input("source.py")).read_bytes(),
        "policy_bytes": Path(h3.policy_path).read_bytes(),
        "accepted_manifest_bytes": manifest_bytes,
        "kernel_feature_contract_bytes": kernel_feature_contract_bytes,
        "trusted_certificate_bundle_bytes": Path(h3._input("bundle.pem")).read_bytes(),
        "gpt_layout_rules_bytes": compact["gpt_layout_rules_bytes"],
    }
    predecessor = {
        name.removesuffix("_bytes") + "_sha256": _sha256(value)
        for name, value in source_bytes.items()
        if name not in {"gpt_layout_rules_bytes"}
    }
    contract = {
        "schema": "conf-proc-spp-boot-contract/v1",
        "contract_version": 1,
        "predecessor_sha256": predecessor,
        "image_order": ["models", "runtime-policy"],
        "module_roles": {"boot": [identities[0]], "serving": [identities[1]]},
        "non_runtime_loadable_modules": [],
        "tmpfs_mounts": [{"path": "/run/spp-state", "size_bytes": 1048576, "mode": 0o755}],
        "mutable_control_order": list(boot._CONTROL_ORDER),
        "observation_contract_sha256": boot.OBSERVATION_CONTRACT_SHA256,
        "gpt_layout_rules_sha256": _sha256(source_bytes["gpt_layout_rules_bytes"]),
    }
    boot_contract_bytes = canonical_dumps(contract)
    module_plan_bytes = canonical_dumps(
        {
            "schema": "conf-proc-spp-module-load-plan/v1",
            "plan_version": 1,
            "boot_contract_sha256": _sha256(boot_contract_bytes),
            "measurement_scope": "future-pcr4-only",
            "entries": [
                {"index": index, **identity, "predecessor_indices": list(range(index))}
                for index, identity in enumerate(identities)
            ],
        }
    )
    binding = boot.bind_boot_inputs(
        **source_bytes,
        boot_contract_bytes=boot_contract_bytes,
        module_plan_bytes=module_plan_bytes,
    )
    return fixture, inspection, binding


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
        cls.h4_fixture, cls.inspection, cls.binding = _matching_h4_h5()

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
        self.plan = _plan(self.binding, self.source_paths)

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
        self.assertEqual(package_value["entries"].count(package_value["entries"][0]), 1)
        self.assertEqual(package_value["cpio"]["sha256"], first.cpio_sha256)
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
        decoded["sources"][0], decoded["sources"][1] = decoded["sources"][1], decoded["sources"][0]
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_PLAN):
            self._compile_plan(canonical_dumps(decoded))
        decoded = canonical_loads(self.plan)
        decoded["sources"][0]["source_path"] = 1
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_PLAN):
            self._compile_plan(canonical_dumps(decoded))
        decoded = canonical_loads(self.plan)
        decoded["schema"] = "conf-proc-spp-boot-payload-plan/v0"
        with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_PLAN):
            self._compile_plan(canonical_dumps(decoded))
        for field in ("boot_contract_sha256", "module_plan_sha256"):
            decoded = canonical_loads(self.plan)
            decoded[field] = "0" * 64
            with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_PLAN):
                self._compile_plan(canonical_dumps(decoded))
        decoded = canonical_loads(self.plan)
        decoded["sources"][0]["source_path"] = "nested"
        decoded["sources"][1]["source_path"] = "nested/child.py"
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
            with self.assertRaisesRegex(ApplianceError, CP_SPP_PAYLOAD_SOURCE) as caught:
                payload._check_source_content(fake)
            self.assertNotIn(authority.archive_path, str(caught.exception))
            self.assertIn(authority.sha256[:16], str(caught.exception))
        object.__setattr__(fake, "data", b"ssh-ed25519x ")
        payload._check_source_content(fake)

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
        with self.assertRaises(ApplianceError):
            payload._parse_newc(b"not-a-cpio")


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o7777


if __name__ == "__main__":
    unittest.main(verbosity=2)
