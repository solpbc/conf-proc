#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fully inline preservation KAT for the independent SPP boot v3 payload."""

from __future__ import annotations

import ast
import errno
import hashlib
import multiprocessing
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from queue import Empty


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

from conf_proc_json import canonical_dumps, canonical_loads
import conf_proc_provenance_v2_inspect as h4
import conf_proc_spp_boot_payload_v3_inspect as independent
from conf_proc_spp_boot_v3 import bind_boot_inputs_v3, parse_boot_contract_v3
from conf_proc_spp_reasons_v3 import ApplianceErrorV3, CP_SPP_PAYLOAD_V3_ADDRESS
from conf_proc_spp_boot_v3_fixture import build_v3_fixture


_CONTEXT = multiprocessing.get_context("fork")
_PINS = (
    ("conf_proc_geometry.py", 2725, "f8273165758c6460bb10d840cb67097a423df819c449119ad15d57b21e05205a"),
    ("conf_proc_json.py", 4425, "b18793b443e3ab2dcaf4bb7762d2e9c52f4d88daddf7bfb614b87ac0d8e80e21"),
    ("conf_proc_lock.py", 21243, "296cdc9ba1238dfa6ac982a33f6b1411a0d7730cbb88edbcfc4492c52c729bba"),
    ("conf_proc_module_authority.py", 3173, "01e9c44c6221b54d792c6f5ff65a9bb82e0b77a29a397b9932b1a13c7d0efe26"),
    ("conf_proc_policy.py", 16686, "e2c48f05dd4233bc8267bb53804e25fd948e06e73a80c6d04ac1e3299118c473"),
    ("conf_proc_provenance_v2.py", 21957, "e94a0818b2d14168190ef7ed490cc147eb18dafd837087eab883630958b59ccd"),
    ("conf_proc_provenance_v2_manifest.py", 16846, "bd3c3ba87c7f6db52759e9f5dd16a5d447b5521c24f714043492ad713549e399"),
    ("conf_proc_reasons.py", 12571, "c56b629a0fc156860c7400d6bc6884c1f41c8a9e4b0626ef4f2821f71102067a"),
    ("conf_proc_spp_boot.py", 147664, "c1dfba4c4ca71cf64ab8ecef12440950edab88f6ef3e2fb73791fc1f900076a6"),
    ("conf_proc_spp_boot_payload.py", 44257, "8fcacd797e7727708d0dcbebbea632db8e8779c08120fa5d5b6e1773bf1eb11d"),
    ("conf_proc_spp_boot_payload_inspect.py", 16879, "cd990a62d73315d93f4f9e45c58c1529beb63a12409ffcfc8c384d8caa0f32d2"),
    ("conf_proc_spp_reasons_v3.py", 3215, "4ca5821dd0edca148bffa312fd6d9208083fa5f6e22345e61c5284d3cbbcdf75"),
    ("conf_proc_spp_boot_v3_tables.py", 37125, "0c50b6a46acd5152d63757956cba65f699c58e1a1566807448f5779e28787824"),
    ("conf_proc_spp_boot_v3_wire.py", 41779, "00c03278031280dd572bf221be2075ab741e36b378af8a7fd2c874560b840e90"),
    ("conf_proc_spp_boot_v3_resource.py", 25792, "b172f2dd4dbe70e295e4dbdd0ebe066c7e247e8d2183db22b15ac48f5afc57de"),
    ("conf_proc_spp_boot_v3.py", 88910, "05aa22b99b2c99274e06147dbcc40053cb110f9a99b4b1433deca2f532b5b6ab"),
    ("conf_proc_spp_boot_v3_semantics.py", 65475, "f1a0dfa7c7013e9e6bb8bf78cfb01b090ea63cf177c6bbeef8da9c28d6eeade6"),
    ("conf_proc_spp_boot_dispatch_v3.py", 1141, "83a0652bff152a7e9e96e4f5daa0bde0278092d012d0b8fbf8832a39f23fa139"),
)
_SOURCE_ROWS_V3 = (
    ("/usr/lib/spp/conf_proc_geometry.py", "support", 0o444),
    ("/usr/lib/spp/conf_proc_json.py", "support", 0o444),
    ("/usr/lib/spp/conf_proc_lock.py", "support", 0o444),
    ("/usr/lib/spp/conf_proc_module_authority.py", "support", 0o444),
    ("/usr/lib/spp/conf_proc_policy.py", "support", 0o444),
    ("/usr/lib/spp/conf_proc_provenance_v2.py", "support", 0o444),
    ("/usr/lib/spp/conf_proc_provenance_v2_manifest.py", "support", 0o444),
    ("/usr/lib/spp/conf_proc_reasons.py", "support", 0o444),
    ("/usr/lib/spp/conf_proc_spp_boot.py", "engine", 0o444),
    ("/usr/lib/spp/conf_proc_spp_boot_dispatch_v3.py", "dispatcher", 0o444),
    ("/usr/lib/spp/conf_proc_spp_boot_v3.py", "engine", 0o444),
    ("/usr/lib/spp/conf_proc_spp_boot_v3_resource.py", "support", 0o444),
    ("/usr/lib/spp/conf_proc_spp_boot_v3_semantics.py", "engine", 0o444),
    ("/usr/lib/spp/conf_proc_spp_boot_v3_tables.py", "support", 0o444),
    ("/usr/lib/spp/conf_proc_spp_boot_v3_wire.py", "support", 0o444),
    ("/usr/lib/spp/conf_proc_spp_reasons_v3.py", "support", 0o444),
)
_EXPECTED_LOCAL_IMPORTS_V3 = {
    "conf_proc_geometry": frozenset(),
    "conf_proc_json": frozenset({"conf_proc_reasons"}),
    "conf_proc_lock": frozenset({"conf_proc_json", "conf_proc_reasons"}),
    "conf_proc_module_authority": frozenset({"conf_proc_lock", "conf_proc_reasons"}),
    "conf_proc_policy": frozenset({"conf_proc_json", "conf_proc_reasons"}),
    "conf_proc_provenance_v2": frozenset({"conf_proc_json", "conf_proc_lock", "conf_proc_reasons"}),
    "conf_proc_provenance_v2_manifest": frozenset({"conf_proc_json", "conf_proc_reasons"}),
    "conf_proc_reasons": frozenset(),
    "conf_proc_spp_boot": frozenset({"conf_proc_geometry", "conf_proc_json", "conf_proc_lock", "conf_proc_module_authority", "conf_proc_policy", "conf_proc_provenance_v2", "conf_proc_provenance_v2_manifest", "conf_proc_reasons"}),
    "conf_proc_spp_boot_dispatch_v3": frozenset({"conf_proc_json", "conf_proc_spp_boot_v3", "conf_proc_spp_reasons_v3"}),
    "conf_proc_spp_boot_v3": frozenset({"conf_proc_json", "conf_proc_spp_boot", "conf_proc_spp_boot_v3_resource", "conf_proc_spp_boot_v3_semantics", "conf_proc_spp_boot_v3_tables", "conf_proc_spp_reasons_v3"}),
    "conf_proc_spp_boot_v3_semantics": frozenset({"conf_proc_spp_boot", "conf_proc_spp_boot_v3_tables", "conf_proc_spp_reasons_v3"}),
    "conf_proc_spp_boot_v3_resource": frozenset({"conf_proc_spp_boot", "conf_proc_spp_boot_v3", "conf_proc_spp_boot_v3_tables", "conf_proc_spp_boot_v3_wire", "conf_proc_spp_reasons_v3"}),
    "conf_proc_spp_boot_v3_tables": frozenset({"conf_proc_spp_boot"}),
    "conf_proc_spp_boot_v3_wire": frozenset({"conf_proc_json", "conf_proc_spp_boot_v3_tables", "conf_proc_spp_reasons_v3"}),
    "conf_proc_spp_reasons_v3": frozenset(),
}
_PLAN_SCHEMA_V3 = "conf-proc-spp-boot-payload-plan/v3"
_PACKAGE_SCHEMA_V3 = "conf-proc-spp-boot-payload-package/v3"
_AUTHORITY_FIELDS_V3 = (
    "root_lock_bytes", "runtime_closure_bytes", "verity_rules_bytes", "tcb_identity_bytes",
    "builder_source_bytes", "policy_bytes", "accepted_manifest_bytes", "kernel_feature_contract_bytes",
    "trusted_certificate_bundle_bytes", "boot_contract_bytes", "module_plan_bytes", "gpt_layout_rules_bytes",
    "literal_v3_observation_shape_bytes",
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _issued_authorities() -> tuple[object, object]:
    values, contract = build_v3_fixture()
    binding = bind_boot_inputs_v3(contract=contract, **values)
    manifest = values["accepted_manifest_bytes"]
    inspection = h4._register_inspection_result(h4.InspectionResult(
        "artifact_consistent", "not_qualified", "1" * 64, "2" * 64,
        "3" * 64, "4" * 64, "5" * 64, "6" * 64, _digest(manifest),
        "7" * 64, "inline KAT evidence ceiling",
    ))
    return inspection, binding


def _plan_bytes(binding: object, source_paths: list[str]) -> bytes:
    return canonical_dumps({
        "schema": _PLAN_SCHEMA_V3,
        "plan_version": 3,
        "boot_contract_sha256": binding.boot_contract_sha256,
        "module_plan_sha256": _digest(binding.module_plan_bytes),
        "entries": [
            {"archive_path": archive_path, "source_path": source_path}
            for (archive_path, _role, _mode), source_path in zip(_SOURCE_ROWS_V3, source_paths, strict=True)
        ],
    })


def _producer_child(inspection: object, binding: object, plan: bytes, source_root: str, output_root: str, queue: object, *, mutation: str | None = None, fault: str | None = None) -> None:
    import conf_proc_spp_boot_payload_v3 as producer

    if mutation == "missing_source_row":
        producer.BOOT_PAYLOAD_SOURCE_AUTHORITY_V3 = producer.BOOT_PAYLOAD_SOURCE_AUTHORITY_V3[:-1]
    elif mutation == "extra_source_row":
        producer.BOOT_PAYLOAD_SOURCE_AUTHORITY_V3 = (
            *producer.BOOT_PAYLOAD_SOURCE_AUTHORITY_V3,
            producer.BOOT_PAYLOAD_SOURCE_AUTHORITY_V3[-1],
        )
    elif mutation == "wrong_hash":
        row = producer.BOOT_PAYLOAD_SOURCE_AUTHORITY_V3[0]
        rows = list(producer.BOOT_PAYLOAD_SOURCE_AUTHORITY_V3)
        rows[0] = producer._SourceAuthorityV3(row.archive_path, row.role, row.mode, row.size_bytes, "0" * 64)
        producer.BOOT_PAYLOAD_SOURCE_AUTHORITY_V3 = tuple(rows)
    elif mutation == "wrong_import_edge":
        graph = dict(producer._EXPECTED_LOCAL_IMPORTS_V3)
        graph["conf_proc_spp_boot_dispatch_v3"] = frozenset()
        producer._EXPECTED_LOCAL_IMPORTS_V3 = graph
    elif mutation == "wrong_schema":
        producer._PLAN_SCHEMA_V3 = "conf-proc-spp-boot-payload-plan/v0"
    if fault is not None:
        def fail(*_args: object, **_kwargs: object) -> None:
            raise OSError(errno.EIO, "injected producer fault")

        setattr(producer, fault, fail)
    try:
        result = producer.compile_boot_payload_v3(inspection=inspection, binding=binding, plan_bytes=plan, source_root=source_root, output_root=output_root)
        queue.put({"ok": True, "state": result.state, "cpio_sha256": result.cpio_sha256, "package_sha256": result.package_sha256, "output_path": result.output_path})
    except Exception as exc:
        queue.put({"ok": False, "type": type(exc).__name__, "error": str(exc)})


def _run_child(inspection: object, binding: object, plan: bytes, source_root: Path, output_root: Path, **kwargs: object) -> dict[str, object]:
    queue = _CONTEXT.Queue()
    process = _CONTEXT.Process(target=_producer_child, args=(inspection, binding, plan, str(source_root), str(output_root), queue), kwargs=kwargs)
    process.start()
    process.join(30)
    if process.is_alive():
        process.terminate()
        process.join(5)
        raise AssertionError("producer child did not terminate")
    try:
        result = queue.get(timeout=2)
    except Empty as exc:
        raise AssertionError(f"producer child exited {process.exitcode} without result") from exc
    if not isinstance(result, dict):
        raise AssertionError("producer child returned malformed result")
    return result


def _cpio_layouts(data: bytes) -> tuple[list[tuple[int, int, int, int, int]], int]:
    offset = 0
    spans: list[tuple[int, int, int, int, int]] = []
    while True:
        start = offset
        if data[offset:offset + 6] != b"070701":
            raise AssertionError("fixture CPIO magic mismatch")
        fields = tuple(int(data[offset + 6 + index:offset + 14 + index], 16) for index in range(0, 104, 8))
        name_size, size = fields[11], fields[6]
        name_start = offset + 110
        name_end = name_start + name_size
        data_start = name_end + ((-(110 + name_size)) & 3)
        data_end = data_start + size
        end = data_end + ((-size) & 3)
        if data[name_start:name_end - 1] == b"TRAILER!!!":
            return spans, start
        spans.append((start, end, name_start, data_start, data_end))
        offset = end


class BootPayloadV3IndependentSelftest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        for name, size, digest in _PINS:
            data = (ROOT / name).read_bytes()
            if len(data) != size or _digest(data) != digest:
                raise AssertionError(f"pinned file drift: {name}")
        cls.inspection, cls.binding = _issued_authorities()
        cls.temporary = tempfile.TemporaryDirectory(dir="/var/tmp")
        base = Path(cls.temporary.name)
        cls.source_root = base / "source"
        cls.output_root = base / "output"
        cls.source_root.mkdir(mode=0o700)
        cls.output_root.mkdir(mode=0o700)
        cls.source_paths = []
        for index, (archive_path, _role, _mode) in enumerate(_SOURCE_ROWS_V3):
            source_path = f"source-{index}.py"
            shutil.copyfile(ROOT / Path(archive_path).name, cls.source_root / source_path)
            os.chmod(cls.source_root / source_path, 0o600)
            cls.source_paths.append(source_path)
        cls.plan = _plan_bytes(cls.binding, cls.source_paths)
        if "conf_proc_spp_boot_payload_v3" in sys.modules:
            raise AssertionError("independent parent imported producer before generation")
        cls.produced = _run_child(cls.inspection, cls.binding, cls.plan, cls.source_root, cls.output_root)
        if not cls.produced.get("ok"):
            raise AssertionError(f"producer fixture failed: {cls.produced}")
        if cls.produced.get("state") != "built_unqualified":
            raise AssertionError(f"unexpected producer state: {cls.produced}")
        cls.output_path = Path(str(cls.produced["output_path"]))
        cls.cpio = (cls.output_path / "spp-boot-payload.cpio").read_bytes()
        cls.package = (cls.output_path / "spp-boot-payload.package.json").read_bytes()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def _reject(self, *, cpio: bytes | None = None, package: bytes | None = None, output_path: str | None = None) -> None:
        with self.assertRaises(ApplianceErrorV3):
            independent.inspect_boot_payload_v3(
                inspection=self.inspection,
                binding=self.binding,
                cpio_bytes=self.cpio if cpio is None else cpio,
                package_bytes=self.package if package is None else package,
                output_path=str(self.output_path) if output_path is None else output_path,
            )

    def test_pinned_base_and_inline_authority_literals(self) -> None:
        self.assertEqual(len(_PINS), 18)
        self.assertEqual(len(_SOURCE_ROWS_V3), 16)
        self.assertEqual(len(_EXPECTED_LOCAL_IMPORTS_V3), 16)
        self.assertEqual((_PLAN_SCHEMA_V3, _PACKAGE_SCHEMA_V3), ("conf-proc-spp-boot-payload-plan/v3", "conf-proc-spp-boot-payload-package/v3"))
        self.assertEqual(len(_AUTHORITY_FIELDS_V3), 13)

    def test_positive_raw_inspection_and_record_count(self) -> None:
        result = independent.inspect_boot_payload_v3(
            inspection=self.inspection, binding=self.binding,
            cpio_bytes=self.cpio, package_bytes=self.package, output_path=str(self.output_path),
        )
        self.assertEqual(result.state, "artifact_consistent")
        self.assertEqual(len(_cpio_layouts(self.cpio)[0]), 29)
        self.assertNotIn("conf_proc_spp_boot_payload_v3", sys.modules)

    def test_raw_cpio_and_package_mutations(self) -> None:
        spans, trailer = _cpio_layouts(self.cpio)
        mutations = []
        bad_magic = bytearray(self.cpio)
        bad_magic[0] = ord("1")
        mutations.append(bytes(bad_magic))
        bad_name = bytearray(self.cpio)
        bad_name[spans[0][2]] ^= 1
        mutations.append(bytes(bad_name))
        bad_data = bytearray(self.cpio)
        bad_data[spans[0][3]] ^= 1
        mutations.append(bytes(bad_data))
        bad_trailer = bytearray(self.cpio)
        bad_trailer[trailer] = ord("1")
        mutations.append(bytes(bad_trailer))
        for mutation in mutations:
            self._reject(cpio=mutation)
        value = canonical_loads(self.package)
        for key, replacement in (("schema", "conf-proc-spp-boot-payload-package/v0"), ("package_version", True), ("cpio_sha256", "0" * 64), ("entries", value["entries"][:-1])):
            changed = dict(value)
            changed[key] = replacement
            self._reject(package=canonical_dumps(changed))
        self._reject(output_path=str(self.output_path.parent / ("0" * 64)))

    def test_literal_and_import_mutations_fail_in_forked_producer(self) -> None:
        for mutation in ("missing_source_row", "extra_source_row", "wrong_hash", "wrong_import_edge", "wrong_schema"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
                output = Path(temporary) / "output"
                output.mkdir(mode=0o700)
                result = _run_child(self.inspection, self.binding, self.plan, self.source_root, output, mutation=mutation)
                self.assertFalse(result.get("ok"), result)

    def test_identical_publishers_race_to_one_address(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o700)
            queue = _CONTEXT.Queue()
            processes = [
                _CONTEXT.Process(
                    target=_producer_child,
                    args=(
                        self.inspection,
                        self.binding,
                        self.plan,
                        str(self.source_root),
                        str(output),
                        queue,
                    ),
                )
                for _ in range(2)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(30)
                self.assertFalse(process.is_alive(), "producer race child did not terminate")
                self.assertEqual(process.exitcode, 0)
            results = [queue.get(timeout=2) for _ in processes]
            self.assertTrue(all(result.get("ok") for result in results), results)
            output_paths = {str(result["output_path"]) for result in results}
            self.assertEqual(len(output_paths), 1)
            self.assertTrue(Path(output_paths.pop()).is_dir())

    def test_faults_leave_no_payload_and_dormancy_has_no_fixture_import(self) -> None:
        for fault in ("_validate_literal_authority", "_validate_plan", "_import_closure", "_newc_archive", "_package_bytes"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
                output = Path(temporary) / "output"
                output.mkdir(mode=0o700)
                result = _run_child(self.inspection, self.binding, self.plan, self.source_root, output, fault=fault)
                self.assertFalse(result.get("ok"), result)
                self.assertFalse(any(path.is_file() for path in output.rglob("*")))
        source = (ROOT / "test" / "conf-proc-spp-boot-payload-v3-independent-selftest.py").read_text()
        tree = ast.parse(source)
        imports = {
            alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
        } | {
            node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        top_level_imports = {
            alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names
        } | {
            node.module for node in tree.body if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        self.assertNotIn("conf_proc_spp_boot_payload_v3", top_level_imports)
        self.assertNotIn("conf_proc_spp_boot_payload_v3_fixture", top_level_imports)
        self.assertNotIn("conf_proc_spp_boot_payload_fixture", top_level_imports)
        self.assertIn("conf_proc_spp_boot_payload_v3_inspect", imports)
        producer_imports = [
            alias
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
            if alias.name == "conf_proc_spp_boot_payload_v3" and alias.asname == "producer"
        ]
        self.assertEqual(len(producer_imports), 1)

    def test_address_reason_remains_v3_specific(self) -> None:
        self._reject(output_path="/bad")
        self.assertEqual(CP_SPP_PAYLOAD_V3_ADDRESS, "CP_SPP_PAYLOAD_V3_ADDRESS")


if __name__ == "__main__":
    unittest.main(verbosity=2)
