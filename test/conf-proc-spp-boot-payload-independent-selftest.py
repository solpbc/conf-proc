#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent VPE oracle, mutation, race, fault, and dormancy checks for H6."""

from __future__ import annotations

import ast
import errno
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

import conf_proc_spp_boot_payload_inspect as independent
from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_reasons import ApplianceError, CP_SPP_PAYLOAD_ADDRESS
from conf_proc_spp_boot_payload_fixture import SOURCE_ARCHIVE_PATHS, matching_h4_h5, plan_bytes


_CONTEXT = multiprocessing.get_context("fork")


def _producer_child(
    inspection: object,
    binding: object,
    plan: bytes,
    source_root: str,
    output_root: str,
    result_queue: object,
    start_event: object | None = None,
    before_rename_event: object | None = None,
    release_rename_event: object | None = None,
    fault_name: str | None = None,
) -> None:
    """Import and execute the producer only in a forked child process."""

    import conf_proc_spp_boot_payload as producer

    if start_event is not None and not start_event.wait(15):
        result_queue.put({"ok": False, "error": "start timeout"})
        return
    if before_rename_event is not None:
        real_rename = producer._rename_noreplace

        def delayed_rename(*args: object, **kwargs: object) -> None:
            before_rename_event.set()
            if release_rename_event is None or not release_rename_event.wait(15):
                raise OSError(errno.ETIMEDOUT, "injected wait timeout")
            real_rename(*args, **kwargs)

        producer._rename_noreplace = delayed_rename
    elif fault_name is not None:
        def fail(*_args: object, **_kwargs: object) -> None:
            raise OSError(errno.EIO, "injected producer phase failure")

        setattr(producer, fault_name, fail)
    try:
        result = producer.compile_boot_payload(
            inspection=inspection,
            binding=binding,
            plan_bytes=plan,
            source_root=source_root,
            output_root=output_root,
        )
        result_queue.put(
            {
                "ok": True,
                "state": result.state,
                "cpio_sha256": result.cpio_sha256,
                "package_sha256": result.package_sha256,
                "output_path": result.output_path,
            }
        )
    except Exception as exc:  # noqa: BLE001 - child reports only type/safe public text
        result_queue.put({"ok": False, "type": type(exc).__name__, "error": str(exc)})


def _run_child(
    inspection: object,
    binding: object,
    plan: bytes,
    source_root: Path,
    output_root: Path,
    **kwargs: object,
) -> dict[str, object]:
    queue = _CONTEXT.Queue()
    process = _CONTEXT.Process(
        target=_producer_child,
        args=(inspection, binding, plan, str(source_root), str(output_root), queue),
        kwargs=kwargs,
    )
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
    """Return independent record byte spans and the trailer offset."""

    offset = 0
    spans: list[tuple[int, int, int, int, int]] = []
    while True:
        start = offset
        if data[offset:offset + 6] != b"070701":
            raise AssertionError("fixture CPIO magic mismatch")
        fields = tuple(int(data[offset + 6 + index:offset + 14 + index], 16) for index in range(0, 104, 8))
        size = fields[6]
        name_size = fields[11]
        name_start = offset + 110
        name_end = name_start + name_size
        data_start = name_end + ((-(110 + name_size)) & 3)
        data_end = data_start + size
        end = data_end + ((-size) & 3)
        name = data[name_start:name_end - 1]
        if name == b"TRAILER!!!":
            return spans, start
        spans.append((start, end, name_start, data_start, data_end))
        offset = end


class BootPayloadIndependentSelftest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.h4_fixture, cls.inspection, cls.binding = matching_h4_h5()
        cls.temporary = tempfile.TemporaryDirectory(dir="/var/tmp")
        base = Path(cls.temporary.name)
        cls.source_root = base / "source"
        cls.output_root = base / "output"
        cls.source_root.mkdir(mode=0o700)
        cls.output_root.mkdir(mode=0o700)
        cls.source_paths = []
        for index, archive_path in enumerate(SOURCE_ARCHIVE_PATHS):
            source_path = f"source-{index}.py"
            shutil.copyfile(ROOT / Path(archive_path).name, cls.source_root / source_path)
            os.chmod(cls.source_root / source_path, 0o600)
            cls.source_paths.append(source_path)
        cls.plan = plan_bytes(cls.binding, cls.source_paths)
        if "conf_proc_spp_boot_payload" in sys.modules:
            raise AssertionError("independent parent imported the producer before generation")
        cls.produced = _run_child(
            cls.inspection, cls.binding, cls.plan, cls.source_root, cls.output_root,
        )
        if not cls.produced.get("ok"):
            raise AssertionError(f"producer fixture failed: {cls.produced}")
        cls.output_path = Path(str(cls.produced["output_path"]))
        cls.cpio = (cls.output_path / "spp-boot-payload.cpio").read_bytes()
        cls.package = (cls.output_path / "spp-boot-payload.package.json").read_bytes()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()
        cls.h4_fixture.cleanup()

    def assert_rejected(
        self,
        *,
        cpio: bytes | None = None,
        package: bytes | None = None,
        output_path: str | None = None,
    ) -> None:
        with self.assertRaises(ApplianceError):
            independent.inspect_boot_payload(
                inspection=self.inspection,
                binding=self.binding,
                cpio_bytes=self.cpio if cpio is None else cpio,
                package_bytes=self.package if package is None else package,
                output_path=str(self.output_path) if output_path is None else output_path,
            )

    def test_positive_raw_inspection_is_narrow_and_independent(self) -> None:
        result = independent.inspect_boot_payload(
            inspection=self.inspection,
            binding=self.binding,
            cpio_bytes=self.cpio,
            package_bytes=self.package,
            output_path=str(self.output_path),
        )
        self.assertEqual(result.state, "artifact_consistent")
        self.assertEqual(result.boot_qualification, "not_qualified")
        self.assertEqual(
            (result.runtime_closure, result.activation_closure, result.directory_closure),
            ("unresolved", "unresolved", "unresolved"),
        )
        self.assertNotIn("conf_proc_spp_boot_payload", sys.modules)

    def test_raw_cpio_header_name_mode_data_padding_order_and_trailer_mutations(self) -> None:
        spans, trailer = _cpio_layouts(self.cpio)
        mutations: list[bytes] = []

        bad_magic = bytearray(self.cpio)
        bad_magic[0] = ord("1")
        mutations.append(bytes(bad_magic))

        bad_mode = bytearray(self.cpio)
        bad_mode[14:22] = b"000001a4"
        mutations.append(bytes(bad_mode))

        bad_name = bytearray(self.cpio)
        bad_name[spans[0][2]] ^= 1
        mutations.append(bytes(bad_name))

        bad_data = bytearray(self.cpio)
        bad_data[spans[0][3]] ^= 1
        mutations.append(bytes(bad_data))

        for start, end, name_start, data_start, data_end in spans:
            name_end = self.cpio.find(b"\0", name_start) + 1
            if data_start > name_end:
                bad_name_pad = bytearray(self.cpio)
                bad_name_pad[name_end] = 1
                mutations.append(bytes(bad_name_pad))
                break
        for start, end, name_start, data_start, data_end in spans:
            if end > data_end:
                bad_data_pad = bytearray(self.cpio)
                bad_data_pad[data_end] = 1
                mutations.append(bytes(bad_data_pad))
                break

        first = self.cpio[spans[0][0]:spans[0][1]]
        second = self.cpio[spans[1][0]:spans[1][1]]
        swapped = second + first + self.cpio[spans[1][1]:]
        mutations.append(swapped)

        bad_trailer = bytearray(self.cpio)
        bad_trailer[trailer] = ord("1")
        mutations.append(bytes(bad_trailer))

        self.assertEqual(len(mutations), 8)
        for mutation in mutations:
            self.assert_rejected(cpio=mutation)

    def test_package_document_and_address_mutations(self) -> None:
        value = canonical_loads(self.package)
        variants: list[bytes] = []
        for key, replacement in (
            ("schema", "conf-proc-spp-boot-payload-package/v0"),
            ("package_version", True),
            ("boot_qualification", "qualified"),
            ("runtime_closure", "closed"),
            ("cpio_sha256", "0" * 64),
            ("entries", value["entries"][:-1]),
            ("external_imports_declared_unresolved", value["external_imports_declared_unresolved"] + [1]),
        ):
            changed = dict(value)
            changed[key] = replacement
            variants.append(canonical_dumps(changed))
        bool_entry = dict(value)
        bool_entry["entries"] = [dict(item) for item in value["entries"]]
        bool_entry["entries"][0]["mode"] = True
        variants.append(canonical_dumps(bool_entry))
        missing = dict(value)
        del missing["directory_closure"]
        variants.append(canonical_dumps(missing))
        extra = dict(value)
        extra["builder_consistency"] = "builder_consistent"
        variants.append(canonical_dumps(extra))
        variants.append(self.package + b"\n")
        for variant in variants:
            self.assert_rejected(package=variant)
        wrong_address = str(self.output_path.parent / ("0" * 64))
        self.assert_rejected(output_path=wrong_address)
        with self.assertRaises(ApplianceError) as caught:
            independent.inspect_boot_payload(
                inspection=self.inspection,
                binding=self.binding,
                cpio_bytes=b"private malformed bytes",
                package_bytes=self.package,
                output_path=str(self.output_path),
            )
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_identical_publishers_race_to_one_exact_address(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o700)
            start = _CONTEXT.Event()
            queue = _CONTEXT.Queue()
            processes = [
                _CONTEXT.Process(
                    target=_producer_child,
                    args=(self.inspection, self.binding, self.plan, str(self.source_root), str(output), queue),
                    kwargs={"start_event": start},
                )
                for _ in range(4)
            ]
            for process in processes:
                process.start()
            start.set()
            for process in processes:
                process.join(30)
                self.assertFalse(process.is_alive())
                self.assertEqual(process.exitcode, 0)
            results = [queue.get(timeout=2) for _ in processes]
            self.assertTrue(all(result.get("ok") for result in results), results)
            self.assertEqual(len({result["output_path"] for result in results}), 1)
            address = Path(str(results[0]["output_path"]))
            self.assertEqual(set(os.listdir(address)), {"spp-boot-payload.cpio", "spp-boot-payload.package.json"})

    def test_disagreeing_existing_publisher_wins_race_and_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o700)
            ready = _CONTEXT.Event()
            release = _CONTEXT.Event()
            queue = _CONTEXT.Queue()
            process = _CONTEXT.Process(
                target=_producer_child,
                args=(self.inspection, self.binding, self.plan, str(self.source_root), str(output), queue),
                kwargs={"before_rename_event": ready, "release_rename_event": release},
            )
            process.start()
            self.assertTrue(ready.wait(15))
            # The contract digest is the first address component.
            hostile = output / "built_unqualified" / self.binding.boot_contract_sha256 / str(self.produced["cpio_sha256"]) / str(self.produced["package_sha256"])
            hostile.mkdir(mode=0o700, parents=True)
            (hostile / "unexpected").write_bytes(b"disagreeing publisher")
            os.chmod(hostile, 0o555)
            release.set()
            process.join(30)
            self.assertFalse(process.is_alive())
            result = queue.get(timeout=2)
            self.assertFalse(result.get("ok"), result)
            self.assertIn(CP_SPP_PAYLOAD_ADDRESS, str(result.get("error")))
            self.assertFalse(any(path.name.startswith(".spp-boot-payload-stage-") for path in hostile.parent.iterdir()))

    def test_injected_producer_phase_failures_expose_no_payload_or_stage(self) -> None:
        phases = (
            "_validate_literal_authority", "_validate_issued_inputs", "_validate_plan",
            "_open_pinned_root", "_read_source", "_check_source_content", "_import_closure",
            "_members", "_newc_archive", "_package_bytes", "_check_builder_consistency",
            "_rename_noreplace",
        )
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
                output = Path(temporary) / "output"
                output.mkdir(mode=0o700)
                result = _run_child(
                    self.inspection, self.binding, self.plan, self.source_root, output,
                    fault_name=phase,
                )
                self.assertFalse(result.get("ok"), result)
                self.assertFalse(any(path.is_file() for path in output.rglob("*")))
                self.assertFalse(any(path.name.startswith(".spp-boot-payload-stage-") for path in output.rglob("*")))

    def test_dormancy_has_no_release_cli_or_producer_to_inspector_edge(self) -> None:
        inspector_source = (ROOT / "conf_proc_spp_boot_payload_inspect.py").read_text()
        inspector_tree = ast.parse(inspector_source)
        imports = {
            alias.name
            for node in ast.walk(inspector_tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module
            for node in ast.walk(inspector_tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        self.assertNotIn("conf_proc_spp_boot_payload", imports)
        producer_source = (ROOT / "conf_proc_spp_boot_payload.py").read_text()
        self.assertNotIn("conf_proc_spp_boot_payload_inspect", producer_source)
        for release_file in (
            "conf_proc_build.py", "conf_proc_promote.py", "conf_proc_guard.py",
            "conf_proc_inspect.py", "verifier.py", "spp_health.py",
        ):
            source = (ROOT / release_file).read_text()
            self.assertNotIn("conf_proc_spp_boot_payload", source, release_file)


if __name__ == "__main__":
    unittest.main(verbosity=2)
