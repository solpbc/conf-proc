#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Synthetic-fixture tests for SPP diagnostic runtime builder operations."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from conf_proc_guard import HermeticGuard  # noqa: E402
from conf_proc_json import canonical_dumps  # noqa: E402
import conf_proc_spp_diag_runtime_build as build  # noqa: E402
from conf_proc_spp_diag_runtime_build_reasons import (  # noqa: E402
    CP_SPP_DIAG_RUNTIME_BUILD_CLOSURE,
    CP_SPP_DIAG_RUNTIME_BUILD_CONSOLE,
    CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_EXISTS,
    CP_SPP_DIAG_RUNTIME_BUILD_DEST_PATH,
    CP_SPP_DIAG_RUNTIME_BUILD_RESERVED_ARG,
    CP_SPP_DIAG_RUNTIME_BUILD_RESERVED_DUPLICATE,
    CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_CONTENT,
    SppDiagRuntimeBuildError,
)


BOUNDARIES = (
    "validate-inputs",
    "pin-reads",
    "read-sources",
    "create-staging-dir",
    "write-files",
    "fsync-directories",
    "reopen-validate",
    "closure-audit",
    "finalize-permissions",
    "recheck-sources",
    "recheck-destination",
    "rename",
    "fsync-parent",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fixture(root: Path, name: str, controller: bytes = b"import helper\n") -> tuple[HermeticGuard, tuple[build.StagedFileSpec, ...], Path, dict[str, bytes]]:
    case = root / name
    sources = case / "sources"
    sources.mkdir(parents=True)
    contents = {"controller.py": controller, "helper.py": b"VALUE = 1\n", "data.bin": b"diagnostic data\x00"}
    specs = []
    modes = {"controller.py": 0o755, "helper.py": 0o644, "data.bin": 0o666}
    for path, data in contents.items():
        source = sources / path
        source.write_bytes(data)
        specs.append(
            build.StagedFileSpec(
                dest_relpath=path,
                source_abspath=str(source),
                mode=modes[path],
                declared_size=len(data),
                declared_sha256=_sha256(data),
            )
        )
    guard = HermeticGuard(
        allowed_reads=frozenset(str(sources / path) for path in contents),
        tools={},
        env={"PATH": "/usr/bin", "LC_ALL": "C", "TZ": "UTC"},
        build_epoch=0,
    )
    return guard, tuple(specs), case, contents


def _expect(reason_code: str, callback) -> None:
    try:
        callback()
    except SppDiagRuntimeBuildError as exc:
        assert exc.reason_code == reason_code
    else:
        raise AssertionError(f"expected {reason_code}")


def _stage(guard: HermeticGuard, specs: tuple[build.StagedFileSpec, ...], destination: Path, **kwargs) -> build.StageRuntimeResult:
    return build.stage_runtime(guard, specs, destination=str(destination), entrypoints=("controller.py",), **kwargs)


def test_finalize_command_line() -> None:
    no_args = build.finalize_command_line(console="ttyS0")
    assert no_args.text == "console=ttyS0 rdinit=/spp-diag-handoff --"
    assert no_args.bytes == no_args.text.encode("utf-8")
    assert no_args.sha256 == _sha256(no_args.bytes)
    assert no_args.text.count("rdinit=/spp-diag-handoff") == 1
    assert no_args.text.split().count("--") == 1
    with_args = build.finalize_command_line(console="ttyS1", reserved_args=("diag=1", "quiet"))
    assert with_args.text == "console=ttyS1 rdinit=/spp-diag-handoff -- diag=1 quiet"
    assert with_args.text.count("rdinit=/spp-diag-handoff") == 1
    assert with_args.text.split().count("--") == 1
    _expect(CP_SPP_DIAG_RUNTIME_BUILD_RESERVED_DUPLICATE, lambda: build.finalize_command_line(console="ttyS0", reserved_args=("quiet", "quiet")))
    for console in ("tty S0", "tty\nS0", "tty\x7fS0", "console=ttyS0", "init=/bin/sh", "rdinit=/bad", "tty--S0"):
        _expect(CP_SPP_DIAG_RUNTIME_BUILD_CONSOLE, lambda console=console: build.finalize_command_line(console=console))
    for argument in ("bad arg", "bad\targ", "--", "x--y", "console=ttyS0", "init=/bin/sh", "rdinit=/bad"):
        _expect(CP_SPP_DIAG_RUNTIME_BUILD_RESERVED_ARG, lambda argument=argument: build.finalize_command_line(console="ttyS0", reserved_args=(argument,)))


def test_stage_runtime_determinism(root: Path) -> None:
    guard, specs, case, contents = _fixture(root, "determinism")
    first = _stage(guard, specs, case / "runtime-one")
    second = _stage(guard, specs, case / "runtime-two")
    expected_inventory = tuple(
        build.InstallInventoryRow(path=spec.dest_relpath, mode=spec.mode & ~0o222, size_bytes=spec.declared_size, sha256=spec.declared_sha256)
        for spec in sorted(specs, key=lambda spec: spec.dest_relpath)
    )
    expected_bytes = canonical_dumps(
        {
            "schema": "sol-spp-diag-runtime-install-inventory/v1",
            "rows": [
                {"path": row.path, "mode": row.mode, "size_bytes": row.size_bytes, "sha256": row.sha256}
                for row in expected_inventory
            ],
        }
    )
    assert first.inventory == expected_inventory
    assert first.inventory_bytes == expected_bytes
    assert first.inventory_sha256 == _sha256(expected_bytes)
    assert second.inventory == first.inventory
    assert second.inventory_bytes == first.inventory_bytes
    assert second.inventory_sha256 == first.inventory_sha256
    for spec in specs:
        staged = Path(first.staged_root) / spec.dest_relpath
        assert staged.read_bytes() == contents[spec.dest_relpath]
        assert stat.S_IMODE(staged.stat().st_mode) == spec.mode & ~0o222
        assert not (stat.S_IMODE(staged.stat().st_mode) & 0o222)


def test_fault_cleanup_and_retry(root: Path) -> None:
    guard, specs, case, _contents = _fixture(root, "faults")
    destination = case / "runtime"
    before = set(os.listdir(case))
    for boundary in BOUNDARIES:
        def hook(current: str, *, wanted: str = boundary) -> None:
            if current == wanted:
                raise RuntimeError(wanted)

        try:
            _stage(guard, specs, destination, fault_hook=hook)
        except RuntimeError as exc:
            assert str(exc) == boundary
        else:
            raise AssertionError(f"fault hook was not called: {boundary}")
        assert not os.path.lexists(destination)
        assert set(os.listdir(case)) == before
        retried = _stage(guard, specs, destination)
        assert retried.inventory
        shutil.rmtree(destination)


def test_stage_input_rejections(root: Path) -> None:
    guard, specs, case, _contents = _fixture(root, "invalid")
    duplicate = specs + (replace(specs[0], source_abspath=specs[1].source_abspath),)
    _expect(CP_SPP_DIAG_RUNTIME_BUILD_DEST_PATH, lambda: _stage(guard, duplicate, case / "duplicate"))
    _expect(CP_SPP_DIAG_RUNTIME_BUILD_DEST_PATH, lambda: _stage(guard, (replace(specs[0], dest_relpath="/absolute"),), case / "absolute"))
    _expect(CP_SPP_DIAG_RUNTIME_BUILD_DEST_PATH, lambda: _stage(guard, (replace(specs[0], dest_relpath="x/../escape"),), case / "escape"))
    mismatch = (replace(specs[0], declared_sha256="0" * 64),) + specs[1:]
    _expect(CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_CONTENT, lambda: _stage(guard, mismatch, case / "mismatch"))


def test_existing_destination_precedes_reads(root: Path) -> None:
    guard, specs, case, _contents = _fixture(root, "destination")
    destination = case / "exists"
    destination.write_text("already here\n", encoding="utf-8")
    invalid_if_read = (replace(specs[0], declared_size=999),) + specs[1:]
    _expect(CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_EXISTS, lambda: _stage(guard, invalid_if_read, destination))
    assert destination.read_text(encoding="utf-8") == "already here\n"


def test_closure_failure_prevents_publish(root: Path) -> None:
    guard, specs, case, _contents = _fixture(root, "closure", controller=b"import socket\n")
    _expect(CP_SPP_DIAG_RUNTIME_BUILD_CLOSURE, lambda: _stage(guard, specs, case / "runtime"))
    assert not os.path.lexists(case / "runtime")


TESTS = (
    test_finalize_command_line,
    test_stage_runtime_determinism,
    test_fault_cleanup_and_retry,
    test_stage_input_rejections,
    test_existing_destination_precedes_reads,
    test_closure_failure_prevents_publish,
)


def test_bind_image_happy_path_and_seams() -> None:
    import importlib.util

    pe_test_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conf-proc-spp-diagbundle-pe-selftest.py")
    spec = importlib.util.spec_from_file_location("_pe_fixture", pe_test_path)
    pe_fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pe_fixture)

    input_closure_address = "cd" * 32
    data, _info = pe_fixture.build_pe(sections=[pe_fixture._sppdiag_section(input_closure_address=input_closure_address)])

    members = {
        name: {"size_bytes": 100 + index, "sha256": format(index, "064x")}
        for index, name in enumerate(build.SIGNED_IMAGE_MEMBER_NAMES)
    }
    result = build.bind_image(diagnostic_efi_bytes=data, input_closure_address=input_closure_address, members=members)
    assert len(result.image_binding_address) == 64
    assert b"sol-spp-diagbundle-signed-image/v1" in result.manifest_bytes

    result2 = build.bind_image(diagnostic_efi_bytes=data, input_closure_address=input_closure_address, members=members)
    assert result.image_binding_address == result2.image_binding_address

    mutated_members = dict(members)
    mutated_members["rootfs.img"] = {"size_bytes": 999999, "sha256": "ff" * 32}
    result3 = build.bind_image(diagnostic_efi_bytes=data, input_closure_address=input_closure_address, members=mutated_members)
    assert result3.image_binding_address != result.image_binding_address

    try:
        build.bind_image(diagnostic_efi_bytes=data, input_closure_address="ee" * 32, members=members)
        raise AssertionError("expected seam mismatch rejection")
    except build.SppDiagRuntimeBuildError as exc:
        assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_IMAGE_SEAM

    widened_members = dict(members)
    widened_members["late-binding.json"] = {"size_bytes": 10, "sha256": "11" * 32}
    try:
        build.bind_image(diagnostic_efi_bytes=data, input_closure_address=input_closure_address, members=widened_members)
        raise AssertionError("expected six-member rejection")
    except build.SppDiagRuntimeBuildError as exc:
        assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_IMAGE_MEMBERS

    narrowed_members = dict(members)
    del narrowed_members["signer-cert.der"]
    try:
        build.bind_image(diagnostic_efi_bytes=data, input_closure_address=input_closure_address, members=narrowed_members)
        raise AssertionError("expected five-member rejection")
    except build.SppDiagRuntimeBuildError as exc:
        assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_IMAGE_MEMBERS


def main() -> None:
    test_finalize_command_line()
    print("ok   test_finalize_command_line")
    test_bind_image_happy_path_and_seams()
    print("ok   test_bind_image_happy_path_and_seams")
    with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
        root = Path(temporary)
        for test in TESTS[1:]:
            test(root)
            print(f"ok   {test.__name__}")
    print("SPP diagnostic runtime build: ok (%d tests, %d boundaries)" % (len(TESTS) + 1, len(BOUNDARIES)))


if __name__ == "__main__":
    main()

