#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Synthetic-fixture tests for SPP diagnostic runtime builder operations."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
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
    CP_SPP_DIAG_RUNTIME_BUILD_COMMAND_LINE,
    CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_EXISTS,
    CP_SPP_DIAG_RUNTIME_BUILD_DEST_PATH,
    CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_CONTENT,
    SppDiagRuntimeBuildError,
)


COMMAND_ARGS = {
    "root_data_partuuid": "11111111-1111-4111-8111-111111111111",
    "root_hash_partuuid": "22222222-2222-4222-8222-222222222222",
    "root_hash": "aa" * 32,
    "challenge": "bb" * 32,
    "run_identity": "cc" * 32,
    "control_plan_address": "dd" * 32,
    "binding_partuuid": "33333333-3333-4333-8333-333333333333",
}
EXPECTED_COMMAND_LINE = (
    "ro rdinit=/spp-diag-handoff init=/usr/lib/spp/spp-diag-controller "
    "root=/dev/mapper/spp-diag-root rootfstype=squashfs ip=off ima_policy=critical_data "
    "spp_diag.root_data=PARTUUID=11111111-1111-4111-8111-111111111111 "
    "spp_diag.root_hash=PARTUUID=22222222-2222-4222-8222-222222222222 "
    f"spp_diag.roothash={'aa' * 32} sol_spp_diag.challenge={'bb' * 32} "
    f"sol_spp_diag.run={'cc' * 32} sol_spp_diag.control_plan={'dd' * 32} -- "
    "sol_spp_diag.target_profile=azure:centralus:3:Standard_NCC40ads_H100_v5:ConfidentialVM:v1 "
    "sol_spp_diag.binding_partuuid=33333333-3333-4333-8333-333333333333\n"
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
    result = build.finalize_command_line(**COMMAND_ARGS)
    assert result.text == EXPECTED_COMMAND_LINE
    assert result.bytes == EXPECTED_COMMAND_LINE.encode("ascii")
    assert result.sha256 == _sha256(result.bytes)
    assert "console=" not in result.text
    assert result.text.count("\n") == 1 and result.text.endswith("\n")
    assert result.text.split().count("--") == 1
    mutations = (
        {"root_data_partuuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaA"},
        {"root_hash_partuuid": COMMAND_ARGS["root_data_partuuid"]},
        {"root_hash": "AA" * 32},
        {"challenge": "bb" * 31},
        {"run_identity": "g0" * 32},
        {"control_plan_address": "dd" * 32 + "00"},
        {"binding_partuuid": "not-a-partuuid"},
    )
    for mutation in mutations:
        arguments = dict(COMMAND_ARGS)
        arguments.update(mutation)
        _expect(CP_SPP_DIAG_RUNTIME_BUILD_COMMAND_LINE, lambda arguments=arguments: build.finalize_command_line(**arguments))


def test_derived_output_and_gpu_policy_addresses() -> None:
    challenge = "01" * 32
    run_identity = "a2" * 32
    model = b"sol-spp-semantic-fixture-model-v1"
    ptx = b"canonical PTX bytes\n"
    cuda_digest = "33" * 32
    output = build.derive_output_oracle(
        challenge=challenge,
        run_identity=run_identity,
        model_bytes=model,
        cuda_child_sha256=cuda_digest,
        ptx_bytes=ptx,
    )
    seed = hashlib.sha256(
        b"sol-spp-diag-input-seed-v1\0" + bytes.fromhex(challenge) + bytes.fromhex(run_identity)
    ).digest()
    expected = bytearray(seed)
    for offset, value in enumerate(model):
        expected[offset % 32] ^= value
    expected_record = struct.pack(">8sHHI32s", b"SPPGPUO1", 1, 1, 32, bytes(expected))
    expected_preimage = json.dumps(
        {
            "algorithm_id": "spp-diag-xor-stride32-v1",
            "challenge": challenge,
            "cuda_child_sha256": cuda_digest,
            "deterministic_seed": seed.hex(),
            "expected_result": bytes(expected).hex(),
            "model_sha256": hashlib.sha256(model).hexdigest(),
            "model_size_bytes": len(model),
            "ptx_sha256": hashlib.sha256(ptx).hexdigest(),
            "run_identity": run_identity,
            "schema": "sol-spp-diag-output-oracle-v1",
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    assert output.preimage_bytes == expected_preimage
    assert output.address == hashlib.sha256(b"sol-spp-diag-output-oracle-v1\0" + expected_preimage).hexdigest()
    assert output.expected_record == expected_record
    assert output.model_sha256 == "1ae959386fcd1dff3db63e50a9ebba5376d5d83f08ef98a2e584e7b0f878d6c8"

    output_mutations = (
        {"challenge": "02" * 32},
        {"run_identity": "a3" * 32},
        {"model_bytes": model + b"!"},
        {"cuda_child_sha256": "34" * 32},
        {"ptx_bytes": ptx + b"!"},
    )
    base = {
        "challenge": challenge,
        "run_identity": run_identity,
        "model_bytes": model,
        "cuda_child_sha256": cuda_digest,
        "ptx_bytes": ptx,
    }
    for mutation in output_mutations:
        arguments = dict(base)
        arguments.update(mutation)
        assert build.derive_output_oracle(**arguments).address != output.address

    policy_args = {
        "output_oracle_address": output.address,
        "gpu_helper_sha256": "55" * 32,
        "cuda_child_sha256": cuda_digest,
        "nvattest_sha256": "66" * 32,
        "nvidia_smi_sha256": "77" * 32,
        "libcuda_sha256": "88" * 32,
    }
    policy = build.derive_gpu_witness_policy(**policy_args)
    expected_policy = {
        "attestation_architecture": "HOPPER",
        "compute_capability": "9.0",
        "confidential_compute_environment": "PRODUCTION",
        "confidential_compute_mode": "ON",
        "cuda_child_sha256": "33" * 32,
        "debug_mode": "OFF",
        "default_outbound": False,
        "gpu_architecture": "GH100",
        "gpu_count": 1,
        "gpu_evidence_protocol": "SPPGPU1/v1",
        "gpu_helper_sha256": "55" * 32,
        "gpu_model": "NVIDIA H100 NVL",
        "libcuda_sha256": "88" * 32,
        "nvidia_smi_sha256": "77" * 32,
        "nvattest_sha256": "66" * 32,
        "output_oracle_address": output.address,
        "public_ip": False,
        "schema": "sol-spp-diag-gpu-witness-policy-v1",
        "secure_boot": True,
        "target_profile_id": "azure:centralus:3:Standard_NCC40ads_H100_v5:ConfidentialVM:v1",
        "vtpm": True,
    }
    expected_policy_bytes = json.dumps(
        expected_policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    assert policy.preimage_bytes == expected_policy_bytes
    expected_policy_address = hashlib.sha256(
        b"sol-spp-diag-gpu-witness-policy-v1\0" + expected_policy_bytes
    ).hexdigest()
    assert policy.address == expected_policy_address
    for key in policy_args:
        mutation = dict(policy_args)
        mutation[key] = "99" * 32
        assert build.derive_gpu_witness_policy(**mutation).address != policy.address
    for key, value in expected_policy.items():
        mutated_policy = dict(expected_policy)
        if type(value) is bool:
            mutated_policy[key] = not value
        elif type(value) is int:
            mutated_policy[key] = value + 1
        else:
            mutated_policy[key] = value + "-mutated"
        mutated_bytes = json.dumps(
            mutated_policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        assert hashlib.sha256(b"sol-spp-diag-gpu-witness-policy-v1\0" + mutated_bytes).hexdigest() != policy.address


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


def test_racing_destination_wins_untouched(root: Path) -> None:
    guard, specs, case, _contents = _fixture(root, "destination-race")
    destination = case / "raced"
    original_rename = build._rename_noreplace

    def racing_rename(source: str, target: str) -> None:
        Path(target).write_text("other writer\n", encoding="utf-8")
        original_rename(source, target)

    build._rename_noreplace = racing_rename
    try:
        _expect(
            CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_EXISTS,
            lambda: _stage(guard, specs, destination),
        )
    finally:
        build._rename_noreplace = original_rename
    assert destination.read_text(encoding="utf-8") == "other writer\n"
    assert not list(case.glob("raced.staging.*"))


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
    test_racing_destination_wins_untouched,
    test_closure_failure_prevents_publish,
)


def test_single_file_transaction_finalize_command_line() -> None:
    with tempfile.TemporaryDirectory() as work_dir:
        output_path = os.path.join(work_dir, "cmdline.txt")
        result = build.finalize_command_line(**COMMAND_ARGS, output_path=output_path)
        with open(output_path, "rb") as handle:
            on_disk = handle.read()
        assert on_disk == result.bytes
        assert hashlib.sha256(on_disk).hexdigest() == result.sha256
        mode = stat.S_IMODE(os.stat(output_path).st_mode)
        assert not (mode & 0o222), "published file must not be writable"

        # rebuilding with identical inputs to a fresh path is byte-identical
        output_path2 = os.path.join(work_dir, "cmdline2.txt")
        result2 = build.finalize_command_line(**COMMAND_ARGS, output_path=output_path2)
        assert result2.bytes == result.bytes

        # no-replace atomic visibility: publishing again to the SAME path rejects,
        # and the original file's bytes remain untouched
        try:
            build.finalize_command_line(**COMMAND_ARGS, output_path=output_path)
            raise AssertionError("expected no-replace rejection")
        except build.SppDiagRuntimeBuildError as exc:
            assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_EXISTS
        with open(output_path, "rb") as handle:
            assert handle.read() == on_disk

        # command-line validation fails before touching the filesystem
        missing_path = os.path.join(work_dir, "never-created.txt")
        bad_arguments = dict(COMMAND_ARGS)
        bad_arguments["challenge"] = "short"
        try:
            build.finalize_command_line(**bad_arguments, output_path=missing_path)
            raise AssertionError("expected command-line validation rejection")
        except build.SppDiagRuntimeBuildError as exc:
            assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_COMMAND_LINE
        assert not os.path.lexists(missing_path)

        # a destination whose parent doesn't exist propagates an ordinary OSError,
        # not a silently-swallowed failure
        try:
            build.finalize_command_line(**COMMAND_ARGS, output_path="/nonexistent-parent-dir/x.txt")
            raise AssertionError("expected OSError")
        except OSError:
            pass

        # A destination created at the atomic publish boundary wins untouched.
        raced_path = os.path.join(work_dir, "raced.txt")
        original_rename = build._rename_noreplace

        def racing_rename(source: str, destination: str) -> None:
            Path(destination).write_bytes(b"other-writer")
            original_rename(source, destination)

        build._rename_noreplace = racing_rename
        try:
            try:
                build.finalize_command_line(**COMMAND_ARGS, output_path=raced_path)
                raise AssertionError("expected racing destination rejection")
            except build.SppDiagRuntimeBuildError as exc:
                assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_EXISTS
        finally:
            build._rename_noreplace = original_rename
        assert Path(raced_path).read_bytes() == b"other-writer"
        assert not list(Path(work_dir).glob("raced.txt.staging.*"))

        # A publish syscall failure leaves neither destination nor staging debris.
        failed_path = os.path.join(work_dir, "failed.txt")

        def failing_rename(_source: str, _destination: str) -> None:
            raise OSError("simulated rename failure")

        build._rename_noreplace = failing_rename
        try:
            try:
                build.finalize_command_line(**COMMAND_ARGS, output_path=failed_path)
                raise AssertionError("expected publish failure")
            except build.SppDiagRuntimeBuildError as exc:
                assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_STAGING
        finally:
            build._rename_noreplace = original_rename
        assert not os.path.lexists(failed_path)
        assert not list(Path(work_dir).glob("failed.txt.staging.*"))

        # Readback failure removes the private candidate before failing closed.
        read_failed_path = os.path.join(work_dir, "read-failed.txt")
        original_read_all = build._read_all

        def failing_read_all(_descriptor: int) -> bytes:
            raise OSError("simulated readback failure")

        build._read_all = failing_read_all
        try:
            try:
                build.finalize_command_line(**COMMAND_ARGS, output_path=read_failed_path)
                raise AssertionError("expected readback failure")
            except build.SppDiagRuntimeBuildError as exc:
                assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_REOPEN
        finally:
            build._read_all = original_read_all
        assert not os.path.lexists(read_failed_path)
        assert not list(Path(work_dir).glob("read-failed.txt.staging.*"))

        # Failure to durably publish the directory removes the exact file just renamed.
        fsync_failed_path = os.path.join(work_dir, "fsync-failed.txt")
        original_fsync = build.os.fsync
        fsync_calls = [0]

        def failing_parent_fsync(descriptor: int) -> None:
            fsync_calls[0] += 1
            if fsync_calls[0] == 2:
                raise OSError("simulated parent fsync failure")
            original_fsync(descriptor)

        build.os.fsync = failing_parent_fsync
        try:
            try:
                build.finalize_command_line(**COMMAND_ARGS, output_path=fsync_failed_path)
                raise AssertionError("expected parent fsync failure")
            except build.SppDiagRuntimeBuildError as exc:
                assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_STAGING
        finally:
            build.os.fsync = original_fsync
        assert not os.path.lexists(fsync_failed_path)
        assert not list(Path(work_dir).glob("fsync-failed.txt.staging.*"))


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
    identities = {
        "challenge": "11" * 32,
        "run_identity": "22" * 32,
        "control_plan_address": "33" * 32,
        "target_profile_id": build.SPP_DIAG_TARGET_PROFILE_ID,
    }
    result = build.bind_image(diagnostic_efi_bytes=data, input_closure_address=input_closure_address, members=members, **identities)
    assert len(result.image_binding_address) == 64
    assert b"sol-spp-diagbundle-signed-image/v1" in result.manifest_bytes
    magic, version, reserved, json_size = struct.unpack(">8sHHI", result.late_binding_record[:16])
    assert (magic, version, reserved) == (b"SPPBND1\0", 1, 0)
    binding_json = result.late_binding_record[16 : 16 + json_size]
    assert result.late_binding_record[16 + json_size : 48 + json_size] == hashlib.sha256(
        b"sol-spp-diag-runtime-late-binding/v1\0" + result.late_binding_record[: 16 + json_size]
    ).digest()
    assert not any(result.late_binding_record[48 + json_size :])
    assert set(json.loads(binding_json)) == {
        "challenge", "control_plan_address", "image_binding_address", "input_closure_address",
        "run_identity", "schema", "target_profile_id",
    }

    result2 = build.bind_image(diagnostic_efi_bytes=data, input_closure_address=input_closure_address, members=members, **identities)
    assert result.image_binding_address == result2.image_binding_address

    mutated_members = dict(members)
    mutated_members["rootfs.img"] = {"size_bytes": 999999, "sha256": "ff" * 32}
    result3 = build.bind_image(diagnostic_efi_bytes=data, input_closure_address=input_closure_address, members=mutated_members, **identities)
    assert result3.image_binding_address != result.image_binding_address

    try:
        build.bind_image(diagnostic_efi_bytes=data, input_closure_address="ee" * 32, members=members, **identities)
        raise AssertionError("expected seam mismatch rejection")
    except build.SppDiagRuntimeBuildError as exc:
        assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_IMAGE_SEAM

    widened_members = dict(members)
    widened_members["late-binding.json"] = {"size_bytes": 10, "sha256": "11" * 32}
    try:
        build.bind_image(diagnostic_efi_bytes=data, input_closure_address=input_closure_address, members=widened_members, **identities)
        raise AssertionError("expected six-member rejection")
    except build.SppDiagRuntimeBuildError as exc:
        assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_IMAGE_MEMBERS

    narrowed_members = dict(members)
    del narrowed_members["signer-cert.der"]
    try:
        build.bind_image(diagnostic_efi_bytes=data, input_closure_address=input_closure_address, members=narrowed_members, **identities)
        raise AssertionError("expected five-member rejection")
    except build.SppDiagRuntimeBuildError as exc:
        assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_IMAGE_MEMBERS

    with tempfile.TemporaryDirectory() as work_dir:
        output_path = os.path.join(work_dir, "signed-image-manifest.json")
        written = build.bind_image(
            diagnostic_efi_bytes=data, input_closure_address=input_closure_address, members=members, output_path=output_path, **identities
        )
        with open(output_path, "rb") as handle:
            on_disk = handle.read()
        assert on_disk == written.late_binding_record
        assert len(on_disk) == 4096 and on_disk[:8] == b"SPPBND1\0"
        mode = stat.S_IMODE(os.stat(output_path).st_mode)
        assert not (mode & 0o222)
        try:
            build.bind_image(
                diagnostic_efi_bytes=data, input_closure_address=input_closure_address, members=members, output_path=output_path, **identities
            )
            raise AssertionError("expected no-replace rejection")
        except build.SppDiagRuntimeBuildError as exc:
            assert exc.reason_code == build.CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_EXISTS
        with open(output_path, "rb") as handle:
            assert handle.read() == on_disk


def test_declared_controller_staging_graph() -> None:
    assert build.SPP_DIAG_RUNTIME_STAGED_PYTHON == (
        "usr/lib/spp/spp-diag-controller",
        "usr/lib/python3.10/conf_proc_reasons.py",
        "usr/lib/python3.10/conf_proc_json.py",
        "usr/lib/python3.10/conf_proc_spp_diag_failure_terminal_reasons.py",
        "usr/lib/python3.10/conf_proc_spp_diag_export.py",
        "usr/lib/python3.10/conf_proc_spp_diag_export_reasons.py",
        "usr/lib/python3.10/conf_proc_spp_diag_quote.py",
        "usr/lib/python3.10/conf_proc_spp_diag_pcr.py",
        "usr/lib/python3.10/conf_proc_spp_diagbundle_protocol.py",
    )


def test_controller_staging_enforces_exact_python_graph(root: Path) -> None:
    sources = root / "controller-graph-sources"
    sources.mkdir()
    specs = []
    allowed = []
    for destination in build.SPP_DIAG_RUNTIME_STAGED_PYTHON:
        source = sources / destination.replace("/", "_")
        payload = b"import conf_proc_json\n" if destination.endswith("spp-diag-controller") else b"VALUE = 1\n"
        source.write_bytes(payload)
        allowed.append(str(source))
        specs.append(build.StagedFileSpec(
            dest_relpath=destination,
            source_abspath=str(source),
            mode=0o755 if destination.endswith("spp-diag-controller") else 0o644,
            declared_size=len(payload),
            declared_sha256=_sha256(payload),
        ))
    guard = HermeticGuard(
        allowed_reads=frozenset(allowed), tools={}, env={"PATH": "/usr/bin", "LC_ALL": "C", "TZ": "UTC"}, build_epoch=0,
    )
    result = build.stage_runtime(
        guard, tuple(specs), destination=str(root / "controller-runtime"),
        entrypoints=("usr/lib/spp/spp-diag-controller",),
    )
    assert result.staged_root.endswith("controller-runtime")
    missing = tuple(spec for spec in specs if not spec.dest_relpath.endswith("conf_proc_spp_diag_pcr.py"))
    _expect(
        CP_SPP_DIAG_RUNTIME_BUILD_DEST_PATH,
        lambda: build.stage_runtime(
            guard, missing, destination=str(root / "controller-runtime-missing"),
            entrypoints=("usr/lib/spp/spp-diag-controller",),
        ),
    )


def main() -> None:
    test_derived_output_and_gpu_policy_addresses()
    print("ok   test_derived_output_and_gpu_policy_addresses")
    test_finalize_command_line()
    print("ok   test_finalize_command_line")
    test_single_file_transaction_finalize_command_line()
    print("ok   test_single_file_transaction_finalize_command_line")
    test_bind_image_happy_path_and_seams()
    print("ok   test_bind_image_happy_path_and_seams")
    test_declared_controller_staging_graph()
    print("ok   test_declared_controller_staging_graph")
    with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
        test_controller_staging_enforces_exact_python_graph(Path(temporary))
    print("ok   test_controller_staging_enforces_exact_python_graph")
    with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
        root = Path(temporary)
        for test in TESTS[1:]:
            test(root)
            print(f"ok   {test.__name__}")
    print("SPP diagnostic runtime build: ok (%d tests, %d boundaries)" % (len(TESTS) + 5, len(BOUNDARIES)))


if __name__ == "__main__":
    main()
