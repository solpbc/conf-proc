#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Transactional builders for the SPP diagnostic runtime and its fixed command line."""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import errno
import hashlib
import os
import posixpath
import re
import shutil
import stat
import struct
from typing import Final

from conf_proc_guard import HermeticGuard
from conf_proc_json import canonical_dumps
from conf_proc_spp_diag_closure_audit import audit_closure, check_closure_allowed
from conf_proc_spp_diag_closure_audit_reasons import SppDiagClosureAuditError
from conf_proc_spp_diagbundle_pe import extract_sppdiag_descriptor
from conf_proc_spp_diagbundle_protocol import image_binding_address as _protocol_image_binding_address
from conf_proc_spp_diag_runtime_build_reasons import (
    CP_SPP_DIAG_RUNTIME_BUILD_CLOSURE,
    CP_SPP_DIAG_RUNTIME_BUILD_COMMAND_LINE,
    CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_CHANGED,
    CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_EXISTS,
    CP_SPP_DIAG_RUNTIME_BUILD_DEST_PATH,
    CP_SPP_DIAG_RUNTIME_BUILD_IMAGE_MEMBERS,
    CP_SPP_DIAG_RUNTIME_BUILD_IMAGE_SEAM,
    CP_SPP_DIAG_RUNTIME_BUILD_INTERNAL_NODE,
    CP_SPP_DIAG_RUNTIME_BUILD_REOPEN,
    CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_CONTENT,
    CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_DECLARATION,
    CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_STAT,
    CP_SPP_DIAG_RUNTIME_BUILD_STAGING,
    SppDiagRuntimeBuildError,
)


_INVENTORY_SCHEMA: Final = "sol-spp-diag-runtime-install-inventory/v1"
_O_DIRECTORY: Final = getattr(os, "O_DIRECTORY", 0)
_AT_FDCWD: Final = -100
_RENAME_NOREPLACE: Final = 1

# Mirrors conf_proc_spp_diagbundle.py's fixed signed-image manifest shape (schema,
# node_kind, layout, member-name set) as literal constants -- not an import, since
# bind_image is producer-only code and must not import the appraiser module.
SIGNED_IMAGE_SCHEMA_ID: Final = "sol-spp-diagbundle-signed-image/v1"
NODE_KIND_SIGNED_IMAGE: Final = "signed_image"
NODE_ARTIFACT_STATE: Final = "diagnostic_unqualified"
SIGNED_IMAGE_LAYOUT: Final = "uki-verity/v1"
SIGNED_IMAGE_MEMBER_NAMES: Final = (
    "diagnostic.efi",
    "rootfs.img",
    "rootfs.verity",
    "verity-root-hash.bin",
    "signer-cert.der",
)
_SIGNED_IMAGE_MEMBER_SET: Final = frozenset(SIGNED_IMAGE_MEMBER_NAMES)
_O_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
SPP_DIAG_TARGET_PROFILE_ID: Final = (
    "azure:centralus:3:Standard_NCC40ads_H100_v5:ConfidentialVM:v1"
)
_OUTPUT_ORACLE_DOMAIN: Final = b"sol-spp-diag-output-oracle-v1\0"
_GPU_WITNESS_POLICY_DOMAIN: Final = b"sol-spp-diag-gpu-witness-policy-v1\0"
_INPUT_SEED_DOMAIN: Final = b"sol-spp-diag-input-seed-v1\0"
_OUTPUT_ALGORITHM_ID: Final = "spp-diag-xor-stride32-v1"
_MAX_SYNTHETIC_MODEL_BYTES: Final = 8 * 1024 * 1024


@dataclass(frozen=True)
class FinalizedCommandLine:
    text: str
    bytes: bytes
    sha256: str


@dataclass(frozen=True)
class StagedFileSpec:
    dest_relpath: str
    source_abspath: str
    mode: int
    declared_size: int
    declared_sha256: str


@dataclass(frozen=True)
class InstallInventoryRow:
    path: str
    mode: int
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class StageRuntimeResult:
    staged_root: str
    inventory: tuple[InstallInventoryRow, ...]
    inventory_bytes: bytes
    inventory_sha256: str


@dataclass(frozen=True)
class DerivedOutputOracle:
    address: str
    preimage_bytes: bytes
    deterministic_seed: bytes
    expected_result: bytes
    expected_record: bytes
    model_sha256: str
    model_size_bytes: int
    ptx_sha256: str


@dataclass(frozen=True)
class DerivedGpuWitnessPolicy:
    address: str
    preimage_bytes: bytes


def derive_output_oracle(
    *,
    challenge: str,
    run_identity: str,
    model_bytes: bytes,
    cuda_child_sha256: str,
    ptx_bytes: bytes,
) -> DerivedOutputOracle:
    """Derive the synthetic GPU result and its challenge/run-bound address."""

    if (
        not _is_sha256(challenge)
        or not _is_sha256(run_identity)
        or type(model_bytes) is not bytes
        or not 1 <= len(model_bytes) <= _MAX_SYNTHETIC_MODEL_BYTES
        or not _is_sha256(cuda_child_sha256)
        or type(ptx_bytes) is not bytes
        or not ptx_bytes
    ):
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_CONTENT)
    seed = hashlib.sha256(
        _INPUT_SEED_DOMAIN + bytes.fromhex(challenge) + bytes.fromhex(run_identity)
    ).digest()
    result = bytearray(seed)
    for offset, value in enumerate(model_bytes):
        result[offset % 32] ^= value
    expected_result = bytes(result)
    expected_record = struct.pack(">8sHHI32s", b"SPPGPUO1", 1, 1, 32, expected_result)
    model_sha256 = hashlib.sha256(model_bytes).hexdigest()
    ptx_sha256 = hashlib.sha256(ptx_bytes).hexdigest()
    preimage_bytes = canonical_dumps(
        {
            "algorithm_id": _OUTPUT_ALGORITHM_ID,
            "challenge": challenge,
            "cuda_child_sha256": cuda_child_sha256,
            "deterministic_seed": seed.hex(),
            "expected_result": expected_result.hex(),
            "model_sha256": model_sha256,
            "model_size_bytes": len(model_bytes),
            "ptx_sha256": ptx_sha256,
            "run_identity": run_identity,
            "schema": "sol-spp-diag-output-oracle-v1",
        }
    )
    return DerivedOutputOracle(
        address=hashlib.sha256(_OUTPUT_ORACLE_DOMAIN + preimage_bytes).hexdigest(),
        preimage_bytes=preimage_bytes,
        deterministic_seed=seed,
        expected_result=expected_result,
        expected_record=expected_record,
        model_sha256=model_sha256,
        model_size_bytes=len(model_bytes),
        ptx_sha256=ptx_sha256,
    )


def derive_gpu_witness_policy(
    *,
    output_oracle_address: str,
    runtime_inventory_sha256: str,
    gpu_helper_sha256: str,
    cuda_child_sha256: str,
    nvattest_sha256: str,
    nvidia_smi_sha256: str,
    libcuda_sha256: str,
) -> DerivedGpuWitnessPolicy:
    """Derive the fixed exact-H100 witness-policy address."""

    digests = (
        output_oracle_address,
        runtime_inventory_sha256,
        gpu_helper_sha256,
        cuda_child_sha256,
        nvattest_sha256,
        nvidia_smi_sha256,
        libcuda_sha256,
    )
    if any(not _is_sha256(value) for value in digests):
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_CONTENT)
    preimage_bytes = canonical_dumps(
        {
            "attestation_architecture": "HOPPER",
            "compute_capability": "9.0",
            "confidential_compute_environment": "PRODUCTION",
            "confidential_compute_mode": "ON",
            "cuda_child_sha256": cuda_child_sha256,
            "debug_mode": "OFF",
            "default_outbound": False,
            "gpu_architecture": "GH100",
            "gpu_count": 1,
            "gpu_evidence_protocol": "SPPGPU1/v1",
            "gpu_helper_sha256": gpu_helper_sha256,
            "gpu_model": "NVIDIA H100 NVL",
            "libcuda_sha256": libcuda_sha256,
            "nvidia_smi_sha256": nvidia_smi_sha256,
            "nvattest_sha256": nvattest_sha256,
            "output_oracle_address": output_oracle_address,
            "public_ip": False,
            "runtime_inventory_sha256": runtime_inventory_sha256,
            "schema": "sol-spp-diag-gpu-witness-policy-v1",
            "secure_boot": True,
            "target_profile_id": SPP_DIAG_TARGET_PROFILE_ID,
            "vtpm": True,
        }
    )
    return DerivedGpuWitnessPolicy(
        address=hashlib.sha256(_GPU_WITNESS_POLICY_DOMAIN + preimage_bytes).hexdigest(),
        preimage_bytes=preimage_bytes,
    )


def _write_single_file_transactional(data: bytes, destination: str) -> None:
    """Single-file transactional publish: sibling temp file, fsync, read-only, reopen
    and re-hash to confirm, then no-replace rename and parent fsync. Mirrors
    stage_runtime's directory transaction at single-file granularity."""

    if os.path.lexists(destination):
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_EXISTS)
    parent = os.path.dirname(destination)
    parent_fd = os.open(parent, os.O_RDONLY | _O_DIRECTORY)
    try:
        candidate = destination + ".staging." + os.urandom(8).hex()
        try:
            descriptor = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY | _O_NOFOLLOW, 0o644)
        except OSError:
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
        try:
            _write_all(descriptor, data)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o444)
        except OSError:
            os.close(descriptor)
            _cleanup_staging(candidate)
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
        os.close(descriptor)

        try:
            reopened = os.open(candidate, os.O_RDONLY | _O_NOFOLLOW)
        except OSError:
            _cleanup_staging(candidate)
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_REOPEN)
        try:
            reopened_stat = os.fstat(reopened)
            reread = _read_all(reopened)
        except OSError:
            _cleanup_staging(candidate)
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_REOPEN)
        finally:
            os.close(reopened)
        if reread != data:
            _cleanup_staging(candidate)
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_REOPEN)

        try:
            _rename_noreplace(candidate, destination)
        except FileExistsError:
            _cleanup_staging(candidate)
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_EXISTS)
        except OSError:
            _cleanup_staging(candidate)
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
        try:
            os.fsync(parent_fd)
        except OSError:
            try:
                published = os.lstat(destination)
                if (published.st_dev, published.st_ino) == (reopened_stat.st_dev, reopened_stat.st_ino):
                    os.unlink(destination)
                    try:
                        os.fsync(parent_fd)
                    except OSError:
                        pass
            except OSError:
                pass
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
    finally:
        os.close(parent_fd)


def finalize_command_line(
    *,
    root_data_partuuid: str,
    root_hash_partuuid: str,
    root_hash: str,
    challenge: str,
    run_identity: str,
    control_plan_address: str,
    target_profile_id: str,
    binding_partuuid: str,
    output_path: str | None = None,
) -> FinalizedCommandLine:
    """Build and optionally publish the one complete diagnostic UKI command line."""

    partuuids = (root_data_partuuid, root_hash_partuuid, binding_partuuid)
    if any(not _is_canonical_partuuid(value) for value in partuuids) or len(set(partuuids)) != len(partuuids):
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_COMMAND_LINE)
    digests = (root_hash, challenge, run_identity, control_plan_address)
    if any(not _is_sha256(value) for value in digests):
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_COMMAND_LINE)
    if not _is_profile_id(target_profile_id):
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_COMMAND_LINE)
    text = (
        "ro rdinit=/spp-diag-handoff init=/usr/lib/spp/spp-diag-controller "
        "root=/dev/mapper/spp-diag-root rootfstype=squashfs ip=off "
        "ima_policy=critical_data "
        f"spp_diag.root_data=PARTUUID={root_data_partuuid} "
        f"spp_diag.root_hash=PARTUUID={root_hash_partuuid} "
        f"spp_diag.roothash={root_hash} "
        f"sol_spp_diag.challenge={challenge} "
        f"sol_spp_diag.run={run_identity} "
        f"sol_spp_diag.control_plan={control_plan_address} -- "
        f"sol_spp_diag.target_profile={target_profile_id} "
        f"sol_spp_diag.binding_partuuid={binding_partuuid}\n"
    )
    encoded = text.encode("ascii")
    if output_path is not None:
        _write_single_file_transactional(encoded, output_path)
    return FinalizedCommandLine(text=text, bytes=encoded, sha256=hashlib.sha256(encoded).hexdigest())


def stage_runtime(
    guard: HermeticGuard,
    files: tuple[StagedFileSpec, ...],
    *,
    destination: str,
    entrypoints: tuple[str, ...],
    dlopen_literals: frozenset[str] = frozenset(),
    apparmor_paths: frozenset[str] = frozenset(),
    allowed_python_modules: frozenset[str] = frozenset(),
    allowed_elf_libraries: frozenset[str] = frozenset(),
    allowed_dlopen: frozenset[str] = frozenset(),
    allowed_apparmor_includes: frozenset[str] = frozenset(),
    fault_hook: object = None,
) -> StageRuntimeResult:
    """Stage a read-only runtime tree, audit its reachable closure, then atomically publish it."""

    staging_dir: str | None = None
    parent_fd: int | None = None
    try:
        _call_fault_hook(fault_hook, "validate-inputs")
        ordered_files = _validate_stage_inputs(guard, files, destination)
        source_paths = tuple(dict.fromkeys(spec.source_abspath for spec in ordered_files))

        _call_fault_hook(fault_hook, "pin-reads")
        with guard.pin_reads(source_paths):
            _call_fault_hook(fault_hook, "read-sources")
            source_data = _read_and_validate_sources(guard, ordered_files)

            _call_fault_hook(fault_hook, "create-staging-dir")
            parent = os.path.dirname(destination)
            parent_fd = os.open(parent, os.O_RDONLY | _O_DIRECTORY)
            parent_before = _directory_identity(parent_fd)
            candidate = destination + ".staging." + os.urandom(8).hex()
            try:
                os.mkdir(candidate, 0o700)
            except OSError:
                _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
            staging_dir = candidate
            if _directory_identity(parent_fd) != parent_before:
                _fail(CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_CHANGED)

            _call_fault_hook(fault_hook, "write-files")
            directories = {staging_dir}
            for spec in ordered_files:
                _write_staged_file(staging_dir, spec, source_data[spec.dest_relpath], directories)

            _call_fault_hook(fault_hook, "fsync-directories")
            _fsync_directories(directories)

            _call_fault_hook(fault_hook, "reopen-validate")
            inventory = _reopen_and_validate(staging_dir, ordered_files)

            _call_fault_hook(fault_hook, "closure-audit")
            try:
                observation = audit_closure(
                    staging_dir,
                    entrypoints,
                    allowed_external=frozenset(),
                    dlopen_literals=dlopen_literals,
                    apparmor_paths=apparmor_paths,
                )
                check_closure_allowed(
                    observation,
                    allowed_python_modules=allowed_python_modules,
                    allowed_elf_libraries=allowed_elf_libraries,
                    allowed_dlopen=allowed_dlopen,
                    allowed_apparmor_includes=allowed_apparmor_includes,
                )
            except SppDiagClosureAuditError:
                _fail(CP_SPP_DIAG_RUNTIME_BUILD_CLOSURE)
            declared_paths = {spec.dest_relpath for spec in ordered_files}
            # This is intentionally one-way: unreachable declared data/config files remain allowed.
            if any(node.path not in declared_paths for node in observation.nodes):
                _fail(CP_SPP_DIAG_RUNTIME_BUILD_INTERNAL_NODE)

            _call_fault_hook(fault_hook, "finalize-permissions")

            _call_fault_hook(fault_hook, "recheck-sources")
            # pin_reads verifies each pinned source descriptor and path on context exit.

        _call_fault_hook(fault_hook, "recheck-destination")
        if os.path.lexists(destination) or _directory_identity(parent_fd) != parent_before:
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_CHANGED)

        # A post-rename injected failure cannot satisfy the no-publication guarantee, so this
        # test-only probe runs before rename while the actual parent fsync remains after it.
        _call_fault_hook(fault_hook, "fsync-parent")
        _call_fault_hook(fault_hook, "rename")
        os.rename(staging_dir, destination)
        staging_dir = None
        os.fsync(parent_fd)

        inventory_bytes = canonical_dumps(
            {
                "schema": _INVENTORY_SCHEMA,
                "rows": [_inventory_object(row) for row in inventory],
            }
        )
        return StageRuntimeResult(
            staged_root=destination,
            inventory=inventory,
            inventory_bytes=inventory_bytes,
            inventory_sha256=hashlib.sha256(inventory_bytes).hexdigest(),
        )
    except Exception:
        _cleanup_staging(staging_dir)
        raise
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


@dataclass(frozen=True)
class BindImageResult:
    image_binding_address: str
    manifest_bytes: bytes
    late_binding_record: bytes


def bind_image(
    *,
    diagnostic_efi_bytes: bytes,
    input_closure_address: str,
    members: dict,
    output_path: str | None = None,
) -> BindImageResult:
    """Bind a captured five-member signed image to its input closure via the shared
    protocol constructor, calling extract_sppdiag_descriptor directly. Rejects any
    attempt to widen the fixed five-member inventory (e.g. smuggling a late-binding
    record in as a sixth member) and any .sppdiag/closure-address mismatch. When
    output_path is given, publishes the manifest bytes via the single-file transaction
    (no-replace atomic visibility) and confirms it by reopen/re-hash before returning."""

    if type(members) is not dict or frozenset(members) != _SIGNED_IMAGE_MEMBER_SET:
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_IMAGE_MEMBERS)
    for name in SIGNED_IMAGE_MEMBER_NAMES:
        row = members[name]
        if (
            type(row) is not dict
            or set(row) != {"size_bytes", "sha256"}
            or type(row["size_bytes"]) is not int
            or row["size_bytes"] < 0
            or not _is_sha256(row["sha256"])
        ):
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_IMAGE_MEMBERS)

    descriptor = extract_sppdiag_descriptor(diagnostic_efi_bytes)
    if descriptor.schema != "sol-spp-diagbundle-descriptor/v1":
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_IMAGE_SEAM)
    if descriptor.input_closure_address != input_closure_address:
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_IMAGE_SEAM)

    ordered_members = {name: members[name] for name in sorted(SIGNED_IMAGE_MEMBER_NAMES)}
    address = _protocol_image_binding_address(
        schema=SIGNED_IMAGE_SCHEMA_ID,
        node_kind=NODE_KIND_SIGNED_IMAGE,
        artifact_state=NODE_ARTIFACT_STATE,
        layout=SIGNED_IMAGE_LAYOUT,
        input_closure_address=input_closure_address,
        members=ordered_members,
    )
    manifest_bytes = canonical_dumps(
        {
            "schema": SIGNED_IMAGE_SCHEMA_ID,
            "node_kind": NODE_KIND_SIGNED_IMAGE,
            "artifact_state": NODE_ARTIFACT_STATE,
            "layout": SIGNED_IMAGE_LAYOUT,
            "input_closure_address": input_closure_address,
            "members": ordered_members,
        }
    )
    late_binding_record = canonical_dumps(
        {
            "schema": "sol-spp-diag-runtime-late-binding/v1",
            "image_binding_address": address,
            "input_closure_address": input_closure_address,
        }
    )
    if output_path is not None:
        _write_single_file_transactional(manifest_bytes, output_path)
    return BindImageResult(image_binding_address=address, manifest_bytes=manifest_bytes, late_binding_record=late_binding_record)


def _validate_stage_inputs(
    guard: HermeticGuard, files: tuple[StagedFileSpec, ...], destination: str
) -> tuple[StagedFileSpec, ...]:
    if type(destination) is not str or not os.path.isabs(destination):
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_DEST_PATH)
    if os.path.lexists(destination):
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_DESTINATION_EXISTS)
    if type(files) is not tuple or not files:
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_DEST_PATH)
    allowed_reads = guard.allowed_reads()
    paths: set[str] = set()
    for spec in files:
        if type(spec) is not StagedFileSpec or not _is_relative_path(spec.dest_relpath) or spec.dest_relpath in paths:
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_DEST_PATH)
        paths.add(spec.dest_relpath)
        if type(spec.source_abspath) is not str or not os.path.isabs(spec.source_abspath):
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_DECLARATION)
        if os.path.realpath(spec.source_abspath) not in allowed_reads:
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_DECLARATION)
        if type(spec.mode) is not int or not 0 <= spec.mode <= 0o7777:
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_DEST_PATH)
        if type(spec.declared_size) is not int or spec.declared_size < 0 or not _is_sha256(spec.declared_sha256):
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_CONTENT)
    return tuple(sorted(files, key=lambda spec: spec.dest_relpath))


def _read_and_validate_sources(guard: HermeticGuard, files: tuple[StagedFileSpec, ...]) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for spec in files:
        source_stat = guard.stat_read(spec.source_abspath)
        if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_nlink != 1:
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_STAT)
        data = guard.read_bytes(spec.source_abspath)
        if len(data) != spec.declared_size or hashlib.sha256(data).hexdigest() != spec.declared_sha256:
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_SOURCE_CONTENT)
        payloads[spec.dest_relpath] = data
    return payloads


def _write_staged_file(staging_dir: str, spec: StagedFileSpec, data: bytes, directories: set[str]) -> None:
    destination = os.path.join(staging_dir, spec.dest_relpath)
    _create_parent_directories(staging_dir, spec.dest_relpath, directories)
    final_mode = spec.mode & ~0o222
    try:
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | _O_NOFOLLOW, final_mode)
    except OSError:
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
    try:
        os.fchmod(descriptor, final_mode)
        _write_all(descriptor, data)
        os.fsync(descriptor)
    except OSError:
        _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
    finally:
        os.close(descriptor)


def _create_parent_directories(staging_dir: str, relpath: str, directories: set[str]) -> None:
    current = staging_dir
    for component in relpath.split("/")[:-1]:
        current = os.path.join(current, component)
        try:
            os.mkdir(current, 0o700)
        except FileExistsError:
            try:
                existing = os.lstat(current)
            except OSError:
                _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
            if not stat.S_ISDIR(existing.st_mode) or stat.S_ISLNK(existing.st_mode):
                _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
        except OSError:
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
        directories.add(current)


def _fsync_directories(directories: set[str]) -> None:
    for directory in sorted(directories, key=lambda value: value.count(os.sep), reverse=True):
        try:
            descriptor = os.open(directory, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
        except OSError:
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
        try:
            os.fsync(descriptor)
        except OSError:
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
        finally:
            os.close(descriptor)


def _reopen_and_validate(staging_dir: str, files: tuple[StagedFileSpec, ...]) -> tuple[InstallInventoryRow, ...]:
    inventory: list[InstallInventoryRow] = []
    for spec in files:
        path = os.path.join(staging_dir, spec.dest_relpath)
        try:
            descriptor = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
        except OSError:
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_REOPEN)
        try:
            reopened = os.fstat(descriptor)
            expected_mode = spec.mode & ~0o222
            if (
                not stat.S_ISREG(reopened.st_mode)
                or reopened.st_nlink != 1
                or stat.S_IMODE(reopened.st_mode) != expected_mode
            ):
                _fail(CP_SPP_DIAG_RUNTIME_BUILD_REOPEN)
            data = _read_all(descriptor)
            digest = hashlib.sha256(data).hexdigest()
            if len(data) != spec.declared_size or digest != spec.declared_sha256:
                _fail(CP_SPP_DIAG_RUNTIME_BUILD_REOPEN)
            inventory.append(
                InstallInventoryRow(
                    path=spec.dest_relpath,
                    mode=stat.S_IMODE(reopened.st_mode),
                    size_bytes=len(data),
                    sha256=digest,
                )
            )
        finally:
            os.close(descriptor)
    return tuple(inventory)


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            _fail(CP_SPP_DIAG_RUNTIME_BUILD_STAGING)
        offset += written


def _rename_noreplace(source: str, destination: str) -> None:
    """Atomically publish one same-filesystem path without replacing a racer."""

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable")
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    result = renameat2(
        _AT_FDCWD,
        os.fsencode(source),
        _AT_FDCWD,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination)


def _read_all(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _directory_identity(descriptor: int) -> tuple[int, int]:
    value = os.fstat(descriptor)
    return (value.st_dev, value.st_ino)


def _inventory_object(row: InstallInventoryRow) -> dict:
    return {"path": row.path, "mode": row.mode, "size_bytes": row.size_bytes, "sha256": row.sha256}


def _cleanup_staging(staging_dir: str | None) -> None:
    if staging_dir is None or not os.path.lexists(staging_dir):
        return
    if os.path.islink(staging_dir) or not os.path.isdir(staging_dir):
        os.unlink(staging_dir)
    else:
        shutil.rmtree(staging_dir)


def _call_fault_hook(fault_hook: object, boundary: str) -> None:
    if fault_hook is not None:
        fault_hook(boundary)


_PARTUUID_PATTERN: Final = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_PROFILE_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def _is_canonical_partuuid(value: object) -> bool:
    return type(value) is str and _PARTUUID_PATTERN.fullmatch(value) is not None


def _is_profile_id(value: object) -> bool:
    return type(value) is str and _PROFILE_PATTERN.fullmatch(value) is not None


def _is_relative_path(path: object) -> bool:
    if type(path) is not str or not path or path.startswith("/") or "\x00" in path:
        return False
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    return posixpath.normpath(path) == path


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and value == value.lower() and all(c in "0123456789abcdef" for c in value)


def _fail(reason_code: str) -> None:
    raise SppDiagRuntimeBuildError(reason_code)
