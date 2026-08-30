#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Direct, fail-closed builder for the sealed SPP boot v3 payload."""

from __future__ import annotations

import ast
import ctypes
import errno
import hashlib
import os
import stat
from collections import namedtuple
from dataclasses import dataclass
from typing import Final

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_prohibited import check_content_markers
from conf_proc_provenance_v2_inspect import InspectionResult, _is_issued_inspection_result
from conf_proc_spp_boot_v3 import BootBindingV3, is_issued_boot_binding_v3
from conf_proc_spp_reasons_v3 import (
    ApplianceErrorV3,
    CP_SPP_PAYLOAD_V3_ADDRESS,
    CP_SPP_PAYLOAD_V3_ARCHIVE,
    CP_SPP_PAYLOAD_V3_AUTHORITY,
    CP_SPP_PAYLOAD_V3_CONSISTENCY,
    CP_SPP_PAYLOAD_V3_IMPORT,
    CP_SPP_PAYLOAD_V3_PLAN,
    CP_SPP_PAYLOAD_V3_POLICY,
    CP_SPP_PAYLOAD_V3_SOURCE,
    CP_SPP_PAYLOAD_V3_STAGING,
)


__all__ = ("BootPayloadResultV3", "compile_boot_payload_v3")

_PLAN_SCHEMA_V3: Final = "conf-proc-spp-boot-payload-plan/v3"
_PACKAGE_SCHEMA_V3: Final = "conf-proc-spp-boot-payload-package/v3"
_MAX_SOURCE_BYTES: Final = 32 * 1024 * 1024
_MAX_TOTAL_BYTES: Final = 128 * 1024 * 1024
_HEX: Final = frozenset("0123456789abcdef")
_RENAME_NOREPLACE: Final = 1
_CPIO_MAGIC: Final = b"070701"
_CPIO_TRAILER: Final = b"TRAILER!!!"
_SOURCE_ROOT_ARCHIVE: Final = "/usr/lib/spp/"
_PAYLOAD_NAMES: Final = ("spp-boot-payload.cpio", "spp-boot-payload.package.json")


@dataclass(frozen=True)
class _SourceAuthorityV3:
    archive_path: str
    role: str
    mode: int
    size_bytes: int
    sha256: str


BOOT_PAYLOAD_SOURCE_AUTHORITY_V3: Final = (
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_geometry.py", "support", 0o444, 2725, "f8273165758c6460bb10d840cb67097a423df819c449119ad15d57b21e05205a"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_json.py", "support", 0o444, 4425, "b18793b443e3ab2dcaf4bb7762d2e9c52f4d88daddf7bfb614b87ac0d8e80e21"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_lock.py", "support", 0o444, 21243, "296cdc9ba1238dfa6ac982a33f6b1411a0d7730cbb88edbcfc4492c52c729bba"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_module_authority.py", "support", 0o444, 3173, "01e9c44c6221b54d792c6f5ff65a9bb82e0b77a29a397b9932b1a13c7d0efe26"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_policy.py", "support", 0o444, 16686, "e2c48f05dd4233bc8267bb53804e25fd948e06e73a80c6d04ac1e3299118c473"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_provenance_v2.py", "support", 0o444, 21957, "e94a0818b2d14168190ef7ed490cc147eb18dafd837087eab883630958b59ccd"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_provenance_v2_manifest.py", "support", 0o444, 16846, "bd3c3ba87c7f6db52759e9f5dd16a5d447b5521c24f714043492ad713549e399"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_reasons.py", "support", 0o444, 12571, "c56b629a0fc156860c7400d6bc6884c1f41c8a9e4b0626ef4f2821f71102067a"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_spp_boot.py", "engine", 0o444, 147664, "c1dfba4c4ca71cf64ab8ecef12440950edab88f6ef3e2fb73791fc1f900076a6"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_spp_boot_dispatch_v3.py", "dispatcher", 0o444, 1141, "83a0652bff152a7e9e96e4f5daa0bde0278092d012d0b8fbf8832a39f23fa139"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_spp_boot_v3.py", "engine", 0o444, 90009, "0253d0c995fb2609668ac5909db7652940d7bf11c31daaa96b148b4fd87b2bae"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_spp_boot_v3_resource.py", "support", 0o444, 25792, "b172f2dd4dbe70e295e4dbdd0ebe066c7e247e8d2183db22b15ac48f5afc57de"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_spp_boot_v3_semantics.py", "engine", 0o444, 127970, "573e613c082557952c47041dbe1e88ca5473e97b781f78038d2c983cf9cc96a9"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_spp_boot_v3_tables.py", "support", 0o444, 37125, "0c50b6a46acd5152d63757956cba65f699c58e1a1566807448f5779e28787824"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_spp_boot_v3_wire.py", "support", 0o444, 41779, "00c03278031280dd572bf221be2075ab741e36b378af8a7fd2c874560b840e90"),
    _SourceAuthorityV3("/usr/lib/spp/conf_proc_spp_reasons_v3.py", "support", 0o444, 3215, "4ca5821dd0edca148bffa312fd6d9208083fa5f6e22345e61c5284d3cbbcdf75"),
)
_ExpectedSourceRowV3 = namedtuple("_ExpectedSourceRowV3", "archive_path role mode size_bytes sha256")
_EXPECTED_LITERAL_SOURCE_ROWS_V3: Final = (
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_geometry.py", "support", 0o444, 2725, "f8273165758c6460bb10d840cb67097a423df819c449119ad15d57b21e05205a"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_json.py", "support", 0o444, 4425, "b18793b443e3ab2dcaf4bb7762d2e9c52f4d88daddf7bfb614b87ac0d8e80e21"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_lock.py", "support", 0o444, 21243, "296cdc9ba1238dfa6ac982a33f6b1411a0d7730cbb88edbcfc4492c52c729bba"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_module_authority.py", "support", 0o444, 3173, "01e9c44c6221b54d792c6f5ff65a9bb82e0b77a29a397b9932b1a13c7d0efe26"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_policy.py", "support", 0o444, 16686, "e2c48f05dd4233bc8267bb53804e25fd948e06e73a80c6d04ac1e3299118c473"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_provenance_v2.py", "support", 0o444, 21957, "e94a0818b2d14168190ef7ed490cc147eb18dafd837087eab883630958b59ccd"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_provenance_v2_manifest.py", "support", 0o444, 16846, "bd3c3ba87c7f6db52759e9f5dd16a5d447b5521c24f714043492ad713549e399"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_reasons.py", "support", 0o444, 12571, "c56b629a0fc156860c7400d6bc6884c1f41c8a9e4b0626ef4f2821f71102067a"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_spp_boot.py", "engine", 0o444, 147664, "c1dfba4c4ca71cf64ab8ecef12440950edab88f6ef3e2fb73791fc1f900076a6"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_spp_boot_dispatch_v3.py", "dispatcher", 0o444, 1141, "83a0652bff152a7e9e96e4f5daa0bde0278092d012d0b8fbf8832a39f23fa139"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_spp_boot_v3.py", "engine", 0o444, 90009, "0253d0c995fb2609668ac5909db7652940d7bf11c31daaa96b148b4fd87b2bae"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_spp_boot_v3_resource.py", "support", 0o444, 25792, "b172f2dd4dbe70e295e4dbdd0ebe066c7e247e8d2183db22b15ac48f5afc57de"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_spp_boot_v3_semantics.py", "engine", 0o444, 127970, "573e613c082557952c47041dbe1e88ca5473e97b781f78038d2c983cf9cc96a9"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_spp_boot_v3_tables.py", "support", 0o444, 37125, "0c50b6a46acd5152d63757956cba65f699c58e1a1566807448f5779e28787824"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_spp_boot_v3_wire.py", "support", 0o444, 41779, "00c03278031280dd572bf221be2075ab741e36b378af8a7fd2c874560b840e90"),
    _ExpectedSourceRowV3("/usr/lib/spp/conf_proc_spp_reasons_v3.py", "support", 0o444, 3215, "4ca5821dd0edca148bffa312fd6d9208083fa5f6e22345e61c5284d3cbbcdf75"),
)
_EXPECTED_LOCAL_IMPORTS_V3: Final = {
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
_PROHIBITED_COMPONENTS: Final = frozenset({
    "apt", "cloud_init", "containerd", "coredump", "dnf", "docker", "getty",
    "hibernate", "journald", "kdump", "mok", "packagekit", "recovery", "serial",
    "shim", "socket", "ssh", "sshd", "subprocess", "swap", "waagent", "walinux",
})
_AuthoritySpecV3 = namedtuple("_AuthoritySpecV3", "attribute path role")
_AUTHORITY_SPECS_V3: Final = (
    _AuthoritySpecV3("root_lock_bytes", "/etc/spp/authority/root-lock.json", "root_lock"),
    _AuthoritySpecV3("runtime_closure_bytes", "/etc/spp/authority/runtime-closure.json", "runtime_closure"),
    _AuthoritySpecV3("verity_rules_bytes", "/etc/spp/authority/verity-rules.json", "verity_rules"),
    _AuthoritySpecV3("tcb_identity_bytes", "/etc/spp/authority/tcb-identity.json", "tcb_identity"),
    _AuthoritySpecV3("builder_source_bytes", "/etc/spp/authority/designated-builder-source.py", "designated_builder_source"),
    _AuthoritySpecV3("policy_bytes", "/etc/spp/authority/policy.json", "policy"),
    _AuthoritySpecV3("accepted_manifest_bytes", "/etc/spp/authority/appliance.manifest.json", "accepted_manifest"),
    _AuthoritySpecV3("kernel_feature_contract_bytes", "/etc/spp/authority/kernel-features.json", "kernel_features"),
    _AuthoritySpecV3("trusted_certificate_bundle_bytes", "/etc/spp/authority/trusted-module-signers.pem", "trusted_module_signers"),
    _AuthoritySpecV3("boot_contract_bytes", "/etc/spp/authority/boot-contract.json", "boot_contract"),
    _AuthoritySpecV3("module_plan_bytes", "/etc/spp/authority/module-load-plan.json", "module_load_plan"),
    _AuthoritySpecV3("gpt_layout_rules_bytes", "/etc/spp/authority/gpt-layout-rules.json", "gpt_layout_rules"),
    _AuthoritySpecV3("literal_v3_observation_shape_bytes", "/etc/spp/authority/literal-v3-observation-shape.bin", "literal_v3_observation_shape"),
)


@dataclass(frozen=True)
class BootPayloadResultV3:
    state: str
    cpio_sha256: str
    package_sha256: str
    output_path: str


@dataclass(frozen=True)
class _PlanV3:
    source_paths: tuple[str, ...]


@dataclass(frozen=True)
class _PayloadAddressV3:
    boot_contract_sha256: str
    cpio_sha256: str
    package_sha256: str


@dataclass(frozen=True)
class _MemberV3:
    path: str
    entry_type: str
    role: str
    mode: int
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass(frozen=True)
class _IdentityV3:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass
class _PinnedRootV3:
    path: str
    descriptors: list[int]
    identities: list[_IdentityV3]

    @property
    def fd(self) -> int:
        return self.descriptors[-1]

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


@dataclass
class _FrozenSourceV3:
    authority: _SourceAuthorityV3
    relative_path: str
    parent_fd: int
    parent_identity: _IdentityV3
    leaf_name: str
    descriptor: int
    identity: _IdentityV3
    data: bytes

    def close(self) -> None:
        for descriptor in (self.descriptor, self.parent_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _error(code: str, message: str = "SPP boot v3 payload rejected") -> None:
    raise ApplianceErrorV3(code, message) from None


def _sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _HEX


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _identity(value: os.stat_result) -> _IdentityV3:
    return _IdentityV3(value.st_dev, value.st_ino, stat.S_IMODE(value.st_mode), value.st_uid, value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _absolute_normalized(value: object, code: str) -> str:
    if type(value) is not str or not value.startswith("/") or value == "/" or "\x00" in value:
        _error(code)
    parts = value.split("/")[1:]
    if not parts or any(not part or part in {".", ".."} for part in parts):
        _error(code)
    return value


def _relative_normalized(value: object, code: str) -> str:
    if type(value) is not str or not value or value.startswith("/") or "\x00" in value:
        _error(code)
    if any(not part or part in {".", ".."} for part in value.split("/")):
        _error(code)
    try:
        if len(value.encode("utf-8")) > 255:
            _error(code)
    except UnicodeEncodeError:
        _error(code)
    return value


def _check_component_policy(value: str, code: str) -> None:
    if any(component.casefold() in _PROHIBITED_COMPONENTS for component in value.strip("/").split("/")):
        _error(code)


def _validate_literal_authority() -> None:
    rows = BOOT_PAYLOAD_SOURCE_AUTHORITY_V3
    if type(rows) is not tuple or len(rows) != 16 or any(type(row) is not _SourceAuthorityV3 for row in rows):
        _error(CP_SPP_PAYLOAD_V3_AUTHORITY)
    actual = tuple((row.archive_path, row.role, row.mode, row.size_bytes, row.sha256) for row in rows)
    if actual != _EXPECTED_LITERAL_SOURCE_ROWS_V3:
        _error(CP_SPP_PAYLOAD_V3_AUTHORITY)
    previous = b""
    seen: set[str] = set()
    roles = {"support": 0, "engine": 0, "dispatcher": 0}
    for row in rows:
        if any(type(value) is not expected for value, expected in ((row.archive_path, str), (row.role, str), (row.mode, int), (row.size_bytes, int), (row.sha256, str))):
            _error(CP_SPP_PAYLOAD_V3_AUTHORITY)
        try:
            encoded = row.archive_path.encode("utf-8")
        except UnicodeEncodeError:
            _error(CP_SPP_PAYLOAD_V3_AUTHORITY)
        if (
            not row.archive_path.startswith(_SOURCE_ROOT_ARCHIVE)
            or row.archive_path == _SOURCE_ROOT_ARCHIVE
            or len(encoded) > 255
            or encoded <= previous
            or row.archive_path in seen
            or row.mode != 0o444
            or not _sha256(row.sha256)
            or not 1 <= row.size_bytes <= _MAX_SOURCE_BYTES
            or row.role not in roles
        ):
            _error(CP_SPP_PAYLOAD_V3_AUTHORITY)
        _absolute_normalized(row.archive_path, CP_SPP_PAYLOAD_V3_AUTHORITY)
        _check_component_policy(row.archive_path, CP_SPP_PAYLOAD_V3_AUTHORITY)
        previous = encoded
        seen.add(row.archive_path)
        roles[row.role] += 1
    if roles != {"support": 12, "engine": 3, "dispatcher": 1} or sum(row.size_bytes for row in rows) != 574321:
        _error(CP_SPP_PAYLOAD_V3_AUTHORITY)
    paths = sorted(seen, key=lambda value: value.encode("utf-8"))
    if any(right.startswith(left + "/") for left, right in zip(paths, paths[1:], strict=False)):
        _error(CP_SPP_PAYLOAD_V3_AUTHORITY)


def _validate_issued_inputs(inspection: object, binding: object) -> tuple[InspectionResult, BootBindingV3]:
    if not _is_issued_inspection_result(inspection) or not is_issued_boot_binding_v3(binding):
        _error(CP_SPP_PAYLOAD_V3_AUTHORITY)
    assert type(inspection) is InspectionResult and type(binding) is BootBindingV3
    if (
        inspection.state != "artifact_consistent"
        or inspection.hardware_qualification != "not_qualified"
        or inspection.manifest_sha256 != _digest(binding.accepted_manifest_bytes)
        or not all(_sha256(value) for value in (
            inspection.artifact_input_sha256,
            inspection.execution_provenance_sha256,
            inspection.manifest_sha256,
            binding.boot_contract_sha256,
            _digest(binding.module_plan_bytes),
        ))
    ):
        _error(CP_SPP_PAYLOAD_V3_AUTHORITY)
    return inspection, binding


def _validate_plan(plan_bytes: object, binding: BootBindingV3) -> _PlanV3:
    if type(plan_bytes) is not bytes:
        _error(CP_SPP_PAYLOAD_V3_PLAN)
    try:
        value = canonical_loads(plan_bytes)
    except Exception:
        _error(CP_SPP_PAYLOAD_V3_PLAN)
    if type(value) is not dict or set(value) != {"schema", "plan_version", "boot_contract_sha256", "module_plan_sha256", "entries"}:
        _error(CP_SPP_PAYLOAD_V3_PLAN)
    if (
        value.get("schema") != _PLAN_SCHEMA_V3
        or value.get("plan_version") != 3
        or type(value.get("boot_contract_sha256")) is not str
        or type(value.get("module_plan_sha256")) is not str
        or type(value.get("entries")) is not list
        or value["boot_contract_sha256"] != binding.boot_contract_sha256
        or value["module_plan_sha256"] != _digest(binding.module_plan_bytes)
        or len(value["entries"]) != len(BOOT_PAYLOAD_SOURCE_AUTHORITY_V3)
    ):
        _error(CP_SPP_PAYLOAD_V3_PLAN)
    source_paths: list[str] = []
    casefolded: set[str] = set()
    for item, authority in zip(value["entries"], BOOT_PAYLOAD_SOURCE_AUTHORITY_V3, strict=True):
        if type(item) is not dict or set(item) != {"archive_path", "source_path"} or item.get("archive_path") != authority.archive_path:
            _error(CP_SPP_PAYLOAD_V3_PLAN)
        source = _relative_normalized(item.get("source_path"), CP_SPP_PAYLOAD_V3_PLAN)
        if source.casefold() in casefolded:
            _error(CP_SPP_PAYLOAD_V3_PLAN)
        casefolded.add(source.casefold())
        source_paths.append(source)
    if len(set(source_paths)) != len(source_paths):
        _error(CP_SPP_PAYLOAD_V3_PLAN)
    normalized = sorted(casefolded, key=lambda value: value.encode("utf-8"))
    if any(right.startswith(left + "/") for left, right in zip(normalized, normalized[1:], strict=False)):
        _error(CP_SPP_PAYLOAD_V3_PLAN)
    return _PlanV3(tuple(source_paths))


def _trusted_directory(value: os.stat_result, *, final: bool) -> None:
    if not stat.S_ISDIR(value.st_mode) or value.st_uid not in {0, os.geteuid()}:
        _error(CP_SPP_PAYLOAD_V3_SOURCE)
    mode = stat.S_IMODE(value.st_mode)
    if value.st_uid == os.geteuid() and mode & 0o022:
        _error(CP_SPP_PAYLOAD_V3_SOURCE)
    if value.st_uid == 0 and mode & 0o022 and not mode & stat.S_ISVTX:
        _error(CP_SPP_PAYLOAD_V3_SOURCE)
    if final and (value.st_uid != os.geteuid() or mode != 0o700):
        _error(CP_SPP_PAYLOAD_V3_SOURCE)


def _open_pinned_root(path: str) -> _PinnedRootV3:
    root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    descriptors = [root_fd]
    identities = [_identity(os.fstat(root_fd))]
    try:
        _trusted_directory(os.fstat(root_fd), final=False)
        current = root_fd
        for component in path.split("/")[1:]:
            current = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
            descriptors.append(current)
            identities.append(_identity(os.fstat(current)))
            _trusted_directory(os.fstat(current), final=False)
        _trusted_directory(os.fstat(current), final=True)
        return _PinnedRootV3(path, descriptors, identities)
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _revalidate_root(root: _PinnedRootV3) -> None:
    for descriptor, expected in zip(root.descriptors, root.identities, strict=True):
        current = _identity(os.fstat(descriptor))
        if current.device != expected.device or current.inode != expected.inode or current.mode != expected.mode or current.uid != expected.uid or current.gid != expected.gid:
            _error(CP_SPP_PAYLOAD_V3_SOURCE)
    reopened = _open_pinned_root(root.path)
    try:
        for expected, current in zip(root.identities, reopened.identities, strict=True):
            if (expected.device, expected.inode, expected.mode, expected.uid, expected.gid) != (current.device, current.inode, current.mode, current.uid, current.gid):
                _error(CP_SPP_PAYLOAD_V3_SOURCE)
    finally:
        reopened.close()


def _read_source(root: _PinnedRootV3, authority: _SourceAuthorityV3, relative_path: str) -> _FrozenSourceV3:
    components = relative_path.split("/")
    parent = os.dup(root.fd)
    descriptor = -1
    try:
        for component in components[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
            _trusted_directory(os.fstat(parent), final=False)
        descriptor = os.open(components[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or before.st_size != authority.size_bytes:
            _error(CP_SPP_PAYLOAD_V3_SOURCE)
        data = bytearray()
        while len(data) < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - len(data)))
            if not chunk:
                _error(CP_SPP_PAYLOAD_V3_SOURCE)
            data.extend(chunk)
        if os.read(descriptor, 1) or _digest(bytes(data)) != authority.sha256 or _identity(os.fstat(descriptor)) != _identity(before):
            _error(CP_SPP_PAYLOAD_V3_SOURCE)
        return _FrozenSourceV3(authority, relative_path, parent, _identity(os.fstat(parent)), components[-1], descriptor, _identity(before), bytes(data))
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)
        raise


def _revalidate_source(root: _PinnedRootV3, source: _FrozenSourceV3) -> None:
    if _identity(os.fstat(source.descriptor)) != source.identity or _identity(os.fstat(source.parent_fd)) != source.parent_identity:
        _error(CP_SPP_PAYLOAD_V3_SOURCE)
    parent = os.dup(root.fd)
    try:
        for component in source.relative_path.split("/")[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
            _trusted_directory(os.fstat(parent), final=False)
        if _identity(os.fstat(parent)) != source.parent_identity:
            _error(CP_SPP_PAYLOAD_V3_SOURCE)
        reopened = os.open(source.leaf_name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            if _identity(os.fstat(reopened)) != source.identity:
                _error(CP_SPP_PAYLOAD_V3_SOURCE)
        finally:
            os.close(reopened)
    except OSError:
        _error(CP_SPP_PAYLOAD_V3_SOURCE)
    finally:
        os.close(parent)


def _check_source_content(source: _FrozenSourceV3) -> None:
    try:
        check_content_markers(source.authority.archive_path, source.data)
    except Exception:
        _error(CP_SPP_PAYLOAD_V3_POLICY, f"source rejected sha256={source.authority.sha256[:16]}")


def _import_closure(sources: tuple[_FrozenSourceV3, ...]) -> tuple[str, ...]:
    local = {source.authority.archive_path.rsplit("/", 1)[-1][:-3]: source for source in sources}
    if set(local) != set(_EXPECTED_LOCAL_IMPORTS_V3):
        _error(CP_SPP_PAYLOAD_V3_IMPORT)
    external: set[str] = set()
    for module, source in local.items():
        try:
            tree = ast.parse(source.data, filename=source.authority.archive_path, mode="exec")
        except (SyntaxError, ValueError, UnicodeDecodeError):
            _error(CP_SPP_PAYLOAD_V3_IMPORT)
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if not alias.name or any(not part.isidentifier() for part in alias.name.split(".")):
                        _error(CP_SPP_PAYLOAD_V3_IMPORT)
                    target = alias.name.split(".")[0]
                    _check_component_policy(alias.name.replace(".", "/"), CP_SPP_PAYLOAD_V3_POLICY)
                    (imports if target in local else external).add(target if target in local else alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level != 0 or node.module is None or any(alias.name == "*" or alias.asname is not None for alias in node.names):
                    _error(CP_SPP_PAYLOAD_V3_IMPORT)
                if node.module == "__future__":
                    continue
                if any(not part.isidentifier() for part in node.module.split(".")):
                    _error(CP_SPP_PAYLOAD_V3_IMPORT)
                _check_component_policy(node.module.replace(".", "/"), CP_SPP_PAYLOAD_V3_POLICY)
                target = node.module.split(".")[0]
                (imports if target in local else external).add(target if target in local else node.module)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__":
                _error(CP_SPP_PAYLOAD_V3_IMPORT)
        if imports != _EXPECTED_LOCAL_IMPORTS_V3[module]:
            _error(CP_SPP_PAYLOAD_V3_IMPORT)
    reached = {"conf_proc_spp_boot_dispatch_v3"}
    while True:
        expanded = reached | set().union(*(_EXPECTED_LOCAL_IMPORTS_V3[module] for module in reached))
        if expanded == reached:
            break
        reached = expanded
    if reached != set(local):
        _error(CP_SPP_PAYLOAD_V3_IMPORT)
    return tuple(sorted(external, key=lambda value: value.encode("utf-8")))


def _members(sources: tuple[_FrozenSourceV3, ...], binding: BootBindingV3) -> tuple[_MemberV3, ...]:
    members = [_MemberV3(item.authority.archive_path, "source", item.authority.role, item.authority.mode, item.data) for item in sources]
    for attribute, path, role in _AUTHORITY_SPECS_V3:
        data = getattr(binding, attribute)
        if type(data) is not bytes or not 1 <= len(data) <= _MAX_SOURCE_BYTES:
            _error(CP_SPP_PAYLOAD_V3_AUTHORITY)
        members.append(_MemberV3(path, "sealed_authority", role, 0o444, data))
    if sum(len(member.data) for member in members) > _MAX_TOTAL_BYTES * 2:
        _error(CP_SPP_PAYLOAD_V3_AUTHORITY)
    return tuple(sorted(members, key=lambda item: item.path.encode("utf-8")))


def _pad4(value: int) -> int:
    return (-value) & 3


def _newc_member(index: int, member: _MemberV3) -> bytes:
    name = member.path[1:].encode("utf-8") + b"\0"
    fields = (index, stat.S_IFREG | member.mode, 0, 0, 1, 0, len(member.data), 0, 0, 0, 0, len(name), 0)
    header = _CPIO_MAGIC + b"".join(f"{field:08x}".encode("ascii") for field in fields)
    return header + name + b"\0" * _pad4(len(header) + len(name)) + member.data + b"\0" * _pad4(len(member.data))


def _newc_archive(members: tuple[_MemberV3, ...]) -> bytes:
    body = b"".join(_newc_member(index, member) for index, member in enumerate(members, 1))
    name = _CPIO_TRAILER + b"\0"
    fields = (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(name), 0)
    header = _CPIO_MAGIC + b"".join(f"{field:08x}".encode("ascii") for field in fields)
    return body + header + name + b"\0" * _pad4(len(header) + len(name))


def _parse_newc(data: bytes) -> tuple[tuple[str, int, bytes], ...]:
    offset = 0
    records: list[tuple[str, int, bytes]] = []
    while True:
        if offset + 110 > len(data) or data[offset:offset + 6] != _CPIO_MAGIC:
            _error(CP_SPP_PAYLOAD_V3_ARCHIVE)
        raw = data[offset + 6:offset + 110]
        if any(byte not in b"0123456789abcdef" for byte in raw):
            _error(CP_SPP_PAYLOAD_V3_ARCHIVE)
        fields = tuple(int(raw[index:index + 8], 16) for index in range(0, 104, 8))
        offset += 110
        name_size, size = fields[11], fields[6]
        if name_size < 1 or offset + name_size > len(data):
            _error(CP_SPP_PAYLOAD_V3_ARCHIVE)
        name_data = data[offset:offset + name_size]
        offset += name_size
        pad = _pad4(110 + name_size)
        if offset + pad > len(data) or any(data[offset:offset + pad]) or not name_data.endswith(b"\0"):
            _error(CP_SPP_PAYLOAD_V3_ARCHIVE)
        offset += pad
        if offset + size > len(data):
            _error(CP_SPP_PAYLOAD_V3_ARCHIVE)
        payload = data[offset:offset + size]
        offset += size
        pad = _pad4(size)
        if offset + pad > len(data) or any(data[offset:offset + pad]):
            _error(CP_SPP_PAYLOAD_V3_ARCHIVE)
        offset += pad
        try:
            name = name_data[:-1].decode("utf-8")
        except UnicodeDecodeError:
            _error(CP_SPP_PAYLOAD_V3_ARCHIVE)
        if name == _CPIO_TRAILER.decode("ascii"):
            if fields != (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0) or offset != len(data):
                _error(CP_SPP_PAYLOAD_V3_ARCHIVE)
            return tuple(records)
        if not name or name.startswith("/") or "\x00" in name or fields[0] != len(records) + 1 or fields[1] != stat.S_IFREG | 0o444 or fields[4] != 1 or any(fields[index] for index in (2, 3, 5, 7, 8, 9, 10, 12)):
            _error(CP_SPP_PAYLOAD_V3_ARCHIVE)
        records.append(("/" + name, fields[1] & 0o7777, payload))


def _entry_record(member: _MemberV3) -> dict[str, object]:
    return {"path": member.path, "role": member.role, "mode": member.mode, "size_bytes": len(member.data), "sha256": member.sha256}


def _package_bytes(inspection: InspectionResult, binding: BootBindingV3, cpio: bytes, members: tuple[_MemberV3, ...], unresolved: tuple[str, ...]) -> bytes:
    return canonical_dumps({
        "schema": _PACKAGE_SCHEMA_V3,
        "package_version": 3,
        "status": "built_unqualified",
        "boot_qualification": "not_qualified",
        "runtime_closure": "unresolved",
        "activation_closure": "unresolved",
        "directory_closure": "unresolved",
        "h4_artifact_input_sha256": inspection.artifact_input_sha256,
        "h4_execution_provenance_sha256": inspection.execution_provenance_sha256,
        "boot_contract_sha256": binding.boot_contract_sha256,
        "module_plan_sha256": _digest(binding.module_plan_bytes),
        "cpio_sha256": _digest(cpio),
        "entries": [_entry_record(member) for member in members],
        "external_imports_declared_unresolved": list(unresolved),
    })


def _payload_address(binding: BootBindingV3, cpio: bytes, package: bytes) -> _PayloadAddressV3:
    return _PayloadAddressV3(binding.boot_contract_sha256, _digest(cpio), _digest(package))


def _check_builder_consistency(cpio: bytes, package: bytes, members: tuple[_MemberV3, ...], inspection: InspectionResult, binding: BootBindingV3, address: _PayloadAddressV3, unresolved: tuple[str, ...]) -> None:
    if address != _payload_address(binding, cpio, package) or _parse_newc(cpio) != tuple((member.path, member.mode, member.data) for member in members):
        _error(CP_SPP_PAYLOAD_V3_CONSISTENCY)
    try:
        value = canonical_loads(package)
    except Exception:
        _error(CP_SPP_PAYLOAD_V3_CONSISTENCY)
    keys = {"schema", "package_version", "status", "boot_qualification", "runtime_closure", "activation_closure", "directory_closure", "h4_artifact_input_sha256", "h4_execution_provenance_sha256", "boot_contract_sha256", "module_plan_sha256", "cpio_sha256", "entries", "external_imports_declared_unresolved"}
    expected = {
        "schema": _PACKAGE_SCHEMA_V3, "status": "built_unqualified", "boot_qualification": "not_qualified", "runtime_closure": "unresolved", "activation_closure": "unresolved", "directory_closure": "unresolved", "h4_artifact_input_sha256": inspection.artifact_input_sha256, "h4_execution_provenance_sha256": inspection.execution_provenance_sha256, "boot_contract_sha256": binding.boot_contract_sha256, "module_plan_sha256": _digest(binding.module_plan_bytes), "cpio_sha256": address.cpio_sha256,
    }
    if type(value) is not dict or set(value) != keys or canonical_dumps(value) != package or value.get("package_version") != 3 or any(type(value.get(key)) is not str or value[key] != expected_value for key, expected_value in expected.items()) or value.get("entries") != [_entry_record(member) for member in members] or value.get("external_imports_declared_unresolved") != list(unresolved):
        _error(CP_SPP_PAYLOAD_V3_CONSISTENCY)


def _open_or_create_directory(parent_fd: int, name: str) -> int:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    value = os.fstat(descriptor)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700:
        os.close(descriptor)
        _error(CP_SPP_PAYLOAD_V3_ADDRESS)
    return descriptor


def _address_parent(output: _PinnedRootV3, binding: BootBindingV3, cpio_digest: str) -> tuple[int, list[int]]:
    current = os.dup(output.fd)
    opened = [current]
    try:
        for name in ("built_unqualified", binding.boot_contract_sha256, cpio_digest):
            current = _open_or_create_directory(current, name)
            opened.append(current)
        return current, opened
    except Exception:
        for descriptor in reversed(opened):
            os.close(descriptor)
        raise


def _write_leaf(parent_fd: int, name: str, data: bytes) -> None:
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
    try:
        offset = 0
        while offset < len(data):
            count = os.write(descriptor, data[offset:])
            if count <= 0:
                _error(CP_SPP_PAYLOAD_V3_STAGING)
            offset += count
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid() or value.st_nlink != 1 or stat.S_IMODE(value.st_mode) != 0o444:
            _error(CP_SPP_PAYLOAD_V3_STAGING)
    finally:
        os.close(descriptor)


def _exact_leaf(parent_fd: int, name: str, expected: bytes) -> None:
    descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o444 or before.st_size != len(expected):
            _error(CP_SPP_PAYLOAD_V3_ADDRESS)
        data = bytearray()
        while len(data) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(data))
            if not chunk:
                _error(CP_SPP_PAYLOAD_V3_ADDRESS)
            data.extend(chunk)
        if os.read(descriptor, 1) or bytes(data) != expected or _identity(os.fstat(descriptor)) != _identity(before):
            _error(CP_SPP_PAYLOAD_V3_ADDRESS)
    finally:
        os.close(descriptor)


def _validate_existing(parent_fd: int, name: str, cpio: bytes, package: bytes) -> None:
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or value.st_nlink != 2 or stat.S_IMODE(value.st_mode) != 0o555 or set(os.listdir(descriptor)) != set(_PAYLOAD_NAMES):
            _error(CP_SPP_PAYLOAD_V3_ADDRESS)
        _exact_leaf(descriptor, _PAYLOAD_NAMES[0], cpio)
        _exact_leaf(descriptor, _PAYLOAD_NAMES[1], package)
    finally:
        os.close(descriptor)


def _check_parent(descriptor: int, expected: _IdentityV3) -> None:
    raw = os.fstat(descriptor)
    value = _identity(raw)
    if not stat.S_ISDIR(raw.st_mode) or value.device != expected.device or value.inode != expected.inode or value.uid != os.geteuid() or value.gid != expected.gid or value.mode != 0o700:
        _error(CP_SPP_PAYLOAD_V3_STAGING)


def _rename_noreplace(old_parent_fd: int, stage_name: str, new_parent_fd: int, final_name: str) -> None:
    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        _error(CP_SPP_PAYLOAD_V3_STAGING)
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(old_parent_fd, stage_name.encode("ascii"), new_parent_fd, final_name.encode("ascii"), _RENAME_NOREPLACE) != 0:
        if ctypes.get_errno() == errno.EEXIST:
            raise FileExistsError()
        _error(CP_SPP_PAYLOAD_V3_STAGING)


def _cleanup_stage(parent_fd: int, name: str) -> None:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    except OSError:
        return
    try:
        if stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o555:
            os.fchmod(descriptor, 0o700)
        for leaf in _PAYLOAD_NAMES:
            try:
                os.unlink(leaf, dir_fd=descriptor)
            except FileNotFoundError:
                pass
    finally:
        os.close(descriptor)
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except OSError:
        pass


def _publish(source_root: _PinnedRootV3, sources: tuple[_FrozenSourceV3, ...], output: _PinnedRootV3, binding: BootBindingV3, cpio: bytes, package: bytes, address: _PayloadAddressV3) -> str:
    parent_fd, opened = _address_parent(output, binding, address.cpio_sha256)
    stage_name = ".spp-boot-payload-v3-stage-" + os.urandom(16).hex()
    stage_fd = -1
    moved = False
    try:
        _revalidate_root(output)
        os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
        stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        stage = os.fstat(stage_fd)
        if not stat.S_ISDIR(stage.st_mode) or stage.st_uid != os.geteuid() or stage.st_nlink != 2 or stat.S_IMODE(stage.st_mode) != 0o700:
            _error(CP_SPP_PAYLOAD_V3_STAGING)
        _write_leaf(stage_fd, _PAYLOAD_NAMES[0], cpio)
        _write_leaf(stage_fd, _PAYLOAD_NAMES[1], package)
        _exact_leaf(stage_fd, _PAYLOAD_NAMES[0], cpio)
        _exact_leaf(stage_fd, _PAYLOAD_NAMES[1], package)
        os.fsync(stage_fd)
        os.fchmod(stage_fd, 0o555)
        os.fsync(stage_fd)
        _revalidate_root(source_root)
        _revalidate_root(output)
        for source in sources:
            _revalidate_source(source_root, source)
        try:
            _rename_noreplace(parent_fd, stage_name, parent_fd, address.package_sha256)
            moved = True
        except FileExistsError:
            _validate_existing(parent_fd, address.package_sha256, cpio, package)
        _validate_existing(parent_fd, address.package_sha256, cpio, package)
        return os.path.join(output.path, "built_unqualified", address.boot_contract_sha256, address.cpio_sha256, address.package_sha256)
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        if not moved:
            _cleanup_stage(parent_fd, stage_name)
        for descriptor in reversed(opened):
            os.close(descriptor)


def compile_boot_payload_v3(*, inspection: InspectionResult, binding: BootBindingV3, plan_bytes: bytes, source_root: str, output_root: str) -> BootPayloadResultV3:
    """Build and atomically publish the sealed, unqualified v3 boot payload."""

    sources: list[_FrozenSourceV3] = []
    source_pin: _PinnedRootV3 | None = None
    output_pin: _PinnedRootV3 | None = None
    result: BootPayloadResultV3 | None = None
    failure_reason: str | None = None
    failure_message = "SPP boot v3 payload rejected"
    try:
        _validate_literal_authority()
        inspection, binding = _validate_issued_inputs(inspection, binding)
        plan = _validate_plan(plan_bytes, binding)
        source_pin = _open_pinned_root(_absolute_normalized(source_root, CP_SPP_PAYLOAD_V3_SOURCE))
        output_pin = _open_pinned_root(_absolute_normalized(output_root, CP_SPP_PAYLOAD_V3_ADDRESS))
        for authority, relative_path in zip(BOOT_PAYLOAD_SOURCE_AUTHORITY_V3, plan.source_paths, strict=True):
            source = _read_source(source_pin, authority, relative_path)
            sources.append(source)
            _check_source_content(source)
        frozen = tuple(sources)
        unresolved = _import_closure(frozen)
        members = _members(frozen, binding)
        cpio = _newc_archive(members)
        package = _package_bytes(inspection, binding, cpio, members, unresolved)
        address = _payload_address(binding, cpio, package)
        _check_builder_consistency(cpio, package, members, inspection, binding, address, unresolved)
        _revalidate_root(source_pin)
        _revalidate_root(output_pin)
        for source in frozen:
            _revalidate_source(source_pin, source)
        final_path = _publish(source_pin, frozen, output_pin, binding, cpio, package, address)
        result = BootPayloadResultV3("built_unqualified", address.cpio_sha256, address.package_sha256, final_path)
    except ApplianceErrorV3 as exc:
        failure_reason = exc.reason_code
        if exc.reason_code == CP_SPP_PAYLOAD_V3_POLICY and "sha256=" in str(exc):
            failure_message = str(exc).split(": ", 1)[-1]
    except OSError:
        failure_reason = CP_SPP_PAYLOAD_V3_STAGING
    except Exception:
        failure_reason = CP_SPP_PAYLOAD_V3_CONSISTENCY
    finally:
        for source in reversed(sources):
            source.close()
        if output_pin is not None:
            output_pin.close()
        if source_pin is not None:
            source_pin.close()
    if failure_reason is not None:
        raise ApplianceErrorV3(failure_reason, failure_message)
    if result is None:
        raise ApplianceErrorV3(CP_SPP_PAYLOAD_V3_CONSISTENCY, "SPP boot v3 payload rejected")
    return result
