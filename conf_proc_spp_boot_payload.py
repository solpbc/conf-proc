#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Direct, fail-closed builder for the dormant unqualified SPP boot payload."""

from __future__ import annotations

import ast
import ctypes
import errno
import hashlib
import os
import stat
from dataclasses import dataclass
from typing import Final, Iterator

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_prohibited import check_content_markers
from conf_proc_provenance_v2_inspect import InspectionResult, _is_issued_inspection_result
from conf_proc_reasons import (
    CP_SPP_PAYLOAD_ADDRESS,
    CP_SPP_PAYLOAD_ARCHIVE,
    CP_SPP_PAYLOAD_AUTHORITY,
    CP_SPP_PAYLOAD_CONSISTENCY,
    CP_SPP_PAYLOAD_IMPORT,
    CP_SPP_PAYLOAD_PLAN,
    CP_SPP_PAYLOAD_POLICY,
    CP_SPP_PAYLOAD_SOURCE,
    CP_SPP_PAYLOAD_STAGING,
    ApplianceError,
)
from conf_proc_spp_boot import BootBinding, _is_issued_boot_binding


__all__ = ("BootPayloadResult", "compile_boot_payload")

_PLAN_SCHEMA: Final = "conf-proc-spp-boot-payload-plan/v1"
_PACKAGE_SCHEMA: Final = "conf-proc-spp-boot-payload-package/v1"
_MAX_SOURCE_BYTES: Final = 32 * 1024 * 1024
_MAX_TOTAL_BYTES: Final = 128 * 1024 * 1024
_HEX: Final = frozenset("0123456789abcdef")
_RENAME_NOREPLACE: Final = 1
_CPIO_MAGIC: Final = b"070701"
_CPIO_TRAILER: Final = b"TRAILER!!!"
_SOURCE_ROOT_ARCHIVE: Final = "/usr/lib/spp/"
_PAYLOAD_NAMES: Final = ("spp-boot-payload.cpio", "spp-boot-payload.package.json")


@dataclass(frozen=True)
class _SourceAuthority:
    archive_path: str
    role: str
    mode: int
    size_bytes: int
    sha256: str


# This is a source-content authority, not a map from archive paths to caller
# locations.  The caller selects each normalized relative ``source_path`` in
# the canonical plan after this literal basis has been sealed.
BOOT_PAYLOAD_SOURCE_AUTHORITY: Final = (
    _SourceAuthority("/usr/lib/spp/conf_proc_geometry.py", "support", 0o444, 2725, "f8273165758c6460bb10d840cb67097a423df819c449119ad15d57b21e05205a"),
    _SourceAuthority("/usr/lib/spp/conf_proc_json.py", "support", 0o444, 4425, "b18793b443e3ab2dcaf4bb7762d2e9c52f4d88daddf7bfb614b87ac0d8e80e21"),
    _SourceAuthority("/usr/lib/spp/conf_proc_lock.py", "support", 0o444, 21243, "296cdc9ba1238dfa6ac982a33f6b1411a0d7730cbb88edbcfc4492c52c729bba"),
    _SourceAuthority("/usr/lib/spp/conf_proc_module_authority.py", "support", 0o444, 3173, "01e9c44c6221b54d792c6f5ff65a9bb82e0b77a29a397b9932b1a13c7d0efe26"),
    _SourceAuthority("/usr/lib/spp/conf_proc_policy.py", "support", 0o444, 16686, "e2c48f05dd4233bc8267bb53804e25fd948e06e73a80c6d04ac1e3299118c473"),
    _SourceAuthority("/usr/lib/spp/conf_proc_provenance_v2.py", "support", 0o444, 21957, "e94a0818b2d14168190ef7ed490cc147eb18dafd837087eab883630958b59ccd"),
    _SourceAuthority("/usr/lib/spp/conf_proc_provenance_v2_manifest.py", "support", 0o444, 16846, "bd3c3ba87c7f6db52759e9f5dd16a5d447b5521c24f714043492ad713549e399"),
    _SourceAuthority("/usr/lib/spp/conf_proc_reasons.py", "support", 0o444, 12571, "c56b629a0fc156860c7400d6bc6884c1f41c8a9e4b0626ef4f2821f71102067a"),
    _SourceAuthority("/usr/lib/spp/conf_proc_spp_boot.py", "engine", 0o444, 147664, "c1dfba4c4ca71cf64ab8ecef12440950edab88f6ef3e2fb73791fc1f900076a6"),
)
_EXPECTED_LITERAL_SOURCE_ROWS: Final = (
    ("/usr/lib/spp/conf_proc_geometry.py", "support", 0o444, 2725, "f8273165758c6460bb10d840cb67097a423df819c449119ad15d57b21e05205a"),
    ("/usr/lib/spp/conf_proc_json.py", "support", 0o444, 4425, "b18793b443e3ab2dcaf4bb7762d2e9c52f4d88daddf7bfb614b87ac0d8e80e21"),
    ("/usr/lib/spp/conf_proc_lock.py", "support", 0o444, 21243, "296cdc9ba1238dfa6ac982a33f6b1411a0d7730cbb88edbcfc4492c52c729bba"),
    ("/usr/lib/spp/conf_proc_module_authority.py", "support", 0o444, 3173, "01e9c44c6221b54d792c6f5ff65a9bb82e0b77a29a397b9932b1a13c7d0efe26"),
    ("/usr/lib/spp/conf_proc_policy.py", "support", 0o444, 16686, "e2c48f05dd4233bc8267bb53804e25fd948e06e73a80c6d04ac1e3299118c473"),
    ("/usr/lib/spp/conf_proc_provenance_v2.py", "support", 0o444, 21957, "e94a0818b2d14168190ef7ed490cc147eb18dafd837087eab883630958b59ccd"),
    ("/usr/lib/spp/conf_proc_provenance_v2_manifest.py", "support", 0o444, 16846, "bd3c3ba87c7f6db52759e9f5dd16a5d447b5521c24f714043492ad713549e399"),
    ("/usr/lib/spp/conf_proc_reasons.py", "support", 0o444, 12571, "c56b629a0fc156860c7400d6bc6884c1f41c8a9e4b0626ef4f2821f71102067a"),
    ("/usr/lib/spp/conf_proc_spp_boot.py", "engine", 0o444, 147664, "c1dfba4c4ca71cf64ab8ecef12440950edab88f6ef3e2fb73791fc1f900076a6"),
)
_EXPECTED_LOCAL_IMPORTS: Final = {
    "conf_proc_spp_boot": frozenset({"conf_proc_geometry", "conf_proc_json", "conf_proc_lock", "conf_proc_module_authority", "conf_proc_policy", "conf_proc_provenance_v2", "conf_proc_provenance_v2_manifest", "conf_proc_reasons"}),
    "conf_proc_geometry": frozenset(),
    "conf_proc_json": frozenset({"conf_proc_reasons"}),
    "conf_proc_lock": frozenset({"conf_proc_json", "conf_proc_reasons"}),
    "conf_proc_module_authority": frozenset({"conf_proc_lock", "conf_proc_reasons"}),
    "conf_proc_policy": frozenset({"conf_proc_json", "conf_proc_reasons"}),
    "conf_proc_provenance_v2": frozenset({"conf_proc_json", "conf_proc_lock", "conf_proc_reasons"}),
    "conf_proc_provenance_v2_manifest": frozenset({"conf_proc_json", "conf_proc_reasons"}),
    "conf_proc_reasons": frozenset(),
}
_PROHIBITED_COMPONENTS: Final = frozenset({
    "apt", "cloud_init", "containerd", "coredump", "dnf", "docker", "getty",
    "hibernate", "journald", "kdump", "mok", "packagekit", "recovery", "serial",
    "shim", "socket", "ssh", "sshd", "subprocess", "swap", "waagent", "walinux",
})
def _authority_specs() -> Iterator[tuple[str, str, str]]:
    yield "root_lock_bytes", "/etc/spp/authority/root-lock.json", "root_lock"
    yield "runtime_closure_bytes", "/etc/spp/authority/runtime-closure.json", "runtime_closure"
    yield "verity_rules_bytes", "/etc/spp/authority/verity-rules.json", "verity_rules"
    yield "tcb_identity_bytes", "/etc/spp/authority/tcb-identity.json", "tcb_identity"
    yield "builder_source_bytes", "/etc/spp/authority/designated-builder-source.py", "designated_builder_source"
    yield "policy_bytes", "/etc/spp/authority/policy.json", "policy"
    yield "accepted_manifest_bytes", "/etc/spp/authority/appliance.manifest.json", "accepted_manifest"
    yield "kernel_feature_contract_bytes", "/etc/spp/authority/kernel-features.json", "kernel_features"
    yield "trusted_certificate_bundle_bytes", "/etc/spp/authority/trusted-module-signers.pem", "trusted_module_signers"
    yield "boot_contract_bytes", "/etc/spp/authority/boot-contract.json", "boot_contract"
    yield "module_plan_bytes", "/etc/spp/authority/module-load-plan.json", "module_load_plan"
    yield "gpt_layout_rules_bytes", "/etc/spp/authority/gpt-layout-rules.json", "gpt_layout_rules"


_AUTHORITY_SPECS: Final = tuple(_authority_specs())


@dataclass(frozen=True)
class BootPayloadResult:
    """Safe final-address information for an emitted payload."""

    state: str
    cpio_sha256: str
    package_sha256: str
    output_path: str


@dataclass(frozen=True)
class _Plan:
    source_paths: tuple[str, ...]


@dataclass(frozen=True)
class _PayloadAddress:
    boot_contract_sha256: str
    cpio_sha256: str
    package_sha256: str


@dataclass(frozen=True)
class _Member:
    path: str
    entry_type: str
    role: str
    mode: int
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass(frozen=True)
class _Identity:
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
class _PinnedRoot:
    path: str
    descriptors: list[int]
    identities: list[_Identity]

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
class _FrozenSource:
    authority: _SourceAuthority
    relative_path: str
    parent_fd: int
    parent_identity: _Identity
    leaf_name: str
    descriptor: int
    identity: _Identity
    data: bytes

    def close(self) -> None:
        for descriptor in (self.descriptor, self.parent_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _error(code: str) -> None:
    raise ApplianceError(code, "SPP boot payload rejected") from None


def _sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _HEX


def _identity(value: os.stat_result) -> _Identity:
    return _Identity(value.st_dev, value.st_ino, stat.S_IMODE(value.st_mode), value.st_uid, value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


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
    parts = value.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        _error(code)
    try:
        if len(value.encode("utf-8")) > 255:
            _error(code)
    except UnicodeEncodeError:
        _error(code)
    return value


def _check_component_policy(value: str, code: str) -> None:
    for component in value.strip("/").split("/"):
        if component.casefold() in _PROHIBITED_COMPONENTS:
            _error(code)


def _validate_literal_authority() -> None:
    rows = BOOT_PAYLOAD_SOURCE_AUTHORITY
    if type(rows) is not tuple or not 1 <= len(rows) <= 64 or len(rows) != 9:
        _error(CP_SPP_PAYLOAD_AUTHORITY)
    if any(type(item) is not _SourceAuthority for item in rows):
        _error(CP_SPP_PAYLOAD_AUTHORITY)
    actual_rows = tuple((item.archive_path, item.role, item.mode, item.size_bytes, item.sha256) for item in rows)
    if actual_rows != _EXPECTED_LITERAL_SOURCE_ROWS:
        _error(CP_SPP_PAYLOAD_AUTHORITY)
    seen: set[str] = set()
    previous = b""
    engine_count = 0
    for item in rows:
        if type(item.archive_path) is not str or type(item.role) is not str or type(item.mode) is not int or type(item.size_bytes) is not int or type(item.sha256) is not str:
            _error(CP_SPP_PAYLOAD_AUTHORITY)
        try:
            encoded = item.archive_path.encode("utf-8")
        except UnicodeEncodeError:
            _error(CP_SPP_PAYLOAD_AUTHORITY)
        if not item.archive_path.startswith(_SOURCE_ROOT_ARCHIVE) or item.archive_path == _SOURCE_ROOT_ARCHIVE or len(encoded) > 255:
            _error(CP_SPP_PAYLOAD_AUTHORITY)
        _absolute_normalized(item.archive_path, CP_SPP_PAYLOAD_AUTHORITY)
        _check_component_policy(item.archive_path, CP_SPP_PAYLOAD_AUTHORITY)
        if encoded <= previous or item.archive_path in seen or item.mode not in {0o444, 0o555} or item.mode != 0o444 or not _sha256(item.sha256) or not 1 <= item.size_bytes <= _MAX_SOURCE_BYTES:
            _error(CP_SPP_PAYLOAD_AUTHORITY)
        previous = encoded
        seen.add(item.archive_path)
        if item.role == "engine" and item.archive_path == "/usr/lib/spp/conf_proc_spp_boot.py":
            engine_count += 1
        elif item.role != "support":
            _error(CP_SPP_PAYLOAD_AUTHORITY)
    if engine_count != 1 or sum(item.size_bytes for item in rows) != 247290 or sum(item.size_bytes for item in rows) > _MAX_TOTAL_BYTES:
        _error(CP_SPP_PAYLOAD_AUTHORITY)
    paths = sorted(seen, key=lambda value: value.encode("utf-8"))
    if any(right.startswith(left + "/") for left, right in zip(paths, paths[1:], strict=False)):
        _error(CP_SPP_PAYLOAD_AUTHORITY)


def _validate_issued_inputs(inspection: object, binding: object) -> tuple[InspectionResult, BootBinding]:
    if not _is_issued_inspection_result(inspection) or not _is_issued_boot_binding(binding):
        _error(CP_SPP_PAYLOAD_AUTHORITY)
    assert type(inspection) is InspectionResult and type(binding) is BootBinding
    if inspection.state != "artifact_consistent" or inspection.hardware_qualification != "not_qualified" or inspection.manifest_sha256 != binding.accepted_manifest_sha256:
        _error(CP_SPP_PAYLOAD_AUTHORITY)
    if not all(_sha256(value) for value in (inspection.artifact_input_sha256, inspection.execution_provenance_sha256, inspection.manifest_sha256, binding.boot_contract_sha256, binding.module_plan_sha256)):
        _error(CP_SPP_PAYLOAD_AUTHORITY)
    return inspection, binding


def _validate_plan(plan_bytes: object, binding: BootBinding) -> _Plan:
    if type(plan_bytes) is not bytes:
        _error(CP_SPP_PAYLOAD_PLAN)
    try:
        value = canonical_loads(plan_bytes)
    except ApplianceError:
        _error(CP_SPP_PAYLOAD_PLAN)
    if type(value) is not dict or set(value) != {"schema", "plan_version", "boot_contract_sha256", "module_plan_sha256", "entries"}:
        _error(CP_SPP_PAYLOAD_PLAN)
    if (
        type(value["schema"]) is not str
        or value["schema"] != _PLAN_SCHEMA
        or type(value["plan_version"]) is not int
        or value["plan_version"] != 1
        or type(value["boot_contract_sha256"]) is not str
        or type(value["module_plan_sha256"]) is not str
        or type(value["entries"]) is not list
    ):
        _error(CP_SPP_PAYLOAD_PLAN)
    if value["boot_contract_sha256"] != binding.boot_contract_sha256 or value["module_plan_sha256"] != binding.module_plan_sha256 or len(value["entries"]) != len(BOOT_PAYLOAD_SOURCE_AUTHORITY):
        _error(CP_SPP_PAYLOAD_PLAN)
    source_paths: list[str] = []
    casefolded: set[str] = set()
    for item, authority in zip(value["entries"], BOOT_PAYLOAD_SOURCE_AUTHORITY, strict=True):
        if type(item) is not dict or set(item) != {"archive_path", "source_path"} or type(item["archive_path"]) is not str:
            _error(CP_SPP_PAYLOAD_PLAN)
        if item["archive_path"] != authority.archive_path:
            _error(CP_SPP_PAYLOAD_PLAN)
        source_path = _relative_normalized(item["source_path"], CP_SPP_PAYLOAD_PLAN)
        if source_path.casefold() in casefolded:
            _error(CP_SPP_PAYLOAD_PLAN)
        casefolded.add(source_path.casefold())
        source_paths.append(source_path)
    if len(set(source_paths)) != len(source_paths):
        _error(CP_SPP_PAYLOAD_PLAN)
    normalized_paths = sorted(casefolded, key=lambda value: value.encode("utf-8"))
    if any(right.startswith(left + "/") for left, right in zip(normalized_paths, normalized_paths[1:], strict=False)):
        _error(CP_SPP_PAYLOAD_PLAN)
    return _Plan(tuple(source_paths))


def _trusted_directory(value: os.stat_result, *, final: bool) -> None:
    if not stat.S_ISDIR(value.st_mode) or value.st_uid not in {0, os.geteuid()}:
        _error(CP_SPP_PAYLOAD_SOURCE)
    mode = stat.S_IMODE(value.st_mode)
    if value.st_uid == os.geteuid() and mode & 0o022:
        _error(CP_SPP_PAYLOAD_SOURCE)
    if value.st_uid == 0 and mode & 0o022 and not mode & stat.S_ISVTX:
        _error(CP_SPP_PAYLOAD_SOURCE)
    if final and (value.st_uid != os.geteuid() or mode != 0o700):
        _error(CP_SPP_PAYLOAD_SOURCE)


def _open_pinned_root(path: str) -> _PinnedRoot:
    root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    descriptors = [root_fd]
    identities = [_identity(os.fstat(root_fd))]
    try:
        _trusted_directory(os.fstat(root_fd), final=False)
        current = root_fd
        for component in path.split("/")[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
            descriptors.append(child)
            identities.append(_identity(os.fstat(child)))
            _trusted_directory(os.fstat(child), final=False)
            current = child
        _trusted_directory(os.fstat(current), final=True)
        return _PinnedRoot(path, descriptors, identities)
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _revalidate_root(root: _PinnedRoot) -> None:
    for descriptor, expected in zip(root.descriptors, root.identities, strict=True):
        current = _identity(os.fstat(descriptor))
        if current.device != expected.device or current.inode != expected.inode or current.mode != expected.mode or current.uid != expected.uid or current.gid != expected.gid:
            _error(CP_SPP_PAYLOAD_SOURCE)
    reopened = _open_pinned_root(root.path)
    try:
        for expected, current in zip(root.identities, reopened.identities, strict=True):
            if (expected.device, expected.inode, expected.mode, expected.uid, expected.gid) != (current.device, current.inode, current.mode, current.uid, current.gid):
                _error(CP_SPP_PAYLOAD_SOURCE)
    finally:
        reopened.close()


def _read_source(root: _PinnedRoot, authority: _SourceAuthority, relative_path: str) -> _FrozenSource:
    components = relative_path.split("/")
    parent = os.dup(root.fd)
    descriptor = -1
    try:
        for component in components[:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = next_fd
            _trusted_directory(os.fstat(parent), final=False)
        descriptor = os.open(components[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or before.st_size != authority.size_bytes:
            _error(CP_SPP_PAYLOAD_SOURCE)
        data = bytearray()
        while len(data) < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - len(data)))
            if not chunk:
                _error(CP_SPP_PAYLOAD_SOURCE)
            data.extend(chunk)
        if os.read(descriptor, 1) or hashlib.sha256(data).hexdigest() != authority.sha256:
            _error(CP_SPP_PAYLOAD_SOURCE)
        after = os.fstat(descriptor)
        if _identity(after) != _identity(before):
            _error(CP_SPP_PAYLOAD_SOURCE)
        return _FrozenSource(
            authority,
            relative_path,
            parent,
            _identity(os.fstat(parent)),
            components[-1],
            descriptor,
            _identity(before),
            bytes(data),
        )
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)
        raise


def _revalidate_source(root: _PinnedRoot, source: _FrozenSource) -> None:
    """Recheck the frozen leaf and its descriptor-only route from the pinned root."""

    if _identity(os.fstat(source.descriptor)) != source.identity or _identity(os.fstat(source.parent_fd)) != source.parent_identity:
        _error(CP_SPP_PAYLOAD_SOURCE)
    parent = os.dup(root.fd)
    try:
        for component in source.relative_path.split("/")[:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = next_fd
            _trusted_directory(os.fstat(parent), final=False)
        if _identity(os.fstat(parent)) != source.parent_identity:
            _error(CP_SPP_PAYLOAD_SOURCE)
        reopened = os.open(source.leaf_name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            if _identity(os.fstat(reopened)) != source.identity:
                _error(CP_SPP_PAYLOAD_SOURCE)
        finally:
            os.close(reopened)
    except OSError:
        _error(CP_SPP_PAYLOAD_SOURCE)
    finally:
        os.close(parent)


def _check_source_content(source: _FrozenSource) -> None:
    """Apply the shared scanner without exposing its path or marker detail."""

    try:
        check_content_markers(source.authority.archive_path, source.data)
    except ApplianceError:
        # The digest prefix is the only source-derived public diagnostic.
        raise ApplianceError(CP_SPP_PAYLOAD_POLICY, f"source rejected sha256={source.authority.sha256[:16]}") from None


def _import_closure(sources: tuple[_FrozenSource, ...]) -> tuple[str, ...]:
    local = {source.authority.archive_path.rsplit("/", 1)[-1][:-3]: source for source in sources}
    if set(local) != set(_EXPECTED_LOCAL_IMPORTS):
        _error(CP_SPP_PAYLOAD_IMPORT)
    external: set[str] = set()
    for module, source in local.items():
        try:
            tree = ast.parse(source.data, filename=source.authority.archive_path, mode="exec")
        except (SyntaxError, ValueError, UnicodeDecodeError):
            _error(CP_SPP_PAYLOAD_IMPORT)
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname is not None or not alias.name or any(not part.isidentifier() for part in alias.name.split(".")):
                        _error(CP_SPP_PAYLOAD_IMPORT)
                    target = alias.name.split(".")[0]
                    _check_component_policy(alias.name.replace(".", "/"), CP_SPP_PAYLOAD_POLICY)
                    if target in local:
                        imports.add(target)
                    else:
                        external.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level != 0 or node.module is None or any(alias.name == "*" or alias.asname is not None for alias in node.names):
                    _error(CP_SPP_PAYLOAD_IMPORT)
                if node.module == "__future__":
                    continue
                if any(not part.isidentifier() for part in node.module.split(".")):
                    _error(CP_SPP_PAYLOAD_IMPORT)
                _check_component_policy(node.module.replace(".", "/"), CP_SPP_PAYLOAD_POLICY)
                target = node.module.split(".")[0]
                if target in local:
                    imports.add(target)
                else:
                    external.add(node.module)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__":
                _error(CP_SPP_PAYLOAD_IMPORT)
        if imports != _EXPECTED_LOCAL_IMPORTS[module]:
            _error(CP_SPP_PAYLOAD_IMPORT)
    reached = {"conf_proc_spp_boot"}
    while True:
        next_reached = reached | set().union(*(_EXPECTED_LOCAL_IMPORTS[item] for item in reached))
        if next_reached == reached:
            break
        reached = next_reached
    if reached != set(local):
        _error(CP_SPP_PAYLOAD_IMPORT)
    return tuple(sorted(external, key=lambda value: value.encode("utf-8")))


def _members(sources: tuple[_FrozenSource, ...], binding: BootBinding) -> tuple[_Member, ...]:
    members = [_Member(source.authority.archive_path, "source", source.authority.role, source.authority.mode, source.data) for source in sources]
    for attribute, path, role in _AUTHORITY_SPECS:
        data = getattr(binding, attribute)
        if type(data) is not bytes or not 1 <= len(data) <= _MAX_SOURCE_BYTES:
            _error(CP_SPP_PAYLOAD_AUTHORITY)
        members.append(_Member(path, "sealed_authority", role, 0o444, data))
    if sum(len(member.data) for member in members) > _MAX_TOTAL_BYTES * 2:
        _error(CP_SPP_PAYLOAD_AUTHORITY)
    return tuple(sorted(members, key=lambda item: item.path.encode("utf-8")))


def _pad4(value: int) -> int:
    return (-value) & 3


def _newc_member(index: int, member: _Member) -> bytes:
    if not member.path.startswith("/"):
        _error(CP_SPP_PAYLOAD_ARCHIVE)
    name = member.path[1:].encode("utf-8") + b"\0"
    fields = (index, stat.S_IFREG | member.mode, 0, 0, 1, 0, len(member.data), 0, 0, 0, 0, len(name), 0)
    header = _CPIO_MAGIC + b"".join(f"{field:08x}".encode("ascii") for field in fields)
    return header + name + b"\0" * _pad4(len(header) + len(name)) + member.data + b"\0" * _pad4(len(member.data))


def _newc_archive(members: tuple[_Member, ...]) -> bytes:
    value = b"".join(_newc_member(index, member) for index, member in enumerate(members, 1))
    name = _CPIO_TRAILER + b"\0"
    fields = (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(name), 0)
    header = _CPIO_MAGIC + b"".join(f"{field:08x}".encode("ascii") for field in fields)
    return value + header + name + b"\0" * _pad4(len(header) + len(name))


def _parse_newc(data: bytes) -> tuple[tuple[str, int, bytes], ...]:
    offset = 0
    records: list[tuple[str, int, bytes]] = []
    while True:
        if data[offset:offset + 6] != _CPIO_MAGIC or offset + 110 > len(data):
            _error(CP_SPP_PAYLOAD_ARCHIVE)
        raw = data[offset + 6:offset + 110]
        if any(byte not in b"0123456789abcdef" for byte in raw):
            _error(CP_SPP_PAYLOAD_ARCHIVE)
        fields = tuple(int(raw[position:position + 8], 16) for position in range(0, 104, 8))
        offset += 110
        name_size, size = fields[11], fields[6]
        if name_size < 1 or offset + name_size > len(data):
            _error(CP_SPP_PAYLOAD_ARCHIVE)
        name_data = data[offset:offset + name_size]
        offset += name_size
        name_padding = _pad4(110 + name_size)
        if offset + name_padding > len(data) or any(data[offset:offset + name_padding]):
            _error(CP_SPP_PAYLOAD_ARCHIVE)
        offset += name_padding
        if not name_data.endswith(b"\0") or offset + size > len(data):
            _error(CP_SPP_PAYLOAD_ARCHIVE)
        try:
            name = name_data[:-1].decode("utf-8")
        except UnicodeDecodeError:
            _error(CP_SPP_PAYLOAD_ARCHIVE)
        payload = data[offset:offset + size]
        offset += size
        data_padding = _pad4(size)
        if offset + data_padding > len(data) or any(data[offset:offset + data_padding]):
            _error(CP_SPP_PAYLOAD_ARCHIVE)
        offset += data_padding
        if name == _CPIO_TRAILER.decode("ascii"):
            if fields != (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0) or offset != len(data):
                _error(CP_SPP_PAYLOAD_ARCHIVE)
            return tuple(records)
        if not name or name.startswith("/") or "\x00" in name or fields[0] != len(records) + 1 or fields[1] != stat.S_IFREG | 0o444 or fields[4] != 1 or any(fields[index] for index in (2, 3, 5, 7, 8, 9, 10, 12)):
            _error(CP_SPP_PAYLOAD_ARCHIVE)
        records.append(("/" + name, fields[1] & 0o7777, payload))


def _entry_record(member: _Member) -> dict[str, object]:
    return {"path": member.path, "role": member.role, "mode": member.mode, "size_bytes": len(member.data), "sha256": member.sha256}


def _package_bytes(inspection: InspectionResult, binding: BootBinding, cpio: bytes, members: tuple[_Member, ...], unresolved: tuple[str, ...]) -> bytes:
    digest = hashlib.sha256(cpio).hexdigest()
    value = {
        "schema": _PACKAGE_SCHEMA,
        "package_version": 1,
        "status": "built_unqualified",
        "boot_qualification": "not_qualified",
        "runtime_closure": "unresolved",
        "activation_closure": "unresolved",
        "directory_closure": "unresolved",
        "h4_artifact_input_sha256": inspection.artifact_input_sha256,
        "h4_execution_provenance_sha256": inspection.execution_provenance_sha256,
        "boot_contract_sha256": binding.boot_contract_sha256,
        "module_plan_sha256": binding.module_plan_sha256,
        "cpio_sha256": digest,
        "entries": [_entry_record(member) for member in members],
        "external_imports_declared_unresolved": list(unresolved),
    }
    return canonical_dumps(value)


def _payload_address(binding: BootBinding, cpio: bytes, package: bytes) -> _PayloadAddress:
    return _PayloadAddress(
        binding.boot_contract_sha256,
        hashlib.sha256(cpio).hexdigest(),
        hashlib.sha256(package).hexdigest(),
    )


def _check_builder_consistency(
    cpio: bytes,
    package: bytes,
    members: tuple[_Member, ...],
    inspection: InspectionResult,
    binding: BootBinding,
    address: _PayloadAddress,
    unresolved: tuple[str, ...],
) -> None:
    expected_address = _payload_address(binding, cpio, package)
    if address != expected_address:
        _error(CP_SPP_PAYLOAD_CONSISTENCY)
    parsed = _parse_newc(cpio)
    expected = tuple((item.path, item.mode, item.data) for item in members)
    if parsed != expected:
        _error(CP_SPP_PAYLOAD_CONSISTENCY)
    try:
        value = canonical_loads(package)
    except ApplianceError:
        _error(CP_SPP_PAYLOAD_CONSISTENCY)
    expected_keys = {
        "schema", "package_version", "status", "boot_qualification", "runtime_closure",
        "activation_closure", "directory_closure", "h4_artifact_input_sha256",
        "h4_execution_provenance_sha256", "boot_contract_sha256", "module_plan_sha256",
        "cpio_sha256", "entries", "external_imports_declared_unresolved",
    }
    if type(value) is not dict or set(value) != expected_keys or canonical_dumps(value) != package:
        _error(CP_SPP_PAYLOAD_CONSISTENCY)
    expected_strings = {
        "schema": _PACKAGE_SCHEMA,
        "status": "built_unqualified",
        "boot_qualification": "not_qualified",
        "runtime_closure": "unresolved",
        "activation_closure": "unresolved",
        "directory_closure": "unresolved",
        "h4_artifact_input_sha256": inspection.artifact_input_sha256,
        "h4_execution_provenance_sha256": inspection.execution_provenance_sha256,
        "boot_contract_sha256": binding.boot_contract_sha256,
        "module_plan_sha256": binding.module_plan_sha256,
        "cpio_sha256": address.cpio_sha256,
    }
    if type(value["package_version"]) is not int or value["package_version"] != 1:
        _error(CP_SPP_PAYLOAD_CONSISTENCY)
    if any(type(value[key]) is not str or value[key] != expected for key, expected in expected_strings.items()):
        _error(CP_SPP_PAYLOAD_CONSISTENCY)
    if type(value["entries"]) is not list:
        _error(CP_SPP_PAYLOAD_CONSISTENCY)
    for entry in value["entries"]:
        if (
            type(entry) is not dict
            or set(entry) != {"path", "role", "mode", "size_bytes", "sha256"}
            or any(type(entry[key]) is not str for key in ("path", "role", "sha256"))
            or type(entry["mode"]) is not int
            or type(entry["size_bytes"]) is not int
            or entry["size_bytes"] < 1
        ):
            _error(CP_SPP_PAYLOAD_CONSISTENCY)
    if value["entries"] != [_entry_record(item) for item in members]:
        _error(CP_SPP_PAYLOAD_CONSISTENCY)
    if type(value["external_imports_declared_unresolved"]) is not list or value["external_imports_declared_unresolved"] != list(unresolved) or any(type(item) is not str for item in value["external_imports_declared_unresolved"]):
        _error(CP_SPP_PAYLOAD_CONSISTENCY)


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
        _error(CP_SPP_PAYLOAD_ADDRESS)
    return descriptor


def _address_parent(output: _PinnedRoot, binding: BootBinding, cpio_digest: str) -> tuple[int, list[int]]:
    current = os.dup(output.fd)
    opened = [current]
    try:
        for name in ("built_unqualified", binding.boot_contract_sha256, cpio_digest):
            child = _open_or_create_directory(current, name)
            opened.append(child)
            current = child
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
                _error(CP_SPP_PAYLOAD_STAGING)
            offset += count
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid() or value.st_nlink != 1 or stat.S_IMODE(value.st_mode) != 0o444:
            _error(CP_SPP_PAYLOAD_STAGING)
    finally:
        os.close(descriptor)


def _exact_leaf(parent_fd: int, name: str, expected: bytes) -> None:
    descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o444 or before.st_size != len(expected):
            _error(CP_SPP_PAYLOAD_ADDRESS)
        data = bytearray()
        while len(data) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(data))
            if not chunk:
                _error(CP_SPP_PAYLOAD_ADDRESS)
            data.extend(chunk)
        if os.read(descriptor, 1) or bytes(data) != expected or _identity(os.fstat(descriptor)) != _identity(before):
            _error(CP_SPP_PAYLOAD_ADDRESS)
    finally:
        os.close(descriptor)


def _validate_existing(parent_fd: int, name: str, cpio: bytes, package: bytes) -> None:
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or value.st_nlink != 2 or stat.S_IMODE(value.st_mode) != 0o555 or set(os.listdir(descriptor)) != set(_PAYLOAD_NAMES):
            _error(CP_SPP_PAYLOAD_ADDRESS)
        _exact_leaf(descriptor, _PAYLOAD_NAMES[0], cpio)
        _exact_leaf(descriptor, _PAYLOAD_NAMES[1], package)
    finally:
        os.close(descriptor)


def _check_final_parent(descriptor: int, expected: _Identity, *, check_nlink: bool) -> None:
    """Keep both rename parents pinned to their euid-owned final form."""

    raw = os.fstat(descriptor)
    value = _identity(raw)
    if (
        not stat.S_ISDIR(raw.st_mode)
        or value.device != expected.device
        or value.inode != expected.inode
        or value.uid != os.geteuid()
        or value.gid != expected.gid
        or (check_nlink and value.nlink != expected.nlink)
        or value.mode != 0o700
    ):
        _error(CP_SPP_PAYLOAD_STAGING)


def _rename_noreplace(old_parent_fd: int, stage_name: str, new_parent_fd: int, final_name: str) -> None:
    """Use only Linux's no-replace directory-FD rename boundary."""

    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        _error(CP_SPP_PAYLOAD_STAGING)
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(old_parent_fd, stage_name.encode("ascii"), new_parent_fd, final_name.encode("ascii"), _RENAME_NOREPLACE) != 0:
        failure = ctypes.get_errno()
        if failure == errno.EEXIST:
            raise FileExistsError(failure, "target exists")
        _error(CP_SPP_PAYLOAD_STAGING)


def _cleanup_stage(output_fd: int, name: str, expected: _Identity | None) -> None:
    """Remove only this invocation's pinned sibling after a failed publish."""

    if expected is None:
        return
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=output_fd)
    except OSError:
        return
    try:
        value = os.fstat(descriptor)
        current = _identity(value)
        if (
            not stat.S_ISDIR(value.st_mode)
            or current.device != expected.device
            or current.inode != expected.inode
            or current.uid != os.geteuid()
            or current.gid != expected.gid
            or current.nlink != 2
            or current.mode not in {0o700, 0o555}
        ):
            return
        # Do not enumerate the directory: only the two known leaf names are
        # candidates for removal, and each must still be the expected owner
        # and single-link regular-file shape before this owned stage is opened.
        for leaf in _PAYLOAD_NAMES:
            try:
                leaf_value = os.stat(leaf, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(leaf_value.st_mode) or leaf_value.st_uid != os.geteuid() or leaf_value.st_nlink != 1:
                return
        os.fchmod(descriptor, 0o700)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700:
            return
        for leaf in _PAYLOAD_NAMES:
            try:
                os.unlink(leaf, dir_fd=descriptor)
            except FileNotFoundError:
                pass
    finally:
        os.close(descriptor)
    try:
        os.rmdir(name, dir_fd=output_fd)
    except OSError:
        pass


def _publish(
    source_root: _PinnedRoot,
    sources: tuple[_FrozenSource, ...],
    output: _PinnedRoot,
    binding: BootBinding,
    cpio: bytes,
    package: bytes,
    address: _PayloadAddress,
) -> str:
    parent_fd, opened = _address_parent(output, binding, address.cpio_sha256)
    opened_identities = tuple(_identity(os.fstat(descriptor)) for descriptor in opened)
    parent_identity = _identity(os.fstat(parent_fd))
    stage_name = ".spp-boot-payload-stage-" + os.urandom(16).hex()
    stage_fd = -1
    stage_identity: _Identity | None = None
    moved = False
    try:
        _revalidate_root(output)
        os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
        stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        stage = os.fstat(stage_fd)
        if not stat.S_ISDIR(stage.st_mode) or stage.st_uid != os.geteuid() or stage.st_nlink != 2 or stat.S_IMODE(stage.st_mode) != 0o700:
            _error(CP_SPP_PAYLOAD_STAGING)
        stage_identity = _identity(stage)
        _write_leaf(stage_fd, _PAYLOAD_NAMES[0], cpio)
        _write_leaf(stage_fd, _PAYLOAD_NAMES[1], package)
        _exact_leaf(stage_fd, _PAYLOAD_NAMES[0], cpio)
        _exact_leaf(stage_fd, _PAYLOAD_NAMES[1], package)
        os.fsync(stage_fd)
        os.fchmod(stage_fd, 0o555)
        os.fsync(stage_fd)
        stage = os.fstat(stage_fd)
        if stage.st_uid != os.geteuid() or stage.st_nlink != 2 or stat.S_IMODE(stage.st_mode) != 0o555:
            _error(CP_SPP_PAYLOAD_STAGING)
        _revalidate_root(output)
        _check_final_parent(output.fd, output.identities[-1], check_nlink=False)
        for descriptor, expected in zip(opened[1:-1], opened_identities[1:-1], strict=True):
            _check_final_parent(descriptor, expected, check_nlink=False)
        parent_expected = _Identity(
            parent_identity.device, parent_identity.inode, parent_identity.mode, parent_identity.uid,
            parent_identity.gid, parent_identity.nlink + 1, parent_identity.size,
            parent_identity.mtime_ns, parent_identity.ctime_ns,
        )
        _check_final_parent(parent_fd, parent_expected, check_nlink=False)
        _revalidate_root(source_root)
        for source in sources:
            _revalidate_source(source_root, source)
        _revalidate_root(output)
        _check_final_parent(output.fd, output.identities[-1], check_nlink=False)
        for descriptor, expected in zip(opened[1:-1], opened_identities[1:-1], strict=True):
            _check_final_parent(descriptor, expected, check_nlink=False)
        _check_final_parent(parent_fd, parent_expected, check_nlink=False)
        try:
            _rename_noreplace(parent_fd, stage_name, parent_fd, address.package_sha256)
            moved = True
        except FileExistsError:
            _validate_existing(parent_fd, address.package_sha256, cpio, package)
        _revalidate_root(output)
        _check_final_parent(parent_fd, parent_expected, check_nlink=False)
        _validate_existing(parent_fd, address.package_sha256, cpio, package)
        return os.path.join(output.path, "built_unqualified", address.boot_contract_sha256, address.cpio_sha256, address.package_sha256)
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        if not moved:
            _cleanup_stage(parent_fd, stage_name, stage_identity)
        for descriptor in reversed(opened):
            os.close(descriptor)


def compile_boot_payload(*, inspection: InspectionResult, binding: BootBinding, plan_bytes: bytes, source_root: str, output_root: str) -> BootPayloadResult:
    """Build and atomically publish the sealed, unqualified boot payload."""

    sources: list[_FrozenSource] = []
    source_pin: _PinnedRoot | None = None
    output_pin: _PinnedRoot | None = None
    result: BootPayloadResult | None = None
    failure_reason: str | None = None
    failure_message = "SPP boot payload rejected"
    try:
        _validate_literal_authority()
        inspection, binding = _validate_issued_inputs(inspection, binding)
        plan = _validate_plan(plan_bytes, binding)
        source_path = _absolute_normalized(source_root, CP_SPP_PAYLOAD_SOURCE)
        output_path = _absolute_normalized(output_root, CP_SPP_PAYLOAD_ADDRESS)
        source_pin = _open_pinned_root(source_path)
        output_pin = _open_pinned_root(output_path)
        for authority, relative_path in zip(BOOT_PAYLOAD_SOURCE_AUTHORITY, plan.source_paths, strict=True):
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
        result = BootPayloadResult("built_unqualified", address.cpio_sha256, address.package_sha256, final_path)
    except ApplianceError as exc:
        failure_reason = exc.reason_code
        if exc.reason_code == CP_SPP_PAYLOAD_POLICY and "sha256=" in str(exc):
            failure_message = str(exc).split(": ", 1)[-1]
    except OSError:
        failure_reason = CP_SPP_PAYLOAD_STAGING
    except Exception:  # noqa: BLE001 - direct public boundary is sanitized
        failure_reason = CP_SPP_PAYLOAD_CONSISTENCY
    finally:
        for source in reversed(sources):
            source.close()
        if output_pin is not None:
            output_pin.close()
        if source_pin is not None:
            source_pin.close()
    if failure_reason is not None:
        # Raise outside every handler so private paths and source syntax cannot
        # survive as __cause__ or __context__ on the public error.
        raise ApplianceError(failure_reason, failure_message)
    if result is None:
        raise ApplianceError(CP_SPP_PAYLOAD_CONSISTENCY, "SPP boot payload rejected")
    return result
