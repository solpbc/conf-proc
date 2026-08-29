#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent raw inspector for dormant, unqualified SPP boot payloads.

This module deliberately does not import the payload compiler.  It parses the
CPIO and package bytes from first principles and binds them back to live H4/H5
issued authority objects.
"""

from __future__ import annotations

import ast
import hashlib
import stat
from dataclasses import dataclass
from typing import Final

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_provenance_v2_inspect import InspectionResult, _is_issued_inspection_result
from conf_proc_reasons import ApplianceError, CP_SPP_PAYLOAD_CONSISTENCY
from conf_proc_spp_boot import BootBinding, _is_issued_boot_binding


__all__ = ("PayloadInspectionResult", "inspect_boot_payload")

_MAGIC: Final = b"070701"
_PACKAGE_SCHEMA: Final = "conf-proc-spp-boot-payload-package/v1"
_PAYLOAD_FILES: Final = ("spp-boot-payload.cpio", "spp-boot-payload.package.json")
_MAX_CPIO_BYTES: Final = 257 * 1024 * 1024
_MAX_PACKAGE_BYTES: Final = 4 * 1024 * 1024
_SOURCE_ROWS: Final = (
    ("/usr/lib/spp/conf_proc_geometry.py", "support", 0o444, 2725, "f8273165758c6460bb10d840cb67097a423df819c449119ad15d57b21e05205a"),
    ("/usr/lib/spp/conf_proc_json.py", "support", 0o444, 4425, "b18793b443e3ab2dcaf4bb7762d2e9c52f4d88daddf7bfb614b87ac0d8e80e21"),
    ("/usr/lib/spp/conf_proc_lock.py", "support", 0o444, 21243, "296cdc9ba1238dfa6ac982a33f6b1411a0d7730cbb88edbcfc4492c52c729bba"),
    ("/usr/lib/spp/conf_proc_module_authority.py", "support", 0o444, 3173, "01e9c44c6221b54d792c6f5ff65a9bb82e0b77a29a397b9932b1a13c7d0efe26"),
    ("/usr/lib/spp/conf_proc_policy.py", "support", 0o444, 16686, "e2c48f05dd4233bc8267bb53804e25fd948e06e73a80c6d04ac1e3299118c473"),
    ("/usr/lib/spp/conf_proc_provenance_v2.py", "support", 0o444, 21957, "e94a0818b2d14168190ef7ed490cc147eb18dafd837087eab883630958b59ccd"),
    ("/usr/lib/spp/conf_proc_provenance_v2_manifest.py", "support", 0o444, 16846, "bd3c3ba87c7f6db52759e9f5dd16a5d447b5521c24f714043492ad713549e399"),
    ("/usr/lib/spp/conf_proc_reasons.py", "support", 0o444, 12571, "c56b629a0fc156860c7400d6bc6884c1f41c8a9e4b0626ef4f2821f71102067a"),
    ("/usr/lib/spp/conf_proc_spp_boot.py", "engine", 0o444, 145201, "f333dac88c6002ce98b8280b92c3e81843237afe2d415b3220ffc67edb6f3a1f"),
)
_AUTHORITY_ROWS: Final = (
    ("root_lock_bytes", "/etc/spp/authority/root-lock.json", "root_lock"),
    ("runtime_closure_bytes", "/etc/spp/authority/runtime-closure.json", "runtime_closure"),
    ("verity_rules_bytes", "/etc/spp/authority/verity-rules.json", "verity_rules"),
    ("tcb_identity_bytes", "/etc/spp/authority/tcb-identity.json", "tcb_identity"),
    ("builder_source_bytes", "/etc/spp/authority/designated-builder-source.py", "designated_builder_source"),
    ("policy_bytes", "/etc/spp/authority/policy.json", "policy"),
    ("accepted_manifest_bytes", "/etc/spp/authority/appliance.manifest.json", "accepted_manifest"),
    ("kernel_feature_contract_bytes", "/etc/spp/authority/kernel-features.json", "kernel_features"),
    ("trusted_certificate_bundle_bytes", "/etc/spp/authority/trusted-module-signers.pem", "trusted_module_signers"),
    ("boot_contract_bytes", "/etc/spp/authority/boot-contract.json", "boot_contract"),
    ("module_plan_bytes", "/etc/spp/authority/module-load-plan.json", "module_load_plan"),
    ("gpt_layout_rules_bytes", "/etc/spp/authority/gpt-layout-rules.json", "gpt_layout_rules"),
)
_LOCAL_IMPORTS: Final = {
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


@dataclass(frozen=True)
class PayloadInspectionResult:
    state: str
    boot_qualification: str
    runtime_closure: str
    activation_closure: str
    directory_closure: str
    cpio_sha256: str
    package_sha256: str


@dataclass(frozen=True)
class _RawMember:
    path: str
    mode: int
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def _reject() -> None:
    raise ApplianceError(CP_SPP_PAYLOAD_CONSISTENCY, "SPP boot payload inspection rejected") from None


def _pad4(value: int) -> int:
    return (-value) & 3


def _parse_newc(value: object) -> tuple[_RawMember, ...]:
    if type(value) is not bytes or not value or len(value) > _MAX_CPIO_BYTES:
        _reject()
    data = value
    offset = 0
    records: list[_RawMember] = []
    previous_name = b""
    while True:
        if offset + 110 > len(data) or data[offset:offset + 6] != _MAGIC:
            _reject()
        raw = data[offset + 6:offset + 110]
        if len(raw) != 104 or any(byte not in b"0123456789abcdef" for byte in raw):
            _reject()
        fields = tuple(int(raw[index:index + 8], 16) for index in range(0, 104, 8))
        offset += 110
        size = fields[6]
        name_size = fields[11]
        if name_size < 1 or offset + name_size > len(data):
            _reject()
        raw_name = data[offset:offset + name_size]
        offset += name_size
        name_pad = _pad4(110 + name_size)
        if offset + name_pad > len(data) or any(data[offset:offset + name_pad]):
            _reject()
        offset += name_pad
        if not raw_name.endswith(b"\0") or b"\0" in raw_name[:-1] or offset + size > len(data):
            _reject()
        try:
            name = raw_name[:-1].decode("utf-8")
        except UnicodeDecodeError:
            _reject()
        payload = data[offset:offset + size]
        offset += size
        data_pad = _pad4(size)
        if offset + data_pad > len(data) or any(data[offset:offset + data_pad]):
            _reject()
        offset += data_pad
        if name == "TRAILER!!!":
            if len(records) != 21 or fields != (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0) or offset != len(data):
                _reject()
            return tuple(records)
        if len(records) >= 21:
            _reject()
        encoded_name = name.encode("utf-8")
        expected_fields = (
            len(records) + 1, stat.S_IFREG | 0o444, 0, 0, 1, 0, len(payload),
            0, 0, 0, 0, len(encoded_name) + 1, 0,
        )
        if (
            not name
            or name.startswith("/")
            or len(encoded_name) > 255
            or encoded_name <= previous_name
            or fields != expected_fields
        ):
            _reject()
        previous_name = encoded_name
        records.append(_RawMember("/" + name, 0o444, payload))


def _check_component_policy(module: str) -> None:
    if any(component.casefold() in _PROHIBITED_COMPONENTS for component in module.replace(".", "/").split("/")):
        _reject()


def _external_imports(records: tuple[_RawMember, ...]) -> tuple[str, ...]:
    sources = {
        record.path.rsplit("/", 1)[-1][:-3]: record.data
        for record in records
        if record.path.startswith("/usr/lib/spp/")
    }
    if set(sources) != set(_LOCAL_IMPORTS):
        _reject()
    external: set[str] = set()
    for module, source in sources.items():
        try:
            tree = ast.parse(source, filename=module + ".py", mode="exec")
        except (SyntaxError, ValueError, UnicodeDecodeError):
            _reject()
        local_imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname is not None or not alias.name or any(not part.isidentifier() for part in alias.name.split(".")):
                        _reject()
                    _check_component_policy(alias.name)
                    root = alias.name.split(".", 1)[0]
                    if root in sources:
                        local_imports.add(root)
                    else:
                        external.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level != 0 or node.module is None or any(alias.name == "*" or alias.asname is not None for alias in node.names):
                    _reject()
                if node.module == "__future__":
                    continue
                if any(not part.isidentifier() for part in node.module.split(".")):
                    _reject()
                _check_component_policy(node.module)
                root = node.module.split(".", 1)[0]
                if root in sources:
                    local_imports.add(root)
                else:
                    external.add(node.module)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__":
                _reject()
        if local_imports != _LOCAL_IMPORTS[module]:
            _reject()
    reached = {"conf_proc_spp_boot"}
    while True:
        expanded = reached | set().union(*(_LOCAL_IMPORTS[name] for name in reached))
        if expanded == reached:
            break
        reached = expanded
    if reached != set(sources):
        _reject()
    return tuple(sorted(external, key=lambda item: item.encode("utf-8")))


def _expected_rows(binding: BootBinding) -> tuple[tuple[str, str, int, int, str, bytes | None], ...]:
    expected: list[tuple[str, str, int, int, str, bytes | None]] = [
        (path, role, mode, size, digest, None)
        for path, role, mode, size, digest in _SOURCE_ROWS
    ]
    for attribute, path, role in _AUTHORITY_ROWS:
        data = getattr(binding, attribute)
        if type(data) is not bytes:
            _reject()
        expected.append((path, role, 0o444, len(data), hashlib.sha256(data).hexdigest(), data))
    return tuple(sorted(expected, key=lambda item: item[0].encode("utf-8")))


def _inspect_package(
    package_bytes: object,
    records: tuple[_RawMember, ...],
    inspection: InspectionResult,
    binding: BootBinding,
    cpio_sha256: str,
    external_imports: tuple[str, ...],
) -> str:
    if type(package_bytes) is not bytes or not package_bytes or len(package_bytes) > _MAX_PACKAGE_BYTES:
        _reject()
    try:
        value = canonical_loads(package_bytes)
    except ApplianceError:
        _reject()
    keys = {
        "schema", "package_version", "status", "boot_qualification", "runtime_closure",
        "activation_closure", "directory_closure", "h4_artifact_input_sha256",
        "h4_execution_provenance_sha256", "boot_contract_sha256", "module_plan_sha256",
        "cpio_sha256", "entries", "external_imports_declared_unresolved",
    }
    if type(value) is not dict or set(value) != keys or canonical_dumps(value) != package_bytes:
        _reject()
    exact_strings = {
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
        "cpio_sha256": cpio_sha256,
    }
    if type(value["package_version"]) is not int or value["package_version"] != 1:
        _reject()
    if any(type(value[key]) is not str or value[key] != expected for key, expected in exact_strings.items()):
        _reject()
    expected_rows = _expected_rows(binding)
    if len(records) != len(expected_rows):
        _reject()
    entries: list[dict[str, object]] = []
    for record, (path, role, mode, size, digest, sealed_bytes) in zip(records, expected_rows, strict=True):
        if record.path != path or record.mode != mode or len(record.data) != size or record.sha256 != digest:
            _reject()
        if sealed_bytes is not None and record.data != sealed_bytes:
            _reject()
        entries.append({"path": path, "role": role, "mode": mode, "size_bytes": size, "sha256": digest})
    if type(value["entries"]) is not list:
        _reject()
    for entry in value["entries"]:
        if (
            type(entry) is not dict
            or set(entry) != {"path", "role", "mode", "size_bytes", "sha256"}
            or any(type(entry[key]) is not str for key in ("path", "role", "sha256"))
            or type(entry["mode"]) is not int
            or type(entry["size_bytes"]) is not int
            or entry["size_bytes"] < 1
        ):
            _reject()
    if value["entries"] != entries:
        _reject()
    if (
        type(value["external_imports_declared_unresolved"]) is not list
        or value["external_imports_declared_unresolved"] != list(external_imports)
        or any(type(item) is not str for item in value["external_imports_declared_unresolved"])
    ):
        _reject()
    return hashlib.sha256(package_bytes).hexdigest()


def _check_output_address(output_path: object, binding: BootBinding, cpio_sha256: str, package_sha256: str) -> None:
    if type(output_path) is not str or not output_path.startswith("/") or "\x00" in output_path:
        _reject()
    parts = output_path.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]) or len(parts) < 6:
        _reject()
    if tuple(parts[-4:]) != ("built_unqualified", binding.boot_contract_sha256, cpio_sha256, package_sha256):
        _reject()


def _inspect_boot_payload(
    *,
    inspection: InspectionResult,
    binding: BootBinding,
    cpio_bytes: bytes,
    package_bytes: bytes,
    output_path: str,
) -> PayloadInspectionResult:
    """Independently accept exact payload bytes without importing the producer."""

    if not _is_issued_inspection_result(inspection) or not _is_issued_boot_binding(binding):
        _reject()
    if type(inspection) is not InspectionResult or type(binding) is not BootBinding:
        _reject()
    if (
        inspection.state != "artifact_consistent"
        or inspection.hardware_qualification != "not_qualified"
        or inspection.manifest_sha256 != binding.accepted_manifest_sha256
    ):
        _reject()
    records = _parse_newc(cpio_bytes)
    expected_paths = tuple(row[0] for row in _expected_rows(binding))
    if tuple(record.path for record in records) != expected_paths:
        _reject()
    external_imports = _external_imports(records)
    cpio_sha256 = hashlib.sha256(cpio_bytes).hexdigest()
    package_sha256 = _inspect_package(
        package_bytes, records, inspection, binding, cpio_sha256, external_imports,
    )
    _check_output_address(output_path, binding, cpio_sha256, package_sha256)
    return PayloadInspectionResult(
        "artifact_consistent", "not_qualified", "unresolved", "unresolved", "unresolved",
        cpio_sha256, package_sha256,
    )


def inspect_boot_payload(
    *,
    inspection: InspectionResult,
    binding: BootBinding,
    cpio_bytes: bytes,
    package_bytes: bytes,
    output_path: str,
) -> PayloadInspectionResult:
    """Public sanitized boundary for the independent raw inspector."""

    result: PayloadInspectionResult | None = None
    failed = False
    try:
        result = _inspect_boot_payload(
            inspection=inspection,
            binding=binding,
            cpio_bytes=cpio_bytes,
            package_bytes=package_bytes,
            output_path=output_path,
        )
    except Exception:  # noqa: BLE001 - public boundary deliberately collapses detail
        failed = True
    if failed:
        # Raise outside the handler so malformed bytes cannot survive on the
        # public error as __cause__ or __context__.
        raise ApplianceError(CP_SPP_PAYLOAD_CONSISTENCY, "SPP boot payload inspection rejected")
    if result is None:
        raise ApplianceError(CP_SPP_PAYLOAD_CONSISTENCY, "SPP boot payload inspection rejected")
    return result
