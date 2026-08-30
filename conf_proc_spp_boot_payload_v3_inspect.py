#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent raw inspector for sealed, unqualified SPP boot v3 payloads."""

from __future__ import annotations

import ast
import hashlib
import stat
from collections import namedtuple
from dataclasses import dataclass
from typing import Final

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_provenance_v2_inspect import InspectionResult, _is_issued_inspection_result
from conf_proc_spp_boot_v3 import BootBindingV3, is_issued_boot_binding_v3
from conf_proc_spp_reasons_v3 import ApplianceErrorV3, CP_SPP_PAYLOAD_V3_CONSISTENCY


__all__ = ("PayloadInspectionResultV3", "inspect_boot_payload_v3")

_MAGIC: Final = b"070701"
_PACKAGE_SCHEMA_V3: Final = "conf-proc-spp-boot-payload-package/v3"
_PAYLOAD_FILES: Final = ("spp-boot-payload.cpio", "spp-boot-payload.package.json")
_MAX_CPIO_BYTES: Final = 257 * 1024 * 1024
_MAX_PACKAGE_BYTES: Final = 4 * 1024 * 1024
_SourceRowV3 = namedtuple("_SourceRowV3", "path role mode size sha256")
_SOURCE_ROWS_V3: Final = (
    _SourceRowV3("/usr/lib/spp/conf_proc_geometry.py", "support", 0o444, 2725, "f8273165758c6460bb10d840cb67097a423df819c449119ad15d57b21e05205a"),
    _SourceRowV3("/usr/lib/spp/conf_proc_json.py", "support", 0o444, 4425, "b18793b443e3ab2dcaf4bb7762d2e9c52f4d88daddf7bfb614b87ac0d8e80e21"),
    _SourceRowV3("/usr/lib/spp/conf_proc_lock.py", "support", 0o444, 21243, "296cdc9ba1238dfa6ac982a33f6b1411a0d7730cbb88edbcfc4492c52c729bba"),
    _SourceRowV3("/usr/lib/spp/conf_proc_module_authority.py", "support", 0o444, 3173, "01e9c44c6221b54d792c6f5ff65a9bb82e0b77a29a397b9932b1a13c7d0efe26"),
    _SourceRowV3("/usr/lib/spp/conf_proc_policy.py", "support", 0o444, 16686, "e2c48f05dd4233bc8267bb53804e25fd948e06e73a80c6d04ac1e3299118c473"),
    _SourceRowV3("/usr/lib/spp/conf_proc_provenance_v2.py", "support", 0o444, 21957, "e94a0818b2d14168190ef7ed490cc147eb18dafd837087eab883630958b59ccd"),
    _SourceRowV3("/usr/lib/spp/conf_proc_provenance_v2_manifest.py", "support", 0o444, 16846, "bd3c3ba87c7f6db52759e9f5dd16a5d447b5521c24f714043492ad713549e399"),
    _SourceRowV3("/usr/lib/spp/conf_proc_reasons.py", "support", 0o444, 12571, "c56b629a0fc156860c7400d6bc6884c1f41c8a9e4b0626ef4f2821f71102067a"),
    _SourceRowV3("/usr/lib/spp/conf_proc_spp_boot.py", "engine", 0o444, 147664, "c1dfba4c4ca71cf64ab8ecef12440950edab88f6ef3e2fb73791fc1f900076a6"),
    _SourceRowV3("/usr/lib/spp/conf_proc_spp_boot_dispatch_v3.py", "dispatcher", 0o444, 1141, "83a0652bff152a7e9e96e4f5daa0bde0278092d012d0b8fbf8832a39f23fa139"),
    _SourceRowV3("/usr/lib/spp/conf_proc_spp_boot_v3.py", "engine", 0o444, 35079, "0aff7ca7069da057e67dcfecc34b347945b3e7e36224510378989b52cbc35e73"),
    _SourceRowV3("/usr/lib/spp/conf_proc_spp_boot_v3_resource.py", "support", 0o444, 15109, "c639a585a15f81c9164878af22a59b484a553154dd9b61f3021818b1bf99f84e"),
    _SourceRowV3("/usr/lib/spp/conf_proc_spp_boot_v3_semantics.py", "engine", 0o444, 58000, "04db2acddf6282c5bc556bad1704629f14db0294c0e6ed9c1a75fc88f97a5578"),
    _SourceRowV3("/usr/lib/spp/conf_proc_spp_boot_v3_tables.py", "support", 0o444, 37125, "0c50b6a46acd5152d63757956cba65f699c58e1a1566807448f5779e28787824"),
    _SourceRowV3("/usr/lib/spp/conf_proc_spp_boot_v3_wire.py", "support", 0o444, 41779, "00c03278031280dd572bf221be2075ab741e36b378af8a7fd2c874560b840e90"),
    _SourceRowV3("/usr/lib/spp/conf_proc_spp_reasons_v3.py", "support", 0o444, 3215, "4ca5821dd0edca148bffa312fd6d9208083fa5f6e22345e61c5284d3cbbcdf75"),
)
_AuthorityRowV3 = namedtuple("_AuthorityRowV3", "attribute path role")
_AUTHORITY_ROWS_V3: Final = (
    _AuthorityRowV3("root_lock_bytes", "/etc/spp/authority/root-lock.json", "root_lock"),
    _AuthorityRowV3("runtime_closure_bytes", "/etc/spp/authority/runtime-closure.json", "runtime_closure"),
    _AuthorityRowV3("verity_rules_bytes", "/etc/spp/authority/verity-rules.json", "verity_rules"),
    _AuthorityRowV3("tcb_identity_bytes", "/etc/spp/authority/tcb-identity.json", "tcb_identity"),
    _AuthorityRowV3("builder_source_bytes", "/etc/spp/authority/designated-builder-source.py", "designated_builder_source"),
    _AuthorityRowV3("policy_bytes", "/etc/spp/authority/policy.json", "policy"),
    _AuthorityRowV3("accepted_manifest_bytes", "/etc/spp/authority/appliance.manifest.json", "accepted_manifest"),
    _AuthorityRowV3("kernel_feature_contract_bytes", "/etc/spp/authority/kernel-features.json", "kernel_features"),
    _AuthorityRowV3("trusted_certificate_bundle_bytes", "/etc/spp/authority/trusted-module-signers.pem", "trusted_module_signers"),
    _AuthorityRowV3("boot_contract_bytes", "/etc/spp/authority/boot-contract.json", "boot_contract"),
    _AuthorityRowV3("module_plan_bytes", "/etc/spp/authority/module-load-plan.json", "module_load_plan"),
    _AuthorityRowV3("gpt_layout_rules_bytes", "/etc/spp/authority/gpt-layout-rules.json", "gpt_layout_rules"),
    _AuthorityRowV3("literal_v3_observation_shape_bytes", "/etc/spp/authority/literal-v3-observation-shape.bin", "literal_v3_observation_shape"),
)
_LOCAL_IMPORTS_V3: Final = {
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
    "conf_proc_spp_boot_v3_resource": frozenset({"conf_proc_spp_boot", "conf_proc_spp_boot_v3_tables", "conf_proc_spp_boot_v3_wire", "conf_proc_spp_reasons_v3"}),
    "conf_proc_spp_boot_v3_tables": frozenset({"conf_proc_spp_boot"}),
    "conf_proc_spp_boot_v3_wire": frozenset({"conf_proc_json", "conf_proc_spp_boot_v3_tables", "conf_proc_spp_reasons_v3"}),
    "conf_proc_spp_reasons_v3": frozenset(),
}
_PROHIBITED_COMPONENTS: Final = frozenset({
    "apt", "cloud_init", "containerd", "coredump", "dnf", "docker", "getty",
    "hibernate", "journald", "kdump", "mok", "packagekit", "recovery", "serial",
    "shim", "socket", "ssh", "sshd", "subprocess", "swap", "waagent", "walinux",
})


@dataclass(frozen=True)
class PayloadInspectionResultV3:
    state: str
    boot_qualification: str
    runtime_closure: str
    activation_closure: str
    directory_closure: str
    cpio_sha256: str
    package_sha256: str


@dataclass(frozen=True)
class _RawMemberV3:
    path: str
    mode: int
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def _reject() -> None:
    raise ApplianceErrorV3(CP_SPP_PAYLOAD_V3_CONSISTENCY, "SPP boot v3 payload inspection rejected") from None


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pad4(value: int) -> int:
    return (-value) & 3


def _parse_newc(value: object) -> tuple[_RawMemberV3, ...]:
    if type(value) is not bytes or not value or len(value) > _MAX_CPIO_BYTES:
        _reject()
    offset = 0
    records: list[_RawMemberV3] = []
    previous_name = b""
    while True:
        if offset + 110 > len(value) or value[offset:offset + 6] != _MAGIC:
            _reject()
        raw = value[offset + 6:offset + 110]
        if len(raw) != 104 or any(byte not in b"0123456789abcdef" for byte in raw):
            _reject()
        fields = tuple(int(raw[index:index + 8], 16) for index in range(0, 104, 8))
        offset += 110
        size, name_size = fields[6], fields[11]
        if name_size < 1 or offset + name_size > len(value):
            _reject()
        raw_name = value[offset:offset + name_size]
        offset += name_size
        name_pad = _pad4(110 + name_size)
        if offset + name_pad > len(value) or any(value[offset:offset + name_pad]) or not raw_name.endswith(b"\0") or b"\0" in raw_name[:-1]:
            _reject()
        offset += name_pad
        if offset + size > len(value):
            _reject()
        payload = value[offset:offset + size]
        offset += size
        data_pad = _pad4(size)
        if offset + data_pad > len(value) or any(value[offset:offset + data_pad]):
            _reject()
        offset += data_pad
        try:
            name = raw_name[:-1].decode("utf-8")
        except UnicodeDecodeError:
            _reject()
        if name == "TRAILER!!!":
            if len(records) != 29 or fields != (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0) or offset != len(value):
                _reject()
            return tuple(records)
        encoded = name.encode("utf-8")
        expected = (len(records) + 1, stat.S_IFREG | 0o444, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(encoded) + 1, 0)
        if len(records) >= 29 or not name or name.startswith("/") or len(encoded) > 255 or encoded <= previous_name or fields != expected:
            _reject()
        previous_name = encoded
        records.append(_RawMemberV3("/" + name, 0o444, payload))


def _check_component_policy(module: str) -> None:
    if any(component.casefold() in _PROHIBITED_COMPONENTS for component in module.replace(".", "/").split("/")):
        _reject()


def _external_imports(records: tuple[_RawMemberV3, ...]) -> tuple[str, ...]:
    sources = {record.path.rsplit("/", 1)[-1][:-3]: record.data for record in records if record.path.startswith("/usr/lib/spp/")}
    if set(sources) != set(_LOCAL_IMPORTS_V3):
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
                    if not alias.name or any(not part.isidentifier() for part in alias.name.split(".")):
                        _reject()
                    _check_component_policy(alias.name)
                    root = alias.name.split(".", 1)[0]
                    (local_imports if root in sources else external).add(root if root in sources else alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level != 0 or node.module is None or any(alias.name == "*" or alias.asname is not None for alias in node.names):
                    _reject()
                if node.module == "__future__":
                    continue
                if any(not part.isidentifier() for part in node.module.split(".")):
                    _reject()
                _check_component_policy(node.module)
                root = node.module.split(".", 1)[0]
                (local_imports if root in sources else external).add(root if root in sources else node.module)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__":
                _reject()
        if local_imports != _LOCAL_IMPORTS_V3[module]:
            _reject()
    reached = {"conf_proc_spp_boot_dispatch_v3"}
    while True:
        expanded = reached | set().union(*(_LOCAL_IMPORTS_V3[name] for name in reached))
        if expanded == reached:
            break
        reached = expanded
    if reached != set(sources):
        _reject()
    return tuple(sorted(external, key=lambda item: item.encode("utf-8")))


def _expected_rows(binding: BootBindingV3) -> tuple[tuple[str, str, int, int, str, bytes | None], ...]:
    rows: list[tuple[str, str, int, int, str, bytes | None]] = [(path, role, mode, size, digest, None) for path, role, mode, size, digest in _SOURCE_ROWS_V3]
    for attribute, path, role in _AUTHORITY_ROWS_V3:
        data = getattr(binding, attribute)
        if type(data) is not bytes:
            _reject()
        rows.append((path, role, 0o444, len(data), _digest(data), data))
    return tuple(sorted(rows, key=lambda row: row[0].encode("utf-8")))


def _inspect_package(package_bytes: object, records: tuple[_RawMemberV3, ...], inspection: InspectionResult, binding: BootBindingV3, cpio_sha256: str, external_imports: tuple[str, ...]) -> str:
    if type(package_bytes) is not bytes or not package_bytes or len(package_bytes) > _MAX_PACKAGE_BYTES:
        _reject()
    try:
        value = canonical_loads(package_bytes)
    except Exception:
        _reject()
    keys = {"schema", "package_version", "status", "boot_qualification", "runtime_closure", "activation_closure", "directory_closure", "h4_artifact_input_sha256", "h4_execution_provenance_sha256", "boot_contract_sha256", "module_plan_sha256", "cpio_sha256", "entries", "external_imports_declared_unresolved"}
    exact = {
        "schema": _PACKAGE_SCHEMA_V3, "status": "built_unqualified", "boot_qualification": "not_qualified", "runtime_closure": "unresolved", "activation_closure": "unresolved", "directory_closure": "unresolved", "h4_artifact_input_sha256": inspection.artifact_input_sha256, "h4_execution_provenance_sha256": inspection.execution_provenance_sha256, "boot_contract_sha256": binding.boot_contract_sha256, "module_plan_sha256": _digest(binding.module_plan_bytes), "cpio_sha256": cpio_sha256,
    }
    if type(value) is not dict or set(value) != keys or canonical_dumps(value) != package_bytes or value.get("package_version") != 3 or any(type(value.get(key)) is not str or value[key] != wanted for key, wanted in exact.items()):
        _reject()
    expected_rows = _expected_rows(binding)
    if len(records) != len(expected_rows):
        _reject()
    entries: list[dict[str, object]] = []
    for record, (path, role, mode, size, digest, sealed) in zip(records, expected_rows, strict=True):
        if record.path != path or record.mode != mode or len(record.data) != size or record.sha256 != digest or (sealed is not None and record.data != sealed):
            _reject()
        entries.append({"path": path, "role": role, "mode": mode, "size_bytes": size, "sha256": digest})
    if type(value.get("entries")) is not list or value["entries"] != entries or type(value.get("external_imports_declared_unresolved")) is not list or value["external_imports_declared_unresolved"] != list(external_imports):
        _reject()
    for entry in value["entries"]:
        if type(entry) is not dict or set(entry) != {"path", "role", "mode", "size_bytes", "sha256"} or any(type(entry.get(key)) is not str for key in ("path", "role", "sha256")) or type(entry.get("mode")) is not int or type(entry.get("size_bytes")) is not int or entry["size_bytes"] < 1:
            _reject()
    return _digest(package_bytes)


def _check_output_address(output_path: object, binding: BootBindingV3, cpio_sha256: str, package_sha256: str) -> None:
    if type(output_path) is not str or not output_path.startswith("/") or "\x00" in output_path:
        _reject()
    parts = output_path.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]) or len(parts) < 6 or tuple(parts[-4:]) != ("built_unqualified", binding.boot_contract_sha256, cpio_sha256, package_sha256):
        _reject()


def _inspect_boot_payload_v3(*, inspection: InspectionResult, binding: BootBindingV3, cpio_bytes: bytes, package_bytes: bytes, output_path: str) -> PayloadInspectionResultV3:
    if not _is_issued_inspection_result(inspection) or not is_issued_boot_binding_v3(binding) or type(inspection) is not InspectionResult or type(binding) is not BootBindingV3:
        _reject()
    if inspection.state != "artifact_consistent" or inspection.hardware_qualification != "not_qualified" or inspection.manifest_sha256 != _digest(binding.accepted_manifest_bytes):
        _reject()
    records = _parse_newc(cpio_bytes)
    if tuple(record.path for record in records) != tuple(row[0] for row in _expected_rows(binding)):
        _reject()
    external_imports = _external_imports(records)
    cpio_sha256 = _digest(cpio_bytes)
    package_sha256 = _inspect_package(package_bytes, records, inspection, binding, cpio_sha256, external_imports)
    _check_output_address(output_path, binding, cpio_sha256, package_sha256)
    return PayloadInspectionResultV3("artifact_consistent", "not_qualified", "unresolved", "unresolved", "unresolved", cpio_sha256, package_sha256)


def inspect_boot_payload_v3(*, inspection: InspectionResult, binding: BootBindingV3, cpio_bytes: bytes, package_bytes: bytes, output_path: str) -> PayloadInspectionResultV3:
    """Public sanitized boundary for the independent v3 raw inspector."""

    result: PayloadInspectionResultV3 | None = None
    failed = False
    try:
        result = _inspect_boot_payload_v3(inspection=inspection, binding=binding, cpio_bytes=cpio_bytes, package_bytes=package_bytes, output_path=output_path)
    except Exception:
        failed = True
    if failed or result is None:
        raise ApplianceErrorV3(CP_SPP_PAYLOAD_V3_CONSISTENCY, "SPP boot v3 payload inspection rejected")
    return result
