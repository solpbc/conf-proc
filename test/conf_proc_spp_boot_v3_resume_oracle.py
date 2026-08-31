#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent A3.1c PCR16/resume oracle; imports no product code."""

from __future__ import annotations

import ast
import hashlib
import json
import struct
from dataclasses import dataclass, fields, is_dataclass, replace


S0 = b"\0" * 32
NONCE_DOMAIN = b"sol-pbc/spp/handoff-nonce-v3\0"
LINEAGE_DOMAIN = b"sol-pbc/spp/boot-lineage-v3\0"
TRANSPORT_DOMAIN = b"sol-pbc/spp/tpmrm-transport-v3\0"
STAGED_DOMAIN = b"sol-pbc/spp/resume-anchor-v3/staged\0"
CONSUMED_DOMAIN = b"sol-pbc/spp/resume-anchor-v3/consumed\0"
READ_REQUEST = bytes.fromhex("8001000000140000017e00000001000b03000001")
EXTEND_PREFIX = bytes.fromhex(
    "80020000004100000182000000100000000940000009000000000000000001000b"
)
EXTEND_SUCCESS = bytes.fromhex("80020000001300000000000000000000010000")
OPERATION_IDS = (
    "stage1_read_start", "stage1_extend_staged", "stage1_read_staged",
    "stage2_read_staged", "stage2_extend_consumed", "stage2_read_consumed",
)
OPERATION_KINDS = ("read", "extend_D1", "read", "read", "extend_D2", "read")
OPERATION_STATES = ("S0", "S0", "S1", "S1", "S1", "S2")
INPUT_ROWS = (
    ("sealed_handoff_frame", 1048), ("handoff_nonce.raw", 32),
    ("issued_binding_digest", 32), ("boot_contract_measurement", 32),
    ("predicted_pcr15", 32), ("root_lock_sha256", 32),
    ("runtime_closure_sha256", 32), ("verity_rules_sha256", 32),
    ("tcb_identity_sha256", 32), ("builder_source_sha256", 32),
    ("policy_sha256", 32), ("accepted_manifest_sha256", 32),
    ("kernel_feature_contract_sha256", 32),
    ("trusted_certificate_bundle_sha256", 32), ("boot_contract_sha256", 32),
    ("module_plan_sha256", 32), ("gpt_layout_rules_sha256", 32),
    ("literal_observation_shape_digest", 32),
    ("mount_namespace_inode", 8), ("user_namespace_inode", 8),
    ("pid_namespace_inode", 8), ("network_namespace_inode", 8),
    ("tpmrm_transport_identity", 32),
)
DOMINANCE_OBJECT = {
    "authorization_sink_kinds": [
        "Stage2ResumeEvidenceV3_constructor",
        "_resume_boot_transition_from_consumed_v3_call",
        "stage2_engine_constructor",
    ],
    "exact_helper_call_edges": 1,
    "exact_preparatory_constructors": 1,
    "forbid_preparatory_authority_bypass": True,
    "modes": ["declared_unissuable", "production_enforced"],
    "preparatory_constructor_kind": "resume_only_binding_constructor",
    "required_dominator": "stage2_consumed_s2_accepted",
    "root_path": "/usr/lib/spp/conf_proc_spp_init.py",
    "root_symbol": "stage2_resume_entry_v3",
    "schema": "conf-proc-spp-resume-dominance/v3",
    "unknown_indirect_call_policy": "reject",
}
DOMINANCE_BYTES = json.dumps(
    DOMINANCE_OBJECT, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
).encode("ascii")
DOMINANCE_SHA256 = "08c7fdd7f94dd6c333a745c32752abd6c1a3cdc5382783a33ceb3abcd625cce6"
DECLARATION_SHA256 = {
    "resume_anchor": "cb6a3e136d60493f4b6ce211be5e37d71f639ac0cf9ce5c95a6e1dbfc3e9266a",
    "resume_domains": "c5d59d8af06649581960517030be020a37944b0063ffd3d3b24e33a825991661",
    "pcr16_operations": "4e4b9e5044d2774d0d71a8992d9d3edfae45ee3a02c2b8cae96885c56755877c",
    "supporting_memfd": "f09349e7c33e026953775acb809d6481c23eeb66e030ddc2452942fb1bd832e2",
    "resume_call_graph": "3b4073df868792238c94eb8b4d7b40b332bcdc88fcdf24437dd8686b1500c4b9",
    "resume_closure_oracle": "6705e8a46ac6946cb945b25df41308d441923d6f281ddb16fe9367ee72de5573",
}
A3_PRODUCTION_SOURCE_PINS = (
    ("conf_proc_geometry.py", 2725, "f8273165758c6460bb10d840cb67097a423df819c449119ad15d57b21e05205a"),
    ("conf_proc_json.py", 4425, "b18793b443e3ab2dcaf4bb7762d2e9c52f4d88daddf7bfb614b87ac0d8e80e21"),
    ("conf_proc_lock.py", 21243, "296cdc9ba1238dfa6ac982a33f6b1411a0d7730cbb88edbcfc4492c52c729bba"),
    ("conf_proc_module_authority.py", 3173, "01e9c44c6221b54d792c6f5ff65a9bb82e0b77a29a397b9932b1a13c7d0efe26"),
    ("conf_proc_policy.py", 16686, "e2c48f05dd4233bc8267bb53804e25fd948e06e73a80c6d04ac1e3299118c473"),
    ("conf_proc_provenance_v2.py", 21957, "e94a0818b2d14168190ef7ed490cc147eb18dafd837087eab883630958b59ccd"),
    ("conf_proc_provenance_v2_manifest.py", 16846, "bd3c3ba87c7f6db52759e9f5dd16a5d447b5521c24f714043492ad713549e399"),
    ("conf_proc_reasons.py", 12571, "c56b629a0fc156860c7400d6bc6884c1f41c8a9e4b0626ef4f2821f71102067a"),
    ("conf_proc_spp_boot.py", 147664, "c1dfba4c4ca71cf64ab8ecef12440950edab88f6ef3e2fb73791fc1f900076a6"),
    ("conf_proc_spp_boot_dispatch_v3.py", 1141, "83a0652bff152a7e9e96e4f5daa0bde0278092d012d0b8fbf8832a39f23fa139"),
    ("conf_proc_spp_boot_v3.py", 119545, "36ae26eb8c9f201f6705f16d2b8bee530b0340b4589714bc39e344d38d7a7028"),
    ("conf_proc_spp_boot_v3_resource.py", 25792, "b172f2dd4dbe70e295e4dbdd0ebe066c7e247e8d2183db22b15ac48f5afc57de"),
    ("conf_proc_spp_boot_v3_semantics.py", 128500, "09572aa6d76e83ee4117ed1f10c7bc32397397014abb34d55812c8f8ebd3cd85"),
    ("conf_proc_spp_boot_v3_tables.py", 76499, "29362baa68d627b1f0453b434e22afbb0bc530916d2fd5d3614ca4451a7ea785"),
    ("conf_proc_spp_boot_v3_wire.py", 47503, "71e491df1ab92a70b1102af866ae8fc917754a8d76763e0c8606bd8b5c1d7549"),
    ("conf_proc_spp_init.py", 4604, "32b7c8f5b6772f52433adcca11051ad1e883bb59aa4f7c66116e43a379bd1dd3"),
    ("conf_proc_spp_reasons_v3.py", 3215, "4ca5821dd0edca148bffa312fd6d9208083fa5f6e22345e61c5284d3cbbcdf75"),
)
A3_PRODUCTION_SOURCE_PATHS = tuple(row[0] for row in A3_PRODUCTION_SOURCE_PINS)
A3_PRODUCTION_SOURCE_ROLES = (
    "support", "support", "support", "support", "support", "support", "support",
    "support", "engine", "dispatcher", "engine", "support", "engine", "support",
    "support", "engine", "support",
)


def _h(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _exact_bytes(value: object, length: int, name: str) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise ValueError(name)
    return value


def _u(value: object, width: int, name: str) -> bytes:
    if type(value) is not int or not 0 <= value < 1 << (width * 8):
        raise ValueError(name)
    return value.to_bytes(width, "big")


def declaration_digest(rows: object) -> str:
    def normalize(value: object) -> object:
        if value is None or type(value) in (bool, int, str):
            return [type(value).__name__, value]
        if type(value) is bytes:
            return ["bytes", len(value), value.hex()]
        if type(value) is tuple:
            return ["tuple", len(value), [normalize(member) for member in value]]
        if is_dataclass(value):
            return [
                "dataclass", type(value).__name__,
                [[field.name, normalize(getattr(value, field.name))] for field in fields(value)],
            ]
        raise ValueError("declaration concrete type")

    return hashlib.sha256(
        json.dumps(normalize(rows), sort_keys=False, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def a3_shipped_source_pins(source_authority: str) -> tuple[tuple[str, int, str], ...]:
    if type(source_authority) is not str:
        raise ValueError("A3 source authority")
    tree = ast.parse(source_authority, filename="conf_proc_spp_boot_payload_v3.py")
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    value: ast.expr | None = None
    for statement in tree.body:
        target = statement.target if isinstance(statement, ast.AnnAssign) else None
        if isinstance(target, ast.Name) and target.id == "BOOT_PAYLOAD_SOURCE_AUTHORITY_V3":
            if value is not None:
                raise ValueError("duplicate A3 source authority")
            value = statement.value
    if value is None:
        raise ValueError("missing A3 source authority")
    if not isinstance(value, ast.Tuple) or len(value.elts) != 17:
        raise ValueError("A3 source authority must be one exact 17-row literal tuple")
    rows: list[tuple[str, int, str]] = []
    direct_calls: set[ast.Call] = set()
    for node in value.elts:
        if (
            not isinstance(node, ast.Call)
            or not isinstance(node.func, ast.Name)
            or node.func.id != "_SourceAuthorityV3"
            or len(node.args) != 5
            or node.keywords
        ):
            raise ValueError("A3 source authority row")
        direct_calls.add(node)
        path_node, role_node, mode_node, size_node, digest_node = node.args
        if (
            not isinstance(path_node, ast.Constant) or type(path_node.value) is not str
            or not isinstance(role_node, ast.Constant) or type(role_node.value) is not str
            or not isinstance(mode_node, ast.Constant) or type(mode_node.value) is not int
            or not isinstance(size_node, ast.Constant) or type(size_node.value) is not int
            or not isinstance(digest_node, ast.Constant) or type(digest_node.value) is not str
        ):
            raise ValueError("A3 source authority literal fields")
        archive_path = path_node.value
        prefix = "/usr/lib/spp/"
        if not archive_path.startswith(prefix) or "/" in archive_path[len(prefix):] or not archive_path.endswith(".py"):
            raise ValueError("A3 source authority path")
        if size_node.value <= 0 or len(digest_node.value) != 64:
            raise ValueError("A3 source authority pin")
        if role_node.value != A3_PRODUCTION_SOURCE_ROLES[len(rows)] or mode_node.value != 0o444:
            raise ValueError("A3 source authority role or mode")
        rows.append((archive_path[len(prefix):], size_node.value, digest_node.value))
    all_direct_calls = {
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "_SourceAuthorityV3"
    }
    if all_direct_calls != direct_calls:
        raise ValueError("A3 source authority constructor denominator")
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "_SourceAuthorityV3" and isinstance(node.ctx, ast.Load):
            parent = parents.get(node)
            allowed = (
                (isinstance(parent, ast.Call) and parent.func is node and parent in direct_calls)
                or (isinstance(parent, ast.arg) and parent.annotation is node)
                or (isinstance(parent, ast.AnnAssign) and parent.annotation is node)
                or isinstance(parent, ast.Compare)
            )
            if not allowed:
                raise ValueError("A3 source authority constructor indirection")
        if isinstance(node, ast.Attribute) and node.attr == "_SourceAuthorityV3":
            raise ValueError("A3 source authority attribute indirection")
        if isinstance(node, ast.Constant) and node.value == "_SourceAuthorityV3":
            raise ValueError("A3 source authority reflective indirection")
    return tuple(rows)


def a3_shipped_source_paths(source_authority: str) -> tuple[str, ...]:
    return tuple(row[0] for row in a3_shipped_source_pins(source_authority))


def _static_bytes(node: ast.AST) -> bytes | None:
    if isinstance(node, ast.Constant) and type(node.value) is bytes:
        return node.value
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        values = [member.value for member in node.elts if isinstance(member, ast.Constant) and type(member.value) is int]
        if len(values) == len(node.elts) and all(0 <= value <= 255 for value in values):
            return bytes(values)
    if not isinstance(node, ast.Call):
        return None
    target = _call_name(node.func)
    if target in ("bytes", "bytearray") and len(node.args) == 1 and not node.keywords:
        return _static_bytes(node.args[0])
    if target in ("bytes.fromhex", "bytearray.fromhex") and len(node.args) == 1:
        argument = node.args[0]
        if isinstance(argument, ast.Constant) and type(argument.value) is str:
            try:
                return bytes.fromhex(argument.value)
            except ValueError:
                return None
    if target in ("struct.pack", "pack") and node.args:
        format_node, *value_nodes = node.args
        if (
            isinstance(format_node, ast.Constant) and type(format_node.value) is str
            and all(isinstance(value, ast.Constant) and type(value.value) in (int, bytes) for value in value_nodes)
        ):
            try:
                return struct.pack(format_node.value, *(value.value for value in value_nodes))
            except (struct.error, TypeError, ValueError):
                return None
    return None


def _contains_pcr_reset_packet(value: bytes) -> bool:
    return any(
        value[offset:offset + 2] in (b"\x80\x01", b"\x80\x02")
        and value[offset + 6:offset + 10] == b"\x00\x00\x01\x3d"
        for offset in range(max(0, len(value) - 9))
    )


def reject_dangerous_tpm_command_authority(sources: dict[str, str]) -> None:
    if type(sources) is not dict or tuple(sources) != A3_PRODUCTION_SOURCE_PATHS:
        raise ValueError("A3 production source denominator")
    for path, source in sources.items():
        if type(source) is not str:
            raise ValueError("A3 production source")
        tree = ast.parse(source, filename=path)
        tpm_fds: set[str] = set()
        assignments = [node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign))]
        changed = True
        while changed:
            changed = False
            for assignment in assignments:
                value = assignment.value
                targets = [assignment.target] if isinstance(assignment, ast.AnnAssign) else assignment.targets
                names = [target.id for target in targets if isinstance(target, ast.Name)]
                if not names:
                    continue
                opens_tpm = (
                    isinstance(value, ast.Call)
                    and (_call_name(value.func) or "").split(".")[-1] in ("open", "os.open")
                    and value.args
                    and isinstance(value.args[0], ast.Constant)
                    and type(value.args[0].value) is str
                    and value.args[0].value.startswith("/dev/tpm")
                )
                aliases_tpm = isinstance(value, ast.Name) and value.id in tpm_fds
                if (opens_tpm or aliases_tpm) and any(name not in tpm_fds for name in names):
                    tpm_fds.update(names)
                    changed = True
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and type(node.value) is int and node.value == 0x0000013D:
                raise ValueError("TPM2_PCR_Reset command code")
            static = _static_bytes(node)
            if static is not None and _contains_pcr_reset_packet(static):
                raise ValueError("TPM2_PCR_Reset command packet")
            if not isinstance(node, ast.Call):
                continue
            target = _call_name(node.func)
            leaf = (target or "").split(".")[-1]
            if (
                leaf in ("open", "os.open") and node.args
                and isinstance(node.args[0], ast.Constant) and type(node.args[0].value) is str
                and node.args[0].value.startswith("/dev/tpm")
            ):
                raise ValueError("executable TPM device acquisition")
            writes_tracked_fd = (
                leaf in ("write", "writev", "pwrite", "send", "sendall")
                and (
                    (node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in tpm_fds)
                    or (
                        isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                        and node.func.value.id in tpm_fds
                    )
                )
            )
            if writes_tracked_fd:
                raise ValueError("generic write to TPM transport")


def validate_a3_tpm_authority_declarations(
    sources: dict[str, str], source_authority: str,
) -> None:
    if a3_shipped_source_pins(source_authority) != A3_PRODUCTION_SOURCE_PINS:
        raise ValueError("A3 shipped source authority denominator")
    if type(sources) is not dict or tuple(sources) != A3_PRODUCTION_SOURCE_PATHS:
        raise ValueError("A3 production source denominator")
    reject_dangerous_tpm_command_authority(sources)
    for path, expected_size, expected_sha256 in A3_PRODUCTION_SOURCE_PINS:
        source = sources[path]
        if type(source) is not str:
            raise ValueError("A3 production source")
        encoded = source.encode("utf-8")
        if len(encoded) != expected_size or hashlib.sha256(encoded).hexdigest() != expected_sha256:
            raise ValueError("A3 complete production source-byte closure")
    table_tree = ast.parse(sources["conf_proc_spp_boot_v3_tables.py"])
    operation_calls = []
    for node in ast.walk(table_tree):
        if not isinstance(node, ast.Call) or (_call_name(node.func) or "").split(".")[-1] != "Pcr16OperationRowV3":
            continue
        if len(node.args) < 4 or not all(isinstance(node.args[index], ast.Constant) for index in (0, 3)):
            raise ValueError("PCR16 authority row shape")
        operation_calls.append((node.args[0].value, node.args[3].value))
    expected = tuple(zip(OPERATION_IDS, (
        "TPM2_PCR_Read_sha256_16", "TPM2_PCR_Extend_sha256_16",
        "TPM2_PCR_Read_sha256_16", "TPM2_PCR_Read_sha256_16",
        "TPM2_PCR_Extend_sha256_16", "TPM2_PCR_Read_sha256_16",
    ), strict=True))
    if tuple(operation_calls) != expected:
        raise ValueError("closed PCR16 declaration denominator")


@dataclass(frozen=True)
class Transport:
    st_dev_major: int
    st_dev_minor: int
    st_ino: int
    st_rdev_major: int
    st_rdev_minor: int
    f_getfl_without_o_cloexec: int
    f_getfd: int
    fdinfo_mnt_id: int
    fdinfo_ino: int
    registration_identity: bytes


@dataclass(frozen=True)
class Inputs:
    frame: bytes
    nonce: bytes
    binding: bytes
    measurement: bytes
    pcr15: bytes
    authority_inputs: tuple[bytes, ...]
    namespaces: tuple[int, ...]
    transport: Transport


@dataclass(frozen=True)
class States:
    nonce_commitment: bytes
    transport_identity: bytes
    lineage: bytes
    frame_sha256: bytes
    d1: bytes
    s1: bytes
    d2: bytes
    s2: bytes


def transport_identity(
    value: Transport, *, endian: str = "big", domain: bytes = TRANSPORT_DOMAIN,
) -> bytes:
    if type(value) is not Transport or endian != "big":
        raise ValueError("transport")
    if type(domain) is not bytes:
        raise ValueError("transport domain")
    fields = (
        _u(value.st_dev_major, 4, "st_dev_major"),
        _u(value.st_dev_minor, 4, "st_dev_minor"),
        _u(value.st_ino, 8, "st_ino"),
        _u(value.st_rdev_major, 4, "st_rdev_major"),
        _u(value.st_rdev_minor, 4, "st_rdev_minor"),
        _u(value.f_getfl_without_o_cloexec, 4, "f_getfl"),
        _u(value.f_getfd, 4, "f_getfd"),
        _u(value.fdinfo_mnt_id, 8, "mnt_id"),
        _u(value.fdinfo_ino, 8, "fdinfo_ino"),
        _exact_bytes(value.registration_identity, 32, "registration_identity"),
    )
    return _h(domain + b"".join(fields))


def calculate_with_domains(
    value: Inputs,
    domains: tuple[bytes, bytes, bytes, bytes, bytes],
) -> States:
    if type(value) is not Inputs:
        raise ValueError("inputs")
    if type(domains) is not tuple or len(domains) != 5 or any(type(item) is not bytes for item in domains):
        raise ValueError("domains")
    nonce_domain, lineage_domain, transport_domain, staged_domain, consumed_domain = domains
    frame = _exact_bytes(value.frame, 1048, "frame")
    nonce = _exact_bytes(value.nonce, 32, "nonce")
    fixed = tuple(
        _exact_bytes(member, 32, name)
        for member, name in zip(
            (value.binding, value.measurement, value.pcr15),
            ("binding", "measurement", "pcr15"), strict=True,
        )
    )
    if type(value.authority_inputs) is not tuple or len(value.authority_inputs) != 13:
        raise ValueError("authority input census")
    authorities = b"".join(
        _exact_bytes(member, 32, "authority input") for member in value.authority_inputs
    )
    if type(value.namespaces) is not tuple or len(value.namespaces) != 4:
        raise ValueError("namespace census")
    namespaces = b"".join(_u(member, 8, "namespace") for member in value.namespaces)
    transport = transport_identity(value.transport, domain=transport_domain)
    nonce_commitment = _h(nonce_domain + nonce)
    lineage = _h(
        lineage_domain + b"".join(fixed) + authorities + namespaces
        + transport + nonce_commitment
    )
    frame_sha256 = _h(frame)
    d1 = _h(
        staged_domain + _u(3, 2, "version") + _u(1048, 4, "frame length")
        + frame_sha256 + lineage + nonce_commitment
    )
    s1 = _h(S0 + d1)
    d2 = _h(
        consumed_domain + _u(3, 2, "version") + s1 + d1 + frame_sha256
        + lineage + nonce_commitment
    )
    return States(nonce_commitment, transport, lineage, frame_sha256, d1, s1, d2, _h(s1 + d2))


def calculate(value: Inputs) -> States:
    return calculate_with_domains(
        value,
        (NONCE_DOMAIN, LINEAGE_DOMAIN, TRANSPORT_DOMAIN, STAGED_DOMAIN, CONSUMED_DOMAIN),
    )


def vector_inputs() -> Inputs:
    def block(label: bytes, length: int) -> bytes:
        out = b""
        counter = 0
        while len(out) < length:
            out += _h(label + counter.to_bytes(4, "big"))
            counter += 1
        return out[:length]

    return Inputs(
        block(b"frame", 1048), block(b"nonce", 32), block(b"binding", 32),
        block(b"measurement", 32), block(b"pcr15", 32),
        tuple(block(b"authority" + bytes([index]), 32) for index in range(13)),
        (4026531840, 4026531837, 4026531836, 4026531992),
        Transport(0, 5, 125, 253, 65536, 32770, 1, 26, 125,
                  bytes.fromhex("546542a11e9f1274de677dbe06facecc78fccaec1e5783e03c767d00d7321526")),
    )


def extend_request(digest: bytes) -> bytes:
    return EXTEND_PREFIX + _exact_bytes(digest, 32, "extend digest")


def read_response(state: bytes, update_counter: int) -> bytes:
    return (
        bytes.fromhex("80010000003e00000000") + _u(update_counter, 4, "counter")
        + bytes.fromhex("00000001000b03000001000000010020")
        + _exact_bytes(state, 32, "read state")
    )


def validate_command_inventory(
    rows: tuple[tuple[str, str], ...], consumers: tuple[str, ...],
) -> None:
    expected = tuple(zip(OPERATION_IDS, OPERATION_KINDS, strict=True))
    if type(rows) is not tuple or rows != expected or type(consumers) is not tuple or consumers:
        raise ValueError("closed command/consumer inventory")
    forbidden = ("reset", "passthrough", "generic", "caller_buffer")
    if any(token in (row_id + kind).casefold() for row_id, kind in rows for token in forbidden):
        raise ValueError("forbidden TPM authority")


class TerminalTrace(ValueError):
    pass


@dataclass(frozen=True)
class TraceOptions:
    copied_bytes: bool = False
    fresh_process: bool = False
    second_entry: bool = False
    duplicate_memfd: bool = False
    pread: bool = False
    reset_offset: bool = False
    live_fd3: bool = False
    crash_after_memfd_consume: bool = False
    crash_at: int | None = None
    ambiguous_at: int | None = None
    initial_pcr: bytes = S0
    forced_state_at: tuple[int, bytes] | None = None
    operation_ids: tuple[str, ...] = OPERATION_IDS


def simulate_trace(inputs: Inputs, options: TraceOptions = TraceOptions()) -> str:
    if type(options) is not TraceOptions or options.operation_ids != OPERATION_IDS:
        raise TerminalTrace("operation inventory")
    if any((options.copied_bytes, options.fresh_process, options.second_entry,
            options.duplicate_memfd, options.pread, options.reset_offset,
            options.live_fd3)):
        raise TerminalTrace("causal continuity")
    states = calculate(inputs)
    if type(options.initial_pcr) is not bytes or len(options.initial_pcr) != 32:
        raise TerminalTrace("initial PCR")
    pcr = options.initial_pcr
    fd3_live = True
    consumed = False
    for index, kind in enumerate(OPERATION_KINDS, start=1):
        if options.forced_state_at is not None and options.forced_state_at[0] == index:
            forced = options.forced_state_at[1]
            if type(forced) is not bytes or len(forced) != 32:
                raise TerminalTrace("forced state")
            pcr = forced
        if options.crash_at == index or options.ambiguous_at == index:
            raise TerminalTrace("terminal operation outcome")
        if kind == "read":
            expected = {1: S0, 3: states.s1, 4: states.s1, 6: states.s2}[index]
            if pcr != expected:
                raise TerminalTrace("state")
        elif kind == "extend_D1":
            pcr = _h(pcr + states.d1)
        else:
            if not fd3_live or consumed:
                raise TerminalTrace("memfd before consume")
            consumed = True
            fd3_live = False
            if options.crash_after_memfd_consume:
                raise TerminalTrace("memfd consumed before D2")
            pcr = _h(pcr + states.d2)
        if options.crash_at == -index:
            raise TerminalTrace("terminal crash after operation")
    if fd3_live or not consumed or pcr != states.s2:
        raise TerminalTrace("completion")
    return "synthetic_helper_sink"


_ROOT = "stage2_resume_entry_v3"
_EVENTS = {
    "resume_only_binding_constructor": "prepare",
    "stage2_read_staged": "s1_read",
    "consume_fd3": "consume_fd3",
    "stage2_extend_consumed": "d2_extend",
    "stage2_read_consumed": "s2_read",
    "stage2_pcr15_read": "pcr15_read",
    "Stage2ResumeEvidenceV3": "evidence",
    "_resume_boot_transition_from_consumed_v3": "helper",
    "Stage2ResumeEngineV3": "engine",
}
_DOMINATOR = "stage2_consumed_s2_accepted"
_SINK_EVENTS = frozenset({"evidence", "helper", "engine"})
_EXPECTED_PATH = (
    "prepare", "s1_read", "consume_fd3", "d2_extend", "s2_read",
    "dominator", "pcr15_read",
    "evidence", "helper", "engine",
)
_REFLECTION = frozenset({"getattr", "setattr", "delattr", "globals", "locals", "vars", "eval", "exec", "__import__"})
_GRAPH_SYMBOLS = frozenset((*_EVENTS, _DOMINATOR, _ROOT))


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _call_name(node.value)
        return None if owner is None else owner + "." + node.attr
    return None


def _combine(left: list[tuple[str, ...]], right: list[tuple[str, ...]]) -> list[tuple[str, ...]]:
    return [a + b for a in left for b in right]


GraphKey = tuple[str, str]


def _binding_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, ast.Subscript):
        names: set[str] = set()
        if isinstance(node.slice, ast.Constant) and type(node.slice.value) is str:
            names.add(node.slice.value)
        return names | _binding_names(node.value)
    if isinstance(node, (ast.Tuple, ast.List)):
        return set().union(*(_binding_names(member) for member in node.elts), set())
    return set()


def _validate_lexical_graph_bindings(
    module: str, tree: ast.Module, module_imports: dict[str, GraphKey],
) -> None:
    protected = set(_GRAPH_SYMBOLS)
    protected.update(local for local, target in module_imports.items() if target[1] in _GRAPH_SYMBOLS)
    bindings: dict[str, list[str]] = {name: [] for name in protected}
    graph_module = False
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if statement.name in protected:
                bindings[statement.name].append(type(statement).__name__)
                graph_module = True
        elif isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                local = alias.asname or alias.name
                if local in protected:
                    bindings[local].append("ImportFrom")
                    graph_module = True
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                local = alias.asname or alias.name
                if local in protected:
                    bindings[local].append("Import")
        elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = [statement.target] if isinstance(statement, (ast.AnnAssign, ast.AugAssign)) else statement.targets
            for target in targets:
                for name in _binding_names(target) & protected:
                    bindings[name].append("dynamic_module_binding")
                    graph_module = True
        elif isinstance(statement, ast.Delete):
            for target in statement.targets:
                for name in _binding_names(target) & protected:
                    bindings[name].append("module_delete")
                    graph_module = True
    if any(len(kinds) > 1 or any(kind in {"dynamic_module_binding", "module_delete", "ClassDef"} for kind in kinds) for kinds in bindings.values()):
        raise ValueError("authority symbol module rebinding")
    if graph_module:
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
                continue
            for node in ast.walk(statement):
                bound: set[str] = set()
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                    targets = [node.target] if not isinstance(node, ast.Assign) else node.targets
                    bound.update(*(_binding_names(target) for target in targets), set())
                elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                    bound.update(_binding_names(node.target))
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    bound.update(*(
                        _binding_names(item.optional_vars) for item in node.items if item.optional_vars is not None
                    ), set())
                elif isinstance(node, ast.ExceptHandler) and node.name is not None:
                    bound.add(node.name)
                elif isinstance(node, ast.Delete):
                    bound.update(*(_binding_names(target) for target in node.targets), set())
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    bound.add(node.name)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    bound.update(alias.asname or alias.name for alias in node.names)
                if bound & protected:
                    raise ValueError("authority symbol dynamic module binding")
                if isinstance(node, ast.Call) and (_call_name(node.func) or "").split(".")[-1] in _REFLECTION:
                    raise ValueError("module reflection or dynamic export")
                if (
                    isinstance(node, ast.Call)
                    and any(
                        isinstance(member, ast.Constant) and member.value in protected
                        for member in ast.walk(node)
                    )
                ):
                    raise ValueError("dynamic authority export")
    for function in (node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        parameters = {
            argument.arg for argument in (
                *function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs,
                *(item for item in (function.args.vararg, function.args.kwarg) if item is not None),
            )
        }
        if parameters & protected:
            raise ValueError("authority symbol parameter shadow")
        for node in ast.walk(function):
            names: set[str] = set()
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                targets = [node.target] if not isinstance(node, ast.Assign) else node.targets
                names.update(*( _binding_names(target) for target in targets))
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                names.update(_binding_names(node.target))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                names.update(*(
                    _binding_names(item.optional_vars) for item in node.items if item.optional_vars is not None
                ), set())
            elif isinstance(node, ast.ExceptHandler) and node.name is not None:
                names.add(node.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not function:
                names.add(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                names.update(alias.asname or alias.name for alias in node.names)
            if names & protected:
                raise ValueError("authority symbol local shadow")


def _module_name(path: str) -> str:
    normalized = path.replace("\\", "/")
    if normalized.endswith(".py"):
        normalized = normalized[:-3]
    return normalized.strip("/").replace("/", ".")


def _resolve_target(
    module: str,
    target: str,
    functions: dict[GraphKey, ast.FunctionDef | ast.AsyncFunctionDef],
    imports: dict[str, dict[str, GraphKey]],
) -> tuple[GraphKey | None, str]:
    if "." not in target:
        imported = imports.get(module, {}).get(target)
        if imported is not None:
            return (imported if imported in functions else None), imported[1]
        local = (module, target)
        return (local if local in functions else None), target
    owner, leaf = target.rsplit(".", 1)
    imported_owner = imports.get(module, {}).get(owner)
    target_module = imported_owner[0] if imported_owner is not None and imported_owner[1] == "" else owner
    key = (target_module, leaf)
    return (key if key in functions else None), leaf


def _function_paths(
    key: GraphKey,
    functions: dict[GraphKey, ast.FunctionDef | ast.AsyncFunctionDef],
    imports: dict[str, dict[str, GraphKey]],
    active: frozenset[GraphKey],
) -> list[tuple[str, ...]]:
    if key in active:
        raise ValueError("recursive resume graph")
    return _statement_paths(functions[key].body, key[0], functions, imports, active | {key})


def _call_paths(
    call: ast.Call,
    module: str,
    functions: dict[GraphKey, ast.FunctionDef | ast.AsyncFunctionDef],
    imports: dict[str, dict[str, GraphKey]],
    active: frozenset[GraphKey],
) -> list[tuple[str, ...]]:
    paths = _expression_paths(call.func, module, functions, imports, active)
    for argument in call.args:
        paths = _combine(paths, _expression_paths(argument, module, functions, imports, active))
    for keyword in call.keywords:
        paths = _combine(paths, _expression_paths(keyword.value, module, functions, imports, active))
    target = _call_name(call.func)
    if target is None:
        raise ValueError("unresolved indirect call")
    function_key, leaf = _resolve_target(module, target, functions, imports)
    if leaf in _REFLECTION:
        raise ValueError("reflection")
    if leaf == _DOMINATOR:
        if function_key is None:
            raise ValueError("unresolved D2/S2 dominator body")
        body_paths = _function_paths(function_key, functions, imports, active)
        if not body_paths or any(path != ("d2_extend", "s2_read") for path in body_paths):
            raise ValueError("dominator body does not prove ordered D2 extend then S2 read")
        return _combine(paths, [path + ("dominator",) for path in body_paths])
    if leaf in _EVENTS:
        return _combine(paths, [(_EVENTS[leaf],)])
    if function_key is not None:
        return _combine(paths, _function_paths(function_key, functions, imports, active))
    if any(token in leaf.casefold() for token in ("resume", "evidence")):
        raise ValueError("unknown resume call")
    return paths


def _expression_paths(
    expression: ast.expr | None,
    module: str,
    functions: dict[GraphKey, ast.FunctionDef | ast.AsyncFunctionDef],
    imports: dict[str, dict[str, GraphKey]],
    active: frozenset[GraphKey],
) -> list[tuple[str, ...]]:
    if expression is None:
        return [()]
    if isinstance(expression, ast.Call):
        return _call_paths(expression, module, functions, imports, active)
    if isinstance(expression, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        if any(isinstance(node, ast.Call) for node in ast.walk(expression)):
            raise ValueError("resume call in deferred or dynamic expression")
        return [()]
    if isinstance(expression, (ast.BoolOp, ast.IfExp)):
        if any(isinstance(node, ast.Call) for node in ast.walk(expression)):
            raise ValueError("resume call in short-circuit expression")
        return [()]
    if any(isinstance(node, ast.Call) for node in ast.walk(expression)):
        raise ValueError("resume call in unsupported composite expression")
    paths: list[tuple[str, ...]] = [()]
    for child in ast.iter_child_nodes(expression):
        if isinstance(child, ast.expr):
            paths = _combine(paths, _expression_paths(child, module, functions, imports, active))
    return paths


def _statement_expressions(statement: ast.stmt) -> tuple[ast.expr, ...]:
    if isinstance(statement, ast.Expr):
        return (statement.value,)
    if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        value = statement.value
        targets = (
            (statement.target,) if isinstance(statement, (ast.AnnAssign, ast.AugAssign))
            else tuple(statement.targets)
        )
        return (value, *targets)
    if isinstance(statement, ast.Assert):
        return tuple(item for item in (statement.test, statement.msg) if item is not None)
    if isinstance(statement, ast.Delete):
        return tuple(statement.targets)
    return tuple(child for child in ast.iter_child_nodes(statement) if isinstance(child, ast.expr))


def _statement_flow(
    statements: list[ast.stmt],
    module: str,
    functions: dict[GraphKey, ast.FunctionDef | ast.AsyncFunctionDef],
    imports: dict[str, dict[str, GraphKey]],
    active: frozenset[GraphKey],
) -> list[tuple[tuple[str, ...], bool]]:
    flows: list[tuple[tuple[str, ...], bool]] = [((), True)]
    for statement in statements:
        branches: list[tuple[tuple[str, ...], bool]]
        if isinstance(statement, ast.If):
            tests = _expression_paths(statement.test, module, functions, imports, active)
            arms = (
                _statement_flow(statement.body, module, functions, imports, active)
                + _statement_flow(statement.orelse, module, functions, imports, active)
            )
            branches = [(test + branch, live) for test in tests for branch, live in arms]
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While, ast.Try, ast.Match, ast.With, ast.AsyncWith)):
            raise ValueError("non-static control flow in resume graph")
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            raise ValueError("nested definition in resume graph")
        else:
            paths: list[tuple[str, ...]] = [()]
            for expression in _statement_expressions(statement):
                paths = _combine(paths, _expression_paths(expression, module, functions, imports, active))
            branches = [
                (path, not isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)))
                for path in paths
            ]
        advanced: list[tuple[tuple[str, ...], bool]] = []
        for prefix, reachable in flows:
            if not reachable:
                advanced.append((prefix, False))
                continue
            advanced.extend((prefix + suffix, remains_reachable) for suffix, remains_reachable in branches)
        flows = advanced
    return flows


def _statement_paths(
    statements: list[ast.stmt],
    module: str,
    functions: dict[GraphKey, ast.FunctionDef | ast.AsyncFunctionDef],
    imports: dict[str, dict[str, GraphKey]],
    active: frozenset[GraphKey],
) -> list[tuple[str, ...]]:
    return [path for path, _reachable in _statement_flow(statements, module, functions, imports, active)]


def analyze_source_corpus(sources: dict[str, str], mode: str) -> tuple[tuple[str, ...], ...]:
    if type(sources) is not dict or mode not in ("declared_unissuable", "production_enforced"):
        raise ValueError("source oracle input")
    functions: dict[GraphKey, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    imports: dict[str, dict[str, GraphKey]] = {}
    trees: dict[str, ast.Module] = {}
    for path, source in sources.items():
        if type(path) is not str or type(source) is not str:
            raise ValueError("source member")
        tree = ast.parse(source, filename=path)
        module = _module_name(path)
        if module in trees:
            raise ValueError("duplicate source module")
        trees[module] = tree
        module_imports: dict[str, GraphKey] = {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                if node.module is None or node.level:
                    raise ValueError("relative resume import")
                for alias in node.names:
                    if alias.name == "*":
                        raise ValueError("star import")
                    local = alias.asname or alias.name
                    if local in module_imports:
                        raise ValueError("duplicate import binding")
                    module_imports[local] = (node.module, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name
                    if local in module_imports:
                        raise ValueError("duplicate import binding")
                    module_imports[local] = (alias.name, "")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key = (module, node.name)
                if key in functions:
                    raise ValueError("duplicate resume-graph function")
                functions[key] = node
        imports[module] = module_imports
        _validate_lexical_graph_bindings(module, tree, module_imports)

    root_keys = tuple(key for key in functions if key[1] == _ROOT)
    total_events: list[str] = []
    for module, tree in trees.items():
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        evidence_variables: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if (
                    isinstance(value, ast.Call)
                    and _resolve_target(module, _call_name(value.func) or "", functions, imports)[1]
                    == "Stage2ResumeEvidenceV3"
                ):
                    targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
                    for target in targets:
                        if not isinstance(target, ast.Name):
                            raise ValueError("evidence alias escape")
                        evidence_variables.add(target.id)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
                raise ValueError("star import")
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                values = [node.value] if isinstance(node, ast.AnnAssign) else [node.value, *node.targets]
                leaves = {
                    _resolve_target(module, _call_name(value) or "", functions, imports)[1]
                    for value in values if isinstance(value, ast.expr)
                }
                if any(leaf in (*_EVENTS, _DOMINATOR) for leaf in leaves):
                    raise ValueError("resume alias escape")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == _ROOT and any(argument.arg in {"evidence", "resume_evidence"} for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)):
                    raise ValueError("public evidence entry")
                for default in (*node.args.defaults, *(item for item in node.args.kw_defaults if item is not None)):
                    if any(
                        _resolve_target(module, _call_name(item) or "", functions, imports)[1]
                        in (*_EVENTS, _DOMINATOR)
                        for item in ast.walk(default) if isinstance(item, (ast.Name, ast.Attribute))
                    ):
                        raise ValueError("closure/default authority capture")
            if isinstance(node, ast.Call):
                target = _call_name(node.func)
                if target is None:
                    continue
                _key, leaf = _resolve_target(module, target, functions, imports)
                if leaf in _EVENTS:
                    total_events.append(_EVENTS[leaf])
            if mode == "production_enforced" and isinstance(node, (ast.Name, ast.Attribute)):
                _key, leaf = _resolve_target(module, _call_name(node) or "", functions, imports)
                parent = parents.get(node)
                if leaf in (*_EVENTS, _DOMINATOR) and not (isinstance(parent, ast.Call) and parent.func is node):
                    if not (isinstance(parent, ast.Attribute) and parents.get(parent) is not None):
                        raise ValueError("callback/registry/re-export authority escape")
            if mode == "production_enforced" and isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in evidence_variables:
                parent = parents.get(node)
                if not isinstance(parent, ast.Call) or (_call_name(parent.func) or "").split(".")[-1] not in {
                    "_resume_boot_transition_from_consumed_v3", "Stage2ResumeEngineV3",
                }:
                    raise ValueError("evidence return/serialization/registration")
    if mode == "declared_unissuable":
        if root_keys or total_events:
            raise ValueError("resume path is issuable")
        return ()
    if len(root_keys) != 1:
        raise ValueError("production root census")
    if total_events.count("prepare") != 1 or total_events.count("helper") != 1:
        raise ValueError("constructor/helper cardinality")
    if tuple(event for event in total_events if event in _SINK_EVENTS) != ("evidence", "helper", "engine"):
        raise ValueError("authorization sink denominator")
    paths = tuple(_function_paths(root_keys[0], functions, imports, frozenset()))
    if not paths or any(path != _EXPECTED_PATH for path in paths):
        raise ValueError("D2/S2 dominance or ordered causal prefix")
    return paths


def verify_closed_source_witness(table_source: str, ordinary_test_source: str) -> None:
    if type(table_source) is not str or type(ordinary_test_source) is not str:
        raise ValueError("source witness")
    for operation in OPERATION_IDS:
        if table_source.count('"' + operation + '"') != 1:
            raise ValueError("operation declaration closure")
        if ordinary_test_source.count("test_" + operation) != 1:
            raise ValueError("ordinary test closure")


def mutate_input_byte(value: Inputs, coordinate: tuple[str, int, int | None]) -> Inputs:
    field, index, nested = coordinate
    if field == "authority_inputs":
        rows = list(value.authority_inputs)
        member = bytearray(rows[index])
        assert nested is not None
        member[nested] ^= 1
        rows[index] = bytes(member)
        return replace(value, authority_inputs=tuple(rows))
    data = bytearray(getattr(value, field))
    data[index] ^= 1
    return replace(value, **{field: bytes(data)})
