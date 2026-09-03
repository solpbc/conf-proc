#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Schema for conf-proc-spp-diag-trace-core-manifest/v1."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from conf_proc_json import canonical_loads
from conf_proc_reasons import ApplianceError
from conf_proc_spp_diag_trace_core_materialize_reasons import (
    CP_SPP_DIAG_TRACE_CORE_SCHEMA,
    CP_SPP_DIAG_TRACE_CORE_TYPE,
    SppDiagTraceCoreMaterializeError,
)

MANIFEST_SCHEMA_ID: Final = "conf-proc-spp-diag-trace-core-manifest/v1"
MANIFEST_VERSION: Final = 2
SOURCE_PREFIX: Final = "spp-diag-trace-core-src/"
PINNED_BASE_COMMIT: Final = "91a8e826012fbb1c7f5cb2a326c08b13e390f469"
CREATE_DESTINATIONS: Final = (
    "security/spp_diag_trace_core/Kconfig", "security/spp_diag_trace_core/Makefile",
    "security/spp_diag_trace_core/core.c", "security/spp_diag_trace_core/core.h",
    "security/spp_diag_trace_core/core_kunit.c", "security/spp_diag_trace_core/protocol_constants.h",
    "security/spp_diag_trace_core/bootstrap.c", "security/spp_diag_trace_core/gate.c",
    "security/spp_diag_trace_core/release.c", "security/spp_diag_trace_core/bootstrap_kunit.c",
    "include/linux/spp_diag_trace_bootstrap.h",
    "security/spp_diag_trace_core/runtime_redirect.h", "security/spp_diag_trace_core/runtime_types.h",
    "security/spp_diag_trace_core/runtime_state.c", "security/spp_diag_trace_core/runtime_fs.c",
    "security/spp_diag_trace_core/runtime_kunit.c",
    "include/linux/spp_diag_trace_runtime.h",
    "include/linux/spp_diag_trace_adapter.h",
    "security/spp_diag_trace_core/adapter.c",
)
REPLACE_MAKEFILE_LINE: Final = "obj-$(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE) += spp_diag_trace_core/"
REPLACE_KCONFIG_LINE: Final = 'source "security/spp_diag_trace_core/Kconfig"'
REPLACE_DESTINATIONS: Final = (
    "security/Makefile", "security/Kconfig", "security/security.c", "security/security.c",
    "security/security.c", "security/integrity/ima/ima_init.c",
    "security/integrity/ima/ima_init.c", "init/main.c", "init/main.c",
    "security/security.c", "security/security.c", "security/security.c",
    "fs/exec.c", "fs/exec.c", "fs/exec.c", "fs/exec.c",
    "kernel/fork.c", "kernel/fork.c", "kernel/fork.c", "kernel/exit.c", "kernel/exit.c",
    "fs/open.c", "fs/open.c", "fs/open.c",
    "mm/util.c", "mm/util.c", "mm/mmap.c", "mm/mmap.c",
    "ipc/shm.c", "ipc/shm.c", "mm/mprotect.c", "mm/mprotect.c",
    "net/socket.c", "net/socket.c", "net/socket.c", "net/socket.c",
    "net/socket.c", "net/socket.c",
)
CORE_API_SYMBOLS: Final = (
    "spp_diag_trace_core_init", "spp_diag_trace_core_is_green",
    "spp_diag_trace_core_append", "spp_diag_trace_core_mark_failure",
)
BOOTSTRAP_API_SYMBOLS: Final = (
    "spp_diag_trace_bootstrap_init", "spp_diag_trace_bootstrap_bprm_check",
    "spp_diag_trace_bootstrap_ima_ready", "spp_diag_trace_bootstrap_release",
)
RUNTIME_API_SYMBOLS: Final = (
    "spp_diag_trace_core_runtime_bind_root",
    "spp_diag_trace_core_runtime_task_alloc_attempt",
    "spp_diag_trace_core_runtime_task_created",
    "spp_diag_trace_core_runtime_task_exit",
    "spp_diag_trace_core_runtime_exec_attempt",
    "spp_diag_trace_core_runtime_exec_commit",
    "spp_diag_trace_core_runtime_exec_reserve",
    "spp_diag_trace_core_runtime_exec_pass",
    "spp_diag_trace_core_runtime_exec_active_operation",
    "spp_diag_trace_core_runtime_exec_return",
    "spp_diag_trace_core_runtime_exec_unsupported",
    "spp_diag_trace_core_runtime_file_open_attempt",
    "spp_diag_trace_core_runtime_file_policy_decision",
    "spp_diag_trace_core_runtime_file_gate_observation",
    "spp_diag_trace_core_runtime_mapping_policy_decision",
    "spp_diag_trace_core_runtime_network_policy_decision",
    "spp_diag_trace_core_runtime_operation_return",
    "spp_diag_trace_core_runtime_operation_return_raw",
    "spp_diag_trace_core_runtime_file_open_return",
    "spp_diag_trace_core_runtime_file_open_active_operation",
    "spp_diag_trace_core_runtime_mmap_active_operation",
    "spp_diag_trace_core_runtime_mprotect_active_operation",
    "spp_diag_trace_core_runtime_connect_active_operation",
    "spp_diag_trace_core_runtime_sendmsg_active_operation",
    "spp_diag_trace_core_runtime_mapping_unsupported",
    "spp_diag_trace_core_runtime_network_unsupported",
    "spp_diag_trace_core_runtime_operation_unsupported",
    "spp_diag_trace_core_runtime_handle_command",
    "spp_diag_trace_core_runtime_stream_read",
    "spp_diag_trace_core_runtime_is_sealed",
)

_TOP_KEYS: Final = frozenset({"schema", "manifest_version", "expected_base_commit", "core_api_symbols", "protocol_authority", "diagnostic_config_fragments", "inputs", "targets"})
_AUTHORITY_KEYS: Final = frozenset({"header", "header_sha256", "source", "source_sha256"})
_FRAGMENT_KEYS: Final = frozenset({"leg", "path", "sha256"})
_INPUT_KEYS: Final = frozenset({"path", "sha256", "mode"})
_CREATE_KEYS: Final = frozenset({"kind", "destination", "source", "mode", "sha256"})
_EOF_REPLACE_KEYS: Final = frozenset({"kind", "destination", "anchor_line", "placement", "preimage_mode", "preimage_sha256", "postimage_mode", "postimage_sha256"})
_ANCHOR_REPLACE_KEYS: Final = frozenset({"kind", "destination", "anchor", "insertion", "placement", "preimage_mode", "preimage_sha256", "postimage_mode", "postimage_sha256"})


@dataclass(frozen=True)
class AuthorityBlobs:
    header: str
    header_sha256: str
    source: str
    source_sha256: str


@dataclass(frozen=True)
class InputBlob:
    path: str
    sha256: str
    mode: int


@dataclass(frozen=True)
class FragmentBlob:
    leg: str
    path: str
    sha256: str


@dataclass(frozen=True)
class CreateTarget:
    destination: str
    source: str
    mode: int
    sha256: str


@dataclass(frozen=True)
class ReplaceTarget:
    destination: str
    anchor_line: str
    placement: str
    insertion: str
    preimage_mode: int
    preimage_sha256: str
    postimage_mode: int
    postimage_sha256: str


@dataclass(frozen=True)
class CoreManifest:
    expected_base_commit: str
    core_api_symbols: tuple[str, ...]
    protocol_authority: AuthorityBlobs
    diagnostic_config_fragments: tuple[FragmentBlob, FragmentBlob, FragmentBlob]
    inputs: tuple[InputBlob, ...]
    creates: tuple[CreateTarget, ...]
    replaces: tuple[ReplaceTarget, ...]
    raw: dict


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and value == value.lower() and all(c in "0123456789abcdef" for c in value)


def _is_commit(value: str) -> bool:
    return len(value) == 40 and value == value.lower() and all(c in "0123456789abcdef" for c in value)


def _require(condition: bool, reason_code: str, message: str) -> None:
    if not condition:
        raise SppDiagTraceCoreMaterializeError(reason_code, message)


def _parse_input(raw: object) -> InputBlob:
    _require(type(raw) is dict and set(raw) == _INPUT_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "input entry has unexpected fields")
    _require(type(raw["path"]) is str and raw["path"], CP_SPP_DIAG_TRACE_CORE_TYPE, "input path must be a nonempty string")
    _require(_is_sha256(raw["sha256"]), CP_SPP_DIAG_TRACE_CORE_TYPE, "input sha256 must be 64 lowercase hex characters")
    _require(type(raw["mode"]) is int and 0 <= raw["mode"] <= 0o7777, CP_SPP_DIAG_TRACE_CORE_TYPE, "input mode must be an integer permission")
    return InputBlob(raw["path"], raw["sha256"], raw["mode"])


def parse_core_manifest(data: bytes) -> CoreManifest:
    try:
        raw = canonical_loads(data)
    except ApplianceError as exc:
        raise SppDiagTraceCoreMaterializeError(CP_SPP_DIAG_TRACE_CORE_SCHEMA, f"manifest JSON is not canonical: {exc}") from exc
    _require(type(raw) is dict, CP_SPP_DIAG_TRACE_CORE_TYPE, "manifest must be a JSON object")
    _require(set(raw) == _TOP_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "manifest has unexpected top-level fields")
    _require(raw["schema"] == MANIFEST_SCHEMA_ID, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "unexpected manifest schema identifier")
    _require(raw["manifest_version"] == MANIFEST_VERSION, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "unexpected manifest version")
    _require(type(raw["expected_base_commit"]) is str and _is_commit(raw["expected_base_commit"]), CP_SPP_DIAG_TRACE_CORE_TYPE, "expected_base_commit must be 40 lowercase hex characters")
    _require(type(raw["core_api_symbols"]) is list and tuple(raw["core_api_symbols"]) == CORE_API_SYMBOLS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "core_api_symbols must declare the four production APIs in order")

    authority_raw = raw["protocol_authority"]
    _require(type(authority_raw) is dict and set(authority_raw) == _AUTHORITY_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "protocol_authority has unexpected fields")
    for key in ("header", "source"):
        _require(type(authority_raw[key]) is str and authority_raw[key], CP_SPP_DIAG_TRACE_CORE_TYPE, f"protocol_authority.{key} must be a nonempty string")
    for key in ("header_sha256", "source_sha256"):
        _require(_is_sha256(authority_raw[key]), CP_SPP_DIAG_TRACE_CORE_TYPE, f"protocol_authority.{key} must be 64 lowercase hex characters")
    authority = AuthorityBlobs(**authority_raw)

    fragments_raw = raw["diagnostic_config_fragments"]
    _require(type(fragments_raw) is list and len(fragments_raw) == 3, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "exactly enabled, disabled, and runtime fragments are required")
    fragments: list[FragmentBlob] = []
    for item in fragments_raw:
        _require(type(item) is dict and set(item) == _FRAGMENT_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "fragment entry has unexpected fields")
        _require(item["leg"] in ("enabled", "disabled", "runtime"), CP_SPP_DIAG_TRACE_CORE_SCHEMA, "fragment leg must be enabled, disabled, or runtime")
        _require(type(item["path"]) is str and item["path"] and _is_sha256(item["sha256"]), CP_SPP_DIAG_TRACE_CORE_TYPE, "fragment path and digest are invalid")
        fragments.append(FragmentBlob(item["leg"], item["path"], item["sha256"]))
    _require(tuple(item.leg for item in fragments) == ("enabled", "disabled", "runtime"), CP_SPP_DIAG_TRACE_CORE_SCHEMA, "fragment legs must be enabled, disabled, then runtime")

    inputs_raw = raw["inputs"]
    _require(type(inputs_raw) is list and inputs_raw, CP_SPP_DIAG_TRACE_CORE_TYPE, "inputs must be a nonempty array")
    inputs = tuple(_parse_input(item) for item in inputs_raw)
    _require(len({item.path for item in inputs}) == len(inputs), CP_SPP_DIAG_TRACE_CORE_SCHEMA, "input paths must be unique")
    _require(all(any(item.path == fragment.path for item in inputs) for fragment in fragments), CP_SPP_DIAG_TRACE_CORE_SCHEMA, "each fragment must be an input")

    creates: list[CreateTarget] = []
    replaces: list[ReplaceTarget] = []
    targets = raw["targets"]
    _require(type(targets) is list and targets, CP_SPP_DIAG_TRACE_CORE_TYPE, "targets must be a nonempty array")
    for entry in targets:
        _require(type(entry) is dict and type(entry.get("kind")) is str, CP_SPP_DIAG_TRACE_CORE_TYPE, "target entry must have a string kind")
        if entry["kind"] == "CREATE":
            _require(set(entry) == _CREATE_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "CREATE target has unexpected fields")
            _require(type(entry["destination"]) is str and entry["destination"], CP_SPP_DIAG_TRACE_CORE_TYPE, "CREATE destination must be a nonempty string")
            _require(type(entry["source"]) is str and entry["source"].startswith(SOURCE_PREFIX), CP_SPP_DIAG_TRACE_CORE_SCHEMA, "CREATE source must be below spp-diag-trace-core-src/")
            _require(entry["destination"] == entry["source"][len(SOURCE_PREFIX):], CP_SPP_DIAG_TRACE_CORE_SCHEMA, "CREATE destination must equal source with the source prefix stripped")
            _require(_is_sha256(entry["sha256"]) and type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o7777, CP_SPP_DIAG_TRACE_CORE_TYPE, "CREATE digest or mode is invalid")
            creates.append(CreateTarget(entry["destination"], entry["source"], entry["mode"], entry["sha256"]))
            continue
        _require(entry["kind"] == "REPLACE", CP_SPP_DIAG_TRACE_CORE_SCHEMA, f"unsupported target kind: {entry['kind']!r}")
        if entry.get("placement") == "eof-append":
            _require(set(entry) == _EOF_REPLACE_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "eof-append REPLACE has unexpected fields")
            anchor, insertion = entry["anchor_line"], ""
        elif entry.get("placement") in ("anchor-insert", "anchor-replace"):
            _require(set(entry) == _ANCHOR_REPLACE_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "anchor REPLACE has unexpected fields")
            anchor, insertion = entry["anchor"], entry["insertion"]
        else:
            _require(False, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "unsupported REPLACE placement")
        _require(type(entry["destination"]) is str and entry["destination"] and type(anchor) is str and anchor and type(insertion) is str, CP_SPP_DIAG_TRACE_CORE_TYPE, "REPLACE destination, anchor, or insertion is invalid")
        _require(all(_is_sha256(entry[key]) for key in ("preimage_sha256", "postimage_sha256")), CP_SPP_DIAG_TRACE_CORE_TYPE, "REPLACE digest is invalid")
        _require(all(type(entry[key]) is int and 0 <= entry[key] <= 0o7777 for key in ("preimage_mode", "postimage_mode")), CP_SPP_DIAG_TRACE_CORE_TYPE, "REPLACE mode is invalid")
        replaces.append(ReplaceTarget(entry["destination"], anchor, entry["placement"], insertion, entry["preimage_mode"], entry["preimage_sha256"], entry["postimage_mode"], entry["postimage_sha256"]))

    _require(tuple(item.destination for item in creates) == CREATE_DESTINATIONS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "CREATE targets must be the closed ordered K1-K4 source set")
    _require(tuple(item.destination for item in replaces) == REPLACE_DESTINATIONS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "REPLACE targets must be the ordered K1-K4 integration set")
    _require(replaces[0].placement == replaces[1].placement == "eof-append", CP_SPP_DIAG_TRACE_CORE_SCHEMA, "top-level security entries must remain eof-append")
    _require(replaces[0].anchor_line == REPLACE_MAKEFILE_LINE and replaces[1].anchor_line == REPLACE_KCONFIG_LINE, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "top-level security anchors mismatch")
    _require(all(item.placement == "anchor-insert" for item in replaces[2:9]), CP_SPP_DIAG_TRACE_CORE_SCHEMA, "K1-K3 kernel callers must use anchor-insert")
    _require(all(item.placement in ("anchor-insert", "anchor-replace") for item in replaces[9:]), CP_SPP_DIAG_TRACE_CORE_SCHEMA, "K4 kernel callers must use an anchor placement")
    return CoreManifest(raw["expected_base_commit"], tuple(raw["core_api_symbols"]), authority, tuple(fragments), inputs, tuple(creates), tuple(replaces), raw)
