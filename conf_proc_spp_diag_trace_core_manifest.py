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
MANIFEST_VERSION: Final = 1
SOURCE_PREFIX: Final = "spp-diag-trace-core-src/"
PINNED_BASE_COMMIT: Final = "91a8e826012fbb1c7f5cb2a326c08b13e390f469"
CREATE_NAMES: Final = (
    "Kconfig",
    "Makefile",
    "core.c",
    "core.h",
    "core_kunit.c",
    "protocol_constants.h",
)
REPLACE_MAKEFILE_LINE: Final = (
    "obj-$(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE) += spp_diag_trace_core/"
)
REPLACE_KCONFIG_LINE: Final = 'source "security/spp_diag_trace_core/Kconfig"'
CORE_API_SYMBOLS: Final = (
    "spp_diag_trace_core_init",
    "spp_diag_trace_core_is_green",
    "spp_diag_trace_core_append",
    "spp_diag_trace_core_mark_failure",
)

_TOP_KEYS: Final = frozenset(
    {
        "schema",
        "manifest_version",
        "expected_base_commit",
        "core_api_symbols",
        "protocol_authority",
        "diagnostic_config_fragment",
        "inputs",
        "targets",
    }
)
_AUTHORITY_KEYS: Final = frozenset({"header", "header_sha256", "source", "source_sha256"})
_FRAGMENT_KEYS: Final = frozenset({"path", "sha256"})
_INPUT_KEYS: Final = frozenset({"path", "sha256", "mode"})
_CREATE_KEYS: Final = frozenset({"kind", "destination", "source", "mode", "sha256"})
_REPLACE_KEYS: Final = frozenset(
    {
        "kind",
        "destination",
        "anchor_line",
        "placement",
        "preimage_mode",
        "preimage_sha256",
        "postimage_mode",
        "postimage_sha256",
    }
)


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
    preimage_mode: int
    preimage_sha256: str
    postimage_mode: int
    postimage_sha256: str


@dataclass(frozen=True)
class CoreManifest:
    expected_base_commit: str
    core_api_symbols: tuple[str, ...]
    protocol_authority: AuthorityBlobs
    diagnostic_config_fragment: InputBlob
    inputs: tuple[InputBlob, ...]
    creates: tuple[CreateTarget, ...]
    replaces: tuple[ReplaceTarget, ...]
    raw: dict


def parse_core_manifest(data: bytes) -> CoreManifest:
    try:
        raw = canonical_loads(data)
    except ApplianceError as exc:
        raise SppDiagTraceCoreMaterializeError(
            CP_SPP_DIAG_TRACE_CORE_SCHEMA, f"manifest JSON is not canonical: {exc}"
        ) from exc
    _require(type(raw) is dict, CP_SPP_DIAG_TRACE_CORE_TYPE, "manifest must be a JSON object")
    _require(set(raw) == _TOP_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "manifest has unexpected top-level fields")
    _require(raw["schema"] == MANIFEST_SCHEMA_ID, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "unexpected manifest schema identifier")
    _require(
        raw["manifest_version"] == MANIFEST_VERSION,
        CP_SPP_DIAG_TRACE_CORE_SCHEMA,
        "unexpected manifest version",
    )
    _require(
        type(raw["expected_base_commit"]) is str and _is_commit(raw["expected_base_commit"]),
        CP_SPP_DIAG_TRACE_CORE_TYPE,
        "expected_base_commit must be 40 lowercase hex characters",
    )
    _require(
        type(raw["core_api_symbols"]) is list
        and tuple(raw["core_api_symbols"]) == CORE_API_SYMBOLS,
        CP_SPP_DIAG_TRACE_CORE_SCHEMA,
        "core_api_symbols must declare the four production APIs in order",
    )

    authority_raw = raw["protocol_authority"]
    _require(type(authority_raw) is dict and set(authority_raw) == _AUTHORITY_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "protocol_authority has unexpected fields")
    _require(type(authority_raw["header"]) is str and authority_raw["header"], CP_SPP_DIAG_TRACE_CORE_TYPE, "protocol_authority.header must be a nonempty string")
    _require(_is_sha256(authority_raw["header_sha256"]), CP_SPP_DIAG_TRACE_CORE_TYPE, "protocol_authority.header_sha256 must be 64 lowercase hex characters")
    _require(type(authority_raw["source"]) is str and authority_raw["source"], CP_SPP_DIAG_TRACE_CORE_TYPE, "protocol_authority.source must be a nonempty string")
    _require(_is_sha256(authority_raw["source_sha256"]), CP_SPP_DIAG_TRACE_CORE_TYPE, "protocol_authority.source_sha256 must be 64 lowercase hex characters")
    authority = AuthorityBlobs(
        header=authority_raw["header"],
        header_sha256=authority_raw["header_sha256"],
        source=authority_raw["source"],
        source_sha256=authority_raw["source_sha256"],
    )

    fragment_raw = raw["diagnostic_config_fragment"]
    _require(type(fragment_raw) is dict and set(fragment_raw) == _FRAGMENT_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "diagnostic_config_fragment has unexpected fields")
    _require(type(fragment_raw["path"]) is str and fragment_raw["path"], CP_SPP_DIAG_TRACE_CORE_TYPE, "diagnostic_config_fragment.path must be a nonempty string")
    _require(_is_sha256(fragment_raw["sha256"]), CP_SPP_DIAG_TRACE_CORE_TYPE, "diagnostic_config_fragment.sha256 must be 64 lowercase hex characters")
    fragment = InputBlob(path=fragment_raw["path"], sha256=fragment_raw["sha256"], mode=0o644)

    raw_inputs = raw["inputs"]
    _require(type(raw_inputs) is list and raw_inputs, CP_SPP_DIAG_TRACE_CORE_TYPE, "inputs must be a nonempty array")
    inputs: list[InputBlob] = []
    for entry in raw_inputs:
        _require(type(entry) is dict and set(entry) == _INPUT_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "input entry has unexpected fields")
        _require(type(entry["path"]) is str and entry["path"], CP_SPP_DIAG_TRACE_CORE_TYPE, "input path must be a nonempty string")
        _require(_is_sha256(entry["sha256"]), CP_SPP_DIAG_TRACE_CORE_TYPE, "input sha256 must be 64 lowercase hex characters")
        _require(type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o7777, CP_SPP_DIAG_TRACE_CORE_TYPE, "input mode must be an integer permission")
        inputs.append(InputBlob(path=entry["path"], sha256=entry["sha256"], mode=entry["mode"]))

    raw_targets = raw["targets"]
    _require(type(raw_targets) is list and raw_targets, CP_SPP_DIAG_TRACE_CORE_TYPE, "targets must be a nonempty array")
    creates: list[CreateTarget] = []
    replaces: list[ReplaceTarget] = []
    for entry in raw_targets:
        _require(type(entry) is dict, CP_SPP_DIAG_TRACE_CORE_TYPE, "target entry must be an object")
        _require(type(entry.get("kind")) is str, CP_SPP_DIAG_TRACE_CORE_TYPE, "target kind must be a string")
        if entry["kind"] == "CREATE":
            _require(set(entry) == _CREATE_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "CREATE target has unexpected fields")
            _require(type(entry["destination"]) is str and entry["destination"], CP_SPP_DIAG_TRACE_CORE_TYPE, "CREATE destination must be a nonempty string")
            _require(type(entry["source"]) is str and entry["source"], CP_SPP_DIAG_TRACE_CORE_TYPE, "CREATE source must be a nonempty string")
            _require(_is_sha256(entry["sha256"]), CP_SPP_DIAG_TRACE_CORE_TYPE, "CREATE sha256 must be 64 lowercase hex characters")
            _require(type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o7777, CP_SPP_DIAG_TRACE_CORE_TYPE, "CREATE mode must be an integer permission")
            _require(
                entry["source"].startswith(SOURCE_PREFIX)
                and entry["destination"] == entry["source"][len(SOURCE_PREFIX) :],
                CP_SPP_DIAG_TRACE_CORE_SCHEMA,
                "CREATE destination must equal source with the spp-diag-trace-core-src/ prefix stripped",
            )
            creates.append(
                CreateTarget(
                    destination=entry["destination"],
                    source=entry["source"],
                    mode=entry["mode"],
                    sha256=entry["sha256"],
                )
            )
        elif entry["kind"] == "REPLACE":
            _require(set(entry) == _REPLACE_KEYS, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "REPLACE target has unexpected fields")
            _require(type(entry["destination"]) is str and entry["destination"], CP_SPP_DIAG_TRACE_CORE_TYPE, "REPLACE destination must be a nonempty string")
            _require(type(entry["anchor_line"]) is str and entry["anchor_line"], CP_SPP_DIAG_TRACE_CORE_TYPE, "REPLACE anchor_line must be a nonempty string")
            _require(entry["placement"] == "eof-append", CP_SPP_DIAG_TRACE_CORE_SCHEMA, "REPLACE placement must be eof-append")
            _require(type(entry["preimage_mode"]) is int and 0 <= entry["preimage_mode"] <= 0o7777, CP_SPP_DIAG_TRACE_CORE_TYPE, "REPLACE preimage_mode must be an integer permission")
            _require(_is_sha256(entry["preimage_sha256"]), CP_SPP_DIAG_TRACE_CORE_TYPE, "REPLACE preimage_sha256 must be 64 lowercase hex characters")
            _require(type(entry["postimage_mode"]) is int and 0 <= entry["postimage_mode"] <= 0o7777, CP_SPP_DIAG_TRACE_CORE_TYPE, "REPLACE postimage_mode must be an integer permission")
            _require(_is_sha256(entry["postimage_sha256"]), CP_SPP_DIAG_TRACE_CORE_TYPE, "REPLACE postimage_sha256 must be 64 lowercase hex characters")
            replaces.append(
                ReplaceTarget(
                    destination=entry["destination"],
                    anchor_line=entry["anchor_line"],
                    placement=entry["placement"],
                    preimage_mode=entry["preimage_mode"],
                    preimage_sha256=entry["preimage_sha256"],
                    postimage_mode=entry["postimage_mode"],
                    postimage_sha256=entry["postimage_sha256"],
                )
            )
        else:
            _require(False, CP_SPP_DIAG_TRACE_CORE_SCHEMA, f"unsupported target kind: {entry['kind']!r}")

    expected_create_dests = tuple(f"security/spp_diag_trace_core/{name}" for name in CREATE_NAMES)
    actual_create_dests = tuple(item.destination for item in creates)
    _require(
        actual_create_dests == expected_create_dests,
        CP_SPP_DIAG_TRACE_CORE_SCHEMA,
        "CREATE targets must be the six kernel core files in order",
    )
    _require(len(replaces) == 2, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "exactly two REPLACE targets are required")
    _require(replaces[0].destination == "security/Makefile", CP_SPP_DIAG_TRACE_CORE_SCHEMA, "first REPLACE destination must be security/Makefile")
    _require(replaces[0].anchor_line == REPLACE_MAKEFILE_LINE, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "Makefile REPLACE anchor_line mismatch")
    _require(replaces[1].destination == "security/Kconfig", CP_SPP_DIAG_TRACE_CORE_SCHEMA, "second REPLACE destination must be security/Kconfig")
    _require(replaces[1].anchor_line == REPLACE_KCONFIG_LINE, CP_SPP_DIAG_TRACE_CORE_SCHEMA, "Kconfig REPLACE anchor_line mismatch")

    return CoreManifest(
        expected_base_commit=raw["expected_base_commit"],
        core_api_symbols=tuple(raw["core_api_symbols"]),
        protocol_authority=authority,
        diagnostic_config_fragment=fragment,
        inputs=tuple(inputs),
        creates=tuple(creates),
        replaces=tuple(replaces),
        raw=raw,
    )


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and value == value.lower() and all(c in "0123456789abcdef" for c in value)


def _is_commit(value: str) -> bool:
    return len(value) == 40 and value == value.lower() and all(c in "0123456789abcdef" for c in value)


def _require(condition: bool, reason_code: str, message: str) -> None:
    if not condition:
        raise SppDiagTraceCoreMaterializeError(reason_code, message)
