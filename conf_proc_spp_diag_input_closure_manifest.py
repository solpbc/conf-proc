#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Produce, but never appraise, sol-spp-diagbundle-input-closure/v1 without importing conf_proc_spp_diagbundle."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import Final

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_spp_diag_input_closure_manifest_reasons import (
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_CONTROL_PLAN_MISSING,
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_CONTROL_PLAN_PAIRING,
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_FORBIDDEN_PATH,
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_MANDATORY_ROLE,
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_PATH,
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_PATH_ORDER,
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_ROW,
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_ROW_COUNT,
    SppDiagInputClosureManifestError,
)
from conf_proc_spp_diagbundle_protocol import DOMAIN_INPUT_CLOSURE, INPUT_CLOSURE_ROLES, domain_address
from conf_proc_spp_diagbundle_reasons import NODE_ARTIFACT_STATE


INPUT_CLOSURE_SCHEMA_ID: Final = "sol-spp-diagbundle-input-closure/v1"
NODE_KIND_INPUT_CLOSURE: Final = "input_closure"
CONTROL_PLAN_PATH: Final = "control-plan.json"
ROLE_CONTROL_PLAN: Final = "canonical_control_plan"
CONTENT_KINDS: Final = frozenset({"canonical_json", "source", "bytes"})
_INPUT_CLOSURE_ROLE_SET: Final = frozenset(INPUT_CLOSURE_ROLES)
_FORBIDDEN_SUFFIXES: Final = (".key", ".pem", ".p12", ".pfx", ".jks")
_FORBIDDEN_BASENAMES: Final = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})


@dataclass(frozen=True)
class InputClosureInputRow:
    path: str
    role: str
    content_kind: str
    size_bytes: int
    sha256: str


def build_input_closure_manifest(rows: tuple[InputClosureInputRow, ...]) -> bytes:
    """Build a canonical input-closure manifest accepted by the independent appraiser."""

    if type(rows) is not tuple or not rows:
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_ROW_COUNT)
    for row in rows:
        _validate_row(row)
    ordered_rows = tuple(sorted(rows, key=lambda row: row.path))
    if any(ordered_rows[index].path == ordered_rows[index - 1].path for index in range(1, len(ordered_rows))):
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_PATH_ORDER)
    _require_control_plan(ordered_rows)
    if not _INPUT_CLOSURE_ROLE_SET <= {row.role for row in ordered_rows}:
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_MANDATORY_ROLE)
    return canonical_dumps(
        {
            "schema": INPUT_CLOSURE_SCHEMA_ID,
            "node_kind": NODE_KIND_INPUT_CLOSURE,
            "artifact_state": NODE_ARTIFACT_STATE,
            "inventory": [_row_object(row) for row in ordered_rows],
        }
    )


def input_closure_address(manifest_bytes: bytes) -> str:
    """Derive the protocol address from canonical manifest bytes without semantic appraisal."""

    return domain_address(DOMAIN_INPUT_CLOSURE, canonical_loads(manifest_bytes))


def _validate_row(row: object) -> None:
    if type(row) is not InputClosureInputRow:
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_ROW)
    if not _is_relative_path(row.path):
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_PATH)
    if _is_forbidden_path(row.path):
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_FORBIDDEN_PATH)
    if type(row.role) is not str or row.role not in _INPUT_CLOSURE_ROLE_SET:
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_ROW)
    if type(row.content_kind) is not str or row.content_kind not in CONTENT_KINDS:
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_ROW)
    if type(row.size_bytes) is not int or row.size_bytes < 0:
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_ROW)
    if not _is_sha256(row.sha256):
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_ROW)


def _require_control_plan(rows: tuple[InputClosureInputRow, ...]) -> None:
    control_rows = tuple(row for row in rows if row.role == ROLE_CONTROL_PLAN)
    plan_rows = tuple(row for row in rows if row.path == CONTROL_PLAN_PATH)
    if not control_rows and not plan_rows:
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_CONTROL_PLAN_MISSING)
    if len(control_rows) != 1 or len(plan_rows) != 1:
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_CONTROL_PLAN_PAIRING)
    if control_rows[0].path != CONTROL_PLAN_PATH or plan_rows[0].role != ROLE_CONTROL_PLAN:
        _fail(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_CONTROL_PLAN_PAIRING)


def _row_object(row: InputClosureInputRow) -> dict:
    return {
        "path": row.path,
        "role": row.role,
        "content_kind": row.content_kind,
        "size_bytes": row.size_bytes,
        "sha256": row.sha256,
    }


def _is_relative_path(path: object) -> bool:
    if type(path) is not str or not path or path.startswith("/") or "\x00" in path:
        return False
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    return posixpath.normpath(path) == path


def _is_forbidden_path(path: str) -> bool:
    base = posixpath.basename(path).lower()
    return any(base.endswith(suffix) for suffix in _FORBIDDEN_SUFFIXES) or base in _FORBIDDEN_BASENAMES


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and value == value.lower() and all(c in "0123456789abcdef" for c in value)


def _fail(reason_code: str) -> None:
    raise SppDiagInputClosureManifestError(reason_code)
