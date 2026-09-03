#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Contract tests for producer-side diagnostic input-closure manifests."""

from __future__ import annotations

import ast
import hashlib
import sys
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import conf_proc_spp_diag_input_closure_manifest as producer  # noqa: E402
import conf_proc_spp_diagbundle as appraiser  # noqa: E402
from conf_proc_json import canonical_dumps, canonical_loads  # noqa: E402
from conf_proc_spp_diag_input_closure_manifest_reasons import (  # noqa: E402
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_CONTROL_PLAN_MISSING,
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_CONTROL_PLAN_PAIRING,
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_FORBIDDEN_PATH,
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_PATH,
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_PATH_ORDER,
    CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_ROW_COUNT,
    SppDiagInputClosureManifestError,
)
from conf_proc_spp_diagbundle_protocol import DOMAIN_INPUT_CLOSURE, INPUT_CLOSURE_ROLES  # noqa: E402


def _row(path: str, role: str, index: int, content_kind: str = "source") -> producer.InputClosureInputRow:
    return producer.InputClosureInputRow(
        path=path,
        role=role,
        content_kind=content_kind,
        size_bytes=index,
        sha256=f"{index:064x}",
    )


def _valid_rows() -> tuple[producer.InputClosureInputRow, ...]:
    rows = [_row("control-plan.json", producer.ROLE_CONTROL_PLAN, 0, "canonical_json")]
    for index, role in enumerate(INPUT_CLOSURE_ROLES, start=1):
        if role != producer.ROLE_CONTROL_PLAN:
            rows.append(_row(f"sources/{index:02d}-{role}.txt", role, index))
    rows.append(_row("sources/99-extra-source.txt", "source_tree_manifest", 99))
    return tuple(rows)


def _expect(reason_code: str, rows: tuple[producer.InputClosureInputRow, ...]) -> None:
    try:
        producer.build_input_closure_manifest(rows)
    except SppDiagInputClosureManifestError as exc:
        assert exc.reason_code == reason_code
    else:
        raise AssertionError(f"expected {reason_code}")


def _row_object(row: producer.InputClosureInputRow) -> dict:
    return {
        "path": row.path,
        "role": row.role,
        "content_kind": row.content_kind,
        "size_bytes": row.size_bytes,
        "sha256": row.sha256,
    }


def test_builds_sorted_canonical_manifest_accepted_by_appraiser() -> None:
    rows = _valid_rows()
    manifest = producer.build_input_closure_manifest(tuple(reversed(rows)))
    parsed = canonical_loads(manifest)
    assert canonical_dumps(parsed) == manifest
    assert [row["path"] for row in parsed["inventory"]] == sorted(row.path for row in rows)
    appraiser.parse_input_closure_manifest(manifest)


def test_missing_each_mandatory_role_rejects() -> None:
    rows = _valid_rows()
    for role in INPUT_CLOSURE_ROLES:
        reduced = tuple(row for row in rows if row.role != role)
        try:
            producer.build_input_closure_manifest(reduced)
        except SppDiagInputClosureManifestError:
            pass
        else:
            raise AssertionError(f"missing mandatory role accepted: {role}")


def test_path_and_control_plan_constraints() -> None:
    rows = _valid_rows()
    _expect(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_ROW_COUNT, ())
    _expect(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_PATH_ORDER, rows + (_row(rows[-1].path, "build_recipe", 100),))
    _expect(
        CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_CONTROL_PLAN_MISSING,
        tuple(row for row in rows if row.path != producer.CONTROL_PLAN_PATH),
    )
    _expect(
        CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_CONTROL_PLAN_PAIRING,
        rows + (_row("sources/98-second-control.txt", producer.ROLE_CONTROL_PLAN, 98),),
    )
    control_index = next(index for index, row in enumerate(rows) if row.path == producer.CONTROL_PLAN_PATH)
    misplaced = list(rows)
    misplaced[control_index] = replace(misplaced[control_index], role="source_tree_manifest")
    _expect(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_CONTROL_PLAN_PAIRING, tuple(misplaced))


def test_bad_and_forbidden_paths_reject() -> None:
    rows = _valid_rows()
    index = next(index for index, row in enumerate(rows) if row.role == "source_tree_manifest")
    for path in ("/absolute", "sources/../escape", ""):
        bad = list(rows)
        bad[index] = replace(bad[index], path=path)
        _expect(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_PATH, tuple(bad))
    forbidden = list(rows)
    forbidden[index] = replace(forbidden[index], path="sources/private.key")
    _expect(CP_SPP_DIAG_INPUT_CLOSURE_MANIFEST_FORBIDDEN_PATH, tuple(forbidden))


def test_address_matches_independent_manifest_shape() -> None:
    rows = _valid_rows()
    manifest = producer.build_input_closure_manifest(rows)
    expected_object = {
        "schema": "sol-spp-diagbundle-input-closure/v1",
        "node_kind": "input_closure",
        "artifact_state": "diagnostic_unqualified",
        "inventory": [_row_object(row) for row in sorted(rows, key=lambda row: row.path)],
    }
    expected = hashlib.sha256(DOMAIN_INPUT_CLOSURE + canonical_dumps(expected_object)).hexdigest()
    assert manifest == canonical_dumps(expected_object)
    assert producer.input_closure_address(manifest) == expected


def test_producer_does_not_import_appraiser() -> None:
    source = (ROOT / "conf_proc_spp_diag_input_closure_manifest.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imports = (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports = (node.module or "",)
        else:
            continue
        assert all(name != "conf_proc_spp_diagbundle" for name in imports)


TESTS = (
    test_builds_sorted_canonical_manifest_accepted_by_appraiser,
    test_missing_each_mandatory_role_rejects,
    test_path_and_control_plan_constraints,
    test_bad_and_forbidden_paths_reject,
    test_address_matches_independent_manifest_shape,
    test_producer_does_not_import_appraiser,
)


def main() -> None:
    for test in TESTS:
        test()
    print("SPP diagnostic input-closure manifest producer: ok (%d tests)" % len(TESTS))


if __name__ == "__main__":
    main()
