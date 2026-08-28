#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Focused schema and builder tests for dormant provenance-v2 SPDX output."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_reasons as reasons  # noqa: E402
from conf_proc_json import canonical_dumps, canonical_loads  # noqa: E402
from conf_proc_lock import BaseImageRecord, Lock, LockInput, Placement  # noqa: E402
from conf_proc_provenance_v2 import ProvenanceInputs  # noqa: E402
from conf_proc_provenance_v2_build_spdx import _build_spdx_v2_bytes  # noqa: E402
from conf_proc_provenance_v2_spdx import parse_spdx_v2  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha(value: int) -> str:
    return format(value, "064x")


def _placement(image: str, path: str, node_type: str, target: str | None = None) -> Placement:
    return Placement(
        image=image,
        path=path,
        node_type=node_type,
        mode=0o644,
        uid=0,
        gid=0,
        xattrs=(),
        source_input_id="input" if node_type == "file" else None,
        target=target,
    )


def _input(input_id: str, role: str, digest: str, placements: tuple[Placement, ...]) -> LockInput:
    return LockInput(
        id=input_id,
        role=role,
        component=f"component-{input_id}",
        sha256=digest,
        size_bytes=1,
        source_local_path=f"fixtures/{input_id}",
        source_retrieval_scheme="local-fixture",
        source_retrieval_identity=f"fixture:{input_id}",
        source_retrieval_immutable_ref=f"sha256:{digest}",
        derivation_kind="fixture",
        derivation_recipe_id="fixture-recipe-v1",
        derivation_parent_ids=(),
        derivation_parameters_sha256=_sha(80),
        placements=placements,
    )


def _lock(inputs: tuple[LockInput, ...] | None = None) -> Lock:
    if inputs is None:
        inputs = (
            _input(
                "build-tool",
                "build_tool",
                _sha(1),
                (
                    _placement("models", "/models/program", "file"),
                    _placement("models", "/models/link", "symlink", "program"),
                    _placement("models", "/models/directory", "directory"),
                ),
            ),
            _input("kernel", "kernel", _sha(2), ()),
        )
    base = BaseImageRecord(
        kind="vhd",
        provider="fixture",
        identity_namespace="fixture",
        identity_name="base",
        identity_immutable_revision="fixture-revision",
        content_sha256=_sha(3),
        content_size_bytes=1,
        content_media_type="application/octet-stream",
        availability="record-only",
        recorded_retrieval_scheme="local-fixture",
        recorded_retrieval_identity="fixture:base",
        recorded_retrieval_immutable_ref="fixture:base-revision",
    )
    return Lock(
        schema="conf-proc-lock/v1",
        lock_version=1,
        base_image_record=base,
        future_cmdline="console=ttyS0",
        inputs=inputs,
        authorized_module_signers=(),
        image_specs={"models": {}, "runtime-policy": {}},
        policy_input_id="kernel",
        tool_ids=("build-tool",),
    )


def _inputs(artifact_input_sha256: str = _sha(100)) -> ProvenanceInputs:
    return ProvenanceInputs(
        artifact_input_schema="conf-proc-lock/v1",
        artifact_input_sha256=artifact_input_sha256,
        runtime_closure_sha256=_sha(101),
        verity_rules_sha256=_sha(102),
        tcb_identity_sha256=_sha(103),
        builder_source_sha256=_sha(104),
        policy_sha256=_sha(105),
        execution_provenance_sha256=_sha(106),
        root_lock_bytes=b"root",
        runtime_closure_bytes=b"closure",
        verity_rules_bytes=b"rules",
        tcb_identity_bytes=b"tcb",
        builder_source_bytes=b"source",
        policy_bytes=b"policy",
    )


class ProvenanceV2SpdxTests(unittest.TestCase):
    def assert_rejected(self, callback, expected_reason: str) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            callback()
        self.assertEqual(ctx.exception.reason_code, expected_reason)
        self.assertIn(ctx.exception.reason_code, reasons.ALL_REASON_CODES)

    def test_builder_projects_full_spdx_and_exact_references(self) -> None:
        inputs = _inputs()
        raw = parse_spdx_v2(_build_spdx_v2_bytes(lock=_lock(), inputs=inputs)).raw
        appliance = next(item for item in raw["packages"] if item["SPDXID"] == "SPDXRef-Package-appliance")
        self.assertEqual(raw["name"], "conf-proc-appliance-" + inputs.artifact_input_sha256[:16])
        self.assertEqual(raw["documentNamespace"], "urn:uuid:64cc8a78-1391-5c68-b0fb-502b8f64ecc9")
        self.assertEqual(raw["creationInfo"]["created"], "2050-04-29T03:24:56Z")
        self.assertEqual([item["referenceType"] for item in appliance["externalRefs"]], [
            "conf-proc-artifact-input",
            "conf-proc-builder-source",
            "conf-proc-execution-provenance",
            "conf-proc-policy",
            "conf-proc-runtime-closure",
            "conf-proc-tcb-identity",
            "conf-proc-verity-rules",
        ])
        self.assertEqual(len(raw["packages"]), 3)
        self.assertEqual(len(raw["files"]), 2)
        self.assertEqual(len(raw["relationships"]), 6)

    def test_schema_requires_appliance_external_refs_and_canonical_bytes(self) -> None:
        data = _build_spdx_v2_bytes(lock=_lock(), inputs=_inputs())
        raw = canonical_loads(data)
        appliance = next(item for item in raw["packages"] if item["SPDXID"] == "SPDXRef-Package-appliance")
        appliance.pop("externalRefs")
        self.assert_rejected(
            lambda: parse_spdx_v2(canonical_dumps(raw)),
            "CP_PROVENANCE_V2_SPDX_PRODUCTION",
        )
        self.assert_rejected(
            lambda: parse_spdx_v2(data + b"\n"),
            "CP_JSON_NONCANONICAL",
        )

    def test_schema_rejects_fields_at_each_top_level_boundary(self) -> None:
        raw = canonical_loads(_build_spdx_v2_bytes(lock=_lock(), inputs=_inputs()))
        raw["creationInfo"]["unexpected"] = True
        self.assert_rejected(
            lambda: parse_spdx_v2(canonical_dumps(raw)),
            "CP_PROVENANCE_V2_SPDX_PRODUCTION",
        )
        raw = canonical_loads(_build_spdx_v2_bytes(lock=_lock(), inputs=_inputs()))
        raw["packages"][0]["unexpected"] = True
        self.assert_rejected(
            lambda: parse_spdx_v2(canonical_dumps(raw)),
            "CP_PROVENANCE_V2_SPDX_PRODUCTION",
        )

    def test_rejects_sanitized_package_and_file_id_collisions(self) -> None:
        package_collision = _lock(
            (
                _input("same/a", "kernel", _sha(10), ()),
                _input("same?a", "build_tool", _sha(11), ()),
            )
        )
        self.assert_rejected(
            lambda: _build_spdx_v2_bytes(lock=package_collision, inputs=_inputs()),
            "CP_PROVENANCE_V2_SPDX_PRODUCTION",
        )
        reserved_collision = _lock((_input("appliance", "kernel", _sha(12), ()),))
        self.assert_rejected(
            lambda: _build_spdx_v2_bytes(lock=reserved_collision, inputs=_inputs()),
            "CP_PROVENANCE_V2_SPDX_PRODUCTION",
        )
        file_collision = _lock(
            (
                _input("one", "kernel", _sha(13), (_placement("models", "/same/a", "file"),)),
                _input("two", "build_tool", _sha(14), (_placement("models", "/same?a", "file"),)),
            )
        )
        self.assert_rejected(
            lambda: _build_spdx_v2_bytes(lock=file_collision, inputs=_inputs()),
            "CP_PROVENANCE_V2_SPDX_PRODUCTION",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
