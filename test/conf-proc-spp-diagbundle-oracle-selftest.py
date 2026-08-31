#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent KAT and seam-mutation tests for the diagnostic-bundle codec."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

import conf_proc_spp_diagbundle as prod  # noqa: E402
import conf_proc_spp_diagbundle_oracle as oracle  # noqa: E402
from conf_proc_json import canonical_dumps  # noqa: E402
from conf_proc_spp_diagbundle_reasons import (  # noqa: E402
    CP_DIAGBUNDLE_FORBIDDEN,
    CP_DIAGBUNDLE_MEMBER,
    CP_DIAGBUNDLE_NODE_KIND,
    CP_DIAGBUNDLE_ROLE,
    CP_DIAGBUNDLE_SCHEMA,
    CP_DIAGBUNDLE_SEAM_CHALLENGE,
    CP_DIAGBUNDLE_SEAM_CONTROL_PLAN,
    CP_DIAGBUNDLE_SEAM_IMAGE_BINDING,
    CP_DIAGBUNDLE_SEAM_IMAGE_FIELD,
    CP_DIAGBUNDLE_SEAM_INNER_RECEIPT,
    CP_DIAGBUNDLE_SEAM_INPUT_CLOSURE,
    CP_DIAGBUNDLE_SEAM_QUOTE_QD,
    CP_DIAGBUNDLE_SEAM_RUN_IDENTITY,
    CP_DIAGBUNDLE_SEAM_SPPDIAG,
    CP_DIAGBUNDLE_SEAM_TARGET_PROFILE,
    DiagBundleError,
)


_EXPECTED_INPUT_CLOSURE_ADDRESS = "bafe18a2cd072235ece04d66650d28104fb2bb6d373031a1a9c78cd7eadd2d51"
_EXPECTED_CONTROL_PLAN_ADDRESS = "a96815d7e0eb79ff8e9e92839badb14b483eca88e0cb3272ad8d798d9457d03e"
_EXPECTED_IMAGE_BINDING_ADDRESS = "e3f4cf091f7a17d7d982bd1bc82c4abe8369d2633725918a5fa3cca514fb4fc7"
_EXPECTED_INNER_RECEIPT_DIGEST = "f1f7dafc97b062ffde6e966d28424e27cc04bbcffc1ddac589dc7742fb2e5873"
_EXPECTED_OUTER_ENVELOPE_ADDRESS = "c372bb7dced7481fca1ed5c5ae91e94c4341e9623040c29837e2a27c661e3c54"
_EXPECTED_QUOTE_EXTRA_DATA = "24bd181188deafe7286b7f8ec894ebdd76c1e887fc543134bc2efd53b8605a31"
_TMP = "/var/tmp"


def _bundle(spec: oracle.BundleSpec = oracle.DEFAULT_SPEC):
    tmp = tempfile.TemporaryDirectory(prefix="diagbundle-oracle-", dir=_TMP)
    source_root = os.path.join(tmp.name, "bundle-source")
    bundle = os.path.join(tmp.name, "bundle.sppdbn")
    exp = os.path.join(tmp.name, "expectations.json")
    addrs = oracle.build_bundle(source_root, exp, spec)
    oracle.pack_bundle(source_root, bundle)
    return tmp, bundle, exp, addrs


def _inspect(spec: oracle.BundleSpec) -> dict[str, str]:
    tmp, root, exp, _addrs = _bundle(spec)
    try:
        return prod.inspect_diagnostic_bundle(root, exp)
    finally:
        tmp.cleanup()


def _expect(code: str, spec: oracle.BundleSpec) -> None:
    tmp, root, exp, _addrs = _bundle(spec)
    try:
        try:
            prod.inspect_diagnostic_bundle(root, exp)
        except DiagBundleError as exc:
            if exc.reason_code != code:
                raise AssertionError(f"expected {code}, got {exc.reason_code}: {exc}") from exc
            return
        raise AssertionError(f"expected {code}")
    finally:
        tmp.cleanup()


def test_literal_kat() -> None:
    tmp, root, exp, addrs = _bundle()
    try:
        assert addrs["input_closure_address"] == _EXPECTED_INPUT_CLOSURE_ADDRESS
        assert addrs["control_plan_address"] == _EXPECTED_CONTROL_PLAN_ADDRESS
        assert addrs["image_binding_address"] == _EXPECTED_IMAGE_BINDING_ADDRESS
        assert addrs["inner_receipt_digest"] == _EXPECTED_INNER_RECEIPT_DIGEST
        assert addrs["outer_envelope_address"] == _EXPECTED_OUTER_ENVELOPE_ADDRESS
        assert addrs["quote_extra_data"] == _EXPECTED_QUOTE_EXTRA_DATA
        produced = prod.inspect_diagnostic_bundle(root, exp)
        assert produced["input_closure_address"] == _EXPECTED_INPUT_CLOSURE_ADDRESS
        assert produced["control_plan_address"] == _EXPECTED_CONTROL_PLAN_ADDRESS
        assert produced["image_binding_address"] == _EXPECTED_IMAGE_BINDING_ADDRESS
        assert produced["inner_receipt_digest"] == _EXPECTED_INNER_RECEIPT_DIGEST
        assert produced["outer_envelope_address"] == _EXPECTED_OUTER_ENVELOPE_ADDRESS
    finally:
        tmp.cleanup()


def test_domain_tag_and_field_name_are_load_bearing() -> None:
    tmp, _root, _exp, addrs = _bundle()
    tmp.cleanup()
    obj = addrs["input_closure_object"]
    mutated_domain = bytearray(oracle.DOMAIN_INPUT_CLOSURE)
    mutated_domain[0] ^= 0x01
    mutated = hashlib.sha256(bytes(mutated_domain) + canonical_dumps(obj)).hexdigest()
    assert mutated != _EXPECTED_INPUT_CLOSURE_ADDRESS
    renamed = dict(obj)
    renamed["schema_"] = renamed.pop("schema")
    assert oracle.domain_address(oracle.DOMAIN_INPUT_CLOSURE, renamed) != _EXPECTED_INPUT_CLOSURE_ADDRESS


def test_add_row_changes_address() -> None:
    rows = oracle.DEFAULT_SPEC.closure_rows + (("zz-extra.json", "source_tree_manifest", "canonical_json", b'{"x":1}'),)
    result = _inspect(replace(oracle.DEFAULT_SPEC, closure_rows=rows))
    assert result["input_closure_address"] != _EXPECTED_INPUT_CLOSURE_ADDRESS


def test_rename_path_changes_address() -> None:
    rows = tuple(("tree-manifest.json", role, kind, data) if path == "source-tree.json" else (path, role, kind, data) for path, role, kind, data in oracle.DEFAULT_SPEC.closure_rows)
    result = _inspect(replace(oracle.DEFAULT_SPEC, closure_rows=rows))
    assert result["input_closure_address"] != _EXPECTED_INPUT_CLOSURE_ADDRESS


def test_content_change_changes_address() -> None:
    rows = tuple((path, role, kind, b'{"tree":false}') if path == "source-tree.json" else (path, role, kind, data) for path, role, kind, data in oracle.DEFAULT_SPEC.closure_rows)
    result = _inspect(replace(oracle.DEFAULT_SPEC, closure_rows=rows))
    assert result["input_closure_address"] != _EXPECTED_INPUT_CLOSURE_ADDRESS


def test_wrong_declared_sha256_is_rejected() -> None:
    _expect(CP_DIAGBUNDLE_MEMBER, replace(oracle.DEFAULT_SPEC, declared_sha256=(("trace.json", "0" * 64),)))


def test_wrong_role_at_control_plan_path() -> None:
    rows = tuple((path, "build_recipe", kind, data) if path == "control-plan.json" else (path, role, kind, data) for path, role, kind, data in oracle.DEFAULT_SPEC.closure_rows)
    _expect(CP_DIAGBUNDLE_ROLE, replace(oracle.DEFAULT_SPEC, closure_rows=rows))


def test_duplicate_control_plan_role() -> None:
    rows = oracle.DEFAULT_SPEC.closure_rows + (("other-plan.json", "canonical_control_plan", "canonical_json", b'{"plan":true}'),)
    _expect(CP_DIAGBUNDLE_ROLE, replace(oracle.DEFAULT_SPEC, closure_rows=rows))


def test_missing_mandatory_role() -> None:
    rows = tuple(row for row in oracle.DEFAULT_SPEC.closure_rows if row[1] != "trace_policy")
    _expect(CP_DIAGBUNDLE_ROLE, replace(oracle.DEFAULT_SPEC, closure_rows=rows))


def test_duplicate_path() -> None:
    extra = ("source-tree.json", "source_tree_manifest", "canonical_json", b'{"tree":true}')
    _expect(CP_DIAGBUNDLE_SCHEMA, replace(oracle.DEFAULT_SPEC, closure_rows=oracle.DEFAULT_SPEC.closure_rows + (extra,)))


def test_unsorted_rows() -> None:
    _expect(CP_DIAGBUNDLE_SCHEMA, replace(oracle.DEFAULT_SPEC, sort_closure=False, closure_rows=tuple(reversed(oracle.DEFAULT_SPEC.closure_rows))))


def test_forbidden_path_names() -> None:
    pem = (("keys/service.pem", "source_tree_manifest", "canonical_json", b'{"k":1}'),) + tuple(row for row in oracle.DEFAULT_SPEC.closure_rows if row[1] != "source_tree_manifest")
    _expect(CP_DIAGBUNDLE_FORBIDDEN, replace(oracle.DEFAULT_SPEC, closure_rows=pem))
    rsa = (("id_rsa", "source_tree_manifest", "bytes", b"secret"),) + tuple(row for row in oracle.DEFAULT_SPEC.closure_rows if row[1] != "source_tree_manifest")
    _expect(CP_DIAGBUNDLE_FORBIDDEN, replace(oracle.DEFAULT_SPEC, closure_rows=rsa))


def test_self_referential_extra_field() -> None:
    _expect(CP_DIAGBUNDLE_SCHEMA, replace(oracle.DEFAULT_SPEC, extra_closure_fields=(("input_closure_address", "a" * 64),)))


def test_challenge_length_boundary() -> None:
    _expect(CP_DIAGBUNDLE_SCHEMA, replace(oracle.DEFAULT_SPEC, receipt_challenge=oracle.DEFAULT_SPEC.challenge[:-1]))
    _expect(CP_DIAGBUNDLE_SCHEMA, replace(oracle.DEFAULT_SPEC, receipt_challenge=oracle.DEFAULT_SPEC.challenge + "aa"))


def test_coherent_control_plan_replay() -> None:
    rows = tuple((path, role, kind, canonical_dumps({"plan": False})) if path == "control-plan.json" else (path, role, kind, data) for path, role, kind, data in oracle.DEFAULT_SPEC.closure_rows)
    _expect(CP_DIAGBUNDLE_SEAM_CONTROL_PLAN, replace(oracle.DEFAULT_SPEC, closure_rows=rows, expectations_control_plan=_EXPECTED_CONTROL_PLAN_ADDRESS))


def test_embedded_descriptor_mismatch() -> None:
    rows = tuple((path, role, kind, b'{"tree":"mutated"}') if path == "source-tree.json" else (path, role, kind, data) for path, role, kind, data in oracle.DEFAULT_SPEC.closure_rows)
    _expect(CP_DIAGBUNDLE_SEAM_SPPDIAG, replace(oracle.DEFAULT_SPEC, closure_rows=rows, sppdiag_address=_EXPECTED_INPUT_CLOSURE_ADDRESS))


def test_image_field_mismatch() -> None:
    _expect(CP_DIAGBUNDLE_SEAM_IMAGE_FIELD, replace(oracle.DEFAULT_SPEC, image_input_closure_address="0" * 64))


def test_image_binding_mismatch() -> None:
    _expect(
        CP_DIAGBUNDLE_SEAM_IMAGE_BINDING,
        replace(
            oracle.DEFAULT_SPEC,
            rootfs=b"rootfs-mutated",
            receipt_image_binding=_EXPECTED_IMAGE_BINDING_ADDRESS,
        ),
    )


def test_inner_receipt_digest_mismatch() -> None:
    _expect(CP_DIAGBUNDLE_SEAM_INNER_RECEIPT, replace(oracle.DEFAULT_SPEC, outer_inner_digest="0" * 64))


def test_quote_extra_data_mismatch() -> None:
    _expect(CP_DIAGBUNDLE_SEAM_QUOTE_QD, replace(oracle.DEFAULT_SPEC, outer_quote_extra="0" * 64))


def test_inner_outer_swap() -> None:
    tmp, root, exp, _addrs = _bundle(replace(oracle.DEFAULT_SPEC, inner_as_root_manifest=True))
    try:
        try:
            prod.inspect_diagnostic_bundle(root, exp)
        except DiagBundleError as exc:
            if exc.reason_code not in {CP_DIAGBUNDLE_SCHEMA, CP_DIAGBUNDLE_NODE_KIND}:
                raise AssertionError(f"expected SCHEMA or NODE_KIND, got {exc.reason_code}: {exc}") from exc
        else:
            raise AssertionError("expected rejection")
    finally:
        tmp.cleanup()


def test_challenge_run_and_profile_replay() -> None:
    tmp, root, exp, addrs = _bundle()
    try:
        assert prod.inspect_diagnostic_bundle(root, exp)["input_closure_address"] == _EXPECTED_INPUT_CLOSURE_ADDRESS
        for field, value, code in (
            ("challenge", hashlib.sha256(b"other-challenge").hexdigest(), CP_DIAGBUNDLE_SEAM_CHALLENGE),
            ("run_identity", hashlib.sha256(b"other-run").hexdigest(), CP_DIAGBUNDLE_SEAM_RUN_IDENTITY),
            ("target_profile_id", "other-profile", CP_DIAGBUNDLE_SEAM_TARGET_PROFILE),
        ):
            payload = {
                "input_closure_address": addrs["input_closure_address"],
                "challenge": oracle.DEFAULT_SPEC.challenge,
                "run_identity": oracle.DEFAULT_SPEC.run_identity,
                "target_profile_id": oracle.DEFAULT_SPEC.target_profile_id,
                "control_plan_address": addrs["control_plan_address"],
            }
            payload[field] = value
            mutated = os.path.join(tmp.name, f"exp-{field}.json")
            Path(mutated).write_bytes(canonical_dumps(payload))
            try:
                prod.inspect_diagnostic_bundle(root, mutated)
            except DiagBundleError as exc:
                if exc.reason_code != code:
                    raise AssertionError(f"expected {code}, got {exc.reason_code}: {exc}") from exc
            else:
                raise AssertionError(f"expected {code}")
    finally:
        tmp.cleanup()


def test_caller_input_closure_mismatch() -> None:
    _expect(CP_DIAGBUNDLE_SEAM_INPUT_CLOSURE, replace(oracle.DEFAULT_SPEC, expectations_input_closure="0" * 64))


def test_no_standalone_expectations_inspect() -> None:
    assert not hasattr(prod, "inspect_caller_expectations")
    source = (ROOT / "conf_proc_spp_diagbundle.py").read_text()
    assert "def inspect_diagnostic_bundle" in source
    assert source.count("return {") >= 1


TESTS = (
    test_literal_kat,
    test_domain_tag_and_field_name_are_load_bearing,
    test_add_row_changes_address,
    test_rename_path_changes_address,
    test_content_change_changes_address,
    test_wrong_declared_sha256_is_rejected,
    test_wrong_role_at_control_plan_path,
    test_duplicate_control_plan_role,
    test_missing_mandatory_role,
    test_duplicate_path,
    test_unsorted_rows,
    test_forbidden_path_names,
    test_self_referential_extra_field,
    test_challenge_length_boundary,
    test_coherent_control_plan_replay,
    test_embedded_descriptor_mismatch,
    test_image_field_mismatch,
    test_image_binding_mismatch,
    test_inner_receipt_digest_mismatch,
    test_quote_extra_data_mismatch,
    test_inner_outer_swap,
    test_challenge_run_and_profile_replay,
    test_caller_input_closure_mismatch,
    test_no_standalone_expectations_inspect,
)


if __name__ == "__main__":
    failed = 0
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report every case
            failed += 1
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok   {test.__name__}")
    raise SystemExit(failed)
