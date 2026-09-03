#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Contract tests for the shared diagnostic-bundle address protocol."""

from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import conf_proc_spp_diagbundle_protocol as protocol  # noqa: E402


DOMAIN_IMAGE_BINDING = b"sol-spp-diagbundle-image-binding-v1\0"
DOMAIN_INNER_RECEIPT = b"sol-spp-diagbundle-inner-receipt-v1\0"
DOMAIN_QUOTE_QD = b"sol-spp-diagbundle-quote-qd-v1\0"
EXPECTED_ROLES = (
    "source_tree_manifest",
    "build_recipe",
    "toolchain_lock",
    "resolved_configuration",
    "kernel_configuration",
    "trace_policy",
    "canonical_control_plan",
    "runtime_manifest",
    "model_manifest",
    "producer_source",
    "controller_source",
    "signer_public_policy",
)


def _independent_address(domain: bytes, obj: dict) -> str:
    encoded = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def test_literal_protocol_values() -> None:
    assert protocol.DOMAIN_INPUT_CLOSURE == b"sol-spp-diagbundle-input-closure-v1\0"
    assert protocol.DOMAIN_IMAGE_BINDING == DOMAIN_IMAGE_BINDING
    assert protocol.DOMAIN_INNER_RECEIPT == DOMAIN_INNER_RECEIPT
    assert protocol.DOMAIN_CONTROL_PLAN == b"sol-spp-diagbundle-control-plan-v1\0"
    assert protocol.DOMAIN_QUOTE_QD == DOMAIN_QUOTE_QD
    assert protocol.DOMAIN_OUTER_ENVELOPE == b"sol-spp-diagbundle-outer-envelope-v1\0"
    assert protocol.INPUT_CLOSURE_ROLES == EXPECTED_ROLES


def test_image_binding_address() -> None:
    members = {
        "diagnostic.efi": {"size_bytes": 17, "sha256": "11" * 32},
        "rootfs.img": {"size_bytes": 23, "sha256": "22" * 32},
    }
    fields = {
        "schema": "sol-spp-diagbundle-signed-image/v1",
        "node_kind": "signed_image",
        "artifact_state": "released",
        "layout": "uki-verity/v1",
        "input_closure_address": "33" * 32,
        "members": members,
    }
    expected = _independent_address(DOMAIN_IMAGE_BINDING, fields)
    assert protocol.image_binding_address(**fields) == expected


def test_inner_receipt_digest() -> None:
    inventory = [{"path": "terminal-frame.bin", "content_kind": "bytes", "size_bytes": 76, "sha256": "44" * 32}]
    fields = {
        "schema": "sol-spp-diagbundle-inner-receipt/v1",
        "node_kind": "inner_receipt",
        "artifact_state": "released",
        "challenge": "55" * 32,
        "run_identity": "66" * 32,
        "signed_image_binding_address": "77" * 32,
        "target_profile_id": "diag-profile-v1",
        "control_plan_address": "88" * 32,
        "inventory": inventory,
    }
    expected = _independent_address(DOMAIN_INNER_RECEIPT, fields)
    assert protocol.inner_receipt_digest(**fields) == expected


def test_quote_qualifying_data() -> None:
    fields = {
        "challenge": "99" * 32,
        "control_plan_address": "aa" * 32,
        "inner_receipt_digest": "bb" * 32,
        "run_identity": "cc" * 32,
        "signed_image_binding_address": "dd" * 32,
        "target_profile_id": "diag-profile-v1",
    }
    expected = _independent_address(DOMAIN_QUOTE_QD, fields)
    assert protocol.quote_qualifying_data(**fields) == expected


def test_protocol_does_not_import_appraiser() -> None:
    source = (ROOT / "conf_proc_spp_diagbundle_protocol.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imports = (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports = (node.module or "",)
        else:
            continue
        assert all(name != "conf_proc_spp_diagbundle" for name in imports)


TESTS = (
    test_literal_protocol_values,
    test_image_binding_address,
    test_inner_receipt_digest,
    test_quote_qualifying_data,
    test_protocol_does_not_import_appraiser,
)


def main() -> None:
    for test in TESTS:
        test()
    print("spp diagnostic-bundle shared protocol: ok (%d tests)" % len(TESTS))


if __name__ == "__main__":
    main()
