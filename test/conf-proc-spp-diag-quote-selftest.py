#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftest for conf_proc_spp_diag_quote: exact argv construction and mutation coverage."""

from __future__ import annotations

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conf_proc_spp_diag_pcr import SPP_DIAG_PCR_SELECTION
from conf_proc_spp_diag_quote import FIXED_AK_HANDLE, QuoteOps, build_quote_invocation, run_quote


BASE_KWARGS = dict(
    challenge=b"\x01" * 32,
    run_identity=b"\x02" * 32,
    inner_receipt_digest="aa" * 32,
    signed_image_binding_address="bb" * 32,
    target_profile_id="target-1",
    control_plan_address="cc" * 32,
    quote_msg_out="/tmp/quote.msg",
    quote_sig_out="/tmp/quote.sig",
    quote_pcrs_out="/tmp/quote.pcrs",
)


def test_argv_uses_shared_pcr_selection() -> None:
    invocation = build_quote_invocation(**BASE_KWARGS)
    expected_pcr_list = ",".join(str(i) for i in SPP_DIAG_PCR_SELECTION)
    assert f"sha256:{expected_pcr_list}" in invocation.argv
    assert FIXED_AK_HANDLE in invocation.argv
    assert invocation.argv[0] == "tpm2_quote"
    assert invocation.argv[invocation.argv.index("-q") + 1] == invocation.qualifying_data.hex()
    assert invocation.argv[invocation.argv.index("-m") + 1] == "/tmp/quote.msg"
    assert invocation.argv[invocation.argv.index("-s") + 1] == "/tmp/quote.sig"
    assert invocation.argv[invocation.argv.index("-o") + 1] == "/tmp/quote.pcrs"


def test_mutations_change_qualifying_data() -> None:
    baseline = build_quote_invocation(**BASE_KWARGS).qualifying_data
    for key, mutation in [
        ("challenge", b"\xff" * 32),
        ("run_identity", b"\xfe" * 32),
        ("inner_receipt_digest", "dd" * 32),
        ("signed_image_binding_address", "ee" * 32),
        ("target_profile_id", "target-2"),
        ("control_plan_address", "ff" * 32),
    ]:
        mutated_kwargs = dict(BASE_KWARGS)
        mutated_kwargs[key] = mutation
        mutated = build_quote_invocation(**mutated_kwargs).qualifying_data
        assert mutated != baseline, key


def test_recording_fake_receives_exact_argv() -> None:
    invocation = build_quote_invocation(**BASE_KWARGS)
    recorded = []

    def fake_run_tool(argv):
        recorded.append(argv)

        class Result:
            returncode = 0

        return Result()

    ops = QuoteOps(run_tool=fake_run_tool)
    run_quote(ops, invocation)
    assert len(recorded) == 1
    assert recorded[0] == invocation.argv


def test_module_does_not_import_appraiser() -> None:
    source_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "conf_proc_spp_diag_quote.py")
    with open(source_path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    forbidden = {"conf_proc_spp_diag_attest", "conf_proc_spp_diagbundle", "conf_proc_spp_diag_trace_semantics"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not (imported & forbidden), imported & forbidden


def main() -> int:
    tests = [
        test_argv_uses_shared_pcr_selection,
        test_mutations_change_qualifying_data,
        test_recording_fake_receives_exact_argv,
        test_module_does_not_import_appraiser,
    ]
    for test in tests:
        test()
        print(f"ok   {test.__name__}")
    print(f"SPP diagnostic quote invocation: ok ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
