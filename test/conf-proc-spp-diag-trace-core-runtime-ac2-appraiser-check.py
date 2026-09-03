#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Appraiser cross-check for AC2 scenario."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys

# Ensure test/ directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from conf_proc_spp_diag_trace_semantic_fixture import (
    CONTROL_PLAN_HEX,
    EXPECTED_LEDGER_HEX,
)
from conf_proc_spp_diag_trace_semantic_reasons import (
    CP_SPP_TRACE_SEMANTICS_CONTROL,
    TraceSemanticsError,
)
from conf_proc_spp_diag_trace_semantics import appraise_spp_diag_trace_semantics

# Import transform_ledger from sibling oracle selftest
oracle_mod = __import__("conf-proc-spp-diag-trace-core-runtime-ac2-oracle-selftest")
transform_ledger = oracle_mod.transform_ledger


def test_semantic_variant(fixture_bin: str, flag: str, expected_reason: str) -> None:
    res = subprocess.run([fixture_bin, flag], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
        print(f"FAIL: K3 fixture {flag} exited with error code {res.returncode}", file=sys.stderr)
        print(res.stderr.decode("utf-8", errors="replace"), file=sys.stderr)
        sys.exit(1)

    control_plan = bytes.fromhex(CONTROL_PLAN_HEX)
    try:
        appraise_spp_diag_trace_semantics(control_plan, res.stdout)
        print(f"FAIL: {flag} unexpectedly succeeded in semantic appraiser!", file=sys.stderr)
        sys.exit(1)
    except TraceSemanticsError as err:
        if err.reason_code != expected_reason:
            print(
                f"FAIL: {flag} raised {err.reason_code}, expected {expected_reason}",
                file=sys.stderr,
            )
            sys.exit(1)
        print(
            f"PASS: {flag} -> K3-side success (exit 0) + appraiser rejection ({err.reason_code})"
        )


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <fixture_binary>", file=sys.stderr)
        sys.exit(1)

    fixture_bin = sys.argv[1]
    actual_stream = subprocess.check_output([fixture_bin])

    expected_ledger = transform_ledger(bytes.fromhex(EXPECTED_LEDGER_HEX))
    control_plan = bytes.fromhex(CONTROL_PLAN_HEX)

    actual_ledger = appraise_spp_diag_trace_semantics(control_plan, actual_stream)

    if actual_ledger != expected_ledger:
        print(
            f"FAIL: Appraised ledger mismatch (actual {len(actual_ledger)} bytes, expected {len(expected_ledger)} bytes)",
            file=sys.stderr,
        )
        sys.exit(1)

    ledger_sha = hashlib.sha256(actual_ledger).hexdigest()
    print(f"PASS: AC2 appraiser ledger cross-check exact match (sha256: {ledger_sha})")

    # AC4 / AC5 Appraiser Integration Tests
    test_semantic_variant(fixture_bin, "--wrong-poison-path", CP_SPP_TRACE_SEMANTICS_CONTROL)
    test_semantic_variant(fixture_bin, "--wrong-endpoint", CP_SPP_TRACE_SEMANTICS_CONTROL)
    test_semantic_variant(fixture_bin, "--successful-denial-canary", CP_SPP_TRACE_SEMANTICS_CONTROL)
    test_semantic_variant(fixture_bin, "--absent-canary", CP_SPP_TRACE_SEMANTICS_CONTROL)


if __name__ == "__main__":
    main()
