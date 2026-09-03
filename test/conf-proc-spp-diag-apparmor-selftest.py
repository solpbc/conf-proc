#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Compile-checks the SPP diagnostic controller AppArmor profile with apparmor_parser
-Q -K and independently asserts its exact, closed set of deny rules from the raw
source text. This test proves the policy PARSES; it makes no claim about live kernel
enforcement, since no live AppArmor-enabled kernel is available in this environment.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(ROOT, "spp-diag-runtime-src", "apparmor", "usr.local.libexec.solstone.spp-diag-controller")

EXPECTED_NETWORK_DENIES = {
    "network inet stream",
    "network inet6 stream",
    "network inet dgram",
}
EXPECTED_EXEC_DENIES = {
    "/tmp/spp-diag-writable-exec-canary",
    "/mnt/spp-diag-attached-disk-canary",
    "/var/spp-diag-remote-code-canary",
}


def test_policy_compiles_with_apparmor_parser() -> None:
    if shutil.which("apparmor_parser") is None:
        raise SystemExit("apparmor_parser is required for this test and was not found on PATH")
    result = subprocess.run(["apparmor_parser", "-Q", "-K", POLICY_PATH], capture_output=True, text=True)
    assert result.returncode == 0, f"apparmor_parser -Q -K failed:\n{result.stdout}\n{result.stderr}"


def test_zero_includes() -> None:
    with open(POLICY_PATH, "r", encoding="utf-8") as handle:
        code_lines = [line.strip() for line in handle if not line.strip().startswith("#")]
    assert not any(line.startswith("#include") for line in code_lines), (
        "this profile is designed to be self-contained with zero #include directives"
    )


def test_exact_closed_deny_set() -> None:
    with open(POLICY_PATH, "r", encoding="utf-8") as handle:
        lines = [line.strip() for line in handle if line.strip() and not line.strip().startswith("#")]

    deny_lines = [line for line in lines if line.startswith("deny ")]
    assert len(deny_lines) == 6, f"expected exactly 6 deny rules, found {len(deny_lines)}: {deny_lines}"

    network_denies = set()
    exec_denies = set()
    for line in deny_lines:
        body = line[len("deny ") :].rstrip(",")
        network_match = re.fullmatch(r"network (inet6?) (stream|dgram)", body)
        exec_match = re.fullmatch(r"(/\S+) x", body)
        if network_match:
            network_denies.add(f"network {network_match.group(1)} {network_match.group(2)}")
        elif exec_match:
            exec_denies.add(exec_match.group(1))
        else:
            raise AssertionError(f"unexpected deny rule shape (not in the closed matrix): {line!r}")

    assert network_denies == EXPECTED_NETWORK_DENIES, network_denies
    assert exec_denies == EXPECTED_EXEC_DENIES, exec_denies

    non_deny_rule_lines = [
        line
        for line in lines
        if not line.startswith("deny ") and not line.startswith("/usr/bin/python3.10 {") and line != "}"
    ]
    allowed_grant_lines = {
        "/usr/bin/python3.10 mr,",
        "/usr/local/libexec/solstone/** r,",
        "/usr/lib/python3.10/** r,",
    }
    assert set(non_deny_rule_lines) == allowed_grant_lines, (
        "the neighbor matrix outside the six denies must be exactly the three fixed read/exec-mmap "
        f"grants; found: {non_deny_rule_lines}"
    )


def test_no_live_enforcement_claim() -> None:
    with open(POLICY_PATH, "r", encoding="utf-8") as handle:
        text = handle.read()
    assert "compile/parser-checked only" in text
    assert "live kernel" in text


def main() -> int:
    tests = [
        test_policy_compiles_with_apparmor_parser,
        test_zero_includes,
        test_exact_closed_deny_set,
        test_no_live_enforcement_claim,
    ]
    for test in tests:
        test()
        print(f"ok   {test.__name__}")
    print(f"SPP diagnostic AppArmor policy: ok ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
