#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Parser-only and source-shape tests for the SPP controller AppArmor profile."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY = os.path.join(ROOT, "spp-diag-runtime-src", "apparmor", "usr.local.libexec.solstone.spp-diag-controller")


def _lines() -> list[str]:
    with open(POLICY, encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.lstrip().startswith("#")]


def test_parser_only_when_available() -> None:
    parser = shutil.which("apparmor_parser")
    if parser is None:
        print("skip apparmor_parser unavailable: parser compilation was not performed")
        return
    # -Q prevents policy load.  Runtime loading is separately pinned in controller
    # source to -r -K --abort-on-error and never uses -Q.
    result = subprocess.run([parser, "-Q", "-K", POLICY], capture_output=True, text=True, check=False)
    assert result.returncode == 0, f"apparmor_parser parser-only check failed:\n{result.stdout}\n{result.stderr}"


def test_attachment_children_and_closed_files() -> None:
    lines = _lines()
    assert lines[0] == "profile /usr/lib/spp/spp-diag-controller {"
    expected_ix = {
        "/usr/bin/python3.10 ix,", "/usr/sbin/apparmor_parser ix,",
        "/opt/solstone/bin/synthetic-runtime ix,", "/opt/solstone/bin/spp-diag-gpu-helper ix,",
        "/usr/bin/tpm2_quote ix,",
    }
    assert expected_ix <= set(lines)
    assert not any("/**" in line or " px," in line or " ux," in line for line in lines)
    assert not any("sys_admin" in line or "mac_admin" in line for line in lines)
    assert "capability sys_boot," in lines
    assert "/proc/self/task/1/children r," in lines


def test_network_exec_and_signal_matrix() -> None:
    lines = _lines()
    assert {
        "network create inet stream,", "network create inet6 stream,", "network create inet dgram,",
        "deny network connect inet stream peer=(ip=198.51.100.7 port=443),",
        "deny network connect inet6 stream peer=(ip=2001:db8::8 port=443),",
        "deny network send inet dgram peer=(ip=203.0.113.9 port=443),",
    } <= set(lines)
    assert not any(line in {"deny network inet stream,", "deny network inet6 stream,", "deny network inet dgram,"} for line in lines)
    assert {line for line in lines if line.startswith("deny /")} == {
        "deny /var/tmp/solstone-writable-exec x,",
        "deny /mnt/solstone-attached/foreign-exec x,",
        "deny /run/solstone/remote-code/foreign-exec x,",
    }
    assert "signal (send) set=(term kill) peer=/usr/lib/spp/spp-diag-controller," in lines
    assert "signal (receive) set=(term kill exists) peer=/usr/lib/spp/spp-diag-controller," in lines


def test_no_includes_or_live_enforcement_claim() -> None:
    source = open(POLICY, encoding="utf-8").read()
    assert "#include" not in source
    assert "Parser-checked only" in source
    assert "live kernel" in source


TESTS = (test_parser_only_when_available, test_attachment_children_and_closed_files, test_network_exec_and_signal_matrix, test_no_includes_or_live_enforcement_claim)


def main() -> int:
    for test in TESTS:
        test()
        print(f"ok   {test.__name__}")
    print(f"SPP diagnostic AppArmor policy: ok ({len(TESTS)} tests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
