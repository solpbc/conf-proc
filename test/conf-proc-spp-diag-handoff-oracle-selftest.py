#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Compiles and exercises the real /spp-diag-handoff binary via its scripted test harness.

This drives the SAME compiled production binary (spp-diag-runtime-src/spp_diag_handoff.c)
through SPP_DIAG_HANDOFF_TEST_HARNESS, never a separately recompiled test double, so a
placeholder or inventory-only handoff cannot pass this suite.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(ROOT, "spp-diag-runtime-src", "spp_diag_handoff.c")
FIXED_ARGV = [
    "/usr/bin/python3.10",
    "-I",
    "-B",
    "-S",
    "/usr/local/libexec/solstone/spp-diag-controller.py",
]
FIXED_ENVP = [
    "LANG=C",
    "LC_ALL=C",
    "PATH=/nonexistent",
    "PYTHONNOUSERSITE=1",
    "PYTHONDONTWRITEBYTECODE=1",
]
DATA_PARTUUID = "11111111-1111-1111-1111-111111111111"
HASH_PARTUUID = "22222222-2222-2222-2222-222222222222"
ROOT_HASH = "ab" * 32
CMDLINE_OK = (
    f"console=ttyS0,115200n8 rdinit=/spp-diag-handoff -- "
    f"spp_diag_data_partuuid={DATA_PARTUUID} spp_diag_hash_partuuid={HASH_PARTUUID} spp_diag_root_hash={ROOT_HASH}"
)


def compile_fixture(build_dir: str) -> str:
    fixture = os.path.join(build_dir, "spp-diag-handoff-fixture")
    result = subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-o", fixture, SOURCE],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(f"compile failed:\n{result.stdout}\n{result.stderr}")
    if result.stdout.strip() or result.stderr.strip():
        raise SystemExit(f"compile produced unexpected output (warnings?):\n{result.stdout}\n{result.stderr}")
    return fixture


def script_line(op: str, **fields: object) -> str:
    parts = [op] + [f"{key}={value}" for key, value in fields.items()]
    return "\t".join(parts)


def happy_path_script(cmdline: str = CMDLINE_OK, root_verity_ok: bool = True, mount_writable: bool = False) -> list[str]:
    lines = [
        script_line("mount", result=0),
        script_line("open", result=0, data=cmdline),
        script_line("readlink", result=0, out="/dev/sda2"),
        script_line("readlink", result=0, out="/dev/sda3"),
        script_line("open", result=0),
        script_line("blkgetsize64", result=0, size=1073741824),
        script_line("open", result=0),
        script_line("dm_dev_create", result=0),
        script_line("dm_table_load", result=0 if root_verity_ok else -1),
    ]
    if not root_verity_ok:
        return lines
    lines += [
        script_line("dm_dev_suspend", result=0),
        script_line("mount", result=0),
        script_line("statvfs_rdonly", result=0 if mount_writable else 1),
    ]
    if mount_writable:
        return lines
    lines += [
        script_line("chdir", result=0),
        script_line("mount", result=0),
        script_line("chroot", result=0),
        script_line("chdir", result=0),
        script_line("mount", result=0),
        script_line("open", result=0),
        script_line("dup2", result=3),
        script_line("open", result=0),
        script_line("dup2", result=4),
        script_line("open", result=0),
        script_line("dup2", result=5),
        script_line("execve", result=0),
    ]
    return lines


def run_fixture(fixture: str, script_lines: list[str], work_dir: str) -> tuple[int, list[str]]:
    script_path = os.path.join(work_dir, "script.tsv")
    log_path = os.path.join(work_dir, "log.tsv")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(script_lines) + "\n")
    env = {
        "SPP_DIAG_HANDOFF_TEST_HARNESS": script_path,
        "SPP_DIAG_HANDOFF_TEST_LOG": log_path,
        "PATH": "/usr/bin:/bin",
    }
    result = subprocess.run([fixture], env=env, capture_output=True, text=True, timeout=10)
    log_lines: list[str] = []
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as handle:
            log_lines = [line.rstrip("\n") for line in handle if line.strip()]
    return result.returncode, log_lines


def log_ops(log_lines: list[str]) -> list[str]:
    return [line.split("\t", 1)[0] for line in log_lines]


def find_log_entry(log_lines: list[str], op: str, occurrence: int = 0) -> str:
    matches = [line for line in log_lines if line.split("\t", 1)[0] == op]
    return matches[occurrence]


def main() -> int:
    with tempfile.TemporaryDirectory() as build_dir:
        fixture = compile_fixture(build_dir)
        tests = 0

        with tempfile.TemporaryDirectory() as work_dir:
            rc, log = run_fixture(fixture, happy_path_script(), work_dir)
            assert rc == 0, f"happy path exit {rc}, log={log}"
            assert log_ops(log)[-1] == "execve", log
            execve_entry = find_log_entry(log, "execve")
            assert f"path=/usr/bin/python3.10" in execve_entry, execve_entry
            assert f"argv={','.join(FIXED_ARGV)}" in execve_entry, execve_entry
            assert f"envp={','.join(FIXED_ENVP)}" in execve_entry, execve_entry
            dup2_entries = [line for line in log if line.startswith("dup2\t")]
            assert len(dup2_entries) == 3, dup2_entries
            assert "newfd=3" in dup2_entries[0] and "result=3" in dup2_entries[0], dup2_entries[0]
            assert "newfd=4" in dup2_entries[1] and "result=4" in dup2_entries[1], dup2_entries[1]
            assert "newfd=5" in dup2_entries[2] and "result=5" in dup2_entries[2], dup2_entries[2]
            table_load_entry = find_log_entry(log, "dm_table_load")
            assert ROOT_HASH in table_load_entry, table_load_entry
            assert "/dev/sda2" in table_load_entry and "/dev/sda3" in table_load_entry, table_load_entry
            root_mount_entry = find_log_entry(log, "mount", 1)
            assert "fstype=squashfs" in root_mount_entry, root_mount_entry
            move_mount_entry = find_log_entry(log, "mount", 2)
            assert "target=/" in move_mount_entry, move_mount_entry
            print("ok   happy_path_full_sequence")
            tests += 1

        with tempfile.TemporaryDirectory() as work_dir:
            script = happy_path_script()
            script[2] = script_line("readlink", result=-1)
            rc, log = run_fixture(fixture, script, work_dir)
            assert rc == 13, f"expected ERR_PARTUUID_MISSING(13), got {rc}"
            assert "execve" not in log_ops(log), log
            assert log_ops(log).count("readlink") == 1, log
            print("ok   missing_partuuid_rejects_before_verity")
            tests += 1

        with tempfile.TemporaryDirectory() as work_dir:
            script = happy_path_script()
            script[2] = script_line("readlink", result=0, out="/dev/sda2")
            script[3] = script_line("readlink", result=0, out="/dev/sda2")
            rc, log = run_fixture(fixture, script, work_dir)
            assert rc == 14, f"expected ERR_PARTUUID_DUPLICATE(14), got {rc}"
            assert "execve" not in log_ops(log), log
            assert log_ops(log).count("open") == 1, log
            print("ok   duplicate_partuuid_rejects")
            tests += 1

        with tempfile.TemporaryDirectory() as work_dir:
            script = happy_path_script(root_verity_ok=False)
            rc, log = run_fixture(fixture, script, work_dir)
            assert rc == 15, f"expected ERR_VERITY(15), got {rc}"
            assert "execve" not in log_ops(log), log
            assert log_ops(log).count("dm_dev_suspend") == 0, log
            print("ok   wrong_root_hash_verity_activation_fails")
            tests += 1

        with tempfile.TemporaryDirectory() as work_dir:
            script = happy_path_script(mount_writable=True)
            rc, log = run_fixture(fixture, script, work_dir)
            assert rc == 17, f"expected ERR_MOUNT_WRITABLE(17), got {rc}"
            assert "execve" not in log_ops(log), log
            assert "chdir" not in log_ops(log), log
            print("ok   writable_mount_rejects_before_switch_root")
            tests += 1

        malformed_cases = {
            "missing_dash": CMDLINE_OK.replace(" -- ", " "),
            "duplicate_console": CMDLINE_OK.replace(
                "console=ttyS0,115200n8", "console=ttyS0,115200n8 console=ttyS1"
            ),
            "missing_reserved_key": CMDLINE_OK.replace(f" spp_diag_root_hash={ROOT_HASH}", ""),
            "unexpected_fourth_key": CMDLINE_OK + " spp_diag_extra=1",
            "second_dash": CMDLINE_OK + " --",
        }
        for name, cmdline in malformed_cases.items():
            with tempfile.TemporaryDirectory() as work_dir:
                script = [
                    script_line("mount", result=0),
                    script_line("open", result=0, data=cmdline),
                ]
                rc, log = run_fixture(fixture, script, work_dir)
                assert rc == 12, f"{name}: expected ERR_CMDLINE_MALFORMED(12), got {rc}, log={log}"
                assert log_ops(log) == ["mount", "open", "close"], f"{name}: {log}"
                print(f"ok   malformed_cmdline_{name}")
                tests += 1

        with tempfile.TemporaryDirectory() as work_dir:
            script = happy_path_script()[:-1]
            rc, log = run_fixture(fixture, script, work_dir)
            assert rc == 99, f"expected harness-exhaustion sentinel(99), got {rc}"
            print("ok   script_exhaustion_after_last_fd_setup_is_a_test_failure_not_a_pass")
            tests += 1

        print(f"SPP diagnostic handoff native binary: ok ({tests} tests)")
        return 0


if __name__ == "__main__":
    sys.exit(main())
