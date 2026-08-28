#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftests for the conf-proc hermetic in-process I/O guard."""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_guard as guard  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha256_file(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class HermeticGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.declared_file = os.path.join(self.tmp, "declared.txt")
        self.undeclared_file = os.path.join(self.tmp, "undeclared.txt")
        with open(self.declared_file, "wb") as handle:
            handle.write(b"declared content")
        with open(self.undeclared_file, "wb") as handle:
            handle.write(b"undeclared content")

        true_path = "/usr/bin/true" if os.path.exists("/usr/bin/true") else "/bin/true"
        false_path = "/usr/bin/false" if os.path.exists("/usr/bin/false") else "/bin/false"
        env_path = "/usr/bin/env"
        self.true_path = true_path
        self.false_path = false_path
        self.env_path = env_path

        self.guard = guard.HermeticGuard(
            allowed_reads=frozenset({self.declared_file, true_path, false_path, env_path}),
            tools={
                true_path: guard.ToolDeclaration(true_path, _sha256_file(true_path)),
                false_path: guard.ToolDeclaration(false_path, _sha256_file(false_path)),
                env_path: guard.ToolDeclaration(env_path, _sha256_file(env_path)),
            },
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
            build_epoch=1700000000,
        )

    def test_read_declared_path(self) -> None:
        self.assertEqual(self.guard.read_bytes(self.declared_file), b"declared content")

    def test_reject_undeclared_read(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            self.guard.read_bytes(self.undeclared_file)
        self.assertEqual(ctx.exception.reason_code, "CP_HERMETIC_UNLISTED_READ")

    def test_pinned_read_is_inode_anchored_across_transient_replacement(self) -> None:
        saved = self.declared_file + ".saved"
        replacement = self.declared_file + ".replacement"
        Path(replacement).write_bytes(b"replacement")
        with self.assertRaises(ApplianceError) as ctx:
            with self.guard.pin_reads((self.declared_file,)):
                os.rename(self.declared_file, saved)
                os.rename(replacement, self.declared_file)
                self.assertEqual(self.guard.read_bytes(self.declared_file), b"declared content")
                os.unlink(self.declared_file)
                os.rename(saved, self.declared_file)
        self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_INPUT_CHANGED")
        self.assertEqual(Path(self.declared_file).read_bytes(), b"declared content")

    def test_pinned_read_rejects_persistent_path_replacement(self) -> None:
        saved = self.declared_file + ".saved"
        replacement = self.declared_file + ".replacement"
        Path(replacement).write_bytes(b"replacement")
        with self.assertRaises(ApplianceError) as ctx:
            with self.guard.pin_reads((self.declared_file,)):
                os.rename(self.declared_file, saved)
                os.rename(replacement, self.declared_file)
        self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_INPUT_CHANGED")

    def test_run_declared_tool(self) -> None:
        result = self.guard.run_tool([self.true_path], cwd=self.tmp)
        self.assertEqual(result.returncode, 0)

    def test_reject_undeclared_tool(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            self.guard.run_tool(["/usr/bin/id"], cwd=self.tmp)
        self.assertEqual(ctx.exception.reason_code, "CP_HERMETIC_UNLISTED_SUBPROCESS")

    def test_reject_relative_tool_path(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            self.guard.run_tool(["true"], cwd=self.tmp)
        self.assertEqual(ctx.exception.reason_code, "CP_HERMETIC_PATH_ESCAPE")

    def test_reject_tool_digest_mismatch(self) -> None:
        bad_guard = guard.HermeticGuard(
            allowed_reads=frozenset({self.true_path}),
            tools={self.true_path: guard.ToolDeclaration(self.true_path, "0" * 64)},
            env={},
            build_epoch=1700000000,
        )
        with self.assertRaises(ApplianceError) as ctx:
            bad_guard.run_tool([self.true_path], cwd=self.tmp)
        self.assertEqual(ctx.exception.reason_code, "CP_TOOL_DIGEST_MISMATCH")

    def test_reject_missing_declared_tool(self) -> None:
        missing_path = os.path.join(self.tmp, "does-not-exist-tool")
        bad_guard = guard.HermeticGuard(
            allowed_reads=frozenset(),
            tools={missing_path: guard.ToolDeclaration(missing_path, "0" * 64)},
            env={},
            build_epoch=1700000000,
        )
        with self.assertRaises(ApplianceError) as ctx:
            bad_guard.run_tool([missing_path], cwd=self.tmp)
        self.assertEqual(ctx.exception.reason_code, "CP_TOOL_MISSING")

    def test_tool_invocation_failure_raises(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            self.guard.run_tool([self.false_path], cwd=self.tmp)
        self.assertEqual(ctx.exception.reason_code, "CP_TOOL_INVOCATION_FAILED")

    def test_subprocess_never_inherits_ambient_environment(self) -> None:
        marker_name = "CONF_PROC_TEST_AMBIENT_MARKER"
        os.environ[marker_name] = "should-not-leak"
        try:
            result = self.guard.run_tool([self.env_path], cwd=self.tmp)
        finally:
            del os.environ[marker_name]
        self.assertNotIn(marker_name, result.stdout.decode("utf-8"))
        self.assertIn(b"PATH=/usr/bin:/bin", result.stdout)

    def test_reject_disallowed_env_key(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            guard.HermeticGuard(
                allowed_reads=frozenset(),
                tools={},
                env={"AWS_SECRET_ACCESS_KEY": "leaked"},
                build_epoch=1700000000,
            )
        self.assertEqual(ctx.exception.reason_code, "CP_HERMETIC_ENV")


class HermeticLockdownTests(unittest.TestCase):
    def test_blocks_wall_clock(self) -> None:
        with guard.hermetic_lockdown():
            with self.assertRaises(ApplianceError) as ctx:
                time.time()
            self.assertEqual(ctx.exception.reason_code, "CP_HERMETIC_CLOCK")
            with self.assertRaises(ApplianceError) as ctx:
                time.time_ns()
            self.assertEqual(ctx.exception.reason_code, "CP_HERMETIC_CLOCK")
        # Restored after the context exits.
        self.assertIsInstance(time.time(), float)

    def test_blocks_socket_construction(self) -> None:
        with guard.hermetic_lockdown():
            with self.assertRaises(ApplianceError) as ctx:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.assertEqual(ctx.exception.reason_code, "CP_HERMETIC_NETWORK")
        # Restored after the context exits: a real socket can be built and closed.
        real_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        real_socket.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
