#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Collector supervision invariants with controlled clocks and processes."""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ratls_gateway import CollectorError, CommandCollector


class CollectorDeadlines(unittest.TestCase):
    def test_expired_never_spawns(self):
        collector = CommandCollector(["collector"], 120)
        with mock.patch("ratls_gateway.time.monotonic", return_value=10), \
                mock.patch("ratls_gateway.subprocess.Popen") as spawn:
            with self.assertRaisesRegex(CollectorError, "queue timeout"):
                collector.call({}, deadline=9)
        spawn.assert_not_called()

    def test_expired_after_lock_never_spawns(self):
        collector = CommandCollector(["collector"], 120)
        with mock.patch("ratls_gateway.time.monotonic", side_effect=[0, 0, 2]), \
                mock.patch("ratls_gateway.subprocess.Popen") as spawn:
            with self.assertRaisesRegex(CollectorError, "queue timeout"):
                collector.call({}, deadline=1)
        spawn.assert_not_called()
        self.assertTrue(collector._lock.acquire(blocking=False))
        collector._lock.release()

    def test_queue_timeout_preserves_active_state(self):
        collector = CommandCollector(["collector"], 120)
        collector._state = "running"
        collector._operation = "status-inventory-v1"
        collector._started = 1
        collector._lock = mock.Mock()
        collector._lock.acquire.return_value = False
        with mock.patch("ratls_gateway.time.monotonic", return_value=10), \
                mock.patch("ratls_gateway.subprocess.Popen") as spawn:
            with self.assertRaisesRegex(CollectorError, "queue timeout"):
                collector.call({}, deadline=11)
            snapshot = collector.snapshot()
        self.assertEqual(snapshot["state"], "running")
        self.assertEqual(snapshot["operation"], "status-inventory-v1")
        self.assertEqual(snapshot["queue_timeouts"], 1)
        self.assertEqual(snapshot["active_seconds"], 9)
        spawn.assert_not_called()

    def test_cleanup_failure_quarantines(self):
        collector = CommandCollector(["collector"], 120)
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"{}", b"")
        with mock.patch("ratls_gateway.subprocess.Popen", return_value=process) as spawn, \
                mock.patch.object(collector, "_cleanup", return_value=False):
            with self.assertRaisesRegex(CollectorError, "cleanup failed"):
                collector.call({})
            with self.assertRaisesRegex(CollectorError, "unavailable"):
                collector.call({})
        self.assertEqual(spawn.call_count, 1)
        snapshot = collector.snapshot()
        self.assertEqual(snapshot["state"], "unavailable")
        self.assertEqual(snapshot["last_result"], "cleanup_failed")
        self.assertFalse(snapshot["available"])

    def test_cleanup_inspection_and_close_errors_return_failure(self):
        collector = CommandCollector(["collector"], 120)
        process = mock.Mock(pid=123)
        process.stdout.close.side_effect = OSError("synthetic")
        with mock.patch("ratls_gateway.os.killpg"), \
                mock.patch.object(collector, "_group_active", side_effect=IndexError):
            self.assertFalse(collector._cleanup(process))

    def test_timeout_then_recovery_and_fixed_diagnostics(self):
        import subprocess
        collector = CommandCollector(["collector"], 120)
        process = mock.Mock(returncode=0)
        process.communicate.side_effect = [subprocess.TimeoutExpired("secret", 1), (b"{}", b"")]
        with mock.patch("ratls_gateway.subprocess.Popen", return_value=process), \
                mock.patch.object(collector, "_cleanup", return_value=True):
            with self.assertRaisesRegex(CollectorError, "execution timeout"):
                collector.call({"operation": "secret", "nonce": "private"})
            snapshot = collector.snapshot()
            self.assertEqual(snapshot["last_result"], "execution_timeout")
            self.assertEqual(snapshot["execution_timeouts"], 1)
            self.assertNotIn("secret", str(snapshot))
            self.assertNotIn("private", str(snapshot))
            self.assertEqual(collector.call({}), {})
            self.assertEqual(collector.snapshot()["last_result"], "success")


if __name__ == "__main__":
    unittest.main()
