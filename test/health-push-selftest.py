#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Reporter boundaries, failure visibility and actual worker progress probes."""
import copy
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import spp_health_push as health
from fleet_usage import FleetUsage
from ratls_gateway import CommandCollector
from asr_shim import create_server

LIVE_PROCESSES = "--live-processes" in sys.argv
if LIVE_PROCESSES:
    sys.argv.remove("--live-processes")


def report(snapshot=None):
    return {"v": 1, "kind": "report", "build": "1" * 64, "boot": "2" * 32, "seq": 1, "uptime_s": 0,
            "cc": {"mode": "on", "environment": "production"}, "gpu": {"present": 1, "cc_ready": 1},
            "units": {name: {"state": "active", "restarts": 0, "last_exit": "none"} for name in health.UNITS},
            "models": {slot: {"identity": "match", "ready": "ready"} for slot in health.MODEL_IDS},
            "errors": [], **(snapshot or health.fallback_snapshot("missing"))}


class HealthTests(unittest.TestCase):
    def test_only_exact_typed_fields_escape(self):
        healthy = report()
        self.assertNotIn(b"owner", health.encode(healthy))
        for path, bad in ((["owner"], "secret"), (["models", "text", "identity"], "owner-secret"),
                          (["units", "sglang", "state"], "prompt"), (["seq"], True),
                          (["errors"], [{"component": "sglang", "code": "prompt", "count": 1}]),
                          (["histogram", "bands"], [1, 2, "owner"])):
            value = copy.deepcopy(healthy)
            current = value
            for key in path[:-1]:
                current = current[key]
            current[path[-1]] = bad
            with self.assertRaises(ValueError):
                health.encode(value)

    @unittest.skipUnless(LIVE_PROCESSES, "operator process check")
    def test_snapshot_is_independent_of_collector_lock_and_restart_age(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "snapshot.json"
            collector = CommandCollector(["unused"], 120)
            fleet = FleetUsage()
            writer = health.SnapshotWriter(collector, fleet, path)
            with collector._lock:
                collector._state = "running"
                collector._started = time.monotonic()
                thread = threading.Thread(target=writer.write)
                thread.start()
                thread.join(1)
                self.assertFalse(thread.is_alive())
            snapshot = health.read_snapshot(path)
            self.assertEqual(snapshot["collector"]["state"], "running")
            self.assertEqual(snapshot["collector"]["snapshot"], "current")
            self.assertEqual(health.read_snapshot(path)["accounting_boot"], snapshot["accounting_boot"])
            raw = json.loads(path.read_text())
            stale = health.read_snapshot(path, raw["written_monotonic_ns"] + health.SNAPSHOT_MAX_AGE_NS + 1)
            self.assertEqual(stale["collector"]["snapshot"], "stale")
            self.assertEqual(stale["accounting_boot"], "0" * 32)
            health.encode(report(stale))
            writer.fleet = FleetUsage()
            writer.write()
            self.assertNotEqual(health.read_snapshot(path)["accounting_boot"], snapshot["accounting_boot"])

    def test_bad_snapshot_still_produces_accepted_unhealthy_shape(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "snapshot.json"
            for raw, category in ((None, "missing"), (b"{", "invalid"), (b"a" * 8193, "invalid"),
                                  (b'{"owner":"secret"}', "invalid")):
                if raw is not None:
                    path.write_bytes(raw)
                snapshot = health.read_snapshot(path)
                self.assertEqual(snapshot["collector"]["snapshot"], category)
                self.assertFalse(snapshot["collector"]["available"])
                self.assertEqual(snapshot["counters"]["as_of_day"], 0)
                self.assertNotIn(b"secret", health.encode(report(snapshot)))

    def test_unit_and_gpu_output_never_passes_through(self):
        runner = lambda args: "ActiveState=active\nNRestarts=2\nResult=success\nExecMainCode=0\nExecMainStatus=0\n"
        self.assertEqual(health.unit_state("sglang", runner), {"state": "active", "restarts": 2, "last_exit": "none"})
        self.assertEqual(health.unit_state("sglang", lambda args: "ActiveState=owner-secret")["state"], "unknown")
        def gpu(args):
            return {"-f": "CC status: ON", "-e": "CC Environment: PRODUCTION",
                    "--format=csv,noheader": "NVIDIA H100 NVL\n"}[args[-1]]
        self.assertEqual(health.gpu_state(gpu), ({"mode": "on", "environment": "production"}, {"present": 1, "cc_ready": 1}))
        self.assertEqual(health.gpu_state(lambda args: "owner-secret")[1]["present"], 0)
        def two(args):
            return "NVIDIA H100 NVL\nNVIDIA H100 NVL" if "--query-gpu=name" in args else gpu(args)
        self.assertEqual(health.gpu_state(two)[1]["present"], 2)

    @unittest.skipUnless(LIVE_PROCESSES, "operator process check")
    def test_probe_command_time_and_size_bounds(self):
        with self.assertRaises(ValueError):
            health.command([sys.executable, "-c", "print('x'*9000)"], timeout=1)
        start = time.monotonic()
        with self.assertRaises(TimeoutError):
            health.command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=.1)
        self.assertLess(time.monotonic() - start, 1.5)

    def test_push_reads_status_only_and_cannot_follow_redirect(self):
        class Wire:
            def __init__(self):
                self.response = bytearray(b"HTTP/1.1 302 Found\r\nLocation: https://evil.invalid\r\n\r\ncommand")
                self.sent = b""
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, value): pass
            def sendall(self, value): self.sent += value
            def recv(self, size):
                self.assert_size = size
                value = self.response[:size]
                del self.response[:size]
                return bytes(value)
        wire = Wire()
        context = mock.Mock()
        context.wrap_socket.return_value = wire
        with mock.patch.object(health.socket, "create_connection", return_value=wire) as connect, \
                mock.patch.object(health.ssl, "create_default_context", return_value=context):
            self.assertEqual(health.post(health.encode(report())), 302)
        connect.assert_called_once_with((health.HOST, 443), timeout=10)
        context.wrap_socket.assert_called_once_with(wire, server_hostname=health.HOST)
        self.assertTrue(wire.response.startswith(b"Location:"))
        self.assertTrue(wire.sent.startswith(b"POST /v1/report HTTP/1.1\r\nHost: spp-health.solpbc.org\r\n"))

    @unittest.skipUnless(LIVE_PROCESSES, "operator socket check")
    def test_slow_local_headers_have_absolute_deadline(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        stop = threading.Event()
        def serve():
            connection, _ = listener.accept()
            with connection:
                connection.recv(4096)
                connection.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                while not stop.wait(.02):
                    try:
                        connection.sendall(b"a")
                    except OSError:
                        return
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        start = time.monotonic()
        try:
            with self.assertRaises((OSError, ValueError, health.http.client.HTTPException)):
                health.local_request(listener.getsockname()[1], "/health", timeout=.15)
            self.assertLess(time.monotonic() - start, 1)
        finally:
            stop.set()
            thread.join(1)
            listener.close()

    @unittest.skipUnless(LIVE_PROCESSES, "operator process check")
    def test_asr_ready_flag_cannot_hide_wedged_worker(self):
        gate = threading.Event()
        class Transcriber:
            blocked = False
            def transcribe_batch(self, batch):
                if self.blocked:
                    gate.wait(3)
                return [{"text": "synthetic", "words": [], "duration": 1.0} for _ in batch]
        transcriber = Transcriber()
        server = create_server(("127.0.0.1", 0), lambda: transcriber, request_timeout_s=.15, batch_window_s=.01)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def request(port, path, *args):
            return health.local_request(server.server_port, path, *args, timeout=1)
        try:
            self.assertTrue(server.worker.ready.wait(2))
            self.assertEqual(health.model_state("asr", request), {"identity": "match", "ready": "ready"})
            transcriber.blocked = True
            self.assertEqual(request(8100, "/v1/audio/health")[0], 200)
            self.assertEqual(health.model_state("asr", request), {"identity": "match", "ready": "failed"})
        finally:
            gate.set()
            server.shutdown()
            server.server_close()

    def test_text_uses_generation_health_and_identity_is_exact(self):
        called = []
        def request(port, path):
            called.append(path)
            return (200, json.dumps({"data": [{"id": health.MODEL_IDS["text"]}]}).encode()) if path == "/v1/models" else (503, b"")
        self.assertEqual(health.model_state("text", request), {"identity": "match", "ready": "failed"})
        self.assertEqual(called, ["/v1/models", "/health_generate"])
        self.assertEqual(health.model_state("text", lambda p, q: (200, b'{"data":[{"id":"owner-secret"}]}'))["identity"], "mismatch")


if __name__ == "__main__":
    unittest.main()
