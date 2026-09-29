#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Self-test for process-randomized usage tallying, accounting, and metrics exposition."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asr_shim import Metrics
from ratls_gateway import (
    EntitlementRejectedError,
    RelayProtocolError,
    _http_relay,
)
from usage_tally import (
    KEY_MAX_BYTES,
    PARSER_DEPTH_MAX,
    TOKEN_MAX,
    USAGE_OBJECT_MAX_BYTES,
    ChatTally,
    LoopbackMetricsServer,
    UsageWalker,
    device_label,
)


class DummyAuthorizer:
    def __init__(self, reject: set[str] | None = None) -> None:
        self.reject = reject or set()

    def authorize(self, credential: str) -> None:
        if credential in self.reject:
            raise EntitlementRejectedError("rejected credential")


class MockUpstream:
    def __init__(self, handler_fn) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(128)
        self.port = self.listener.getsockname()[1]
        self.handler_fn = handler_fn
        self.accept_count = 0
        self.received_requests: list[tuple[bytes, bytes]] = []
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                break
            self.accept_count += 1
            threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def _handle_client(self, conn: socket.socket) -> None:
        try:
            self.handler_fn(self, conn)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self) -> None:
        try:
            self.listener.close()
        except Exception:
            pass


def _read_http_request(conn: socket.socket) -> tuple[bytes, bytes]:
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
    if b"\r\n\r\n" not in buf:
        return bytes(buf), b""
    idx = buf.index(b"\r\n\r\n")
    head = bytes(buf[: idx + 4])
    body = bytearray(buf[idx + 4 :])
    content_length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break
    while len(body) < content_length:
        chunk = conn.recv(min(4096, content_length - len(body)))
        if not chunk:
            break
        body.extend(chunk)
    return head, bytes(body)


def _run_client_request(
    target_relay_fn,
    request_bytes: bytes,
    timeout: float = 5.0,
) -> bytes:
    client_sock, relay_sock = socket.socketpair()
    received_bytes = bytearray()

    def client_worker() -> None:
        try:
            client_sock.sendall(request_bytes)
            while True:
                data = client_sock.recv(4096)
                if not data:
                    break
                received_bytes.extend(data)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    ct = threading.Thread(target=client_worker, daemon=True)
    ct.start()
    try:
        target_relay_fn(relay_sock)
    finally:
        try:
            relay_sock.close()
        except Exception:
            pass
        ct.join(timeout)
    return bytes(received_bytes)


class UsageTallyTest(unittest.TestCase):
    def test_distinct_process_keys_do_not_share_labels(self) -> None:
        key1 = b"\x01" * 32
        key2 = b"\x02" * 32
        cred = "user-cred-abc"
        tally1 = ChatTally(key1)
        tally2 = ChatTally(key2)
        label1 = tally1.label_for(cred)
        label2 = tally2.label_for(cred)
        self.assertNotEqual(label1, label2)
        self.assertEqual(label1, device_label(key1, cred))
        self.assertEqual(label2, device_label(key2, cred))
        tally3 = ChatTally(key1)
        self.assertEqual(tally3.label_for(cred), label1)

        w = UsageWalker()
        w.feed(b'{"usage":{"prompt_tokens":10,"completion_tokens":20}}')
        tally1.commit_response(label1, w, truncated=False)
        self.assertIn(f'spp_chat_prompt_tokens_total{{device="{label1}"}} 10', tally1.render())
        self.assertNotIn(f'device="{label1}"', tally2.render())

        m_key1 = b"\x11" * 32
        m_key2 = b"\x22" * 32
        metrics1 = Metrics(m_key1)
        metrics2 = Metrics(m_key2)
        metrics1.record_audio(2.5, "dev-test-123")
        metrics2.record_audio(4.0, "dev-test-123")
        m_label1 = device_label(m_key1, "dev-test-123")
        m_label2 = device_label(m_key2, "dev-test-123")
        self.assertNotEqual(m_label1, m_label2)
        self.assertIn(f'spp_asr_device_audio_seconds_total{{device="{m_label1}"}} 2.500', metrics1.render(0, True))
        self.assertIn(f'spp_asr_device_audio_seconds_total{{device="{m_label2}"}} 4.000', metrics2.render(0, True))
        self.assertNotIn(f'device="{m_label2}"', metrics1.render(0, True))
        self.assertEqual(tally1.label_for(cred), label1)

    def test_json_and_chunked_usage_added_once(self) -> None:
        key = b"\x07" * 32
        tally = ChatTally(key)
        authorizer = DummyAuthorizer()
        cred1 = "cred-user-1"
        cred2 = "cred-user-2"
        label1 = tally.label_for(cred1)
        label2 = tally.label_for(cred2)
        self.assertEqual(label1, device_label(key, cred1))
        self.assertNotEqual(label1, hashlib.sha256(cred1.encode("ascii")).hexdigest())

        sentinel = "SENTINEL_SECRET_TOKEN"
        upstream_json_body = (
            f'{{"id":"c1","choices":[{{"message":{{"content":"hello \\"usage\\": {{\"prompt_tokens\": 9999}}, {sentinel}"}}}}],'
            f'"usage":{{"prompt_tokens":15,"completion_tokens":25,"image_tokens":100,"total_tokens":40}}}}'
        ).encode("utf-8")
        upstream_json_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(upstream_json_body)}\r\n\r\n".encode("ascii")
            + upstream_json_body
        )

        def handle_json(server: MockUpstream, conn: socket.socket) -> None:
            head, body = _read_http_request(conn)
            server.received_requests.append((head, body))
            conn.sendall(upstream_json_response)

        server_json = MockUpstream(handle_json)
        try:
            req_body = b'{"messages":[],"usage":{"prompt_tokens":8888}}'
            req = (
                b"POST /v1/chat/completions HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: close\r\n"
                b"Authorization: Bearer " + cred1.encode("ascii") + b"\r\n"
                b"x-sol-device: client-spoof\r\n"
                + f"Content-Length: {len(req_body)}\r\n\r\n".encode("ascii")
                + req_body
            )

            def relay_call_json(client_sock: socket.socket) -> None:
                _http_relay(
                    client_sock,
                    ("127.0.0.1", server_json.port),
                    None,
                    10,
                    authorizer,
                    60.0,
                    time.monotonic(),
                    tally,
                )

            client_bytes = _run_client_request(relay_call_json, req)
            self.assertEqual(client_bytes, upstream_json_response)

            self.assertEqual(len(server_json.received_requests), 1)
            up_head, up_body = server_json.received_requests[0]
            self.assertIn(f"x-sol-device: {label1}".encode("ascii"), up_head)
            self.assertNotIn(b"client-spoof", up_head)
            self.assertNotIn(b"authorization:", up_head.lower())

            render1 = tally.render()
            self.assertIn(f'spp_chat_prompt_tokens_total{{device="{label1}"}} 15', render1)
            self.assertIn(f'spp_chat_completion_tokens_total{{device="{label1}"}} 25', render1)
            self.assertIn("spp_chat_incomplete_accounting_total 0", render1)
            self.assertNotIn("9999", render1)
            self.assertNotIn("8888", render1)
            self.assertNotIn("100", render1)
            self.assertNotIn(sentinel, render1)
        finally:
            server_json.close()

        chunk1_body = b'data: {"choices":[{"delta":{"content":"hi"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}\n\n'
        chunk2_body = b'data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":15}}\n\ndata: [DONE]\n\n'
        upstream_chunked_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            + f"{len(chunk1_body):x}\r\n".encode("ascii") + chunk1_body + b"\r\n"
            + f"{len(chunk2_body):x}\r\n".encode("ascii") + chunk2_body + b"\r\n"
            + b"0\r\n\r\n"
        )

        def handle_chunked(server: MockUpstream, conn: socket.socket) -> None:
            head, body = _read_http_request(conn)
            server.received_requests.append((head, body))
            conn.sendall(upstream_chunked_response)

        server_chunked = MockUpstream(handle_chunked)
        try:
            req2 = (
                b"POST /v1/chat/completions HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: close\r\n"
                b"Authorization: Bearer " + cred1.encode("ascii") + b"\r\n"
                b"Content-Length: 2\r\n\r\n{}"
            )

            def relay_call_chunked(client_sock: socket.socket) -> None:
                _http_relay(
                    client_sock,
                    ("127.0.0.1", server_chunked.port),
                    None,
                    10,
                    authorizer,
                    60.0,
                    time.monotonic(),
                    tally,
                )

            client_bytes2 = _run_client_request(relay_call_chunked, req2)
            self.assertEqual(client_bytes2, upstream_chunked_response)

            render2 = tally.render()
            self.assertIn(f'spp_chat_prompt_tokens_total{{device="{label1}"}} 25', render2)
            self.assertIn(f'spp_chat_completion_tokens_total{{device="{label1}"}} 40', render2)
            self.assertIn("spp_chat_incomplete_accounting_total 0", render2)
        finally:
            server_chunked.close()

        upstream_cred2_body = b'{"usage":{"prompt_tokens":50,"completion_tokens":60}}'
        upstream_cred2_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(upstream_cred2_body)}\r\n\r\n".encode("ascii")
            + upstream_cred2_body
        )

        def handle_cred2(server: MockUpstream, conn: socket.socket) -> None:
            head, body = _read_http_request(conn)
            server.received_requests.append((head, body))
            conn.sendall(upstream_cred2_response)

        server_cred2 = MockUpstream(handle_cred2)
        try:
            req3 = (
                b"POST /v1/chat/completions HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: close\r\n"
                b"Authorization: Bearer " + cred2.encode("ascii") + b"\r\n"
                b"Content-Length: 2\r\n\r\n{}"
            )

            def relay_call_cred2(client_sock: socket.socket) -> None:
                _http_relay(
                    client_sock,
                    ("127.0.0.1", server_cred2.port),
                    None,
                    10,
                    authorizer,
                    60.0,
                    time.monotonic(),
                    tally,
                )

            client_bytes3 = _run_client_request(relay_call_cred2, req3)
            self.assertEqual(client_bytes3, upstream_cred2_response)

            render3 = tally.render()
            self.assertIn(f'spp_chat_prompt_tokens_total{{device="{label1}"}} 25', render3)
            self.assertIn(f'spp_chat_completion_tokens_total{{device="{label1}"}} 40', render3)
            self.assertIn(f'spp_chat_prompt_tokens_total{{device="{label2}"}} 50', render3)
            self.assertIn(f'spp_chat_completion_tokens_total{{device="{label2}"}} 60', render3)
        finally:
            server_cred2.close()

    def test_split_chunk_usage_added_once(self) -> None:
        key = b"\x08" * 32
        tally = ChatTally(key)
        authorizer = DummyAuthorizer()
        cred = "cred-split-test"
        label = tally.label_for(cred)

        c1 = b'data: {"choices":[], "usage": {"prompt_tok'
        c2 = b'ens": 14, "completion_tokens": 28}}\n\ndata: [DONE]\n\n'
        upstream_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            + f"{len(c1):x}\r\n".encode("ascii") + c1 + b"\r\n"
            + f"{len(c2):x}\r\n".encode("ascii") + c2 + b"\r\n"
            + b"0\r\n\r\n"
        )

        def handle_split(server: MockUpstream, conn: socket.socket) -> None:
            _read_http_request(conn)
            conn.sendall(upstream_response)

        server = MockUpstream(handle_split)
        try:
            req = (
                b"POST /v1/chat/completions HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: close\r\n"
                b"Authorization: Bearer " + cred.encode("ascii") + b"\r\n"
                b"Content-Length: 2\r\n\r\n{}"
            )

            def relay_call(client_sock: socket.socket) -> None:
                _http_relay(
                    client_sock,
                    ("127.0.0.1", server.port),
                    None,
                    10,
                    authorizer,
                    60.0,
                    time.monotonic(),
                    tally,
                )

            client_bytes = _run_client_request(relay_call, req)
            self.assertEqual(client_bytes, upstream_response)
            render = tally.render()
            self.assertIn(f'spp_chat_prompt_tokens_total{{device="{label}"}} 14', render)
            self.assertIn(f'spp_chat_completion_tokens_total{{device="{label}"}} 28', render)
            self.assertIn("spp_chat_incomplete_accounting_total 0", render)
        finally:
            server.close()

    def test_incomplete_does_not_invent_tokens(self) -> None:
        key = b"\x09" * 32
        tally = ChatTally(key)
        authorizer = DummyAuthorizer()
        cred = "cred-incomplete"
        label = tally.label_for(cred)

        test_cases = [
            b'{"id":"c1","choices":[{"message":{"content":"no usage"}}]}',
            b'{"id":"c2","usage":{"prompt_tokens":"10","completion_tokens":10}}',
            b'{"id":"c3","usage":{"prompt_tokens":true,"completion_tokens":10}}',
            f'{{"id":"c4","usage":{{"padding":"{"x" * 5000}","prompt_tokens":10,"completion_tokens":10}}}}'.encode("ascii"),
            f'{{"id":"c5","usage":{{"prompt_tokens":{TOKEN_MAX + 1},"completion_tokens":10}}}}'.encode("ascii"),
        ]

        for i, body in enumerate(test_cases, start=1):
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                + body
            )

            def handle_case(server: MockUpstream, conn: socket.socket, payload=resp) -> None:
                _read_http_request(conn)
                conn.sendall(payload)

            server = MockUpstream(handle_case)
            try:
                req = (
                    b"POST /v1/chat/completions HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Connection: close\r\n"
                    b"Authorization: Bearer " + cred.encode("ascii") + b"\r\n"
                    b"Content-Length: 2\r\n\r\n{}"
                )

                def relay_call(client_sock: socket.socket) -> None:
                    _http_relay(
                        client_sock,
                        ("127.0.0.1", server.port),
                        None,
                        10,
                        authorizer,
                        60.0,
                        time.monotonic(),
                        tally,
                    )

                client_bytes = _run_client_request(relay_call, req)
                self.assertEqual(client_bytes, resp)
                render = tally.render()
                self.assertNotIn(f'device="{label}"', render)
                self.assertIn(f"spp_chat_incomplete_accounting_total {i}", render)
            finally:
                server.close()

        valid_max_body = f'{{"id":"c6","usage":{{"prompt_tokens":{TOKEN_MAX},"completion_tokens":0}}}}'.encode("ascii")
        valid_max_resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(valid_max_body)}\r\n\r\n".encode("ascii")
            + valid_max_body
        )

        def handle_max(server: MockUpstream, conn: socket.socket) -> None:
            _read_http_request(conn)
            conn.sendall(valid_max_resp)

        server_max = MockUpstream(handle_max)
        try:
            req_max = (
                b"POST /v1/chat/completions HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: close\r\n"
                b"Authorization: Bearer " + cred.encode("ascii") + b"\r\n"
                b"Content-Length: 2\r\n\r\n{}"
            )

            def relay_call_max(client_sock: socket.socket) -> None:
                _http_relay(
                    client_sock,
                    ("127.0.0.1", server_max.port),
                    None,
                    10,
                    authorizer,
                    60.0,
                    time.monotonic(),
                    tally,
                )

            client_bytes = _run_client_request(relay_call_max, req_max)
            self.assertEqual(client_bytes, valid_max_resp)
            render = tally.render()
            self.assertIn(f'spp_chat_prompt_tokens_total{{device="{label}"}} {TOKEN_MAX}', render)
            self.assertIn(f'spp_chat_completion_tokens_total{{device="{label}"}} 0', render)
            self.assertIn(f"spp_chat_incomplete_accounting_total {len(test_cases)}", render)
        finally:
            server_max.close()

    def test_truncated_stream_keeps_last_snapshot_and_marks_incomplete(self) -> None:
        key = b"\x0a" * 32
        tally = ChatTally(key)
        authorizer = DummyAuthorizer()
        cred = "cred-truncated"
        label = tally.label_for(cred)

        partial_body = b'{"usage":{"prompt_tokens":12,"completion_tokens":34},"rest":"'

        def handle_trunc(server: MockUpstream, conn: socket.socket) -> None:
            _read_http_request(conn)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 500\r\n\r\n"
                + partial_body
            )
            conn.close()

        server = MockUpstream(handle_trunc)
        try:
            req = (
                b"POST /v1/chat/completions HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: close\r\n"
                b"Authorization: Bearer " + cred.encode("ascii") + b"\r\n"
                b"Content-Length: 2\r\n\r\n{}"
            )

            client_sock, relay_sock = socket.socketpair()
            try:
                client_sock.sendall(req)
                with self.assertRaises(RelayProtocolError):
                    _http_relay(
                        relay_sock,
                        ("127.0.0.1", server.port),
                        None,
                        10,
                        authorizer,
                        60.0,
                        time.monotonic(),
                        tally,
                    )
            finally:
                client_sock.close()
                relay_sock.close()

            render = tally.render()
            self.assertIn(f'spp_chat_prompt_tokens_total{{device="{label}"}} 12', render)
            self.assertIn(f'spp_chat_completion_tokens_total{{device="{label}"}} 34', render)
            self.assertIn("spp_chat_incomplete_accounting_total 1", render)
        finally:
            server.close()

    def test_rejected_credential_creates_no_row(self) -> None:
        key = b"\x0b" * 32
        tally = ChatTally(key)
        authorizer = DummyAuthorizer(reject={"cred-bad"})

        def handle_never(server: MockUpstream, conn: socket.socket) -> None:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

        server = MockUpstream(handle_never)
        try:
            req = (
                b"POST /v1/chat/completions HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: close\r\n"
                b"Authorization: Bearer cred-bad\r\n"
                b"Content-Length: 2\r\n\r\n{}"
            )

            client_sock, relay_sock = socket.socketpair()
            try:
                client_sock.sendall(req)
                _http_relay(
                    relay_sock,
                    ("127.0.0.1", server.port),
                    None,
                    10,
                    authorizer,
                    60.0,
                    time.monotonic(),
                    tally,
                )
                resp = client_sock.recv(4096)
                self.assertIn(b"401 Unauthorized", resp)
            finally:
                client_sock.close()
                relay_sock.close()

            self.assertEqual(server.accept_count, 0)
            render = tally.render()
            self.assertNotIn("device=", render)
            self.assertIn("spp_chat_incomplete_accounting_total 0", render)
        finally:
            server.close()

    def test_relay_metrics_path_is_404_without_a_tally_row(self) -> None:
        key = b"\x0c" * 32
        tally = ChatTally(key)
        authorizer = DummyAuthorizer()

        def handle_never(server: MockUpstream, conn: socket.socket) -> None:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

        server = MockUpstream(handle_never)
        try:
            req = (
                b"GET /metrics HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: close\r\n"
                b"Authorization: Bearer cred-valid\r\n\r\n"
            )

            client_sock, relay_sock = socket.socketpair()
            try:
                client_sock.sendall(req)
                _http_relay(
                    relay_sock,
                    ("127.0.0.1", server.port),
                    None,
                    10,
                    authorizer,
                    60.0,
                    time.monotonic(),
                    tally,
                )
                resp = client_sock.recv(4096)
                self.assertIn(b"404 Not Found", resp)
                self.assertIn(b'{"error":"not found"}', resp)
            finally:
                client_sock.close()
                relay_sock.close()

            self.assertEqual(server.accept_count, 0)
            render = tally.render()
            self.assertNotIn("device=", render)
            self.assertIn("spp_chat_incomplete_accounting_total 0", render)
        finally:
            server.close()

    def test_metrics_bind_rejects_non_loopback(self) -> None:
        tally = ChatTally()
        with mock.patch("socket.socket", side_effect=AssertionError("bound")):
            with self.assertRaises(ValueError):
                LoopbackMetricsServer(("0.0.0.0", 0), tally)

        server = LoopbackMetricsServer(("127.0.0.1", 0), tally)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            label = tally.label_for("cred-metrics-test")
            w = UsageWalker()
            w.feed(b'{"usage":{"prompt_tokens":111,"completion_tokens":222}}')
            tally.commit_response(label, w, truncated=False)

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/metrics")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8")
            conn.close()

            self.assertEqual(body, tally.render())
            self.assertIn(f'spp_chat_prompt_tokens_total{{device="{label}"}} 111', body)
            self.assertIn(f'spp_chat_completion_tokens_total{{device="{label}"}} 222', body)
            self.assertIn("spp_chat_incomplete_accounting_total 0", body)
        finally:
            server.shutdown()
            server.server_close()

    def test_no_overflow_series_at_4097(self) -> None:
        key = b"\x0d" * 32
        tally = ChatTally(key)
        metrics = Metrics(key)

        for i in range(4097):
            cred = f"cred-{i:04d}"
            label = tally.label_for(cred)
            w = UsageWalker()
            w.feed(f'{{"usage":{{"prompt_tokens":{i},"completion_tokens":1}}}}'.encode("ascii"))
            tally.commit_response(label, w, truncated=False)
            metrics.record_audio(1.0, f"device-{i:04d}")

        metrics.record_audio(5.0, None)

        rendered_chat = tally.render()
        rendered_asr = metrics.render(0, True)

        self.assertNotIn("overflow", rendered_chat)
        self.assertNotIn("overflow", rendered_asr)
        self.assertIn('spp_asr_device_audio_seconds_total{device="unlabeled"} 5.000', rendered_asr)

        chat_devices = re.findall(r'spp_chat_prompt_tokens_total\{device="([^"]+)"\}', rendered_chat)
        asr_devices = re.findall(r'spp_asr_device_audio_seconds_total\{device="([^"]+)"\}', rendered_asr)
        self.assertEqual(len(chat_devices), 4097)
        self.assertEqual(len(asr_devices), 4098)
        self.assertIn("unlabeled", asr_devices)

    def test_parser_overflow_bounds_buffers_and_disables_accounting(self) -> None:
        key_walker = UsageWalker()
        key_walker.feed(b'{"' + b"x" * 1_048_576)
        self.assertTrue(key_walker.disabled)
        self.assertLessEqual(len(key_walker._key_buffer), KEY_MAX_BYTES)
        self.assertLess(len(key_walker._key_buffer), 1_048_576)
        self.assertLessEqual(len(key_walker._usage_buffer), USAGE_OBJECT_MAX_BYTES)
        self.assertLessEqual(len(key_walker._stack), PARSER_DEPTH_MAX)

        depth_walker = UsageWalker()
        depth_walker.feed(b"[" * 100_000)
        self.assertTrue(depth_walker.disabled)
        self.assertLessEqual(len(depth_walker._stack), PARSER_DEPTH_MAX)
        self.assertLess(len(depth_walker._stack), 100_000)
        self.assertLessEqual(len(depth_walker._key_buffer), KEY_MAX_BYTES)
        self.assertLessEqual(depth_walker._depth, PARSER_DEPTH_MAX)

        usage_walker = UsageWalker()
        usage_walker.feed(
            b'{"usage":{"pad":"' + b"x" * (USAGE_OBJECT_MAX_BYTES + 10) + b'"}}'
        )
        self.assertTrue(usage_walker.disabled)
        self.assertLessEqual(len(usage_walker._usage_buffer), USAGE_OBJECT_MAX_BYTES)
        self.assertLessEqual(len(usage_walker._key_buffer), KEY_MAX_BYTES)
        self.assertLessEqual(len(usage_walker._stack), PARSER_DEPTH_MAX)

        tally = ChatTally(b"\x0e" * 32)
        label = tally.label_for("cred-overflow")
        held = UsageWalker()
        held.feed(b'{"usage":{"prompt_tokens":3,"completion_tokens":4}}')
        self.assertEqual(held.last, (3, 4))
        held.feed(b"[" * 100_000)
        self.assertTrue(held.disabled)
        self.assertEqual(held.last, (3, 4))
        tally.commit_response(label, held, truncated=True)
        render = tally.render()
        self.assertNotIn(f'device="{label}"', render)
        self.assertIn("spp_chat_incomplete_accounting_total 1", render)

        finished = UsageWalker()
        finished.feed(b'{"usage":{"prompt_tokens":3,"completion_tokens":4}}')
        finished.feed(b'{"' + b"x" * 1_048_576)
        self.assertTrue(finished.disabled)
        tally.commit_response(label, finished, truncated=False)
        render = tally.render()
        self.assertNotIn(f'device="{label}"', render)
        self.assertIn("spp_chat_incomplete_accounting_total 2", render)

    def test_truncated_malformed_usage_counts_last_valid_sample_once(self) -> None:
        tally = ChatTally(b"\x0f" * 32)
        label = tally.label_for("cred-last-valid")
        walker = UsageWalker()
        walker.feed(b'{"usage":{"prompt_tokens":3,"completion_tokens":4}}')
        walker.feed(b'{"usage":{"prompt_tokens":true,"completion_tokens":1}}')
        self.assertEqual(walker.last, (3, 4))
        self.assertTrue(walker.bad)
        self.assertFalse(walker.disabled)
        tally.commit_response(label, walker, truncated=True)
        render = tally.render()
        self.assertIn(f'spp_chat_prompt_tokens_total{{device="{label}"}} 3', render)
        self.assertIn(f'spp_chat_completion_tokens_total{{device="{label}"}} 4', render)
        self.assertIn("spp_chat_incomplete_accounting_total 1", render)

    def test_parser_overflow_does_not_change_forwarded_bytes(self) -> None:
        key = b"\x10" * 32
        tally = ChatTally(key)
        authorizer = DummyAuthorizer()
        cred = "cred-overflow-bytes"
        label = tally.label_for(cred)
        bodies = (
            b'{"' + b"x" * 1_048_576,
            b"[" * 100_000,
        )
        for i, body in enumerate(bodies, start=1):
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                + body
            )

            def handle(server: MockUpstream, conn: socket.socket, payload=resp) -> None:
                _read_http_request(conn)
                conn.sendall(payload)

            server = MockUpstream(handle)
            try:
                req = (
                    b"POST /v1/chat/completions HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Connection: close\r\n"
                    b"Authorization: Bearer " + cred.encode("ascii") + b"\r\n"
                    b"Content-Length: 2\r\n\r\n{}"
                )

                def relay_call(client_sock: socket.socket) -> None:
                    _http_relay(
                        client_sock,
                        ("127.0.0.1", server.port),
                        None,
                        10,
                        authorizer,
                        60.0,
                        time.monotonic(),
                        tally,
                    )

                client_bytes = _run_client_request(relay_call, req)
                self.assertEqual(client_bytes, resp)
                render = tally.render()
                self.assertNotIn(f'device="{label}"', render)
                self.assertIn(f"spp_chat_incomplete_accounting_total {i}", render)
            finally:
                server.close()


if __name__ == "__main__":
    unittest.main()
