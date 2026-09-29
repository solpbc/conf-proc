# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Process-randomized device labeling, chat token accounting, and loopback metrics."""

from __future__ import annotations

import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import threading
from typing import Any

TOKEN_MAX = 2**31 - 1
USAGE_OBJECT_MAX_BYTES = 4096
KEY_MAX_BYTES = 4096
PARSER_DEPTH_MAX = 64


def device_label(key: bytes, material: str) -> str:
    return hmac.new(key, material.encode("ascii"), hashlib.sha256).hexdigest()


class UsageWalker:
    """Incremental streaming JSON walker that captures chat completion usage."""

    def __init__(self) -> None:
        self.last: tuple[int, int] | None = None
        self.bad: bool = False
        # Buffer or depth overflow: do not record totals for this response.
        self.disabled: bool = False
        self._depth = 0
        self._in_string = False
        self._escaped = False
        self._stack: list[str] = []
        self._expecting_key = False
        self._capturing_key = False
        self._key_buffer = bytearray()
        self._current_key: str | None = None
        self._expecting_value = False
        self._capturing_usage = False
        self._usage_start_depth = 0
        self._usage_buffer = bytearray()

    def feed(self, data: bytes) -> None:
        if self.disabled:
            return
        try:
            self._feed(data)
        except Exception:
            self.bad = True

    def _disable_accounting(self) -> None:
        # Overflow drops parser memory. feed() does not raise, so forwarded
        # response bytes stay unchanged.
        self.disabled = True
        self.bad = True
        self._depth = 0
        self._in_string = False
        self._escaped = False
        self._stack.clear()
        self._expecting_key = False
        self._capturing_key = False
        self._key_buffer.clear()
        self._current_key = None
        self._expecting_value = False
        self._capturing_usage = False
        self._usage_buffer.clear()

    def _append_key(self, byte: int) -> bool:
        if len(self._key_buffer) >= KEY_MAX_BYTES:
            self._disable_accounting()
            return False
        self._key_buffer.append(byte)
        return True

    def _push(self, kind: str) -> bool:
        if self._depth >= PARSER_DEPTH_MAX or len(self._stack) >= PARSER_DEPTH_MAX:
            self._disable_accounting()
            return False
        self._stack.append(kind)
        self._depth += 1
        return True

    def _feed(self, data: bytes) -> None:
        for b in data:
            if self.disabled:
                return
            if self._capturing_usage:
                if len(self._usage_buffer) >= USAGE_OBJECT_MAX_BYTES:
                    self._disable_accounting()
                    return
                self._usage_buffer.append(b)

            if self._in_string:
                if self._escaped:
                    self._escaped = False
                    if self._capturing_key and not self._append_key(b):
                        return
                elif b == ord(b"\\"):
                    self._escaped = True
                    if self._capturing_key and not self._append_key(b):
                        return
                elif b == ord(b'"'):
                    self._in_string = False
                    if self._capturing_key:
                        self._capturing_key = False
                        self._current_key = self._key_buffer.decode("utf-8", errors="replace")
                        self._key_buffer.clear()
                else:
                    if self._capturing_key and not self._append_key(b):
                        return
                continue

            if b == ord(b'"'):
                self._in_string = True
                self._escaped = False
                if self._expecting_key and self._stack and self._stack[-1] == "obj":
                    self._capturing_key = True
                    self._expecting_key = False
                    self._key_buffer.clear()
                elif self._expecting_value:
                    if self._current_key == "usage":
                        self.bad = True
                    self._expecting_value = False
                    self._current_key = None
                continue

            if self._expecting_value and not (b in b" \t\r\n"):
                if self._current_key == "usage":
                    if b == ord(b"{"):
                        self._capturing_usage = True
                        self._usage_start_depth = self._depth + 1
                        self._usage_buffer.clear()
                        self._usage_buffer.append(b)
                    elif b == ord(b"n"):
                        pass
                    else:
                        self.bad = True
                self._expecting_value = False
                self._current_key = None

            if b == ord(b"{"):
                if self._depth == 0 or (self._stack and self._stack[-1] == "obj"):
                    self._expecting_key = True
                if not self._push("obj"):
                    return
                self._expecting_value = False
            elif b == ord(b"["):
                if not self._push("arr"):
                    return
                self._expecting_value = False
            elif b == ord(b"}"):
                if self._depth > 0:
                    if self._stack and self._stack[-1] == "obj":
                        self._stack.pop()
                    self._depth -= 1
                    if self._capturing_usage and self._depth == self._usage_start_depth - 1:
                        self._capturing_usage = False
                        self._process_usage_buffer()
                self._expecting_key = False
                self._expecting_value = False
            elif b == ord(b"]"):
                if self._depth > 0:
                    if self._stack and self._stack[-1] == "arr":
                        self._stack.pop()
                    self._depth -= 1
                self._expecting_key = False
                self._expecting_value = False
            elif b == ord(b","):
                if self._stack and self._stack[-1] == "obj":
                    self._expecting_key = True
                self._expecting_value = False
            elif b == ord(b":"):
                if self._stack and self._stack[-1] == "obj":
                    self._expecting_value = True

    def _process_usage_buffer(self) -> None:
        try:
            parsed = json.loads(self._usage_buffer.decode("utf-8"))
            if (
                isinstance(parsed, dict)
                and "prompt_tokens" in parsed
                and "completion_tokens" in parsed
            ):
                pt = parsed["prompt_tokens"]
                ct = parsed["completion_tokens"]
                if (
                    type(pt) is int
                    and type(ct) is int
                    and 0 <= pt <= TOKEN_MAX
                    and 0 <= ct <= TOKEN_MAX
                ):
                    self.last = (pt, ct)
                else:
                    self.bad = True
            else:
                self.bad = True
        except Exception:
            self.bad = True
        finally:
            self._usage_buffer.clear()


class ChatTally:
    """Thread-safe accounting of token usage across admitted channels."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key if key is not None else os.urandom(32)
        self._lock = threading.Lock()
        self._prompt_tokens: dict[str, int] = {}
        self._completion_tokens: dict[str, int] = {}
        self._incomplete: int = 0

    def label_for(self, credential: str) -> str:
        return device_label(self._key, credential)

    def commit_response(self, label: str, walker: UsageWalker, truncated: bool) -> None:
        disabled = walker.disabled
        last = walker.last
        bad = walker.bad
        walker._usage_buffer.clear()
        with self._lock:
            if disabled:
                self._incomplete += 1
                return
            if truncated:
                # A later malformed usage object must not drop the last valid
                # cumulative sample. Overflow sets disabled and is handled above.
                if last is not None:
                    pt, ct = last
                    self._prompt_tokens[label] = self._prompt_tokens.get(label, 0) + pt
                    self._completion_tokens[label] = self._completion_tokens.get(label, 0) + ct
                self._incomplete += 1
                return
            if not bad and last is not None:
                pt, ct = last
                self._prompt_tokens[label] = self._prompt_tokens.get(label, 0) + pt
                self._completion_tokens[label] = self._completion_tokens.get(label, 0) + ct
            else:
                self._incomplete += 1

    def render(self) -> str:
        with self._lock:
            lines = [
                "# TYPE spp_chat_prompt_tokens_total counter",
                *(
                    f'spp_chat_prompt_tokens_total{{device="{key}"}} {self._prompt_tokens[key]}'
                    for key in sorted(self._prompt_tokens.keys())
                ),
                "# TYPE spp_chat_completion_tokens_total counter",
                *(
                    f'spp_chat_completion_tokens_total{{device="{key}"}} {self._completion_tokens[key]}'
                    for key in sorted(self._completion_tokens.keys())
                ),
                "# TYPE spp_chat_incomplete_accounting_total counter",
                f"spp_chat_incomplete_accounting_total {self._incomplete}",
            ]
        return "\n".join(lines) + "\n"


def _require_loopback(host: str) -> None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"metrics host {host!r} is not a loopback address") from exc
    if not ip.is_loopback:
        raise ValueError(f"metrics host {host!r} is not a loopback address")


class _MetricsHandler(http.server.BaseHTTPRequestHandler):
    server: LoopbackMetricsServer

    def do_GET(self) -> None:
        if self.path == "/metrics":
            body = self.server.tally.render().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404, "not found")

    def log_message(self, format: str, *args: Any) -> None:
        pass


class LoopbackMetricsServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], tally: ChatTally) -> None:
        _require_loopback(address[0])
        self.tally = tally
        super().__init__(address, _MetricsHandler)
