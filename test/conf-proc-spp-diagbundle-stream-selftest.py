#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent framing and capture tests for the SPPDBN1 stream."""

from __future__ import annotations

import hashlib
import errno
import os
import struct
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import conf_proc_spp_diagbundle_stream as stream  # noqa: E402
from conf_proc_spp_diagbundle_reasons import (  # noqa: E402
    CP_DIAGBUNDLE_FORBIDDEN,
    CP_DIAGBUNDLE_STREAM_FORMAT,
    CP_DIAGBUNDLE_STREAM_SIZE,
    DiagBundleError,
)


_TMP = "/var/tmp"
_HEADER = struct.Struct(">8sII")
_RECORD = struct.Struct(">HQ32s")


def _encode(members: list[tuple[bytes, bytes]]) -> bytes:
    output = bytearray(_HEADER.pack(b"SPPDBN1\0", 1, len(members)))
    for path, payload in members:
        output += _RECORD.pack(len(path), len(payload), hashlib.sha256(payload).digest())
        output += path
        output += payload
    return bytes(output)


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as handle:
        handle.write(data)


def _expect(code: str, data: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-stream-", dir=_TMP) as tmp:
        path = os.path.join(tmp, "bundle.sppdbn")
        _write(path, data)
        try:
            with stream.capture_bundle(path):
                pass
        except DiagBundleError as exc:
            if exc.reason_code != code:
                raise AssertionError(f"expected {code}, got {exc.reason_code}: {exc}") from exc
            return
        raise AssertionError(f"expected {code}")


def test_positive_exact_capture_and_close() -> None:
    data = _encode([(b"a", b"alpha"), (b"b/c", b"beta")])
    with tempfile.TemporaryDirectory(prefix="diagbundle-stream-", dir=_TMP) as tmp:
        path = os.path.join(tmp, "bundle.sppdbn")
        _write(path, data)
        names_before = set(os.listdir(tmp))
        with stream.capture_bundle(path) as captured:
            assert captured.captured_size == len(data)
            assert tuple(captured.members) == ("a", "b/c")
            assert captured.members["a"].read_all(5) == b"alpha"
            private = captured.handle
            assert not private.writable()
            try:
                os.pwrite(private.fileno(), b"X", 0)
            except OSError as exc:
                assert exc.errno == errno.EBADF
            else:
                raise AssertionError("read-only private capture accepted a write")
            assert set(os.listdir(tmp)) == names_before
        assert private.closed
        assert set(os.listdir(tmp)) == names_before


def test_header_boundaries() -> None:
    positive = _encode([(b"a", b"x")])
    for data in (
        b"",
        positive[:15],
        b"X" + positive[1:],
        _HEADER.pack(b"SPPDBN1\0", 2, 1) + positive[_HEADER.size :],
    ):
        _expect(CP_DIAGBUNDLE_STREAM_FORMAT, data)
    _expect(CP_DIAGBUNDLE_STREAM_SIZE, _HEADER.pack(b"SPPDBN1\0", 1, 0))
    _expect(CP_DIAGBUNDLE_STREAM_SIZE, _HEADER.pack(b"SPPDBN1\0", 1, 8193))


def test_record_and_payload_boundaries() -> None:
    positive = _encode([(b"a", b"payload")])
    _expect(CP_DIAGBUNDLE_STREAM_FORMAT, positive[: _HEADER.size + _RECORD.size - 1])
    _expect(
        CP_DIAGBUNDLE_STREAM_FORMAT,
        _HEADER.pack(b"SPPDBN1\0", 1, 1)
        + _RECORD.pack(0, 0, hashlib.sha256(b"").digest()),
    )
    _expect(
        CP_DIAGBUNDLE_STREAM_FORMAT,
        _HEADER.pack(b"SPPDBN1\0", 1, 1)
        + _RECORD.pack(256, 0, hashlib.sha256(b"").digest()),
    )
    _expect(CP_DIAGBUNDLE_STREAM_FORMAT, positive[:-1])
    bad_digest = bytearray(positive)
    bad_digest[_HEADER.size + 10] ^= 1
    _expect(CP_DIAGBUNDLE_STREAM_FORMAT, bytes(bad_digest))
    _expect(CP_DIAGBUNDLE_STREAM_FORMAT, positive + b"x")


def test_path_encoding_normalization_and_order() -> None:
    invalid_paths = (
        b"\xff",
        b"/a",
        b"a\\b",
        b"a\x00b",
        b".",
        b"..",
        b"a//b",
        b"a/./b",
        b"a/../b",
        "e\u0301".encode("utf-8"),
    )
    for path in invalid_paths:
        _expect(CP_DIAGBUNDLE_STREAM_FORMAT, _encode([(path, b"x")]))
    _expect(CP_DIAGBUNDLE_STREAM_FORMAT, _encode([(b"b", b"x"), (b"a", b"y")]))
    _expect(CP_DIAGBUNDLE_STREAM_FORMAT, _encode([(b"a", b"x"), (b"a", b"y")]))


def test_private_key_markers_including_chunk_boundary() -> None:
    markers = (
        b"-----BEGIN PRIVATE KEY",
        b"-----BEGIN ENCRYPTED PRIVATE KEY",
        b"-----BEGIN RSA PRIVATE KEY",
        b"-----BEGIN EC PRIVATE KEY",
        b"-----BEGIN OPENSSH PRIVATE KEY",
        b"-----BEGIN DSA PRIVATE KEY",
    )
    for marker in markers:
        _expect(CP_DIAGBUNDLE_FORBIDDEN, _encode([(b"member", b"prefix" + marker + b"suffix")]))
    marker = markers[0]
    payload = b"x" * (1024 * 1024 - 7) + marker + b"tail"
    _expect(CP_DIAGBUNDLE_FORBIDDEN, _encode([(b"member", payload)]))


def test_capture_limit_without_large_allocation() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-stream-", dir=_TMP) as tmp:
        path = os.path.join(tmp, "bundle.sppdbn")
        _write(path, b"12345")
        prior = stream.MAX_CAPTURE_BYTES
        stream.MAX_CAPTURE_BYTES = 4
        try:
            try:
                with stream.capture_bundle(path):
                    pass
            except DiagBundleError as exc:
                assert exc.reason_code == CP_DIAGBUNDLE_STREAM_SIZE
            else:
                raise AssertionError("expected STREAM_SIZE")
        finally:
            stream.MAX_CAPTURE_BYTES = prior


def test_non_regular_and_hardlink_sources_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-stream-", dir=_TMP) as tmp:
        source = os.path.join(tmp, "source")
        hardlink = os.path.join(tmp, "hardlink")
        _write(source, _encode([(b"a", b"x")]))
        os.link(source, hardlink)
        for path in (source, hardlink, tmp):
            try:
                with stream.capture_bundle(path):
                    pass
            except DiagBundleError as exc:
                assert exc.reason_code == CP_DIAGBUNDLE_STREAM_FORMAT
            else:
                raise AssertionError("expected STREAM_FORMAT")


TESTS = (
    test_positive_exact_capture_and_close,
    test_header_boundaries,
    test_record_and_payload_boundaries,
    test_path_encoding_normalization_and_order,
    test_private_key_markers_including_chunk_boundary,
    test_capture_limit_without_large_allocation,
    test_non_regular_and_hardlink_sources_rejected,
)


if __name__ == "__main__":
    failed = 0
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report all cases
            failed += 1
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok   {test.__name__}")
    raise SystemExit(failed)
