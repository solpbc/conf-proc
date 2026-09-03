#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent literal tests for bounded off-box SPP UART capture."""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from conf_proc_spp_diag_capture import (  # noqa: E402
    CAPTURE_DEADLINE_SECONDS,
    FAILURE_STATUS,
    MAX_PREAMBLE_BYTES,
    SUCCESS_STATUS,
    capture_diagnostic_uart,
)
from conf_proc_spp_diag_capture_reasons import (  # noqa: E402
    CP_SPP_DIAG_CAPTURE_DEADLINE,
    CP_SPP_DIAG_CAPTURE_MARKER,
    CP_SPP_DIAG_CAPTURE_PREAMBLE,
    CP_SPP_DIAG_CAPTURE_SIZE,
    CP_SPP_DIAG_CAPTURE_TYPE,
    SppDiagCaptureError,
)
from conf_proc_spp_diag_export_reasons import (  # noqa: E402
    CP_SPP_DIAG_EXPORT_TERMINAL,
    CP_SPP_DIAG_EXPORT_TRAILING_BYTES,
    SppDiagExportError,
)
from conf_proc_spp_diag_failure_terminal_reasons import (  # noqa: E402
    SPPFLR1_TRACE,
    SppDiagFailureTerminalError,
)


CHALLENGE = bytes.fromhex("11" * 32)
RUN = bytes.fromhex("22" * 32)
_NAMES = (
    "ak-public.pem", "firmware-event-log.bin", "gpu-evidence.tlv", "hcla.bin",
    "ima-measurements.bin", "inner-receipt/ak-tpmt-public.bin",
    "inner-receipt/firmware-event-log.sha256", "inner-receipt/gpu-evidence.sha256",
    "inner-receipt/ima-measurements.sha256", "inner-receipt/manifest.json",
    "inner-receipt/synthetic-output.bin", "inner-receipt/terminal-frame.bin",
    "inner-receipt/trace.bin", "quote.msg", "quote.pcrs", "quote.sig",
    "zz-capture-terminal.bin",
)
_HEADER = struct.Struct(">8sII")
_RECORD = struct.Struct(">HQ32s")


def _record(name: str, payload: bytes) -> bytes:
    name_bytes = name.encode("utf-8")
    return _RECORD.pack(len(name_bytes), len(payload), hashlib.sha256(payload).digest()) + name_bytes + payload


def _success_stream() -> bytes:
    prefix = bytearray(_HEADER.pack(b"SPPDBN1\0", 1, len(_NAMES)))
    for name in _NAMES[:-1]:
        prefix.extend(_record(name, ("payload:" + name).encode()))
    terminal = struct.pack(
        ">8sHH32s32s32s",
        b"SPPCAP1\0", 1, 1, CHALLENGE, RUN, hashlib.sha256(prefix).digest(),
    )
    return bytes(prefix) + _record(_NAMES[-1], terminal)


def _failure_stream() -> bytes:
    prefix = struct.pack(">8sHHI32s32s", b"SPPFLR1\0", 1, 5, 9, CHALLENGE, RUN)
    return prefix + hashlib.sha256(b"sol-spp-diag-failure-v1\0" + prefix).digest()


class Feed:
    def __init__(self, rows: list[tuple[float, bytes]]) -> None:
        self.rows = list(rows)
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def read(self, limit: int, deadline: float) -> bytes:
        assert limit == 65_536 and deadline == CAPTURE_DEADLINE_SECONDS
        if not self.rows:
            return b""
        self.now, chunk = self.rows.pop(0)
        return chunk


def _capture(rows: list[tuple[float, bytes]], *, challenge: bytes = CHALLENGE):
    feed = Feed(rows)
    return capture_diagnostic_uart(
        feed.read, feed.monotonic,
        expected_challenge=challenge, expected_run_identity=RUN,
    )


def _expect(reason: str, action) -> None:
    try:
        action()
    except SppDiagCaptureError as exc:
        assert exc.reason_code == reason, (exc.reason_code, reason)
    else:
        raise AssertionError(f"expected {reason}")


def test_literal_success_chunking_and_observations() -> None:
    stream = _success_stream()
    terminal = stream.rfind(b"SPPCAP1\0")
    preamble = b"firmware preamble\r\n"
    result = _capture([
        (1.0, preamble + stream[:3]),
        (2.0, stream[3:terminal + 8]),
        (3.0, stream[terminal + 8:]),
        (3.0, b""),
    ])
    assert result.status == SUCCESS_STATUS
    assert result.marker_monotonic == 2.0 and result.terminal_monotonic == 3.0
    assert result.preamble_size == len(preamble)
    assert result.preamble_sha256 == hashlib.sha256(preamble).digest()
    assert result.stream == stream and result.exported is not None and result.failure is None
    assert result.exported.challenge == CHALLENGE and result.exported.run_identity == RUN


def test_exact_preamble_and_deadline_boundaries() -> None:
    stream = _success_stream()
    exact = _capture(
        [(CAPTURE_DEADLINE_SECONDS, b"P" * 65_536)] * 16
        + [(CAPTURE_DEADLINE_SECONDS, stream), (CAPTURE_DEADLINE_SECONDS, b"")]
    )
    assert exact.preamble_size == MAX_PREAMBLE_BYTES
    _expect(
        CP_SPP_DIAG_CAPTURE_DEADLINE,
        lambda: _capture([(CAPTURE_DEADLINE_SECONDS + 0.001, stream)]),
    )
    _expect(
        CP_SPP_DIAG_CAPTURE_PREAMBLE,
        lambda: _capture([(1.0, b"P" * 65_536)] * 16 + [(2.0, b"P" * 8)]),
    )


def test_failure_terminal_is_distinct_and_bound() -> None:
    failure = _failure_stream()
    result = _capture([(1.0, b"boot" + failure[:7]), (2.0, failure[7:]), (2.0, b"")])
    assert result.status == FAILURE_STATUS and result.exported is None
    assert result.failure is not None and result.failure.reason == SPPFLR1_TRACE
    assert result.failure.current_phase == 9 and result.marker_monotonic == 2.0
    try:
        _capture([(1.0, failure + b"x"), (1.0, b"")])
    except (SppDiagCaptureError, SppDiagFailureTerminalError):
        pass
    else:
        raise AssertionError("failure suffix accepted")


def test_second_marker_suffix_and_identity_reject() -> None:
    stream = _success_stream()
    _expect(CP_SPP_DIAG_CAPTURE_MARKER, lambda: _capture([(1.0, stream + _failure_stream()), (1.0, b"")]))
    try:
        _capture([(1.0, stream + b"\0"), (1.0, b"")])
    except SppDiagExportError as exc:
        assert exc.reason_code == CP_SPP_DIAG_EXPORT_TRAILING_BYTES
    else:
        raise AssertionError("success suffix accepted")
    try:
        _capture([(1.0, stream), (1.0, b"")], challenge=b"\xff" * 32)
    except SppDiagExportError as exc:
        assert exc.reason_code == CP_SPP_DIAG_EXPORT_TERMINAL
    else:
        raise AssertionError("wrong challenge accepted")


def test_missing_marker_and_reader_contract_reject() -> None:
    _expect(CP_SPP_DIAG_CAPTURE_MARKER, lambda: _capture([(1.0, b"ordinary boot"), (1.0, b"")]))
    _expect(CP_SPP_DIAG_CAPTURE_TYPE, lambda: _capture([(1.0, "not bytes")]))  # type: ignore[list-item]
    _expect(CP_SPP_DIAG_CAPTURE_SIZE, lambda: _capture([(1.0, b"x" * 65_537)]))


TESTS = (
    test_literal_success_chunking_and_observations,
    test_exact_preamble_and_deadline_boundaries,
    test_failure_terminal_is_distinct_and_bound,
    test_second_marker_suffix_and_identity_reject,
    test_missing_marker_and_reader_contract_reject,
)


def main() -> int:
    for test in TESTS:
        test()
        print(f"ok   {test.__name__}")
    print(f"SPP diagnostic off-box capture: ok ({len(TESTS)} tests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
