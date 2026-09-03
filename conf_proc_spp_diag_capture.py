#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Bounded off-box capture of one SPP diagnostic UART result."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Callable, Final

from conf_proc_spp_diag_capture_reasons import (
    CP_SPP_DIAG_CAPTURE_DEADLINE,
    CP_SPP_DIAG_CAPTURE_IO,
    CP_SPP_DIAG_CAPTURE_MARKER,
    CP_SPP_DIAG_CAPTURE_PREAMBLE,
    CP_SPP_DIAG_CAPTURE_SIZE,
    CP_SPP_DIAG_CAPTURE_TYPE,
    SppDiagCaptureError,
)
from conf_proc_spp_diag_export import ExportedBundle, MAX_STREAM_BYTES, parse_export_stream
from conf_proc_spp_diag_failure_terminal_reasons import (
    FAILURE_TERMINAL_MAGIC,
    FAILURE_TERMINAL_SIZE,
    FailureTerminal,
    parse_failure_terminal,
)


SUCCESS_MARKER: Final = b"SPPDBN1\0"
FAILURE_MARKER: Final = FAILURE_TERMINAL_MAGIC
SUCCESS_STATUS: Final = "capture_complete_poweroff_intent"
FAILURE_STATUS: Final = "failure_terminal"
MAX_PREAMBLE_BYTES: Final = 1_048_576
CAPTURE_DEADLINE_SECONDS: Final = 1_800.0
_READ_BYTES: Final = 65_536
ReadChunk = Callable[[int, float], bytes]
Clock = Callable[[], float]


@dataclass(frozen=True)
class CapturedDiagnostic:
    status: str
    preamble_size: int
    preamble_sha256: bytes
    marker_monotonic: float
    terminal_monotonic: float
    stream: bytes
    exported: ExportedBundle | None
    failure: FailureTerminal | None


def _clock_value(monotonic: Clock) -> float:
    try:
        value = monotonic()
    except Exception as exc:
        raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_IO) from exc
    if type(value) not in (int, float) or not math.isfinite(value):
        raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_TYPE)
    return float(value)


def _marker_offset(data: bytearray) -> tuple[int, bytes] | None:
    positions = tuple(
        (offset, marker)
        for marker in (SUCCESS_MARKER, FAILURE_MARKER)
        if (offset := data.find(marker)) >= 0
    )
    if not positions:
        return None
    return min(positions, key=lambda item: item[0])


def _observation_time(observations: list[tuple[int, float]], absolute_end: int) -> float:
    for captured_size, observed in observations:
        if captured_size >= absolute_end:
            return observed
    raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_MARKER)


def capture_diagnostic_uart(
    read_chunk: ReadChunk,
    monotonic: Clock,
    *,
    expected_challenge: bytes,
    expected_run_identity: bytes,
) -> CapturedDiagnostic:
    """Capture one EOF-terminated UART result under the fixed 1,800-second bound.

    ``read_chunk`` must return at most the requested bytes and treats ``b""`` as
    final EOF. It receives the absolute deadline so a live reader can bound its
    own wait instead of hiding a blocking read behind this API.
    """

    if (
        not callable(read_chunk)
        or not callable(monotonic)
        or type(expected_challenge) is not bytes
        or len(expected_challenge) != 32
        or type(expected_run_identity) is not bytes
        or len(expected_run_identity) != 32
    ):
        raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_TYPE)

    deadline = _clock_value(monotonic) + CAPTURE_DEADLINE_SECONDS
    captured = bytearray()
    observations: list[tuple[int, float]] = []
    marker: tuple[int, bytes] | None = None

    while True:
        if _clock_value(monotonic) > deadline:
            raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_DEADLINE)
        try:
            chunk = read_chunk(_READ_BYTES, deadline)
        except SppDiagCaptureError:
            raise
        except Exception as exc:
            raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_IO) from exc
        observed = _clock_value(monotonic)
        if observed > deadline:
            raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_DEADLINE)
        if type(chunk) is not bytes:
            raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_TYPE)
        if len(chunk) > _READ_BYTES:
            raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_SIZE)
        if not chunk:
            break
        captured.extend(chunk)
        observations.append((len(captured), observed))
        if marker is None:
            marker = _marker_offset(captured)
            if marker is None and len(captured) > MAX_PREAMBLE_BYTES + len(SUCCESS_MARKER) - 1:
                raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_PREAMBLE)
            if marker is not None and marker[0] > MAX_PREAMBLE_BYTES:
                raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_PREAMBLE)
        if marker is not None:
            body_size = len(captured) - marker[0]
            maximum = MAX_STREAM_BYTES if marker[1] == SUCCESS_MARKER else FAILURE_TERMINAL_SIZE
            if body_size > maximum:
                raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_SIZE)

    if marker is None:
        raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_MARKER)
    marker_offset, marker_bytes = marker
    preamble = bytes(captured[:marker_offset])
    stream = bytes(captured[marker_offset:])
    if SUCCESS_MARKER in stream[1:] or FAILURE_MARKER in stream[1:]:
        raise SppDiagCaptureError(CP_SPP_DIAG_CAPTURE_MARKER)
    marker_time = _observation_time(observations, marker_offset + len(marker_bytes))

    if marker_bytes == SUCCESS_MARKER:
        exported = parse_export_stream(
            stream,
            expected_challenge=expected_challenge,
            expected_run_identity=expected_run_identity,
        )
        return CapturedDiagnostic(
            status=SUCCESS_STATUS,
            preamble_size=len(preamble),
            preamble_sha256=hashlib.sha256(preamble).digest(),
            marker_monotonic=marker_time,
            terminal_monotonic=_observation_time(observations, marker_offset + len(stream)),
            stream=stream,
            exported=exported,
            failure=None,
        )

    failure = parse_failure_terminal(
        stream,
        expected_challenge=expected_challenge,
        expected_run_identity=expected_run_identity,
    )
    return CapturedDiagnostic(
        status=FAILURE_STATUS,
        preamble_size=len(preamble),
        preamble_sha256=hashlib.sha256(preamble).digest(),
        marker_monotonic=marker_time,
        terminal_monotonic=_observation_time(observations, marker_offset + FAILURE_TERMINAL_SIZE),
        stream=stream,
        exported=None,
        failure=failure,
    )
