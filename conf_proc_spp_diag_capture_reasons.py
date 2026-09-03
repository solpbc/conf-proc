#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Stable public failures for off-box SPP diagnostic UART capture."""

from __future__ import annotations

from typing import Final


CP_SPP_DIAG_CAPTURE_TYPE: Final = "CP_SPP_DIAG_CAPTURE_TYPE"
CP_SPP_DIAG_CAPTURE_IO: Final = "CP_SPP_DIAG_CAPTURE_IO"
CP_SPP_DIAG_CAPTURE_DEADLINE: Final = "CP_SPP_DIAG_CAPTURE_DEADLINE"
CP_SPP_DIAG_CAPTURE_PREAMBLE: Final = "CP_SPP_DIAG_CAPTURE_PREAMBLE"
CP_SPP_DIAG_CAPTURE_MARKER: Final = "CP_SPP_DIAG_CAPTURE_MARKER"
CP_SPP_DIAG_CAPTURE_SIZE: Final = "CP_SPP_DIAG_CAPTURE_SIZE"

ALL_SPP_DIAG_CAPTURE_REASONS: Final = frozenset(
    {
        CP_SPP_DIAG_CAPTURE_TYPE,
        CP_SPP_DIAG_CAPTURE_IO,
        CP_SPP_DIAG_CAPTURE_DEADLINE,
        CP_SPP_DIAG_CAPTURE_PREAMBLE,
        CP_SPP_DIAG_CAPTURE_MARKER,
        CP_SPP_DIAG_CAPTURE_SIZE,
    }
)


class SppDiagCaptureError(RuntimeError):
    """One stable public off-box capture reason code."""

    def __init__(self, reason_code: str) -> None:
        if reason_code not in ALL_SPP_DIAG_CAPTURE_REASONS:
            raise ValueError("unknown SPP diagnostic capture reason")
        self.reason_code = reason_code
        super().__init__(reason_code)
