#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Stable public failures for SPP diagnostic UART evidence export."""

from __future__ import annotations

from typing import Final


CP_SPP_DIAG_EXPORT_MEMBER_NAME: Final = "CP_SPP_DIAG_EXPORT_MEMBER_NAME"
CP_SPP_DIAG_EXPORT_MEMBER_ORDER: Final = "CP_SPP_DIAG_EXPORT_MEMBER_ORDER"
CP_SPP_DIAG_EXPORT_MEMBER_SIZE: Final = "CP_SPP_DIAG_EXPORT_MEMBER_SIZE"
CP_SPP_DIAG_EXPORT_MEMBER_HASH: Final = "CP_SPP_DIAG_EXPORT_MEMBER_HASH"
CP_SPP_DIAG_EXPORT_TERMINAL: Final = "CP_SPP_DIAG_EXPORT_TERMINAL"
CP_SPP_DIAG_EXPORT_TRUNCATED: Final = "CP_SPP_DIAG_EXPORT_TRUNCATED"
CP_SPP_DIAG_EXPORT_TRAILING_BYTES: Final = "CP_SPP_DIAG_EXPORT_TRAILING_BYTES"

ALL_SPP_DIAG_EXPORT_REASONS: Final = frozenset(
    {
        CP_SPP_DIAG_EXPORT_MEMBER_NAME,
        CP_SPP_DIAG_EXPORT_MEMBER_ORDER,
        CP_SPP_DIAG_EXPORT_MEMBER_SIZE,
        CP_SPP_DIAG_EXPORT_MEMBER_HASH,
        CP_SPP_DIAG_EXPORT_TERMINAL,
        CP_SPP_DIAG_EXPORT_TRUNCATED,
        CP_SPP_DIAG_EXPORT_TRAILING_BYTES,
    }
)


class SppDiagExportError(RuntimeError):
    """One stable public UART-export reason code."""

    def __init__(self, reason_code: str) -> None:
        if reason_code not in ALL_SPP_DIAG_EXPORT_REASONS:
            raise ValueError("unknown SPP diagnostic export reason")
        self.reason_code = reason_code
        super().__init__(reason_code)
