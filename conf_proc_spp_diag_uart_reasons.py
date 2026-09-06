#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Closed reason vocabulary for the SPPUART/1 framing boundary."""

from __future__ import annotations

from typing import Final


CP_SPP_DIAG_UART_ASCII: Final = "CP_SPP_DIAG_UART_ASCII"
CP_SPP_DIAG_UART_BASE64: Final = "CP_SPP_DIAG_UART_BASE64"
CP_SPP_DIAG_UART_DEADLINE: Final = "CP_SPP_DIAG_UART_DEADLINE"
CP_SPP_DIAG_UART_HASH: Final = "CP_SPP_DIAG_UART_HASH"
CP_SPP_DIAG_UART_IDENTITY: Final = "CP_SPP_DIAG_UART_IDENTITY"
CP_SPP_DIAG_UART_KIND: Final = "CP_SPP_DIAG_UART_KIND"
CP_SPP_DIAG_UART_LIMIT: Final = "CP_SPP_DIAG_UART_LIMIT"
CP_SPP_DIAG_UART_SEQUENCE: Final = "CP_SPP_DIAG_UART_SEQUENCE"
CP_SPP_DIAG_UART_STATE: Final = "CP_SPP_DIAG_UART_STATE"
CP_SPP_DIAG_UART_WRITE: Final = "CP_SPP_DIAG_UART_WRITE"

ALL_CP_SPP_DIAG_UART_REASONS: Final = frozenset(
    (
        CP_SPP_DIAG_UART_ASCII,
        CP_SPP_DIAG_UART_BASE64,
        CP_SPP_DIAG_UART_DEADLINE,
        CP_SPP_DIAG_UART_HASH,
        CP_SPP_DIAG_UART_IDENTITY,
        CP_SPP_DIAG_UART_KIND,
        CP_SPP_DIAG_UART_LIMIT,
        CP_SPP_DIAG_UART_SEQUENCE,
        CP_SPP_DIAG_UART_STATE,
        CP_SPP_DIAG_UART_WRITE,
    )
)


class SppDiagUartError(RuntimeError):
    """A strict SPPUART/1 codec or transport error."""

    def __init__(self, reason_code: str) -> None:
        if reason_code not in ALL_CP_SPP_DIAG_UART_REASONS:
            raise ValueError("unknown SPP UART reason")
        self.reason_code = reason_code
        super().__init__(reason_code)
