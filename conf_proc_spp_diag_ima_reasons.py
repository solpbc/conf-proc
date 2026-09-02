#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Stable public failures for SPP canonical IMA/PCR10 replay."""

from __future__ import annotations

from typing import Final


CP_SPP_DIAG_IMA_TYPE: Final = "CP_SPP_DIAG_IMA_TYPE"
CP_SPP_DIAG_IMA_IO: Final = "CP_SPP_DIAG_IMA_IO"
CP_SPP_DIAG_IMA_LENGTH: Final = "CP_SPP_DIAG_IMA_LENGTH"
CP_SPP_DIAG_IMA_CAP: Final = "CP_SPP_DIAG_IMA_CAP"
CP_SPP_DIAG_IMA_TEMPLATE: Final = "CP_SPP_DIAG_IMA_TEMPLATE"
CP_SPP_DIAG_IMA_DIGEST: Final = "CP_SPP_DIAG_IMA_DIGEST"
CP_SPP_DIAG_IMA_VIOLATION: Final = "CP_SPP_DIAG_IMA_VIOLATION"
CP_SPP_DIAG_IMA_PCR: Final = "CP_SPP_DIAG_IMA_PCR"
CP_SPP_DIAG_IMA_BUFFER: Final = "CP_SPP_DIAG_IMA_BUFFER"
CP_SPP_DIAG_IMA_CHECKPOINT: Final = "CP_SPP_DIAG_IMA_CHECKPOINT"
CP_SPP_DIAG_IMA_REPLAY: Final = "CP_SPP_DIAG_IMA_REPLAY"
CP_SPP_DIAG_IMA_PRIVACY: Final = "CP_SPP_DIAG_IMA_PRIVACY"

ALL_SPP_DIAG_IMA_REASONS: Final = frozenset(
    {
        CP_SPP_DIAG_IMA_TYPE,
        CP_SPP_DIAG_IMA_IO,
        CP_SPP_DIAG_IMA_LENGTH,
        CP_SPP_DIAG_IMA_CAP,
        CP_SPP_DIAG_IMA_TEMPLATE,
        CP_SPP_DIAG_IMA_DIGEST,
        CP_SPP_DIAG_IMA_VIOLATION,
        CP_SPP_DIAG_IMA_PCR,
        CP_SPP_DIAG_IMA_BUFFER,
        CP_SPP_DIAG_IMA_CHECKPOINT,
        CP_SPP_DIAG_IMA_REPLAY,
        CP_SPP_DIAG_IMA_PRIVACY,
    }
)


class SppDiagImaError(RuntimeError):
    """One stable reason and non-secret location fields."""

    def __init__(
        self, reason_code: str, entry_index: int | None, byte_offset: int
    ) -> None:
        if reason_code not in ALL_SPP_DIAG_IMA_REASONS:
            raise ValueError("unknown SPP diagnostic IMA reason")
        if entry_index is not None and type(entry_index) is not int:
            raise ValueError("invalid SPP diagnostic IMA location")
        if type(byte_offset) is not int:
            raise ValueError("invalid SPP diagnostic IMA location")
        self.reason_code = reason_code
        self.entry_index = entry_index
        self.byte_offset = byte_offset
        super().__init__(reason_code)
