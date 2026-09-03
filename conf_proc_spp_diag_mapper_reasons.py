#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Stable public failures for SPP diagnostic off-box mapping."""

from __future__ import annotations

from typing import Final


CP_SPP_DIAG_MAPPER_TYPE: Final = "CP_SPP_DIAG_MAPPER_TYPE"
CP_SPP_DIAG_MAPPER_SOURCE: Final = "CP_SPP_DIAG_MAPPER_SOURCE"
CP_SPP_DIAG_MAPPER_SEAM: Final = "CP_SPP_DIAG_MAPPER_SEAM"
CP_SPP_DIAG_MAPPER_OUTPUT: Final = "CP_SPP_DIAG_MAPPER_OUTPUT"
CP_SPP_DIAG_MAPPER_PCR: Final = "CP_SPP_DIAG_MAPPER_PCR"
CP_SPP_DIAG_MAPPER_PUBLISH: Final = "CP_SPP_DIAG_MAPPER_PUBLISH"

ALL_SPP_DIAG_MAPPER_REASONS: Final = frozenset(
    {
        CP_SPP_DIAG_MAPPER_TYPE,
        CP_SPP_DIAG_MAPPER_SOURCE,
        CP_SPP_DIAG_MAPPER_SEAM,
        CP_SPP_DIAG_MAPPER_OUTPUT,
        CP_SPP_DIAG_MAPPER_PCR,
        CP_SPP_DIAG_MAPPER_PUBLISH,
    }
)


class SppDiagMapperError(RuntimeError):
    """One stable public off-box mapping reason code."""

    def __init__(self, reason_code: str) -> None:
        if reason_code not in ALL_SPP_DIAG_MAPPER_REASONS:
            raise ValueError("unknown SPP diagnostic mapper reason")
        self.reason_code = reason_code
        super().__init__(reason_code)
