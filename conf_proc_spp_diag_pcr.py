#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Shared PCR selections and bitmaps for the appraiser and appliance producer; imports neither side's code."""

from __future__ import annotations

from typing import Final


SPP_DIAG_PCR_SELECTION: Final = (0, 2, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 22, 23)
SPP_DIAG_BASELINE_PCR_SELECTION: Final = (0, 2, 4, 7, 8, 9, 11, 12, 13, 14, 15, 16, 22, 23)


def pcr_bitmap(indices, size=3):
    bitmap = bytearray(size)
    for index in indices:
        bitmap[index // 8] |= 1 << (index % 8)
    return bytes(bitmap)


QUOTE_PCR_BITMAP: Final = pcr_bitmap(SPP_DIAG_PCR_SELECTION)
