#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Contract tests for shared SPP diagnostic PCR selections and bitmaps."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import conf_proc_spp_diag_attest as attest  # noqa: E402
import conf_proc_spp_diag_pcr as pcr  # noqa: E402


EXPECTED_PCR_SELECTION = (0, 2, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 22, 23)
EXPECTED_BASELINE_PCR_SELECTION = (0, 2, 4, 7, 8, 9, 11, 12, 13, 14, 15, 16, 22, 23)
EXPECTED_QUOTE_PCR_BITMAP = b"\x95\xff\xc1"


def test_literal_selection_and_bitmap_vectors() -> None:
    assert pcr.SPP_DIAG_PCR_SELECTION == EXPECTED_PCR_SELECTION
    assert pcr.SPP_DIAG_BASELINE_PCR_SELECTION == EXPECTED_BASELINE_PCR_SELECTION
    assert pcr.pcr_bitmap(EXPECTED_PCR_SELECTION) == EXPECTED_QUOTE_PCR_BITMAP
    assert pcr.pcr_bitmap((1, 8, 23)) == b"\x02\x01\x80"
    assert pcr.QUOTE_PCR_BITMAP == EXPECTED_QUOTE_PCR_BITMAP


def test_attestation_uses_shared_quote_bitmap() -> None:
    assert attest.SPP_DIAG_PCR_SELECTION == EXPECTED_PCR_SELECTION
    assert attest.SPP_DIAG_BASELINE_PCR_SELECTION == EXPECTED_BASELINE_PCR_SELECTION
    assert attest._QUOTE_PCR_BITMAP == EXPECTED_QUOTE_PCR_BITMAP
    assert attest._QUOTE_PCR_BITMAP is pcr.QUOTE_PCR_BITMAP


TESTS = (test_literal_selection_and_bitmap_vectors, test_attestation_uses_shared_quote_bitmap)


def main() -> None:
    for test in TESTS:
        test()
    print("spp diagnostic PCR shared protocol: ok (%d tests)" % len(TESTS))


if __name__ == "__main__":
    main()
