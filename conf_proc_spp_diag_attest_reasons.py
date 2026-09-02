#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Stable public failures for SPP diagnostic attestation."""

from __future__ import annotations

from typing import Final


CP_SPP_DIAG_ATTEST_TYPE: Final = "CP_SPP_DIAG_ATTEST_TYPE"
CP_SPP_DIAG_ATTEST_CAP: Final = "CP_SPP_DIAG_ATTEST_CAP"
CP_SPP_DIAG_ATTEST_X509: Final = "CP_SPP_DIAG_ATTEST_X509"
CP_SPP_DIAG_ATTEST_ROOT: Final = "CP_SPP_DIAG_ATTEST_ROOT"
CP_SPP_DIAG_ATTEST_CRL: Final = "CP_SPP_DIAG_ATTEST_CRL"
CP_SPP_DIAG_ATTEST_HCLA: Final = "CP_SPP_DIAG_ATTEST_HCLA"
CP_SPP_DIAG_ATTEST_SNP: Final = "CP_SPP_DIAG_ATTEST_SNP"
CP_SPP_DIAG_ATTEST_VCEK: Final = "CP_SPP_DIAG_ATTEST_VCEK"
CP_SPP_DIAG_ATTEST_AK: Final = "CP_SPP_DIAG_ATTEST_AK"
CP_SPP_DIAG_ATTEST_QUOTE: Final = "CP_SPP_DIAG_ATTEST_QUOTE"
CP_SPP_DIAG_ATTEST_PCR: Final = "CP_SPP_DIAG_ATTEST_PCR"
CP_SPP_DIAG_ATTEST_POLICY: Final = "CP_SPP_DIAG_ATTEST_POLICY"
CP_SPP_DIAG_ATTEST_PRIVACY: Final = "CP_SPP_DIAG_ATTEST_PRIVACY"

ALL_SPP_DIAG_ATTEST_REASONS: Final = frozenset(
    {
        CP_SPP_DIAG_ATTEST_TYPE,
        CP_SPP_DIAG_ATTEST_CAP,
        CP_SPP_DIAG_ATTEST_X509,
        CP_SPP_DIAG_ATTEST_ROOT,
        CP_SPP_DIAG_ATTEST_CRL,
        CP_SPP_DIAG_ATTEST_HCLA,
        CP_SPP_DIAG_ATTEST_SNP,
        CP_SPP_DIAG_ATTEST_VCEK,
        CP_SPP_DIAG_ATTEST_AK,
        CP_SPP_DIAG_ATTEST_QUOTE,
        CP_SPP_DIAG_ATTEST_PCR,
        CP_SPP_DIAG_ATTEST_POLICY,
        CP_SPP_DIAG_ATTEST_PRIVACY,
    }
)


class SppDiagAttestError(RuntimeError):
    """One stable public reason code."""

    def __init__(self, reason_code: str) -> None:
        if reason_code not in ALL_SPP_DIAG_ATTEST_REASONS:
            raise ValueError("unknown SPP diagnostic attestation reason")
        self.reason_code = reason_code
        super().__init__(reason_code)
