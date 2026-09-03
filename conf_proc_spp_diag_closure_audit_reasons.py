#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Stable public failures for independent SPP diagnostic closure auditing."""

from __future__ import annotations

from typing import Final


CP_SPP_DIAG_CLOSURE_AUDIT_RELATIVE_IMPORT: Final = "CP_SPP_DIAG_CLOSURE_AUDIT_RELATIVE_IMPORT"
CP_SPP_DIAG_CLOSURE_AUDIT_DYNAMIC_IMPORT: Final = "CP_SPP_DIAG_CLOSURE_AUDIT_DYNAMIC_IMPORT"
CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_ESCAPE: Final = "CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_ESCAPE"
CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_WILDCARD: Final = "CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_WILDCARD"
CP_SPP_DIAG_CLOSURE_AUDIT_UNREADABLE: Final = "CP_SPP_DIAG_CLOSURE_AUDIT_UNREADABLE"
CP_SPP_DIAG_CLOSURE_AUDIT_EXTERNAL: Final = "CP_SPP_DIAG_CLOSURE_AUDIT_EXTERNAL"

ALL_SPP_DIAG_CLOSURE_AUDIT_REASONS: Final = frozenset(
    {
        CP_SPP_DIAG_CLOSURE_AUDIT_RELATIVE_IMPORT,
        CP_SPP_DIAG_CLOSURE_AUDIT_DYNAMIC_IMPORT,
        CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_ESCAPE,
        CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_WILDCARD,
        CP_SPP_DIAG_CLOSURE_AUDIT_UNREADABLE,
        CP_SPP_DIAG_CLOSURE_AUDIT_EXTERNAL,
    }
)


class SppDiagClosureAuditError(RuntimeError):
    """One stable public closure-audit reason code."""

    def __init__(self, reason_code: str) -> None:
        if reason_code not in ALL_SPP_DIAG_CLOSURE_AUDIT_REASONS:
            raise ValueError("unknown SPP diagnostic closure-audit reason")
        self.reason_code = reason_code
        super().__init__(reason_code)
