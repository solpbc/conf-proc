#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fixed shared vocabulary for controller/exporter failure termination with only stdlib imports."""

from __future__ import annotations

from typing import Final


SPPFLR1_CONTROL_WRITE: Final = "SPPFLR1_CONTROL_WRITE"
SPPFLR1_PHASE_SEQUENCE: Final = "SPPFLR1_PHASE_SEQUENCE"
SPPFLR1_CANARY_EXEC: Final = "SPPFLR1_CANARY_EXEC"
SPPFLR1_NETWORK_DENIAL: Final = "SPPFLR1_NETWORK_DENIAL"
SPPFLR1_CHILD_SUPERVISION: Final = "SPPFLR1_CHILD_SUPERVISION"
SPPFLR1_GPU_EVIDENCE: Final = "SPPFLR1_GPU_EVIDENCE"
SPPFLR1_IMA_EXTENSION: Final = "SPPFLR1_IMA_EXTENSION"
SPPFLR1_QUOTE: Final = "SPPFLR1_QUOTE"
SPPFLR1_DEADLINE: Final = "SPPFLR1_DEADLINE"
SPPFLR1_EXPORT: Final = "SPPFLR1_EXPORT"

_REASON_CODE_ORDER: Final = (
    SPPFLR1_CONTROL_WRITE,
    SPPFLR1_PHASE_SEQUENCE,
    SPPFLR1_CANARY_EXEC,
    SPPFLR1_NETWORK_DENIAL,
    SPPFLR1_CHILD_SUPERVISION,
    SPPFLR1_GPU_EVIDENCE,
    SPPFLR1_IMA_EXTENSION,
    SPPFLR1_QUOTE,
    SPPFLR1_DEADLINE,
    SPPFLR1_EXPORT,
)
ALL_SPPFLR1_REASONS: Final = frozenset(_REASON_CODE_ORDER)
_FAILURE_TERMINAL_MAGIC: Final = b"SPPFLR1\0"


class SppDiagFailureTerminalError(RuntimeError):
    """One stable public failure-terminal reason code."""

    def __init__(self, reason_code: str) -> None:
        if reason_code not in ALL_SPPFLR1_REASONS:
            raise ValueError("unknown SPP failure-terminal reason")
        self.reason_code = reason_code
        super().__init__(reason_code)


def encode_failure_terminal(reason_code: str, current_phase: int) -> bytes:
    """Encode 16 bytes: 8-byte ``SPPFLR1\\0`` magic, one-byte reason index, one-byte phase, six zero reserved bytes."""

    if type(reason_code) is not str or reason_code not in ALL_SPPFLR1_REASONS:
        raise SppDiagFailureTerminalError(SPPFLR1_EXPORT)
    if type(current_phase) is not int or not 0 <= current_phase <= 15:
        raise SppDiagFailureTerminalError(SPPFLR1_EXPORT)
    return _FAILURE_TERMINAL_MAGIC + bytes((_REASON_CODE_ORDER.index(reason_code), current_phase)) + bytes(6)
