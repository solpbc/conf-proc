#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Canonical SPPFLR1 diagnostic-failure terminal."""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Final


SPPFLR1_INPUT: Final = "SPPFLR1_INPUT"
SPPFLR1_ROOT: Final = "SPPFLR1_ROOT"
SPPFLR1_BINDING: Final = "SPPFLR1_BINDING"
SPPFLR1_POLICY: Final = "SPPFLR1_POLICY"
SPPFLR1_TRACE: Final = "SPPFLR1_TRACE"
SPPFLR1_CHILD: Final = "SPPFLR1_CHILD"
SPPFLR1_GPU: Final = "SPPFLR1_GPU"
SPPFLR1_TPM: Final = "SPPFLR1_TPM"
SPPFLR1_IMA: Final = "SPPFLR1_IMA"
SPPFLR1_EXPORT: Final = "SPPFLR1_EXPORT"

_REASON_CODES: Final = {
    SPPFLR1_INPUT: 1,
    SPPFLR1_ROOT: 2,
    SPPFLR1_BINDING: 3,
    SPPFLR1_POLICY: 4,
    SPPFLR1_TRACE: 5,
    SPPFLR1_CHILD: 6,
    SPPFLR1_GPU: 7,
    SPPFLR1_TPM: 8,
    SPPFLR1_IMA: 9,
    SPPFLR1_EXPORT: 10,
}
ALL_SPPFLR1_REASONS: Final = frozenset(_REASON_CODES)

# Compatibility names used by the phase controller map to the closed public enum.
SPPFLR1_CONTROL_WRITE: Final = SPPFLR1_TRACE
SPPFLR1_PHASE_SEQUENCE: Final = SPPFLR1_TRACE
SPPFLR1_CANARY_EXEC: Final = SPPFLR1_POLICY
SPPFLR1_NETWORK_DENIAL: Final = SPPFLR1_POLICY
SPPFLR1_CHILD_SUPERVISION: Final = SPPFLR1_CHILD
SPPFLR1_GPU_EVIDENCE: Final = SPPFLR1_GPU
SPPFLR1_IMA_EXTENSION: Final = SPPFLR1_IMA
SPPFLR1_QUOTE: Final = SPPFLR1_TPM
SPPFLR1_DEADLINE: Final = SPPFLR1_CHILD

FAILURE_TERMINAL_MAGIC: Final = b"SPPFLR1\0"
FAILURE_TERMINAL_VERSION: Final = 1
FAILURE_TERMINAL_SIZE: Final = 112
_FAILURE_PREFIX = struct.Struct(">8sHHI32s32s")
_FAILURE_RECORD = struct.Struct(">8sHHI32s32s32s")
_FAILURE_DIGEST_DOMAIN: Final = b"sol-spp-diag-failure-v1\0"


class SppDiagFailureTerminalError(RuntimeError):
    """The failure terminal is invalid."""

    def __init__(self, reason_code: str = SPPFLR1_EXPORT) -> None:
        if reason_code not in ALL_SPPFLR1_REASONS:
            raise ValueError("unknown SPP failure-terminal reason")
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class FailureTerminal:
    reason: str
    reason_code: int
    current_phase: int
    challenge: bytes
    run_identity: bytes


def encode_failure_terminal(
    reason: str,
    current_phase: int,
    challenge: bytes,
    run_identity: bytes,
) -> bytes:
    """Encode the identity-bound 112-byte ``SPPFLR1`` record."""

    if type(reason) is not str or reason not in _REASON_CODES:
        raise SppDiagFailureTerminalError()
    if type(current_phase) is not int or not 0 <= current_phase <= 0xFFFFFFFF:
        raise SppDiagFailureTerminalError()
    if type(challenge) is not bytes or len(challenge) != 32:
        raise SppDiagFailureTerminalError()
    if type(run_identity) is not bytes or len(run_identity) != 32:
        raise SppDiagFailureTerminalError()
    prefix = _FAILURE_PREFIX.pack(
        FAILURE_TERMINAL_MAGIC,
        FAILURE_TERMINAL_VERSION,
        _REASON_CODES[reason],
        current_phase,
        challenge,
        run_identity,
    )
    digest = hashlib.sha256(_FAILURE_DIGEST_DOMAIN + prefix).digest()
    record = prefix + digest
    assert len(record) == FAILURE_TERMINAL_SIZE
    return record


def parse_failure_terminal(
    record: bytes,
    *,
    expected_challenge: bytes | None = None,
    expected_run_identity: bytes | None = None,
) -> FailureTerminal:
    """Validate one complete failure record; never interpret it as a bundle result."""

    if type(record) is not bytes or len(record) != FAILURE_TERMINAL_SIZE:
        raise SppDiagFailureTerminalError()
    magic, version, reason_code, phase, challenge, run_identity, digest = _FAILURE_RECORD.unpack(record)
    by_code = {code: reason for reason, code in _REASON_CODES.items()}
    if magic != FAILURE_TERMINAL_MAGIC or version != FAILURE_TERMINAL_VERSION or reason_code not in by_code:
        raise SppDiagFailureTerminalError()
    expected_digest = hashlib.sha256(_FAILURE_DIGEST_DOMAIN + record[:80]).digest()
    if not hmac.compare_digest(digest, expected_digest):
        raise SppDiagFailureTerminalError()
    if expected_challenge is not None and not hmac.compare_digest(challenge, expected_challenge):
        raise SppDiagFailureTerminalError()
    if expected_run_identity is not None and not hmac.compare_digest(run_identity, expected_run_identity):
        raise SppDiagFailureTerminalError()
    return FailureTerminal(by_code[reason_code], reason_code, phase, challenge, run_identity)
