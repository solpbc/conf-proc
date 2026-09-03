#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent literal checks for the SPPFLR1 failure terminal."""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from conf_proc_spp_diag_failure_terminal_reasons import (  # noqa: E402
    ALL_SPPFLR1_REASONS,
    FAILURE_TERMINAL_SIZE,
    SPPFLR1_BINDING,
    SPPFLR1_CHILD,
    SPPFLR1_EXPORT,
    SPPFLR1_GPU,
    SPPFLR1_IMA,
    SPPFLR1_INPUT,
    SPPFLR1_POLICY,
    SPPFLR1_ROOT,
    SPPFLR1_TPM,
    SPPFLR1_TRACE,
    SppDiagFailureTerminalError,
    encode_failure_terminal,
    parse_failure_terminal,
)


REASONS = (
    SPPFLR1_INPUT,
    SPPFLR1_ROOT,
    SPPFLR1_BINDING,
    SPPFLR1_POLICY,
    SPPFLR1_TRACE,
    SPPFLR1_CHILD,
    SPPFLR1_GPU,
    SPPFLR1_TPM,
    SPPFLR1_IMA,
    SPPFLR1_EXPORT,
)
CHALLENGE = bytes(range(32))
RUN = bytes(range(32, 64))


def literal_record(reason_code: int, phase: int, challenge: bytes = CHALLENGE, run: bytes = RUN) -> bytes:
    prefix = struct.pack(">8sHHI32s32s", b"SPPFLR1\0", 1, reason_code, phase, challenge, run)
    return prefix + hashlib.sha256(b"sol-spp-diag-failure-v1\0" + prefix).digest()


def test_pinned_wire_vectors() -> None:
    assert len(ALL_SPPFLR1_REASONS) == len(REASONS) == 10
    for reason_code, reason in enumerate(REASONS, start=1):
        encoded = encode_failure_terminal(reason, 0x1020304, CHALLENGE, RUN)
        assert encoded == literal_record(reason_code, 0x1020304)
        assert len(encoded) == FAILURE_TERMINAL_SIZE == 112
        decoded = parse_failure_terminal(
            encoded,
            expected_challenge=CHALLENGE,
            expected_run_identity=RUN,
        )
        assert (decoded.reason, decoded.reason_code, decoded.current_phase) == (reason, reason_code, 0x1020304)


def test_every_protected_bit_mutation_rejects() -> None:
    record = encode_failure_terminal(SPPFLR1_CHILD, 7, CHALLENGE, RUN)
    for byte_index in range(80):
        for bit in range(8):
            mutated = bytearray(record)
            mutated[byte_index] ^= 1 << bit
            try:
                parse_failure_terminal(bytes(mutated))
            except SppDiagFailureTerminalError:
                pass
            else:
                raise AssertionError((byte_index, bit))


def test_wrong_identity_unknown_reason_and_trailing_bytes_reject() -> None:
    record = literal_record(6, 7)
    invalid = (
        literal_record(0, 7),
        literal_record(11, 7),
        record + b"\0",
    )
    for candidate in invalid:
        try:
            parse_failure_terminal(candidate)
        except SppDiagFailureTerminalError:
            pass
        else:
            raise AssertionError("invalid failure record accepted")
    for kwargs in (
        {"expected_challenge": b"x" * 32},
        {"expected_run_identity": b"y" * 32},
    ):
        try:
            parse_failure_terminal(record, **kwargs)
        except SppDiagFailureTerminalError:
            pass
        else:
            raise AssertionError("wrong identity accepted")


def test_invalid_encoder_inputs_reject() -> None:
    cases = (
        ("SPPFLR1_UNKNOWN", 0, CHALLENGE, RUN),
        (SPPFLR1_EXPORT, -1, CHALLENGE, RUN),
        (SPPFLR1_EXPORT, 0x1_0000_0000, CHALLENGE, RUN),
        (SPPFLR1_EXPORT, 0, b"short", RUN),
        (SPPFLR1_EXPORT, 0, CHALLENGE, b"short"),
    )
    for args in cases:
        try:
            encode_failure_terminal(*args)
        except SppDiagFailureTerminalError:
            pass
        else:
            raise AssertionError("invalid failure-terminal input accepted")


TESTS = (
    test_pinned_wire_vectors,
    test_every_protected_bit_mutation_rejects,
    test_wrong_identity_unknown_reason_and_trailing_bytes_reject,
    test_invalid_encoder_inputs_reject,
)


if __name__ == "__main__":
    for test in TESTS:
        test()
    print("SPPFLR1 failure-terminal protocol: ok (%d tests)" % len(TESTS))
