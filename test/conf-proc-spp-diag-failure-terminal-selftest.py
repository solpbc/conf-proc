#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Contract tests for the fixed SPPFLR1 failure-terminal wire record."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from conf_proc_spp_diag_failure_terminal_reasons import (  # noqa: E402
    ALL_SPPFLR1_REASONS,
    SPPFLR1_CANARY_EXEC,
    SPPFLR1_CHILD_SUPERVISION,
    SPPFLR1_CONTROL_WRITE,
    SPPFLR1_DEADLINE,
    SPPFLR1_EXPORT,
    SPPFLR1_GPU_EVIDENCE,
    SPPFLR1_IMA_EXTENSION,
    SPPFLR1_NETWORK_DENIAL,
    SPPFLR1_PHASE_SEQUENCE,
    SPPFLR1_QUOTE,
    SppDiagFailureTerminalError,
    encode_failure_terminal,
)


ENCODING_FIXTURES = (
    (SPPFLR1_CONTROL_WRITE, 0, "535050464c5231000000000000000000"),
    (SPPFLR1_PHASE_SEQUENCE, 1, "535050464c5231000101000000000000"),
    (SPPFLR1_CANARY_EXEC, 2, "535050464c5231000202000000000000"),
    (SPPFLR1_NETWORK_DENIAL, 3, "535050464c5231000303000000000000"),
    (SPPFLR1_CHILD_SUPERVISION, 4, "535050464c5231000404000000000000"),
    (SPPFLR1_GPU_EVIDENCE, 5, "535050464c5231000505000000000000"),
    (SPPFLR1_IMA_EXTENSION, 6, "535050464c5231000606000000000000"),
    (SPPFLR1_QUOTE, 7, "535050464c5231000707000000000000"),
    (SPPFLR1_DEADLINE, 8, "535050464c5231000808000000000000"),
    (SPPFLR1_EXPORT, 15, "535050464c523100090f000000000000"),
)


def test_pinned_wire_vectors() -> None:
    assert len(ALL_SPPFLR1_REASONS) == 10
    for reason_code, current_phase, expected_hex in ENCODING_FIXTURES:
        encoded = encode_failure_terminal(reason_code, current_phase)
        assert encoded.hex() == expected_hex
        assert len(encoded) == 16


def test_invalid_inputs_reject() -> None:
    for reason_code, current_phase in (("SPPFLR1_UNKNOWN", 0), (SPPFLR1_EXPORT, -1), (SPPFLR1_EXPORT, 16)):
        try:
            encode_failure_terminal(reason_code, current_phase)
        except SppDiagFailureTerminalError:
            pass
        else:
            raise AssertionError("invalid failure-terminal input was accepted")
    try:
        SppDiagFailureTerminalError("SPPFLR1_UNKNOWN")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown reason code was accepted")


TESTS = (test_pinned_wire_vectors, test_invalid_inputs_reject)


def main() -> None:
    for test in TESTS:
        test()
    print("SPPFLR1 failure-terminal protocol: ok (%d tests)" % len(TESTS))


if __name__ == "__main__":
    main()
