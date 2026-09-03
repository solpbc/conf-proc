#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftest for conf_proc_spp_diag_controller: wire encoding and phase choreography."""

from __future__ import annotations

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conf_proc_spp_diag_controller import (
    ControllerIdentity,
    ControllerOps,
    ControllerTerminated,
    encode_command,
    run_controller,
)
from conf_proc_spp_diag_failure_terminal_reasons import (
    SPPFLR1_CANARY_EXEC,
    SPPFLR1_CHILD_SUPERVISION,
    SPPFLR1_CONTROL_WRITE,
    SPPFLR1_DEADLINE,
    SPPFLR1_NETWORK_DENIAL,
)


def test_encode_command_literal_vector() -> None:
    challenge = bytes(range(32))
    run_identity = bytes(range(32, 64))
    control_plan_address = bytes([0xAA] * 32)
    encoded = encode_command(1, 2, challenge, run_identity, control_plan_address)
    assert len(encoded) == 128
    assert encoded[0:8] == b"SPPCMD1\x00"
    assert encoded[8:10] == (1).to_bytes(2, "big")  # version
    assert encoded[10:12] == (1).to_bytes(2, "big")  # kind = ADVANCE_PHASE
    assert encoded[12:16] == (128).to_bytes(4, "big")  # command_length
    assert encoded[16:48] == challenge
    assert encoded[48:80] == run_identity
    assert encoded[80:112] == control_plan_address
    assert encoded[112:114] == (2).to_bytes(2, "big")  # requested_phase
    assert encoded[114:128] == b"\x00" * 14
    seal = encode_command(2, 15, challenge, run_identity, control_plan_address)
    assert seal[10:12] == (2).to_bytes(2, "big")
    assert seal[112:114] == (15).to_bytes(2, "big")


class FakeRecorder:
    def __init__(self, *, deadline_seconds: float = 30.0):
        self.control_writes: list[bytes] = []
        self.read_calls = 0
        self.poweroff_calls: list[bytes] = []
        self.probe_failures: set[tuple] = set()
        self._clock = 1000.0
        self._deadline_seconds = deadline_seconds
        self.fail_at_clock_call = None
        self._clock_calls = 0

    def monotonic(self) -> float:
        self._clock_calls += 1
        if self.fail_at_clock_call == self._clock_calls:
            return self._clock + self._deadline_seconds + 1000.0
        self._clock += 0.01
        return self._clock

    def write_control(self, data: bytes) -> None:
        if ("write_control", len(self.control_writes)) in self.probe_failures:
            raise OSError("forced control write failure")
        self.control_writes.append(data)

    def read_stream(self, max_bytes: int) -> bytes:
        self.read_calls += 1
        return b"STREAMBYTES"

    def import_probe(self, module_name: str) -> bool:
        return ("import_probe", module_name) not in self.probe_failures

    def cdll_probe(self, path: str) -> bool:
        return ("cdll_probe", path) not in self.probe_failures

    def connect_probe(self, family: str, endpoint) -> bool:
        return ("connect_probe", family) not in self.probe_failures

    def exec_probe(self, path: str) -> bool:
        return ("exec_probe", path) not in self.probe_failures

    def jit_probe(self) -> bool:
        return "jit_probe" not in self.probe_failures

    def request_poweroff(self, record: bytes) -> None:
        self.poweroff_calls.append(record)

    def as_ops(self) -> ControllerOps:
        return ControllerOps(
            write_control=self.write_control,
            read_stream=self.read_stream,
            monotonic=self.monotonic,
            import_probe=self.import_probe,
            cdll_probe=self.cdll_probe,
            connect_probe=self.connect_probe,
            exec_probe=self.exec_probe,
            jit_probe=self.jit_probe,
            request_poweroff=self.request_poweroff,
        )


IDENTITY = ControllerIdentity(challenge=b"\x01" * 32, run_identity=b"\x02" * 32, control_plan_address=b"\x03" * 32)


def test_happy_path_full_phase_sequence() -> None:
    recorder = FakeRecorder()
    result = run_controller(recorder.as_ops(), IDENTITY)
    assert result == b"STREAMBYTES"
    phases_written = []
    kinds_written = []
    for command in recorder.control_writes:
        kinds_written.append(int.from_bytes(command[10:12], "big"))
        phases_written.append(int.from_bytes(command[112:114], "big"))
        assert command[16:48] == IDENTITY.challenge
        assert command[48:80] == IDENTITY.run_identity
        assert command[80:112] == IDENTITY.control_plan_address
    assert phases_written == [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    assert kinds_written == [1] * 13 + [2]
    assert recorder.read_calls == 1
    assert recorder.poweroff_calls == []


def test_no_pre_seal_read() -> None:
    recorder = FakeRecorder()
    run_controller(recorder.as_ops(), IDENTITY)
    # read_stream must only ever be called once, and only after all 14 writes.
    assert recorder.read_calls == 1


def test_poison_import_failure_terminates() -> None:
    recorder = FakeRecorder()
    recorder.probe_failures.add(("import_probe", "spp_diag_poison_module_absent"))
    try:
        run_controller(recorder.as_ops(), IDENTITY)
        raise AssertionError("expected ControllerTerminated")
    except ControllerTerminated as exc:
        assert exc.reason_code == SPPFLR1_CHILD_SUPERVISION
        assert exc.phase == 4
    assert len(recorder.poweroff_calls) == 1
    assert recorder.poweroff_calls[0][:8] == b"SPPFLR1\x00"
    assert recorder.poweroff_calls[0][9] == 4  # current_phase byte (offset 8 is the reason-code index)
    phases_written = [int.from_bytes(c[112:114], "big") for c in recorder.control_writes]
    assert phases_written == [2, 3, 4]
    assert recorder.read_calls == 0


def test_network_denial_failure_terminates() -> None:
    recorder = FakeRecorder()
    recorder.probe_failures.add(("connect_probe", "ipv6"))
    try:
        run_controller(recorder.as_ops(), IDENTITY)
        raise AssertionError("expected ControllerTerminated")
    except ControllerTerminated as exc:
        assert exc.reason_code == SPPFLR1_NETWORK_DENIAL
        assert exc.phase == 8
    phases_written = [int.from_bytes(c[112:114], "big") for c in recorder.control_writes]
    assert phases_written == [2, 3, 4, 5, 6, 7, 8]


def test_exec_canary_failure_terminates() -> None:
    recorder = FakeRecorder()
    recorder.probe_failures.add(("exec_probe", "/mnt/spp-diag-attached-disk-canary"))
    try:
        run_controller(recorder.as_ops(), IDENTITY)
        raise AssertionError("expected ControllerTerminated")
    except ControllerTerminated as exc:
        assert exc.reason_code == SPPFLR1_CANARY_EXEC
        assert exc.phase == 11
    phases_written = [int.from_bytes(c[112:114], "big") for c in recorder.control_writes]
    assert phases_written == [2, 3, 4, 5, 6, 7, 8, 9, 10, 11]


def test_control_write_failure_terminates() -> None:
    recorder = FakeRecorder()
    recorder.probe_failures.add(("write_control", 5))
    try:
        run_controller(recorder.as_ops(), IDENTITY)
        raise AssertionError("expected ControllerTerminated")
    except ControllerTerminated as exc:
        assert exc.reason_code == SPPFLR1_CONTROL_WRITE
        assert exc.phase == 7  # 6th write attempted (index 5) is phase 7's advance
    assert len(recorder.control_writes) == 5


def test_deadline_exceeded_terminates() -> None:
    recorder = FakeRecorder()
    recorder.fail_at_clock_call = 5
    try:
        run_controller(recorder.as_ops(), IDENTITY)
        raise AssertionError("expected ControllerTerminated")
    except ControllerTerminated as exc:
        assert exc.reason_code == SPPFLR1_DEADLINE


def test_module_does_not_import_appraiser_modules() -> None:
    source_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "conf_proc_spp_diag_controller.py")
    with open(source_path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    forbidden = {
        "conf_proc_spp_diag_trace_semantics",
        "conf_proc_spp_diag_attest",
        "conf_proc_spp_diagbundle",
        "conf_proc_spp_diag_trace_checkpoints",
        "conf_proc_spp_diag_ima",
    }
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not (imported & forbidden), imported & forbidden


def main() -> int:
    tests = [
        test_encode_command_literal_vector,
        test_happy_path_full_phase_sequence,
        test_no_pre_seal_read,
        test_poison_import_failure_terminates,
        test_network_denial_failure_terminates,
        test_exec_canary_failure_terminates,
        test_control_write_failure_terminates,
        test_deadline_exceeded_terminates,
        test_module_does_not_import_appraiser_modules,
    ]
    for test in tests:
        test()
        print(f"ok   {test.__name__}")
    print(f"SPP diagnostic controller: ok ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
