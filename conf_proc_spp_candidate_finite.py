#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Actual cold-workload phases and one-way kernel trace sealing for a candidate."""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import os
import stat
import time

from conf_proc_spp_candidate_cold import CandidateColdWorkloads, ColdResult
from conf_proc_spp_diag_controller import (
    ControllerIdentity, encode_command, _real_direct, _POISONS, _NETWORKS,
    _EXEC_DENIALS, _JIT,
)

CONTROL = '/sys/kernel/security/sol_spp_diag_trace/control'
STREAM = '/sys/kernel/security/sol_spp_diag_trace/stream'
MAX_STREAM_BYTES = 8 * 1024 * 1024


def _fixed_file(fd: int, path: str, access: int) -> None:
    actual = os.fstat(fd)
    expected = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISREG(actual.st_mode)
            or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)
            or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != access
            or os.get_inheritable(fd)):
        raise RuntimeError('candidate kernel trace descriptor differs')


@dataclass(frozen=True)
class SealedColdInterval:
    cold: tuple[ColdResult, ColdResult]
    stream: bytes
    stream_sha256: bytes


class CandidateFiniteInterval:
    """No trace construction or serving authority: commands go to the kernel.

    Stage2 inherits the original kernel control at fd6 after its sealed resume.
    The read-only stream is opened only after the kernel acknowledges SEAL.
    Independent replay and IMA appraisal remain prerequisites to a lease.
    """
    def __init__(self, controller, identity: ControllerIdentity) -> None:
        if (type(identity) is not ControllerIdentity
                or any(type(value) is not bytes or len(value) != 32 for value in
                       (identity.challenge, identity.run_identity, identity.control_plan_address))):
            raise ValueError('candidate finite interval binding differs')
        _fixed_file(6, CONTROL, os.O_WRONLY)
        self.controller = controller
        self.identity = identity
        self.cold = CandidateColdWorkloads(controller)
        self.attempted = False
        self.phase = 1

    def _command(self, kind: int, phase: int) -> None:
        # User-space census reads belong to the workload interval. Negative
        # phases and the empty final phase permit only their fixed operations;
        # the kernel itself enforces quiescence on every transition.
        if phase in (2, 3, 4):
            self.cold._quiescent()
        if phase != self.phase + 1 or not 2 <= phase <= 15 or kind != (2 if phase == 15 else 1):
            raise RuntimeError('candidate trace phase transition differs')
        _fixed_file(6, CONTROL, os.O_WRONLY)
        i = self.identity
        raw = encode_command(kind, phase, i.challenge, i.run_identity, i.control_plan_address)
        if os.write(6, raw) != len(raw):
            raise RuntimeError('candidate kernel trace command not acknowledged')
        self.phase = phase

    def run(self) -> SealedColdInterval:
        if self.attempted:
            self.controller.fail_stop()
            raise RuntimeError('candidate finite interval cannot be repeated')
        self.attempted = True
        stream_fd = None
        try:
            for phase, role in ((2, 'inference'), (3, 'asr')):
                self._command(1, phase)
                self.cold.run(role)
            for phase, action, value in (
                (4, 'poison-open', _POISONS[0]), (5, 'poison-open', _POISONS[1]),
                (6, 'poison-open', _POISONS[2]), (7, 'network', _NETWORKS[0]),
                (8, 'network', _NETWORKS[1]), (9, 'network', _NETWORKS[2]),
                (10, 'exec-denial', _EXEC_DENIALS[0]), (11, 'exec-denial', _EXEC_DENIALS[1]),
                (12, 'exec-denial', _EXEC_DENIALS[2]), (13, 'jit', _JIT),
            ):
                self._command(1, phase)
                if _real_direct(action, value) is not True:
                    raise RuntimeError('candidate finite negative or JIT control failed')
            self._command(1, 14)
            self._command(2, 15)
            stream_fd = os.open(STREAM, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            _fixed_file(stream_fd, STREAM, os.O_RDONLY)
            deadline = time.monotonic_ns() + 30_000_000_000
            data = bytearray()
            while True:
                if time.monotonic_ns() >= deadline:
                    raise TimeoutError('candidate sealed trace read expired')
                chunk = os.read(stream_fd, min(65536, MAX_STREAM_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_STREAM_BYTES:
                    raise RuntimeError('candidate sealed trace exceeds bound')
            self.cold._quiescent()
            if not data or len(self.cold.results) != 2:
                raise RuntimeError('candidate sealed interval is incomplete')
            raw = bytes(data)
            return SealedColdInterval(tuple(self.cold.results), raw, hashlib.sha256(raw).digest())
        except BaseException:
            self.controller.fail_stop()
            raise
        finally:
            try:
                if stream_fd is not None:
                    os.close(stream_fd)
            finally:
                os.close(6)
