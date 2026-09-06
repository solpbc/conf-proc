#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""PID1 collection of fixed cold workloads, with actual EOF and child reaping."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import selectors
import time

from conf_proc_json import canonical_loads
from conf_proc_spp_candidate_launch import launch_workload
from conf_proc_spp_candidate_workloads import appraise_asr_outputs, appraise_inference_outputs

MAX_RESULT = 4096
COLD_BUDGET_NS = 600_000_000_000
ROLES = ('inference', 'asr')


def appraise_cold_result(role: str, raw: bytes) -> tuple[str, ...]:
    if role not in ROLES or type(raw) is not bytes or not 1 <= len(raw) <= MAX_RESULT:
        raise ValueError('candidate cold result identity or size differs')
    result = canonical_loads(raw)
    if (type(result) is not dict or set(result) != {'role', 'outputs'}
            or result['role'] != role):
        raise ValueError('candidate cold result schema or canonical encoding differs')
    (appraise_inference_outputs if role == 'inference' else appraise_asr_outputs)(result['outputs'])
    return tuple(result['outputs'])


@dataclass(frozen=True)
class ColdResult:
    role: str
    pid: int
    raw: bytes
    outputs: tuple[str, ...]


class CandidateColdWorkloads:
    """Cold evidence only; this path never grants serving readiness or leases.

    The boot entry invokes each role within its kernel trace phase. A return
    requires the independently checked outputs, pipe EOF, successful native
    waitid status and an empty workload cgroup. No helper callback can assert
    completion on behalf of a live child.
    """

    def __init__(self, controller) -> None:
        self.controller = controller
        self.results: list[ColdResult] = []
        self._attempted: set[str] = set()

    def _quiescent(self) -> None:
        c = self.controller
        if (c.failed or c.cgroups is None or c.children or c.ledger.sessions
                or Path('/proc/self/task/1/children').read_text().strip()):
            raise RuntimeError('candidate cold interval is not quiescent')
        c.cgroups.check()
        if c.device_monitor is not None:
            c.device_monitor.check()

    def run(self, role: str) -> ColdResult:
        c = self.controller
        read_fd = write_fd = None
        registered = False
        try:
            self._quiescent()
            if (len(self.results) >= len(ROLES) or role != ROLES[len(self.results)]
                    or role in self._attempted or 'cold-' + role in c.results):
                raise RuntimeError('candidate cold invocation repeated or out of order')
            self._attempted.add(role)
            deadline = time.monotonic_ns() + COLD_BUDGET_NS
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
            os.set_blocking(read_fd, False)
            c.sessions.register(read_fd, selectors.EVENT_READ, ('cold-result', role))
            registered = True
            pid = launch_workload(c, role, 'cold', write_fd)
            os.close(write_fd)
            write_fd = None
            data = bytearray()
            eof = False
            while True:
                if time.monotonic_ns() >= deadline:
                    raise TimeoutError('candidate cold workload deadline expired')
                if not eof:
                    try:
                        chunk = os.read(read_fd, MAX_RESULT + 1 - len(data))
                    except BlockingIOError:
                        chunk = None
                    if chunk is not None:
                        data.extend(chunk)
                        if len(data) > MAX_RESULT:
                            raise RuntimeError('candidate cold result exceeds bound')
                        if not chunk:
                            eof = True
                            c.sessions.unregister(read_fd)
                            registered = False
                # Native waitid and cgroup readback dominate acceptance even
                # when a helper writes a valid result before crashing/hanging.
                c._reap()
                if eof and 'cold-' + role in c.results:
                    if c.results['cold-' + role] != (os.CLD_EXITED, 0):
                        raise RuntimeError('candidate cold exit was not successful')
                    self._quiescent()
                    c.cgroups.require_empty('cold-' + role)
                    raw = bytes(data)
                    result = ColdResult(role, pid, raw, appraise_cold_result(role, raw))
                    self.results.append(result)
                    return result
                for key, _mask in c.step():
                    if key.fd != read_fd or key.data != ('cold-result', role):
                        raise RuntimeError('unexpected event during candidate cold interval')
        except BaseException:
            c.fail_stop()
            raise
        finally:
            if registered:
                c.sessions.unregister(read_fd)
            for fd in (read_fd, write_fd):
                if fd is not None:
                    os.close(fd)
