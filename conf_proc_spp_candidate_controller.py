#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Linux operations for the candidate's PID1 signal and child supervisor."""
from __future__ import annotations

import ctypes
import errno
import os
import signal
import struct

from conf_proc_spp_init import Stage2ControllerV3


class LinuxStage2KernelOpsV3:
    """Concrete Linux x86_64 signalfd/waitid provider for the existing controller."""

    def __init__(self) -> None:
        if os.uname().machine != 'x86_64' or ctypes.sizeof(ctypes.c_ulong) != 8:
            raise RuntimeError('candidate requires Linux x86_64 signal ABI')
        self._libc = ctypes.CDLL(None, use_errno=True)
        self._libc.signalfd.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
        self._libc.signalfd.restype = ctypes.c_int
        self._libc.sigemptyset.argtypes = (ctypes.c_void_p,)
        self._libc.sigaddset.argtypes = (ctypes.c_void_p, ctypes.c_int)
        self._mask = None
        self._fd = None
        self.exits: dict[int, tuple[int, int]] = {}

    def block_signals_exact(self, mask: tuple[str, ...]) -> None:
        if self._mask is not None:
            raise RuntimeError('signal mask already installed')
        values = {getattr(signal, name) for name in mask}
        signal.pthread_sigmask(signal.SIG_BLOCK, values)
        if signal.pthread_sigmask(signal.SIG_BLOCK, set()) != values:
            raise RuntimeError('unexpected inherited signal mask')
        self._mask = mask

    def set_signal_dispositions_exact(self) -> None:
        if self._mask is None:
            raise RuntimeError('signals must be blocked before dispositions')
        for name in self._mask:
            number = getattr(signal, name)
            signal.signal(number, signal.SIG_DFL)
            if signal.getsignal(number) != signal.SIG_DFL:
                raise RuntimeError('signal disposition readback differs')
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    def signalfd(self, mask: tuple[str, ...], flags: tuple[str, ...]) -> int:
        if (mask != self._mask or self._fd is not None
                or flags != ('SFD_NONBLOCK', 'SFD_CLOEXEC')):
            raise RuntimeError('unexpected signalfd setup')
        sigset = (ctypes.c_ulong * 16)()
        if self._libc.sigemptyset(ctypes.byref(sigset)) != 0:
            raise OSError(ctypes.get_errno(), 'sigemptyset')
        for name in mask:
            if self._libc.sigaddset(ctypes.byref(sigset), getattr(signal, name)) != 0:
                raise OSError(ctypes.get_errno(), 'sigaddset')
        fd = self._libc.signalfd(-1, ctypes.byref(sigset), os.O_NONBLOCK | os.O_CLOEXEC)
        if fd < 0:
            raise OSError(ctypes.get_errno(), 'signalfd')
        if os.get_blocking(fd) or os.get_inheritable(fd):
            os.close(fd)
            raise RuntimeError('signalfd flags readback differs')
        self._fd = fd
        return fd

    def read_signalfd_record(self, fd: int, size: int):
        if fd != self._fd or size != 128:
            raise RuntimeError('wrong signalfd read')
        while True:
            try:
                raw = os.read(fd, size)
                break
            except InterruptedError:
                continue
            except BlockingIOError:
                return ('EAGAIN', None, None, None)
        if len(raw) != size:
            raise RuntimeError('short signalfd read')
        number, _error, code = struct.unpack_from('<Iii', raw)
        name = signal.Signals(number).name
        codes = ({1: 'CLD_EXITED', 2: 'CLD_KILLED', 3: 'CLD_DUMPED'}
                 if number == signal.SIGCHLD else
                 {0: 'SI_USER', -1: 'SI_QUEUE', -6: 'SI_TKILL', 128: 'SI_KERNEL'})
        if code not in codes:
            raise RuntimeError('unsupported signalfd event')
        return ('record', raw, name, codes[code])

    def waitid(self, selector: str, ident: int, flags: tuple[str, ...]):
        if (selector, ident, flags) != ('P_ALL', 0, ('WEXITED', 'WNOHANG')):
            raise RuntimeError('unexpected child reap operation')
        while True:
            try:
                result = os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG)
                break
            except InterruptedError:
                continue
            except ChildProcessError:
                return ('ECHILD', 0)
        if result is None or result.si_pid == 0:
            return ('zero', 0)
        if result.si_pid in self.exits or len(self.exits) >= 256:
            raise RuntimeError('unconsumed or repeated child exit')
        self.exits[result.si_pid] = (result.si_code, result.si_status)
        return ('child', result.si_pid)

    def take_exit(self, pid: int) -> tuple[int, int]:
        return self.exits.pop(pid)

    def fork(self) -> int:
        if self._fd is None:
            raise RuntimeError('signal supervisor must precede child creation')
        return os.fork()

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


def make_signal_supervisor() -> tuple[Stage2ControllerV3, LinuxStage2KernelOpsV3, int]:
    ops = LinuxStage2KernelOpsV3()
    controller = Stage2ControllerV3(ops)
    try:
        fd = controller.run_event('install_signal_supervisor')
        return controller, ops, fd
    except BaseException:
        ops.close()
        raise


class CandidateController:
    """PID1 event loop: child events and lease expiry share one authority thread."""

    def __init__(self, device_monitor=None) -> None:
        if os.getpid() != 1 or os.getuid() != 0:
            raise RuntimeError('candidate controller requires namespace PID1/root')
        import selectors
        from conf_proc_spp_boot_v3_resource import ServingResourceReducerV3
        from conf_proc_spp_candidate_session import CandidateSessionOwner
        self.signals, self.kernel, fd = make_signal_supervisor()
        self.ledger = ServingResourceReducerV3()
        self.sessions = CandidateSessionOwner(self.ledger)
        self.sessions.register(fd, selectors.EVENT_READ, ('signal', None))
        self.children: dict[int, str] = {}
        self.results: dict[str, tuple[int, int]] = {}
        self.failed = False
        self.cgroups = None
        self.device_monitor = device_monitor
        if device_monitor is not None:
            try:
                device_monitor.check()
            except BaseException:
                self.fail_stop()
                raise

    def install_workload_limits(self) -> None:
        if self.failed or self.cgroups is not None or self.children:
            raise RuntimeError('candidate resource setup is out of order')
        from conf_proc_spp_candidate_cgroups import CandidateCgroups
        try:
            self.cgroups = CandidateCgroups()
        except BaseException:
            self.fail_stop()
            raise

    def register_child(self, pid: int, role: str) -> None:
        if (type(pid) is not int or pid <= 1 or pid in self.children
                or role not in ('cold-inference', 'cold-asr', 'inference', 'asr', 'gateway', 'collector')
                or role in self.children.values() or len(self.children) >= 6):
            self.fail_stop()
            raise RuntimeError('invalid candidate child census')
        self.children[pid] = role

    def _reap(self) -> None:
        for pid in self.signals.run_event('before_blocking_epoll_wait'):
            result = self.kernel.take_exit(pid)
            role = self.children.pop(pid, None)
            if role is None:
                self.fail_stop()
                raise RuntimeError('unregistered adopted child exit')
            if self.cgroups is not None:
                self.cgroups.require_empty(role)
            self.results[role] = result
            if role in ('inference', 'asr', 'gateway') or result != (os.CLD_EXITED, 0):
                self.fail_stop()
                raise RuntimeError('candidate cohort or workload failed')

    def step(self) -> list:
        """Only bounded nonblocking handlers may run between calls to step()."""
        if self.failed:
            raise RuntimeError('candidate controller revoked')
        try:
            return self._step()
        except BaseException:
            self.fail_stop()
            raise

    def _step(self) -> list:
        if self.device_monitor is not None:
            self.device_monitor.check()
        if self.cgroups is not None:
            self.cgroups.check()
        self._reap()
        events = self.sessions.wait()
        if self.device_monitor is not None:
            self.device_monitor.check()
        other = []
        for key, mask in events:
            if key.data == ('signal', None):
                for record in self.signals.run_event('signal_ready'):
                    number = struct.unpack_from('<I', record)[0]
                    if number != signal.SIGCHLD:
                        self.fail_stop()
                        raise RuntimeError('candidate termination signal')
                self._reap()
            else:
                other.append((key, mask))
        return other

    def fail_stop(self) -> None:
        """Revoke live sockets/grants before terminating every owned child."""
        if self.failed:
            return
        self.failed = True
        try:
            self.sessions.revoke_all()
        finally:
            # Construction requires PID1 in the appliance namespace. Kill all
            # descendants, including a worker that escaped its original group.
            try:
                if self.device_monitor is not None:
                    self.device_monitor.close()
            finally:
                try:
                    os.kill(-1, signal.SIGKILL)
                except ProcessLookupError:
                    pass
