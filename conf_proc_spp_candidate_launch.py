#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fixed native fork/chroot/credential handoff for candidate GPU workloads."""
from __future__ import annotations

import ctypes
import fcntl
import os
from pathlib import Path
import resource
import select
import time
import signal
import stat

from conf_proc_spp_candidate_workloads import fixed_environment, launch_argv, runtime


def _duplicate_inputs(descriptors: tuple[int, ...]) -> tuple[int, ...]:
    """Preserve sources above fixed output slots before dup2 can overwrite any."""
    copies = []
    try:
        for fd in descriptors:
            copies.append(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 64))
        return tuple(copies)
    except BaseException:
        for fd in copies:
            os.close(fd)
        raise


def _install_fds(null_fd: int, result_or_listener: int, readiness: int | None) -> None:
    sources = (null_fd, result_or_listener) + (() if readiness is None else (readiness,))
    copies = _duplicate_inputs(sources)
    try:
        for target in (0, 1, 2):
            os.dup2(copies[0], target, inheritable=True)
        os.dup2(copies[1], 3, inheritable=True)
        if readiness is not None:
            os.dup2(copies[2], 4, inheritable=True)
        keep = {0, 1, 2, 3} | ({4} if readiness is not None else set())
        # Enumerate before chroot while the actual proc mount is available.
        for name in os.listdir('/proc/self/fd'):
            fd = int(name)
            if fd not in keep:
                try:
                    os.close(fd)
                except OSError:
                    # The directory fd used by listdir has already closed.
                    if Path('/proc/self/fd/' + name).exists():
                        raise
    except BaseException:
        for fd in copies:
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _drop_bounding_set() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_int
    # Drop the bounding set while CAP_SETPCAP is still available. NNP alone
    # would prevent gaining privilege but leave a falsely nonempty census.
    if Path('/proc/sys/kernel/cap_last_cap').read_text().strip() != '40':
        raise RuntimeError('candidate capability ABI differs')
    for capability in range(41):
        if libc.prctl(24, capability, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'candidate capability bounding drop')
        if libc.prctl(23, capability, 0, 0, 0) != 0:
            raise RuntimeError('candidate capability bounding readback differs')


def _drop_credentials(uid: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_int
    # No-new-privileges survives exec and prohibits setuid/file-cap transitions.
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(39, 0, 0, 0, 0) != 1:
        raise OSError(ctypes.get_errno(), 'candidate no-new-privileges')
    _drop_bounding_set()
    os.setgroups([])
    os.setresgid(uid, uid, uid)
    os.setresuid(uid, uid, uid)
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (uid, uid, uid) or os.getgroups():
        raise RuntimeError('candidate credential readback differs')
    status = Path('/proc/self/status').read_text()
    values = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
        if int(values[key].strip(), 16) != 0:
            raise RuntimeError('candidate retained process capabilities')
    if values['NoNewPrivs'].strip() != '1':
        raise RuntimeError('candidate privilege lock absent')


def _await_parent_release(fd: int) -> None:
    """No workload instruction executes before PID1's physical placement check."""
    deadline = time.monotonic() + 5.0
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise RuntimeError('candidate parent placement deadline expired')
        if os.read(fd, 2) != b'R':
            raise RuntimeError('candidate parent placement absent or malformed')
    finally:
        os.close(fd)


def _child_entry(role: str, mode: str, root_fd: int, null_fd: int,
                 result_or_listener: int, readiness: int | None) -> None:
    os.setsid()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (512, 512))
    resource.setrlimit(resource.RLIMIT_NPROC, (128, 128))
    os.fchdir(root_fd)
    # The current directory pins the root before descriptor remapping closes it.
    _install_fds(null_fd, result_or_listener, readiness)
    os.chroot('.')
    os.chdir('/')
    _drop_credentials(runtime(role).uid)
    for number in (signal.SIGCHLD, signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(number, signal.SIG_DFL)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    signal.pthread_sigmask(signal.SIG_SETMASK, set())
    argv = launch_argv(role, mode)
    os.execve(argv[0], argv, fixed_environment(role))


def launch_workload(controller, role: str, mode: str, result_or_listener: int,
                    readiness: int | None = None) -> int:
    """Launch only after the caller has mounted and appraised immutable inputs.

    PID1 retains listener/result ownership; this function supplies no serving
    admission. The existing controller must observe exit and separate readiness.
    """
    if os.getpid() != 1 or os.getuid() != 0 or controller.failed:
        raise RuntimeError('candidate workload launch requires active PID1')
    if controller.cgroups is None:
        raise RuntimeError('candidate resource controls must precede launch')
    argv = launch_argv(role, mode)
    if (mode == 'serve') != (readiness is not None):
        raise ValueError('candidate readiness FD shape differs')
    spec = runtime(role)
    root_fd = os.open(spec.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    null_fd = None
    gate_read = gate_write = None
    try:
        st = os.fstat(root_fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or not os.fstatvfs(root_fd).f_flag & os.ST_RDONLY:
            raise RuntimeError('candidate workload root is not immutable and root-owned')
        exe = Path(spec.root + argv[0])
        if not exe.is_file() or not os.access(exe, os.X_OK):
            raise RuntimeError('candidate fixed interpreter absent')
        null_fd = os.open('/dev/null', os.O_RDWR | os.O_CLOEXEC)
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        pid = controller.signals.run_event('launch_child')
        if pid == 0:
            try:
                os.close(gate_write)
                _await_parent_release(gate_read)
                _child_entry(role, mode, root_fd, null_fd, result_or_listener, readiness)
            except BaseException:
                os._exit(127)
        os.close(gate_read)
        gate_read = None
        child_role = ('cold-' if mode == 'cold' else '') + role
        controller.register_child(pid, child_role)
        controller.cgroups.place(child_role, pid)
        if os.write(gate_write, b'R') != 1:
            raise RuntimeError('candidate parent release write was partial')
        return pid
    except BaseException:
        controller.fail_stop()
        raise
    finally:
        for gate in (gate_read, gate_write):
            if gate is not None:
                os.close(gate)
        os.close(root_fd)
        if null_fd is not None:
            os.close(null_fd)
