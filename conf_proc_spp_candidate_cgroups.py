#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fixed cgroup-v2 limits and readbacks for the sealed candidate's children."""
from __future__ import annotations
import ctypes
import os
from pathlib import Path
import stat

from conf_proc_spp_diag_controller import _StatFs

ROOT = '/sys/fs/cgroup'
LIMITS = {
    'cold-inference': (32 * 1024**3, 128), 'inference': (32 * 1024**3, 128),
    'cold-asr': (16 * 1024**3, 128), 'asr': (16 * 1024**3, 128),
    'gateway': (1024**3, 32), 'collector': (1024**3, 32),
}
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _read(directory: int, name: str) -> str:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        data = b''
        while True:
            chunk = os.read(fd, 4097 - len(data))
            data += chunk
            if len(data) > 4096:
                raise RuntimeError('candidate cgroup read exceeds bound')
            if not chunk:
                return data.decode('ascii').strip()
    finally:
        os.close(fd)


def _write(directory: int, name: str, value: str) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        raw = value.encode('ascii')
        if os.write(fd, raw) != len(raw):
            raise RuntimeError('candidate cgroup write was partial')
    finally:
        os.close(fd)


def _counters(raw: str) -> dict[str, int]:
    result = {}
    for line in raw.splitlines():
        key, value = line.split()
        if key in result or not value.isascii() or not value.isdecimal():
            raise RuntimeError('candidate cgroup counter shape differs')
        result[key] = int(value)
    return result


def _directory(parent: int, name: str) -> int:
    fd = os.open(name, FLAGS, dir_fd=parent)
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid or st.st_gid or st.st_mode & 0o022:
            raise RuntimeError('candidate cgroup ownership differs')
        value = _StatFs()
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fstatfs.argtypes = (ctypes.c_int, ctypes.POINTER(_StatFs))
        libc.fstatfs.restype = ctypes.c_int
        if libc.fstatfs(fd, ctypes.byref(value)) != 0:
            raise OSError(ctypes.get_errno(), 'candidate cgroup filesystem readback')
        if value.f_type != 0x63677270:
            raise RuntimeError('candidate limits are not on cgroup-v2')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _enable(directory: int) -> None:
    required = {'memory', 'pids'}
    if not required <= set(_read(directory, 'cgroup.controllers').split()):
        raise RuntimeError('candidate resource controllers unavailable')
    _write(directory, 'cgroup.subtree_control', '+memory +pids')
    if not required <= set(_read(directory, 'cgroup.subtree_control').split()):
        raise RuntimeError('candidate resource controllers not enabled')


class CandidateCgroups:
    def __init__(self) -> None:
        if os.getpid() != 1 or os.getuid() != 0:
            raise RuntimeError('candidate cgroup setup requires PID1/root')
        self.groups: dict[str, int] = {}
        self.placed: dict[str, int] = {}
        root = _directory(-100, ROOT)
        parent = None
        try:
            _enable(root)
            os.mkdir('spp', 0o755, dir_fd=root)
            parent = _directory(root, 'spp')
            if _read(parent, 'cgroup.procs') or _read(parent, 'cgroup.type') != 'domain':
                raise RuntimeError('candidate cgroup hierarchy is not empty domain')
            _enable(parent)
            for role, (memory, pids) in LIMITS.items():
                os.mkdir(role, 0o755, dir_fd=parent)
                fd = _directory(parent, role)
                self.groups[role] = fd
                for name, value in (('memory.max', str(memory)), ('memory.swap.max', '0'),
                                    ('memory.oom.group', '1'), ('pids.max', str(pids))):
                    _write(fd, name, value)
                self._limits(role)
                if _read(fd, 'cgroup.procs') or _counters(_read(fd, 'cgroup.events')) != {'populated': 0, 'frozen': 0}:
                    raise RuntimeError('candidate child cgroup was populated')
        except BaseException:
            self.close()
            raise
        finally:
            if parent is not None:
                os.close(parent)
            os.close(root)

    def _limits(self, role: str) -> None:
        memory, pids = LIMITS[role]
        fd = self.groups[role]
        wanted = {'memory.max': str(memory), 'memory.swap.max': '0',
                  'memory.oom.group': '1', 'pids.max': str(pids), 'cgroup.type': 'domain'}
        if any(_read(fd, key) != value for key, value in wanted.items()):
            raise RuntimeError('candidate resource limit readback differs')
        memory_events = _counters(_read(fd, 'memory.events'))
        pids_events = _counters(_read(fd, 'pids.events'))
        if not {'max', 'oom', 'oom_kill'} <= memory_events.keys() or 'max' not in pids_events:
            raise RuntimeError('candidate resource pressure evidence unavailable')
        if any(memory_events.values()) or any(pids_events.values()):
            raise RuntimeError('candidate resource pressure exceeded policy')

    def place(self, role: str, pid: int) -> None:
        if role not in self.groups or role in self.placed or type(pid) is not int or pid <= 1:
            raise RuntimeError('candidate cgroup placement role or PID differs')
        fd = self.groups[role]
        self._limits(role)
        if (_read(fd, 'cgroup.procs')
                or _counters(_read(fd, 'cgroup.events')) != {'populated': 0, 'frozen': 0}):
            raise RuntimeError('candidate cgroup already occupied or frozen')
        _write(fd, 'cgroup.procs', str(pid))
        if (_read(fd, 'cgroup.procs') != str(pid)
                or Path(f'/proc/{pid}/cgroup').read_text() != f'0::/spp/{role}\n'
                or _counters(_read(fd, 'cgroup.events')) != {'populated': 1, 'frozen': 0}):
            raise RuntimeError('candidate child membership readback differs')
        self._limits(role)
        self.placed[role] = pid

    def check(self) -> None:
        for role in self.placed:
            self._limits(role)

    def require_empty(self, role: str) -> None:
        fd = self.groups[role]
        if _read(fd, 'cgroup.procs') or _counters(_read(fd, 'cgroup.events')) != {'populated': 0, 'frozen': 0}:
            raise RuntimeError('candidate descendants remain after child reap')
        self._limits(role)

    def close(self) -> None:
        # Closing monitor FDs does not remove or relax any kernel limit.
        for fd in self.groups.values():
            os.close(fd)
        self.groups.clear()
