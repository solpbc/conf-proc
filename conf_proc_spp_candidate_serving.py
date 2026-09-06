#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Physical startup/readiness of the separate candidate GPU serving cohort.

The boot entry invokes this after the finite cold interval is sealed. A live
cohort result is input to fresh appraisal, never a lease or listener admission.
"""
from __future__ import annotations

import array
import ctypes
from dataclasses import dataclass
import hashlib
import os
import selectors
import socket
import struct
import time

from conf_proc_spp_boot_v3_wire import (
    StandaloneReadinessProbeV3, decode_standalone_readiness_result_v3,
    encode_standalone_readiness_probe_v3,
)
from conf_proc_spp_candidate_launch import launch_workload
from conf_proc_spp_candidate_workloads import runtime

STARTUP_NS = 600_000_000_000
ROLES = ('inference', 'asr')
PORTS = {'inference': 8000, 'asr': 8100}


def _read(path: str, cap: int) -> bytes:
    with open(path, 'rb') as source:
        result = source.read(cap + 1)
    if len(result) > cap:
        raise RuntimeError('candidate process evidence exceeds bound')
    return result


def _open_role_executable(pid: int, uid: int) -> int:
    """Open the child executable without retaining CAP_SYS_PTRACE.

    The target kernel permits this read under the role's filesystem credentials
    with an empty effective capability set. Real/effective UIDs stay PID1/root;
    restore filesystem IDs and the exact capability snapshot before returning.
    """
    from conf_proc_spp_candidate_isolation import _CapHeader, _CapData, PID1_CAPABILITIES
    if os.getpid() != 1 or os.getresuid() != (0, 0, 0) or os.listdir('/proc/self/task') != ['1']:
        raise RuntimeError('candidate executable census requires singleton PID1')
    libc = ctypes.CDLL(None, use_errno=True)
    for name in ('setfsuid', 'setfsgid'):
        getattr(libc, name).argtypes = (ctypes.c_uint,)
        getattr(libc, name).restype = ctypes.c_uint
    header = _CapHeader(0x20080522, 0)
    saved = (_CapData * 2)()
    if libc.capget(ctypes.byref(header), ctypes.byref(saved)) != 0:
        raise OSError(ctypes.get_errno(), 'candidate capability census')
    mask = sum(1 << bit for bit in PID1_CAPABILITIES)
    if (saved[0].effective != mask or saved[0].permitted != mask or saved[0].inheritable
            or bytes(saved[1]) != bytes(ctypes.sizeof(_CapData))
            or libc.setfsuid(0xffffffff) != 0 or libc.setfsgid(0xffffffff) != 0):
        raise RuntimeError('candidate executable census authority differs')
    reduced = (_CapData * 2).from_buffer_copy(bytes(saved))
    reduced[0].effective = reduced[1].effective = 0
    fd = None
    try:
        try:
            libc.setfsgid(uid); libc.setfsuid(uid)
            if (libc.setfsuid(0xffffffff) != uid or libc.setfsgid(0xffffffff) != uid
                    or libc.capset(ctypes.byref(header), ctypes.byref(reduced)) != 0):
                raise RuntimeError('candidate role filesystem credentials unavailable')
            observed = (_CapData * 2)()
            if libc.capget(ctypes.byref(header), ctypes.byref(observed)) != 0 or bytes(observed) != bytes(reduced):
                raise RuntimeError('candidate read-only capability state differs')
            fd = os.open(f'/proc/{pid}/exe', os.O_RDONLY | os.O_CLOEXEC)
        finally:
            libc.setfsgid(0); libc.setfsuid(0)
            restored = (_CapData * 2)()
            if (libc.capset(ctypes.byref(header), ctypes.byref(saved)) != 0
                    or libc.setfsuid(0xffffffff) != 0 or libc.setfsgid(0xffffffff) != 0
                    or libc.capget(ctypes.byref(header), ctypes.byref(restored)) != 0
                    or bytes(restored) != bytes(saved)):
                raise RuntimeError('candidate PID1 authority restoration failed')
        return fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise


def _process_identity(pid: int, role: str, expected_executable: bytes) -> tuple[int, bytes]:
    status = dict(line.split(':', 1) for line in _read(f'/proc/{pid}/status', 16384).decode('ascii').splitlines() if ':' in line)
    uid = runtime(role).uid
    for key in ('Uid', 'Gid'):
        if tuple(map(int, status[key].split())) != (uid,) * 4:
            raise RuntimeError('candidate serving process credentials differ')
    if int(status['PPid']) != 1 or status['NoNewPrivs'].strip() != '1':
        raise RuntimeError('candidate serving parent or privilege lock differs')
    if any(int(status[key], 16) for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')):
        raise RuntimeError('candidate serving process retained capabilities')
    if _read(f'/proc/{pid}/cgroup', 4096) != f'0::/spp/{role}\n'.encode():
        raise RuntimeError('candidate serving process left its cgroup')
    raw = _read(f'/proc/{pid}/stat', 16384).decode('ascii')
    fields = raw.rsplit(')', 1)[1].split()
    if fields[0] in ('Z', 'X'):
        raise RuntimeError('candidate serving process is dead')
    start_ticks = int(fields[19])  # field 22; suffix starts at field 3.
    digest = hashlib.sha256()
    size = 0
    with os.fdopen(_open_role_executable(pid, uid), 'rb') as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > 64 * 1024 * 1024:
                raise RuntimeError('candidate serving executable exceeds bound')
            digest.update(chunk)
    if not size or digest.digest() != expected_executable:
        raise RuntimeError('candidate serving executable differs from inspected input')
    return start_ticks, digest.digest()


def _receive(channel: socket.socket):
    """Close received rights even on a rejecting datagram; credentials only."""
    try:
        data, ancillary, flags, _ = channel.recvmsg(81, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4 * 8), socket.MSG_CMSG_CLOEXEC)
    except BlockingIOError:
        return None
    rights = []
    credentials = []
    invalid = bool(flags & ~socket.MSG_CMSG_CLOEXEC)
    for level, kind, raw in ancillary:
        if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            values = array.array('i')
            values.frombytes(raw[:len(raw) - len(raw) % values.itemsize])
            rights.extend(values)
            invalid = True
        elif (level, kind) == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS) and len(raw) == 12:
            credentials.append(struct.unpack('3i', raw))
        else:
            invalid = True
    for fd in rights:
        os.close(fd)
    if invalid or len(credentials) != 1 or len(data) != 80:
        raise RuntimeError('candidate readiness datagram shape differs')
    return decode_standalone_readiness_result_v3(data), credentials[0], data


@dataclass(frozen=True)
class ServingIdentity:
    role: str
    pid: int
    uid: int
    start_ticks: int
    executable_sha256: bytes
    readiness_wire: bytes


class CandidateServingWorkloads:
    def __init__(self, controller, expected_executables: dict[str, bytes]) -> None:
        if (type(expected_executables) is not dict or set(expected_executables) != set(ROLES)
                or any(type(value) is not bytes or len(value) != 32 or value == bytes(32)
                       for value in expected_executables.values())):
            raise ValueError('candidate serving requires independently inspected executable identities')
        self.controller = controller
        self.expected = dict(expected_executables)
        self.identities: list[ServingIdentity] = []
        self.listeners: dict[str, socket.socket] = {}
        self.channels: dict[str, socket.socket] = {}
        self.attempted: set[str] = set()

    def start(self, role: str) -> ServingIdentity:
        c = self.controller
        listener = parent = child = None
        registered = False
        try:
            if (c.failed or c.cgroups is None or c.ledger.sessions
                    or len(self.identities) >= 2 or role != ROLES[len(self.identities)]
                    or role in self.attempted
                    or set(c.children.values()) != {item.role for item in self.identities}
                    or any(c.results.get('cold-' + item) != (os.CLD_EXITED, 0) for item in ROLES)):
                raise RuntimeError('candidate serving startup is out of order')
            self.attempted.add(role)
            self.check()
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
            listener.bind(('127.0.0.1', PORTS[role]))
            listener.listen(1)
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            parent.setblocking(False)
            deadline = time.monotonic_ns() + STARTUP_NS
            probe = StandaloneReadinessProbeV3(ROLES.index(role) + 2, 1, deadline)
            wire = encode_standalone_readiness_probe_v3(probe)
            if parent.send(wire) != len(wire):
                raise RuntimeError('candidate readiness probe send incomplete')
            pid = launch_workload(c, role, 'serve', listener.fileno(), child.fileno())
            child.close(); child = None
            c.sessions.register(parent.fileno(), selectors.EVENT_READ, ('serving-readiness', role))
            registered = True
            while True:
                if time.monotonic_ns() >= deadline:
                    raise TimeoutError('candidate serving startup deadline expired')
                c._reap()
                received = _receive(parent)
                if received is not None:
                    result, credentials, raw = received
                    uid = runtime(role).uid
                    if (credentials != (pid, uid, uid) or result.role_id != probe.role_id
                            or result.flags != 1 or result.census_generation != 1
                            or result.absolute_monotonic_deadline_ns != deadline
                            or (result.supervised_child_pid, result.role_uid, result.role_gid) != credentials
                            or result.executable_sha256 != self.expected[role]):
                        raise RuntimeError('candidate serving readiness identity differs')
                    start_ticks, executable = _process_identity(pid, role, self.expected[role])
                    c._reap()
                    if c.children.get(pid) != role:
                        raise RuntimeError('candidate serving child disappeared')
                    c.cgroups.check()
                    if c.device_monitor is not None:
                        c.device_monitor.check()
                    if time.monotonic_ns() >= deadline:
                        raise TimeoutError('candidate readiness acceptance expired')
                    identity = ServingIdentity(role, pid, uid, start_ticks, executable, raw)
                    self.identities.append(identity)
                    self.listeners[role] = listener; listener = None
                    self.channels[role] = parent
                    return identity
                for key, _ in c.step():
                    if key.fd != parent.fileno() or key.data != ('serving-readiness', role):
                        raise RuntimeError('unexpected event during candidate serving startup')
        except BaseException:
            try:
                c.fail_stop()
            finally:
                self.close()
            raise
        finally:
            try:
                if registered:
                    c.sessions.unregister(parent.fileno())
            finally:
                for item in (listener, child):
                    if item is not None:
                        item.close()
                if parent is not None and role not in self.channels:
                    parent.close()

    def check(self) -> None:
        try:
            self._check()
        except BaseException:
            try:
                self.controller.fail_stop()
            finally:
                self.close()
            raise

    def _check(self) -> None:
        c = self.controller
        if c.failed:
            raise RuntimeError('candidate serving cohort revoked')
        c._reap()
        c.cgroups.check()
        if c.device_monitor is not None:
            c.device_monitor.check()
        for item in self.identities:
            if (c.children.get(item.pid) != item.role
                    or _process_identity(item.pid, item.role, self.expected[item.role]) !=
                       (item.start_ticks, item.executable_sha256)):
                raise RuntimeError('candidate serving cohort identity changed')
            # A duplicate response, EOF or unexpected rights invalidates census.
            if _receive(self.channels[item.role]) is not None:
                raise RuntimeError('candidate readiness response repeated')

    def close(self) -> None:
        for item in (*self.listeners.values(), *self.channels.values()):
            item.close()
        self.listeners.clear(); self.channels.clear()
