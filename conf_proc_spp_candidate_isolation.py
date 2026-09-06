#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Candidate's network namespace and final PID1 capability boundary."""
from __future__ import annotations
import ctypes
import fcntl
import os
from pathlib import Path
import socket
import struct

CLONE_NEWNET = 0x40000000
# Workload launch/revocation and terminal poweroff; no namespace, module,
# network-admin/raw, ptrace, DAC override or mount authority survives.
PID1_CAPABILITIES = frozenset({5, 6, 7, 8, 18, 22})


def _require_singleton_pid1() -> None:
    if (os.getpid() != 1 or os.getresuid() != (0, 0, 0)
            or os.getresgid() != (0, 0, 0)
            or os.listdir('/proc/self/task') != ['1']
            or Path('/proc/self/task/1/children').read_text().strip()):
        raise RuntimeError('candidate isolation requires single-threaded childless PID1/root')


def _prctl(option: int, value: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(option, value, 0, 0, 0)
    if result < 0:
        raise OSError(ctypes.get_errno(), 'candidate privilege operation')
    return result


def _loopback_up() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as control:
        query = bytearray(40);query[:2] = b'lo'
        fcntl.ioctl(control.fileno(), 0x8913, query, True)  # SIOCGIFFLAGS
        flags = struct.unpack_from('H', query, 16)[0]
        struct.pack_into('H', query, 16, flags | 1)
        fcntl.ioctl(control.fileno(), 0x8914, query, True)  # SIOCSIFFLAGS
        fcntl.ioctl(control.fileno(), 0x8913, query, True)
        if not struct.unpack_from('H', query, 16)[0] & 1:
            raise RuntimeError('candidate loopback remained down')


def _netns() -> tuple[int, int]:
    node = os.stat('/proc/self/ns/net')
    return node.st_dev, node.st_ino


def require_loopback_only(expected: tuple[int, int]) -> None:
    if _netns() != expected:
        raise RuntimeError('candidate network namespace changed')
    names = {name for _, name in socket.if_nameindex()}
    if names != {'lo'}:
        raise RuntimeError('candidate workload network exposes an external interface')
    rows = Path('/proc/net/route').read_text().splitlines()
    if len(rows) != 1 or rows[0].split()[:3] != ['Iface', 'Destination', 'Gateway']:
        raise RuntimeError('candidate workload IPv4 route table is not empty')
    # IPv6 may retain only the local ::1/128 entry and unreachable default.
    # No non-loopback device exists, so neither family has external reachability.
    for line in Path('/proc/net/ipv6_route').read_text().splitlines():
        columns = line.split()
        if len(columns) != 10 or columns[-1] != 'lo':
            raise RuntimeError('candidate workload IPv6 route escaped loopback')


def enter_workload_network() -> tuple[int, int]:
    """Invoke after opening the fixed host-network sockets, before any child."""
    _require_singleton_pid1()
    before = _netns()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), 'candidate network namespace creation')
    after = _netns()
    if before == after:
        raise RuntimeError('candidate retained the host network namespace')
    _loopback_up()
    require_loopback_only(after)
    return after


class _CapHeader(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                ('inheritable', ctypes.c_uint32)]


def restrict_pid1_capabilities() -> None:
    _require_singleton_pid1()
    if Path('/proc/sys/kernel/cap_last_cap').read_text().strip() != '40':
        raise RuntimeError('candidate capability ABI differs')
    if _prctl(38, 1) != 0 or _prctl(39, 0) != 1:
        raise RuntimeError('candidate no-new-privileges readback differs')
    for capability in range(41):
        if capability not in PID1_CAPABILITIES:
            _prctl(24, capability)
        if _prctl(23, capability) != int(capability in PID1_CAPABILITIES):
            raise RuntimeError('candidate PID1 bounding-set readback differs')
    mask = sum(1 << capability for capability in PID1_CAPABILITIES)
    header = _CapHeader(0x20080522, 0)
    data = (_CapData * 2)()
    data[0].effective = data[0].permitted = mask
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), 'candidate PID1 capability freeze')
    got = (_CapData * 2)()
    if libc.capget(ctypes.byref(header), ctypes.byref(got)) != 0:
        raise OSError(ctypes.get_errno(), 'candidate PID1 capability readback')
    if (got[0].effective, got[0].permitted, got[0].inheritable,
        got[1].effective, got[1].permitted, got[1].inheritable) != (mask, mask, 0, 0, 0, 0):
        raise RuntimeError('candidate PID1 retained forbidden capabilities')
    values = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if any(int(values[key].strip(), 16) != mask for key in ('CapEff', 'CapPrm', 'CapBnd')) or any(
            int(values[key].strip(), 16) for key in ('CapInh', 'CapAmb')):
        raise RuntimeError('candidate PID1 final capability census differs')


class _Filter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]


class _Program(ctypes.Structure):
    _fields_ = [('length', ctypes.c_ushort), ('filters', ctypes.POINTER(_Filter))]


def freeze_namespace_transitions() -> None:
    """Inherited seccomp forbids namespace escape, including unprivileged clone."""
    _require_singleton_pid1()
    if os.uname().machine != 'x86_64' or _prctl(39, 0) != 1:
        raise RuntimeError('candidate seccomp requires fixed x86_64 and NNP')
    deny = 0x00050001  # SECCOMP_RET_ERRNO | EPERM
    allow = 0x7fff0000
    kill = 0x80000000
    # seccomp_data: nr@0, arch@4, args[0] low word@16.
    code = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xc000003e), (0x06, 0, 0, kill),
            (0x20, 0, 0, 0), (0x35, 0, 1, 0x40000000), (0x06, 0, 0, kill)]
    for number in (101, 155, 165, 166, 175, 176, 246, 250, 272, 304, 308, 313, 320, 321, 323):
        code += [(0x15, 0, 1, number), (0x06, 0, 0, deny)]
    # clone3's pointer argument cannot be inspected by classic BPF; ENOSYS
    # retains libc's documented fallback to inspectable clone for normal threads.
    code += [(0x15, 0, 1, 435), (0x06, 0, 0, 0x00050026),
             (0x15, 0, 3, 56), (0x20, 0, 0, 16),
             (0x45, 0, 1, 0x7e020000), (0x06, 0, 0, deny), (0x06, 0, 0, allow)]
    filters = (_Filter * len(code))(*(_Filter(*row) for row in code))
    program = _Program(len(code), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'candidate seccomp install')
    if _prctl(21, 0) != 2:
        raise RuntimeError('candidate seccomp filter readback differs')
