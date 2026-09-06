#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""PID1-owned kernel device-event subscription across the sealed handoff."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct

NETLINK_KOBJECT_UEVENT = 15
SO_COOKIE = 57
SO_RXQ_OVFL = 40


def device_census() -> tuple[tuple[str, str, str], ...]:
    """No block-device or PCI additions/removals can become an unnoticed sink."""
    rows = []
    for directory in ('/sys/class/block', '/sys/bus/pci/devices'):
        for name in sorted(os.listdir(directory)):
            path = Path(directory) / name
            target = path.resolve(strict=True)
            if not str(target).startswith('/sys/devices/'):
                raise RuntimeError('candidate device link escapes kernel devices')
            identity = ((path / 'dev').read_text().strip() if directory.endswith('block') else
                        (path / 'vendor').read_text().strip() + ':' + (path / 'device').read_text().strip())
            rows.append((directory + '/' + name, str(target), identity))
    if len(rows) > 512 or not any(row[0].startswith('/sys/class/block/') for row in rows):
        raise RuntimeError('candidate physical device census differs')
    return tuple(rows)


def _digest(value) -> bytes:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).digest()


def _adopt_handoff_socket() -> socket.socket:
    try:
        return socket.socket(fileno=4)
    except BaseException:
        # The handoff owns fd4 even when it is the wrong object. Construction
        # can reject a non-socket before a Python socket object owns its close.
        try:
            os.close(4)
        except OSError:
            pass
        raise


class DeviceMonitor:
    """After driver/device setup, every further device event fails closed.

    The socket remains subscribed in its original namespace after PID1 enters
    the workload network. No userspace event can be mistaken for a kernel one.
    """
    def __init__(self) -> None:
        if os.getpid() != 1 or os.getuid() != 0:
            raise RuntimeError('candidate device monitor requires PID1/root')
        self.socket = socket.socket(socket.AF_NETLINK,
            socket.SOCK_DGRAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK,
            NETLINK_KOBJECT_UEVENT)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, SO_RXQ_OVFL, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            self.socket.bind((1, 1))
            self.census = device_census()
            self.identity = self._identity()
            self.check()
        except BaseException:
            self.close()
            raise

    def _identity(self) -> dict:
        fd = self.socket.fileno()
        node = os.fstat(fd)
        if (not stat.S_ISSOCK(node.st_mode) or os.get_inheritable(fd) or os.get_blocking(fd)
                or self.socket.family != socket.AF_NETLINK
                or self.socket.proto != NETLINK_KOBJECT_UEVENT
                or self.socket.getsockname() != (1, 1)
                or self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1
                or self.socket.getsockopt(socket.SOL_SOCKET, SO_RXQ_OVFL) != 1):
            raise RuntimeError('candidate device monitor descriptor differs')
        return {'dev': node.st_dev, 'inode': node.st_ino,
                'cookie': self.socket.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8).hex(),
                'address': [1, 1], 'protocol': NETLINK_KOBJECT_UEVENT}

    def binding(self) -> bytes:
        self.check()
        return _digest({'socket': self.identity, 'devices': self.census})

    def move_to_handoff(self) -> bytes:
        digest = self.binding()
        if self.socket.fileno() != 4:
            # fd4 must have been freed by the boot entry; never overwrite it.
            try:
                os.fstat(4)
            except OSError as error:
                if error.errno != 9:
                    raise
            else:
                raise RuntimeError('candidate device handoff slot is occupied')
            os.dup2(self.socket.fileno(), 4, inheritable=False)
            self.socket.close()
            self.socket = _adopt_handoff_socket()
        if self.binding() != digest:
            raise RuntimeError('candidate device monitor changed during handoff')
        return digest

    @classmethod
    def resume(cls, expected: bytes) -> 'DeviceMonitor':
        if type(expected) is not bytes or len(expected) != 32 or os.getpid() != 1 or os.getuid() != 0:
            raise RuntimeError('candidate device monitor resume identity differs')
        value = cls.__new__(cls)
        value.socket = _adopt_handoff_socket()
        try:
            value.census = device_census()
            value.identity = value._identity()
            if value.binding() != expected:
                raise RuntimeError('candidate resumed device monitor binding differs')
            return value
        except BaseException:
            value.close()
            raise

    def check(self) -> None:
        if self._identity() != self.identity or device_census() != self.census:
            raise RuntimeError('candidate physical device identity changed')
        try:
            packet, ancillary, flags, address = self.socket.recvmsg(65536, 128)
        except BlockingIOError:
            return
        # Even a well-formed kernel event invalidates the quiescent sealed census;
        # malformed, truncated, lost or userspace-origin messages also revoke.
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or address[0] != 0:
            raise RuntimeError('candidate device event transport is invalid')
        credentials = [value for level, kind, value in ancillary
                       if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS]
        overflow = [value for level, kind, value in ancillary
                    if level == socket.SOL_SOCKET and kind == SO_RXQ_OVFL]
        if (credentials != [struct.pack('3i', 0, 0, 0)] or not packet
                or any(len(value) != 4 or struct.unpack('I', value)[0] for value in overflow)):
            raise RuntimeError('candidate device event authentication or delivery differs')
        raise RuntimeError('candidate received a device event after census sealing')

    def close(self) -> None:
        self.socket.close()
