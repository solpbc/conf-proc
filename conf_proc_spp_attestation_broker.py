#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fixed quote/PCR service over the inherited TPM resource-manager descriptor."""
from __future__ import annotations

import array
import fcntl
import hashlib
import os
import select
import socket
import stat
import struct
import time

from conf_proc_spp_candidate_tpm import NativeTpm, _command, _response
from conf_proc_spp_boot_v3_wire import (
    StandaloneReadinessResultV3, decode_standalone_readiness_probe_v3,
    encode_standalone_readiness_result_v3,
)

PCR14 = (0, 2, 4, 7, 8, 9, 11, 12, 13, 14, 15, 16, 22, 23)
PCR15 = tuple(sorted((*PCR14, 10)))
REQUEST = b'SPPTMQ1\0'
RESPONSE = b'SPPTMR1\0'
HEADER = struct.Struct('>8sBBHQQ')
MAX_RESPONSE = 4096
REQUEST_NS = 5_000_000_000


def _remaining(deadline: int) -> float:
    remaining = deadline - time.monotonic_ns()
    if remaining <= 0:
        raise TimeoutError('candidate broker request expired')
    return remaining / 1_000_000_000


def _selection(indices: tuple[int, ...]) -> bytes:
    return struct.pack('>IHB', 1, 0x000b, 3) + sum(1 << n for n in indices).to_bytes(3, 'little')


def quote_command(indices: tuple[int, ...], nonce: bytes) -> bytes:
    if indices not in (PCR14, PCR15) or type(nonce) is not bytes or len(nonce) != 32:
        raise ValueError('candidate broker quote selection or nonce differs')
    # Fixed Azure AK and empty password session. Encoding is independently
    # checked against google/go-tpm v0.9.8; no caller command buffer is accepted.
    auth = struct.pack('>IHBH', 0x40000009, 0, 0, 0)
    body = struct.pack('>II', 0x81000003, len(auth)) + auth
    body += struct.pack('>H', 32) + nonce + struct.pack('>HH', 0x0014, 0x000b)
    return _command(0x8002, 0x158, body + _selection(indices))


def encode_request(operation: int, sequence: int, deadline: int, nonce: bytes = b'') -> bytes:
    if (type(operation) is not int or operation not in (1, 2, 3, 4)
            or type(sequence) is not int or not 1 <= sequence < 1 << 64
            or type(deadline) is not int or not 0 < deadline < 1 << 64
            or type(nonce) is not bytes or len(nonce) != (32 if operation >= 3 else 0)):
        raise ValueError('candidate broker request fields differ')
    return HEADER.pack(REQUEST, 1, operation, len(nonce), sequence, deadline) + nonce


def decode_response(raw: bytes, request: bytes) -> bytes:
    expected = HEADER.unpack(request[:HEADER.size])
    if type(raw) is not bytes or not HEADER.size < len(raw) <= HEADER.size + MAX_RESPONSE:
        raise ValueError('candidate broker response bound differs')
    magic, version, operation, size, sequence, deadline = HEADER.unpack(raw[:HEADER.size])
    if ((magic, version, operation, sequence, deadline) !=
            (RESPONSE, 1, expected[2], expected[4], expected[5]) or size != len(raw) - HEADER.size):
        raise ValueError('candidate broker response binding differs')
    _remaining(deadline)
    return raw[HEADER.size:]


class FixedTpmService:
    """Only fixed PCR selections and fixed-AK quotes; poison after any ambiguity.

    Deadlines reject late results. Linux TPM poll/read/close can wait on an
    in-flight kernel operation, so PID1 must independently time the request
    and revoke authority. This class does not promise kernel cancellation.
    """
    def __init__(self, transport: NativeTpm) -> None:
        self.transport = transport
        self.sequence = 1
        self.failed = False

    def _exchange(self, command: bytes, deadline: int) -> bytes:
        _remaining(deadline)
        raw = self.transport.exchange(command)
        _remaining(deadline)
        return raw

    def _read(self, indices: tuple[int, ...], deadline: int) -> bytes:
        remaining = indices
        values = {}
        counter = None
        # TPMs can return only part of a selection. Each response must make
        # progress within the requested set and retain the update counter.
        for _ in indices:
            body = _response(self._exchange(_command(0x8001, 0x17e, _selection(remaining)), deadline), 0x8001)
            if len(body) < 18 or body[4:11] != struct.pack('>IHB', 1, 0x000b, 3):
                raise ValueError('candidate broker PCR response selection differs')
            observed_counter = int.from_bytes(body[:4], 'big')
            if counter is not None and counter != observed_counter:
                raise ValueError('candidate broker PCR update counter changed')
            counter = observed_counter
            bitmap = int.from_bytes(body[11:14], 'little')
            selected = tuple(n for n in range(24) if bitmap & (1 << n))
            count = int.from_bytes(body[14:18], 'big')
            if not selected or not set(selected) <= set(remaining) or count != len(selected) or len(body) != 18 + count * 34:
                raise ValueError('candidate broker PCR read made invalid progress')
            for i, n in enumerate(selected):
                offset = 18 + i * 34
                if body[offset:offset + 2] != b'\0\x20':
                    raise ValueError('candidate broker PCR digest size differs')
                values[n] = body[offset + 2:offset + 34]
            remaining = tuple(n for n in remaining if n not in values)
            if not remaining:
                return struct.pack('>IB', counter, len(indices)) + b''.join(bytes([n]) + values[n] for n in indices)
        raise RuntimeError('candidate broker PCR read incomplete')

    def _quote(self, indices: tuple[int, ...], nonce: bytes, deadline: int) -> bytes:
        body = _response(self._exchange(quote_command(indices, nonce), deadline), 0x8002)
        if len(body) < 11:
            raise ValueError('candidate broker quote response too short')
        size = int.from_bytes(body[:4], 'big')
        if len(body) != 4 + size + 5 or body[4 + size:] != b'\0\0\x01\0\0':
            raise ValueError('candidate broker quote authorization response differs')
        parameters = body[4:4 + size]
        length = int.from_bytes(parameters[:2], 'big')
        signature = parameters[2 + length:]
        if not 1 <= length <= 1024 or len(signature) != 262 or signature[:6] != b'\0\x14\0\x0b\x01\0':
            raise ValueError('candidate broker quote signature shape differs')
        return parameters

    def handle(self, raw: bytes) -> bytes:
        try:
            if self.failed or type(raw) is not bytes or not HEADER.size <= len(raw) <= HEADER.size + 32:
                raise ValueError('candidate broker request unavailable')
            magic, version, operation, size, sequence, deadline = HEADER.unpack(raw[:HEADER.size])
            nonce = raw[HEADER.size:]
            if (raw != encode_request(operation, sequence, deadline, nonce)
                    or sequence != self.sequence or size != len(nonce)
                    or magic != REQUEST or version != 1):
                raise ValueError('candidate broker request replay or framing differs')
            if deadline - time.monotonic_ns() > REQUEST_NS:
                raise ValueError('candidate broker request deadline exceeds bound')
            _remaining(deadline)
            indices = PCR14 if operation in (1, 3) else PCR15
            payload = self._read(indices, deadline) if operation <= 2 else self._quote(indices, nonce, deadline)
            _remaining(deadline)
            if not 0 < len(payload) <= MAX_RESPONSE:
                raise ValueError('candidate broker response exceeds bound')
            self.sequence += 1
            return HEADER.pack(RESPONSE, 1, operation, len(payload), sequence, deadline) + payload
        except BaseException:
            self.failed = True
            raise


def receive(channel: socket.socket, peer: tuple[int, int, int]) -> bytes | None:
    try:
        raw, ancillary, flags, _ = channel.recvmsg(81, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(32), socket.MSG_CMSG_CLOEXEC)
    except BlockingIOError:
        return None
    credentials = []
    invalid = bool(flags & ~socket.MSG_CMSG_CLOEXEC)
    for level, kind, data in ancillary:
        if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            values = array.array('i')
            values.frombytes(data[:len(data) - len(data) % values.itemsize])
            for fd in values:
                os.close(fd)
            invalid = True
        elif (level, kind) == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS) and len(data) == 12:
            credentials.append(struct.unpack('3i', data))
        else:
            invalid = True
    if invalid or not raw or credentials != [peer]:
        raise ValueError('candidate broker sender or ancillary data differs')
    return raw


def _send(channel: socket.socket, raw: bytes, deadline: int) -> None:
    while True:
        remaining = _remaining(deadline)
        if not select.select([], [channel], [], remaining)[1]:
            raise TimeoutError('candidate broker response blocked')
        try:
            size = channel.send(raw, socket.MSG_NOSIGNAL)
        except BlockingIOError:
            continue
        _remaining(deadline)
        if size != len(raw):
            raise RuntimeError('candidate broker response incomplete')
        return


def main() -> int:
    if os.getresuid() != (61100,) * 3 or os.getresgid() != (61100,) * 3 or os.getgroups():
        raise RuntimeError('candidate broker credentials differ')
    node = os.fstat(4)
    if not stat.S_ISCHR(node.st_mode) or fcntl.fcntl(4, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDWR:
        raise RuntimeError('candidate broker TPM transport differs')
    os.set_inheritable(4, False)
    os.set_blocking(4, False)
    if os.get_inheritable(4) or os.get_blocking(4):
        raise RuntimeError('candidate broker TPM flags readback differs')
    transport = NativeTpm.__new__(NativeTpm)
    transport.fd = 4
    channel = socket.socket(fileno=3)
    if channel.family != socket.AF_UNIX or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET:
        raise RuntimeError('candidate broker channel differs')
    channel.set_inheritable(False)
    channel.setblocking(False)
    channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    if channel.get_inheritable() or channel.getblocking() or channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1:
        raise RuntimeError('candidate broker channel flags readback differs')
    service = FixedTpmService(transport)
    try:
        deadline = time.monotonic_ns() + 4_000_000_000
        while True:
            if not select.select([channel], [], [], _remaining(deadline))[0]:
                raise TimeoutError('candidate broker readiness expired')
            raw = receive(channel, (1, 0, 0))
            if raw is not None:
                break
        probe = decode_standalone_readiness_probe_v3(raw)
        if probe.role_id != 1 or probe.absolute_monotonic_deadline_ns > deadline:
            raise ValueError('candidate broker readiness authority differs')
        with open('/proc/self/exe', 'rb') as source:
            executable = source.read(32 * 1024 * 1024 + 1)
        if not executable or len(executable) > 32 * 1024 * 1024:
            raise ValueError('candidate broker executable bound differs')
        result = StandaloneReadinessResultV3(1, 1, 1, probe.absolute_monotonic_deadline_ns,
            os.getpid(), 61100, 61100, hashlib.sha256(executable).digest())
        _send(channel, encode_standalone_readiness_result_v3(result), probe.absolute_monotonic_deadline_ns)
        while True:
            select.select([channel], [], [])
            raw = receive(channel, (1, 0, 0))
            if raw is None:
                continue
            response = service.handle(raw)
            _send(channel, response, HEADER.unpack(raw[:HEADER.size])[-1])
    finally:
        channel.close()  # Release authority before potentially blocking TPM close.
        transport.close()


if __name__ == '__main__':
    raise SystemExit(main())
