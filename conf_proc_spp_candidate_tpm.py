#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Bounded native PCR15 read/extend/readback for the candidate boot manifest."""
from __future__ import annotations

import hashlib
import os
import select
import stat
import struct
import time


def _command(tag: int, command: int, body: bytes) -> bytes:
    return struct.pack('>HII', tag, 10 + len(body), command) + body


PCR15_READ = _command(0x8001, 0x17e, struct.pack('>IHB3s', 1, 0x000b, 3, b'\0\x80\0'))


def _response(raw: bytes, tag: int) -> bytes:
    if type(raw) is not bytes or len(raw) < 10 or len(raw) > 4096:
        raise ValueError('candidate TPM response size differs')
    actual_tag, size, result = struct.unpack_from('>HII', raw)
    if actual_tag != tag or size != len(raw) or result != 0:
        raise ValueError('candidate TPM command was not acknowledged')
    return raw[10:]


def parse_pcr15_read(raw: bytes) -> bytes:
    body = _response(raw, 0x8001)
    if len(body) != 52:
        raise ValueError('candidate PCR15 read size differs')
    # updateCounter is metadata; it never supplies the expected PCR value.
    if body[4:14] != struct.pack('>IHB3s', 1, 0x000b, 3, b'\0\x80\0'):
        raise ValueError('candidate PCR15 read selection differs')
    if body[14:20] != struct.pack('>IH', 1, 32):
        raise ValueError('candidate PCR15 digest list differs')
    return body[20:]


def pcr15_extend_command(digest: bytes) -> bytes:
    if type(digest) is not bytes or len(digest) != 32:
        raise ValueError('candidate manifest digest must be SHA256')
    password = struct.pack('>IHBH', 0x40000009, 0, 0, 0)
    body = struct.pack('>II', 15, len(password)) + password + struct.pack('>IH', 1, 0x000b) + digest
    return _command(0x8002, 0x182, body)


def parse_extend_ack(raw: bytes) -> None:
    # Empty parameters followed by empty nonce, continueSession=1, empty HMAC.
    if _response(raw, 0x8002) != struct.pack('>IHBH', 0, 0, 1, 0):
        raise ValueError('candidate PCR15 extend acknowledgement differs')


class NativeTpm:
    def __init__(self) -> None:
        self.fd = os.open('/dev/tpmrm0', os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
        info = os.fstat(self.fd)
        if not stat.S_ISCHR(info.st_mode):
            self.close()
            raise RuntimeError('candidate TPM transport is not a character device')

    def exchange(self, command: bytes) -> bytes:
        if type(command) is not bytes or not 10 <= len(command) <= 4096:
            raise ValueError('candidate TPM command size differs')
        deadline = time.monotonic() + 5
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [self.fd], [], remaining)[1]:
                raise TimeoutError('candidate TPM write expired')
            try:
                written = os.write(self.fd, command)
                break
            except BlockingIOError:
                continue
        if written != len(command):
            raise RuntimeError('candidate TPM write incomplete')
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.fd], [], [], remaining)[0]:
                raise TimeoutError('candidate TPM read expired')
            try:
                return os.read(self.fd, 4096)
            except BlockingIOError:
                continue

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class ManifestPcr15:
    def __init__(self, transport: NativeTpm) -> None:
        self.transport = transport
        self._attempted = False

    def measure(self, manifest_digest: bytes) -> bytes:
        command = pcr15_extend_command(manifest_digest)
        if self._attempted:
            raise RuntimeError('candidate PCR15 measurement cannot be retried')
        self._attempted = True
        initial = parse_pcr15_read(self.transport.exchange(PCR15_READ))
        if initial != bytes(32):
            raise RuntimeError('candidate PCR15 was not initially zero')
        expected = hashlib.sha256(bytes(32) + manifest_digest).digest()
        parse_extend_ack(self.transport.exchange(command))
        observed = parse_pcr15_read(self.transport.exchange(PCR15_READ))
        if observed != expected:
            raise RuntimeError('candidate PCR15 independent readback differs')
        return expected
