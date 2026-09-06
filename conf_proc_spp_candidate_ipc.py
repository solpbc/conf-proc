#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Native authenticated seqpacket transport for the existing candidate v3 wire."""
from __future__ import annotations

import array
import os
import socket
import struct
from dataclasses import dataclass

from conf_proc_spp_boot_v3_wire import (
    FLAG_START_V3, FLAG_END_V3, FLAG_HAS_FD_V3, HEADER_SIZE_V3, MAX_CHUNK_PAYLOAD_BYTES_V3,
    SessionFdPayloadV3, ServingWireFrameV3, decode_serving_wire_frame_v3,
)

SO_COOKIE = 57
MAX_FRAME = HEADER_SIZE_V3 + MAX_CHUNK_PAYLOAD_BYTES_V3


def socket_identity(sock: socket.socket, epoch: int) -> SessionFdPayloadV3:
    if (sock.family != socket.AF_INET
            or sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
        raise ValueError('candidate session requires connected IPv4 stream')
    local, peer = sock.getsockname(), sock.getpeername()
    cookie = struct.unpack('=Q', sock.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8))[0]
    if not cookie:
        raise ValueError('candidate socket has no kernel identity')
    return SessionFdPayloadV3(epoch, socket.AF_INET, socket.inet_aton(local[0]), local[1],
                             socket.inet_aton(peer[0]), peer[1], cookie)


@dataclass
class ReceivedFrame:
    frame: ServingWireFrameV3
    descriptor: socket.socket | None


class CandidateWireEndpoint:
    """One thread, one peer, one queued frame; no blocking controller writes.

    Sequence numbers cover logical messages; chunk positions cover their frames.
    The caller handles v3 acknowledgements before queuing a subsequent chunk.
    All data is decoded by the existing closed codec before delivery.
    """

    def __init__(self, channel: socket.socket, peer_credentials: tuple[int, int, int]) -> None:
        if (channel.family != socket.AF_UNIX
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
                or type(peer_credentials) is not tuple or len(peer_credentials) != 3
                or any(type(x) is not int or x < 0 for x in peer_credentials)
                or peer_credentials[0] == 0):
            raise ValueError('invalid candidate IPC authority')
        self.channel = channel
        self.peer_credentials = peer_credentials
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        channel.setblocking(False)
        channel.set_inheritable(False)
        self._rx_sequence = 1
        self._tx_sequence = 1
        self._rx_train = None
        self._tx_train = None
        self._pending: tuple[bytes, socket.socket | None, ServingWireFrameV3] | None = None
        self._closed = False

    @staticmethod
    def _advance(frame: ServingWireFrameV3, sequence: int, train):
        h = frame.header
        count = (h.total_length + MAX_CHUNK_PAYLOAD_BYTES_V3 - 1) // MAX_CHUNK_PAYLOAD_BYTES_V3
        if (not 0 < h.total_length <= 8 * 1024 * 1024 + 44
                or not 1 <= h.chunk_count == count <= 513
                or not 0 <= h.chunk_index < count
                or h.chunk_length != min(MAX_CHUNK_PAYLOAD_BYTES_V3,
                    h.total_length - h.chunk_index * MAX_CHUNK_PAYLOAD_BYTES_V3)
                or bool(h.flags & FLAG_START_V3) != (h.chunk_index == 0)
                or bool(h.flags & FLAG_END_V3) != (h.chunk_index == count - 1)):
            raise ValueError('candidate IPC chunk shape or bound differs')
        identity = (h.message_type, h.session_token, h.chunk_count, h.total_length)
        index = 0 if train is None else train[1]
        if h.sequence != sequence or h.chunk_index != index or (train is not None and train[0] != identity):
            raise ValueError('candidate IPC replay or chunk discontinuity')
        if h.flags & FLAG_END_V3:
            return sequence + 1, None
        return sequence, (identity, index + 1)

    def queue(self, wire: bytes, descriptor: socket.socket | None = None) -> None:
        if self._closed or self._pending is not None:
            raise RuntimeError('candidate IPC write unavailable')
        frame = decode_serving_wire_frame_v3(wire)
        self._advance(frame, self._tx_sequence, self._tx_train)
        if bool(frame.header.flags & FLAG_HAS_FD_V3) != (descriptor is not None):
            raise ValueError('candidate IPC descriptor count differs')
        retained = None
        if descriptor is not None:
            if type(frame.payload) is not SessionFdPayloadV3:
                raise ValueError('candidate IPC descriptor payload differs')
            retained = descriptor.dup()
            try:
                if socket_identity(retained, frame.payload.session_epoch) != frame.payload:
                    raise ValueError('candidate outgoing socket identity differs')
            except BaseException:
                retained.close()
                raise
        self._pending = wire, retained, frame

    @property
    def wants_write(self) -> bool:
        return self._pending is not None

    def flush(self) -> bool:
        if self._closed:
            raise RuntimeError('candidate IPC closed')
        if self._pending is None:
            return True
        wire, descriptor, frame = self._pending
        ancillary = [] if descriptor is None else [
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [descriptor.fileno()]))]
        try:
            size = self.channel.sendmsg([wire], ancillary, socket.MSG_NOSIGNAL)
        except BlockingIOError:
            return False
        except BaseException:
            self.close()
            raise
        if size != len(wire):
            self.close()
            raise RuntimeError('candidate seqpacket write incomplete')
        self._tx_sequence, self._tx_train = self._advance(frame, self._tx_sequence, self._tx_train)
        if descriptor is not None:
            descriptor.close()
        self._pending = None
        return True

    def receive(self) -> ReceivedFrame | None:
        if self._closed:
            raise RuntimeError('candidate IPC closed')
        descriptors: list[int] = []
        retained = None
        try:
            try:
                data, ancillary, flags, _ = self.channel.recvmsg(
                    MAX_FRAME + 1, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(16), socket.MSG_CMSG_CLOEXEC)
            except BlockingIOError:
                return None
            credentials = []
            unknown = False
            for level, kind, payload in ancillary:
                if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                    values = array.array('i')
                    values.frombytes(payload[:len(payload) - len(payload) % values.itemsize])
                    descriptors.extend(values)
                    unknown |= len(payload) % values.itemsize != 0
                elif (level, kind) == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS) and len(payload) == 12:
                    credentials.append(struct.unpack('3i', payload))
                else:
                    unknown = True
            if (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or unknown
                    or not data or len(data) > MAX_FRAME or credentials != [self.peer_credentials]):
                raise ValueError('candidate IPC sender or datagram differs')
            frame = decode_serving_wire_frame_v3(data)
            sequence, train = self._advance(frame, self._rx_sequence, self._rx_train)
            if len(descriptors) != int(bool(frame.header.flags & FLAG_HAS_FD_V3)):
                raise ValueError('candidate IPC descriptor count differs')
            if descriptors:
                fd = descriptors.pop()
                try:
                    retained = socket.socket(fileno=fd)
                except BaseException:
                    os.close(fd)
                    raise
                if (os.get_inheritable(fd) or type(frame.payload) is not SessionFdPayloadV3
                        or socket_identity(retained, frame.payload.session_epoch) != frame.payload):
                    raise ValueError('candidate incoming socket identity differs')
            self._rx_sequence, self._rx_train = sequence, train
            result = ReceivedFrame(frame, retained)
            retained = None
            return result
        except BaseException:
            self.close()
            raise
        finally:
            for fd in descriptors:
                os.close(fd)
            if retained is not None:
                retained.close()

    def close(self) -> None:
        if self._pending is not None and self._pending[1] is not None:
            self._pending[1].close()
        self._pending = None
        self.channel.close()
        self._closed = True
