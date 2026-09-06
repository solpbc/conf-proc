#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Bounded controller/gateway messages over the native credentialed v3 wire."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import socket
import time

import conf_proc_spp_boot_v3_wire as w
from conf_proc_spp_boot_v3_tables import ServingWireMessageTypeV3 as T
from conf_proc_spp_candidate_ipc import CandidateWireEndpoint

PACKET_NS = 5_000_000_000
COLLECTOR_NS = 180_000_000_000


@dataclass(frozen=True)
class CandidateMessage:
    kind: T
    token: bytes
    payload: object
    descriptor: socket.socket | None = None


class CandidateMessageChannel:
    """Nonblocking, one collector train with a checked ACK for every chunk.

    Only PID1 sends collector responses. Simultaneous incoming/outgoing trains
    are invalid; ordinary messages cannot interleave a train. tick() belongs in
    the controller's bounded event loop even when the channel stays idle.
    """
    def __init__(self, endpoint: CandidateWireEndpoint) -> None:
        self.endpoint = endpoint
        self._out = None
        self._in = None
        self._ack_expected = None
        self._ack_queued = False
        self._ready = None
        self._deadline = None
        self._overall = None
        self._closed = False

    def _packet(self, kind, token, raw, *, index=0, count=1, total=None, descriptor=None):
        flags = (w.FLAG_START_V3 if index == 0 else 0) | (w.FLAG_END_V3 if index == count-1 else 0)
        if descriptor is not None:
            flags |= w.FLAG_HAS_FD_V3
        wire = w.encode_serving_wire_frame_v3(kind, session_token=token,
            sequence=self.endpoint._tx_sequence, chunk_index=index, chunk_count=count,
            chunk_length=len(raw), total_length=len(raw) if total is None else total,
            flags=flags, payload_bytes=raw)
        self.endpoint.queue(wire, descriptor)
        self._deadline = time.monotonic_ns() + PACKET_NS

    def send(self, kind: T, token: bytes, raw: bytes, descriptor=None) -> None:
        self.tick()
        if (self._out is not None or self._in is not None or self._ready is not None
                or self.endpoint.wants_write or kind is T.CHUNK_ACK):
            raise RuntimeError('candidate message channel is busy or ACK is not owned')
        # Validate the full typed payload before sending the first byte.
        payload = w.WIRE_PAYLOAD_DECODERS_V3[kind](raw)
        if kind is T.COLLECTOR_RESPONSE:
            if descriptor is not None:
                raise ValueError('collector response cannot carry a descriptor')
            if (payload.result is w.CollectorResultV3.SUCCESS
                    and hashlib.sha256(payload.json_bytes).digest() != payload.stdout_sha256):
                raise ValueError('collector stdout digest differs')
            self._out = [token, raw, 0, hashlib.sha256()]
            self._overall = time.monotonic_ns() + COLLECTOR_NS
            self._next_chunk()
        else:
            self._packet(kind, token, raw, descriptor=descriptor)

    def _next_chunk(self):
        token, raw, index, digest = self._out
        size = w.MAX_CHUNK_PAYLOAD_BYTES_V3
        chunk = raw[index*size:(index+1)*size]
        count = (len(raw)+size-1)//size
        sequence = self.endpoint._tx_sequence
        self._packet(T.COLLECTOR_RESPONSE, token, chunk, index=index, count=count, total=len(raw))
        digest.update(chunk)
        self._ack_expected = (token, w.ChunkAckPayloadV3(sequence, index,
            min((index+1)*size, len(raw)), digest.digest()))

    def tick(self) -> None:
        if self._closed:
            raise RuntimeError('candidate message channel closed')
        now = time.monotonic_ns()
        if any(deadline is not None and now >= deadline for deadline in (self._deadline, self._overall)):
            self.close()
            raise TimeoutError('candidate message or chunk acknowledgement expired')

    @property
    def wants_write(self):
        return self.endpoint.wants_write

    def flush(self) -> bool:
        self.tick()
        try:
            if not self.endpoint.flush():
                return False
            self.tick()
            if self._ack_queued:
                self._ack_queued = False
                if self._ready is not None:
                    self._in = None
                    self._overall = None
                    self._deadline = None
                else:
                    self._deadline = time.monotonic_ns() + PACKET_NS
            elif self._out is not None or self._in is not None:
                # Keep the original absolute deadline; repeated writable events
                # cannot extend a missing acknowledgement's budget.
                pass
            else:
                self._deadline = None
            return True
        except BaseException:
            self.close()
            raise

    def receive(self) -> CandidateMessage | None:
        self.tick()
        if self._ready is not None and not self._ack_queued:
            result, self._ready = self._ready, None
            return result
        received = None
        try:
            received = self.endpoint.receive()
            self.tick()
            if received is None:
                return None
            frame = received.frame
            h = frame.header
            if h.message_type is T.CHUNK_ACK:
                if (self._ack_expected is None or self.endpoint.wants_write
                        or (h.session_token, frame.payload) != self._ack_expected):
                    raise ValueError('candidate chunk acknowledgement differs or is unsolicited')
                self._ack_expected = None
                self._out[2] += 1
                if self._out[2] * w.MAX_CHUNK_PAYLOAD_BYTES_V3 >= len(self._out[1]):
                    self._out = None
                    self._deadline = self._overall = None
                else:
                    self._next_chunk()
                return None
            if self._out is not None or self._ack_queued or self._ready is not None:
                raise ValueError('candidate message interleaves an outstanding chunk')
            if h.message_type is not T.COLLECTOR_RESPONSE:
                if self._in is not None:
                    raise ValueError('candidate message interleaves collector response')
                result = CandidateMessage(h.message_type, h.session_token, frame.payload, received.descriptor)
                received = None
                return result
            if self.endpoint.wants_write:
                raise ValueError('candidate collector response overlaps pending output')
            if self._in is None:
                self._in = [bytearray(), hashlib.sha256()]
                self._overall = time.monotonic_ns() + COLLECTOR_NS
            raw = (frame.payload if h.chunk_count > 1 else w.encode_collector_response_payload_v3(frame.payload))
            self._in[0].extend(raw)
            self._in[1].update(raw)
            if h.flags & w.FLAG_END_V3:
                payload = w.decode_collector_response_payload_v3(bytes(self._in[0]))
                if (payload.result is w.CollectorResultV3.SUCCESS
                        and hashlib.sha256(payload.json_bytes).digest() != payload.stdout_sha256):
                    raise ValueError('candidate received collector stdout digest differs')
                self._ready = CandidateMessage(T.COLLECTOR_RESPONSE, h.session_token, payload)
            self.tick()  # Full-payload decoding cannot reset an expired budget.
            ack = w.ChunkAckPayloadV3(h.sequence, h.chunk_index, len(self._in[0]), self._in[1].digest())
            self._packet(T.CHUNK_ACK, h.session_token, w.encode_chunk_ack_payload_v3(ack))
            self._ack_queued = True
            return None
        except BaseException:
            self.close()
            raise
        finally:
            if received is not None and received.descriptor is not None:
                received.descriptor.close()

    def close(self):
        self.endpoint.close()
        self._out = self._in = self._ready = self._ack_expected = None
        self._closed = True
