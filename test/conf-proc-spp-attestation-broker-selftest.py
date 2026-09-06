#!/usr/bin/env python3
"""Native broker IPC and fixed TPM commands; TPM response leaves substituted."""
from pathlib import Path
import array
import json
import os
import socket
import struct
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import conf_proc_spp_attestation_broker as m


def response(tag, body):
    return struct.pack('>HII', tag, len(body) + 10, 0) + body


def pcr_response(indices, counter=7):
    bitmap = bytearray(3)
    for n in indices:
        bitmap[n // 8] |= 1 << (n % 8)
    body = struct.pack('>IIHB', counter, 1, 11, 3) + bitmap + struct.pack('>I', len(indices))
    body += b''.join(b'\0\x20' + bytes([n]) * 32 for n in indices)
    return response(0x8001, body)


def quote_response():
    # An intentionally non-cryptographic response. The independent appraiser,
    # not this broker, must authenticate the real quote and its full context.
    parameters = b'\0\x08attested' + b'\0\x14\0\x0b\x01\0' + bytes(256)
    return response(0x8002, struct.pack('>I', len(parameters)) + parameters + b'\0\0\1\0\0')


class Transport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.commands = []

    def exchange(self, command):
        self.commands.append(command)
        value = self.responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


class BrokerTests(unittest.TestCase):
    def request(self, operation, sequence=1):
        return m.encode_request(operation, sequence, time.monotonic_ns() + 4_000_000_000,
                                b'\x22' * 32 if operation >= 3 else b'')

    def test_commands_match_independent_pinned_go_library(self):
        fixture = json.loads((Path(__file__).parent/'fixtures/spp-broker-go-tpm-v0.9.8.json').read_text())
        self.assertEqual(len(fixture['rows']), 4)
        for i, indices in enumerate((m.PCR14, m.PCR15)):
            transport = Transport(quote_response(), pcr_response(indices))
            service = m.FixedTpmService(transport)
            quote = self.request(3 + i)
            read = self.request(1 + i, 2)
            self.assertTrue(m.decode_response(service.handle(quote), quote))
            self.assertTrue(m.decode_response(service.handle(read), read))
            self.assertEqual([x.hex() for x in transport.commands],
                             [x['command_hex'] for x in fixture['rows'][i * 2:i * 2 + 2]])

    def test_partial_pcr_read_requires_progress_and_stable_counter(self):
        first, second = m.PCR14[:8], m.PCR14[8:]
        transport = Transport(pcr_response(first), pcr_response(second))
        request = self.request(1)
        body = m.decode_response(m.FixedTpmService(transport).handle(request), request)
        self.assertEqual(body[:5], b'\0\0\0\7\x0e')
        self.assertEqual(body[5:], b''.join(bytes([n]) * 33 for n in m.PCR14))
        self.assertEqual(len(transport.commands), 2)
        self.assertEqual(transport.commands[1][-3:], b'\0\xe0\xc1')
        for responses in ((pcr_response(first), pcr_response(second, 8)),
                          (pcr_response(()),), (pcr_response((1,)),),
                          (pcr_response(first), pcr_response(first)),
                          (pcr_response(m.PCR14)[:-1],)):
            service = m.FixedTpmService(Transport(*responses))
            with self.assertRaises((ValueError, RuntimeError)):
                service.handle(request)
            self.assertTrue(service.failed)

    def test_replay_and_failure_permanently_poison_service(self):
        transport = Transport(quote_response())
        service = m.FixedTpmService(transport)
        request = self.request(3)
        service.handle(request)
        with self.assertRaises(ValueError):
            service.handle(request)
        with self.assertRaises(ValueError):
            service.handle(self.request(3, 2))
        self.assertEqual(len(transport.commands), 1)
        for raw in (b'', request + b'x', b'WRONGMAG' + request[8:],
                    request[:9] + b'\5' + request[10:], self.request(3, 2)):
            transport = Transport()
            service = m.FixedTpmService(transport)
            with self.assertRaises(ValueError):
                service.handle(raw)
            self.assertTrue(service.failed)
            self.assertFalse(transport.commands)

    def test_quote_malformed_response_and_transport_failure_deny(self):
        good = quote_response()
        for raw in (good[:-1], good[:-3] + b'\0\0\0', b'\x80\x01' + good[2:],
                    good[:6] + b'\0\0\1\0' + good[10:], OSError('device failed')):
            service = m.FixedTpmService(Transport(raw))
            with self.assertRaises((ValueError, OSError)):
                service.handle(self.request(3))
            self.assertTrue(service.failed)

    def test_deadline_before_and_after_native_operation(self):
        now = time.monotonic_ns()
        for deadline in (now - 1, now + 10_000_000_000):
            service = m.FixedTpmService(Transport())
            request = m.encode_request(3, 1, deadline, bytes(32))
            with self.assertRaises((TimeoutError, ValueError)):
                service.handle(request)
            self.assertFalse(service.transport.commands)
        class SlowTransport:
            def exchange(self, _command):
                clock[0] += 6_000_000_000
                return quote_response()
        clock = [now]
        request = m.encode_request(3, 1, now + 4_000_000_000, bytes(32))
        with patch.object(m.time, 'monotonic_ns', side_effect=lambda: clock[0]):
            service = m.FixedTpmService(SlowTransport())
            with self.assertRaises(TimeoutError):
                service.handle(request)
            self.assertTrue(service.failed)

    def test_native_credentials_and_received_rights_are_closed(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        peer = (os.getpid(), os.getuid(), os.getgid())
        right.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        right.setblocking(False)
        fd = os.open('/dev/null', os.O_RDONLY)
        try:
            request = self.request(3)
            self.assertIsNone(m.receive(right, peer))
            left.send(request)
            self.assertEqual(m.receive(right, peer), request)
            left.send(request)
            with self.assertRaises(ValueError):
                m.receive(right, (peer[0] + 1, peer[1], peer[2]))
            before = set(os.listdir('/proc/self/fd'))
            left.sendmsg([request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
            with self.assertRaises(ValueError):
                m.receive(right, peer)
            self.assertEqual(set(os.listdir('/proc/self/fd')), before)
            left.close()
            with self.assertRaises(ValueError):
                m.receive(right, peer)
        finally:
            left.close(); right.close(); os.close(fd)

    def test_native_response_binding_and_expiration(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        left.setblocking(False)
        try:
            request = self.request(3)
            response = m.FixedTpmService(Transport(quote_response())).handle(request)
            m._send(left, response, m.HEADER.unpack(request[:m.HEADER.size])[-1])
            self.assertTrue(m.decode_response(right.recv(8192), request))
            with self.assertRaises(ValueError):
                m.decode_response(response, self.request(3, 2))
            with patch.object(m.time, 'monotonic_ns', return_value=m.HEADER.unpack(request[:m.HEADER.size])[-1]):
                with self.assertRaises(TimeoutError):
                    m.decode_response(response, request)
        finally:
            left.close(); right.close()


if __name__ == '__main__':
    unittest.main()
