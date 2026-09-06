#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Native seqpacket exchange with independently constructed rejecting packets."""
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import conf_proc_spp_boot_v3_wire as w
from conf_proc_spp_boot_v3_tables import ServingWireMessageTypeV3 as T
from conf_proc_spp_candidate_ipc import CandidateWireEndpoint
from conf_proc_spp_candidate_messages import CandidateMessageChannel

TOKEN = b't'*32
CREDS = (os.getpid(), os.getuid(), os.getgid())


def response(size=40000):
    raw = b'{"synthetic":"'+b'x'*size+b'"}'
    return w.encode_collector_response_payload_v3(w.CollectorResponsePayloadV3(
        w.CollectorGenerationV3.CERTIFICATE,w.CollectorResultV3.SUCCESS,0,123,0,
        hashlib.sha256(raw).digest(),raw))


def packet(kind,raw,seq=1,token=TOKEN,index=0,count=1,total=None):
    return w.encode_serving_wire_frame_v3(kind,session_token=token,sequence=seq,
        chunk_index=index,chunk_count=count,chunk_length=len(raw),total_length=len(raw) if total is None else total,
        flags=(w.FLAG_START_V3 if index==0 else 0)|(w.FLAG_END_V3 if index==count-1 else 0),payload_bytes=raw)


class Tests(unittest.TestCase):
    def setUp(self):
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.a=CandidateMessageChannel(CandidateWireEndpoint(a,CREDS))
        self.b=CandidateMessageChannel(CandidateWireEndpoint(b,CREDS))
    def tearDown(self):
        self.a.close();self.b.close()
    def test_actual_multichunk_and_single_response(self):
        for size in (40000,1):
            raw=response(size)
            self.a.send(T.COLLECTOR_RESPONSE,TOKEN,raw)
            received=None
            for _ in range(10):
                self.a.flush();self.assertIsNone(self.b.receive())
                self.b.flush();self.assertIsNone(self.a.receive())
                received=self.b.receive()
                if received is not None:break
            self.assertIsNotNone(received)
            self.assertEqual(w.encode_collector_response_payload_v3(received.payload),raw)
            self.assertEqual(received.token,TOKEN)
            self.assertIsNone(self.a._out)
    def test_no_next_chunk_without_ack(self):
        self.a.send(T.COLLECTOR_RESPONSE,TOKEN,response());self.a.flush()
        self.b.receive()
        self.assertFalse(self.a.wants_write)
        with self.assertRaises(RuntimeError):self.a.send(T.GATEWAY_READINESS_PROBE,bytes(32),b'x')
        before=self.a._deadline
        self.a.flush();self.assertEqual(self.a._deadline,before)
        with patch('time.monotonic_ns',return_value=before):
            with self.assertRaises(TimeoutError):self.a.tick()
        self.assertEqual(self.a.endpoint.channel.fileno(),-1)
    def test_receiver_deadline_survives_idle_flush(self):
        self.a.send(T.COLLECTOR_RESPONSE,TOKEN,response());self.a.flush()
        self.b.receive();self.b.flush()
        before=self.b._deadline
        self.b.flush();self.assertEqual(self.b._deadline,before)
        with patch('time.monotonic_ns',return_value=before):
            with self.assertRaises(TimeoutError):self.b.receive()
    def test_overall_deadline_not_extended_by_ack(self):
        self.a.send(T.COLLECTOR_RESPONSE,TOKEN,response());self.a.flush()
        overall=self.a._overall
        self.b.receive();self.b.flush();self.a.receive()
        self.assertEqual(self.a._overall,overall)
        self.a._deadline=overall+1
        with patch('time.monotonic_ns',return_value=overall):
            with self.assertRaises(TimeoutError):self.a.tick()
    def test_wrong_ack_digest_closes(self):
        self.a.send(T.COLLECTOR_RESPONSE,TOKEN,response());self.a.flush()
        self.b.endpoint.receive()
        token,ack=self.a._ack_expected
        bad=replace(ack,rolling_sha256=bytes(32))
        self.b.endpoint.channel.send(packet(T.CHUNK_ACK,w.encode_chunk_ack_payload_v3(bad)))
        with self.assertRaises(ValueError):self.a.receive()
        self.assertEqual(self.a.endpoint.channel.fileno(),-1)
    def test_duplicate_ack_closes(self):
        self.a.send(T.COLLECTOR_RESPONSE,TOKEN,response(1));self.a.flush()
        self.b.endpoint.receive()
        token,ack=self.a._ack_expected
        for seq in (1,2):
            self.b.endpoint.channel.send(packet(T.CHUNK_ACK,w.encode_chunk_ack_payload_v3(ack),seq))
            if seq==1:self.assertIsNone(self.a.receive())
            else:
                with self.assertRaises(ValueError):self.a.receive()
    def test_receiver_rejects_next_chunk_before_ack_sent(self):
        raw=response();size=w.MAX_CHUNK_PAYLOAD_BYTES_V3;count=(len(raw)+size-1)//size
        for index in (0,1):
            self.a.endpoint.channel.send(packet(T.COLLECTOR_RESPONSE,raw[index*size:(index+1)*size],
                index=index,count=count,total=len(raw)))
            if index==0:self.assertIsNone(self.b.receive())
            else:
                with self.assertRaises(ValueError):self.b.receive()
    def test_full_response_validated_before_delivery(self):
        raw=bytearray(response(1));raw[12]^=1
        self.a.endpoint.channel.send(packet(T.COLLECTOR_RESPONSE,bytes(raw)))
        with self.assertRaises(ValueError):self.b.receive()
        self.assertIsNone(self.b._ready)
    def test_send_rejects_digest_before_output(self):
        raw=bytearray(response());raw[12]^=1
        with self.assertRaises(ValueError):self.a.send(T.COLLECTOR_RESPONSE,TOKEN,bytes(raw))
        self.assertIsNone(self.b.endpoint.receive())
    def test_ordinary_readiness_message(self):
        raw=w.encode_gateway_readiness_probe_payload_v3(w.GatewayReadinessProbePayloadV3(1,12345))
        self.a.send(T.GATEWAY_READINESS_PROBE,bytes(32),raw);self.a.flush()
        got=self.b.receive()
        self.assertEqual(got.payload,w.GatewayReadinessProbePayloadV3(1,12345))
        self.assertFalse(self.b.wants_write)
    def test_final_delivery_waits_for_ack_flush(self):
        self.a.send(T.COLLECTOR_RESPONSE,TOKEN,response(1));self.a.flush()
        self.assertIsNone(self.b.receive());self.assertIsNone(self.b.receive())
        self.b.flush();self.assertIsNotNone(self.b.receive())
    def test_native_backpressure_is_bounded_and_recoverable(self):
        self.a.endpoint.channel.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,16384)
        raw=w.encode_gateway_readiness_probe_payload_v3(w.GatewayReadinessProbePayloadV3(1,12345))
        queued=0
        for _ in range(1024):
            self.a.send(T.GATEWAY_READINESS_PROBE,bytes(32),raw);queued+=1
            if not self.a.flush():break
        else:self.fail('native queue never exerted backpressure')
        before=self.a._deadline
        self.assertFalse(self.a.flush());self.assertEqual(self.a._deadline,before)
        consumed=0
        while self.b.receive() is not None:consumed+=1
        self.assertEqual(consumed,queued-1)
        self.assertTrue(self.a.flush());self.assertIsNotNone(self.b.receive())
    def test_malformed_multichunk_tail_never_delivered(self):
        raw=response(20000)[:-1]+b'!'
        size=w.MAX_CHUNK_PAYLOAD_BYTES_V3;count=(len(raw)+size-1)//size
        for index in range(count):
            self.a.endpoint.channel.send(packet(T.COLLECTOR_RESPONSE,raw[index*size:(index+1)*size],
                index=index,count=count,total=len(raw)))
            if index<count-1:
                self.assertIsNone(self.b.receive());self.b.flush();self.a.endpoint.receive()
            else:
                with self.assertRaises(w.ApplianceErrorV3):self.b.receive()
                self.assertIsNone(self.b._ready)
                self.assertEqual(self.b.endpoint.channel.fileno(),-1)
    def test_wrong_ack_session_closes(self):
        self.a.send(T.COLLECTOR_RESPONSE,TOKEN,response(1));self.a.flush();self.b.endpoint.receive()
        _,ack=self.a._ack_expected
        self.b.endpoint.channel.send(packet(T.CHUNK_ACK,w.encode_chunk_ack_payload_v3(ack),token=b'q'*32))
        with self.assertRaises(ValueError):self.a.receive()
    def test_slow_final_decode_cannot_reset_expired_deadline(self):
        raw=response(20000)
        self.a.send(T.COLLECTOR_RESPONSE,TOKEN,raw);self.a.flush()
        self.b.receive();self.b.flush();self.a.receive();self.a.flush()
        deadline=self.b._deadline
        clock=[deadline-1]
        decode=w.decode_collector_response_payload_v3
        def slow(data):
            result=decode(data)
            clock[0]=deadline
            return result
        with patch('time.monotonic_ns',side_effect=lambda:clock[0]),patch.object(w,'decode_collector_response_payload_v3',slow):
            with self.assertRaises(TimeoutError):self.b.receive()
        self.assertIsNone(self.b._ready)
        self.assertEqual(self.b.endpoint.channel.fileno(),-1)
    def test_ack_identity_coordinates(self):
        for field,value in (('acknowledged_message_sequence',2),('chunk_index',1),('cumulative_payload_bytes',2)):
            # Each mismatch gets a fresh native channel.
            a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            sender=CandidateMessageChannel(CandidateWireEndpoint(a,CREDS))
            receiver=CandidateWireEndpoint(b,CREDS)
            try:
                sender.send(T.COLLECTOR_RESPONSE,TOKEN,response(1));sender.flush();receiver.receive()
                _,ack=sender._ack_expected
                receiver.channel.send(packet(T.CHUNK_ACK,w.encode_chunk_ack_payload_v3(replace(ack,**{field:value}))))
                with self.assertRaises(ValueError):sender.receive()
            finally:sender.close();receiver.close()

if __name__=='__main__':unittest.main()
