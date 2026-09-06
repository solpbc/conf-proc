#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Actual credential, descriptor and sequence failures over Linux seqpacket."""
import array
from dataclasses import replace
import os
from pathlib import Path
import socket
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import conf_proc_spp_boot_v3_wire as w
from conf_proc_spp_boot_v3_tables import ServingWireMessageTypeV3 as T
from conf_proc_spp_candidate_ipc import CandidateWireEndpoint, socket_identity, MAX_FRAME

CREDS=(os.getpid(),os.getuid(),os.getgid())
TOKEN=b't'*32

def frame(kind,payload,seq=1,fd=False):
    return w.encode_serving_wire_frame_v3(kind,session_token=TOKEN if kind==T.SESSION_FD else bytes(32),
        sequence=seq,chunk_index=0,chunk_count=1,chunk_length=len(payload),total_length=len(payload),
        flags=w.FLAG_START_V3|w.FLAG_END_V3|(w.FLAG_HAS_FD_V3 if fd else 0),payload_bytes=payload)

def probe(seq=1):
    return frame(T.GATEWAY_READINESS_PROBE,w.encode_gateway_readiness_probe_payload_v3(w.GatewayReadinessProbePayloadV3(1,123456)),seq)

class Tests(unittest.TestCase):
    def setUp(self):
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.a=CandidateWireEndpoint(a,CREDS);self.b=CandidateWireEndpoint(b,CREDS)
        self.extra=[]
    def tearDown(self):
        self.a.close();self.b.close()
        for s in self.extra:s.close()
    def tcp(self):
        listener=socket.socket();self.extra.append(listener)
        listener.bind(('127.0.0.1',0));listener.listen(1)
        client=socket.create_connection(listener.getsockname());self.extra.append(client)
        server,_=listener.accept();self.extra.append(server)
        return client,server
    def test_actual_credentials_nonblocking_and_replay(self):
        self.assertIsNone(self.b.receive())
        self.a.queue(probe());self.assertTrue(self.a.flush())
        result=self.b.receive();self.assertIsNone(result.descriptor)
        self.assertEqual(result.frame.payload.census_generation,1)
        self.a.channel.send(probe())
        with self.assertRaises(ValueError):self.b.receive()
        self.assertEqual(self.b.channel.fileno(),-1)
    def test_wrong_sender_closes_channel(self):
        self.b.peer_credentials=(CREDS[0]+1,CREDS[1],CREDS[2])
        self.a.queue(probe());self.a.flush()
        with self.assertRaises(ValueError):self.b.receive()
    def test_actual_fd_identity_and_use_after_sender_closes(self):
        client,server=self.tcp();identity=socket_identity(client,1)
        data=frame(T.SESSION_FD,w.encode_session_fd_payload_v3(identity),fd=True)
        self.a.queue(data,client);client.close();self.a.flush()
        result=self.b.receive();self.assertIsNotNone(result.descriptor)
        with result.descriptor as received:
            self.assertFalse(os.get_inheritable(received.fileno()))
            self.assertEqual(socket_identity(received,1),identity)
            received.sendall(b'actual-rights');self.assertEqual(server.recv(64),b'actual-rights')
    def test_changed_fd_metadata_rejected_and_received_fd_closed(self):
        client,_=self.tcp();identity=replace(socket_identity(client,1),so_cookie=7)
        data=frame(T.SESSION_FD,w.encode_session_fd_payload_v3(identity),fd=True)
        with self.assertRaises(ValueError):self.a.queue(data,client)
        before=set(os.listdir('/proc/self/fd'))
        self.a.channel.sendmsg([data],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[client.fileno()]))])
        with self.assertRaises(ValueError):self.b.receive()
        self.assertLessEqual(set(os.listdir('/proc/self/fd')),before)
    def test_unexpected_extra_fds_and_oversize_close(self):
        client,_=self.tcp()
        self.a.channel.sendmsg([probe()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[client.fileno(),client.fileno()]))])
        before=set(os.listdir('/proc/self/fd'))
        with self.assertRaises(ValueError):self.b.receive()
        self.assertLessEqual(set(os.listdir('/proc/self/fd')),before)
    def test_oversized_datagram_rejected(self):
        self.a.channel.send(b'x'*(MAX_FRAME+2))
        with self.assertRaises(ValueError):self.b.receive()
    def test_queue_bound_and_order(self):
        with self.assertRaises(ValueError):self.a.queue(probe(2))
        self.a.queue(probe())
        with self.assertRaises(RuntimeError):self.a.queue(probe(2))
        self.a.flush();self.b.receive();self.a.queue(probe(2));self.a.flush()
        self.assertEqual(self.b.receive().frame.header.sequence,2)
    def test_chunk_discontinuity_rejected_before_delivery(self):
        raw=b'x'*w.MAX_CHUNK_PAYLOAD_BYTES_V3
        data=w.encode_serving_wire_frame_v3(T.COLLECTOR_RESPONSE,session_token=TOKEN,sequence=1,
            chunk_index=0,chunk_count=2,chunk_length=len(raw),total_length=len(raw)+1,
            flags=w.FLAG_START_V3,payload_bytes=raw)
        self.a.channel.send(data);self.assertIsNotNone(self.b.receive())
        self.a.channel.send(probe())
        with self.assertRaises(ValueError):self.b.receive()

    def test_inconsistent_chunk_boundaries_rejected(self):
        good=probe();header=w.decode_serving_wire_header_v3(good[:w.HEADER_SIZE_V3])
        for changed in (replace(header,chunk_count=0),replace(header,flags=w.FLAG_START_V3),
                        replace(header,total_length=999999999),replace(header,total_length=17)):
            with self.assertRaises(ValueError):
                self.a.queue(w.encode_serving_wire_header_v3(changed)+good[w.HEADER_SIZE_V3:])

if __name__=='__main__':unittest.main()
