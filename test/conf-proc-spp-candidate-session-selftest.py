#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Real socket tests of candidate expiry, including blocked gateway operations."""
import os
from pathlib import Path
import selectors
import socket
import sys
import threading
import time
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from conf_proc_spp_candidate_session import CandidateSessionOwner
from conf_proc_spp_boot_v3_resource import ServingResourceReducerV3
from conf_proc_spp_boot_v3_wire import CollectorGenerationV3, RouteV3


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.ledger = ServingResourceReducerV3()
        self.owner = CandidateSessionOwner(self.ledger)
        self.token = self.ledger.session_acquire()
        self.sockets = []
        self.threads = []

    def pair(self):
        pair = socket.socketpair()
        self.sockets.extend(pair)
        return pair

    def tearDown(self):
        self.owner.close()
        for sock in self.sockets:
            sock.close()
        for thread in self.threads:
            thread.join(2)
            self.assertFalse(thread.is_alive())

    def expire(self):
        deadline = time.monotonic() + 2
        while self.token in self.ledger.sessions:
            self.owner.wait(0.2)
            self.assertLess(time.monotonic(), deadline)
        self.assertFalse(self.ledger.route_slot_holders)

    def test_unexpired_usable_then_idle_and_grants_revoke(self):
        client, peer = self.pair()
        self.owner.adopt(self.token, client, time.monotonic_ns() + 150_000_000)
        for generation in CollectorGenerationV3:
            permit = self.ledger.collector_acquire(self.token, generation)
            self.ledger.collector_finish(self.token, generation, permit)
        permits = self.ledger.request_acquire(self.token, RouteV3.INFERENCE)
        self.ledger.work_begin(self.token, permits[1])
        peer.sendall(b'usable')
        self.assertEqual(client.recv(6), b'usable')
        self.expire()
        peer.settimeout(1)
        self.assertEqual(peer.recv(1), b'')
        with self.assertRaises(OSError):
            client.sendall(b'after-expiry')

    def test_blocked_upstream_read_wakes_at_expiry(self):
        client, _peer = self.pair()
        upstream, _server = self.pair()
        self.owner.adopt(self.token, client, time.monotonic_ns() + 150_000_000)
        self.owner.attach(self.token, upstream)
        finished = threading.Event()
        received = []
        def read():
            try:
                received.append(upstream.recv(1))
            finally:
                finished.set()
        thread = threading.Thread(target=read)
        self.threads.append(thread)
        thread.start()
        self.assertFalse(finished.wait(0.02))
        self.expire()
        self.assertTrue(finished.wait(1))
        self.assertEqual(received, [b''])

    def test_blocked_send_and_continuously_ready_control_do_not_extend(self):
        client, _peer = self.pair()
        client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        wake, signal = self.pair()
        signal.sendall(b'remains-readable')
        self.owner.register(wake.fileno(), selectors.EVENT_READ, 'control')
        self.owner.adopt(self.token, client, time.monotonic_ns() + 150_000_000)
        finished = threading.Event()
        def write():
            try:
                while True:
                    client.sendall(b'x' * 65536)
            except OSError:
                finished.set()
        thread = threading.Thread(target=write)
        self.threads.append(thread)
        thread.start()
        self.expire()
        self.assertTrue(finished.wait(1))

    def test_closed_original_and_reused_fd_cannot_redirect_revocation(self):
        client, peer = self.pair()
        original_fd = client.fileno()
        self.owner.adopt(self.token, client, time.monotonic_ns() + 100_000_000)
        client.close()
        other, other_peer = self.pair()
        self.assertEqual(other.fileno(), original_fd)
        self.expire()
        self.assertEqual(peer.recv(1), b'')
        other.sendall(b'other')
        self.assertEqual(other_peer.recv(5), b'other')

    def test_completed_upstream_detaches_before_next_request(self):
        client,_=self.pair()
        self.owner.adopt(self.token,client,time.monotonic_ns()+500_000_000)
        for _ in range(5):
            upstream,peer=self.pair()
            self.owner.attach(self.token,upstream)
            self.owner.detach(self.token,upstream)
            self.assertEqual(peer.recv(1),b'')
        self.assertIn(self.token,self.ledger.sessions)

    def test_invalid_and_replayed_adoption_denied(self):
        client, peer = self.pair()
        for bad in (True, time.monotonic_ns()-1, time.monotonic_ns()+61_000_000_000):
            with self.assertRaises(ValueError):
                self.owner.adopt(self.token, client, bad)
        self.owner.adopt(self.token, client, time.monotonic_ns()+500_000_000)
        with self.assertRaises(ValueError):
            self.owner.adopt(self.token, client, time.monotonic_ns()+500_000_000)
        with self.assertRaises(ValueError):
            self.owner.attach(self.token, client)
        self.owner.revoke_all()
        self.assertTrue(self.ledger.revoked)
        self.assertEqual(peer.recv(1), b'')

    def test_expiry_between_admission_and_attach_preserves_failure(self):
        from unittest.mock import patch
        client, _peer = self.pair()
        with patch('conf_proc_spp_candidate_session.time.monotonic_ns', side_effect=[1, 3]):
            with self.assertRaises(TimeoutError):
                self.owner.adopt(self.token, client, 2)
        self.assertNotIn(self.token, self.ledger.sessions)

if __name__ == '__main__':
    unittest.main()
