#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Signed collateral, timer, privacy and real TLS delivery boundary checks."""

import base64
import dataclasses
import json
import socket
import sys
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from OpenSSL import SSL

from ratls_contract import CompositeEvidence, ExporterProof, PREFACE_MAGIC, STATUS_PROOFS
from ratls_gateway import GatewayServer, _make_certificate
from ratls_status_proofs import (Collateral, NvidiaTransport, ProofCache, StatusUnavailable,
                                StatusWorker, Subject, decode_bundle, encode_bundle,
                                inventory_from_envelope, verify_response)

DATA = ROOT / "test/status-proofs"
ENVELOPE = (DATA / "gpu-envelope.tlv").read_bytes()
FIXTURE_NOW = 1790993100


def populated(clock=lambda: FIXTURE_NOW):
    cache = ProofCache(Collateral(), clock)
    cache.initialize(inventory_from_envelope(ENVELOPE))
    responses = decode_bundle((DATA / "bundle.der").read_bytes())
    for subject in cache.required():
        serial = ocsp.load_der_ocsp_request(subject.request).serial_number
        cache.accept(subject, next(r for r in responses
                                  if ocsp.load_der_ocsp_response(r).serial_number == serial))
    return cache


class SignedProofTest(unittest.TestCase):
    def setUp(self):
        self.now = 1790993100
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.issuer = self.cert("issuer", self.key, None, self.key, ca=True)
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        self.leaf = self.cert("leaf", self.leaf_key, self.issuer, self.key)
        request = ocsp.OCSPRequestBuilder().add_certificate(
            self.leaf, self.issuer, hashes.SHA1()).build().public_bytes(serialization.Encoding.DER)
        self.subject = Subject(self.leaf, self.issuer, request)

    def cert(self, name, key, issuer, signer, ca=False, eku=None):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (x509.CertificateBuilder().subject_name(subject)
                   .issuer_name(issuer.subject if issuer else subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.fromtimestamp(self.now - 3600, timezone.utc))
                   .not_valid_after(datetime.fromtimestamp(self.now + 86400, timezone.utc))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if eku is not None:
            builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        return builder.sign(signer, hashes.SHA256())

    def response(self, status=ocsp.OCSPCertStatus.GOOD, age=0, lifetime=86400,
                 signer=None, key=None, include=True, nonce=False, next_update=True):
        signer, key = signer or self.issuer, key or self.key
        now = datetime.fromtimestamp(self.now, timezone.utc)
        builder = (ocsp.OCSPResponseBuilder().add_response(
            self.leaf, self.issuer, hashes.SHA1(), status, now + timedelta(seconds=age),
            now + timedelta(seconds=age + lifetime) if next_update else None,
            now - timedelta(minutes=1) if status == ocsp.OCSPCertStatus.REVOKED else None,
            x509.ReasonFlags.key_compromise if status == ocsp.OCSPCertStatus.REVOKED else None)
            .responder_id(ocsp.OCSPResponderEncoding.HASH, signer))
        if include and signer != self.issuer:
            builder = builder.certificates([signer])
        if nonce:
            builder = builder.add_extension(x509.OCSPNonce(b"nonce"), critical=False)
        return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def test_issuer_signature_and_exact_certid(self):
        proof = verify_response(self.response(), self.subject, self.now)
        self.assertEqual(proof.status, "good")
        self.assertEqual(proof.deadline, self.now + 86400)
        other = dataclasses.replace(self.subject, request=ocsp.OCSPRequestBuilder().add_certificate(
            self.issuer, self.issuer, hashes.SHA1()).build().public_bytes(serialization.Encoding.DER))
        with self.assertRaises(StatusUnavailable):
            verify_response(self.response(), other, self.now)

    def test_authorized_delegation_and_unrelated_signer(self):
        key = ec.generate_private_key(ec.SECP256R1())
        good = self.cert("OCSP", key, self.issuer, self.key, eku=[ExtendedKeyUsageOID.OCSP_SIGNING])
        self.assertEqual(verify_response(self.response(signer=good, key=key), self.subject, self.now).status, "good")
        no_eku = self.cert("OCSP", key, self.issuer, self.key)
        wrong = self.cert("OCSP", key, None, key, eku=[ExtendedKeyUsageOID.OCSP_SIGNING])
        for signer in (no_eku, wrong):
            with self.subTest(signer=signer.subject), self.assertRaises(StatusUnavailable):
                verify_response(self.response(signer=signer, key=key), self.subject, self.now)
        with self.assertRaises(StatusUnavailable):
            verify_response(self.response(signer=good, key=key, include=False), self.subject, self.now)

    def test_bad_signature_and_der_reject(self):
        raw = self.response()
        for corrupt in (raw[:-1] + bytes([raw[-1] ^ 1]), raw + b"x", b"not DER"):
            with self.subTest(raw=corrupt[:4]), self.assertRaises(ValueError):
                verify_response(corrupt, self.subject, self.now)

    def test_signed_time_and_nonce_boundaries(self):
        self.assertEqual(verify_response(self.response(age=60), self.subject, self.now).this_update, self.now + 60)
        for args in ({"age":61}, {"age":-86400}, {"next_update":False}, {"nonce":True}):
            with self.subTest(args=args), self.assertRaises(StatusUnavailable):
                verify_response(self.response(**args), self.subject, self.now)
        self.assertEqual(verify_response(self.response(lifetime=172800), self.subject, self.now).deadline,
                         self.now + 86400)

    def test_latest_adverse_conflict_recovery_and_invalid_retention(self):
        class FakeCollateral:
            def inventory(_self, _inventory):
                return (b"identity",), (self.subject,)
        now = [self.now]
        cache = ProofCache(FakeCollateral(), lambda: now[0])
        cache.initialize({})
        good = self.response()
        cache.accept(self.subject, good)
        cache.accept(self.subject, self.response(status=ocsp.OCSPCertStatus.REVOKED, age=-1))
        self.assertEqual(decode_bundle(cache.snapshot()), (good,))
        with self.assertRaises(ValueError):
            cache.accept(self.subject, b"bad")
        self.assertEqual(decode_bundle(cache.snapshot()), (good,))
        cache.accept(self.subject, self.response(status=ocsp.OCSPCertStatus.UNKNOWN))
        with self.assertRaises(StatusUnavailable):
            cache.snapshot()
        cache.accept(self.subject, good)
        with self.assertRaises(StatusUnavailable):
            cache.snapshot()
        now[0] += 1
        newer = self.response(age=1)
        cache.accept(self.subject, newer)
        self.assertEqual(decode_bundle(cache.snapshot()), (newer,))
        now[0] += 1
        cache.accept(self.subject, self.response(status=ocsp.OCSPCertStatus.REVOKED, age=2))
        with self.assertRaises(StatusUnavailable):
            cache.snapshot()


class InventoryAndDeliveryTest(unittest.TestCase):
    def test_journal_golden_vectors(self):
        artifact = json.loads((ROOT / "test/ratls-status-proofs-v1-vectors.json").read_bytes())
        for vector in artifact["vectors"]:
            with self.subTest(name=vector["name"]):
                data = bytes.fromhex(vector["hex"])
                if vector["valid"]:
                    responses = decode_bundle(data)
                    self.assertEqual(len(responses), vector["response_count"])
                    self.assertEqual(encode_bundle(responses), data)
                else:
                    with self.assertRaises(ValueError):
                        decode_bundle(data)

    def test_real_nvidia_signature_inventory_and_limits(self):
        cache = populated()
        self.assertEqual(len(cache.required()), 8)
        bundle = cache.snapshot(ENVELOPE)
        self.assertEqual(len(bundle), 7543)
        self.assertEqual(set(decode_bundle(bundle)), set(decode_bundle((DATA / "bundle.der").read_bytes())))
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _make_certificate(key, b"evidence", bundle)
        extension = certificate.extensions.get_extension_for_oid(x509.ObjectIdentifier(STATUS_PROOFS["oid"]))
        self.assertFalse(extension.critical)
        self.assertEqual(extension.value.value, bundle)
        with self.assertRaises(StatusUnavailable):
            _make_certificate(key, b"evidence" * 8000, bundle)

    def test_fresh_identity_mismatch_and_path_extras_refused(self):
        cache = populated()
        inventory = inventory_from_envelope(ENVELOPE)
        with self.assertRaises(StatusUnavailable):
            cache.collateral.inventory({**inventory, "driver":"unapproved"})
        with self.assertRaises(StatusUnavailable):
            cache.collateral.inventory({**inventory, "vbios":"00.00.00"})
        chain = base64.b64decode(inventory["chain_b64"])
        with self.assertRaises(StatusUnavailable):
            cache.collateral.inventory({**inventory, "chain_b64":base64.b64encode(chain + chain).decode()})
        for broken in (ENVELOPE + b"extra", ENVELOPE[:50], b"bad"):
            with self.assertRaises(StatusUnavailable):
                cache.snapshot(broken)

    def test_no_boot_cache_and_exact_headroom_expiry(self):
        now = [FIXTURE_NOW]
        empty = ProofCache(Collateral(), lambda: now[0])
        with self.assertRaises(StatusUnavailable):
            empty.snapshot()
        cache = populated(lambda: now[0])
        deadline = min(ocsp.load_der_ocsp_response(r).next_update_utc.timestamp()
                       for r in decode_bundle(cache.snapshot()))
        now[0] = deadline - 130
        cache.snapshot()
        now[0] += 0.01
        with self.assertRaises(StatusUnavailable):
            cache.snapshot()

    def test_narrow_collector_takes_no_caller_input_or_tpm_quote(self):
        import ratls_collector as c
        with mock.patch.object(c, "_require_cc_production"), mock.patch.object(c, "_gpu_tlv", return_value=ENVELOPE) as gpu, mock.patch.object(c, "_quote", side_effect=AssertionError("TPM opened")):
            result = c._status_inventory({"operation":"status-inventory-v1"})
            self.assertEqual(set(result), {"chain_b64", "driver", "vbios", "architecture"})
            self.assertEqual(len(gpu.call_args.args[0]), 32)
            self.assertNotEqual(gpu.call_args.args[0], bytes(32))
            with self.assertRaises(ValueError):
                c._status_inventory({"operation":"status-inventory-v1", "owner_nonce_b64":"forbidden"})
            self.assertEqual(gpu.call_count, 1)

    def test_timer_runs_idle_and_bursts_do_not_fetch(self):
        cache = populated()
        captured = []
        responses = {ocsp.load_der_ocsp_response(r).serial_number:r for r in decode_bundle(cache.snapshot())}
        def fetch(request):
            decoded = ocsp.load_der_ocsp_request(request)
            self.assertEqual(len(decoded.extensions), 0)
            captured.append(request)
            return responses[decoded.serial_number]
        collector = mock.Mock(timeout=1)
        worker = StatusWorker(collector, cache, fetch, jitter=lambda:1)
        worker._stop = mock.Mock()
        waits = []
        worker._stop.is_set.return_value = False
        def wait(delay):
            waits.append(delay)
            before = len(captured)
            # No handler-controlled refresh/wakeup exists; snapshots read RAM.
            for _ in range(100):
                cache.snapshot(ENVELOPE)
            self.assertEqual(len(captured), before)
            if len(waits) == 2:
                worker._stop.is_set.return_value = True
        worker._stop.wait.side_effect = wait
        worker._run()
        self.assertEqual(waits, [3600, 3600])
        self.assertEqual(len(captured), 16)
        collector.collect_status_inventory.assert_not_called()
        worker._stop.is_set.return_value = False
        with mock.patch.object(cache, "accept", side_effect=ValueError("network failure")):
            self.assertFalse(worker.refresh())
        self.assertEqual(len(captured), 24)
        cache.snapshot()

    def test_warm_inventory_and_failure_retry_schedule(self):
        cache = ProofCache(Collateral(), lambda: FIXTURE_NOW)
        collector = mock.Mock(timeout=1)
        collector.collect_status_inventory.return_value = inventory_from_envelope(ENVELOPE)
        responses = {ocsp.load_der_ocsp_response(r).serial_number:r
                     for r in decode_bundle((DATA / "bundle.der").read_bytes())}
        fetch = mock.Mock(side_effect=lambda request: responses[ocsp.load_der_ocsp_request(request).serial_number])
        worker = StatusWorker(collector, cache, fetch, jitter=lambda:1)
        self.assertTrue(worker.refresh())
        self.assertEqual(fetch.call_count, 8)
        collector.collect_status_inventory.assert_called_once_with()
        cache.snapshot()
        worker._stop = mock.Mock()
        worker._stop.is_set.return_value = False
        waits = []
        def wait(delay):
            waits.append(delay)
            if len(waits) == 6:
                worker._stop.is_set.return_value = True
        worker._stop.wait.side_effect = wait
        fetch.side_effect = TimeoutError("failure")
        with self.assertLogs("spp.status", level="WARNING"):
            worker._run()
        self.assertEqual(waits, [30, 60, 120, 240, 300, 300])
        collector.collect_status_inventory.assert_called_once_with()
        cache.snapshot()

    def test_fixed_https_request_proxy_and_redirect_policy(self):
        transport = NvidiaTransport()
        self.assertTrue(any(isinstance(h, __import__('urllib.request', fromlist=['ProxyHandler']).ProxyHandler) and h.proxies == {} for h in transport.opener.handlers) or not any(isinstance(h, __import__('urllib.request', fromlist=['ProxyHandler']).ProxyHandler) for h in transport.opener.handlers))
        response = mock.MagicMock(status=200)
        response.__enter__.return_value = response
        response.headers.get_content_type.return_value = "application/ocsp-response"
        response.headers.get.return_value = "3"
        response.read1.side_effect = [b"DER", b""]
        with mock.patch.object(transport.opener, "open", return_value=response) as opened:
            self.assertEqual(transport(b"CertID"), b"DER")
        request = opened.call_args.args[0]
        self.assertEqual(request.full_url, "https://ocsp.ndis.nvidia.com")
        self.assertEqual(request.data, b"CertID")
        self.assertFalse(request.has_header("Authorization"))
        from ratls_status_proofs import _NoRedirect
        with self.assertRaises(__import__('urllib.error', fromlist=['HTTPError']).HTTPError):
            _NoRedirect().redirect_request(request, None, 302, "redirect", {}, "https://other.test/")

    def test_transport_body_and_elapsed_time_are_bounded(self):
        transport = NvidiaTransport()
        response = mock.MagicMock(status=200)
        response.__enter__.return_value = response
        response.headers.get_content_type.return_value = "application/ocsp-response"
        response.headers.get.return_value = None
        response.read1.return_value = b"x" * 2049
        with mock.patch.object(transport.opener, "open", return_value=response):
            with self.assertRaises(StatusUnavailable):
                transport(b"CertID")
            self.assertEqual(response.read1.call_args.args[0], 2049)
            response.read1.reset_mock()
            response.headers.get.return_value = "999999"
            with self.assertRaises(StatusUnavailable):
                transport(b"CertID")
            response.read1.assert_not_called()
            response.headers.get.return_value = None
            with mock.patch("ratls_status_proofs.time.monotonic", side_effect=[0, 10]):
                with self.assertRaises(TimeoutError):
                    transport(b"CertID")
            response.read1.assert_not_called()

    def test_immutable_collateral_digest_mismatch_refused(self):
        import tempfile
        import shutil
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "collateral"
            shutil.copytree(ROOT / "status-collateral", target)
            xml = next(target.glob("*.xml"))
            xml.write_bytes(xml.read_bytes() + b" ")
            with self.assertRaisesRegex(StatusUnavailable, "digest"):
                Collateral(target)

    def test_real_tls_carries_snapshot_and_rechecks_before_admission(self):
        cache = populated()
        admitted = []
        expired = [False]
        class Collector:
            def collect_composite(_self, nonce, spki):
                return CompositeEvidence(nonce, spki, *([b"fixture"] * 9), ENVELOPE)
            def collect_exporter_proof(_self, nonce, spki, exporter, envelope):
                if expired[0]:
                    cache.clock = lambda: FIXTURE_NOW + 86400
                return ExporterProof(nonce, spki, exporter, b"msg", b"sig", b"pcrs")
        server = GatewayServer(("127.0.0.1", 0), Collector(), mock.Mock(), ("127.0.0.1", 1), 5,
                               status_cache=cache)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with mock.patch("ratls_gateway._http_relay", side_effect=lambda *_:admitted.append(True)):
                raw = socket.create_connection(server.server_address, timeout=5)
                raw.sendall(PREFACE_MAGIC + bytes(32))
                context = SSL.Context(SSL.TLS_CLIENT_METHOD)
                context.set_verify(SSL.VERIFY_NONE, lambda *_:True)
                connection = SSL.Connection(context, raw)
                connection.setblocking(1)
                connection.set_connect_state()
                connection.do_handshake()
                peer = connection.get_peer_certificate().to_cryptography()
                extension = peer.extensions.get_extension_for_oid(x509.ObjectIdentifier(STATUS_PROOFS["oid"]))
                self.assertEqual(extension.value.value, cache.snapshot())
                connection.send(b"GET /._sol/spp/exporter-proof HTTP/1.1\r\nHost: fixture\r\n\r\n")
                response = connection.recv(8192)
                self.assertTrue(response.startswith(b"HTTP/1.1 200"))
                connection.close()
                raw.close()
                for _ in range(50):
                    if admitted:
                        break
                    time.sleep(0.01)
                self.assertTrue(admitted)
                # The same real exchange must stop if the signed status ages
                # out while the fresh exporter evidence is being collected.
                expired[0] = True
                raw = socket.create_connection(server.server_address, timeout=5)
                raw.sendall(PREFACE_MAGIC + bytes(32))
                connection = SSL.Connection(context, raw)
                connection.setblocking(1)
                connection.set_connect_state()
                connection.do_handshake()
                connection.send(b"GET /._sol/spp/exporter-proof HTTP/1.1\r\nHost: fixture\r\n\r\n")
                try:
                    self.assertEqual(connection.recv(8192), b"")
                except (SSL.ZeroReturnError, SSL.SysCallError):
                    pass
                connection.close()
                raw.close()
                self.assertEqual(admitted, [True])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)

    def test_not_ready_refuses_before_evidence_collection(self):
        cache = ProofCache(Collateral())
        collector = mock.Mock()
        server = GatewayServer(("127.0.0.1", 0), collector, mock.Mock(), ("127.0.0.1", 1), 5,
                               status_cache=cache)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.create_connection(server.server_address, timeout=5) as raw:
                raw.sendall(PREFACE_MAGIC + bytes(32))
                self.assertEqual(raw.recv(1), b"")
            collector.collect_composite.assert_not_called()
            collector.collect_status_inventory.assert_not_called()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)


if __name__ == "__main__":
    unittest.main()
