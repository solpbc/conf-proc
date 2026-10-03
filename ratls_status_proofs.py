# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Scheduled NVIDIA collateral delivery; the journal remains the verifier."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import random
import struct
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, SignatureAlgorithmOID

from ratls_contract import STATUS_PROOFS, _der_integer, _der_octets, _der_sequence, _read_tlv

LOG = logging.getLogger("spp.status")
LIMITS = STATUS_PROOFS["limits"]
POLICY = STATUS_PROOFS["verification"]
OCSP_URL = "https://ocsp.ndis.nvidia.com"
MAX_CHAIN_BYTES = 16384
MAX_ENVELOPE_BYTES = 65536
REFRESH_SECONDS = 3600
FETCH_TIMEOUT_SECONDS = 10


class StatusUnavailable(ValueError):
    """No complete acceptable snapshot. Never contains device identifiers."""


def encode_bundle(responses: tuple[bytes, ...]) -> bytes:
    if not 1 <= len(responses) <= LIMITS["max_responses"]:
        raise ValueError("invalid proof count")
    if any(not r or len(r) > LIMITS["max_response_bytes"] for r in responses):
        raise ValueError("invalid proof size")
    result = _der_sequence([_der_integer(STATUS_PROOFS["version"]),
                            _der_sequence([_der_octets(r) for r in responses])])
    if len(result) > LIMITS["max_extension_value_bytes"]:
        raise ValueError("proof bundle exceeds limit")
    return result


def decode_bundle(data: bytes) -> tuple[bytes, ...]:
    if len(data) > LIMITS["max_extension_value_bytes"]:
        raise ValueError("proof bundle exceeds limit")
    body, end = _read_tlv(data, 0, 0x30)
    if end != len(data):
        raise ValueError("trailing proof data")
    version, offset = _read_tlv(body, 0, 0x02)
    if version != bytes([STATUS_PROOFS["version"]]):
        raise ValueError("invalid proof version")
    sequence, end = _read_tlv(body, offset, 0x30)
    if end != len(body):
        raise ValueError("unexpected proof field")
    result, offset = [], 0
    while offset < len(sequence):
        value, offset = _read_tlv(sequence, offset, 0x04)
        result.append(value)
        if len(result) > LIMITS["max_responses"]:
            raise ValueError("too many proofs")
    responses = tuple(result)
    if encode_bundle(responses) != data:
        raise ValueError("noncanonical proof bundle")
    return responses


def inventory_from_envelope(data: bytes) -> dict[str, str]:
    if len(data) > MAX_ENVELOPE_BYTES or data[:8] != b"SPPGPU1\x00" or len(data) < 10:
        raise StatusUnavailable("invalid GPU inventory")
    count = struct.unpack_from(">H", data, 8)[0]
    if count != 7:
        raise StatusUnavailable("invalid GPU inventory")
    fields, offset = {}, 10
    for expected in range(1, 8):
        if offset + 6 > len(data):
            raise StatusUnavailable("invalid GPU inventory")
        field, size = struct.unpack_from(">HI", data, offset)
        offset += 6
        if field != expected or offset + size > len(data):
            raise StatusUnavailable("invalid GPU inventory")
        fields[field] = data[offset:offset + size]
        offset += size
    if offset != len(data) or len(fields[1]) != 32 or len(fields[3]) > MAX_CHAIN_BYTES:
        raise StatusUnavailable("invalid GPU inventory")
    return {"chain_b64": base64.b64encode(fields[3]).decode("ascii"),
            "driver": fields[4].decode("ascii"), "vbios": fields[5].decode("ascii"),
            "architecture": fields[7].decode("ascii")}


@dataclass(frozen=True)
class Subject:
    certificate: x509.Certificate
    issuer: x509.Certificate
    request: bytes

    @property
    def key(self) -> bytes:
        # Include the actual issuer context, not just collision-prone SHA-1 IDs.
        return self.request + self.issuer.fingerprint(hashes.SHA256())


def subjects(chain: tuple[x509.Certificate, ...], root: x509.Certificate,
             *, device: bool = False) -> tuple[Subject, ...]:
    if not 2 <= len(chain) <= 8 or chain[-1] != root or len(set(chain)) != len(chain):
        raise StatusUnavailable("unexpected certificate path")
    for certificate, issuer in zip(chain, chain[1:]):
        certificate.verify_directly_issued_by(issuer)
        if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise StatusUnavailable("unexpected certificate path")
    # GPU alias leaf and root are still path-checked, but have no OCSP request.
    return tuple(Subject(certificate, issuer,
                         ocsp.OCSPRequestBuilder().add_certificate(
                             certificate, issuer, hashes.SHA1()).build().public_bytes(
                                 serialization.Encoding.DER))
                 for certificate, issuer in zip(chain[1:] if device else chain,
                                                 chain[2:] if device else chain[1:]))


class Collateral:
    def __init__(self, directory: Path | None = None) -> None:
        directory = directory or Path(__file__).with_name("status-collateral")
        self.profile = json.loads((directory / "profile.json").read_bytes())
        if self.profile["version"] != 1:
            raise StatusUnavailable("unsupported collateral profile")
        files = {}
        for name, expected in self.profile["files"].items():
            if Path(name).name != name:
                raise StatusUnavailable("invalid collateral path")
            data = (directory / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                raise StatusUnavailable("collateral digest mismatch")
            files[name] = data
        self.device_root = x509.load_pem_x509_certificate(files["device_root_cert.txt"])
        rim_root = x509.load_pem_x509_certificate(files["rim_root_cert.txt"])
        rims = {}
        for name, data in files.items():
            if name.endswith(".xml"):
                tree = ET.fromstring(data)
                chain = tuple(x509.load_der_x509_certificate(base64.b64decode("".join(e.text.split()), validate=True))
                              for e in tree.iter() if e.tag.endswith("}X509Certificate"))
                for subject in subjects(chain, rim_root):
                    rims[subject.key] = subject
        if not rims:
            raise StatusUnavailable("empty collateral inventory")
        self.rims = tuple(rims.values())

    def device_subjects(self, inventory: dict[str, str]) -> tuple[Subject, ...]:
        if (inventory["driver"] != self.profile["driver"] or
                inventory["vbios"] not in self.profile["vbios"] or
                inventory["architecture"] != self.profile["architecture"]):
            raise StatusUnavailable("unsupported GPU profile")
        encoded = inventory["chain_b64"]
        if len(encoded) > (MAX_CHAIN_BYTES + 2) // 3 * 4:
            raise StatusUnavailable("GPU chain exceeds limit")
        chain = x509.load_pem_x509_certificates(base64.b64decode(encoded, validate=True))
        return subjects(tuple(chain), self.device_root, device=True)

    def inventory(self, inventory: dict[str, str]) -> tuple[tuple[bytes, ...], tuple[Subject, ...]]:
        gpu = self.device_subjects(inventory)
        all_subjects = {s.key: s for s in (*gpu, *self.rims)}
        if not gpu or len(all_subjects) > LIMITS["max_responses"]:
            raise StatusUnavailable("unexpected inventory size")
        # Ephemeral GPU alias certificate bytes do not change these stable IDs.
        identity = tuple(s.key for s in gpu) + tuple(
            inventory[k].encode("ascii") for k in ("driver", "vbios", "architecture"))
        return identity, tuple(all_subjects.values())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


class NvidiaTransport:
    def __init__(self) -> None:
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def __call__(self, request: bytes) -> bytes:
        started = time.monotonic()
        req = urllib.request.Request(OCSP_URL, data=request, method="POST",
                                     headers={"Content-Type": "application/ocsp-request",
                                              "Accept": "application/ocsp-response"})
        with self.opener.open(req, timeout=FETCH_TIMEOUT_SECONDS) as response:
            if response.status != 200 or response.headers.get_content_type() != "application/ocsp-response":
                raise StatusUnavailable("unexpected OCSP transport response")
            declared = response.headers.get("Content-Length")
            if declared is not None and not 0 < int(declared) <= LIMITS["max_response_bytes"]:
                raise StatusUnavailable("OCSP response exceeds limit")
            data = bytearray()
            # read1 does at most one underlying read. A peer sending a slow
            # trickle cannot keep a full-body read alive indefinitely.
            while len(data) <= LIMITS["max_response_bytes"]:
                if time.monotonic() - started >= FETCH_TIMEOUT_SECONDS:
                    raise TimeoutError("OCSP response time limit")
                chunk = response.read1(LIMITS["max_response_bytes"] + 1 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
        if not data or len(data) > LIMITS["max_response_bytes"]:
            raise StatusUnavailable("OCSP response exceeds limit")
        return bytes(data)


@dataclass(frozen=True)
class Proof:
    raw: bytes
    status: str
    this_update: float
    next_update: float
    deadline: float


def verify_response(raw: bytes, subject: Subject, now: float) -> Proof:
    """Bounded readiness precheck, never an owner-side appraisal result."""
    if not raw or len(raw) > LIMITS["max_response_bytes"]:
        raise StatusUnavailable("invalid OCSP response size")
    response = ocsp.load_der_ocsp_response(raw)
    if (response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL or
            response.public_bytes(serialization.Encoding.DER) != raw):
        raise StatusUnavailable("invalid OCSP response")
    single = tuple(response.responses)
    if len(single) != 1:
        raise StatusUnavailable("unexpected OCSP coverage")
    entry = single[0]
    request = ocsp.load_der_ocsp_request(subject.request)
    if (not isinstance(entry.hash_algorithm, hashes.SHA1) or
            (entry.issuer_name_hash, entry.issuer_key_hash, entry.serial_number) !=
            (request.issuer_name_hash, request.issuer_key_hash, request.serial_number)):
        raise StatusUnavailable("OCSP CertID mismatch")
    # No extensions are needed for nonce-free, single-CertID readiness. Refuse
    # unknown critical semantics; the journal repeats its stricter verifier.
    for extensions in (response.extensions, response.single_extensions):
        if any(e.critical or isinstance(e.value, x509.OCSPNonce) for e in extensions):
            raise StatusUnavailable("unexpected OCSP extension")
    signers = [subject.issuer]
    if len(response.certificates) > 4:
        raise StatusUnavailable("too many responder certificates")
    signers.extend(response.certificates)
    authorized = False
    for signer in signers:
        if response.responder_name is not None and signer.subject != response.responder_name:
            continue
        if response.responder_key_hash is not None:
            key_hash = ocsp.OCSPRequestBuilder().add_certificate(signer, signer, hashes.SHA1()).build().issuer_key_hash
            if response.responder_key_hash != key_hash:
                continue
        try:
            if signer != subject.issuer:
                signer.verify_directly_issued_by(subject.issuer)
                eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
                    continue
            if not signer.not_valid_before_utc.timestamp() <= now <= signer.not_valid_after_utc.timestamp():
                continue
            try:
                if not signer.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
                    continue
            except x509.ExtensionNotFound:
                pass
            public_key = signer.public_key()
            algorithm = response.signature_hash_algorithm
            if not isinstance(algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512)):
                continue
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                if response.signature_algorithm_oid not in (SignatureAlgorithmOID.ECDSA_WITH_SHA256,
                        SignatureAlgorithmOID.ECDSA_WITH_SHA384, SignatureAlgorithmOID.ECDSA_WITH_SHA512):
                    continue
                public_key.verify(response.signature, response.tbs_response_bytes, ec.ECDSA(algorithm))
            elif isinstance(public_key, rsa.RSAPublicKey):
                if response.signature_algorithm_oid not in (SignatureAlgorithmOID.RSA_WITH_SHA256,
                        SignatureAlgorithmOID.RSA_WITH_SHA384, SignatureAlgorithmOID.RSA_WITH_SHA512):
                    continue
                public_key.verify(response.signature, response.tbs_response_bytes, padding.PKCS1v15(), algorithm)
            else:
                continue
            authorized = True
            break
        except (InvalidSignature, ValueError, x509.ExtensionNotFound, TypeError):
            continue
    if not authorized:
        raise StatusUnavailable("unauthorized OCSP signature")
    this_update = entry.this_update_utc.timestamp()
    if entry.next_update_utc is None:
        raise StatusUnavailable("missing signed expiry")
    next_update = entry.next_update_utc.timestamp()
    deadline = min(next_update, this_update + POLICY["max_signed_age_seconds"])
    if (this_update > now + POLICY["future_tolerance_seconds"] or
            next_update <= this_update or deadline <= now):
        raise StatusUnavailable("invalid signed OCSP time")
    return Proof(raw, entry.certificate_status.name.lower(), this_update, next_update, deadline)


class ProofCache:
    def __init__(self, collateral: Collateral, clock: Callable[[], float] = time.time) -> None:
        self.collateral, self.clock = collateral, clock
        self._lock = threading.Lock()
        self._identity: tuple[bytes, ...] | None = None
        self._subjects: tuple[Subject, ...] = ()
        self._proofs: dict[bytes, Proof] = {}

    def initialize(self, inventory: dict[str, str]) -> None:
        identity, required = self.collateral.inventory(inventory)
        with self._lock:
            if self._identity is not None and self._identity != identity:
                raise StatusUnavailable("GPU inventory changed")
            self._identity, self._subjects = identity, required

    def required(self) -> tuple[Subject, ...]:
        with self._lock:
            return self._subjects

    def accept(self, subject: Subject, raw: bytes) -> None:
        proof = verify_response(raw, subject, self.clock())
        with self._lock:
            if subject.key not in {s.key for s in self._subjects}:
                raise StatusUnavailable("unexpected proof subject")
            previous = self._proofs.get(subject.key)
            if previous is None or proof.this_update > previous.this_update:
                self._proofs[subject.key] = proof
            elif proof.this_update == previous.this_update:
                if (proof.status, proof.next_update) != (previous.status, previous.next_update):
                    self._proofs[subject.key] = Proof(previous.raw, "conflict", previous.this_update,
                                                     previous.next_update, previous.deadline)

    def snapshot(self, envelope: bytes | None = None) -> bytes:
        identity = None
        if envelope is not None:
            identity, _ = self.collateral.inventory(inventory_from_envelope(envelope))
        now = self.clock()
        with self._lock:
            if self._identity is None or (identity is not None and identity != self._identity):
                raise StatusUnavailable("GPU inventory not ready")
            responses = []
            for subject in self._subjects:
                proof = self._proofs.get(subject.key)
                if (proof is None or proof.status != "good" or
                        proof.this_update > now + POLICY["future_tolerance_seconds"] or
                        proof.deadline - now < POLICY["admission_min_remaining_seconds"]):
                    raise StatusUnavailable("status proofs not ready")
                responses.append(proof.raw)
            return encode_bundle(tuple(responses))


class StatusWorker:
    def __init__(self, collector, cache: ProofCache,
                 fetch: Callable[[bytes], bytes] | None = None,
                 jitter: Callable[[], float] | None = None) -> None:
        self.collector, self.cache = collector, cache
        self.fetch = fetch or NvidiaTransport()
        self.jitter = jitter or (lambda: random.SystemRandom().uniform(0.9, 1.1))
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="nvidia-status", daemon=True)

    def refresh(self) -> bool:
        if not self.cache.required():
            try:
                self.cache.initialize(self.collector.collect_status_inventory())
            except Exception:
                LOG.warning("event=status_inventory_unavailable")
                return False
        success = True
        for subject in self.cache.required():
            if self._stop.is_set():
                return False
            try:
                self.cache.accept(subject, self.fetch(subject.request))
            except Exception:
                success = False
                LOG.warning("event=status_refresh_failed")
        LOG.info("event=status_refresh_complete" if success else "event=status_refresh_incomplete")
        return success

    def _run(self) -> None:
        failures = 0
        while not self._stop.is_set():
            success = self.refresh()
            failures = 0 if success else min(failures + 1, 5)
            delay = REFRESH_SECONDS if success else min(30 * 2 ** (failures - 1), 300)
            self._stop.wait(delay * self.jitter())

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        # One bounded fetch can be active. No new fetch begins after stop.
        self._thread.join(2 * FETCH_TIMEOUT_SECONDS + self.collector.timeout + 2)
