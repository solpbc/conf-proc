#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Pure certificate-bundle decoding shared by builder and inspector.

Decoding a locked, offline certificate bundle into fingerprints is a
generic byte-format operation, not appliance inventory logic, so both
sides may share it -- the point of independence is that neither side
trusts the OTHER side's claims about what the bundle contains; both
decode the same trusted bytes themselves.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from conf_proc_lock import Lock
from conf_proc_reasons import CP_MODULE_KEYRING, ApplianceError


@dataclass(frozen=True)
class CertificateFingerprint:
    certificate_sha256: str
    spki_sha256: str
    subject: str


def decode_certificate_bundle(bundle_bytes: bytes) -> tuple[CertificateFingerprint, ...]:
    """Decode a PEM bundle of one or more certificates into fingerprints."""

    try:
        certificates = x509.load_pem_x509_certificates(bundle_bytes)
    except ValueError as exc:
        raise ApplianceError(CP_MODULE_KEYRING, f"could not decode trusted certificate bundle: {exc}") from exc
    if not certificates:
        raise ApplianceError(CP_MODULE_KEYRING, "trusted certificate bundle contains no certificates")

    fingerprints = []
    for certificate in certificates:
        certificate_sha256 = certificate.fingerprint(hashes.SHA256()).hex()
        spki_der = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        spki_sha256 = hashlib.sha256(spki_der).hexdigest()
        fingerprints.append(
            CertificateFingerprint(
                certificate_sha256=certificate_sha256,
                spki_sha256=spki_sha256,
                subject=certificate.subject.rfc4514_string(),
            )
        )
    return tuple(fingerprints)


def check_authorized_signers_match_bundle(lock: Lock, trusted_bundle_pem_bytes: bytes) -> None:
    """No extra module-signing authority in either direction (AC11).

    Pure comparison of two sets of already-trusted, already-loaded bytes
    (the lock's declared signer set and the lock's own trusted certificate
    bundle) -- both builder and inspector must reach the same conclusion,
    so this check is shared rather than duplicated.
    """

    bundle_fingerprints = {cert.certificate_sha256 for cert in decode_certificate_bundle(trusted_bundle_pem_bytes)}
    lock_fingerprints = {signer.certificate_sha256 for signer in lock.authorized_module_signers}
    if bundle_fingerprints != lock_fingerprints:
        extra_in_bundle = bundle_fingerprints - lock_fingerprints
        extra_in_lock = lock_fingerprints - bundle_fingerprints
        raise ApplianceError(
            CP_MODULE_KEYRING,
            f"authorized_module_signers does not exactly match the trusted certificate bundle "
            f"(extra in bundle: {sorted(extra_in_bundle)}, extra in lock: {sorted(extra_in_lock)})",
        )
