#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Candidate 14-PCR channel evidence and separate 15-PCR trace conjunction."""
from __future__ import annotations

from dataclasses import dataclass, fields, replace
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_spp_diag_attest import (
    SppDiagAttestation, SppDiagAttestationEvidence, SppDiagAttestationExpectations,
    _Cursor, appraise_spp_diag_attestation,
)
from conf_proc_spp_diag_pcr import SPP_DIAG_BASELINE_PCR_SELECTION, pcr_bitmap
from ratls_contract import (
    CERTIFICATE_BINDING_DOMAIN, EXPORTER_BINDING_DOMAIN, CompositeEvidence, ExporterProof,
)

RECEIPT_SCHEMA = 'sol-pbc/spp/candidate-supplement/1'
RECEIPT_DOMAIN = b'sol-pbc/spp/candidate-supplement/1\0'
MAX_ENVELOPE = 9 * 1024 * 1024
MAX_PROOF = 16384


def _h(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def _bytes(raw: bytes, minimum: int, maximum: int) -> bytes:
    if type(raw) is not bytes or not minimum <= len(raw) <= maximum:
        raise ValueError('candidate attestation byte field or bound differs')
    return raw


@dataclass(frozen=True)
class SupplementalContext:
    challenge: bytes
    run_identity: bytes
    control_plan: bytes
    build: bytes
    closure: bytes
    manifest: bytes
    trace: bytes
    ima: bytes
    cohort: bytes
    recipient: bytes
    channel: bytes

    def object(self) -> dict[str, str]:
        return {field.name: _bytes(getattr(self, field.name), 32, 32).hex() for field in fields(self)}


def supplemental_receipt(envelope_der: bytes, context: SupplementalContext) -> bytes:
    """Acyclic receipt: envelope first, this receipt second, its quote last."""
    _bytes(envelope_der, 1, MAX_ENVELOPE)
    if type(context) is not SupplementalContext:
        raise ValueError('candidate supplemental context type differs')
    return canonical_dumps({'schema': RECEIPT_SCHEMA, 'envelope_sha256': _h(envelope_der).hex(), **context.object()})


def receipt_digest(raw: bytes) -> bytes:
    _bytes(raw, 1, 4096)
    return _h(RECEIPT_DOMAIN + raw)


@dataclass(frozen=True)
class Quote14:
    clock: int
    reset_count: int
    restart_count: int
    firmware: int
    pcrs: tuple[tuple[int, bytes], ...]


def _pcr14_file(raw: bytes) -> tuple[tuple[int, bytes], ...]:
    _bytes(raw, 1, 8192)
    c = _Cursor(raw, 'little')
    if c.integer(4) != 1:
        raise ValueError('candidate PCR bank count differs')
    for index in range(8):
        algorithm, size, bitmap, pad = c.integer(2), c.integer(1), c.take(8), c.take(5)
        wanted = (0x000b, 3, pcr_bitmap(SPP_DIAG_BASELINE_PCR_SELECTION) + bytes(5), bytes(5)) if index == 0 else (0, 0, bytes(8), bytes(5))
        if (algorithm, size, bitmap, pad) != wanted:
            raise ValueError('candidate 14-PCR file selection or padding differs')
    if c.integer(4) != 2:
        raise ValueError('candidate PCR digest block count differs')
    values = []
    for expected_count in (8, 6):
        if c.integer(4) != expected_count:
            raise ValueError('candidate PCR digest count differs')
        for index in range(8):
            size, buffer = c.integer(2), c.take(64)
            if index < expected_count:
                if size != 32 or any(buffer[32:]):
                    raise ValueError('candidate PCR digest padding differs')
                values.append(buffer[:32])
            elif size != 0 or any(buffer):
                raise ValueError('candidate unused PCR slot differs')
    c.consumed()
    return tuple(zip(SPP_DIAG_BASELINE_PCR_SELECTION, values))


def _quote14(message: bytes, signature: bytes, pcrs: bytes, *, ak, qualified: bytes,
             extra: bytes, expected_pcrs: tuple[tuple[int, bytes], ...]) -> Quote14:
    _bytes(message, 1, 4096)
    _bytes(signature, 1, 1024)
    c = _Cursor(message, 'big')
    if c.integer(4) != 0xff544347 or c.integer(2) != 0x8018:
        raise ValueError('candidate quote magic or type differs')
    if c.take(c.integer(2)) != qualified or c.take(c.integer(2)) != extra:
        raise ValueError('candidate quote AK or channel challenge differs')
    clock, reset, restart, safe, firmware = c.integer(8), c.integer(4), c.integer(4), c.integer(1), c.integer(8)
    if safe != 1 or c.integer(4) != 1 or c.integer(2) != 0x000b:
        raise ValueError('candidate quote clock safety or bank differs')
    if c.take(c.integer(1)) != pcr_bitmap(SPP_DIAG_BASELINE_PCR_SELECTION):
        raise ValueError('candidate envelope must retain the approved 14-PCR selection')
    digest = c.take(c.integer(2))
    c.consumed()
    s = _Cursor(signature, 'big')
    if s.integer(2) != 0x0014 or s.integer(2) != 0x000b:
        raise ValueError('candidate quote signature algorithm differs')
    raw_signature = s.take(s.integer(2))
    s.consumed()
    if len(raw_signature) != 256 or len(digest) != 32:
        raise ValueError('candidate quote signature or digest size differs')
    ak.verify(raw_signature, message, padding.PKCS1v15(), hashes.SHA256())
    values = _pcr14_file(pcrs)
    if values != expected_pcrs or not hmac.compare_digest(_h(b''.join(value for _, value in values)), digest):
        raise ValueError('candidate envelope PCRs differ from independent expectations')
    return Quote14(clock, reset, restart, firmware, values)


@dataclass(frozen=True)
class CandidateQuoteConjunction:
    """CPU/quote conjunction only; GPU and finite-trace appraisal still required."""
    supplemental: SppDiagAttestation
    certificate: Quote14
    exporter: Quote14
    envelope_sha256: bytes
    receipt_sha256: bytes


def appraise_quote_conjunction(
    envelope_der: bytes, exporter_der: bytes, receipt: bytes,
    supplemental: SppDiagAttestationEvidence, platform: SppDiagAttestationExpectations,
    expected: SupplementalContext, *, connected_spki_der: bytes, tls_exporter: bytes,
) -> CandidateQuoteConjunction:
    """Verify original channel evidence plus the separately signed trace receipt.

    The private verifier supplies expected from independently inspected build,
    trace/IMA/cohort and its actual TLS channel. No expectation is read out of
    receipt or learned from the PCRs being appraised. This function cannot mint
    a lease: the caller must additionally appraise GPU and trace semantics.
    """
    _bytes(envelope_der, 1, MAX_ENVELOPE)
    _bytes(exporter_der, 1, MAX_PROOF)
    _bytes(receipt, 1, 4096)
    _bytes(connected_spki_der, 1, 1024)
    _bytes(tls_exporter, 32, 32)
    if dict(platform.baseline_pcrs).get(14) != bytes(32):
        raise ValueError('candidate profile requires the MOK door to remain closed')
    wanted = supplemental_receipt(envelope_der, expected)
    if canonical_dumps(canonical_loads(receipt)) != receipt or receipt != wanted:
        raise ValueError('candidate supplemental receipt differs from independent context')
    if expected.channel != _h(tls_exporter):
        raise ValueError('candidate supplemental channel differs from connected TLS')
    envelope = CompositeEvidence.from_der(envelope_der)
    proof = ExporterProof.from_der(exporter_der)
    if (envelope.to_der() != envelope_der or proof.to_der() != exporter_der
            or envelope.owner_nonce != expected.challenge or proof.owner_nonce != expected.challenge
            or envelope.tls_spki_der != connected_spki_der or proof.tls_spki_der != connected_spki_der
            or proof.tls_exporter != tls_exporter):
        raise ValueError('candidate envelope recipient or exporter binding differs')
    pairs = ((envelope.hcl_report, supplemental.hcl_report),
             (envelope.ak_public_key_pem, supplemental.ak_public_pem),
             (envelope.amd_ark_pem, supplemental.ark_pem),
             (envelope.amd_ask_pem, supplemental.ask_pem),
             (envelope.amd_vcek_pem, supplemental.vcek_pem))
    if any(left != right for left, right in pairs):
        raise ValueError('candidate envelopes do not share the same HCLA-bound AK and CPU evidence')
    if envelope.amd_report != supplemental.hcl_report[0x20:0x20 + 1184]:
        raise ValueError('candidate separate SNP report differs from HCLA report')
    # Reuse the existing complete strict SNP/HCLA/AK/CRL/15-PCR appraiser.
    digest = receipt_digest(receipt)
    accepted = appraise_spp_diag_attestation(supplemental, replace(platform, quote_extra_data=digest))
    # This key and its TPMT_PUBLIC/qualified name have now passed the full HCLA
    # and SNP binding. Derive the same name, never trust one supplied in a quote.
    ak = serialization.load_pem_public_key(supplemental.ak_public_pem)
    name = b'\0\x0b' + _h(supplemental.ak_tpmt_public)
    qualified = b'\0\x0b' + _h(platform.ak_parent_qualified_name + name)
    certificate_extra = _h(CERTIFICATE_BINDING_DOMAIN + expected.challenge
                           + _h(connected_spki_der) + _h(envelope.gpu_envelope))
    exporter_extra = _h(EXPORTER_BINDING_DOMAIN + expected.challenge
                        + _h(connected_spki_der) + tls_exporter + _h(envelope.gpu_envelope))
    certificate = _quote14(envelope.quote_message, envelope.quote_signature, envelope.quote_pcrs,
        ak=ak, qualified=qualified, extra=certificate_extra, expected_pcrs=platform.baseline_pcrs)
    exporter = _quote14(proof.quote_message, proof.quote_signature, proof.quote_pcrs,
        ak=ak, qualified=qualified, extra=exporter_extra, expected_pcrs=platform.baseline_pcrs)
    for quote in (certificate, exporter):
        if (quote.reset_count != accepted.quote_reset_count
                or quote.restart_count != accepted.quote_restart_count
                or quote.firmware != accepted.quote_firmware_version):
            raise ValueError('candidate quote boot, reset/restart or firmware conjunction differs')
    if not certificate.clock <= exporter.clock <= accepted.quote_clock <= certificate.clock + 60_000:
        raise ValueError('candidate quote ordering or freshness interval differs')
    return CandidateQuoteConjunction(accepted, certificate, exporter, _h(envelope_der), digest)
