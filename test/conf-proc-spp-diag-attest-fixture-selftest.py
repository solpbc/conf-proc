#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent coherence checks for the frozen diagnostic-attestation oracle."""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import ObjectIdentifier, SignatureAlgorithmOID

import conf_proc_spp_diag_attest_fixture as fixture


UTC = timezone.utc
TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018
TPM_ALG_SHA256 = 0x000B
TPM_ALG_RSASSA = 0x0014
TPM_ALG_RSAPSS = 0x0016
AMD_OID = "1.3.6.1.4.1.3704.1."


class Cursor:
    def __init__(self, data: bytes, byteorder: str) -> None:
        self.data = data
        self.byteorder = byteorder
        self.offset = 0

    def take(self, size: int) -> bytes:
        end = self.offset + size
        assert end <= len(self.data), (self.offset, size, len(self.data))
        result = self.data[self.offset : end]
        self.offset = end
        return result

    def integer(self, size: int) -> int:
        return int.from_bytes(self.take(size), self.byteorder)

    def consumed(self) -> None:
        assert self.offset == len(self.data), (self.offset, len(self.data))


def main() -> int:
    check_integrity_and_public_only()
    ark, ask, vcek = check_certificates_and_crls()
    ak_public = check_hcla_and_snp(vcek)
    check_quote(ak_public)
    print("SPP diagnostic attestation frozen fixture: 4 groups passed")
    return 0


def check_integrity_and_public_only() -> None:
    assert set(fixture.BLOBS_BASE64) == set(fixture.BLOB_SHA256)
    for name, expected in fixture.BLOB_SHA256.items():
        raw = fixture.fixture_bytes(name)
        assert hashlib.sha256(raw).hexdigest() == expected, name
        assert b"PRIVATE KEY" not in raw, name
    assert fixture.EXPECTED_PCRS[10] == fixture.EXPECTED_IMA_PCR10
    assert tuple(fixture.EXPECTED_PCRS) == fixture.EXPECTED_PCR_SELECTION


def check_certificates_and_crls() -> tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
    ark = x509.load_pem_x509_certificate(fixture.fixture_bytes("ark.pem"))
    ask = x509.load_pem_x509_certificate(fixture.fixture_bytes("ask.pem"))
    vcek = x509.load_pem_x509_certificate(fixture.fixture_bytes("vcek.pem"))

    assert ark.fingerprint(hashes.SHA256()) == fixture.EXPECTED_ARK_DER_SHA256
    assert ask.fingerprint(hashes.SHA256()) == fixture.EXPECTED_ASK_DER_SHA256
    assert ark.subject == ark.issuer
    assert ask.issuer == ark.subject
    assert vcek.issuer == ask.subject
    assert ark.extensions.get_extension_for_class(x509.BasicConstraints).value == x509.BasicConstraints(True, 1)
    assert ask.extensions.get_extension_for_class(x509.BasicConstraints).value == x509.BasicConstraints(True, 0)
    ark_usage = ark.extensions.get_extension_for_class(x509.KeyUsage).value
    ask_usage = ask.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ark_usage == x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )
    assert ask_usage == x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    assert extension_inventory(ark) == {
        ("2.5.29.15", True),
        ("2.5.29.19", True),
    }
    assert extension_inventory(ask) == {
        ("2.5.29.15", True),
        ("2.5.29.19", True),
    }
    assert extension_inventory(vcek) == {
        (AMD_OID + "1", False),
        (AMD_OID + "2", False),
        (AMD_OID + "3.1", False),
        (AMD_OID + "3.2", False),
        (AMD_OID + "3.3", False),
        (AMD_OID + "3.4", False),
        (AMD_OID + "3.5", False),
        (AMD_OID + "3.6", False),
        (AMD_OID + "3.7", False),
        (AMD_OID + "3.8", False),
        (AMD_OID + "4", False),
    }
    for extension_class in (x509.BasicConstraints, x509.KeyUsage):
        try:
            vcek.extensions.get_extension_for_class(extension_class)
        except x509.ExtensionNotFound:
            pass
        else:
            raise AssertionError(extension_class)
    assert vcek.serial_number == 0

    verify_pss_certificate(ark, ark)
    verify_pss_certificate(ask, ark)
    verify_pss_certificate(vcek, ask)
    at = datetime.fromtimestamp(fixture.FIXTURE_APPRAISAL_UNIX, UTC)
    for cert in (ark, ask, vcek):
        assert certificate_time(cert, "not_valid_before") <= at <= certificate_time(cert, "not_valid_after")

    healthy = x509.load_der_x509_crl(fixture.fixture_bytes("ark.crl.der"))
    revoked = x509.load_der_x509_crl(fixture.fixture_bytes("ark-revokes-ask.crl.der"))
    for crl in (healthy, revoked):
        assert crl.issuer == ark.subject
        assert crl.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS
        ark.public_key().verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48),
            hashes.SHA384(),
        )
        assert crl_time(crl, "last_update") <= at <= crl_time(crl, "next_update")
    assert ask.serial_number not in {entry.serial_number for entry in healthy}
    assert ask.serial_number in {entry.serial_number for entry in revoked}

    expected_extensions = {
        AMD_OID + "1": (0x02, 0),
        AMD_OID + "2": (0x16, b"GENOA-B0"),
        AMD_OID + "3.1": (0x02, fixture.EXPECTED_REPORTED_TCB[0]),
        AMD_OID + "3.2": (0x02, fixture.EXPECTED_REPORTED_TCB[1]),
        AMD_OID + "3.3": (0x02, fixture.EXPECTED_REPORTED_TCB[6]),
        AMD_OID + "3.4": (0x02, fixture.EXPECTED_REPORTED_TCB[2]),
        AMD_OID + "3.5": (0x02, fixture.EXPECTED_REPORTED_TCB[3]),
        AMD_OID + "3.6": (0x02, fixture.EXPECTED_REPORTED_TCB[4]),
        AMD_OID + "3.7": (0x02, fixture.EXPECTED_REPORTED_TCB[5]),
        AMD_OID + "3.8": (0x02, fixture.EXPECTED_REPORTED_TCB[7]),
        AMD_OID + "4": (0x04, fixture.EXPECTED_CHIP_ID),
    }
    for oid, (tag, expected) in expected_extensions.items():
        extension = vcek.extensions.get_extension_for_oid(ObjectIdentifier(oid)).value
        assert isinstance(extension, x509.UnrecognizedExtension)
        body = der_body(extension.value, tag)
        observed = int.from_bytes(body, "big") if tag == 0x02 else body
        assert observed == expected, oid
    return ark, ask, vcek


def extension_inventory(cert: x509.Certificate) -> set[tuple[str, bool]]:
    observed = {(extension.oid.dotted_string, extension.critical) for extension in cert.extensions}
    assert len(observed) == len(cert.extensions)
    return observed


def verify_pss_certificate(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    assert cert.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS
    parameters = cert.signature_algorithm_parameters
    assert isinstance(parameters, padding.PSS)
    public_key = issuer.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    public_key.verify(cert.signature, cert.tbs_certificate_bytes, parameters, cert.signature_hash_algorithm)


def certificate_time(cert: x509.Certificate, base: str) -> datetime:
    aware = getattr(cert, base + "_utc", None)
    if aware is not None:
        return aware
    return getattr(cert, base).replace(tzinfo=UTC)


def crl_time(crl: x509.CertificateRevocationList, base: str) -> datetime:
    aware = getattr(crl, base + "_utc", None)
    if aware is not None:
        return aware
    return getattr(crl, base).replace(tzinfo=UTC)


def der_body(value: bytes, expected_tag: int) -> bytes:
    cursor = Cursor(value, "big")
    assert cursor.integer(1) == expected_tag
    initial = cursor.integer(1)
    if initial & 0x80:
        size_octets = initial & 0x7F
        assert 1 <= size_octets <= 4
        size = cursor.integer(size_octets)
    else:
        size = initial
    body = cursor.take(size)
    cursor.consumed()
    return body


def check_hcla_and_snp(vcek: x509.Certificate):
    hcla = fixture.fixture_bytes("hcl_report.bin")
    assert len(hcla) == 2600
    magic, version, report_size, request_type, status, reserved1, reserved2, reserved3 = struct.unpack_from(
        "<4s7I", hcla, 0
    )
    assert (magic, version, request_type, status, reserved1, reserved2, reserved3) == (
        b"HCLA",
        2,
        2,
        0,
        0,
        0,
        0,
    )
    report = hcla[32:1216]
    assert len(report) == 1184
    data_size, runtime_version, runtime_report_type, hash_type, claim_size = struct.unpack_from(
        "<5I", hcla, 1216
    )
    assert (data_size, runtime_version, runtime_report_type, hash_type) == (20 + claim_size, 1, 2, 1)
    assert report_size == 32 + 1184 + data_size
    claim_start = 1236
    claim_end = claim_start + claim_size
    runtime_json = hcla[claim_start:claim_end]
    assert hcla[claim_end:] == bytes(len(hcla) - claim_end)
    runtime = json.loads(runtime_json, object_pairs_hook=unique_object)

    assert int.from_bytes(report[0x000:0x004], "little") == fixture.EXPECTED_SNP_REPORT_VERSION
    assert int.from_bytes(report[0x008:0x010], "little") == fixture.EXPECTED_SNP_POLICY
    assert int.from_bytes(report[0x030:0x034], "little") == fixture.EXPECTED_SNP_VMPL
    assert int.from_bytes(report[0x034:0x038], "little") == 1
    assert report[0x038:0x040] == fixture.EXPECTED_REPORTED_TCB
    assert report[0x050:0x070] == hashlib.sha256(runtime_json).digest()
    assert report[0x070:0x090] == bytes(32)
    assert report[0x090:0x0C0] == fixture.EXPECTED_SNP_MEASUREMENT
    assert report[0x0C0:0x0E0] == fixture.EXPECTED_SNP_HOST_DATA
    assert report[0x180:0x188] == fixture.EXPECTED_REPORTED_TCB
    assert report[0x1A0:0x1E0] == fixture.EXPECTED_CHIP_ID
    assert report[0x1E0:0x1E8] == fixture.EXPECTED_REPORTED_TCB
    assert report[0x1F0:0x1F8] == fixture.EXPECTED_REPORTED_TCB
    assert ((int.from_bytes(report[0x008:0x010], "little") >> 19) & 1) == 0

    r = int.from_bytes(report[0x2A0:0x2E8], "little")
    s = int.from_bytes(report[0x2E8:0x330], "little")
    signature = utils.encode_dss_signature(r, s)
    public_key = vcek.public_key()
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    public_key.verify(signature, report[:0x2A0], ec.ECDSA(hashes.SHA384()))

    keys = runtime["keys"]
    assert isinstance(keys, list) and len(keys) == 1
    jwk = keys[0]
    assert set(jwk) == {"e", "kid", "kty", "n"}
    assert (jwk["kid"], jwk["kty"]) == ("HCLAkPub", "RSA")
    ak_public = serialization.load_pem_public_key(fixture.fixture_bytes("akpub.pem"))
    assert isinstance(ak_public, rsa.RSAPublicKey)
    numbers = ak_public.public_numbers()
    assert b64url_decode(jwk["n"]) == numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    assert b64url_decode(jwk["e"]) == numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    check_ak_public_area(ak_public)
    return ak_public


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        assert key not in result, key
        result[key] = value
    return result


def b64url_decode(value: str) -> bytes:
    assert isinstance(value, str)
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


def check_ak_public_area(ak_public: rsa.RSAPublicKey) -> None:
    public_area_bytes = fixture.fixture_bytes("ak-tpmt-public.bin")
    public_area = Cursor(public_area_bytes, "big")
    assert public_area.integer(2) == 0x0001  # TPM_ALG_RSA
    assert public_area.integer(2) == TPM_ALG_SHA256
    assert public_area.integer(4) == 0x0005_0072
    assert public_area.take(public_area.integer(2)) == b""
    assert public_area.integer(2) == 0x0010  # symmetric = TPM_ALG_NULL
    assert public_area.integer(2) == TPM_ALG_RSASSA
    assert public_area.integer(2) == TPM_ALG_SHA256
    assert public_area.integer(2) == 2048
    assert public_area.integer(4) == 0  # default exponent 65537
    modulus = public_area.take(public_area.integer(2))
    public_area.consumed()
    numbers = ak_public.public_numbers()
    assert modulus == numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")

    name = TPM_ALG_SHA256.to_bytes(2, "big") + hashlib.sha256(public_area_bytes).digest()
    assert name == fixture.EXPECTED_AK_NAME == fixture.fixture_bytes("ak-name.bin")
    parent_qualified_name = fixture.fixture_bytes("ak-parent-qualified-name.bin")
    assert parent_qualified_name == fixture.EXPECTED_AK_PARENT_QUALIFIED_NAME
    assert parent_qualified_name == (0x4000_000B).to_bytes(4, "big")
    qualified_name = TPM_ALG_SHA256.to_bytes(2, "big") + hashlib.sha256(
        parent_qualified_name + name
    ).digest()
    assert qualified_name == fixture.EXPECTED_AK_QUALIFIED_NAME
    assert qualified_name == fixture.fixture_bytes("ak-qualified-name.bin")


def check_quote(ak_public) -> None:
    quote = Cursor(fixture.fixture_bytes("quote.msg"), "big")
    assert quote.integer(4) == TPM_GENERATED_VALUE
    assert quote.integer(2) == TPM_ST_ATTEST_QUOTE
    assert quote.take(quote.integer(2)) == fixture.EXPECTED_AK_QUALIFIED_NAME
    assert quote.take(quote.integer(2)) == fixture.EXPECTED_QUOTE_EXTRA_DATA
    assert quote.integer(8) == 0x0102030405060708
    assert quote.integer(4) == 4
    assert quote.integer(4) == 2
    assert quote.integer(1) == 1
    assert quote.integer(8) == 0x1122334455667788
    assert quote.integer(4) == 1
    assert quote.integer(2) == TPM_ALG_SHA256
    select = quote.take(quote.integer(1))
    assert selected_indices(select) == fixture.EXPECTED_PCR_SELECTION
    quoted_digest = quote.take(quote.integer(2))
    assert len(quoted_digest) == 32
    quote.consumed()

    signature = Cursor(fixture.fixture_bytes("quote.sig"), "big")
    assert signature.integer(2) == TPM_ALG_RSASSA
    assert signature.integer(2) == TPM_ALG_SHA256
    raw_signature = signature.take(signature.integer(2))
    signature.consumed()
    ak_public.verify(
        raw_signature,
        fixture.fixture_bytes("quote.msg"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    pcrs = Cursor(fixture.fixture_bytes("quote.pcrs"), "little")
    assert pcrs.integer(4) == 1
    selections = []
    for slot_index in range(8):
        algorithm = pcrs.integer(2)
        size = pcrs.integer(1)
        bitmap_slot = pcrs.take(8)
        pad = pcrs.take(5)
        assert pad == bytes(5)
        if slot_index == 0:
            assert (algorithm, size) == (TPM_ALG_SHA256, 3)
            assert bitmap_slot[size:] == bytes(8 - size)
            selections = list(selected_indices(bitmap_slot[:size]))
        else:
            assert (algorithm, size, bitmap_slot) == (0, 0, bytes(8))
    assert tuple(selections) == fixture.EXPECTED_PCR_SELECTION

    digest_values = []
    assert pcrs.integer(4) == 2
    for expected_count in (8, 7):
        count = pcrs.integer(4)
        assert count == expected_count
        for slot_index in range(8):
            size = pcrs.integer(2)
            buffer = pcrs.take(64)
            if slot_index < count:
                assert size == 32 and buffer[32:] == bytes(32)
                digest_values.append(buffer[:32])
            else:
                assert size == 0 and buffer == bytes(64)
    pcrs.consumed()

    observed = dict(zip(selections, digest_values, strict=True))
    assert observed == fixture.EXPECTED_PCRS
    assert observed[10] == fixture.EXPECTED_IMA_PCR10
    assert hashlib.sha256(b"".join(digest_values)).digest() == quoted_digest


def selected_indices(bitmap: bytes) -> tuple[int, ...]:
    return tuple(
        (byte_index * 8) + bit_index
        for byte_index, byte in enumerate(bitmap)
        for bit_index in range(8)
        if byte & (1 << bit_index)
    )


if __name__ == "__main__":
    raise SystemExit(main())
