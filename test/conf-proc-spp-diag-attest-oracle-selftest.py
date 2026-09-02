#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Independent frozen-fixture and fresh-key oracle for SPP diagnostic attestation."""

import ast
import base64
import hashlib
import hmac
import json
import struct
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import NameOID, ObjectIdentifier

from conf_proc_spp_diag_attest_fixture import fixture_bytes


# Inside every cert/CRL validity window (certs 2026-01-01..2036-01-01,
# CRL last_update 2026-09-02T03:49:26Z). Not taken from the fixture module.
_APPRAISAL_UNIX = 1_788_321_600

_BLOB_NAMES = (
    "ark.pem",
    "ask.pem",
    "vcek.pem",
    "ark.crl.der",
    "ark-revokes-ask.crl.der",
    "akpub.pem",
    "ak-tpmt-public.bin",
    "ak-name.bin",
    "ak-parent-qualified-name.bin",
    "ak-qualified-name.bin",
    "hcl_report.bin",
    "quote.msg",
    "quote.sig",
    "quote.pcrs",
)

_AMD_PRODUCT_OID = "1.3.6.1.4.1.3704.1.2"
_AMD_PREFIX = "1.3.6.1.4.1.3704.1."
_COMMITMENT_DOMAIN = b"solpbc:conf-proc:spp-diag-attestation:v1\0"
_TPM_GENERATED = 0xFF544347
_TPM_ST_QUOTE = 0x8018
_TPM_SHA256 = 0x000B
_TPM_RSASSA = 0x0014
_TPM_RSA = 0x0001
_TPM_NULL = 0x0010
_PCR_INDEXES = (0, 2, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 22, 23)
_BASELINE_INDEXES = (0, 2, 4, 7, 8, 9, 11, 12, 13, 14, 15, 16, 22, 23)
_FRESH_UNIX = 1_800_000_000
_UTC = timezone.utc
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
_PARENT_QN = (0x4000000B).to_bytes(4, "big")
_KU_ARK = x509.KeyUsage(
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
_KU_ASK = x509.KeyUsage(
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


@dataclass(frozen=True)
class FrozenTcbFloor:
    boot_loader: int
    tee: int
    snp: int
    microcode: int


@dataclass(frozen=True)
class FrozenEvidence:
    ark_pem: bytes
    ask_pem: bytes
    vcek_pem: bytes
    ark_crl_der: bytes
    ak_public_pem: bytes
    ak_tpmt_public: bytes
    hcl_report: bytes
    quote_msg: bytes
    quote_sig: bytes
    quote_pcrs: bytes


@dataclass(frozen=True)
class FrozenExpectations:
    appraisal_unix: int
    quote_extra_data: bytes
    ark_der_sha256: bytes
    ask_der_sha256: bytes
    ark_crl_der_sha256: bytes
    ak_parent_qualified_name: bytes
    snp_report_version: int
    snp_policy: int
    snp_vmpl: int
    snp_measurement: bytes
    snp_host_data: bytes
    minimum_tcb: FrozenTcbFloor
    vcek_product_name: bytes
    cpuid_family: int
    cpuid_model: int
    cpuid_step: int
    baseline_pcrs: tuple[tuple[int, bytes], ...]
    ima_pcr10: bytes


class _Walk:
    def __init__(self, data, order):
        self.data = data
        self.order = order
        self.at = 0

    def pull(self, size):
        stop = self.at + size
        assert stop <= len(self.data), (self.at, size, len(self.data))
        piece = self.data[self.at : stop]
        self.at = stop
        return piece

    def number(self, size):
        return int.from_bytes(self.pull(size), self.order)

    def done(self):
        assert self.at == len(self.data), (self.at, len(self.data))


def _sha256(data):
    return hashlib.sha256(data).digest()


def _u32le(buf, offset):
    return int.from_bytes(buf[offset : offset + 4], "little")


def _u64le(buf, offset):
    return int.from_bytes(buf[offset : offset + 8], "little")


def _unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        assert key not in out, key
        out[key] = value
    return out


def _b64url(text):
    assert type(text) is str
    pad = "=" * ((-len(text)) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _pem_body_der(raw):
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    text = raw.strip()
    assert text.startswith(begin), "pem begin"
    assert text.endswith(end), "pem end"
    inner = text[len(begin) : len(text) - len(end)]
    joined = b"".join(inner.split())
    return base64.b64decode(joined, validate=True)


def _tlv_body(raw, tag):
    assert type(raw) is bytes and len(raw) >= 2
    assert raw[0] == tag
    first = raw[1]
    assert first != 0x80
    pos = 2
    if first & 0x80:
        count = first & 0x7F
        assert 1 <= count <= 4
        length_bytes = raw[pos : pos + count]
        assert length_bytes and length_bytes[0] != 0
        length = int.from_bytes(length_bytes, "big")
        pos += count
    else:
        length = first
    stop = pos + length
    assert stop == len(raw)
    return raw[pos:stop]


def _ia5_body(raw):
    body = _tlv_body(raw, 0x16)
    for item in body:
        assert 0x20 <= item <= 0x7E
    return body


def _bits_set(bitmap):
    found = []
    for byte_index, byte in enumerate(bitmap):
        for bit in range(8):
            if byte & (1 << bit):
                found.append(byte_index * 8 + bit)
    return tuple(found)


def _parse_tpmt_public(raw):
    walk = _Walk(raw, "big")
    assert walk.number(2) == _TPM_RSA
    assert walk.number(2) == _TPM_SHA256
    walk.number(4)
    assert walk.pull(walk.number(2)) == b""
    assert walk.number(2) == _TPM_NULL
    scheme = walk.number(2)
    if scheme == _TPM_RSASSA:
        assert walk.number(2) == _TPM_SHA256
    else:
        assert scheme == _TPM_NULL
    assert walk.number(2) == 2048
    exponent = walk.number(4)
    assert exponent in (0, 65537)
    modulus = walk.pull(walk.number(2))
    walk.done()
    return modulus


def _parse_hcla(hcla):
    assert len(hcla) == 2600
    assert hcla[0:4] == b"HCLA"
    assert _u32le(hcla, 4) == 2
    report_size = _u32le(hcla, 8)
    assert _u32le(hcla, 12) == 2
    for offset in (16, 20, 24, 28):
        assert _u32le(hcla, offset) == 0
    report = hcla[0x20 : 0x20 + 1184]
    assert len(report) == 1184
    data_size = _u32le(hcla, 0x4C0)
    assert _u32le(hcla, 0x4C4) == 1
    assert _u32le(hcla, 0x4C8) == 2
    assert _u32le(hcla, 0x4CC) == 1
    claim_size = _u32le(hcla, 0x4D0)
    assert data_size == 20 + claim_size
    assert report_size == 32 + 1184 + data_size
    claim = hcla[0x4D4 : 0x4D4 + claim_size]
    assert hcla[0x4D4 + claim_size :] == bytes(len(hcla) - (0x4D4 + claim_size))
    runtime = json.loads(claim, object_pairs_hook=_unique_pairs)
    assert hmac.compare_digest(report[0x050:0x070], _sha256(claim))
    assert report[0x070:0x090] == bytes(32)
    return report, claim, runtime


def _parse_quote_msg(raw):
    walk = _Walk(raw, "big")
    assert walk.number(4) == _TPM_GENERATED
    assert walk.number(2) == _TPM_ST_QUOTE
    qualified = walk.pull(walk.number(2))
    extra = walk.pull(walk.number(2))
    walk.number(8)
    walk.number(4)
    walk.number(4)
    assert walk.number(1) == 1
    walk.number(8)
    assert walk.number(4) == 1
    assert walk.number(2) == _TPM_SHA256
    select = walk.pull(walk.number(1))
    pcr_digest = walk.pull(walk.number(2))
    walk.done()
    assert len(pcr_digest) == 32
    return extra, qualified, select, pcr_digest


def _parse_quote_sig(raw):
    walk = _Walk(raw, "big")
    assert walk.number(2) == _TPM_RSASSA
    assert walk.number(2) == _TPM_SHA256
    signature = walk.pull(walk.number(2))
    walk.done()
    return signature


def _parse_pcrs(raw):
    walk = _Walk(raw, "little")
    assert walk.number(4) == 1
    selected = None
    for slot in range(8):
        algorithm = walk.number(2)
        size = walk.number(1)
        bitmap = walk.pull(8)
        pad = walk.pull(5)
        assert pad == bytes(5)
        if slot == 0:
            assert algorithm == _TPM_SHA256 and size == 3
            assert bitmap[3:] == bytes(5)
            selected = _bits_set(bitmap[:3])
        else:
            assert (algorithm, size, bitmap) == (0, 0, bytes(8))
    assert walk.number(4) == 2
    digests = []
    for wanted in (8, 7):
        count = walk.number(4)
        assert count == wanted
        for slot in range(8):
            size = walk.number(2)
            buffer = walk.pull(64)
            if slot < count:
                assert size == 32 and buffer[32:] == bytes(32)
                digests.append(buffer[:32])
            else:
                assert size == 0 and buffer == bytes(64)
    walk.done()
    assert selected is not None and len(selected) == len(digests) == 15
    return tuple(zip(selected, digests))


def _product_name(vcek_pem):
    cert = x509.load_pem_x509_certificate(vcek_pem)
    extension = cert.extensions.get_extension_for_oid(
        ObjectIdentifier(_AMD_PRODUCT_OID)
    ).value
    assert isinstance(extension, x509.UnrecognizedExtension)
    return _ia5_body(extension.value)


def _unix_window(cert):
    start = int(cert.not_valid_before_utc.timestamp())
    stop = int(cert.not_valid_after_utc.timestamp())
    return start, stop


def _oracle_commitment(evidence, expectations):
    pieces = [_COMMITMENT_DOMAIN]

    def add(path, value):
        name = path.encode("ascii")
        pieces.append(struct.pack(">H", len(name)))
        pieces.append(name)
        pieces.append(struct.pack(">Q", len(value)))
        pieces.append(value)

    add("evidence.ark_pem", evidence.ark_pem)
    add("evidence.ask_pem", evidence.ask_pem)
    add("evidence.vcek_pem", evidence.vcek_pem)
    add("evidence.ark_crl_der", evidence.ark_crl_der)
    add("evidence.ak_public_pem", evidence.ak_public_pem)
    add("evidence.ak_tpmt_public", evidence.ak_tpmt_public)
    add("evidence.hcl_report", evidence.hcl_report)
    add("evidence.quote_msg", evidence.quote_msg)
    add("evidence.quote_sig", evidence.quote_sig)
    add("evidence.quote_pcrs", evidence.quote_pcrs)
    add("expectations.appraisal_unix", struct.pack(">Q", expectations.appraisal_unix))
    add("expectations.quote_extra_data", expectations.quote_extra_data)
    add("expectations.ark_der_sha256", expectations.ark_der_sha256)
    add("expectations.ask_der_sha256", expectations.ask_der_sha256)
    add("expectations.ark_crl_der_sha256", expectations.ark_crl_der_sha256)
    add("expectations.ak_parent_qualified_name", expectations.ak_parent_qualified_name)
    add(
        "expectations.snp_report_version",
        struct.pack(">Q", expectations.snp_report_version),
    )
    add("expectations.snp_policy", struct.pack(">Q", expectations.snp_policy))
    add("expectations.snp_vmpl", struct.pack(">Q", expectations.snp_vmpl))
    add("expectations.snp_measurement", expectations.snp_measurement)
    add("expectations.snp_host_data", expectations.snp_host_data)
    floor = expectations.minimum_tcb
    add("expectations.minimum_tcb.boot_loader", bytes([floor.boot_loader]))
    add("expectations.minimum_tcb.tee", bytes([floor.tee]))
    add("expectations.minimum_tcb.snp", bytes([floor.snp]))
    add("expectations.minimum_tcb.microcode", bytes([floor.microcode]))
    add("expectations.vcek_product_name", expectations.vcek_product_name)
    add("expectations.cpuid_family", struct.pack(">Q", expectations.cpuid_family))
    add("expectations.cpuid_model", struct.pack(">Q", expectations.cpuid_model))
    add("expectations.cpuid_step", struct.pack(">Q", expectations.cpuid_step))
    for slot, pair in enumerate(expectations.baseline_pcrs):
        index, digest = pair
        head = "expectations.baseline_pcrs[%02d]" % slot
        add(head + ".index", bytes([index]))
        add(head + ".digest", digest)
    add("expectations.ima_pcr10", expectations.ima_pcr10)
    hasher = hashlib.sha256()
    for piece in pieces:
        hasher.update(piece)
    return hasher.digest()


def frozen_positive():
    blobs = {name: fixture_bytes(name) for name in _BLOB_NAMES}
    evidence = FrozenEvidence(
        ark_pem=blobs["ark.pem"],
        ask_pem=blobs["ask.pem"],
        vcek_pem=blobs["vcek.pem"],
        ark_crl_der=blobs["ark.crl.der"],
        ak_public_pem=blobs["akpub.pem"],
        ak_tpmt_public=blobs["ak-tpmt-public.bin"],
        hcl_report=blobs["hcl_report.bin"],
        quote_msg=blobs["quote.msg"],
        quote_sig=blobs["quote.sig"],
        quote_pcrs=blobs["quote.pcrs"],
    )

    ark = x509.load_pem_x509_certificate(evidence.ark_pem)
    ask = x509.load_pem_x509_certificate(evidence.ask_pem)
    vcek = x509.load_pem_x509_certificate(evidence.vcek_pem)
    crl = x509.load_der_x509_crl(evidence.ark_crl_der)
    starts = []
    stops = []
    for cert in (ark, ask, vcek):
        start, stop = _unix_window(cert)
        starts.append(start)
        stops.append(stop)
    starts.append(int(crl.last_update_utc.timestamp()))
    stops.append(int(crl.next_update_utc.timestamp()))
    assert max(starts) <= _APPRAISAL_UNIX <= min(stops)

    ark_der = _pem_body_der(evidence.ark_pem)
    ask_der = _pem_body_der(evidence.ask_pem)
    assert ark_der == ark.public_bytes(serialization.Encoding.DER)
    assert ask_der == ask.public_bytes(serialization.Encoding.DER)

    report, _claim, runtime = _parse_hcla(evidence.hcl_report)
    extra, qualified, select, pcr_digest = _parse_quote_msg(evidence.quote_msg)
    sig_bytes = _parse_quote_sig(evidence.quote_sig)
    pcr_pairs = _parse_pcrs(evidence.quote_pcrs)
    assert _bits_set(select) == tuple(item[0] for item in pcr_pairs)
    concat = b"".join(item[1] for item in pcr_pairs)
    assert hmac.compare_digest(_sha256(concat), pcr_digest)

    r = int.from_bytes(report[0x2A0:0x2E8], "little")
    s = int.from_bytes(report[0x2E8:0x330], "little")
    vcek_key = vcek.public_key()
    assert isinstance(vcek_key, ec.EllipticCurvePublicKey)
    vcek_key.verify(
        utils.encode_dss_signature(r, s),
        report[:0x2A0],
        ec.ECDSA(hashes.SHA384()),
    )

    ak_public = serialization.load_pem_public_key(evidence.ak_public_pem)
    assert isinstance(ak_public, rsa.RSAPublicKey)
    tpmt_modulus = _parse_tpmt_public(evidence.ak_tpmt_public)
    numbers = ak_public.public_numbers()
    pem_modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    keys = runtime["keys"]
    assert type(keys) is list
    ak_jwk = None
    for item in keys:
        if type(item) is dict and item.get("kid") == "HCLAkPub":
            ak_jwk = item
            break
    assert ak_jwk is not None
    jwk_modulus = _b64url(ak_jwk["n"])
    jwk_exponent = _b64url(ak_jwk["e"])
    assert tpmt_modulus == pem_modulus == jwk_modulus
    assert int.from_bytes(jwk_exponent, "big") == numbers.e
    ak_public.verify(
        sig_bytes,
        evidence.quote_msg,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    parent_qn = blobs["ak-parent-qualified-name.bin"]
    assert parent_qn == (0x4000000B).to_bytes(4, "big")
    ordinary = _TPM_SHA256.to_bytes(2, "big") + _sha256(evidence.ak_tpmt_public)
    qualified_name = _TPM_SHA256.to_bytes(2, "big") + _sha256(parent_qn + ordinary)
    assert hmac.compare_digest(ordinary, blobs["ak-name.bin"])
    assert hmac.compare_digest(qualified_name, blobs["ak-qualified-name.bin"])
    assert hmac.compare_digest(qualified, qualified_name)

    reported = report[0x180:0x188]
    chip_id = report[0x1A0:0x1E0]
    assert len(chip_id) == 64 and chip_id != bytes(64)
    ima = None
    baseline = []
    for index, digest in pcr_pairs:
        if index == 10:
            ima = digest
        else:
            baseline.append((index, digest))
    assert ima is not None and len(baseline) == 14

    expectations = FrozenExpectations(
        appraisal_unix=_APPRAISAL_UNIX,
        quote_extra_data=extra,
        ark_der_sha256=_sha256(ark_der),
        ask_der_sha256=_sha256(ask_der),
        ark_crl_der_sha256=_sha256(evidence.ark_crl_der),
        ak_parent_qualified_name=parent_qn,
        snp_report_version=int.from_bytes(report[0x000:0x004], "little"),
        snp_policy=_u64le(report, 0x008),
        snp_vmpl=_u32le(report, 0x030),
        snp_measurement=report[0x090:0x0C0],
        snp_host_data=report[0x0C0:0x0E0],
        minimum_tcb=FrozenTcbFloor(
            boot_loader=reported[0],
            tee=reported[1],
            snp=reported[6],
            microcode=reported[7],
        ),
        vcek_product_name=_product_name(evidence.vcek_pem),
        cpuid_family=report[0x188],
        cpuid_model=report[0x189],
        cpuid_step=report[0x18A],
        baseline_pcrs=tuple(baseline),
        ima_pcr10=ima,
    )
    assert blobs["ark-revokes-ask.crl.der"] != evidence.ark_crl_der
    return evidence, expectations


def _pcr_bitmap(indexes, size=3):
    bitmap = bytearray(size)
    for index in indexes:
        bitmap[index // 8] |= 1 << (index % 8)
    return bytes(bitmap)


_PCR_BITMAP = _pcr_bitmap(_PCR_INDEXES)
assert _PCR_BITMAP == bytes((0x95, 0xFF, 0xC1))


def _b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _der_uint_encode(value):
    if value < 0:
        raise ValueError("der")
    if value == 0:
        return b"\x02\x01\x00"
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return bytes((0x02, len(body))) + body


def _der_ia5_encode(value):
    return bytes((0x16, len(value))) + value


def _der_octet_encode(value):
    if len(value) < 128:
        return bytes((0x04, len(value))) + value
    raise ValueError("der")


def _cn(text):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def _sign_cert(builder, key):
    return builder.sign(key, hashes.SHA384(), rsa_padding=_PSS)


def _sign_crl(builder, key):
    return builder.sign(key, hashes.SHA384(), rsa_padding=_PSS)


def _amd_values(tcb, chip, product):
    return {
        "1": 0,
        "2": product,
        "3.1": tcb[0],
        "3.2": tcb[1],
        "3.3": tcb[6],
        "3.4": tcb[2],
        "3.5": tcb[3],
        "3.6": tcb[4],
        "3.7": tcb[5],
        "3.8": tcb[7],
        "4": chip,
    }


def _amd_der(suffix, value):
    if suffix == "2":
        return _der_ia5_encode(value)
    if suffix == "4":
        return _der_octet_encode(value)
    return _der_uint_encode(value)


def _tpm2b(data):
    return len(data).to_bytes(2, "big") + data


def _jwk(kid, ops, modulus, exponent=65537):
    exp = exponent.to_bytes((exponent.bit_length() + 7) // 8, "big")
    return {
        "e": _b64url_encode(exp),
        "kid": kid,
        "key_ops": ops,
        "kty": "RSA",
        "n": _b64url_encode(modulus),
    }


class _Kit:
    def __init__(self):
        self.ark_key = rsa.generate_private_key(65537, 4096)
        self.ask_key = rsa.generate_private_key(65537, 4096)
        self.vcek_key = ec.generate_private_key(ec.SECP384R1())
        self.ak_key = rsa.generate_private_key(65537, 2048)
        self.ek_key = rsa.generate_private_key(65537, 2048)
        self.tcb = bytes((5, 2, 0, 0, 0, 0, 26, 219))
        self.chip = bytes((0x42,)) * 64
        self.product = b"GENOA-B0"
        self.measurement = bytes(range(48))
        self.host_data = bytes(range(32, 64))
        self.extra = bytes(range(96, 128))
        self.policy = 0x00030000
        self.version = 5
        self.vmpl = 0
        self.cpuid = (0x19, 0x11, 0x01)
        self.pcr_map = {
            index: hashlib.sha256(b"pcr" + bytes((index,))).digest()
            for index in _PCR_INDEXES
        }
        self.not_before = datetime(2026, 1, 1, tzinfo=_UTC)
        self.not_after = datetime(2036, 1, 1, tzinfo=_UTC)
        self.crl_last = datetime(2026, 6, 1, tzinfo=_UTC)
        self.crl_next = datetime(2035, 1, 1, tzinfo=_UTC)
        self.ark_cert = self._build_ark()
        self.ask_cert = self._build_ask()
        self.vcek_cert = self._build_vcek(self._amd())
        self.crl = self._build_crl(())
        self.ak_mod = self.ak_key.public_key().public_numbers().n.to_bytes(256, "big")
        self.ek_mod = self.ek_key.public_key().public_numbers().n.to_bytes(256, "big")
        self.claim = self._build_claim(self._ak_jwk(), self._ek_jwk())
        self.report = self._build_report(self.claim, self.tcb, self.tcb, self.tcb, self.tcb)
        self.hcla = self._wrap_hcla(self.report, self.claim)
        self.tpmt = self._tpmt(0x00050072, 65537)
        self.ak_pem = self.ak_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.qn = self._qualified(self.tpmt)
        self.pcr_list = tuple(self.pcr_map[index] for index in _PCR_INDEXES)
        self.pcr_digest = _sha256(b"".join(self.pcr_list))
        self.quote_msg = self._quote_msg(
            self.qn, self.extra, _PCR_BITMAP, self.pcr_digest, 1
        )
        self.quote_sig = self._quote_sig(self.quote_msg)
        self.quote_pcrs = self._pcrs_file(self.pcr_list, _PCR_BITMAP, (8, 7))
        self.evidence, self.expectations = self._assemble(
            self.vcek_cert, self.crl, self.hcla, self.tpmt, self.quote_msg,
            self.quote_sig, self.quote_pcrs, self.pcr_map,
        )

    def _amd(self, tcb=None, chip=None, product=None):
        return _amd_values(
            self.tcb if tcb is None else tcb,
            self.chip if chip is None else chip,
            self.product if product is None else product,
        )

    def _build_ark(self):
        name = _cn("ARK-Fresh")
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.ark_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self.not_before)
            .not_valid_after(self.not_after)
            .add_extension(x509.BasicConstraints(True, 1), True)
            .add_extension(_KU_ARK, True)
        )
        return _sign_cert(builder, self.ark_key)

    def _build_ask(self):
        builder = (
            x509.CertificateBuilder()
            .subject_name(_cn("ASK-Fresh"))
            .issuer_name(self.ark_cert.subject)
            .public_key(self.ask_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self.not_before)
            .not_valid_after(self.not_after)
            .add_extension(x509.BasicConstraints(True, 0), True)
            .add_extension(_KU_ASK, True)
        )
        return _sign_cert(builder, self.ark_key)

    def _build_vcek(
        self,
        amd,
        ski_aki=True,
        ski=None,
        aki=None,
        ski_critical=False,
        aki_critical=False,
        extra_ext=None,
    ):
        builder = (
            x509.CertificateBuilder()
            .subject_name(_cn("VCEK-Fresh"))
            .issuer_name(self.ask_cert.subject)
            .public_key(self.vcek_key.public_key())
            .serial_number(1)
            .not_valid_before(self.not_before)
            .not_valid_after(self.not_after)
        )
        for suffix, value in amd.items():
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier(_AMD_PREFIX + suffix),
                    _amd_der(suffix, value),
                ),
                False,
            )
        if ski_aki or ski is not None:
            if ski is None:
                ski = x509.SubjectKeyIdentifier.from_public_key(self.vcek_key.public_key())
            builder = builder.add_extension(ski, ski_critical)
        if ski_aki or aki is not None:
            if aki is None:
                ask_ski = x509.SubjectKeyIdentifier.from_public_key(self.ask_key.public_key())
                aki = x509.AuthorityKeyIdentifier(ask_ski.digest, None, None)
            builder = builder.add_extension(aki, aki_critical)
        if extra_ext is not None:
            ext, critical = extra_ext
            builder = builder.add_extension(ext, critical)
        # cryptography 46 refuses serial 0 on the builder; VCEK ABI requires it.
        builder._serial_number = 0
        return _sign_cert(builder, self.ask_key)

    def _build_crl(self, serials):
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ark_cert.subject)
            .last_update(self.crl_last)
            .next_update(self.crl_next)
        )
        for serial in serials:
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(self.crl_last)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)
        return _sign_crl(builder, self.ark_key)

    def _ak_jwk(self, **changes):
        item = _jwk("HCLAkPub", ["sign"], self.ak_mod)
        item.update(changes)
        return item

    def _ek_jwk(self, **changes):
        item = _jwk("HCLEkPub", ["encrypt"], self.ek_mod)
        item.update(changes)
        return item

    def _build_claim(self, ak_jwk, ek_jwk, extra_top=None):
        obj = {
            "keys": [ak_jwk, ek_jwk],
            "vm-configuration": {"secure-boot": True, "tpm-enabled": True},
        }
        if extra_top:
            obj.update(extra_top)
        return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("ascii")

    def _build_report(
        self,
        claim,
        current,
        reported,
        committed,
        launch,
        chip=None,
        policy=None,
        vmpl=None,
        cpuid=None,
        measurement=None,
        host=None,
    ):
        buf = bytearray(1184)
        struct.pack_into("<I", buf, 0x000, self.version)
        struct.pack_into("<Q", buf, 0x008, self.policy if policy is None else policy)
        struct.pack_into("<I", buf, 0x030, self.vmpl if vmpl is None else vmpl)
        struct.pack_into("<I", buf, 0x034, 1)
        buf[0x038:0x040] = current
        digest = _sha256(claim)
        buf[0x050:0x070] = digest
        buf[0x070:0x090] = bytes(32)
        buf[0x090:0x0C0] = self.measurement if measurement is None else measurement
        buf[0x0C0:0x0E0] = self.host_data if host is None else host
        buf[0x180:0x188] = reported
        family, model, step = self.cpuid if cpuid is None else cpuid
        buf[0x188] = family
        buf[0x189] = model
        buf[0x18A] = step
        buf[0x1A0:0x1E0] = self.chip if chip is None else chip
        buf[0x1E0:0x1E8] = committed
        buf[0x1F0:0x1F8] = launch
        der = self.vcek_key.sign(bytes(buf[:0x2A0]), ec.ECDSA(hashes.SHA384()))
        r_val, s_val = utils.decode_dss_signature(der)
        buf[0x2A0:0x2E8] = r_val.to_bytes(72, "little")
        buf[0x2E8:0x330] = s_val.to_bytes(72, "little")
        return bytes(buf)

    def _wrap_hcla(self, report, claim):
        claim_size = len(claim)
        data_size = 20 + claim_size
        report_size = 32 + 1184 + data_size
        header = bytearray(32)
        header[0:4] = b"HCLA"
        struct.pack_into("<I", header, 4, 2)
        struct.pack_into("<I", header, 8, report_size)
        struct.pack_into("<I", header, 12, 2)
        meta = struct.pack("<5I", data_size, 1, 2, 1, claim_size)
        blob = bytes(header) + report + meta + claim
        assert len(blob) <= 2600
        return blob + bytes(2600 - len(blob))

    def _tpmt(self, attrs, exponent):
        out = bytearray()
        out += _TPM_RSA.to_bytes(2, "big")
        out += _TPM_SHA256.to_bytes(2, "big")
        out += attrs.to_bytes(4, "big")
        out += (0).to_bytes(2, "big")
        out += _TPM_NULL.to_bytes(2, "big")
        out += _TPM_RSASSA.to_bytes(2, "big")
        out += _TPM_SHA256.to_bytes(2, "big")
        out += (2048).to_bytes(2, "big")
        out += exponent.to_bytes(4, "big")
        out += (256).to_bytes(2, "big")
        out += self.ak_mod
        return bytes(out)

    def _qualified(self, tpmt):
        name = _TPM_SHA256.to_bytes(2, "big") + _sha256(tpmt)
        return _TPM_SHA256.to_bytes(2, "big") + _sha256(_PARENT_QN + name)

    def _quote_msg(self, qn, extra, bitmap, digest, safe):
        out = bytearray()
        out += _TPM_GENERATED.to_bytes(4, "big")
        out += _TPM_ST_QUOTE.to_bytes(2, "big")
        out += _tpm2b(qn)
        out += _tpm2b(extra)
        out += (0x0807060504030201).to_bytes(8, "big")
        out += (7).to_bytes(4, "big")
        out += (3).to_bytes(4, "big")
        out += bytes((safe,))
        out += (0xAABBCCDDEEFF0011).to_bytes(8, "big")
        out += (1).to_bytes(4, "big")
        out += _TPM_SHA256.to_bytes(2, "big")
        out += bytes((len(bitmap),))
        out += bitmap
        out += _tpm2b(digest)
        return bytes(out)

    def _quote_sig(self, msg):
        raw = self.ak_key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        return (
            _TPM_RSASSA.to_bytes(2, "big")
            + _TPM_SHA256.to_bytes(2, "big")
            + _tpm2b(raw)
        )

    def _pcrs_file(self, values, bitmap, counts, mutate_slot=None):
        out = bytearray()
        out += (1).to_bytes(4, "little")
        out += _TPM_SHA256.to_bytes(2, "little")
        out += bytes((3,))
        out += bitmap + bytes(8 - len(bitmap))
        out += bytes(5)
        for _ in range(7):
            out += bytes(16)
        out += (2).to_bytes(4, "little")
        offset = 0
        for count in counts:
            out += int(count).to_bytes(4, "little")
            for slot in range(8):
                if slot < count:
                    digest = values[offset]
                    offset += 1
                    size = 32
                    buffer = digest + bytes(32)
                else:
                    size = 0
                    buffer = bytes(64)
                if mutate_slot is not None:
                    size, buffer = mutate_slot(count, slot, size, buffer)
                out += int(size).to_bytes(2, "little")
                out += buffer
        return bytes(out)

    def _assemble(
        self, vcek_cert, crl, hcla, tpmt, quote_msg, quote_sig, quote_pcrs, pcr_map
    ):
        ark_der = self.ark_cert.public_bytes(serialization.Encoding.DER)
        ask_der = self.ask_cert.public_bytes(serialization.Encoding.DER)
        crl_der = crl.public_bytes(serialization.Encoding.DER)
        baseline = tuple((index, pcr_map[index]) for index in _BASELINE_INDEXES)
        evidence = FrozenEvidence(
            ark_pem=self.ark_cert.public_bytes(serialization.Encoding.PEM),
            ask_pem=self.ask_cert.public_bytes(serialization.Encoding.PEM),
            vcek_pem=vcek_cert.public_bytes(serialization.Encoding.PEM),
            ark_crl_der=crl_der,
            ak_public_pem=self.ak_pem,
            ak_tpmt_public=tpmt,
            hcl_report=hcla,
            quote_msg=quote_msg,
            quote_sig=quote_sig,
            quote_pcrs=quote_pcrs,
        )
        expectations = FrozenExpectations(
            appraisal_unix=_FRESH_UNIX,
            quote_extra_data=self.extra,
            ark_der_sha256=_sha256(ark_der),
            ask_der_sha256=_sha256(ask_der),
            ark_crl_der_sha256=_sha256(crl_der),
            ak_parent_qualified_name=_PARENT_QN,
            snp_report_version=self.version,
            snp_policy=self.policy,
            snp_vmpl=self.vmpl,
            snp_measurement=self.measurement,
            snp_host_data=self.host_data,
            minimum_tcb=FrozenTcbFloor(
                boot_loader=self.tcb[0],
                tee=self.tcb[1],
                snp=self.tcb[6],
                microcode=self.tcb[7],
            ),
            vcek_product_name=self.product,
            cpuid_family=self.cpuid[0],
            cpuid_model=self.cpuid[1],
            cpuid_step=self.cpuid[2],
            baseline_pcrs=baseline,
            ima_pcr10=pcr_map[10],
        )
        return evidence, expectations


_KIT = None


def _kit():
    global _KIT
    if _KIT is None:
        _KIT = _Kit()
    return _KIT


def _assert_vcek_report(vcek_pem, report):
    cert = x509.load_pem_x509_certificate(vcek_pem)
    key = cert.public_key()
    r_val = int.from_bytes(report[0x2A0:0x2E8], "little")
    s_val = int.from_bytes(report[0x2E8:0x330], "little")
    key.verify(
        utils.encode_dss_signature(r_val, s_val),
        report[:0x2A0],
        ec.ECDSA(hashes.SHA384()),
    )


def _assert_ask_vcek(ask_pem, vcek_pem):
    ask = x509.load_pem_x509_certificate(ask_pem)
    vcek = x509.load_pem_x509_certificate(vcek_pem)
    ask.public_key().verify(
        vcek.signature, vcek.tbs_certificate_bytes, _PSS, hashes.SHA384()
    )


def _assert_ark_crl(ark_pem, crl_der):
    ark = x509.load_pem_x509_certificate(ark_pem)
    crl = x509.load_der_x509_crl(crl_der)
    ark.public_key().verify(crl.signature, crl.tbs_certlist_bytes, _PSS, hashes.SHA384())


def _assert_ak_quote(ak_pem, msg, sig_blob):
    key = serialization.load_pem_public_key(ak_pem)
    walk = _Walk(sig_blob, "big")
    walk.number(2)
    walk.number(2)
    raw = walk.pull(walk.number(2))
    walk.done()
    key.verify(raw, msg, padding.PKCS1v15(), hashes.SHA256())


def _check_fresh(evidence, expectations):
    report, claim, runtime = _parse_hcla(evidence.hcl_report)
    extra, qualified, select, pcr_digest = _parse_quote_msg(evidence.quote_msg)
    pairs = _parse_pcrs(evidence.quote_pcrs)
    assert extra == expectations.quote_extra_data
    assert _bits_set(select) == _PCR_INDEXES
    assert hmac.compare_digest(_sha256(b"".join(item[1] for item in pairs)), pcr_digest)
    _assert_vcek_report(evidence.vcek_pem, report)
    _assert_ak_quote(evidence.ak_public_pem, evidence.quote_msg, evidence.quote_sig)
    keys = runtime["keys"]
    assert type(keys) is list and len(keys) == 2
    kids = [item["kid"] for item in keys]
    assert kids == ["HCLAkPub", "HCLEkPub"]
    for item in keys:
        assert set(item) == {"e", "kid", "key_ops", "kty", "n"}
    digest = _oracle_commitment(evidence, expectations)
    assert len(digest) == 32
    return digest


def fresh_positive():
    kit = _kit()
    _check_fresh(kit.evidence, kit.expectations)
    _assert_ask_vcek(kit.evidence.ask_pem, kit.evidence.vcek_pem)
    _assert_ark_crl(kit.evidence.ark_pem, kit.evidence.ark_crl_der)
    return kit.evidence, kit.expectations


def fresh_positive_attr_50472():
    kit = _kit()
    tpmt = kit._tpmt(0x00050472, 65537)
    qn = kit._qualified(tpmt)
    msg = kit._quote_msg(qn, kit.extra, _PCR_BITMAP, kit.pcr_digest, 1)
    sig = kit._quote_sig(msg)
    evidence, expectations = kit._assemble(
        kit.vcek_cert, kit.crl, kit.hcla, tpmt, msg, sig, kit.quote_pcrs, kit.pcr_map
    )
    _check_fresh(evidence, expectations)
    return evidence, expectations


def _vcek_twin(amd, **opts):
    kit = _kit()
    cert = kit._build_vcek(amd, **opts)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    _assert_ask_vcek(kit.evidence.ask_pem, pem)
    return replace(kit.evidence, vcek_pem=pem), kit.expectations


def twin_vcek_ext_1():
    """VCEK OID .1 not zero."""
    kit = _kit()
    amd = kit._amd()
    amd["1"] = 1
    return _vcek_twin(amd)


def twin_vcek_ext_2():
    """VCEK product IA5String disagrees with expectations."""
    kit = _kit()
    amd = kit._amd()
    amd["2"] = b"MILAN-B0"
    return _vcek_twin(amd)


def _twin_vcek_tcb(suffix, new_value):
    kit = _kit()
    amd = kit._amd()
    amd[suffix] = new_value
    return _vcek_twin(amd)


def twin_vcek_ext_3_1():
    return _twin_vcek_tcb("3.1", _kit().tcb[0] + 1)


def twin_vcek_ext_3_2():
    return _twin_vcek_tcb("3.2", _kit().tcb[1] + 1)


def twin_vcek_ext_3_3():
    return _twin_vcek_tcb("3.3", _kit().tcb[6] + 1)


def twin_vcek_ext_3_4():
    return _twin_vcek_tcb("3.4", 1)


def twin_vcek_ext_3_5():
    return _twin_vcek_tcb("3.5", 1)


def twin_vcek_ext_3_6():
    return _twin_vcek_tcb("3.6", 1)


def twin_vcek_ext_3_7():
    return _twin_vcek_tcb("3.7", 1)


def twin_vcek_ext_3_8():
    return _twin_vcek_tcb("3.8", (_kit().tcb[7] + 1) % 256)


def twin_vcek_ext_4():
    kit = _kit()
    amd = kit._amd()
    amd["4"] = bytes((0x41,)) * 64
    return _vcek_twin(amd)


def twin_vcek_ski_only():
    kit = _kit()
    ski = x509.SubjectKeyIdentifier.from_public_key(kit.vcek_key.public_key())
    return _vcek_twin(kit._amd(), ski_aki=False, ski=ski)


def twin_vcek_aki_only():
    kit = _kit()
    ask_ski = x509.SubjectKeyIdentifier.from_public_key(kit.ask_key.public_key())
    aki = x509.AuthorityKeyIdentifier(ask_ski.digest, None, None)
    return _vcek_twin(kit._amd(), ski_aki=False, aki=aki)


def twin_vcek_ski_wrong():
    kit = _kit()
    ski = x509.SubjectKeyIdentifier(digest=bytes((0x11,)) * 20)
    ask_ski = x509.SubjectKeyIdentifier.from_public_key(kit.ask_key.public_key())
    aki = x509.AuthorityKeyIdentifier(ask_ski.digest, None, None)
    return _vcek_twin(kit._amd(), ski_aki=False, ski=ski, aki=aki)


def twin_vcek_aki_wrong():
    kit = _kit()
    ski = x509.SubjectKeyIdentifier.from_public_key(kit.vcek_key.public_key())
    aki = x509.AuthorityKeyIdentifier(bytes((0x22,)) * 20, None, None)
    return _vcek_twin(kit._amd(), ski_aki=False, ski=ski, aki=aki)


def twin_vcek_ski_aki_critical():
    return _vcek_twin(_kit()._amd(), ski_critical=True, aki_critical=True)


def twin_vcek_extra_extension():
    extra = (
        x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4.5.6"), b"\x04\x01\x00"),
        False,
    )
    return _vcek_twin(_kit()._amd(), extra_ext=extra)


def _report_twin(**report_kw):
    kit = _kit()
    current = report_kw.pop("current", kit.tcb)
    reported = report_kw.pop("reported", kit.tcb)
    committed = report_kw.pop("committed", kit.tcb)
    launch = report_kw.pop("launch", kit.tcb)
    vcek_cert = report_kw.pop("vcek_cert", kit.vcek_cert)
    expectations = report_kw.pop("expectations", None)
    report = kit._build_report(
        kit.claim, current, reported, committed, launch, **report_kw
    )
    hcla = kit._wrap_hcla(report, kit.claim)
    _assert_vcek_report(vcek_cert.public_bytes(serialization.Encoding.PEM), report)
    evidence = replace(
        kit.evidence,
        vcek_pem=vcek_cert.public_bytes(serialization.Encoding.PEM),
        hcl_report=hcla,
    )
    if expectations is None:
        expectations = kit.expectations
    return evidence, expectations


def twin_chip_id_mismatch():
    return _report_twin(chip=bytes((0x43,)) * 64)


def twin_reported_tcb_mismatch():
    reported = bytearray(_kit().tcb)
    reported[0] = (reported[0] + 1) & 0xFF
    return _report_twin(reported=bytes(reported))


def twin_debug_bit():
    kit = _kit()
    policy = kit.policy | (1 << 19)
    evidence, _unused = _report_twin(policy=policy)
    return evidence, replace(kit.expectations, snp_policy=policy)


def twin_vmpl_expectation():
    return _report_twin(vmpl=1)


def twin_cpuid_family():
    kit = _kit()
    return _report_twin(cpuid=(0x18, kit.cpuid[1], kit.cpuid[2]))


def twin_cpuid_model_expectation():
    kit = _kit()
    return kit.evidence, replace(kit.expectations, cpuid_model=0)


def twin_measurement_expectation():
    kit = _kit()
    return kit.evidence, replace(kit.expectations, snp_measurement=bytes(48))


def twin_host_data_expectation():
    kit = _kit()
    return kit.evidence, replace(kit.expectations, snp_host_data=bytes(32))


def twin_floor_current_boot():
    kit = _kit()
    current = bytearray(kit.tcb)
    current[0] = kit.tcb[0] - 1
    return _report_twin(current=bytes(current))


def twin_floor_committed_tee():
    kit = _kit()
    committed = bytearray(kit.tcb)
    committed[1] = kit.tcb[1] - 1
    return _report_twin(committed=bytes(committed))


def twin_floor_launch_snp():
    kit = _kit()
    launch = bytearray(kit.tcb)
    launch[6] = kit.tcb[6] - 1
    return _report_twin(launch=bytes(launch))


def twin_floor_reported_ucode():
    kit = _kit()
    reported = bytearray(kit.tcb)
    reported[7] = kit.tcb[7] - 1
    amd = kit._amd(tcb=bytes(reported))
    cert = kit._build_vcek(amd)
    _assert_ask_vcek(kit.evidence.ask_pem, cert.public_bytes(serialization.Encoding.PEM))
    return _report_twin(reported=bytes(reported), vcek_cert=cert)


def twin_reserved_current():
    kit = _kit()
    current = bytearray(kit.tcb)
    current[2] = 1
    return _report_twin(current=bytes(current))


def twin_reserved_reported():
    kit = _kit()
    reported = bytearray(kit.tcb)
    reported[2] = 1
    amd = kit._amd(tcb=bytes(reported))
    cert = kit._build_vcek(amd)
    _assert_ask_vcek(kit.evidence.ask_pem, cert.public_bytes(serialization.Encoding.PEM))
    return _report_twin(reported=bytes(reported), vcek_cert=cert)


def _hcla_twin(claim):
    kit = _kit()
    report = kit._build_report(claim, kit.tcb, kit.tcb, kit.tcb, kit.tcb)
    hcla = kit._wrap_hcla(report, claim)
    _assert_vcek_report(kit.evidence.vcek_pem, report)
    return replace(kit.evidence, hcl_report=hcla), kit.expectations


def twin_hcla_missing_n():
    kit = _kit()
    ak = kit._ak_jwk()
    del ak["n"]
    return _hcla_twin(kit._build_claim(ak, kit._ek_jwk()))


def twin_hcla_extra_field():
    kit = _kit()
    ak = kit._ak_jwk()
    ak["x"] = "y"
    return _hcla_twin(kit._build_claim(ak, kit._ek_jwk()))


def twin_hcla_private_d():
    kit = _kit()
    ak = kit._ak_jwk()
    ak["d"] = _b64url_encode(b"\x01" + bytes(31))
    return _hcla_twin(kit._build_claim(ak, kit._ek_jwk()))


def twin_hcla_duplicate_kid():
    kit = _kit()
    obj = {
        "keys": [kit._ak_jwk(), kit._ak_jwk(), kit._ek_jwk()],
        "vm-configuration": {"secure-boot": True, "tpm-enabled": True},
    }
    claim = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("ascii")
    return _hcla_twin(claim)


def twin_hcla_duplicate_json_key():
    kit = _kit()
    base = kit._build_claim(kit._ak_jwk(), kit._ek_jwk())
    claim = b'{"dup":1,"dup":2,' + base[1:]
    return _hcla_twin(claim)


def twin_hcla_bad_ek_ops():
    kit = _kit()
    ek = kit._ek_jwk()
    ek["key_ops"] = ["verify"]
    return _hcla_twin(kit._build_claim(kit._ak_jwk(), ek))


def twin_ask_revoked():
    kit = _kit()
    crl = kit._build_crl((kit.ask_cert.serial_number,))
    der = crl.public_bytes(serialization.Encoding.DER)
    _assert_ark_crl(kit.evidence.ark_pem, der)
    evidence = replace(kit.evidence, ark_crl_der=der)
    expectations = replace(kit.expectations, ark_crl_der_sha256=_sha256(der))
    return evidence, expectations


def _quote_twin(msg, pcrs=None, expectations=None):
    kit = _kit()
    sig = kit._quote_sig(msg)
    _assert_ak_quote(kit.ak_pem, msg, sig)
    evidence = replace(
        kit.evidence,
        quote_msg=msg,
        quote_sig=sig,
        quote_pcrs=kit.quote_pcrs if pcrs is None else pcrs,
    )
    if expectations is None:
        expectations = kit.expectations
    return evidence, expectations


def twin_quote_qn():
    kit = _kit()
    qn = bytearray(kit.qn)
    qn[4] ^= 1
    msg = kit._quote_msg(bytes(qn), kit.extra, _PCR_BITMAP, kit.pcr_digest, 1)
    return _quote_twin(msg)


def twin_quote_challenge():
    kit = _kit()
    extra = bytes((0x99,)) * 32
    msg = kit._quote_msg(kit.qn, extra, _PCR_BITMAP, kit.pcr_digest, 1)
    return _quote_twin(msg)


def twin_quote_safe():
    kit = _kit()
    msg = kit._quote_msg(kit.qn, kit.extra, _PCR_BITMAP, kit.pcr_digest, 0)
    return _quote_twin(msg)


def twin_quote_selection():
    kit = _kit()
    bitmap = _pcr_bitmap((2, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 22, 23))
    selected = [kit.pcr_map[i] for i in (2, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 22, 23)]
    digest = _sha256(b"".join(selected))
    msg = kit._quote_msg(kit.qn, kit.extra, bitmap, digest, 1)
    return _quote_twin(msg)


def twin_quote_digest():
    kit = _kit()
    digest = bytes((0x5A,)) * 32
    msg = kit._quote_msg(kit.qn, kit.extra, _PCR_BITMAP, digest, 1)
    return _quote_twin(msg)


def twin_pcr_file_selection():
    kit = _kit()
    bitmap = _pcr_bitmap((0, 2, 4, 7, 8, 9, 11, 12, 13, 14, 15, 16, 22, 23))
    values = list(kit.pcr_list)
    pcrs = kit._pcrs_file(values, bitmap, (8, 7))
    return replace(kit.evidence, quote_pcrs=pcrs), kit.expectations


def twin_pcr_list1_count():
    kit = _kit()
    pcrs = kit._pcrs_file(kit.pcr_list, _PCR_BITMAP, (7, 7))
    return replace(kit.evidence, quote_pcrs=pcrs), kit.expectations


def twin_pcr_list2_count():
    kit = _kit()
    pcrs = kit._pcrs_file(kit.pcr_list, _PCR_BITMAP, (8, 6))
    return replace(kit.evidence, quote_pcrs=pcrs), kit.expectations


def twin_pcr_active_size():
    kit = _kit()

    def mutate(count, slot, size, buffer):
        if count == 8 and slot == 0:
            return 31, buffer
        return size, buffer

    pcrs = kit._pcrs_file(kit.pcr_list, _PCR_BITMAP, (8, 7), mutate)
    return replace(kit.evidence, quote_pcrs=pcrs), kit.expectations


def twin_pcr_inactive_size():
    kit = _kit()

    def mutate(count, slot, size, buffer):
        if count == 7 and slot == 7:
            return 32, buffer
        return size, buffer

    pcrs = kit._pcrs_file(kit.pcr_list, _PCR_BITMAP, (8, 7), mutate)
    return replace(kit.evidence, quote_pcrs=pcrs), kit.expectations


def twin_pcr_inactive_pad():
    kit = _kit()

    def mutate(count, slot, size, buffer):
        if count == 7 and slot == 7:
            return 0, bytes((1,)) + bytes(63)
        return size, buffer

    pcrs = kit._pcrs_file(kit.pcr_list, _PCR_BITMAP, (8, 7), mutate)
    return replace(kit.evidence, quote_pcrs=pcrs), kit.expectations


def twin_pcr_active_tail():
    kit = _kit()

    def mutate(count, slot, size, buffer):
        if count == 8 and slot == 0:
            return 32, buffer[:32] + bytes((1,)) + buffer[33:]
        return size, buffer

    pcrs = kit._pcrs_file(kit.pcr_list, _PCR_BITMAP, (8, 7), mutate)
    return replace(kit.evidence, quote_pcrs=pcrs), kit.expectations


def twin_pcr_composite():
    kit = _kit()
    values = list(kit.pcr_list)
    values[0], values[1] = values[1], values[0]
    pcrs = kit._pcrs_file(values, _PCR_BITMAP, (8, 7))
    return replace(kit.evidence, quote_pcrs=pcrs), kit.expectations


def twin_pcr_baseline():
    kit = _kit()
    values = list(kit.pcr_list)
    values[0] = hashlib.sha256(b"baseline-mismatch").digest()
    digest = _sha256(b"".join(values))
    msg = kit._quote_msg(kit.qn, kit.extra, _PCR_BITMAP, digest, 1)
    pcrs = kit._pcrs_file(values, _PCR_BITMAP, (8, 7))
    return _quote_twin(msg, pcrs=pcrs)


def twin_pcr10():
    kit = _kit()
    values = list(kit.pcr_list)
    values[6] = hashlib.sha256(b"pcr10-mismatch").digest()
    digest = _sha256(b"".join(values))
    msg = kit._quote_msg(kit.qn, kit.extra, _PCR_BITMAP, digest, 1)
    pcrs = kit._pcrs_file(values, _PCR_BITMAP, (8, 7))
    return _quote_twin(msg, pcrs=pcrs)


FRESH_TWINS = (
    ("vcek_ext_1", twin_vcek_ext_1),
    ("vcek_ext_2", twin_vcek_ext_2),
    ("vcek_ext_3_1", twin_vcek_ext_3_1),
    ("vcek_ext_3_2", twin_vcek_ext_3_2),
    ("vcek_ext_3_3", twin_vcek_ext_3_3),
    ("vcek_ext_3_4", twin_vcek_ext_3_4),
    ("vcek_ext_3_5", twin_vcek_ext_3_5),
    ("vcek_ext_3_6", twin_vcek_ext_3_6),
    ("vcek_ext_3_7", twin_vcek_ext_3_7),
    ("vcek_ext_3_8", twin_vcek_ext_3_8),
    ("vcek_ext_4", twin_vcek_ext_4),
    ("vcek_ski_only", twin_vcek_ski_only),
    ("vcek_aki_only", twin_vcek_aki_only),
    ("vcek_ski_wrong", twin_vcek_ski_wrong),
    ("vcek_aki_wrong", twin_vcek_aki_wrong),
    ("vcek_ski_aki_critical", twin_vcek_ski_aki_critical),
    ("vcek_extra_extension", twin_vcek_extra_extension),
    ("chip_id_mismatch", twin_chip_id_mismatch),
    ("reported_tcb_mismatch", twin_reported_tcb_mismatch),
    ("debug_bit", twin_debug_bit),
    ("vmpl_expectation", twin_vmpl_expectation),
    ("cpuid_family", twin_cpuid_family),
    ("cpuid_model_expectation", twin_cpuid_model_expectation),
    ("measurement_expectation", twin_measurement_expectation),
    ("host_data_expectation", twin_host_data_expectation),
    ("floor_current_boot", twin_floor_current_boot),
    ("floor_committed_tee", twin_floor_committed_tee),
    ("floor_launch_snp", twin_floor_launch_snp),
    ("floor_reported_ucode", twin_floor_reported_ucode),
    ("reserved_current", twin_reserved_current),
    ("reserved_reported", twin_reserved_reported),
    ("hcla_missing_n", twin_hcla_missing_n),
    ("hcla_extra_field", twin_hcla_extra_field),
    ("hcla_private_d", twin_hcla_private_d),
    ("hcla_duplicate_kid", twin_hcla_duplicate_kid),
    ("hcla_duplicate_json_key", twin_hcla_duplicate_json_key),
    ("hcla_bad_ek_ops", twin_hcla_bad_ek_ops),
    ("ask_revoked", twin_ask_revoked),
    ("quote_qn", twin_quote_qn),
    ("quote_challenge", twin_quote_challenge),
    ("quote_safe", twin_quote_safe),
    ("quote_selection", twin_quote_selection),
    ("quote_digest", twin_quote_digest),
    ("pcr_file_selection", twin_pcr_file_selection),
    ("pcr_list1_count", twin_pcr_list1_count),
    ("pcr_list2_count", twin_pcr_list2_count),
    ("pcr_active_size", twin_pcr_active_size),
    ("pcr_inactive_size", twin_pcr_inactive_size),
    ("pcr_inactive_pad", twin_pcr_inactive_pad),
    ("pcr_active_tail", twin_pcr_active_tail),
    ("pcr_composite", twin_pcr_composite),
    ("pcr_baseline", twin_pcr_baseline),
    ("pcr10", twin_pcr10),
)


def _static_independence():
    here = Path(__file__)
    source = here.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = set()
    fixture_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")
            if node.module == "conf_proc_spp_diag_attest_fixture":
                fixture_names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {
                "__import__",
                "eval",
                "exec",
                "open",
            }:
                raise AssertionError("dynamic or write-capable oracle call")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "open",
                "read_bytes",
                "write_bytes",
                "write_text",
                "glob",
                "rglob",
                "iterdir",
            }:
                raise AssertionError("write-capable oracle call")
    if imports != {
        "ast",
        "base64",
        "hashlib",
        "hmac",
        "json",
        "struct",
        "dataclasses",
        "datetime",
        "pathlib",
        "cryptography",
        "cryptography.hazmat.primitives",
        "cryptography.hazmat.primitives.asymmetric",
        "cryptography.x509.oid",
        "conf_proc_spp_diag_attest_fixture",
    }:
        raise AssertionError("oracle import set changed: %r" % (sorted(imports),))
    if fixture_names != {"fixture_bytes"}:
        raise AssertionError("oracle fixture names changed: %r" % (sorted(fixture_names),))
    forbidden = (
        "sub" + "process",
        "ct" + "ypes",
        "conf_proc_spp_diag_attest" + ".py",
        "conf_proc_spp_diag_attest_" + "reasons",
        "appraise_spp_diag_" + "attestation",
        "SppDiagAttest" + "Error",
        "EXPEC" + "TED_",
    )
    if any(token in source for token in forbidden):
        raise AssertionError("oracle reached forbidden authority")


def main():
    _static_independence()
    frozen_evidence, frozen_expectations = frozen_positive()
    frozen_digest = _oracle_commitment(frozen_evidence, frozen_expectations)
    assert len(frozen_digest) == 32
    print("frozen oracle: ok")
    print("frozen_commitment", frozen_digest.hex())
    fresh_evidence, fresh_expectations = fresh_positive()
    fresh_digest = _oracle_commitment(fresh_evidence, fresh_expectations)
    assert frozen_digest != fresh_digest
    print("fresh oracle: ok")
    print("fresh_commitment", fresh_digest.hex())
    extra_evidence, extra_expectations = fresh_positive_attr_50472()
    _check_fresh(extra_evidence, extra_expectations)
    print("fresh attr 0x00050472: ok")
    for name, builder in FRESH_TWINS:
        evidence, expectations = builder()
        assert type(evidence) is FrozenEvidence
        assert type(expectations) is FrozenExpectations
        print("twin", name, "ok")
    print("spp diagnostic attestation oracle: ok (%d twins)" % len(FRESH_TWINS))


if __name__ == "__main__":
    main()
