# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Independent appraisal of SPP diagnostic SNP/HCLA/TPM-quote evidence."""

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier, SignatureAlgorithmOID

from conf_proc_spp_diag_pcr import (
    QUOTE_PCR_BITMAP as _QUOTE_PCR_BITMAP,
    SPP_DIAG_BASELINE_PCR_SELECTION,
    SPP_DIAG_PCR_SELECTION,
)
from conf_proc_spp_diag_attest_reasons import (
    CP_SPP_DIAG_ATTEST_AK,
    CP_SPP_DIAG_ATTEST_CAP,
    CP_SPP_DIAG_ATTEST_CRL,
    CP_SPP_DIAG_ATTEST_HCLA,
    CP_SPP_DIAG_ATTEST_PCR,
    CP_SPP_DIAG_ATTEST_POLICY,
    CP_SPP_DIAG_ATTEST_PRIVACY,
    CP_SPP_DIAG_ATTEST_QUOTE,
    CP_SPP_DIAG_ATTEST_ROOT,
    CP_SPP_DIAG_ATTEST_SNP,
    CP_SPP_DIAG_ATTEST_TYPE,
    CP_SPP_DIAG_ATTEST_VCEK,
    CP_SPP_DIAG_ATTEST_X509,
    SppDiagAttestError,
)


MAX_CERT_PEM_BYTES = 16_384
MAX_CRL_DER_BYTES = 4_194_304
MAX_AK_PEM_BYTES = 4_096
MAX_AK_PUBLIC_BYTES = 1_024
HCLA_BYTES = 2_600
MAX_QUOTE_MSG_BYTES = 4_096
MAX_QUOTE_SIG_BYTES = 1_024
MAX_QUOTE_PCRS_BYTES = 8_192

_STATUS = "diagnostic_attestation_verified"
_COMMITMENT_DOMAIN = b"solpbc:conf-proc:spp-diag-attestation:v1\0"
_AK_PARENT_QN = bytes.fromhex("4000000b")
_AMD_PREFIX = "1.3.6.1.4.1.3704.1."
_AMD_SPECS = (
    ("1", 0x02),
    ("2", 0x16),
    ("3.1", 0x02),
    ("3.2", 0x02),
    ("3.3", 0x02),
    ("3.4", 0x02),
    ("3.5", 0x02),
    ("3.6", 0x02),
    ("3.7", 0x02),
    ("3.8", 0x02),
    ("4", 0x04),
)
_AMD_OIDS = tuple(ObjectIdentifier(_AMD_PREFIX + suffix) for suffix, _tag in _AMD_SPECS)
_SNP_REPORT_BYTES = 1184
_SNP_FAMILY_19H = 0x19
_POLICY_DEBUG_BIT = 19
_TPM_GENERATED_VALUE = 0xFF544347
_TPM_ST_ATTEST_QUOTE = 0x8018
_TPM_ALG_RSA = 0x0001
_TPM_ALG_SHA256 = 0x000B
_TPM_ALG_NULL = 0x0010
_TPM_ALG_RSASSA = 0x0014
_TPM_ATTR_FIXED = frozenset({0x00050072, 0x00050472})
_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_ARK_KEY_USAGE = x509.KeyUsage(
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
_ASK_KEY_USAGE = x509.KeyUsage(
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
_ARK_ASK_ALLOWED_OIDS = frozenset(
    {
        ExtensionOID.BASIC_CONSTRAINTS,
        ExtensionOID.KEY_USAGE,
        ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        ExtensionOID.CRL_DISTRIBUTION_POINTS,
    }
)
_ARK_ASK_OPTIONAL_OIDS = frozenset(
    {
        ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        ExtensionOID.CRL_DISTRIBUTION_POINTS,
    }
)
_CRL_SUPPORTED_CRITICAL = frozenset(
    {
        ExtensionOID.CRL_NUMBER,
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    }
)
_PSS_SHA384 = padding.PSS(
    mgf=padding.MGF1(hashes.SHA384()),
    salt_length=48,
)
_UTC = timezone.utc


@dataclass(frozen=True)
class SppDiagTcbFloor:
    boot_loader: int
    tee: int
    snp: int
    microcode: int


@dataclass(frozen=True)
class SppDiagAttestationEvidence:
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
class SppDiagAttestationExpectations:
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
    minimum_tcb: SppDiagTcbFloor
    vcek_product_name: bytes
    cpuid_family: int
    cpuid_model: int
    cpuid_step: int
    baseline_pcrs: tuple[tuple[int, bytes], ...]
    ima_pcr10: bytes


@dataclass(frozen=True)
class SppDiagAttestation:
    status: str
    evidence_expectations_sha256: bytes
    quote_extra_data: bytes
    snp_measurement: bytes
    snp_host_data: bytes
    reported_tcb: bytes
    pcr_sha256: tuple[tuple[int, bytes], ...]
    quote_clock: int
    quote_reset_count: int
    quote_restart_count: int
    quote_safe: bool
    quote_firmware_version: int


class _SppDiagAttestStageError(Exception):
    def __init__(self, reason_code):
        self.reason_code = reason_code
        super().__init__(reason_code)


class _Ctx:
    pass


class _Cursor:
    def __init__(self, data, byteorder):
        self.data = data
        self.byteorder = byteorder
        self.offset = 0

    def take(self, size):
        end = self.offset + size
        if end > len(self.data):
            raise ValueError("cursor")
        result = self.data[self.offset : end]
        self.offset = end
        return result

    def integer(self, size):
        return int.from_bytes(self.take(size), self.byteorder)

    def consumed(self):
        if self.offset != len(self.data):
            raise ValueError("cursor")


def _fail(reason_code):
    raise SppDiagAttestError(reason_code)


def _bad(reason_code):
    raise _SppDiagAttestStageError(reason_code)


def _run(reason_code, stage, ctx):
    try:
        stage(ctx)
    except _SppDiagAttestStageError:
        raise
    except Exception:
        raise _SppDiagAttestStageError(reason_code)


def _sha256(data):
    return hashlib.sha256(data).digest()


def _u32le(buf, offset):
    return int.from_bytes(buf[offset : offset + 4], "little")


def _u64le(buf, offset):
    return int.from_bytes(buf[offset : offset + 8], "little")


def _is_int(value):
    return type(value) is int


def _is_bytes(value):
    return type(value) is bytes


def _printable_ascii_bytes(value):
    if not _is_bytes(value):
        return False
    for item in value:
        if item < 0x20 or item > 0x7E:
            return False
    return True


def _der_body(value, expected_tag):
    if not _is_bytes(value) or len(value) < 2:
        raise ValueError("der")
    if value[0] != expected_tag:
        raise ValueError("der")
    initial = value[1]
    if initial == 0x80:
        raise ValueError("der")
    pos = 2
    if initial & 0x80:
        size_octets = initial & 0x7F
        if size_octets < 1 or size_octets > 4 or pos + size_octets > len(value):
            raise ValueError("der")
        length_bytes = value[pos : pos + size_octets]
        if length_bytes[0] == 0:
            raise ValueError("der")
        length = int.from_bytes(length_bytes, "big")
        if length < 0x80:
            raise ValueError("der")
        if size_octets > 1 and length < (1 << (8 * (size_octets - 1))):
            raise ValueError("der")
        pos += size_octets
    else:
        length = initial
    end = pos + length
    if end != len(value):
        raise ValueError("der")
    return value[pos:end]


def _der_uint(value):
    body = _der_body(value, 0x02)
    if not body:
        raise ValueError("der")
    if body[0] & 0x80:
        raise ValueError("der")
    if len(body) > 1 and body[0] == 0x00 and not (body[1] & 0x80):
        raise ValueError("der")
    return int.from_bytes(body, "big")


def _der_ia5(value):
    body = _der_body(value, 0x16)
    if not _printable_ascii_bytes(body):
        raise ValueError("der")
    return body


def _der_octet(value):
    return _der_body(value, 0x04)


def _hwid_from_extension(raw):
    if not isinstance(raw, bytes):
        raise ValueError("der")
    if len(raw) == 64:
        return raw
    if len(raw) == 66 and raw[0] == 0x04 and raw[1] == 0x40:
        return raw[2:66]
    raise ValueError("der")


def _pem_to_der(raw, label):
    begin = ("-----BEGIN " + label + "-----").encode("ascii")
    end = ("-----END " + label + "-----").encode("ascii")
    if not _is_bytes(raw):
        raise ValueError("pem")
    trimmed = raw
    if trimmed.endswith(b"\n"):
        trimmed = trimmed[:-1]
        if trimmed.endswith(b"\r"):
            trimmed = trimmed[:-1]
    if trimmed.count(begin) != 1 or trimmed.count(end) != 1:
        raise ValueError("pem")
    if not trimmed.startswith(begin) or not trimmed.endswith(end):
        raise ValueError("pem")
    inner = trimmed[len(begin) : len(trimmed) - len(end)]
    if not inner.startswith(b"\n") or not inner.endswith(b"\n"):
        raise ValueError("pem")
    joined = b"".join(inner.split())
    if not joined:
        raise ValueError("pem")
    return base64.b64decode(joined, validate=True)


def _load_cert_pem(raw):
    der = _pem_to_der(raw, "CERTIFICATE")
    cert = x509.load_der_x509_certificate(der)
    if cert.public_bytes(Encoding.DER) != der:
        raise ValueError("pem")
    if cert.public_bytes(Encoding.PEM) != raw:
        raise ValueError("pem")
    return cert, der


def _load_public_pem(raw):
    der = _pem_to_der(raw, "PUBLIC KEY")
    key = serialization.load_der_public_key(der)
    encoded = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    if encoded != der:
        raise ValueError("pem")
    pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    if pem != raw:
        raise ValueError("pem")
    return key, der


def _load_crl_der(raw):
    if not _is_bytes(raw):
        raise ValueError("crl")
    crl = x509.load_der_x509_crl(raw)
    if crl.public_bytes(Encoding.DER) != raw:
        raise ValueError("crl")
    return crl


def _pss_sha384_ok(entity):
    if entity.signature_algorithm_oid != SignatureAlgorithmOID.RSASSA_PSS:
        return False
    algorithm = entity.signature_hash_algorithm
    if algorithm is None or algorithm.name != "sha384":
        return False
    params = entity.signature_algorithm_parameters
    if not isinstance(params, padding.PSS):
        return False
    salt = getattr(params, "_salt_length", None)
    if salt not in (48, padding.PSS.DIGEST_LENGTH):
        return False
    mgf = getattr(params, "_mgf", None)
    if not isinstance(mgf, padding.MGF1):
        return False
    mgf_algorithm = getattr(mgf, "_algorithm", None)
    if mgf_algorithm is None or mgf_algorithm.name != "sha384":
        return False
    return True


def _rsa_key(cert):
    key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("rsa")
    return key


def _verify_pss(issuer_key, signature, data):
    issuer_key.verify(signature, data, _PSS_SHA384, hashes.SHA384())


def _cert_time(cert, base):
    aware = getattr(cert, base + "_utc", None)
    if aware is not None:
        return aware
    return getattr(cert, base).replace(tzinfo=_UTC)


def _crl_time(crl, base):
    aware = getattr(crl, base + "_utc", None)
    if aware is not None:
        return aware
    value = getattr(crl, base)
    if value is None:
        raise ValueError("crl")
    return value.replace(tzinfo=_UTC)


def _in_window(start, end, instant):
    return start <= instant <= end


def _extension(cert, cls):
    return cert.extensions.get_extension_for_class(cls)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _b64url_decode_canonical(text):
    if type(text) is not str or not text:
        raise ValueError("b64")
    for char in text:
        if char not in _B64URL_ALPHABET:
            raise ValueError("b64")
    padded = text + ("=" * ((-len(text)) % 4))
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if encoded != text:
        raise ValueError("b64")
    if not raw or raw[0] == 0:
        raise ValueError("b64")
    return raw


def _printable_kid(value):
    if type(value) is not str:
        return False
    encoded = value.encode("ascii")
    if not (1 <= len(encoded) <= 64):
        return False
    return _printable_ascii_bytes(encoded)


def _parse_jwk(item):
    if type(item) is not dict:
        raise ValueError("jwk")
    names = set(item)
    if names == {"kid", "kty", "e", "n"}:
        key_ops = None
    elif names == {"kid", "kty", "e", "n", "key_ops"}:
        key_ops = item["key_ops"]
        if type(key_ops) is not list or len(key_ops) != 1:
            raise ValueError("jwk")
        if key_ops[0] not in ("sign", "encrypt"):
            raise ValueError("jwk")
    else:
        raise ValueError("jwk")
    kid = item["kid"]
    if not _printable_kid(kid):
        raise ValueError("jwk")
    if item["kty"] != "RSA":
        raise ValueError("jwk")
    exponent = _b64url_decode_canonical(item["e"])
    modulus = _b64url_decode_canonical(item["n"])
    return {
        "kid": kid,
        "e": int.from_bytes(exponent, "big"),
        "n": modulus,
        "key_ops": None if key_ops is None else tuple(key_ops),
    }


def _record(path, value):
    encoded = path.encode("ascii")
    return struct.pack(">H", len(encoded)) + encoded + struct.pack(">Q", len(value)) + value


def _commitment(evidence, expectations):
    chunks = [_COMMITMENT_DOMAIN]
    chunks.append(_record("evidence.ark_pem", evidence.ark_pem))
    chunks.append(_record("evidence.ask_pem", evidence.ask_pem))
    chunks.append(_record("evidence.vcek_pem", evidence.vcek_pem))
    chunks.append(_record("evidence.ark_crl_der", evidence.ark_crl_der))
    chunks.append(_record("evidence.ak_public_pem", evidence.ak_public_pem))
    chunks.append(_record("evidence.ak_tpmt_public", evidence.ak_tpmt_public))
    chunks.append(_record("evidence.hcl_report", evidence.hcl_report))
    chunks.append(_record("evidence.quote_msg", evidence.quote_msg))
    chunks.append(_record("evidence.quote_sig", evidence.quote_sig))
    chunks.append(_record("evidence.quote_pcrs", evidence.quote_pcrs))
    chunks.append(
        _record("expectations.appraisal_unix", struct.pack(">Q", expectations.appraisal_unix))
    )
    chunks.append(_record("expectations.quote_extra_data", expectations.quote_extra_data))
    chunks.append(_record("expectations.ark_der_sha256", expectations.ark_der_sha256))
    chunks.append(_record("expectations.ask_der_sha256", expectations.ask_der_sha256))
    chunks.append(_record("expectations.ark_crl_der_sha256", expectations.ark_crl_der_sha256))
    chunks.append(
        _record(
            "expectations.ak_parent_qualified_name",
            expectations.ak_parent_qualified_name,
        )
    )
    chunks.append(
        _record(
            "expectations.snp_report_version",
            struct.pack(">Q", expectations.snp_report_version),
        )
    )
    chunks.append(_record("expectations.snp_policy", struct.pack(">Q", expectations.snp_policy)))
    chunks.append(_record("expectations.snp_vmpl", struct.pack(">Q", expectations.snp_vmpl)))
    chunks.append(_record("expectations.snp_measurement", expectations.snp_measurement))
    chunks.append(_record("expectations.snp_host_data", expectations.snp_host_data))
    floor = expectations.minimum_tcb
    chunks.append(
        _record("expectations.minimum_tcb.boot_loader", struct.pack(">B", floor.boot_loader))
    )
    chunks.append(_record("expectations.minimum_tcb.tee", struct.pack(">B", floor.tee)))
    chunks.append(_record("expectations.minimum_tcb.snp", struct.pack(">B", floor.snp)))
    chunks.append(
        _record("expectations.minimum_tcb.microcode", struct.pack(">B", floor.microcode))
    )
    chunks.append(_record("expectations.vcek_product_name", expectations.vcek_product_name))
    chunks.append(
        _record("expectations.cpuid_family", struct.pack(">Q", expectations.cpuid_family))
    )
    chunks.append(
        _record("expectations.cpuid_model", struct.pack(">Q", expectations.cpuid_model))
    )
    chunks.append(_record("expectations.cpuid_step", struct.pack(">Q", expectations.cpuid_step)))
    for index, pair in enumerate(expectations.baseline_pcrs):
        pcr_index, digest = pair
        prefix = "expectations.baseline_pcrs[%02d]" % index
        chunks.append(_record(prefix + ".index", struct.pack(">B", pcr_index)))
        chunks.append(_record(prefix + ".digest", digest))
    chunks.append(_record("expectations.ima_pcr10", expectations.ima_pcr10))
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk)
    return digest.digest()


def _stage_type(ctx):
    evidence = ctx.evidence
    expectations = ctx.expectations
    if type(evidence) is not SppDiagAttestationEvidence:
        _bad(CP_SPP_DIAG_ATTEST_TYPE)
    if type(expectations) is not SppDiagAttestationExpectations:
        _bad(CP_SPP_DIAG_ATTEST_TYPE)
    for name in (
        "ark_pem",
        "ask_pem",
        "vcek_pem",
        "ark_crl_der",
        "ak_public_pem",
        "ak_tpmt_public",
        "hcl_report",
        "quote_msg",
        "quote_sig",
        "quote_pcrs",
    ):
        if not _is_bytes(getattr(evidence, name)):
            _bad(CP_SPP_DIAG_ATTEST_TYPE)
    unix = expectations.appraisal_unix
    if not _is_int(unix) or unix < 0 or unix > (2**63 - 1):
        _bad(CP_SPP_DIAG_ATTEST_TYPE)
    for name, size in (
        ("quote_extra_data", 32),
        ("ark_der_sha256", 32),
        ("ask_der_sha256", 32),
        ("ark_crl_der_sha256", 32),
        ("ima_pcr10", 32),
        ("snp_measurement", 48),
        ("snp_host_data", 32),
    ):
        value = getattr(expectations, name)
        if not _is_bytes(value) or len(value) != size:
            _bad(CP_SPP_DIAG_ATTEST_TYPE)
    parent = expectations.ak_parent_qualified_name
    if not _is_bytes(parent) or len(parent) != len(_AK_PARENT_QN):
        _bad(CP_SPP_DIAG_ATTEST_TYPE)
    version = expectations.snp_report_version
    if not _is_int(version) or version < 0 or version > (2**32 - 1):
        _bad(CP_SPP_DIAG_ATTEST_TYPE)
    policy = expectations.snp_policy
    if not _is_int(policy) or policy < 0 or policy > (2**64 - 1):
        _bad(CP_SPP_DIAG_ATTEST_TYPE)
    vmpl = expectations.snp_vmpl
    if not _is_int(vmpl) or vmpl < 0 or vmpl > (2**32 - 1):
        _bad(CP_SPP_DIAG_ATTEST_TYPE)
    for name in ("cpuid_family", "cpuid_model", "cpuid_step"):
        value = getattr(expectations, name)
        if not _is_int(value) or value < 0 or value > 255:
            _bad(CP_SPP_DIAG_ATTEST_TYPE)
    floor = expectations.minimum_tcb
    if type(floor) is not SppDiagTcbFloor:
        _bad(CP_SPP_DIAG_ATTEST_TYPE)
    for name in ("boot_loader", "tee", "snp", "microcode"):
        value = getattr(floor, name)
        if not _is_int(value) or value < 0 or value > 255:
            _bad(CP_SPP_DIAG_ATTEST_TYPE)
    product = expectations.vcek_product_name
    if not _is_bytes(product) or not (1 <= len(product) <= 64):
        _bad(CP_SPP_DIAG_ATTEST_TYPE)
    baseline = expectations.baseline_pcrs
    if type(baseline) is not tuple or len(baseline) != 14:
        _bad(CP_SPP_DIAG_ATTEST_TYPE)
    for position, expected_index in enumerate(SPP_DIAG_BASELINE_PCR_SELECTION):
        pair = baseline[position]
        if type(pair) is not tuple or len(pair) != 2:
            _bad(CP_SPP_DIAG_ATTEST_TYPE)
        index, digest = pair
        if not _is_int(index) or not _is_bytes(digest) or len(digest) != 32:
            _bad(CP_SPP_DIAG_ATTEST_TYPE)
        if index != expected_index:
            _bad(CP_SPP_DIAG_ATTEST_TYPE)


def _stage_cap(ctx):
    evidence = ctx.evidence
    if (
        len(evidence.ark_pem) > MAX_CERT_PEM_BYTES
        or len(evidence.ask_pem) > MAX_CERT_PEM_BYTES
        or len(evidence.vcek_pem) > MAX_CERT_PEM_BYTES
    ):
        _bad(CP_SPP_DIAG_ATTEST_CAP)
    if len(evidence.ark_crl_der) > MAX_CRL_DER_BYTES:
        _bad(CP_SPP_DIAG_ATTEST_CAP)
    if len(evidence.ak_public_pem) > MAX_AK_PEM_BYTES:
        _bad(CP_SPP_DIAG_ATTEST_CAP)
    if len(evidence.ak_tpmt_public) > MAX_AK_PUBLIC_BYTES:
        _bad(CP_SPP_DIAG_ATTEST_CAP)
    if len(evidence.hcl_report) > HCLA_BYTES:
        _bad(CP_SPP_DIAG_ATTEST_CAP)
    if len(evidence.quote_msg) > MAX_QUOTE_MSG_BYTES:
        _bad(CP_SPP_DIAG_ATTEST_CAP)
    if len(evidence.quote_sig) > MAX_QUOTE_SIG_BYTES:
        _bad(CP_SPP_DIAG_ATTEST_CAP)
    if len(evidence.quote_pcrs) > MAX_QUOTE_PCRS_BYTES:
        _bad(CP_SPP_DIAG_ATTEST_CAP)


def _https_crldp_uri_ok(uri):
    if type(uri) is not str or not uri.startswith("https://"):
        return False
    if "?" in uri or "#" in uri or "@" in uri:
        return False
    rest = uri[8:]
    if not rest:
        return False
    slash = rest.find("/")
    host = rest if slash < 0 else rest[:slash]
    if not host or ":" in host:
        return False
    return True


def _require_crldp(value):
    if not isinstance(value, x509.CRLDistributionPoints) or len(value) != 1:
        _bad(CP_SPP_DIAG_ATTEST_X509)
    point = value[0]
    if point.relative_name is not None or point.reasons is not None or point.crl_issuer is not None:
        _bad(CP_SPP_DIAG_ATTEST_X509)
    names = point.full_name
    if names is None or len(names) != 1:
        _bad(CP_SPP_DIAG_ATTEST_X509)
    name = names[0]
    if not isinstance(name, x509.UniformResourceIdentifier):
        _bad(CP_SPP_DIAG_ATTEST_X509)
    if not _https_crldp_uri_ok(name.value):
        _bad(CP_SPP_DIAG_ATTEST_X509)


def _require_ca(cert, path_lengths, usage):
    basic = _extension(cert, x509.BasicConstraints)
    if not basic.critical:
        _bad(CP_SPP_DIAG_ATTEST_X509)
    if not basic.value.ca or basic.value.path_length not in path_lengths:
        _bad(CP_SPP_DIAG_ATTEST_X509)
    key_usage = _extension(cert, x509.KeyUsage)
    if not key_usage.critical:
        _bad(CP_SPP_DIAG_ATTEST_X509)
    if key_usage.value != usage:
        _bad(CP_SPP_DIAG_ATTEST_X509)
    crldp = None
    for extension in cert.extensions:
        if extension.oid not in _ARK_ASK_ALLOWED_OIDS:
            _bad(CP_SPP_DIAG_ATTEST_X509)
        if extension.oid in _ARK_ASK_OPTIONAL_OIDS and extension.critical:
            _bad(CP_SPP_DIAG_ATTEST_X509)
        if extension.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
            crldp = extension.value
    if crldp is not None:
        _require_crldp(crldp)
    key = _rsa_key(cert)
    if key.key_size != 4096:
        _bad(CP_SPP_DIAG_ATTEST_X509)
    if not _pss_sha384_ok(cert):
        _bad(CP_SPP_DIAG_ATTEST_X509)


def _require_ski_value(cert):
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        return
    expected = x509.SubjectKeyIdentifier.from_public_key(cert.public_key())
    if not hmac.compare_digest(extension.value.digest, expected.digest):
        _bad(CP_SPP_DIAG_ATTEST_ROOT)


def _require_aki_value(cert, issuer_public_key):
    try:
        extension = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    except x509.ExtensionNotFound:
        return
    aki = extension.value
    expected = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key)
    if aki.key_identifier is None or expected.key_identifier is None:
        _bad(CP_SPP_DIAG_ATTEST_ROOT)
    if not hmac.compare_digest(aki.key_identifier, expected.key_identifier):
        _bad(CP_SPP_DIAG_ATTEST_ROOT)
    if aki.authority_cert_issuer is not None or aki.authority_cert_serial_number is not None:
        _bad(CP_SPP_DIAG_ATTEST_ROOT)


def _duplicate_amd_extension(error):
    if getattr(error, "oid", None) not in _AMD_OIDS:
        _bad(CP_SPP_DIAG_ATTEST_X509)


def _capture_amd_extensions(cert):
    try:
        items = list(cert.extensions)
    except x509.DuplicateExtension as error:
        _duplicate_amd_extension(error)
        return [], None, None, True
    records = []
    ski = None
    aki = None
    for extension in items:
        oid = extension.oid
        if oid in _AMD_OIDS:
            if not isinstance(extension.value, x509.UnrecognizedExtension):
                _bad(CP_SPP_DIAG_ATTEST_X509)
            suffix = oid.dotted_string[len(_AMD_PREFIX) :]
            records.append((suffix, extension.critical, extension.value.value))
            continue
        if oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            if extension.critical:
                _bad(CP_SPP_DIAG_ATTEST_X509)
            ski = extension.value
            continue
        if oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
            if extension.critical:
                _bad(CP_SPP_DIAG_ATTEST_X509)
            aki = extension.value
            continue
        _bad(CP_SPP_DIAG_ATTEST_X509)
    return records, ski, aki, False


def _decode_amd_values(records):
    by_suffix = {}
    for suffix, critical, raw in records:
        if critical:
            _bad(CP_SPP_DIAG_ATTEST_VCEK)
        if suffix in by_suffix:
            _bad(CP_SPP_DIAG_ATTEST_VCEK)
        by_suffix[suffix] = raw
    expected = set(suffix for suffix, _tag in _AMD_SPECS)
    if set(by_suffix) != expected:
        _bad(CP_SPP_DIAG_ATTEST_VCEK)
    values = {}
    for suffix, tag in _AMD_SPECS:
        raw = by_suffix[suffix]
        try:
            if suffix == "4":
                values[suffix] = _hwid_from_extension(raw)
            elif tag == 0x02:
                values[suffix] = _der_uint(raw)
            elif tag == 0x16:
                values[suffix] = _der_ia5(raw)
            else:
                values[suffix] = _der_octet(raw)
        except Exception:
            _bad(CP_SPP_DIAG_ATTEST_VCEK)
    return values


def _stage_x509(ctx):
    evidence = ctx.evidence
    instant = datetime.fromtimestamp(ctx.expectations.appraisal_unix, _UTC)
    try:
        ark, ark_der = _load_cert_pem(evidence.ark_pem)
        ask, ask_der = _load_cert_pem(evidence.ask_pem)
        vcek, _vcek_der = _load_cert_pem(evidence.vcek_pem)
        crl = _load_crl_der(evidence.ark_crl_der)
    except Exception:
        _bad(CP_SPP_DIAG_ATTEST_X509)
    _require_ca(ark, frozenset({1, None}), _ARK_KEY_USAGE)
    _require_ca(ask, frozenset({0}), _ASK_KEY_USAGE)
    if vcek.serial_number != 0:
        _bad(CP_SPP_DIAG_ATTEST_X509)
    vcek_key = vcek.public_key()
    if not isinstance(vcek_key, ec.EllipticCurvePublicKey):
        _bad(CP_SPP_DIAG_ATTEST_X509)
    if vcek_key.curve.name != "secp384r1":
        _bad(CP_SPP_DIAG_ATTEST_X509)
    if not _pss_sha384_ok(vcek):
        _bad(CP_SPP_DIAG_ATTEST_X509)
    amd_records, ski, aki, amd_duplicate = _capture_amd_extensions(vcek)
    if not amd_duplicate:
        if (ski is None) != (aki is None):
            _bad(CP_SPP_DIAG_ATTEST_X509)
        if ski is not None:
            expected_ski = x509.SubjectKeyIdentifier.from_public_key(vcek_key)
            if not hmac.compare_digest(ski.digest, expected_ski.digest):
                _bad(CP_SPP_DIAG_ATTEST_X509)
            ask_ski = x509.SubjectKeyIdentifier.from_public_key(ask.public_key())
            if aki.key_identifier is None:
                _bad(CP_SPP_DIAG_ATTEST_X509)
            if not hmac.compare_digest(aki.key_identifier, ask_ski.digest):
                _bad(CP_SPP_DIAG_ATTEST_X509)
            if aki.authority_cert_issuer is not None or aki.authority_cert_serial_number is not None:
                _bad(CP_SPP_DIAG_ATTEST_X509)
    for cert in (ark, ask, vcek):
        if not _in_window(
            _cert_time(cert, "not_valid_before"),
            _cert_time(cert, "not_valid_after"),
            instant,
        ):
            _bad(CP_SPP_DIAG_ATTEST_X509)
    ctx.ark = ark
    ctx.ask = ask
    ctx.vcek = vcek
    ctx.ark_der = ark_der
    ctx.ask_der = ask_der
    ctx.vcek_key = vcek_key
    ctx.crl = crl
    ctx.amd_records = amd_records
    ctx.amd_duplicate = amd_duplicate
    ctx.instant = instant


def _stage_root(ctx):
    if not hmac.compare_digest(_sha256(ctx.ark_der), ctx.expectations.ark_der_sha256):
        _bad(CP_SPP_DIAG_ATTEST_ROOT)
    if not hmac.compare_digest(_sha256(ctx.ask_der), ctx.expectations.ask_der_sha256):
        _bad(CP_SPP_DIAG_ATTEST_ROOT)
    if ctx.ark.subject != ctx.ark.issuer:
        _bad(CP_SPP_DIAG_ATTEST_ROOT)
    if ctx.ask.issuer != ctx.ark.subject:
        _bad(CP_SPP_DIAG_ATTEST_ROOT)
    if ctx.vcek.issuer != ctx.ask.subject:
        _bad(CP_SPP_DIAG_ATTEST_ROOT)
    _require_ski_value(ctx.ark)
    _require_aki_value(ctx.ark, ctx.ark.public_key())
    _require_ski_value(ctx.ask)
    _require_aki_value(ctx.ask, ctx.ark.public_key())
    try:
        ark_key = _rsa_key(ctx.ark)
        ask_key = _rsa_key(ctx.ask)
        _verify_pss(ark_key, ctx.ark.signature, ctx.ark.tbs_certificate_bytes)
        _verify_pss(ark_key, ctx.ask.signature, ctx.ask.tbs_certificate_bytes)
        _verify_pss(ask_key, ctx.vcek.signature, ctx.vcek.tbs_certificate_bytes)
    except Exception:
        _bad(CP_SPP_DIAG_ATTEST_ROOT)


def _stage_crl(ctx):
    raw = ctx.evidence.ark_crl_der
    if not hmac.compare_digest(_sha256(raw), ctx.expectations.ark_crl_der_sha256):
        _bad(CP_SPP_DIAG_ATTEST_CRL)
    crl = ctx.crl
    if crl.issuer != ctx.ark.subject:
        _bad(CP_SPP_DIAG_ATTEST_CRL)
    if not _pss_sha384_ok(crl):
        _bad(CP_SPP_DIAG_ATTEST_CRL)
    try:
        _verify_pss(_rsa_key(ctx.ark), crl.signature, crl.tbs_certlist_bytes)
        last_update = _crl_time(crl, "last_update")
        next_update = _crl_time(crl, "next_update")
    except Exception:
        _bad(CP_SPP_DIAG_ATTEST_CRL)
    if not _in_window(last_update, next_update, ctx.instant):
        _bad(CP_SPP_DIAG_ATTEST_CRL)
    for extension in crl.extensions:
        if extension.critical and extension.oid not in _CRL_SUPPORTED_CRITICAL:
            _bad(CP_SPP_DIAG_ATTEST_CRL)
    ask_serial = ctx.ask.serial_number
    for entry in crl:
        for extension in entry.extensions:
            if extension.critical and extension.oid not in _CRL_SUPPORTED_CRITICAL:
                _bad(CP_SPP_DIAG_ATTEST_CRL)
        if entry.serial_number == ask_serial:
            _bad(CP_SPP_DIAG_ATTEST_CRL)


def _stage_hcla(ctx):
    blob = ctx.evidence.hcl_report
    if len(blob) != HCLA_BYTES:
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    if blob[0:4] != b"HCLA":
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    version = _u32le(blob, 0x004)
    report_size = _u32le(blob, 0x008)
    request_type = _u32le(blob, 0x00C)
    if version != 2 or request_type != 2:
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    for offset in (0x010, 0x014, 0x018, 0x01C):
        if _u32le(blob, offset) != 0:
            _bad(CP_SPP_DIAG_ATTEST_HCLA)
    report = blob[0x020 : 0x020 + _SNP_REPORT_BYTES]
    if len(report) != _SNP_REPORT_BYTES:
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    data_size = _u32le(blob, 0x4C0)
    runtime_version = _u32le(blob, 0x4C4)
    runtime_report_type = _u32le(blob, 0x4C8)
    hash_type = _u32le(blob, 0x4CC)
    claim_size = _u32le(blob, 0x4D0)
    if runtime_version != 1 or runtime_report_type != 2 or hash_type != 1:
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    if claim_size < 1 or 0x4D4 + claim_size > HCLA_BYTES:
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    if data_size != 20 + claim_size:
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    if report_size != 32 + _SNP_REPORT_BYTES + data_size:
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    claim = blob[0x4D4 : 0x4D4 + claim_size]
    tail = blob[0x4D4 + claim_size :]
    if tail != bytes(len(tail)):
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    try:
        text = claim.decode("utf-8")
        runtime = json.loads(text, object_pairs_hook=_unique_object)
    except Exception:
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    if type(runtime) is not dict or "keys" not in runtime:
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    keys = runtime["keys"]
    if type(keys) is not list or not (1 <= len(keys) <= 8):
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    parsed = []
    kids = []
    try:
        for item in keys:
            jwk = _parse_jwk(item)
            if jwk["key_ops"] is None and jwk["kid"] != "HCLAkPub":
                _bad(CP_SPP_DIAG_ATTEST_HCLA)
            if jwk["kid"] in kids:
                _bad(CP_SPP_DIAG_ATTEST_HCLA)
            kids.append(jwk["kid"])
            parsed.append(jwk)
    except _SppDiagAttestStageError:
        raise
    except Exception:
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    ak_keys = [item for item in parsed if item["kid"] == "HCLAkPub"]
    if len(ak_keys) != 1:
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    ak_jwk = ak_keys[0]
    if ak_jwk["key_ops"] not in (None, ("sign",)):
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    if ak_jwk["e"] != 65537 or len(ak_jwk["n"]) != 256:
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    report_hash = report[0x050:0x070]
    report_tail = report[0x070:0x090]
    if not hmac.compare_digest(report_hash, _sha256(claim)):
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    if report_tail != bytes(32):
        _bad(CP_SPP_DIAG_ATTEST_HCLA)
    ctx.snp_report = report
    ctx.hcl_ak_jwk = ak_jwk
    claim = b""
    tail = b""


def _tcb_reserved_zero(record):
    return record[2:6] == bytes(4)


def _stage_snp(ctx):
    report = ctx.snp_report
    if len(report) != _SNP_REPORT_BYTES:
        _bad(CP_SPP_DIAG_ATTEST_SNP)
    version = _u32le(report, 0x000)
    policy = _u64le(report, 0x008)
    vmpl = _u32le(report, 0x030)
    sig_algo = _u32le(report, 0x034)
    if sig_algo != 1:
        _bad(CP_SPP_DIAG_ATTEST_SNP)
    current_tcb = report[0x038:0x040]
    reported_tcb = report[0x180:0x188]
    committed_tcb = report[0x1E0:0x1E8]
    launch_tcb = report[0x1F0:0x1F8]
    for record in (current_tcb, reported_tcb, committed_tcb, launch_tcb):
        if len(record) != 8 or not _tcb_reserved_zero(record):
            _bad(CP_SPP_DIAG_ATTEST_SNP)
    # AMD SNP ATTESTATION_REPORT v3+: cpuid_fam_id/mod_id/step at 0x188/0x189/0x18A.
    cpuid_family = report[0x188]
    cpuid_model = report[0x189]
    cpuid_step = report[0x18A]
    if cpuid_family != _SNP_FAMILY_19H:
        _bad(CP_SPP_DIAG_ATTEST_SNP)
    chip_id = report[0x1A0:0x1E0]
    if len(chip_id) != 64 or chip_id == bytes(64):
        _bad(CP_SPP_DIAG_ATTEST_SNP)
    measurement = report[0x090:0x0C0]
    host_data = report[0x0C0:0x0E0]
    if len(measurement) != 48 or len(host_data) != 32:
        _bad(CP_SPP_DIAG_ATTEST_SNP)
    if report[0x330:0x4A0] != bytes(0x4A0 - 0x330):
        _bad(CP_SPP_DIAG_ATTEST_SNP)
    r = int.from_bytes(report[0x2A0:0x2E8], "little")
    s = int.from_bytes(report[0x2E8:0x330], "little")
    if r == 0 or s == 0 or r.bit_length() > 384 or s.bit_length() > 384:
        _bad(CP_SPP_DIAG_ATTEST_SNP)
    try:
        signature = utils.encode_dss_signature(r, s)
        ctx.vcek_key.verify(signature, report[:0x2A0], ec.ECDSA(hashes.SHA384()))
    except Exception:
        _bad(CP_SPP_DIAG_ATTEST_SNP)
    ctx.snp_version = version
    ctx.snp_policy = policy
    ctx.snp_vmpl = vmpl
    ctx.current_tcb = current_tcb
    ctx.reported_tcb = reported_tcb
    ctx.committed_tcb = committed_tcb
    ctx.launch_tcb = launch_tcb
    ctx.cpuid_family = cpuid_family
    ctx.cpuid_model = cpuid_model
    ctx.cpuid_step = cpuid_step
    ctx.chip_id = chip_id
    ctx.measurement = measurement
    ctx.host_data = host_data


def _stage_vcek(ctx):
    if ctx.amd_duplicate:
        _bad(CP_SPP_DIAG_ATTEST_VCEK)
    values = _decode_amd_values(ctx.amd_records)
    reported = ctx.reported_tcb
    if values["1"] != 0:
        _bad(CP_SPP_DIAG_ATTEST_VCEK)
    if not hmac.compare_digest(values["2"], ctx.expectations.vcek_product_name):
        _bad(CP_SPP_DIAG_ATTEST_VCEK)
    if values["3.1"] != reported[0]:
        _bad(CP_SPP_DIAG_ATTEST_VCEK)
    if values["3.2"] != reported[1]:
        _bad(CP_SPP_DIAG_ATTEST_VCEK)
    if values["3.3"] != reported[6]:
        _bad(CP_SPP_DIAG_ATTEST_VCEK)
    if values["3.4"] != reported[2]:
        _bad(CP_SPP_DIAG_ATTEST_VCEK)
    if values["3.5"] != reported[3]:
        _bad(CP_SPP_DIAG_ATTEST_VCEK)
    if values["3.6"] != reported[4]:
        _bad(CP_SPP_DIAG_ATTEST_VCEK)
    if values["3.7"] != reported[5]:
        _bad(CP_SPP_DIAG_ATTEST_VCEK)
    if values["3.8"] != reported[7]:
        _bad(CP_SPP_DIAG_ATTEST_VCEK)
    if not hmac.compare_digest(values["4"], ctx.chip_id):
        _bad(CP_SPP_DIAG_ATTEST_VCEK)


def _stage_ak(ctx):
    try:
        key, _ak_der = _load_public_pem(ctx.evidence.ak_public_pem)
    except Exception:
        _bad(CP_SPP_DIAG_ATTEST_AK)
    if not hmac.compare_digest(ctx.expectations.ak_parent_qualified_name, _AK_PARENT_QN):
        _bad(CP_SPP_DIAG_ATTEST_AK)
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
        _bad(CP_SPP_DIAG_ATTEST_AK)
    numbers = key.public_numbers()
    if numbers.e != 65537:
        _bad(CP_SPP_DIAG_ATTEST_AK)
    modulus = numbers.n.to_bytes(256, "big")
    raw = ctx.evidence.ak_tpmt_public
    try:
        cursor = _Cursor(raw, "big")
        if cursor.integer(2) != _TPM_ALG_RSA:
            _bad(CP_SPP_DIAG_ATTEST_AK)
        if cursor.integer(2) != _TPM_ALG_SHA256:
            _bad(CP_SPP_DIAG_ATTEST_AK)
        attributes = cursor.integer(4)
        if attributes not in _TPM_ATTR_FIXED:
            _bad(CP_SPP_DIAG_ATTEST_AK)
        policy = cursor.take(cursor.integer(2))
        if policy != b"":
            _bad(CP_SPP_DIAG_ATTEST_AK)
        if cursor.integer(2) != _TPM_ALG_NULL:
            _bad(CP_SPP_DIAG_ATTEST_AK)
        scheme = cursor.integer(2)
        if scheme == _TPM_ALG_RSASSA:
            if cursor.integer(2) != _TPM_ALG_SHA256:
                _bad(CP_SPP_DIAG_ATTEST_AK)
        elif scheme != _TPM_ALG_NULL:
            _bad(CP_SPP_DIAG_ATTEST_AK)
        if cursor.integer(2) != 2048:
            _bad(CP_SPP_DIAG_ATTEST_AK)
        exponent = cursor.integer(4)
        if exponent not in (0, 65537):
            _bad(CP_SPP_DIAG_ATTEST_AK)
        tpmt_modulus = cursor.take(cursor.integer(2))
        cursor.consumed()
    except _SppDiagAttestStageError:
        raise
    except Exception:
        _bad(CP_SPP_DIAG_ATTEST_AK)
    jwk = ctx.hcl_ak_jwk
    if tpmt_modulus != modulus or jwk["n"] != modulus or jwk["e"] != 65537:
        _bad(CP_SPP_DIAG_ATTEST_AK)
    name = _TPM_ALG_SHA256.to_bytes(2, "big") + _sha256(raw)
    qualified = _TPM_ALG_SHA256.to_bytes(2, "big") + _sha256(
        ctx.expectations.ak_parent_qualified_name + name
    )
    ctx.ak_qualified_name = qualified
    ctx.ak_rsa = key
    policy = b""
    tpmt_modulus = b""
    _ak_der = b""


def _stage_quote(ctx):
    try:
        quote = _Cursor(ctx.evidence.quote_msg, "big")
        if quote.integer(4) != _TPM_GENERATED_VALUE:
            _bad(CP_SPP_DIAG_ATTEST_QUOTE)
        if quote.integer(2) != _TPM_ST_ATTEST_QUOTE:
            _bad(CP_SPP_DIAG_ATTEST_QUOTE)
        qualified = quote.take(quote.integer(2))
        extra = quote.take(quote.integer(2))
        clock = quote.integer(8)
        reset_count = quote.integer(4)
        restart_count = quote.integer(4)
        safe = quote.integer(1)
        firmware = quote.integer(8)
        if quote.integer(4) != 1:
            _bad(CP_SPP_DIAG_ATTEST_QUOTE)
        if quote.integer(2) != _TPM_ALG_SHA256:
            _bad(CP_SPP_DIAG_ATTEST_QUOTE)
        select = quote.take(quote.integer(1))
        quoted_digest = quote.take(quote.integer(2))
        quote.consumed()
        signature = _Cursor(ctx.evidence.quote_sig, "big")
        sig_alg = signature.integer(2)
        sig_hash = signature.integer(2)
        raw_signature = signature.take(signature.integer(2))
        signature.consumed()
    except _SppDiagAttestStageError:
        raise
    except Exception:
        _bad(CP_SPP_DIAG_ATTEST_QUOTE)
    if not hmac.compare_digest(qualified, ctx.ak_qualified_name):
        _bad(CP_SPP_DIAG_ATTEST_QUOTE)
    if not hmac.compare_digest(extra, ctx.expectations.quote_extra_data):
        _bad(CP_SPP_DIAG_ATTEST_QUOTE)
    if safe != 1:
        _bad(CP_SPP_DIAG_ATTEST_QUOTE)
    if select != _QUOTE_PCR_BITMAP:
        _bad(CP_SPP_DIAG_ATTEST_QUOTE)
    if len(quoted_digest) != 32:
        _bad(CP_SPP_DIAG_ATTEST_QUOTE)
    if sig_alg != _TPM_ALG_RSASSA or sig_hash != _TPM_ALG_SHA256:
        _bad(CP_SPP_DIAG_ATTEST_QUOTE)
    if len(raw_signature) != 256:
        _bad(CP_SPP_DIAG_ATTEST_QUOTE)
    try:
        ctx.ak_rsa.verify(
            raw_signature,
            ctx.evidence.quote_msg,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception:
        _bad(CP_SPP_DIAG_ATTEST_QUOTE)
    ctx.quoted_digest = quoted_digest
    ctx.quote_clock = clock
    ctx.quote_reset_count = reset_count
    ctx.quote_restart_count = restart_count
    ctx.quote_safe_byte = safe
    ctx.quote_firmware_version = firmware
    qualified = b""
    extra = b""
    raw_signature = b""


def _stage_pcr(ctx):
    try:
        pcrs = _Cursor(ctx.evidence.quote_pcrs, "little")
        if pcrs.integer(4) != 1:
            _bad(CP_SPP_DIAG_ATTEST_PCR)
        file_bitmap = None
        for slot in range(8):
            algorithm = pcrs.integer(2)
            size = pcrs.integer(1)
            bitmap = pcrs.take(8)
            pad = pcrs.take(5)
            if pad != bytes(5):
                _bad(CP_SPP_DIAG_ATTEST_PCR)
            if slot == 0:
                if algorithm != _TPM_ALG_SHA256 or size != 3:
                    _bad(CP_SPP_DIAG_ATTEST_PCR)
                if bitmap[3:] != bytes(5):
                    _bad(CP_SPP_DIAG_ATTEST_PCR)
                file_bitmap = bitmap[:3]
            else:
                if algorithm != 0 or size != 0 or bitmap != bytes(8):
                    _bad(CP_SPP_DIAG_ATTEST_PCR)
        if file_bitmap != _QUOTE_PCR_BITMAP:
            _bad(CP_SPP_DIAG_ATTEST_PCR)
        if pcrs.integer(4) != 2:
            _bad(CP_SPP_DIAG_ATTEST_PCR)
        digest_values = []
        for expected_count in (8, 7):
            count = pcrs.integer(4)
            if count != expected_count:
                _bad(CP_SPP_DIAG_ATTEST_PCR)
            for slot in range(8):
                size = pcrs.integer(2)
                buffer = pcrs.take(64)
                if slot < count:
                    if size != 32 or buffer[32:] != bytes(32):
                        _bad(CP_SPP_DIAG_ATTEST_PCR)
                    digest_values.append(buffer[:32])
                else:
                    if size != 0 or buffer != bytes(64):
                        _bad(CP_SPP_DIAG_ATTEST_PCR)
        pcrs.consumed()
    except _SppDiagAttestStageError:
        raise
    except Exception:
        _bad(CP_SPP_DIAG_ATTEST_PCR)
    if len(digest_values) != 15:
        _bad(CP_SPP_DIAG_ATTEST_PCR)
    composite = _sha256(b"".join(digest_values))
    if not hmac.compare_digest(composite, ctx.quoted_digest):
        _bad(CP_SPP_DIAG_ATTEST_PCR)
    pairs = tuple(zip(SPP_DIAG_PCR_SELECTION, digest_values))
    by_index = dict(pairs)
    for index, digest in ctx.expectations.baseline_pcrs:
        if not hmac.compare_digest(by_index[index], digest):
            _bad(CP_SPP_DIAG_ATTEST_PCR)
    if not hmac.compare_digest(by_index[10], ctx.expectations.ima_pcr10):
        _bad(CP_SPP_DIAG_ATTEST_PCR)
    ctx.pcr_pairs = pairs


def _tcb_meets_floor(record, floor):
    return (
        record[0] >= floor.boot_loader
        and record[1] >= floor.tee
        and record[6] >= floor.snp
        and record[7] >= floor.microcode
    )


def _stage_policy(ctx):
    expectations = ctx.expectations
    if ctx.snp_version != expectations.snp_report_version:
        _bad(CP_SPP_DIAG_ATTEST_POLICY)
    if ctx.snp_policy != expectations.snp_policy:
        _bad(CP_SPP_DIAG_ATTEST_POLICY)
    if ((ctx.snp_policy >> _POLICY_DEBUG_BIT) & 1) != 0:
        _bad(CP_SPP_DIAG_ATTEST_POLICY)
    if ((expectations.snp_policy >> _POLICY_DEBUG_BIT) & 1) != 0:
        _bad(CP_SPP_DIAG_ATTEST_POLICY)
    if ctx.snp_vmpl != expectations.snp_vmpl:
        _bad(CP_SPP_DIAG_ATTEST_POLICY)
    if not hmac.compare_digest(ctx.measurement, expectations.snp_measurement):
        _bad(CP_SPP_DIAG_ATTEST_POLICY)
    if not hmac.compare_digest(ctx.host_data, expectations.snp_host_data):
        _bad(CP_SPP_DIAG_ATTEST_POLICY)
    if ctx.cpuid_family != expectations.cpuid_family:
        _bad(CP_SPP_DIAG_ATTEST_POLICY)
    if ctx.cpuid_model != expectations.cpuid_model:
        _bad(CP_SPP_DIAG_ATTEST_POLICY)
    if ctx.cpuid_step != expectations.cpuid_step:
        _bad(CP_SPP_DIAG_ATTEST_POLICY)
    floor = expectations.minimum_tcb
    for record in (ctx.current_tcb, ctx.reported_tcb, ctx.committed_tcb, ctx.launch_tcb):
        if not _tcb_meets_floor(record, floor):
            _bad(CP_SPP_DIAG_ATTEST_POLICY)


def _build_result(ctx):
    return SppDiagAttestation(
        status=_STATUS,
        evidence_expectations_sha256=_commitment(ctx.evidence, ctx.expectations),
        quote_extra_data=ctx.expectations.quote_extra_data,
        snp_measurement=ctx.measurement,
        snp_host_data=ctx.host_data,
        reported_tcb=ctx.reported_tcb,
        pcr_sha256=ctx.pcr_pairs,
        quote_clock=ctx.quote_clock,
        quote_reset_count=ctx.quote_reset_count,
        quote_restart_count=ctx.quote_restart_count,
        quote_safe=ctx.quote_safe_byte == 1,
        quote_firmware_version=ctx.quote_firmware_version,
    )


def _appraise_spp_diag_attestation(evidence, expectations):
    ctx = _Ctx()
    ctx.evidence = evidence
    ctx.expectations = expectations
    _run(CP_SPP_DIAG_ATTEST_TYPE, _stage_type, ctx)
    _run(CP_SPP_DIAG_ATTEST_CAP, _stage_cap, ctx)
    _run(CP_SPP_DIAG_ATTEST_X509, _stage_x509, ctx)
    _run(CP_SPP_DIAG_ATTEST_ROOT, _stage_root, ctx)
    _run(CP_SPP_DIAG_ATTEST_CRL, _stage_crl, ctx)
    _run(CP_SPP_DIAG_ATTEST_HCLA, _stage_hcla, ctx)
    _run(CP_SPP_DIAG_ATTEST_SNP, _stage_snp, ctx)
    _run(CP_SPP_DIAG_ATTEST_VCEK, _stage_vcek, ctx)
    _run(CP_SPP_DIAG_ATTEST_AK, _stage_ak, ctx)
    _run(CP_SPP_DIAG_ATTEST_QUOTE, _stage_quote, ctx)
    _run(CP_SPP_DIAG_ATTEST_PCR, _stage_pcr, ctx)
    _run(CP_SPP_DIAG_ATTEST_POLICY, _stage_policy, ctx)
    return _build_result(ctx)


def appraise_spp_diag_attestation(evidence, expectations):
    """Appraise caller-supplied diagnostic attestation evidence."""

    failure = None
    result = None
    try:
        result = _appraise_spp_diag_attestation(evidence, expectations)
    except _SppDiagAttestStageError as error:
        failure = error.reason_code
        error.__traceback__ = None
    except Exception as error:
        failure = CP_SPP_DIAG_ATTEST_PRIVACY
        error.__traceback__ = None
        error.__context__ = None
        error.__cause__ = None
    if failure is None:
        return result
    evidence = None
    expectations = None
    result = None
    _fail(failure)
