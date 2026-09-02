#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Frozen production contract for SPP diagnostic attestation appraisal."""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import inspect
import warnings
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.utils import CryptographyDeprecationWarning

import conf_proc_spp_diag_attest as attest_mod
from conf_proc_spp_diag_attest import (
    HCLA_BYTES,
    MAX_AK_PEM_BYTES,
    MAX_AK_PUBLIC_BYTES,
    MAX_CERT_PEM_BYTES,
    MAX_CRL_DER_BYTES,
    MAX_QUOTE_MSG_BYTES,
    MAX_QUOTE_PCRS_BYTES,
    MAX_QUOTE_SIG_BYTES,
    SPP_DIAG_BASELINE_PCR_SELECTION,
    SPP_DIAG_PCR_SELECTION,
    SppDiagAttestation,
    SppDiagAttestationEvidence,
    SppDiagAttestationExpectations,
    SppDiagTcbFloor,
    appraise_spp_diag_attestation,
)
from conf_proc_spp_diag_attest_reasons import (
    ALL_SPP_DIAG_ATTEST_REASONS,
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
from conf_proc_spp_diag_attest_fixture import fixture_bytes


TYPE = CP_SPP_DIAG_ATTEST_TYPE
CAP = CP_SPP_DIAG_ATTEST_CAP
X509 = CP_SPP_DIAG_ATTEST_X509
ROOT = CP_SPP_DIAG_ATTEST_ROOT
CRL = CP_SPP_DIAG_ATTEST_CRL
HCLA = CP_SPP_DIAG_ATTEST_HCLA
SNP = CP_SPP_DIAG_ATTEST_SNP
VCEK = CP_SPP_DIAG_ATTEST_VCEK
AK = CP_SPP_DIAG_ATTEST_AK
QUOTE = CP_SPP_DIAG_ATTEST_QUOTE
PCR = CP_SPP_DIAG_ATTEST_PCR
POLICY = CP_SPP_DIAG_ATTEST_POLICY
PRIVACY = CP_SPP_DIAG_ATTEST_PRIVACY

_ORACLE_SPEC = importlib.util.spec_from_file_location(
    "_spp_diag_attest_oracle",
    Path(__file__).with_name("conf-proc-spp-diag-attest-oracle-selftest.py"),
)
assert _ORACLE_SPEC is not None and _ORACLE_SPEC.loader is not None
_oracle = importlib.util.module_from_spec(_ORACLE_SPEC)
_ORACLE_SPEC.loader.exec_module(_oracle)

_TWIN_HITS: set[str] = set()
_PARENT_QN = bytes.fromhex("4000000b")
_EVIDENCE_BYTES = (
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
)
_FIXED_BYTES = (
    ("quote_extra_data", 32),
    ("ark_der_sha256", 32),
    ("ask_der_sha256", 32),
    ("ark_crl_der_sha256", 32),
    ("snp_measurement", 48),
    ("snp_host_data", 32),
    ("ima_pcr10", 32),
)


class BytesSubclass(bytes):
    pass


def _to_production(evidence, expectations):
    floor = expectations.minimum_tcb
    return (
        SppDiagAttestationEvidence(
            ark_pem=evidence.ark_pem,
            ask_pem=evidence.ask_pem,
            vcek_pem=evidence.vcek_pem,
            ark_crl_der=evidence.ark_crl_der,
            ak_public_pem=evidence.ak_public_pem,
            ak_tpmt_public=evidence.ak_tpmt_public,
            hcl_report=evidence.hcl_report,
            quote_msg=evidence.quote_msg,
            quote_sig=evidence.quote_sig,
            quote_pcrs=evidence.quote_pcrs,
        ),
        SppDiagAttestationExpectations(
            appraisal_unix=expectations.appraisal_unix,
            quote_extra_data=expectations.quote_extra_data,
            ark_der_sha256=expectations.ark_der_sha256,
            ask_der_sha256=expectations.ask_der_sha256,
            ark_crl_der_sha256=expectations.ark_crl_der_sha256,
            ak_parent_qualified_name=expectations.ak_parent_qualified_name,
            snp_report_version=expectations.snp_report_version,
            snp_policy=expectations.snp_policy,
            snp_vmpl=expectations.snp_vmpl,
            snp_measurement=expectations.snp_measurement,
            snp_host_data=expectations.snp_host_data,
            minimum_tcb=SppDiagTcbFloor(
                boot_loader=floor.boot_loader,
                tee=floor.tee,
                snp=floor.snp,
                microcode=floor.microcode,
            ),
            vcek_product_name=expectations.vcek_product_name,
            cpuid_family=expectations.cpuid_family,
            cpuid_model=expectations.cpuid_model,
            cpuid_step=expectations.cpuid_step,
            baseline_pcrs=tuple(expectations.baseline_pcrs),
            ima_pcr10=expectations.ima_pcr10,
        ),
    )


def _appraise(evidence, expectations):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        return appraise_spp_diag_attestation(evidence, expectations)


def _expect_error(reason, evidence, expectations) -> SppDiagAttestError:
    try:
        _appraise(evidence, expectations)
    except SppDiagAttestError as exc:
        assert type(exc) is SppDiagAttestError
        assert exc.reason_code == reason
        assert exc.args == (reason,)
        assert str(exc) == reason
        assert vars(exc) == {"reason_code": reason}
        assert exc.__cause__ is None
        assert exc.__context__ is None
        return exc
    raise AssertionError("expected %s" % reason)


def _frozen_oracle():
    return _oracle.frozen_positive()


def _frozen_pair():
    return _to_production(*_frozen_oracle())


def _fresh_pair():
    return _to_production(*_oracle.fresh_positive())


def _hit(name):
    _TWIN_HITS.add(name)


def _twins_named(predicate):
    for name, builder in _oracle.FRESH_TWINS:
        if predicate(name):
            yield name, builder


def _expect_twins(reason, predicate):
    for name, builder in _twins_named(predicate):
        _hit(name)
        oracle_ev, oracle_exp = builder()
        ev, exp = _to_production(oracle_ev, oracle_exp)
        try:
            _expect_error(reason, ev, exp)
        except AssertionError as exc:
            raise AssertionError("twin %s" % name) from exc


def _find_twin(name):
    for twin_name, builder in _oracle.FRESH_TWINS:
        if twin_name == name:
            return builder
    raise AssertionError("missing twin: %s" % name)


def _quote_clock_fields(raw: bytes):
    offset = 0

    def take(size):
        nonlocal offset
        piece = raw[offset : offset + size]
        offset += size
        return piece

    def number(size):
        return int.from_bytes(take(size), "big")

    assert number(4) == 0xFF544347
    assert number(2) == 0x8018
    take(number(2))
    take(number(2))
    clock = number(8)
    reset = number(4)
    restart = number(4)
    safe = number(1)
    firmware = number(8)
    return clock, reset, restart, safe == 1, firmware


def _field_names(cls):
    return tuple(item.name for item in dataclasses.fields(cls))


def _field_types(cls):
    return tuple(item.type for item in dataclasses.fields(cls))


def _product_frames(exc, filename):
    frames = []
    traceback = exc.__traceback__
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename.endswith(filename):
            frames.append(traceback.tb_frame)
        traceback = traceback.tb_next
    return frames


def test_public_contract() -> None:
    names = {
        CP_SPP_DIAG_ATTEST_TYPE,
        CP_SPP_DIAG_ATTEST_CAP,
        CP_SPP_DIAG_ATTEST_X509,
        CP_SPP_DIAG_ATTEST_ROOT,
        CP_SPP_DIAG_ATTEST_CRL,
        CP_SPP_DIAG_ATTEST_HCLA,
        CP_SPP_DIAG_ATTEST_SNP,
        CP_SPP_DIAG_ATTEST_VCEK,
        CP_SPP_DIAG_ATTEST_AK,
        CP_SPP_DIAG_ATTEST_QUOTE,
        CP_SPP_DIAG_ATTEST_PCR,
        CP_SPP_DIAG_ATTEST_POLICY,
        CP_SPP_DIAG_ATTEST_PRIVACY,
    }
    assert len(ALL_SPP_DIAG_ATTEST_REASONS) == 13
    assert ALL_SPP_DIAG_ATTEST_REASONS == frozenset(names)
    try:
        SppDiagAttestError("not-a-real-code")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown reason")
    error = SppDiagAttestError(TYPE)
    assert error.reason_code == TYPE
    assert isinstance(error, RuntimeError)
    assert _field_names(SppDiagTcbFloor) == ("boot_loader", "tee", "snp", "microcode")
    assert _field_types(SppDiagTcbFloor) == (int, int, int, int)
    assert _field_names(SppDiagAttestationEvidence) == (
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
    )
    assert _field_types(SppDiagAttestationEvidence) == (bytes,) * 10
    assert _field_names(SppDiagAttestationExpectations) == (
        "appraisal_unix",
        "quote_extra_data",
        "ark_der_sha256",
        "ask_der_sha256",
        "ark_crl_der_sha256",
        "ak_parent_qualified_name",
        "snp_report_version",
        "snp_policy",
        "snp_vmpl",
        "snp_measurement",
        "snp_host_data",
        "minimum_tcb",
        "vcek_product_name",
        "cpuid_family",
        "cpuid_model",
        "cpuid_step",
        "baseline_pcrs",
        "ima_pcr10",
    )
    assert _field_types(SppDiagAttestationExpectations) == (
        int,
        bytes,
        bytes,
        bytes,
        bytes,
        bytes,
        int,
        int,
        int,
        bytes,
        bytes,
        SppDiagTcbFloor,
        bytes,
        int,
        int,
        int,
        tuple[tuple[int, bytes], ...],
        bytes,
    )
    assert _field_names(SppDiagAttestation) == (
        "status",
        "evidence_expectations_sha256",
        "quote_extra_data",
        "snp_measurement",
        "snp_host_data",
        "reported_tcb",
        "pcr_sha256",
        "quote_clock",
        "quote_reset_count",
        "quote_restart_count",
        "quote_safe",
        "quote_firmware_version",
    )
    assert _field_types(SppDiagAttestation) == (
        str,
        bytes,
        bytes,
        bytes,
        bytes,
        bytes,
        tuple[tuple[int, bytes], ...],
        int,
        int,
        int,
        bool,
        int,
    )
    assert MAX_CERT_PEM_BYTES == 16_384
    assert MAX_CRL_DER_BYTES == 4_194_304
    assert MAX_AK_PEM_BYTES == 4_096
    assert MAX_AK_PUBLIC_BYTES == 1_024
    assert HCLA_BYTES == 2_600
    assert MAX_QUOTE_MSG_BYTES == 4_096
    assert MAX_QUOTE_SIG_BYTES == 1_024
    assert MAX_QUOTE_PCRS_BYTES == 8_192
    assert SPP_DIAG_PCR_SELECTION == (0, 2, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 22, 23)
    assert SPP_DIAG_BASELINE_PCR_SELECTION == (
        0, 2, 4, 7, 8, 9, 11, 12, 13, 14, 15, 16, 22, 23,
    )
    signature = inspect.signature(attest_mod.appraise_spp_diag_attestation)
    assert tuple(signature.parameters) == ("evidence", "expectations")


def test_positive_frozen_fixture() -> None:
    oracle_ev, oracle_exp = _frozen_oracle()
    ev, exp = _to_production(oracle_ev, oracle_exp)
    result = _appraise(ev, exp)
    assert result.status == "diagnostic_attestation_verified"
    assert result.evidence_expectations_sha256 == _oracle._oracle_commitment(
        oracle_ev, oracle_exp
    )
    reported = fixture_bytes("hcl_report.bin")[0x020 + 0x180 : 0x020 + 0x188]
    assert result.reported_tcb == reported
    assert len(result.pcr_sha256) == 15
    assert tuple(item[0] for item in result.pcr_sha256) == SPP_DIAG_PCR_SELECTION
    assert result.pcr_sha256[6] == (10, exp.ima_pcr10)
    clock, reset, restart, safe, firmware = _quote_clock_fields(fixture_bytes("quote.msg"))
    assert result.quote_clock == clock
    assert result.quote_reset_count == reset
    assert result.quote_restart_count == restart
    assert result.quote_safe is True and safe is True
    assert result.quote_firmware_version == firmware
    assert result.quote_extra_data == exp.quote_extra_data
    assert result.snp_measurement == exp.snp_measurement
    assert result.snp_host_data == exp.snp_host_data


def test_positive_fresh_factory() -> None:
    for builder in (_oracle.fresh_positive, _oracle.fresh_positive_attr_50472):
        oracle_ev, oracle_exp = builder()
        ev, exp = _to_production(oracle_ev, oracle_exp)
        result = _appraise(ev, exp)
        assert result.status == "diagnostic_attestation_verified"
        assert result.evidence_expectations_sha256 == _oracle._oracle_commitment(
            oracle_ev, oracle_exp
        )
        assert result.quote_safe is True
        assert len(result.pcr_sha256) == 15
        assert result.pcr_sha256[6][0] == 10
        assert result.pcr_sha256[6][1] == exp.ima_pcr10


def test_type_stage() -> None:
    ev, exp = _frozen_pair()
    int_fields = (
        "appraisal_unix",
        "snp_report_version",
        "snp_policy",
        "snp_vmpl",
        "cpuid_family",
        "cpuid_model",
        "cpuid_step",
    )
    for name in int_fields:
        _expect_error(TYPE, ev, dataclasses.replace(exp, **{name: True}))
    floor = exp.minimum_tcb
    for name in ("boot_loader", "tee", "snp", "microcode"):
        _expect_error(
            TYPE,
            ev,
            dataclasses.replace(exp, minimum_tcb=dataclasses.replace(floor, **{name: True})),
        )
    for name in _EVIDENCE_BYTES:
        value = getattr(ev, name)
        _expect_error(TYPE, dataclasses.replace(ev, **{name: bytearray(value)}), exp)
        _expect_error(TYPE, dataclasses.replace(ev, **{name: BytesSubclass(value)}), exp)
    for name, size in _FIXED_BYTES:
        _expect_error(TYPE, ev, dataclasses.replace(exp, **{name: bytes(size - 1)}))
        _expect_error(TYPE, ev, dataclasses.replace(exp, **{name: bytes(size + 1)}))
        value = getattr(exp, name)
        _expect_error(TYPE, ev, dataclasses.replace(exp, **{name: bytearray(value)}))
        _expect_error(TYPE, ev, dataclasses.replace(exp, **{name: BytesSubclass(value)}))
    _expect_error(TYPE, ev, dataclasses.replace(exp, ak_parent_qualified_name=b"\x40\x00\x00\x0c"))
    _expect_error(TYPE, ev, dataclasses.replace(exp, ak_parent_qualified_name=bytearray(_PARENT_QN)))
    _expect_error(TYPE, ev, dataclasses.replace(exp, vcek_product_name=b""))
    _expect_error(TYPE, ev, dataclasses.replace(exp, vcek_product_name=bytes(65)))
    _expect_error(TYPE, ev, dataclasses.replace(exp, baseline_pcrs=list(exp.baseline_pcrs)))
    _expect_error(TYPE, ev, dataclasses.replace(exp, baseline_pcrs=exp.baseline_pcrs[:-1]))
    extra = exp.baseline_pcrs + ((0, bytes(32)),)
    _expect_error(TYPE, ev, dataclasses.replace(exp, baseline_pcrs=extra))
    with_ten = ((10, exp.ima_pcr10),) + exp.baseline_pcrs[1:]
    _expect_error(TYPE, ev, dataclasses.replace(exp, baseline_pcrs=with_ten))
    _expect_error(TYPE, ev, dataclasses.replace(exp, baseline_pcrs=tuple(reversed(exp.baseline_pcrs))))
    flipped = ((True, exp.baseline_pcrs[0][1]),) + exp.baseline_pcrs[1:]
    _expect_error(TYPE, ev, dataclasses.replace(exp, baseline_pcrs=flipped))
    _expect_error(TYPE, {}, exp)
    _expect_error(TYPE, ev, {})
    _expect_error(TYPE, ev, dataclasses.replace(exp, appraisal_unix=-1))
    _expect_error(TYPE, ev, dataclasses.replace(exp, snp_vmpl=256))


def test_cap_stage() -> None:
    ev, exp = _frozen_pair()
    limits = (
        ("ark_pem", MAX_CERT_PEM_BYTES),
        ("ask_pem", MAX_CERT_PEM_BYTES),
        ("vcek_pem", MAX_CERT_PEM_BYTES),
        ("ark_crl_der", MAX_CRL_DER_BYTES),
        ("ak_public_pem", MAX_AK_PEM_BYTES),
        ("ak_tpmt_public", MAX_AK_PUBLIC_BYTES),
        ("quote_msg", MAX_QUOTE_MSG_BYTES),
        ("quote_sig", MAX_QUOTE_SIG_BYTES),
        ("quote_pcrs", MAX_QUOTE_PCRS_BYTES),
    )
    for name, cap in limits:
        value = getattr(ev, name)
        assert len(value) <= cap
        padded = value + bytes(cap + 1 - len(value))
        _expect_error(CAP, dataclasses.replace(ev, **{name: padded}), exp)
    assert len(ev.hcl_report) == HCLA_BYTES
    _expect_error(CAP, dataclasses.replace(ev, hcl_report=ev.hcl_report[:-1]), exp)
    _expect_error(CAP, dataclasses.replace(ev, hcl_report=ev.hcl_report + b"\x00"), exp)


def test_x509_root_crl() -> None:
    _expect_twins(
        X509,
        lambda name: name.startswith("vcek_ski")
        or name.startswith("vcek_aki")
        or name == "vcek_extra_extension",
    )
    ev, exp = _frozen_pair()
    flipped_ark = bytearray(exp.ark_der_sha256)
    flipped_ark[0] ^= 1
    _expect_error(ROOT, ev, dataclasses.replace(exp, ark_der_sha256=bytes(flipped_ark)))
    flipped_ask = bytearray(exp.ask_der_sha256)
    flipped_ask[0] ^= 1
    _expect_error(ROOT, ev, dataclasses.replace(exp, ask_der_sha256=bytes(flipped_ask)))
    flipped_crl = bytearray(exp.ark_crl_der_sha256)
    flipped_crl[0] ^= 1
    _expect_error(CRL, ev, dataclasses.replace(exp, ark_crl_der_sha256=bytes(flipped_crl)))
    _expect_twins(CRL, lambda name: name == "ask_revoked")
    _expect_error(X509, dataclasses.replace(ev, ark_pem=ev.ark_pem + b"\x00"), exp)
    _expect_error(X509, dataclasses.replace(ev, ark_pem=ev.ark_pem + ev.ark_pem), exp)


def test_hcla_snp() -> None:
    _expect_twins(HCLA, lambda name: name.startswith("hcla_"))
    ev, exp = _fresh_pair()
    report = bytearray(ev.hcl_report)
    report[0x020 + 0x2A0] ^= 1
    _expect_error(SNP, dataclasses.replace(ev, hcl_report=bytes(report)), exp)
    _expect_twins(SNP, lambda name: name in {"cpuid_family", "reserved_current", "reserved_reported"})


def test_vcek_binding() -> None:
    oracle_ev, oracle_exp = _oracle.fresh_positive()
    ev, exp = _to_production(oracle_ev, oracle_exp)
    result = _appraise(ev, exp)
    assert result.status == "diagnostic_attestation_verified"
    _expect_twins(
        VCEK,
        lambda name: name.startswith("vcek_ext_")
        or name in {"chip_id_mismatch", "reported_tcb_mismatch"},
    )


def test_ak_quote_pcr() -> None:
    _expect_twins(QUOTE, lambda name: name.startswith("quote_") and name != "quote_digest")
    _expect_twins(PCR, lambda name: name == "quote_digest")
    _expect_twins(PCR, lambda name: name.startswith("pcr_") or name == "pcr10")
    # GHSA-8rjm-5f5f-h4q6: tpm2-tools PCR-selection confusion between the signed
    # quote and a separately-supplied PCR values file. The PCR-file's own
    # selection must independently match the quote's signed selection before
    # any PCR value is trusted.
    ghsa_ev, ghsa_exp = _to_production(*_find_twin("pcr_file_selection")())
    _expect_error(PCR, ghsa_ev, ghsa_exp)
    ev, exp = _fresh_pair()
    tpmt = bytearray(ev.ak_tpmt_public)
    tpmt[-1] ^= 1
    _expect_error(AK, dataclasses.replace(ev, ak_tpmt_public=bytes(tpmt)), exp)
    ak = serialization.load_pem_public_key(fixture_bytes("akpub.pem"))
    sig = fixture_bytes("quote.sig")
    offset = 4
    size = int.from_bytes(sig[offset : offset + 2], "big")
    raw = sig[offset + 2 : offset + 2 + size]
    try:
        ak.verify(
            raw,
            fixture_bytes("quote.msg"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    except InvalidSignature:
        pass
    else:
        raise AssertionError("PSS must not verify frozen quote")


def test_policy_and_commitment() -> None:
    remaining = {
        "debug_bit",
        "vmpl_expectation",
        "cpuid_model_expectation",
        "measurement_expectation",
        "host_data_expectation",
        "floor_current_boot",
        "floor_committed_tee",
        "floor_launch_snp",
        "floor_reported_ucode",
    }
    _expect_twins(POLICY, lambda name: name in remaining)
    names = {name for name, _builder in _oracle.FRESH_TWINS}
    assert names == _TWIN_HITS, sorted(names - _TWIN_HITS)
    oracle_ev, oracle_exp = _oracle.fresh_positive()
    original = _oracle._oracle_commitment(oracle_ev, oracle_exp)
    mutated_ev = dataclasses.replace(oracle_ev, quote_sig=oracle_ev.quote_sig[:-1] + bytes((oracle_ev.quote_sig[-1] ^ 1,)))
    assert _oracle._oracle_commitment(mutated_ev, oracle_exp) != original
    mutated_unix = dataclasses.replace(oracle_exp, appraisal_unix=oracle_exp.appraisal_unix + 1)
    assert _oracle._oracle_commitment(oracle_ev, mutated_unix) != original
    flipped = bytearray(oracle_exp.snp_host_data)
    flipped[0] ^= 1
    mutated_host = dataclasses.replace(oracle_exp, snp_host_data=bytes(flipped))
    assert _oracle._oracle_commitment(oracle_ev, mutated_host) != original
    new_tee = (oracle_exp.minimum_tcb.tee + 1) % 256
    mutated_floor = dataclasses.replace(
        oracle_exp, minimum_tcb=dataclasses.replace(oracle_exp.minimum_tcb, tee=new_tee)
    )
    assert _oracle._oracle_commitment(oracle_ev, mutated_floor) != original
    baseline = list(oracle_exp.baseline_pcrs)
    index, digest = baseline[0]
    digest = bytes((digest[0] ^ 1,)) + digest[1:]
    baseline[0] = (index, digest)
    mutated_pcr = dataclasses.replace(oracle_exp, baseline_pcrs=tuple(baseline))
    assert _oracle._oracle_commitment(oracle_ev, mutated_pcr) != original
    ima = bytearray(oracle_exp.ima_pcr10)
    ima[0] ^= 1
    mutated_ima = dataclasses.replace(oracle_exp, ima_pcr10=bytes(ima))
    assert _oracle._oracle_commitment(oracle_ev, mutated_ima) != original


def test_privacy_and_independence() -> None:
    ev, exp = _frozen_pair()
    original = attest_mod._build_result

    def boom(_ctx):
        raise RuntimeError("secret detail: sk=deadbeef")

    attest_mod._build_result = boom
    try:
        exc = _expect_error(PRIVACY, ev, exp)
    finally:
        attest_mod._build_result = original
    text = str(exc) + repr(exc)
    assert "secret detail" not in text
    assert "deadbeef" not in text
    assert "secret detail" not in exc.args
    assert "deadbeef" not in exc.args
    frames = _product_frames(exc, "conf_proc_spp_diag_attest.py")
    assert [frame.f_code.co_name for frame in frames] == [
        "appraise_spp_diag_attestation",
        "_fail",
    ]
    typed = _expect_error(TYPE, ev, dataclasses.replace(exp, snp_vmpl=True))
    frames = _product_frames(typed, "conf_proc_spp_diag_attest.py")
    assert [frame.f_code.co_name for frame in frames] == [
        "appraise_spp_diag_attestation",
        "_fail",
    ]
    for frame in frames:
        if frame.f_code.co_name == "appraise_spp_diag_attestation":
            assert frame.f_locals.get("evidence") is None
            assert frame.f_locals.get("expectations") is None
            assert frame.f_locals.get("result") is None
        for value in frame.f_locals.values():
            if type(value) is bytes:
                assert value not in {ev.hcl_report, ev.quote_msg, exp.snp_measurement}

    root = Path(__file__).resolve().parents[1]
    attest_source = (root / "conf_proc_spp_diag_attest.py").read_text(encoding="utf-8")
    reasons_source = (root / "conf_proc_spp_diag_attest_reasons.py").read_text(
        encoding="utf-8"
    )
    attest_imports = _import_set(attest_source)
    reasons_imports = _import_set(reasons_source)
    allowed = {
        "dataclasses",
        "datetime",
        "hashlib",
        "hmac",
        "json",
        "struct",
        "base64",
        "typing",
        "__future__",
        "conf_proc_spp_diag_attest_reasons",
    }
    for name in attest_imports:
        assert name in allowed or name.startswith("cryptography"), name
    for name in reasons_imports:
        assert name in {"__future__", "typing"}, name
    forbidden = (
        "sub" + "process",
        "ct" + "ypes",
        "verifi" + "er",
        "spp_diag_attest_fix" + "ture",
        "soc" + "ket",
        "urll" + "ib",
        "requ" + "ests",
        "os.en" + "viron",
        "datetime" + ".now(",
        "time.ti" + "me(",
        "time.mono" + "tonic(",
    )
    for source in (attest_source, reasons_source):
        assert "open(" not in source
        if any(token in source for token in forbidden):
            raise AssertionError("production reached forbidden authority")
    here = Path(__file__).read_text(encoding="utf-8")
    oracle = Path(__file__).with_name("conf-proc-spp-diag-attest-oracle-selftest.py").read_text(
        encoding="utf-8"
    )
    token_import = "import verifi" + "er"
    token_from = "from verifi" + "er"
    assert token_import not in here and token_from not in here
    assert token_import not in oracle and token_from not in oracle


def _import_set(source: str) -> set[str]:
    tree = ast.parse(source)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"__import__", "eval", "exec", "open"}
        ):
            raise AssertionError("production dynamic or path-opening call")
    return imports


TESTS = (
    test_public_contract,
    test_positive_frozen_fixture,
    test_positive_fresh_factory,
    test_type_stage,
    test_cap_stage,
    test_x509_root_crl,
    test_hcla_snp,
    test_vcek_binding,
    test_ak_quote_pcr,
    test_policy_and_commitment,
    test_privacy_and_independence,
)


def main() -> None:
    for test in TESTS:
        test()
    print(
        "spp diagnostic attestation production contract: ok (%d tests, %d twins)"
        % (len(TESTS), len(_TWIN_HITS))
    )


if __name__ == "__main__":
    main()
