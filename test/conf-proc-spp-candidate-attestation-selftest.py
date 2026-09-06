#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fresh signed CPU/AK chains exercise the actual candidate quote conjunction."""
from dataclasses import asdict, fields, replace
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'test')]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


import conf_proc_spp_candidate_attestation as r
oracle = load('independent_attestation_oracle', ROOT / 'test/conf-proc-spp-diag-attest-oracle-selftest.py')
from conf_proc_spp_diag_attest import SppDiagAttestationEvidence, SppDiagAttestationExpectations, SppDiagTcbFloor
from ratls_contract import CompositeEvidence, ExporterProof


def h(raw): return hashlib.sha256(raw).digest()


class Fixture:
    def __init__(self):
        self.k = oracle._Kit()
        self.k.pcr_map[14] = bytes(32)
        self.spki = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.exporter = b'e' * 32
        self.context = r.SupplementalContext(**{field.name: h(field.name.encode()) for field in fields(r.SupplementalContext)})
        self.context = replace(self.context, channel=h(self.exporter))
        values = asdict(self.k.expectations)
        values['minimum_tcb'] = SppDiagTcbFloor(**values['minimum_tcb'])
        values['baseline_pcrs'] = tuple((index, self.k.pcr_map[index]) for index in oracle._BASELINE_INDEXES)
        self.platform = SppDiagAttestationExpectations(**values)
        self.gpu = b'opaque GPU evidence is bound here and separately appraised later'

    def quote(self, extra, indices, *, clock=1000, reset=7, restart=3, safe=1, changes=None):
        values = dict(self.k.pcr_map); values.update(changes or {})
        pcrs = tuple(values[index] for index in indices)
        bitmap = bytearray(3)
        for index in indices: bitmap[index // 8] |= 1 << (index % 8)
        message = bytearray(self.k._quote_msg(self.k.qn, extra, bytes(bitmap), h(b''.join(pcrs)), safe))
        offset = 6 + 2 + len(self.k.qn) + 2 + len(extra)
        struct.pack_into('>QII', message, offset, clock, reset, restart)
        message = bytes(message)
        return message, self.k._quote_sig(message), self.k._pcrs_file(pcrs, bytes(bitmap), (8, len(indices) - 8))

    def bundle(self, *, cert_options=None, exporter_options=None, supplemental_options=None, context=None):
        ctx = context or self.context
        cert_extra = h(b'sol-spp-ratls-certificate-bind-v1' + ctx.challenge + h(self.spki) + h(self.gpu))
        msg, sig, pcrs = self.quote(cert_extra, oracle._BASELINE_INDEXES, **(cert_options or {}))
        evidence = CompositeEvidence(ctx.challenge, self.spki, self.k.report, self.k.hcla, self.k.ak_pem,
            msg, sig, pcrs, self.k.evidence.ark_pem, self.k.evidence.ask_pem, self.k.evidence.vcek_pem, self.gpu).to_der()
        export_extra = h(b'sol-spp-ratls-exporter-bind-v1' + ctx.challenge + h(self.spki) + self.exporter + h(self.gpu))
        msg, sig, pcrs = self.quote(export_extra, oracle._BASELINE_INDEXES, **({'clock': 1100} | (exporter_options or {})))
        proof = ExporterProof(ctx.challenge, self.spki, self.exporter, msg, sig, pcrs).to_der()
        receipt = r.supplemental_receipt(evidence, ctx)
        msg, sig, pcrs = self.quote(h(b'sol-pbc/spp/candidate-supplement/1\0' + receipt), oracle._PCR_INDEXES,
            **({'clock': 1200} | (supplemental_options or {})))
        supplement = SppDiagAttestationEvidence(**asdict(self.k.evidence))
        supplement = replace(supplement, quote_msg=msg, quote_sig=sig, quote_pcrs=pcrs)
        return [evidence, proof, receipt, supplement]

    def appraise(self, bundle, *, context=None, spki=None, exporter=None):
        return r.appraise_quote_conjunction(*bundle, self.platform, context or self.context,
            connected_spki_der=spki or self.spki, tls_exporter=exporter or self.exporter)


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.f = Fixture()

    def test_full_fresh_signed_cpu_and_three_quote_conjunction(self):
        bundle = self.f.bundle(); result = self.f.appraise(bundle)
        self.assertEqual(result.envelope_sha256, h(bundle[0]))
        self.assertEqual((result.certificate.clock, result.exporter.clock, result.supplemental.quote_clock), (1000, 1100, 1200))
        self.assertEqual(len(result.certificate.pcrs), 14)
        self.assertEqual(len(result.supplemental.pcr_sha256), 15)
        self.assertFalse(hasattr(result, 'lease'))

    def test_each_independent_context_coordinate_rejects_coherent_alternative(self):
        for field in fields(r.SupplementalContext):
            changed = replace(self.f.context, **{field.name: b'x' * 32})
            with self.subTest(field=field.name), self.assertRaises(Exception):
                self.f.appraise(self.f.bundle(context=changed))

    def test_wrong_connected_spki_or_exporter_rejects(self):
        for kwargs in ({'spki': b'wrong'}, {'exporter': b'x' * 32}):
            with self.assertRaises(ValueError): self.f.appraise(self.f.bundle(), **kwargs)

    def test_signed_clock_boot_and_safety_mismatches_reject(self):
        for kwargs in ({'cert_options': {'clock': 1101}}, {'exporter_options': {'clock': 1201}},
                       {'supplemental_options': {'clock': 61001}}, {'exporter_options': {'reset': 8}},
                       {'cert_options': {'restart': 4}}, {'cert_options': {'safe': 0}},
                       {'supplemental_options': {'safe': 0}}):
            with self.subTest(kwargs=kwargs), self.assertRaises(Exception): self.f.appraise(self.f.bundle(**kwargs))

    def test_signed_changed_pcrs_in_either_selection_reject(self):
        for key in ('cert_options', 'exporter_options', 'supplemental_options'):
            for index in ((10, 16) if key == 'supplemental_options' else (14, 16)):
                with self.assertRaises(Exception):
                    self.f.appraise(self.f.bundle(**{key: {'changes': {index: b'x' * 32}}}))

    def test_altered_quote_signature_hcla_and_missing_pcr10_reject(self):
        bundle = self.f.bundle()
        for field in ('quote_sig', 'hcl_report', 'ak_public_pem', 'ark_crl_der'):
            bad = bundle.copy(); value = getattr(bad[3], field)
            bad[3] = replace(bad[3], **{field: value[:-1] + bytes([value[-1] ^ 1])})
            with self.assertRaises(Exception): self.f.appraise(bad)
        msg, sig, pcrs = self.f.quote(r.receipt_digest(bundle[2]), oracle._BASELINE_INDEXES)
        bundle[3] = replace(bundle[3], quote_msg=msg, quote_sig=sig, quote_pcrs=pcrs)
        with self.assertRaises(Exception): self.f.appraise(bundle)

    def test_receipt_cannot_contain_own_quote_or_extra_fields(self):
        bundle = self.f.bundle()
        obj = r.canonical_loads(bundle[2]); obj['quote_digest'] = h(bundle[3].quote_msg).hex()
        bundle[2] = r.canonical_dumps(obj)
        with self.assertRaises(ValueError): self.f.appraise(bundle)


if __name__ == '__main__': unittest.main()
