#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent contract tests for the SPP diagnostic off-box mapper."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import os
import stat
import struct
import tempfile
from pathlib import Path

import conf_proc_spp_diag_mapper as mapper
import conf_proc_spp_diagbundle_oracle as oracle
from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_spp_diag_attest import SppDiagTcbFloor
from conf_proc_spp_diag_capture import capture_diagnostic_uart
from conf_proc_spp_diag_export import build_export_stream
from conf_proc_spp_diag_ima import SppDiagImaCheckpoint, SppDiagImaReplay
from conf_proc_spp_diag_mapper_reasons import (
    CP_SPP_DIAG_MAPPER_OUTPUT,
    CP_SPP_DIAG_MAPPER_PCR,
    CP_SPP_DIAG_MAPPER_PUBLISH,
    CP_SPP_DIAG_MAPPER_SEAM,
    SppDiagMapperError,
)
from conf_proc_spp_diag_pcr import QUOTE_PCR_BITMAP, SPP_DIAG_PCR_SELECTION
from conf_proc_spp_diag_trace_checkpoints import (
    SppDiagTraceCheckpointExpectations,
)
from conf_proc_spp_diagbundle import CallerExpectations, inspect_diagnostic_members
from conf_proc_spp_diagbundle_stream import capture_bundle


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return str(path)


def _quote_pcrs(pcr10: bytes) -> bytes:
    values = [hashlib.sha256(b"pcr-" + bytes([index])).digest() for index in SPP_DIAG_PCR_SELECTION]
    values[SPP_DIAG_PCR_SELECTION.index(10)] = pcr10
    output = bytearray(struct.pack("<I", 1))
    output += struct.pack("<HB", 0x000B, 3) + QUOTE_PCR_BITMAP + bytes(5) + bytes(5)
    for _slot in range(7):
        output += bytes(16)
    output += struct.pack("<I", 2)
    offset = 0
    for count in (8, 7):
        output += struct.pack("<I", count)
        for slot in range(8):
            if slot < count:
                output += struct.pack("<H", 32) + values[offset] + bytes(32)
                offset += 1
            else:
                output += bytes(66)
    assert offset == len(values)
    return bytes(output)


class _AppraiserRecorder:
    def __init__(self, fixture: "_Fixture") -> None:
        self.fixture = fixture
        self.ima_result = SppDiagImaReplay(
            status="ima_pcr10_replayed",
            measurement_byte_count=len(fixture.ima),
            measurements_sha256=hashlib.sha256(fixture.ima).digest(),
            entry_count=3,
            pcr10_entry_count=3,
            final_pcr10_sha256=fixture.pcr10,
            checkpoints=tuple(
                SppDiagImaCheckpoint(
                    event_name=name,
                    record=bytes([index + 1]) * 256,
                    entry_index=index,
                )
                for index, name in enumerate(
                    (b"spp-diag/checkpoint/ready", b"spp-diag/checkpoint/release", b"spp-diag/checkpoint/terminal")
                )
            ),
        )
        self.checkpoint_result = object()
        self.attestation_result = object()
        self.calls: list[str] = []

    def replay(self, source: io.BytesIO, size: int, expected: bytes) -> SppDiagImaReplay:
        self.calls.append("ima")
        assert size == len(self.fixture.ima)
        assert source.read() == self.fixture.ima
        assert expected == self.fixture.pcr10
        return self.ima_result

    def bind(self, source, size, checkpoints, expectations):
        self.calls.append("checkpoints")
        assert source.read() == self.fixture.trace and size == len(self.fixture.trace)
        assert expectations is self.fixture.expectations.trace_checkpoints
        assert tuple((item.event_name, item.record) for item in checkpoints) == tuple(
            (item.event_name, item.record) for item in self.ima_result.checkpoints
        )
        return self.checkpoint_result

    def semantics(self, plan: bytes, trace: bytes) -> bytes:
        self.calls.append("semantics")
        assert plan == self.fixture.control_plan and trace == self.fixture.trace
        return b"trace-ledger"

    def attest(self, evidence, expectations):
        self.calls.append("attestation")
        assert evidence.ark_pem == self.fixture.amd.ark_pem
        assert evidence.ask_pem == self.fixture.amd.ask_pem
        assert evidence.vcek_pem == self.fixture.amd.vcek_pem
        assert evidence.ark_crl_der == self.fixture.amd.ark_crl_der
        assert evidence.ak_public_pem == self.fixture.ak_pem
        assert evidence.ak_tpmt_public == self.fixture.ak_tpmt
        assert evidence.hcl_report == self.fixture.hcla
        assert evidence.quote_msg == self.fixture.quote_msg
        assert evidence.quote_sig == self.fixture.quote_sig
        assert evidence.quote_pcrs == self.fixture.quote_pcrs
        expected_qd = oracle.domain_address(
            oracle.DOMAIN_QUOTE_QD,
            {
                "challenge": self.fixture.challenge.hex(),
                "control_plan_address": self.fixture.control_plan_address,
                "inner_receipt_digest": self.fixture.inner_receipt_digest,
                "run_identity": self.fixture.run_identity.hex(),
                "signed_image_binding_address": self.fixture.image_binding_address,
                "target_profile_id": self.fixture.target_profile,
            },
        )
        assert expectations.quote_extra_data == bytes.fromhex(expected_qd)
        assert expectations.ima_pcr10 == self.fixture.pcr10
        return self.attestation_result

    def table(self) -> mapper._Appraisers:
        return mapper._Appraisers(self.replay, self.bind, self.semantics, self.attest)


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.challenge = hashlib.sha256(b"mapper-challenge").digest()
        self.run_identity = hashlib.sha256(b"mapper-run").digest()
        self.target_profile = "azure:centralus:3:Standard_NCC40ads_H100_v5:ConfidentialVM:v1"
        expected_result = hashlib.sha256(b"mapper-expected-result").digest()
        seed = hashlib.sha256(
            b"sol-spp-diag-input-seed-v1\0" + self.challenge + self.run_identity
        ).digest()
        self.output_oracle_preimage = canonical_dumps(
            {
                "algorithm_id": "spp-diag-xor-stride32-v1",
                "challenge": self.challenge.hex(),
                "cuda_child_sha256": _sha(b"cuda-child"),
                "deterministic_seed": seed.hex(),
                "expected_result": expected_result.hex(),
                "model_sha256": _sha(b"model"),
                "model_size_bytes": 5,
                "ptx_sha256": _sha(b"ptx"),
                "run_identity": self.run_identity.hex(),
                "schema": "sol-spp-diag-output-oracle-v1",
            }
        )
        self.output_oracle = hashlib.sha256(
            b"sol-spp-diag-output-oracle-v1\0" + self.output_oracle_preimage
        ).hexdigest()
        self.output = struct.pack(">8sHHI32s", b"SPPGPUO1", 1, 1, 32, expected_result)
        self.trace = b"literal-trace"
        self.ima = b"literal-ima"
        self.firmware = b"literal-firmware"
        self.gpu = b"literal-gpu"
        self.pcr10 = hashlib.sha256(b"quoted-pcr10").digest()
        self.quote_pcrs = _quote_pcrs(self.pcr10)
        self.quote_msg = b"quote-message"
        self.quote_sig = b"quote-signature"
        self.ak_pem = b"-----BEGIN PUBLIC KEY-----\nAK\n-----END PUBLIC KEY-----\n"
        self.ak_tpmt = b"tpmt-public"
        self.hcla = b"H" * 2600
        self.control_plan = canonical_dumps(
            {
                "schema": "sol-spp-diag-trace-control-plan-v1",
                "synthetic_inference": {
                    "model_sha256": _sha(b"model"),
                    "output_oracle_address": self.output_oracle,
                },
            }
        )
        self.control_plan_address = hashlib.sha256(
            oracle.DOMAIN_CONTROL_PLAN + self.control_plan
        ).hexdigest()

        closure_data: list[tuple[str, str, str, bytes]] = []
        roles = (
            "source_tree_manifest",
            "build_recipe",
            "toolchain_lock",
            "resolved_configuration",
            "kernel_configuration",
            "trace_policy",
            "runtime_manifest",
            "model_manifest",
            "producer_source",
            "controller_source",
            "signer_public_policy",
        )
        for index, role in enumerate(roles):
            closure_data.append((f"{index:02d}-{role}.bin", role, "bytes", role.encode("ascii")))
        closure_data.append(("control-plan.json", "canonical_control_plan", "canonical_json", self.control_plan))
        closure_data.sort(key=lambda item: item[0])
        closure_inventory = []
        closure_root = root / "closure"
        for path, role, kind, payload in closure_data:
            _write(closure_root / path, payload)
            closure_inventory.append(
                {
                    "path": path,
                    "role": role,
                    "content_kind": kind,
                    "size_bytes": len(payload),
                    "sha256": _sha(payload),
                }
            )
        closure_object = {
            "schema": oracle.SCHEMA_INPUT_CLOSURE,
            "node_kind": oracle.KIND_INPUT_CLOSURE,
            "artifact_state": oracle.ARTIFACT_STATE,
            "inventory": closure_inventory,
        }
        closure_manifest = canonical_dumps(closure_object)
        self.input_closure_address = oracle.domain_address(oracle.DOMAIN_INPUT_CLOSURE, closure_object)
        self.closure_root = str(closure_root)
        self.closure_manifest_path = _write(root / "closure-manifest.json", closure_manifest)

        image_payloads = {
            "diagnostic.efi": oracle.build_uki(self.input_closure_address),
            "rootfs.img": b"rootfs",
            "rootfs.verity": b"verity",
            "verity-root-hash.bin": b"R" * 32,
            "signer-cert.der": b"\x30\x03\x02\x01\x00",
        }
        self.signed_paths = {
            name: _write(root / "signed" / name, payload) for name, payload in image_payloads.items()
        }
        image_members = {
            name: {"size_bytes": len(payload), "sha256": _sha(payload)}
            for name, payload in image_payloads.items()
        }
        self.image_binding_address = oracle.domain_address(
            oracle.DOMAIN_IMAGE_BINDING,
            {
                "schema": oracle.SCHEMA_SIGNED_IMAGE,
                "node_kind": oracle.KIND_SIGNED_IMAGE,
                "artifact_state": oracle.ARTIFACT_STATE,
                "layout": oracle.LAYOUT_IMAGE,
                "input_closure_address": self.input_closure_address,
                "members": {name: image_members[name] for name in sorted(image_members)},
            },
        )
        self.amd = mapper.SppDiagPinnedAmdEvidence(
            ark_pem=b"-----BEGIN CERTIFICATE-----\nARK\n-----END CERTIFICATE-----\n",
            ask_pem=b"-----BEGIN CERTIFICATE-----\nASK\n-----END CERTIFICATE-----\n",
            vcek_pem=b"-----BEGIN CERTIFICATE-----\nVCEK\n-----END CERTIFICATE-----\n",
            ark_crl_der=b"literal-crl",
        )
        bundle_expectations = CallerExpectations(
            input_closure_address=self.input_closure_address,
            challenge=self.challenge.hex(),
            run_identity=self.run_identity.hex(),
            target_profile_id=self.target_profile,
            control_plan_address=self.control_plan_address,
        )
        trace_expectations = SppDiagTraceCheckpointExpectations(
            source_commit=bytes(20),
            challenge=self.challenge,
            run_identity=self.run_identity,
            control_plan_address=bytes.fromhex(self.control_plan_address),
            command_line_sha256=bytes(32),
        )
        policy = mapper.SppDiagAttestationPolicy(
            appraisal_unix=1,
            ark_der_sha256=bytes(32),
            ask_der_sha256=bytes(32),
            ark_crl_der_sha256=hashlib.sha256(self.amd.ark_crl_der).digest(),
            ak_parent_qualified_name=bytes(34),
            snp_report_version=2,
            snp_policy=0,
            snp_vmpl=0,
            snp_measurement=bytes(48),
            snp_host_data=bytes(32),
            minimum_tcb=SppDiagTcbFloor(0, 0, 0, 0),
            vcek_product_name=b"Milan-B0",
            cpuid_family=25,
            cpuid_model=1,
            cpuid_step=1,
            baseline_pcrs=tuple(),
        )
        self.expectations = mapper.SppDiagMapperExpectations(
            bundle=bundle_expectations,
            trace_checkpoints=trace_expectations,
            attestation=policy,
            output_oracle_preimage=self.output_oracle_preimage,
        )
        self.inner_receipt_digest = ""
        self.capture = self.make_capture()

    def make_capture(
        self,
        *,
        raw_changes: dict[str, bytes] | None = None,
        digest_changes: dict[str, bytes] | None = None,
        quote_pcrs: bytes | None = None,
    ):
        raw = {
            "firmware-event-log.bin": self.firmware,
            "ima-measurements.bin": self.ima,
            "gpu-evidence.tlv": self.gpu,
        }
        raw.update(raw_changes or {})
        inner = {
            "ak-tpmt-public.bin": self.ak_tpmt,
            "firmware-event-log.sha256": hashlib.sha256(self.firmware).digest(),
            "gpu-evidence.sha256": hashlib.sha256(self.gpu).digest(),
            "ima-measurements.sha256": hashlib.sha256(self.ima).digest(),
            "synthetic-output.bin": self.output,
            "trace.bin": self.trace,
            "terminal-frame.bin": oracle.TERMINAL_FRAME_PREFIX + self.challenge + self.run_identity,
        }
        inner.update(digest_changes or {})
        ordered = sorted(name for name in inner if name != "terminal-frame.bin") + ["terminal-frame.bin"]
        inventory = [
            {
                "path": name,
                "content_kind": "bytes",
                "size_bytes": len(inner[name]),
                "sha256": _sha(inner[name]),
            }
            for name in ordered
        ]
        receipt_object = {
            "schema": oracle.SCHEMA_INNER_RECEIPT,
            "node_kind": oracle.KIND_INNER_RECEIPT,
            "artifact_state": oracle.ARTIFACT_STATE,
            "challenge": self.challenge.hex(),
            "run_identity": self.run_identity.hex(),
            "signed_image_binding_address": self.image_binding_address,
            "target_profile_id": self.target_profile,
            "control_plan_address": self.control_plan_address,
            "inventory": inventory,
        }
        self.inner_receipt_digest = oracle.domain_address(oracle.DOMAIN_INNER_RECEIPT, receipt_object)
        export_members = {
            "ak-public.pem": self.ak_pem,
            "firmware-event-log.bin": raw["firmware-event-log.bin"],
            "gpu-evidence.tlv": raw["gpu-evidence.tlv"],
            "hcla.bin": self.hcla,
            "ima-measurements.bin": raw["ima-measurements.bin"],
            **{"inner-receipt/" + name: inner[name] for name in inner},
            "inner-receipt/manifest.json": canonical_dumps(receipt_object),
            "quote.msg": self.quote_msg,
            "quote.pcrs": self.quote_pcrs if quote_pcrs is None else quote_pcrs,
            "quote.sig": self.quote_sig,
        }
        stream = build_export_stream(
            members=export_members,
            challenge=self.challenge,
            run_identity=self.run_identity,
        )
        chunks = [stream, b""]
        return capture_diagnostic_uart(
            lambda maximum, deadline: chunks.pop(0),
            lambda: 0.0,
            expected_challenge=self.challenge,
            expected_run_identity=self.run_identity,
        )

    def run(self, destination: Path, *, capture=None, expectations=None, appraisers=None):
        return mapper._assemble_and_appraise_spp_diagnostic(
            captured=self.capture if capture is None else capture,
            input_closure_manifest_path=self.closure_manifest_path,
            input_closure_root=self.closure_root,
            signed_image_paths=self.signed_paths,
            amd=self.amd,
            expectations=self.expectations if expectations is None else expectations,
            destination=str(destination),
            appraisers=appraisers if appraisers is not None else _AppraiserRecorder(self).table(),
        )


def _expect_reason(reason: str, operation) -> None:
    try:
        operation()
    except SppDiagMapperError as error:
        assert error.reason_code == reason, (error.reason_code, reason)
    else:
        raise AssertionError("expected mapper failure")


def test_closed_fanout_and_appraiser_inputs() -> None:
    with tempfile.TemporaryDirectory() as work:
        fixture = _Fixture(Path(work))
        recorder = _AppraiserRecorder(fixture)
        destination = Path(work) / "final.sppdbn"
        result = fixture.run(destination, appraisers=recorder.table())
        assert result.status == "diagnostic_appraised"
        assert destination.exists() and stat.S_IMODE(destination.stat().st_mode) == 0o400
        assert result.bundle_size_bytes == destination.stat().st_size
        assert result.bundle_sha256 == _sha(destination.read_bytes())
        assert result.input_closure_address == fixture.input_closure_address
        assert result.image_binding_address == fixture.image_binding_address
        assert result.inner_receipt_digest == fixture.inner_receipt_digest
        assert result.control_plan_address == fixture.control_plan_address
        assert result.ima_replay is recorder.ima_result
        assert result.trace_checkpoints is recorder.checkpoint_result
        assert result.trace_ledger == b"trace-ledger"
        assert result.attestation is recorder.attestation_result
        assert recorder.calls == ["ima", "checkpoints", "semantics", "attestation"]
        with capture_bundle(str(destination)) as bundle:
            addresses = inspect_diagnostic_members(bundle, fixture.expectations.bundle)
            assert addresses["inner_receipt_digest"] == fixture.inner_receipt_digest
            assert bundle.members["snp-vcek.pem"].read_all(4096) == fixture.amd.vcek_pem
            assert bundle.members["snp-cert-chain.pem"].read_all(4096) == (
                fixture.amd.ask_pem + fixture.amd.ark_pem
            )
            assert "ark-crl.der" not in bundle.members
            assert bundle.members["inner-receipt/trace.bin"].read_all(4096) == fixture.trace
        assert not list(Path(work).glob(".final.sppdbn.staging.*"))


def test_both_splice_directions_reject_for_all_raw_seams() -> None:
    with tempfile.TemporaryDirectory() as work:
        fixture = _Fixture(Path(work))
        seams = (
            ("firmware-event-log.bin", "firmware-event-log.sha256"),
            ("ima-measurements.bin", "ima-measurements.sha256"),
            ("gpu-evidence.tlv", "gpu-evidence.sha256"),
        )
        for index, (raw_name, digest_name) in enumerate(seams):
            changed_raw = fixture.make_capture(raw_changes={raw_name: b"changed-raw-" + bytes([index])})
            destination = Path(work) / f"raw-{index}.sppdbn"
            _expect_reason(CP_SPP_DIAG_MAPPER_SEAM, lambda: fixture.run(destination, capture=changed_raw))
            assert not destination.exists()

            changed_digest = fixture.make_capture(digest_changes={digest_name: bytes([index + 1]) * 32})
            destination = Path(work) / f"digest-{index}.sppdbn"
            _expect_reason(CP_SPP_DIAG_MAPPER_SEAM, lambda: fixture.run(destination, capture=changed_digest))
            assert not destination.exists()


def test_output_oracle_quote_pcr_and_publication_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as work:
        fixture = _Fixture(Path(work))
        wrong_output = fixture.make_capture(
            digest_changes={"synthetic-output.bin": b"wrong"}
        )
        destination = Path(work) / "output.sppdbn"
        _expect_reason(
            CP_SPP_DIAG_MAPPER_OUTPUT,
            lambda: fixture.run(destination, capture=wrong_output),
        )
        assert not destination.exists()

        wrong_plan_preimage = canonical_dumps(
            {
                **canonical_loads(fixture.output_oracle_preimage),
                "expected_result": "aa" * 32,
            }
        )
        wrong_oracle = dataclasses.replace(
            fixture.expectations,
            output_oracle_preimage=wrong_plan_preimage,
        )
        destination = Path(work) / "oracle.sppdbn"
        _expect_reason(
            CP_SPP_DIAG_MAPPER_OUTPUT,
            lambda: fixture.run(destination, expectations=wrong_oracle),
        )
        assert not destination.exists()

        truncated_pcrs = fixture.make_capture(quote_pcrs=fixture.quote_pcrs[:-1])
        destination = Path(work) / "pcr.sppdbn"
        _expect_reason(CP_SPP_DIAG_MAPPER_PCR, lambda: fixture.run(destination, capture=truncated_pcrs))
        assert not destination.exists()
        assert not list(Path(work).glob(".*.staging.*"))

        destination = Path(work) / "exists.sppdbn"
        destination.write_bytes(b"do-not-replace")
        _expect_reason(CP_SPP_DIAG_MAPPER_PUBLISH, lambda: fixture.run(destination))
        assert destination.read_bytes() == b"do-not-replace"


def test_failure_capture_and_appraiser_failure_never_publish() -> None:
    with tempfile.TemporaryDirectory() as work:
        fixture = _Fixture(Path(work))
        rejected = dataclasses.replace(fixture.capture, status="failure_terminal")
        destination = Path(work) / "failure.sppdbn"
        _expect_reason(mapper.CP_SPP_DIAG_MAPPER_TYPE, lambda: fixture.run(destination, capture=rejected))
        assert not destination.exists()

        recorder = _AppraiserRecorder(fixture)

        def reject_semantics(plan: bytes, trace: bytes) -> bytes:
            del plan, trace
            raise RuntimeError("trace-rejected")

        appraisers = mapper._Appraisers(recorder.replay, recorder.bind, reject_semantics, recorder.attest)
        destination = Path(work) / "appraiser.sppdbn"
        try:
            fixture.run(destination, appraisers=appraisers)
        except RuntimeError as error:
            assert str(error) == "trace-rejected"
        else:
            raise AssertionError("expected appraiser failure")
        assert not destination.exists()
        assert not list(Path(work).glob(".appraiser.sppdbn.staging.*"))


TESTS = (
    test_closed_fanout_and_appraiser_inputs,
    test_both_splice_directions_reject_for_all_raw_seams,
    test_output_oracle_quote_pcr_and_publication_fail_closed,
    test_failure_capture_and_appraiser_failure_never_publish,
)


def main() -> None:
    for test in TESTS:
        test()
        print("ok  ", test.__name__)
    print("SPP diagnostic off-box mapper: ok (%d tests)" % len(TESTS))


if __name__ == "__main__":
    main()
