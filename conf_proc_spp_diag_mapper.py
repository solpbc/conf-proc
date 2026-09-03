#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Closed off-box fan-out, appraisal, and publication for SPP diagnostics."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import io
import os
import posixpath
import stat
import struct
import unicodedata
from dataclasses import dataclass
from typing import Callable, Final

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_spp_diag_attest import (
    SppDiagAttestation,
    SppDiagAttestationEvidence,
    SppDiagAttestationExpectations,
    SppDiagTcbFloor,
    appraise_spp_diag_attestation,
)
from conf_proc_spp_diag_capture import CapturedDiagnostic, SUCCESS_STATUS
from conf_proc_spp_diag_export import parse_export_stream
from conf_proc_spp_diag_ima import SppDiagImaReplay, replay_spp_diag_ima_pcr10
from conf_proc_spp_diag_mapper_reasons import (
    CP_SPP_DIAG_MAPPER_OUTPUT,
    CP_SPP_DIAG_MAPPER_PCR,
    CP_SPP_DIAG_MAPPER_PUBLISH,
    CP_SPP_DIAG_MAPPER_SEAM,
    CP_SPP_DIAG_MAPPER_SOURCE,
    CP_SPP_DIAG_MAPPER_TYPE,
    SppDiagMapperError,
)
from conf_proc_spp_diag_pcr import QUOTE_PCR_BITMAP, SPP_DIAG_PCR_SELECTION
from conf_proc_spp_diag_trace_checkpoints import (
    SppDiagTraceCheckpointBinding,
    SppDiagTraceCheckpointExpectations,
    SppDiagTraceCheckpointInput,
    bind_spp_diag_trace_checkpoints,
)
from conf_proc_spp_diag_trace_semantics import appraise_spp_diag_trace_semantics
from conf_proc_spp_diagbundle import (
    CallerExpectations,
    INNER_RECEIPT_SCHEMA_ID,
    NODE_ARTIFACT_STATE,
    NODE_KIND_INNER_RECEIPT,
    NODE_KIND_SIGNED_IMAGE,
    OUTER_ENVELOPE_LAYOUT,
    OUTER_ENVELOPE_SCHEMA_ID,
    SIGNED_IMAGE_LAYOUT,
    SIGNED_IMAGE_MEMBER_NAMES,
    SIGNED_IMAGE_SCHEMA_ID,
    inspect_diagnostic_members,
    parse_inner_receipt_manifest,
    parse_input_closure_manifest,
)
from conf_proc_spp_diagbundle_pe import extract_sppdiag_descriptor
from conf_proc_spp_diagbundle_protocol import (
    DOMAIN_CONTROL_PLAN,
    DOMAIN_INPUT_CLOSURE,
    domain_address,
    image_binding_address,
    inner_receipt_digest,
    quote_qualifying_data,
)
from conf_proc_spp_diagbundle_stream import (
    MAX_CAPTURE_BYTES,
    MAX_MEMBERS,
    MAX_PATH_BYTES,
    STREAM_MAGIC,
    STREAM_VERSION,
    capture_bundle,
)


_HEADER: Final = struct.Struct(">8sII")
_RECORD: Final = struct.Struct(">HQ32s")
_CHUNK_BYTES: Final = 1024 * 1024
_RENAME_NOREPLACE: Final = 1
_OUTPUT_ORACLE_DOMAIN: Final = b"sol-spp-diag-output-oracle-v1\0"
_INPUT_SEED_DOMAIN: Final = b"sol-spp-diag-input-seed-v1\0"
_OUTPUT_ORACLE_KEYS: Final = frozenset(
    {
        "algorithm_id",
        "challenge",
        "cuda_child_sha256",
        "deterministic_seed",
        "expected_result",
        "model_sha256",
        "model_size_bytes",
        "ptx_sha256",
        "run_identity",
        "schema",
    }
)
_OPEN_FLAGS: Final = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
_OUTER_FILE_CAPS: Final = {
    "ak-public.pem": 1024 * 1024,
    "quote.msg": 64 * 1024,
    "quote.sig": 16 * 1024,
    "quote.pcrs": 1024 * 1024,
    "hcla.bin": 16 * 1024 * 1024,
    "snp-vcek.pem": 4 * 1024 * 1024,
    "snp-cert-chain.pem": 4 * 1024 * 1024,
    "firmware-event-log.bin": 512 * 1024 * 1024,
    "ima-measurements.bin": 16 * 1024**3,
    "gpu-evidence.tlv": 4 * 1024**3,
}
_SIGNED_IMAGE_CAPS: Final = {
    "diagnostic.efi": 1024**3,
    "rootfs.img": 64 * 1024**3,
    "rootfs.verity": 8 * 1024**3,
    "verity-root-hash.bin": 128,
    "signer-cert.der": 1024 * 1024,
}
_INNER_PAYLOAD_NAMES: Final = (
    "ak-tpmt-public.bin",
    "firmware-event-log.sha256",
    "gpu-evidence.sha256",
    "ima-measurements.sha256",
    "synthetic-output.bin",
    "trace.bin",
    "terminal-frame.bin",
)
_OUTER_UART_NAMES: Final = (
    "ak-public.pem",
    "quote.msg",
    "quote.sig",
    "quote.pcrs",
    "hcla.bin",
    "firmware-event-log.bin",
    "ima-measurements.bin",
    "gpu-evidence.tlv",
)


@dataclass(frozen=True)
class SppDiagPinnedAmdEvidence:
    ark_pem: bytes
    ask_pem: bytes
    vcek_pem: bytes
    ark_crl_der: bytes


@dataclass(frozen=True)
class SppDiagAttestationPolicy:
    appraisal_unix: int
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

    def bind(self, quote_extra_data: bytes, ima_pcr10: bytes) -> SppDiagAttestationExpectations:
        return SppDiagAttestationExpectations(
            appraisal_unix=self.appraisal_unix,
            quote_extra_data=quote_extra_data,
            ark_der_sha256=self.ark_der_sha256,
            ask_der_sha256=self.ask_der_sha256,
            ark_crl_der_sha256=self.ark_crl_der_sha256,
            ak_parent_qualified_name=self.ak_parent_qualified_name,
            snp_report_version=self.snp_report_version,
            snp_policy=self.snp_policy,
            snp_vmpl=self.snp_vmpl,
            snp_measurement=self.snp_measurement,
            snp_host_data=self.snp_host_data,
            minimum_tcb=self.minimum_tcb,
            vcek_product_name=self.vcek_product_name,
            cpuid_family=self.cpuid_family,
            cpuid_model=self.cpuid_model,
            cpuid_step=self.cpuid_step,
            baseline_pcrs=self.baseline_pcrs,
            ima_pcr10=ima_pcr10,
        )


@dataclass(frozen=True)
class SppDiagMapperExpectations:
    bundle: CallerExpectations
    trace_checkpoints: SppDiagTraceCheckpointExpectations
    attestation: SppDiagAttestationPolicy
    output_oracle_preimage: bytes


@dataclass(frozen=True)
class SppDiagMappedAppraisal:
    status: str
    destination: str
    bundle_size_bytes: int
    bundle_sha256: str
    outer_envelope_address: str
    inner_receipt_digest: str
    image_binding_address: str
    input_closure_address: str
    control_plan_address: str
    ima_replay: SppDiagImaReplay
    trace_checkpoints: SppDiagTraceCheckpointBinding
    trace_ledger: bytes
    attestation: SppDiagAttestation


@dataclass(frozen=True)
class _Appraisers:
    replay_ima: Callable[..., SppDiagImaReplay]
    bind_checkpoints: Callable[..., SppDiagTraceCheckpointBinding]
    trace_semantics: Callable[[bytes, bytes], bytes]
    attestation: Callable[..., SppDiagAttestation]


_PRODUCTION_APPRAISERS: Final = _Appraisers(
    replay_ima=replay_spp_diag_ima_pcr10,
    bind_checkpoints=bind_spp_diag_trace_checkpoints,
    trace_semantics=appraise_spp_diag_trace_semantics,
    attestation=appraise_spp_diag_attestation,
)


@dataclass
class _FileSnapshot:
    path: str
    descriptor: int
    identity: tuple[int, int, int, int, int, int, int]
    size_bytes: int
    sha256: str

    def close(self) -> None:
        if self.descriptor >= 0:
            try:
                os.close(self.descriptor)
            except OSError:
                pass
            self.descriptor = -1

    def read_all(self, maximum: int) -> bytes:
        if self.size_bytes > maximum:
            _fail(CP_SPP_DIAG_MAPPER_SOURCE)
        try:
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(self.descriptor, min(_CHUNK_BYTES, maximum - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    _fail(CP_SPP_DIAG_MAPPER_SOURCE)
                digest.update(chunk)
                chunks.append(chunk)
            if total != self.size_bytes or not hmac.compare_digest(digest.hexdigest(), self.sha256):
                _fail(CP_SPP_DIAG_MAPPER_SOURCE)
            return b"".join(chunks)
        except SppDiagMapperError:
            raise
        except OSError as exc:
            raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_SOURCE) from exc

    def read_range(self, offset: int, length: int) -> bytes:
        if type(offset) is not int or type(length) is not int or offset < 0 or length < 0:
            _fail(CP_SPP_DIAG_MAPPER_SOURCE)
        if offset > self.size_bytes or length > self.size_bytes - offset:
            _fail(CP_SPP_DIAG_MAPPER_SOURCE)
        try:
            data = os.pread(self.descriptor, length, offset)
        except OSError as exc:
            raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_SOURCE) from exc
        if len(data) != length:
            _fail(CP_SPP_DIAG_MAPPER_SOURCE)
        return data

    def copy_to(self, destination_fd: int, bundle_digest: object) -> int:
        try:
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            payload_digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(self.descriptor, _CHUNK_BYTES)
                if not chunk:
                    break
                _write_all(destination_fd, chunk)
                bundle_digest.update(chunk)
                payload_digest.update(chunk)
                total += len(chunk)
            if (
                total != self.size_bytes
                or not hmac.compare_digest(payload_digest.hexdigest(), self.sha256)
                or _identity(os.fstat(self.descriptor)) != self.identity
            ):
                _fail(CP_SPP_DIAG_MAPPER_SOURCE)
            return total
        except SppDiagMapperError:
            raise
        except OSError as exc:
            raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_SOURCE) from exc


def assemble_and_appraise_spp_diagnostic(
    *,
    captured: CapturedDiagnostic,
    input_closure_manifest_path: str,
    input_closure_root: str,
    signed_image_paths: dict[str, str],
    amd: SppDiagPinnedAmdEvidence,
    expectations: SppDiagMapperExpectations,
    destination: str,
) -> SppDiagMappedAppraisal:
    """Map one successful UART capture into an appraised, no-replace bundle."""

    return _assemble_and_appraise_spp_diagnostic(
        captured=captured,
        input_closure_manifest_path=input_closure_manifest_path,
        input_closure_root=input_closure_root,
        signed_image_paths=signed_image_paths,
        amd=amd,
        expectations=expectations,
        destination=destination,
        appraisers=_PRODUCTION_APPRAISERS,
    )


def _assemble_and_appraise_spp_diagnostic(
    *,
    captured: CapturedDiagnostic,
    input_closure_manifest_path: str,
    input_closure_root: str,
    signed_image_paths: dict[str, str],
    amd: SppDiagPinnedAmdEvidence,
    expectations: SppDiagMapperExpectations,
    destination: str,
    appraisers: _Appraisers,
) -> SppDiagMappedAppraisal:
    snapshots: list[_FileSnapshot] = []
    parent_fd = -1
    staging_name: str | None = None
    try:
        _validate_top_level(
            captured,
            input_closure_manifest_path,
            input_closure_root,
            signed_image_paths,
            amd,
            expectations,
            destination,
            appraisers,
        )
        bundle_expectations = expectations.bundle
        challenge = bytes.fromhex(bundle_expectations.challenge)
        run_identity = bytes.fromhex(bundle_expectations.run_identity)
        if captured.status != SUCCESS_STATUS or captured.failure is not None:
            _fail(CP_SPP_DIAG_MAPPER_TYPE)
        exported = parse_export_stream(
            captured.stream,
            expected_challenge=challenge,
            expected_run_identity=run_identity,
        )
        uart = {member.name: member.payload for member in exported.members[:-1]}

        manifest_snapshot = _open_snapshot(input_closure_manifest_path, 4 * 1024 * 1024)
        snapshots.append(manifest_snapshot)
        closure_manifest_bytes = manifest_snapshot.read_all(4 * 1024 * 1024)
        closure_manifest = parse_input_closure_manifest(closure_manifest_bytes)
        if any(row.path == "manifest.json" for row in closure_manifest.inventory):
            _fail(CP_SPP_DIAG_MAPPER_SEAM)
        closure_object = canonical_loads(closure_manifest_bytes)
        input_address = domain_address(DOMAIN_INPUT_CLOSURE, closure_object)
        if not _hex_equal(input_address, bundle_expectations.input_closure_address):
            _fail(CP_SPP_DIAG_MAPPER_SEAM)

        closure_sources: dict[str, _FileSnapshot] = {}
        closure_total = 0
        if len(closure_manifest.inventory) > 4096:
            _fail(CP_SPP_DIAG_MAPPER_SOURCE)
        for row in closure_manifest.inventory:
            source = _open_snapshot(os.path.join(input_closure_root, row.path), 64 * 1024**3)
            snapshots.append(source)
            if source.size_bytes != row.size_bytes or not _hex_equal(source.sha256, row.sha256):
                _fail(CP_SPP_DIAG_MAPPER_SOURCE)
            closure_total += source.size_bytes
            if closure_total > 256 * 1024**3:
                _fail(CP_SPP_DIAG_MAPPER_SOURCE)
            closure_sources[row.path] = source
        control_plan = closure_sources["control-plan.json"].read_all(4 * 1024 * 1024)
        canonical_loads(control_plan)
        control_plan_address = hashlib.sha256(DOMAIN_CONTROL_PLAN + control_plan).hexdigest()
        if not _hex_equal(control_plan_address, bundle_expectations.control_plan_address):
            _fail(CP_SPP_DIAG_MAPPER_SEAM)
        expected_output = _expected_output_from_oracle(
            control_plan,
            expectations.output_oracle_preimage,
            bundle_expectations.challenge,
            bundle_expectations.run_identity,
        )

        image_sources: dict[str, _FileSnapshot] = {}
        image_members: dict[str, dict[str, object]] = {}
        for name in SIGNED_IMAGE_MEMBER_NAMES:
            source = _open_snapshot(signed_image_paths[name], _SIGNED_IMAGE_CAPS[name])
            snapshots.append(source)
            image_sources[name] = source
            image_members[name] = {"size_bytes": source.size_bytes, "sha256": source.sha256}
        descriptor = extract_sppdiag_descriptor(image_sources["diagnostic.efi"])
        if not _hex_equal(descriptor.input_closure_address, input_address):
            _fail(CP_SPP_DIAG_MAPPER_SEAM)
        image_binding = image_binding_address(
            schema=SIGNED_IMAGE_SCHEMA_ID,
            node_kind=NODE_KIND_SIGNED_IMAGE,
            artifact_state=NODE_ARTIFACT_STATE,
            layout=SIGNED_IMAGE_LAYOUT,
            input_closure_address=input_address,
            members={name: image_members[name] for name in sorted(image_members)},
        )
        image_manifest_bytes = canonical_dumps(
            {
                "schema": SIGNED_IMAGE_SCHEMA_ID,
                "node_kind": NODE_KIND_SIGNED_IMAGE,
                "artifact_state": NODE_ARTIFACT_STATE,
                "layout": SIGNED_IMAGE_LAYOUT,
                "input_closure_address": input_address,
                "members": image_members,
            }
        )

        receipt_bytes = uart["inner-receipt/manifest.json"]
        receipt = parse_inner_receipt_manifest(receipt_bytes)
        if tuple(row.path for row in receipt.inventory) != _INNER_PAYLOAD_NAMES:
            _fail(CP_SPP_DIAG_MAPPER_SEAM)
        actual_inventory: list[dict[str, object]] = []
        for row in receipt.inventory:
            payload = uart["inner-receipt/" + row.path]
            digest = hashlib.sha256(payload).hexdigest()
            if len(payload) != row.size_bytes or not _hex_equal(digest, row.sha256):
                _fail(CP_SPP_DIAG_MAPPER_SEAM)
            actual_inventory.append(
                {
                    "path": row.path,
                    "content_kind": row.content_kind,
                    "size_bytes": len(payload),
                    "sha256": digest,
                }
            )
        if (
            receipt.schema != INNER_RECEIPT_SCHEMA_ID
            or receipt.node_kind != NODE_KIND_INNER_RECEIPT
            or receipt.artifact_state != NODE_ARTIFACT_STATE
            or not _hex_equal(receipt.challenge, bundle_expectations.challenge)
            or not _hex_equal(receipt.run_identity, bundle_expectations.run_identity)
            or receipt.target_profile_id != bundle_expectations.target_profile_id
            or not _hex_equal(receipt.control_plan_address, control_plan_address)
            or not _hex_equal(receipt.signed_image_binding_address, image_binding)
        ):
            _fail(CP_SPP_DIAG_MAPPER_SEAM)
        receipt_digest = inner_receipt_digest(
            schema=receipt.schema,
            node_kind=receipt.node_kind,
            artifact_state=receipt.artifact_state,
            challenge=receipt.challenge,
            run_identity=receipt.run_identity,
            signed_image_binding_address=receipt.signed_image_binding_address,
            target_profile_id=receipt.target_profile_id,
            control_plan_address=receipt.control_plan_address,
            inventory=actual_inventory,
        )
        _require_raw_digest(uart, "firmware-event-log.bin")
        _require_raw_digest(uart, "ima-measurements.bin")
        _require_raw_digest(uart, "gpu-evidence.tlv")
        if not hmac.compare_digest(
            uart["inner-receipt/synthetic-output.bin"], expected_output
        ):
            _fail(CP_SPP_DIAG_MAPPER_OUTPUT)

        quote_extra = quote_qualifying_data(
            challenge=bundle_expectations.challenge,
            control_plan_address=control_plan_address,
            inner_receipt_digest=receipt_digest,
            run_identity=bundle_expectations.run_identity,
            signed_image_binding_address=image_binding,
            target_profile_id=bundle_expectations.target_profile_id,
        )
        outer_payloads: dict[str, bytes] = {name: uart[name] for name in _OUTER_UART_NAMES}
        outer_payloads["snp-vcek.pem"] = amd.vcek_pem
        outer_payloads["snp-cert-chain.pem"] = amd.ask_pem + amd.ark_pem
        outer_members: dict[str, object] = {"inner-receipt": {"digest": receipt_digest}}
        for name, payload in outer_payloads.items():
            if len(payload) > _OUTER_FILE_CAPS[name]:
                _fail(CP_SPP_DIAG_MAPPER_SOURCE)
            outer_members[name] = {
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        outer_manifest = canonical_dumps(
            {
                "schema": OUTER_ENVELOPE_SCHEMA_ID,
                "node_kind": "outer_envelope",
                "artifact_state": NODE_ARTIFACT_STATE,
                "layout": OUTER_ENVELOPE_LAYOUT,
                "inner_receipt_digest": receipt_digest,
                "quote_extra_data": quote_extra,
                "members": outer_members,
            }
        )

        members: dict[str, bytes | _FileSnapshot] = {
            "manifest.json": outer_manifest,
            "input-closure/manifest.json": manifest_snapshot,
            "signed-image/manifest.json": image_manifest_bytes,
            "inner-receipt/manifest.json": receipt_bytes,
        }
        members.update({"input-closure/" + name: source for name, source in closure_sources.items()})
        members.update({"signed-image/" + name: source for name, source in image_sources.items()})
        members.update(
            {
                "inner-receipt/" + name: uart["inner-receipt/" + name]
                for name in _INNER_PAYLOAD_NAMES
            }
        )
        members.update(outer_payloads)

        parent, final_name = _destination_parts(destination)
        parent_before, parent_fd = _open_parent(parent)
        staging_name, staging_fd = _create_staging(parent_fd, final_name)
        try:
            bundle_size, bundle_sha256 = _write_bundle(staging_fd, members)
            os.fchmod(staging_fd, stat.S_IRUSR)
            os.fsync(staging_fd)
        except OSError as exc:
            raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_PUBLISH) from exc
        finally:
            try:
                os.close(staging_fd)
            except OSError:
                pass

        staging_path = f"/proc/self/fd/{parent_fd}/{staging_name}"
        with capture_bundle(staging_path) as final_bundle:
            addresses = inspect_diagnostic_members(final_bundle, bundle_expectations)

        quoted_pcr10 = _extract_quote_pcr10(uart["quote.pcrs"])
        ima = appraisers.replay_ima(
            io.BytesIO(uart["ima-measurements.bin"]),
            len(uart["ima-measurements.bin"]),
            quoted_pcr10,
        )
        checkpoint_inputs = tuple(
            SppDiagTraceCheckpointInput(event_name=item.event_name, record=item.record)
            for item in ima.checkpoints
        )
        trace = uart["inner-receipt/trace.bin"]
        checkpoints = appraisers.bind_checkpoints(
            io.BytesIO(trace), len(trace), checkpoint_inputs, expectations.trace_checkpoints
        )
        trace_ledger = appraisers.trace_semantics(control_plan, trace)
        attest_expectations = expectations.attestation.bind(bytes.fromhex(quote_extra), ima.final_pcr10_sha256)
        attestation = appraisers.attestation(
            SppDiagAttestationEvidence(
                ark_pem=amd.ark_pem,
                ask_pem=amd.ask_pem,
                vcek_pem=amd.vcek_pem,
                ark_crl_der=amd.ark_crl_der,
                ak_public_pem=uart["ak-public.pem"],
                ak_tpmt_public=uart["inner-receipt/ak-tpmt-public.bin"],
                hcl_report=uart["hcla.bin"],
                quote_msg=uart["quote.msg"],
                quote_sig=uart["quote.sig"],
                quote_pcrs=uart["quote.pcrs"],
            ),
            attest_expectations,
        )

        if not _parent_is_same(parent, parent_before):
            _fail(CP_SPP_DIAG_MAPPER_PUBLISH)
        _rename_noreplace_at(parent_fd, staging_name, final_name)
        staging_name = None
        _fsync_parent(parent_fd)
        return SppDiagMappedAppraisal(
            status="diagnostic_appraised",
            destination=destination,
            bundle_size_bytes=bundle_size,
            bundle_sha256=bundle_sha256,
            outer_envelope_address=addresses["outer_envelope_address"],
            inner_receipt_digest=addresses["inner_receipt_digest"],
            image_binding_address=addresses["image_binding_address"],
            input_closure_address=addresses["input_closure_address"],
            control_plan_address=addresses["control_plan_address"],
            ima_replay=ima,
            trace_checkpoints=checkpoints,
            trace_ledger=trace_ledger,
            attestation=attestation,
        )
    except SppDiagMapperError:
        raise
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_SOURCE) from exc
    finally:
        if staging_name is not None and parent_fd >= 0:
            try:
                os.unlink(staging_name, dir_fd=parent_fd)
            except OSError:
                pass
        if parent_fd >= 0:
            try:
                os.close(parent_fd)
            except OSError:
                pass
        for source in snapshots:
            source.close()


def _validate_top_level(
    captured: object,
    input_closure_manifest_path: object,
    input_closure_root: object,
    signed_image_paths: object,
    amd: object,
    expectations: object,
    destination: object,
    appraisers: object,
) -> None:
    if (
        type(captured) is not CapturedDiagnostic
        or type(input_closure_manifest_path) is not str
        or type(input_closure_root) is not str
        or type(signed_image_paths) is not dict
        or set(signed_image_paths) != set(SIGNED_IMAGE_MEMBER_NAMES)
        or any(type(value) is not str for value in signed_image_paths.values())
        or type(amd) is not SppDiagPinnedAmdEvidence
        or any(
            type(getattr(amd, name)) is not bytes
            for name in ("ark_pem", "ask_pem", "vcek_pem", "ark_crl_der")
        )
        or type(expectations) is not SppDiagMapperExpectations
        or type(expectations.bundle) is not CallerExpectations
        or type(expectations.trace_checkpoints) is not SppDiagTraceCheckpointExpectations
        or type(expectations.attestation) is not SppDiagAttestationPolicy
        or type(expectations.output_oracle_preimage) is not bytes
        or type(destination) is not str
        or type(appraisers) is not _Appraisers
    ):
        _fail(CP_SPP_DIAG_MAPPER_TYPE)
    bundle = expectations.bundle
    if (
        not _is_sha256(bundle.input_closure_address)
        or not _is_sha256(bundle.challenge)
        or not _is_sha256(bundle.run_identity)
        or not _is_sha256(bundle.control_plan_address)
        or type(bundle.target_profile_id) is not str
        or not bundle.target_profile_id
    ):
        _fail(CP_SPP_DIAG_MAPPER_TYPE)
    trace = expectations.trace_checkpoints
    if (
        not hmac.compare_digest(trace.challenge, bytes.fromhex(bundle.challenge))
        or not hmac.compare_digest(trace.run_identity, bytes.fromhex(bundle.run_identity))
        or not hmac.compare_digest(trace.control_plan_address, bytes.fromhex(bundle.control_plan_address))
    ):
        _fail(CP_SPP_DIAG_MAPPER_SEAM)


def _open_snapshot(path: str, maximum: int) -> _FileSnapshot:
    descriptor = -1
    try:
        descriptor = os.open(path, _OPEN_FLAGS)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            _fail(CP_SPP_DIAG_MAPPER_SOURCE)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, _CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                _fail(CP_SPP_DIAG_MAPPER_SOURCE)
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _identity(after) != _identity(before) or total != before.st_size:
            _fail(CP_SPP_DIAG_MAPPER_SOURCE)
        return _FileSnapshot(path, descriptor, _identity(after), total, digest.hexdigest())
    except SppDiagMapperError:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_SOURCE) from exc


def _expected_output_from_oracle(
    control_plan: bytes,
    preimage: bytes,
    challenge: str,
    run_identity: str,
) -> bytes:
    try:
        plan = canonical_loads(control_plan)
        synthetic = plan["synthetic_inference"]
        plan_address = synthetic["output_oracle_address"]
        plan_model_sha256 = synthetic["model_sha256"]
        oracle = canonical_loads(preimage)
    except Exception as exc:
        raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_SEAM) from exc
    if type(oracle) is not dict or set(oracle) != _OUTPUT_ORACLE_KEYS:
        _fail(CP_SPP_DIAG_MAPPER_OUTPUT)
    digest_fields = (
        oracle["cuda_child_sha256"],
        oracle["deterministic_seed"],
        oracle["expected_result"],
        oracle["model_sha256"],
        oracle["ptx_sha256"],
    )
    if (
        oracle["schema"] != "sol-spp-diag-output-oracle-v1"
        or oracle["algorithm_id"] != "spp-diag-xor-stride32-v1"
        or oracle["challenge"] != challenge
        or oracle["run_identity"] != run_identity
        or any(not _is_sha256(value) for value in digest_fields)
        or type(oracle["model_size_bytes"]) is not int
        or not 1 <= oracle["model_size_bytes"] <= 8 * 1024 * 1024
        or not _hex_equal(oracle["model_sha256"], plan_model_sha256)
    ):
        _fail(CP_SPP_DIAG_MAPPER_OUTPUT)
    expected_seed = hashlib.sha256(
        _INPUT_SEED_DOMAIN + bytes.fromhex(challenge) + bytes.fromhex(run_identity)
    ).hexdigest()
    address = hashlib.sha256(_OUTPUT_ORACLE_DOMAIN + preimage).hexdigest()
    if not _hex_equal(oracle["deterministic_seed"], expected_seed) or not _hex_equal(address, plan_address):
        _fail(CP_SPP_DIAG_MAPPER_OUTPUT)
    return struct.pack(
        ">8sHHI32s",
        b"SPPGPUO1",
        1,
        1,
        32,
        bytes.fromhex(oracle["expected_result"]),
    )


def _require_raw_digest(uart: dict[str, bytes], raw_name: str) -> None:
    digest_name = "inner-receipt/" + raw_name.removesuffix(".bin").removesuffix(".tlv") + ".sha256"
    expected = uart[digest_name]
    if len(expected) != 32 or not hmac.compare_digest(hashlib.sha256(uart[raw_name]).digest(), expected):
        _fail(CP_SPP_DIAG_MAPPER_SEAM)


def _extract_quote_pcr10(data: bytes) -> bytes:
    if type(data) is not bytes:
        _fail(CP_SPP_DIAG_MAPPER_PCR)
    offset = 0

    def take(amount: int) -> bytes:
        nonlocal offset
        if amount < 0 or amount > len(data) - offset:
            _fail(CP_SPP_DIAG_MAPPER_PCR)
        result = data[offset : offset + amount]
        offset += amount
        return result

    def integer(amount: int) -> int:
        return int.from_bytes(take(amount), "little")

    if integer(4) != 1:
        _fail(CP_SPP_DIAG_MAPPER_PCR)
    for slot in range(8):
        algorithm = integer(2)
        size = integer(1)
        bitmap = take(8)
        padding = take(5)
        if slot == 0:
            if algorithm != 0x000B or size != 3 or bitmap[:3] != QUOTE_PCR_BITMAP or bitmap[3:] != bytes(5):
                _fail(CP_SPP_DIAG_MAPPER_PCR)
        elif algorithm != 0 or size != 0 or bitmap != bytes(8):
            _fail(CP_SPP_DIAG_MAPPER_PCR)
        if padding != bytes(5):
            _fail(CP_SPP_DIAG_MAPPER_PCR)
    if integer(4) != 2:
        _fail(CP_SPP_DIAG_MAPPER_PCR)
    digests: list[bytes] = []
    for expected_count in (8, 7):
        if integer(4) != expected_count:
            _fail(CP_SPP_DIAG_MAPPER_PCR)
        for slot in range(8):
            size = integer(2)
            value = take(64)
            if slot < expected_count:
                if size != 32 or value[32:] != bytes(32):
                    _fail(CP_SPP_DIAG_MAPPER_PCR)
                digests.append(value[:32])
            elif size != 0 or value != bytes(64):
                _fail(CP_SPP_DIAG_MAPPER_PCR)
    if offset != len(data) or len(digests) != len(SPP_DIAG_PCR_SELECTION):
        _fail(CP_SPP_DIAG_MAPPER_PCR)
    return dict(zip(SPP_DIAG_PCR_SELECTION, digests))[10]


def _write_bundle(descriptor: int, members: dict[str, bytes | _FileSnapshot]) -> tuple[int, str]:
    if not 1 <= len(members) <= MAX_MEMBERS:
        _fail(CP_SPP_DIAG_MAPPER_SOURCE)
    encoded_paths: list[tuple[bytes, str]] = []
    for path in members:
        path_bytes = _canonical_path(path)
        encoded_paths.append((path_bytes, path))
    encoded_paths.sort()
    digest = hashlib.sha256()
    total = 0

    def write(data: bytes) -> None:
        nonlocal total
        if len(data) > MAX_CAPTURE_BYTES - total:
            _fail(CP_SPP_DIAG_MAPPER_SOURCE)
        _write_all(descriptor, data)
        digest.update(data)
        total += len(data)

    write(_HEADER.pack(STREAM_MAGIC, STREAM_VERSION, len(encoded_paths)))
    for path_bytes, path in encoded_paths:
        payload = members[path]
        if type(payload) is bytes:
            payload_size = len(payload)
            payload_digest = hashlib.sha256(payload).digest()
        else:
            payload_size = payload.size_bytes
            payload_digest = bytes.fromhex(payload.sha256)
        write(_RECORD.pack(len(path_bytes), payload_size, payload_digest))
        write(path_bytes)
        if type(payload) is bytes:
            write(payload)
        else:
            if payload_size > MAX_CAPTURE_BYTES - total:
                _fail(CP_SPP_DIAG_MAPPER_SOURCE)
            copied = payload.copy_to(descriptor, digest)
            total += copied
    return total, digest.hexdigest()


def _canonical_path(path: object) -> bytes:
    if type(path) is not str or not path or path.startswith("/") or "\\" in path or "\x00" in path:
        _fail(CP_SPP_DIAG_MAPPER_SOURCE)
    if unicodedata.normalize("NFC", path) != path:
        _fail(CP_SPP_DIAG_MAPPER_SOURCE)
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts) or posixpath.normpath(path) != path:
        _fail(CP_SPP_DIAG_MAPPER_SOURCE)
    encoded = path.encode("utf-8", errors="strict")
    if len(encoded) > MAX_PATH_BYTES:
        _fail(CP_SPP_DIAG_MAPPER_SOURCE)
    return encoded


def _destination_parts(destination: str) -> tuple[str, str]:
    if not destination or destination.endswith(os.sep):
        _fail(CP_SPP_DIAG_MAPPER_PUBLISH)
    parent = os.path.dirname(destination) or "."
    name = os.path.basename(destination)
    if name in ("", ".", "..") or os.path.lexists(destination):
        _fail(CP_SPP_DIAG_MAPPER_PUBLISH)
    return parent, name


def _open_parent(parent: str) -> tuple[os.stat_result, int]:
    descriptor = -1
    try:
        before = os.stat(parent, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            _fail(CP_SPP_DIAG_MAPPER_PUBLISH)
        descriptor = os.open(
            parent,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        if _directory_identity(os.fstat(descriptor)) != _directory_identity(before):
            _fail(CP_SPP_DIAG_MAPPER_PUBLISH)
        return before, descriptor
    except SppDiagMapperError:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    except OSError as exc:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_PUBLISH) from exc


def _parent_is_same(parent: str, before: os.stat_result) -> bool:
    try:
        return _directory_identity(os.stat(parent, follow_symlinks=False)) == _directory_identity(before)
    except OSError as exc:
        raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_PUBLISH) from exc


def _fsync_parent(parent_fd: int) -> None:
    try:
        os.fsync(parent_fd)
    except OSError as exc:
        raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_PUBLISH) from exc


def _create_staging(parent_fd: int, final_name: str) -> tuple[str, int]:
    for _attempt in range(16):
        name = "." + final_name + ".staging." + os.urandom(8).hex()
        try:
            descriptor = os.open(
                name,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            return name, descriptor
        except FileExistsError:
            continue
        except OSError as exc:
            raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_PUBLISH) from exc
    _fail(CP_SPP_DIAG_MAPPER_PUBLISH)


def _rename_noreplace_at(parent_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        _fail(CP_SPP_DIAG_MAPPER_PUBLISH)
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if renameat2(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    ) != 0:
        number = ctypes.get_errno()
        raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_PUBLISH) from OSError(
            number or errno.EIO, os.strerror(number or errno.EIO), destination
        )


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(descriptor, data[offset:])
        except OSError as exc:
            raise SppDiagMapperError(CP_SPP_DIAG_MAPPER_PUBLISH) from exc
        if written <= 0:
            _fail(CP_SPP_DIAG_MAPPER_PUBLISH)
        offset += written


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _directory_identity(value: os.stat_result) -> tuple[int, int]:
    return (value.st_dev, value.st_ino)


def _hex_equal(left: object, right: object) -> bool:
    return type(left) is str and type(right) is str and hmac.compare_digest(left, right)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _fail(reason: str) -> None:
    raise SppDiagMapperError(reason)
