#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent diagnostic-bundle oracle: addresses, UKI bytes, and fixtures."""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass

from conf_proc_json import canonical_dumps, canonical_loads


DOMAIN_INPUT_CLOSURE = b"sol-spp-diagbundle-input-closure-v1\0"
DOMAIN_IMAGE_BINDING = b"sol-spp-diagbundle-image-binding-v1\0"
DOMAIN_INNER_RECEIPT = b"sol-spp-diagbundle-inner-receipt-v1\0"
DOMAIN_CONTROL_PLAN = b"sol-spp-diagbundle-control-plan-v1\0"
DOMAIN_QUOTE_QD = b"sol-spp-diagbundle-quote-qd-v1\0"
DOMAIN_OUTER_ENVELOPE = b"sol-spp-diagbundle-outer-envelope-v1\0"

SCHEMA_INPUT_CLOSURE = "sol-spp-diagbundle-input-closure/v1"
SCHEMA_SIGNED_IMAGE = "sol-spp-diagbundle-signed-image/v1"
SCHEMA_INNER_RECEIPT = "sol-spp-diagbundle-inner-receipt/v1"
SCHEMA_OUTER_ENVELOPE = "sol-spp-diagbundle-outer-envelope/v1"
KIND_INPUT_CLOSURE = "input_closure"
KIND_SIGNED_IMAGE = "signed_image"
KIND_INNER_RECEIPT = "inner_receipt"
KIND_OUTER_ENVELOPE = "outer_envelope"
ARTIFACT_STATE = "diagnostic_unqualified"
LAYOUT_IMAGE = "uki-verity/v1"
LAYOUT_OUTER = "snp-tpm-gpu/v1"
TERMINAL_INTENT = "intent_to_export"
CONTROL_PLAN_PATH = "control-plan.json"
SIGNED_IMAGE_MEMBER_NAMES = (
    "diagnostic.efi",
    "rootfs.img",
    "rootfs.verity",
    "verity-root-hash.bin",
    "signer-cert.der",
)
OUTER_FILE_MEMBER_NAMES = (
    "ak-public.pem",
    "quote.msg",
    "quote.sig",
    "quote.pcrs",
    "hcla.bin",
    "snp-vcek.pem",
    "snp-cert-chain.pem",
    "firmware-event-log.bin",
    "ima-measurements.bin",
    "gpu-evidence.tlv",
)

_SCN_INITIALIZED = 0x40
_SCN_READ = 0x40000000
_COFF_FORMAT = "<HHIIIHH"
_SECTION_FORMAT = "<8sIIIIIIHHI"


def domain_address(domain: bytes, obj: dict) -> str:
    return hashlib.sha256(domain + canonical_dumps(obj)).hexdigest()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)


def build_uki(descriptor_input_closure_address: str) -> bytes:
    payload = canonical_dumps(
        {
            "schema": SCHEMA_INPUT_CLOSURE,
            "artifact_state": ARTIFACT_STATE,
            "input_closure_address": descriptor_input_closure_address,
        }
    )
    raw = struct.pack("<I", len(payload)) + payload
    directories = [(0, 0)] * 16
    optional = bytearray()
    optional += struct.pack("<HBB", 0x10B, 0, 0)
    optional += struct.pack("<9I", 0, 0, 0, 0, 0, 0, 0, 4096, 512)
    optional += struct.pack("<6H", 0, 0, 0, 0, 0, 0)
    optional += struct.pack("<3I", 0, 0, 0)
    optional += struct.pack("<I", 0)
    optional += struct.pack("<HH", 10, 0)
    optional += struct.pack("<4I", 0, 0, 0, 0)
    optional += struct.pack("<II", 0, 16)
    for virtual_address, size in directories:
        optional += struct.pack("<II", virtual_address, size)
    e_lfanew = 64
    optional_start = e_lfanew + 24
    section_table_start = optional_start + len(optional)
    headers_end = section_table_start + 40
    pointer = headers_end
    buf = bytearray(pointer + len(raw))
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 60, e_lfanew)
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into(_COFF_FORMAT, buf, e_lfanew + 4, 0x8664, 1, 0, 0, 0, len(optional), 0)
    buf[optional_start : optional_start + len(optional)] = optional
    struct.pack_into(
        _SECTION_FORMAT,
        buf,
        section_table_start,
        b".sppdiag",
        len(raw),
        0,
        len(raw),
        pointer,
        0,
        0,
        0,
        0,
        _SCN_INITIALIZED | _SCN_READ,
    )
    buf[pointer : pointer + len(raw)] = raw
    return bytes(buf)


@dataclass(frozen=True)
class BundleSpec:
    closure_rows: tuple[tuple[str, str, str, bytes], ...]
    receipt_rows: tuple[tuple[str, str, bytes], ...]
    challenge: str
    run_identity: str
    target_profile_id: str
    terminal_intent: str
    rootfs: bytes
    verity: bytes
    root_hash: bytes
    signer_cert: bytes
    outer_files: tuple[tuple[str, bytes], ...]
    declared_sha256: tuple[tuple[str, str], ...] = ()
    extra_closure_fields: tuple[tuple[str, object], ...] = ()
    sort_closure: bool = True
    sppdiag_address: str | None = None
    image_input_closure_address: str | None = None
    receipt_image_binding: str | None = None
    receipt_control_plan: str | None = None
    receipt_challenge: str | None = None
    receipt_run_identity: str | None = None
    outer_inner_digest: str | None = None
    outer_quote_extra: str | None = None
    expectations_input_closure: str | None = None
    expectations_challenge: str | None = None
    expectations_run_identity: str | None = None
    expectations_target_profile: str | None = None
    expectations_control_plan: str | None = None
    extra_root_file: str | None = None
    extra_signed_image_file: str | None = None
    skip_signed_image_dir: bool = False
    skip_closure_file: str | None = None
    inner_as_root_manifest: bool = False


def _default_closure_rows() -> tuple[tuple[str, str, str, bytes], ...]:
    plan = canonical_dumps({"plan": True})
    return (
        ("config.json", "resolved_configuration", "canonical_json", b'{"k":1}'),
        ("control-plan.json", "canonical_control_plan", "canonical_json", plan),
        ("controller.py", "controller_source", "source", b"print(1)\n"),
        ("kernel.json", "kernel_configuration", "canonical_json", b'{"kcfg":true}'),
        ("lock.json", "toolchain_lock", "canonical_json", b'{"lock":true}'),
        ("model.json", "model_manifest", "canonical_json", b'{"model":true}'),
        ("producer.py", "producer_source", "source", b"print(2)\n"),
        ("recipe.json", "build_recipe", "canonical_json", b'{"recipe":true}'),
        ("runtime.json", "runtime_manifest", "canonical_json", b'{"runtime":true}'),
        ("signer-policy.json", "signer_public_policy", "canonical_json", b'{"signer":true}'),
        ("source-tree.json", "source_tree_manifest", "canonical_json", b'{"tree":true}'),
        ("trace.json", "trace_policy", "canonical_json", b'{"trace":true}'),
    )


DEFAULT_SPEC = BundleSpec(
    closure_rows=_default_closure_rows(),
    receipt_rows=(("prequote.bin", "bytes", b"prequote"),),
    challenge=_sha(b"diagbundle-oracle-challenge-v1"),
    run_identity=_sha(b"diagbundle-oracle-run-identity-v1"),
    target_profile_id="profile-v1",
    terminal_intent=TERMINAL_INTENT,
    rootfs=b"rootfs",
    verity=b"verity",
    root_hash=b"h" * 32,
    signer_cert=b"\x30\x03\x02\x01\x00",
    outer_files=tuple((name, b"outer-" + name.encode("ascii")) for name in OUTER_FILE_MEMBER_NAMES),
)


def build_bundle(root_dir: str, expectations_path: str, spec: BundleSpec) -> dict[str, str]:
    rows = list(spec.closure_rows)
    if spec.sort_closure:
        rows.sort(key=lambda row: row[0])
    declared_sha256 = dict(spec.declared_sha256)
    closure_inventory = []
    for path, role, kind, data in rows:
        if spec.skip_closure_file != path:
            _write(os.path.join(root_dir, "input-closure", path), data)
        closure_inventory.append(
            {
                "path": path,
                "role": role,
                "content_kind": kind,
                "size_bytes": len(data),
                "sha256": declared_sha256.get(path, _sha(data)),
            }
        )
    true_inventory = []
    for path, role, kind, data in rows:
        true_inventory.append(
            {
                "path": path,
                "role": role,
                "content_kind": kind,
                "size_bytes": len(data),
                "sha256": _sha(data),
            }
        )
    control_plan_bytes = next(data for path, _role, _kind, data in rows if path == CONTROL_PLAN_PATH)
    canonical_loads(control_plan_bytes)
    control_plan_address = hashlib.sha256(DOMAIN_CONTROL_PLAN + control_plan_bytes).hexdigest()
    input_closure_object = {
        "schema": SCHEMA_INPUT_CLOSURE,
        "node_kind": KIND_INPUT_CLOSURE,
        "artifact_state": ARTIFACT_STATE,
        "inventory": true_inventory,
    }
    input_closure_address = domain_address(DOMAIN_INPUT_CLOSURE, input_closure_object)
    closure_manifest = {
        "schema": SCHEMA_INPUT_CLOSURE,
        "node_kind": KIND_INPUT_CLOSURE,
        "artifact_state": ARTIFACT_STATE,
        "inventory": closure_inventory,
    }
    for key, value in spec.extra_closure_fields:
        closure_manifest[key] = value
    _write(os.path.join(root_dir, "input-closure", "manifest.json"), canonical_dumps(closure_manifest))

    sppdiag_address = spec.sppdiag_address if spec.sppdiag_address is not None else input_closure_address
    uki = build_uki(sppdiag_address)
    image_payloads = {
        "diagnostic.efi": uki,
        "rootfs.img": spec.rootfs,
        "rootfs.verity": spec.verity,
        "verity-root-hash.bin": spec.root_hash,
        "signer-cert.der": spec.signer_cert,
    }
    image_members = {}
    if not spec.skip_signed_image_dir:
        for name in SIGNED_IMAGE_MEMBER_NAMES:
            data = image_payloads[name]
            _write(os.path.join(root_dir, "signed-image", name), data)
            image_members[name] = {"size_bytes": len(data), "sha256": _sha(data)}
        if spec.extra_signed_image_file is not None:
            _write(os.path.join(root_dir, "signed-image", spec.extra_signed_image_file), b"extra")
    image_declared_closure = (
        spec.image_input_closure_address if spec.image_input_closure_address is not None else input_closure_address
    )
    image_binding_address = domain_address(
        DOMAIN_IMAGE_BINDING,
        {
            "schema": SCHEMA_SIGNED_IMAGE,
            "node_kind": KIND_SIGNED_IMAGE,
            "artifact_state": ARTIFACT_STATE,
            "layout": LAYOUT_IMAGE,
            "input_closure_address": image_declared_closure,
            "members": {name: image_members[name] for name in sorted(SIGNED_IMAGE_MEMBER_NAMES)} if image_members else {},
        },
    )
    if not spec.skip_signed_image_dir:
        _write(
            os.path.join(root_dir, "signed-image", "manifest.json"),
            canonical_dumps(
                {
                    "schema": SCHEMA_SIGNED_IMAGE,
                    "node_kind": KIND_SIGNED_IMAGE,
                    "artifact_state": ARTIFACT_STATE,
                    "layout": LAYOUT_IMAGE,
                    "input_closure_address": image_declared_closure,
                    "members": image_members,
                }
            ),
        )

    receipt_inventory = []
    true_receipt = []
    for path, kind, data in spec.receipt_rows:
        _write(os.path.join(root_dir, "inner-receipt", path), data)
        true_receipt.append({"path": path, "content_kind": kind, "size_bytes": len(data), "sha256": _sha(data)})
        receipt_inventory.append({"path": path, "content_kind": kind, "size_bytes": len(data), "sha256": _sha(data)})
    receipt_image_binding = spec.receipt_image_binding if spec.receipt_image_binding is not None else image_binding_address
    receipt_control_plan = spec.receipt_control_plan if spec.receipt_control_plan is not None else control_plan_address
    receipt_challenge = spec.receipt_challenge if spec.receipt_challenge is not None else spec.challenge
    receipt_run_identity = spec.receipt_run_identity if spec.receipt_run_identity is not None else spec.run_identity
    inner_object = {
        "schema": SCHEMA_INNER_RECEIPT,
        "node_kind": KIND_INNER_RECEIPT,
        "artifact_state": ARTIFACT_STATE,
        "challenge": receipt_challenge,
        "run_identity": receipt_run_identity,
        "signed_image_binding_address": receipt_image_binding,
        "target_profile_id": spec.target_profile_id,
        "control_plan_address": receipt_control_plan,
        "terminal_intent": spec.terminal_intent,
        "inventory": true_receipt,
    }
    inner_receipt_digest = domain_address(DOMAIN_INNER_RECEIPT, inner_object)
    inner_manifest = canonical_dumps(
        {
            "schema": SCHEMA_INNER_RECEIPT,
            "node_kind": KIND_INNER_RECEIPT,
            "artifact_state": ARTIFACT_STATE,
            "challenge": receipt_challenge,
            "run_identity": receipt_run_identity,
            "signed_image_binding_address": receipt_image_binding,
            "target_profile_id": spec.target_profile_id,
            "control_plan_address": receipt_control_plan,
            "terminal_intent": spec.terminal_intent,
            "inventory": receipt_inventory,
        }
    )
    _write(os.path.join(root_dir, "inner-receipt", "manifest.json"), inner_manifest)

    quote_extra_data = domain_address(
        DOMAIN_QUOTE_QD,
        {
            "challenge": spec.expectations_challenge if spec.expectations_challenge is not None else spec.challenge,
            "control_plan_address": control_plan_address,
            "inner_receipt_digest": inner_receipt_digest,
            "run_identity": spec.expectations_run_identity if spec.expectations_run_identity is not None else spec.run_identity,
            "signed_image_binding_address": image_binding_address,
            "target_profile_id": spec.expectations_target_profile if spec.expectations_target_profile is not None else spec.target_profile_id,
        },
    )
    declared_inner = spec.outer_inner_digest if spec.outer_inner_digest is not None else inner_receipt_digest
    declared_quote = spec.outer_quote_extra if spec.outer_quote_extra is not None else quote_extra_data
    outer_members: dict[str, object] = {"inner-receipt": {"digest": inner_receipt_digest}}
    for name, data in spec.outer_files:
        _write(os.path.join(root_dir, name), data)
        outer_members[name] = {"size_bytes": len(data), "sha256": _sha(data)}
    outer_object = {
        "schema": SCHEMA_OUTER_ENVELOPE,
        "node_kind": KIND_OUTER_ENVELOPE,
        "artifact_state": ARTIFACT_STATE,
        "layout": LAYOUT_OUTER,
        "inner_receipt_digest": declared_inner,
        "quote_extra_data": declared_quote,
        "members": outer_members,
    }
    outer_envelope_address = domain_address(DOMAIN_OUTER_ENVELOPE, outer_object)
    outer_manifest = canonical_dumps(
        {
            "schema": SCHEMA_OUTER_ENVELOPE,
            "node_kind": KIND_OUTER_ENVELOPE,
            "artifact_state": ARTIFACT_STATE,
            "layout": LAYOUT_OUTER,
            "inner_receipt_digest": declared_inner,
            "quote_extra_data": declared_quote,
            "members": {
                "inner-receipt": {"digest": declared_inner},
                **{name: outer_members[name] for name, _data in spec.outer_files},
            },
        }
    )
    if spec.inner_as_root_manifest:
        _write(os.path.join(root_dir, "manifest.json"), inner_manifest)
    else:
        _write(os.path.join(root_dir, "manifest.json"), outer_manifest)
    if spec.extra_root_file is not None:
        _write(os.path.join(root_dir, spec.extra_root_file), b"unexpected")

    expectations = {
        "input_closure_address": spec.expectations_input_closure if spec.expectations_input_closure is not None else input_closure_address,
        "challenge": spec.expectations_challenge if spec.expectations_challenge is not None else spec.challenge,
        "run_identity": spec.expectations_run_identity if spec.expectations_run_identity is not None else spec.run_identity,
        "target_profile_id": spec.expectations_target_profile if spec.expectations_target_profile is not None else spec.target_profile_id,
        "control_plan_address": spec.expectations_control_plan if spec.expectations_control_plan is not None else control_plan_address,
    }
    _write(expectations_path, canonical_dumps(expectations))
    return {
        "input_closure_address": input_closure_address,
        "control_plan_address": control_plan_address,
        "image_binding_address": image_binding_address,
        "inner_receipt_digest": inner_receipt_digest,
        "outer_envelope_address": outer_envelope_address,
        "quote_extra_data": quote_extra_data,
        "input_closure_object": input_closure_object,
    }
