#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Closed schemas, domain-separated addresses, and graph inspect for diagnostic bundles."""

from __future__ import annotations

import hashlib
import hmac
import posixpath
from dataclasses import dataclass
from typing import Final

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_prohibited import check_content_markers
from conf_proc_reasons import ApplianceError
from conf_proc_spp_diagbundle_pe import extract_sppdiag_descriptor
from conf_proc_spp_diagbundle_reasons import (
    CP_DIAGBUNDLE_EXPECTATIONS,
    CP_DIAGBUNDLE_FORBIDDEN,
    CP_DIAGBUNDLE_GRAPH,
    CP_DIAGBUNDLE_JSON_INVALID,
    CP_DIAGBUNDLE_LAYOUT,
    CP_DIAGBUNDLE_MEMBER,
    CP_DIAGBUNDLE_NODE_KIND,
    CP_DIAGBUNDLE_ROLE,
    CP_DIAGBUNDLE_SCHEMA,
    CP_DIAGBUNDLE_SEAM_CHALLENGE,
    CP_DIAGBUNDLE_SEAM_CONTROL_PLAN,
    CP_DIAGBUNDLE_SEAM_IMAGE_BINDING,
    CP_DIAGBUNDLE_SEAM_IMAGE_FIELD,
    CP_DIAGBUNDLE_SEAM_INNER_RECEIPT,
    CP_DIAGBUNDLE_SEAM_INPUT_CLOSURE,
    CP_DIAGBUNDLE_SEAM_QUOTE_QD,
    CP_DIAGBUNDLE_SEAM_RUN_IDENTITY,
    CP_DIAGBUNDLE_SEAM_SPPDIAG,
    CP_DIAGBUNDLE_SEAM_TARGET_PROFILE,
    CP_DIAGBUNDLE_SNAPSHOT_SIZE,
    CP_DIAGBUNDLE_TERMINAL_FRAME,
    DiagBundleError,
    NODE_ARTIFACT_STATE,
)
from conf_proc_spp_diagbundle_snapshot import SnapshotBudget, pin_bundle_root, read_bounded_file, revalidate


NODE_KIND_INPUT_CLOSURE: Final = "input_closure"
NODE_KIND_SIGNED_IMAGE: Final = "signed_image"
NODE_KIND_INNER_RECEIPT: Final = "inner_receipt"
NODE_KIND_OUTER_ENVELOPE: Final = "outer_envelope"
ALL_NODE_KINDS: Final = frozenset(
    {
        NODE_KIND_INPUT_CLOSURE,
        NODE_KIND_SIGNED_IMAGE,
        NODE_KIND_INNER_RECEIPT,
        NODE_KIND_OUTER_ENVELOPE,
    }
)
assert NODE_ARTIFACT_STATE not in ALL_NODE_KINDS

DOMAIN_INPUT_CLOSURE: Final = b"sol-spp-diagbundle-input-closure-v1\0"
DOMAIN_IMAGE_BINDING: Final = b"sol-spp-diagbundle-image-binding-v1\0"
DOMAIN_INNER_RECEIPT: Final = b"sol-spp-diagbundle-inner-receipt-v1\0"
DOMAIN_CONTROL_PLAN: Final = b"sol-spp-diagbundle-control-plan-v1\0"
DOMAIN_QUOTE_QD: Final = b"sol-spp-diagbundle-quote-qd-v1\0"
DOMAIN_OUTER_ENVELOPE: Final = b"sol-spp-diagbundle-outer-envelope-v1\0"

INPUT_CLOSURE_SCHEMA_ID: Final = "sol-spp-diagbundle-input-closure/v1"
SIGNED_IMAGE_SCHEMA_ID: Final = "sol-spp-diagbundle-signed-image/v1"
INNER_RECEIPT_SCHEMA_ID: Final = "sol-spp-diagbundle-inner-receipt/v1"
OUTER_ENVELOPE_SCHEMA_ID: Final = "sol-spp-diagbundle-outer-envelope/v1"
SIGNED_IMAGE_LAYOUT: Final = "uki-verity/v1"
OUTER_ENVELOPE_LAYOUT: Final = "snp-tpm-gpu/v1"
TERMINAL_INTENT_EXPORT: Final = "intent_to_export"
CONTROL_PLAN_PATH: Final = "control-plan.json"
ROLE_CONTROL_PLAN: Final = "canonical_control_plan"

INPUT_CLOSURE_ROLES: Final = (
    "source_tree_manifest",
    "build_recipe",
    "toolchain_lock",
    "resolved_configuration",
    "kernel_configuration",
    "trace_policy",
    ROLE_CONTROL_PLAN,
    "runtime_manifest",
    "model_manifest",
    "producer_source",
    "controller_source",
    "signer_public_policy",
)
INPUT_CLOSURE_ROLE_SET: Final = frozenset(INPUT_CLOSURE_ROLES)
CONTENT_KINDS: Final = frozenset({"canonical_json", "source", "bytes"})
SIGNED_IMAGE_MEMBER_NAMES: Final = (
    "diagnostic.efi",
    "rootfs.img",
    "rootfs.verity",
    "verity-root-hash.bin",
    "signer-cert.der",
)
SIGNED_IMAGE_MEMBER_SET: Final = frozenset(SIGNED_IMAGE_MEMBER_NAMES)
OUTER_FILE_MEMBER_NAMES: Final = (
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
OUTER_MEMBER_NAMES: Final = OUTER_FILE_MEMBER_NAMES + ("inner-receipt",)
OUTER_FILE_MEMBER_SET: Final = frozenset(OUTER_FILE_MEMBER_NAMES)
OUTER_MEMBER_SET: Final = frozenset(OUTER_MEMBER_NAMES)
OUTER_PEM_MEMBER_NAMES: Final = frozenset({"ak-public.pem", "snp-vcek.pem", "snp-cert-chain.pem"})
_OUTER_MEMBER_BASENAMES: Final = frozenset(OUTER_FILE_MEMBER_NAMES)
_FORBIDDEN_SUFFIXES: Final = (".key", ".pem", ".p12", ".pfx", ".jks")
_FORBIDDEN_BASENAMES: Final = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})
_PRIVATE_KEY_MARKERS: Final = (
    b"-----BEGIN PRIVATE KEY",
    b"-----BEGIN RSA PRIVATE KEY",
    b"-----BEGIN EC PRIVATE KEY",
    b"-----BEGIN OPENSSH PRIVATE KEY",
    b"-----BEGIN DSA PRIVATE KEY",
)
_INPUT_CLOSURE_KEYS: Final = frozenset({"schema", "node_kind", "artifact_state", "inventory"})
_INPUT_ROW_KEYS: Final = frozenset({"path", "role", "content_kind", "size_bytes", "sha256"})
_RECEIPT_ROW_KEYS: Final = frozenset({"path", "content_kind", "size_bytes", "sha256"})
_SIGNED_IMAGE_KEYS: Final = frozenset(
    {"schema", "node_kind", "artifact_state", "layout", "input_closure_address", "members"}
)
_INNER_RECEIPT_KEYS: Final = frozenset(
    {
        "schema",
        "node_kind",
        "artifact_state",
        "challenge",
        "run_identity",
        "signed_image_binding_address",
        "target_profile_id",
        "control_plan_address",
        "terminal_intent",
        "inventory",
    }
)
_OUTER_ENVELOPE_KEYS: Final = frozenset(
    {"schema", "node_kind", "artifact_state", "layout", "inner_receipt_digest", "quote_extra_data", "members"}
)
_SIZE_HASH_KEYS: Final = frozenset({"size_bytes", "sha256"})
_DIGEST_KEYS: Final = frozenset({"digest"})
_EXPECTATION_KEYS: Final = frozenset(
    {"input_closure_address", "challenge", "run_identity", "target_profile_id", "control_plan_address"}
)
_MAX_EXPECTATIONS_BYTES: Final = 4 * 1024 * 1024
_GIB: Final = 1024**3
_MIB: Final = 1024**2
_TEXT_CONTENT_KINDS: Final = frozenset({"source", "canonical_json"})
_SIGNED_IMAGE_FILE_CAPS: Final = {
    "diagnostic.efi": 1 * _GIB,
    "rootfs.img": 64 * _GIB,
    "rootfs.verity": 8 * _GIB,
    "verity-root-hash.bin": 128,
    "signer-cert.der": 1 * _MIB,
}
_GRAPH_BUDGET: Final = SnapshotBudget(
    max_entries=8192,
    max_depth=64,
    max_file_bytes=64 * 1024**3,
    max_total_bytes=384 * 1024**3,
)
_MANDATORY_ROLE_MESSAGE: Final = (
    "inventory must declare exactly one canonical_control_plan at control-plan.json "
    "and at least one row for every mandatory role: source_tree_manifest, build_recipe, "
    "toolchain_lock, resolved_configuration, kernel_configuration, trace_policy, "
    "canonical_control_plan, runtime_manifest, model_manifest, producer_source, "
    "controller_source, signer_public_policy"
)


@dataclass(frozen=True)
class InputClosureRow:
    path: str
    role: str
    content_kind: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class InputClosureManifest:
    schema: str
    node_kind: str
    artifact_state: str
    inventory: tuple[InputClosureRow, ...]


@dataclass(frozen=True)
class SignedImageManifest:
    schema: str
    node_kind: str
    artifact_state: str
    layout: str
    input_closure_address: str
    members: dict[str, tuple[int, str]]


@dataclass(frozen=True)
class InnerReceiptRow:
    path: str
    content_kind: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class InnerReceiptManifest:
    schema: str
    node_kind: str
    artifact_state: str
    challenge: str
    run_identity: str
    signed_image_binding_address: str
    target_profile_id: str
    control_plan_address: str
    terminal_intent: str
    inventory: tuple[InnerReceiptRow, ...]


@dataclass(frozen=True)
class OuterEnvelopeManifest:
    schema: str
    node_kind: str
    artifact_state: str
    layout: str
    inner_receipt_digest: str
    quote_extra_data: str
    members: dict[str, object]


@dataclass(frozen=True)
class CallerExpectations:
    input_closure_address: str
    challenge: str
    run_identity: str
    target_profile_id: str
    control_plan_address: str


def parse_input_closure_manifest(data: bytes) -> InputClosureManifest:
    raw = _object(data, _INPUT_CLOSURE_KEYS)
    _require_common(raw, INPUT_CLOSURE_SCHEMA_ID, NODE_KIND_INPUT_CLOSURE)
    inventory_raw = raw["inventory"]
    _require(type(inventory_raw) is list, CP_DIAGBUNDLE_SCHEMA, "inventory must be an array")
    inventory = tuple(_parse_input_row(item) for item in inventory_raw)
    _require_strictly_increasing([row.path for row in inventory])
    _require_input_roles(inventory)
    return InputClosureManifest(
        schema=raw["schema"],
        node_kind=raw["node_kind"],
        artifact_state=raw["artifact_state"],
        inventory=inventory,
    )


def parse_signed_image_manifest(data: bytes) -> SignedImageManifest:
    raw = _object(data, _SIGNED_IMAGE_KEYS)
    _require_common(raw, SIGNED_IMAGE_SCHEMA_ID, NODE_KIND_SIGNED_IMAGE)
    _require(raw["layout"] == SIGNED_IMAGE_LAYOUT, CP_DIAGBUNDLE_LAYOUT, "signed-image layout is invalid")
    _require(_is_sha256(raw["input_closure_address"]), CP_DIAGBUNDLE_SCHEMA, "input_closure_address is invalid")
    members_raw = raw["members"]
    _require(type(members_raw) is dict and set(members_raw) == SIGNED_IMAGE_MEMBER_SET, CP_DIAGBUNDLE_SCHEMA, "signed-image members are invalid")
    members = {name: _parse_size_hash(members_raw[name]) for name in SIGNED_IMAGE_MEMBER_NAMES}
    return SignedImageManifest(
        schema=raw["schema"],
        node_kind=raw["node_kind"],
        artifact_state=raw["artifact_state"],
        layout=raw["layout"],
        input_closure_address=raw["input_closure_address"],
        members=members,
    )


def parse_inner_receipt_manifest(data: bytes) -> InnerReceiptManifest:
    raw = _object(data, _INNER_RECEIPT_KEYS)
    _require_common(raw, INNER_RECEIPT_SCHEMA_ID, NODE_KIND_INNER_RECEIPT)
    _require(_is_sha256(raw["challenge"]), CP_DIAGBUNDLE_SCHEMA, "challenge is invalid")
    _require(_is_sha256(raw["run_identity"]), CP_DIAGBUNDLE_SCHEMA, "run_identity is invalid")
    _require(_is_sha256(raw["signed_image_binding_address"]), CP_DIAGBUNDLE_SCHEMA, "signed_image_binding_address is invalid")
    _require(_is_target_profile(raw["target_profile_id"]), CP_DIAGBUNDLE_SCHEMA, "target_profile_id is invalid")
    _require(_is_sha256(raw["control_plan_address"]), CP_DIAGBUNDLE_SCHEMA, "control_plan_address is invalid")
    _require(raw["terminal_intent"] == TERMINAL_INTENT_EXPORT, CP_DIAGBUNDLE_TERMINAL_FRAME, "terminal_intent is invalid")
    inventory_raw = raw["inventory"]
    _require(type(inventory_raw) is list, CP_DIAGBUNDLE_SCHEMA, "inventory must be an array")
    inventory = tuple(_parse_receipt_row(item) for item in inventory_raw)
    _require_strictly_increasing([row.path for row in inventory])
    return InnerReceiptManifest(
        schema=raw["schema"],
        node_kind=raw["node_kind"],
        artifact_state=raw["artifact_state"],
        challenge=raw["challenge"],
        run_identity=raw["run_identity"],
        signed_image_binding_address=raw["signed_image_binding_address"],
        target_profile_id=raw["target_profile_id"],
        control_plan_address=raw["control_plan_address"],
        terminal_intent=raw["terminal_intent"],
        inventory=inventory,
    )


def parse_outer_envelope_manifest(data: bytes) -> OuterEnvelopeManifest:
    raw = _object(data, _OUTER_ENVELOPE_KEYS)
    _require_common(raw, OUTER_ENVELOPE_SCHEMA_ID, NODE_KIND_OUTER_ENVELOPE)
    _require(raw["layout"] == OUTER_ENVELOPE_LAYOUT, CP_DIAGBUNDLE_LAYOUT, "outer-envelope layout is invalid")
    _require(_is_sha256(raw["inner_receipt_digest"]), CP_DIAGBUNDLE_SCHEMA, "inner_receipt_digest is invalid")
    _require(_is_sha256(raw["quote_extra_data"]), CP_DIAGBUNDLE_SCHEMA, "quote_extra_data is invalid")
    members_raw = raw["members"]
    _require(type(members_raw) is dict and set(members_raw) == OUTER_MEMBER_SET, CP_DIAGBUNDLE_SCHEMA, "outer-envelope members are invalid")
    members: dict[str, object] = {}
    inner = members_raw["inner-receipt"]
    _require(type(inner) is dict and set(inner) == _DIGEST_KEYS, CP_DIAGBUNDLE_SCHEMA, "inner-receipt member is invalid")
    _require(_is_sha256(inner["digest"]), CP_DIAGBUNDLE_SCHEMA, "inner-receipt digest is invalid")
    members["inner-receipt"] = {"digest": inner["digest"]}
    for name in OUTER_FILE_MEMBER_NAMES:
        members[name] = _parse_size_hash(members_raw[name])
    return OuterEnvelopeManifest(
        schema=raw["schema"],
        node_kind=raw["node_kind"],
        artifact_state=raw["artifact_state"],
        layout=raw["layout"],
        inner_receipt_digest=raw["inner_receipt_digest"],
        quote_extra_data=raw["quote_extra_data"],
        members=members,
    )


def inspect_diagnostic_bundle(bundle_root: str, expectations_path: str) -> dict[str, str]:
    expectations = _parse_expectations(read_bounded_file(expectations_path, _MAX_EXPECTATIONS_BYTES))
    with pin_bundle_root(bundle_root, SnapshotBudget(
        max_entries=_GRAPH_BUDGET.max_entries,
        max_depth=_GRAPH_BUDGET.max_depth,
        max_file_bytes=_GRAPH_BUDGET.max_file_bytes,
        max_total_bytes=_GRAPH_BUDGET.max_total_bytes,
    )) as snapshot:
        _require_root_shape(snapshot)
        _require_unique_identities(snapshot)
        _require_subtree_budget(snapshot, "input-closure", max_entries=4096, max_file_bytes=64 * _GIB, max_total_bytes=256 * _GIB)
        _require_subtree_budget(snapshot, "inner-receipt", max_entries=1024, max_file_bytes=4 * _GIB, max_total_bytes=16 * _GIB)
        _require_outer_member_budget(snapshot)
        _require_signed_image_file_caps(snapshot)

        outer_manifest = parse_outer_envelope_manifest(_pinned(snapshot, "manifest.json").read_all())
        closure_manifest = parse_input_closure_manifest(_pinned(snapshot, "input-closure/manifest.json").read_all())
        closure_files = _subtree_files(snapshot, "input-closure")
        _require_member_paths(set(closure_files) - {"manifest.json"}, {row.path for row in closure_manifest.inventory})
        closure_inventory = []
        for row in closure_manifest.inventory:
            pinned = closure_files[row.path]
            # Opaque bytes can be multi-gigabyte; AC disclaims detecting arbitrarily
            # mislabeled secret bytes. Scan only text-like content kinds.
            if row.content_kind in _TEXT_CONTENT_KINDS:
                _reject_forbidden_content("input-closure/" + row.path, pinned.read_all(), allow_pem=False)
            closure_inventory.append(
                {
                    "path": row.path,
                    "role": row.role,
                    "content_kind": row.content_kind,
                    "size_bytes": pinned.identity[4],
                    "sha256": pinned.pass1_sha256,
                }
            )
        control_plan_bytes = closure_files[CONTROL_PLAN_PATH].read_all()
        _loads(control_plan_bytes)
        control_plan_address = hashlib.sha256(DOMAIN_CONTROL_PLAN + control_plan_bytes).hexdigest()
        input_closure_address = _domain_address(
            DOMAIN_INPUT_CLOSURE,
            {
                "schema": closure_manifest.schema,
                "node_kind": closure_manifest.node_kind,
                "artifact_state": closure_manifest.artifact_state,
                "inventory": closure_inventory,
            },
        )

        image_manifest = parse_signed_image_manifest(_pinned(snapshot, "signed-image/manifest.json").read_all())
        image_files = _subtree_files(snapshot, "signed-image")
        _require_member_paths(set(image_files) - {"manifest.json"}, SIGNED_IMAGE_MEMBER_SET)
        image_members = {}
        for name in SIGNED_IMAGE_MEMBER_NAMES:
            pinned = image_files[name]
            # AC: private-key roles/names are forbidden; detecting arbitrarily
            # mislabeled secret bytes in image members is out of this codec's
            # claim. Do not slurp rootfs.img/verity (up to 64/8 GiB) for a
            # substring scan. diagnostic.efi is read below for PE parsing only.
            image_members[name] = {"size_bytes": pinned.identity[4], "sha256": pinned.pass1_sha256}
        sppdiag = extract_sppdiag_descriptor(image_files["diagnostic.efi"].read_all())
        image_binding_address = _domain_address(
            DOMAIN_IMAGE_BINDING,
            {
                "schema": image_manifest.schema,
                "node_kind": image_manifest.node_kind,
                "artifact_state": image_manifest.artifact_state,
                "layout": image_manifest.layout,
                "input_closure_address": image_manifest.input_closure_address,
                "members": {name: image_members[name] for name in sorted(SIGNED_IMAGE_MEMBER_NAMES)},
            },
        )

        receipt_manifest = parse_inner_receipt_manifest(_pinned(snapshot, "inner-receipt/manifest.json").read_all())
        receipt_files = _subtree_files(snapshot, "inner-receipt")
        _require_member_paths(set(receipt_files) - {"manifest.json"}, {row.path for row in receipt_manifest.inventory})
        receipt_inventory = []
        for row in receipt_manifest.inventory:
            pinned = receipt_files[row.path]
            # Same size-driven skip as input-closure: do not materialize opaque bytes.
            if row.content_kind in _TEXT_CONTENT_KINDS:
                _reject_forbidden_content("inner-receipt/" + row.path, pinned.read_all(), allow_pem=False)
            receipt_inventory.append(
                {
                    "path": row.path,
                    "content_kind": row.content_kind,
                    "size_bytes": pinned.identity[4],
                    "sha256": pinned.pass1_sha256,
                }
            )
        inner_receipt_digest = _domain_address(
            DOMAIN_INNER_RECEIPT,
            {
                "schema": receipt_manifest.schema,
                "node_kind": receipt_manifest.node_kind,
                "artifact_state": receipt_manifest.artifact_state,
                "challenge": receipt_manifest.challenge,
                "run_identity": receipt_manifest.run_identity,
                "signed_image_binding_address": receipt_manifest.signed_image_binding_address,
                "target_profile_id": receipt_manifest.target_profile_id,
                "control_plan_address": receipt_manifest.control_plan_address,
                "terminal_intent": receipt_manifest.terminal_intent,
                "inventory": receipt_inventory,
            },
        )

        outer_members: dict[str, object] = {"inner-receipt": {"digest": inner_receipt_digest}}
        for name in OUTER_FILE_MEMBER_NAMES:
            pinned = _pinned(snapshot, name)
            _reject_forbidden_content(name, pinned.read_all(), allow_pem=name in OUTER_PEM_MEMBER_NAMES)
            outer_members[name] = {"size_bytes": pinned.identity[4], "sha256": pinned.pass1_sha256}
        outer_envelope_address = _domain_address(
            DOMAIN_OUTER_ENVELOPE,
            {
                "schema": outer_manifest.schema,
                "node_kind": outer_manifest.node_kind,
                "artifact_state": outer_manifest.artifact_state,
                "layout": outer_manifest.layout,
                "inner_receipt_digest": outer_manifest.inner_receipt_digest,
                "quote_extra_data": outer_manifest.quote_extra_data,
                "members": outer_members,
            },
        )
        quote_extra_data = _domain_address(
            DOMAIN_QUOTE_QD,
            {
                "challenge": expectations.challenge,
                "control_plan_address": control_plan_address,
                "inner_receipt_digest": inner_receipt_digest,
                "run_identity": expectations.run_identity,
                "signed_image_binding_address": image_binding_address,
                "target_profile_id": expectations.target_profile_id,
            },
        )

        _require_hex_equal(input_closure_address, expectations.input_closure_address, CP_DIAGBUNDLE_SEAM_INPUT_CLOSURE)
        _require_hex_equal(input_closure_address, sppdiag.input_closure_address, CP_DIAGBUNDLE_SEAM_SPPDIAG)
        _require_hex_equal(input_closure_address, image_manifest.input_closure_address, CP_DIAGBUNDLE_SEAM_IMAGE_FIELD)
        _require_hex_equal(image_binding_address, receipt_manifest.signed_image_binding_address, CP_DIAGBUNDLE_SEAM_IMAGE_BINDING)
        _require_hex_equal(inner_receipt_digest, outer_manifest.inner_receipt_digest, CP_DIAGBUNDLE_SEAM_INNER_RECEIPT)
        if not hmac.compare_digest(control_plan_address, expectations.control_plan_address) or not hmac.compare_digest(
            control_plan_address, receipt_manifest.control_plan_address
        ):
            raise DiagBundleError(CP_DIAGBUNDLE_SEAM_CONTROL_PLAN, "control-plan address seam mismatch")
        _require_hex_equal(expectations.challenge, receipt_manifest.challenge, CP_DIAGBUNDLE_SEAM_CHALLENGE)
        _require_hex_equal(expectations.run_identity, receipt_manifest.run_identity, CP_DIAGBUNDLE_SEAM_RUN_IDENTITY)
        if expectations.target_profile_id != receipt_manifest.target_profile_id:
            raise DiagBundleError(CP_DIAGBUNDLE_SEAM_TARGET_PROFILE, "target profile seam mismatch")
        _require_hex_equal(quote_extra_data, outer_manifest.quote_extra_data, CP_DIAGBUNDLE_SEAM_QUOTE_QD)
        revalidate(snapshot)
        return {
            "outer_envelope_address": outer_envelope_address,
            "inner_receipt_digest": inner_receipt_digest,
            "image_binding_address": image_binding_address,
            "input_closure_address": input_closure_address,
            "control_plan_address": control_plan_address,
        }


def _parse_expectations(data: bytes) -> CallerExpectations:
    try:
        raw = _loads(data)
    except DiagBundleError:
        raise
    if type(raw) is not dict or set(raw) != _EXPECTATION_KEYS:
        raise DiagBundleError(CP_DIAGBUNDLE_EXPECTATIONS, "caller expectations have unexpected fields")
    if not _is_sha256(raw.get("input_closure_address")):
        raise DiagBundleError(CP_DIAGBUNDLE_EXPECTATIONS, "caller expectations input_closure_address is invalid")
    if not _is_sha256(raw.get("challenge")):
        raise DiagBundleError(CP_DIAGBUNDLE_EXPECTATIONS, "caller expectations challenge is invalid")
    if not _is_sha256(raw.get("run_identity")):
        raise DiagBundleError(CP_DIAGBUNDLE_EXPECTATIONS, "caller expectations run_identity is invalid")
    if not _is_target_profile(raw.get("target_profile_id")):
        raise DiagBundleError(CP_DIAGBUNDLE_EXPECTATIONS, "caller expectations target_profile_id is invalid")
    if not _is_sha256(raw.get("control_plan_address")):
        raise DiagBundleError(CP_DIAGBUNDLE_EXPECTATIONS, "caller expectations control_plan_address is invalid")
    return CallerExpectations(
        input_closure_address=raw["input_closure_address"],
        challenge=raw["challenge"],
        run_identity=raw["run_identity"],
        target_profile_id=raw["target_profile_id"],
        control_plan_address=raw["control_plan_address"],
    )


def _reject_forbidden_content(path: str, data: bytes, *, allow_pem: bool) -> None:
    if allow_pem:
        for marker in _PRIVATE_KEY_MARKERS:
            if marker in data:
                raise DiagBundleError(CP_DIAGBUNDLE_FORBIDDEN, "member contains a private-key marker")
        return
    try:
        check_content_markers(path, data)
    except ApplianceError as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_FORBIDDEN, str(exc)) from exc


def _domain_address(domain: bytes, obj: dict) -> str:
    return hashlib.sha256(domain + canonical_dumps(obj)).hexdigest()


def _object(data: bytes, keys: frozenset[str]) -> dict:
    raw = _loads(data)
    _require(type(raw) is dict, CP_DIAGBUNDLE_SCHEMA, "document must be a JSON object")
    _require(set(raw) == keys, CP_DIAGBUNDLE_SCHEMA, "document has unexpected fields")
    return raw


def _require_common(raw: dict, schema_id: str, node_kind: str) -> None:
    _require(raw["schema"] == schema_id, CP_DIAGBUNDLE_SCHEMA, "unexpected schema identifier")
    _require(raw["node_kind"] == node_kind, CP_DIAGBUNDLE_NODE_KIND, "unexpected node_kind")
    _require(raw["artifact_state"] == NODE_ARTIFACT_STATE, CP_DIAGBUNDLE_SCHEMA, "unexpected artifact_state")


def _parse_input_row(raw: object) -> InputClosureRow:
    _require(type(raw) is dict and set(raw) == _INPUT_ROW_KEYS, CP_DIAGBUNDLE_SCHEMA, "inventory row has unexpected fields")
    path = raw["path"]
    _require(_is_relative_path(path), CP_DIAGBUNDLE_SCHEMA, "inventory path is invalid")
    _reject_forbidden_path(path)
    _require(raw["role"] in INPUT_CLOSURE_ROLE_SET, CP_DIAGBUNDLE_SCHEMA, "inventory role is invalid")
    _require(raw["content_kind"] in CONTENT_KINDS, CP_DIAGBUNDLE_SCHEMA, "inventory content_kind is invalid")
    _require(type(raw["size_bytes"]) is int and raw["size_bytes"] >= 0, CP_DIAGBUNDLE_SCHEMA, "inventory size_bytes is invalid")
    _require(_is_sha256(raw["sha256"]), CP_DIAGBUNDLE_SCHEMA, "inventory sha256 is invalid")
    return InputClosureRow(
        path=path,
        role=raw["role"],
        content_kind=raw["content_kind"],
        size_bytes=raw["size_bytes"],
        sha256=raw["sha256"],
    )


def _parse_receipt_row(raw: object) -> InnerReceiptRow:
    _require(type(raw) is dict and set(raw) == _RECEIPT_ROW_KEYS, CP_DIAGBUNDLE_SCHEMA, "inventory row has unexpected fields")
    path = raw["path"]
    _require(_is_relative_path(path), CP_DIAGBUNDLE_SCHEMA, "inventory path is invalid")
    _reject_forbidden_path(path)
    if posixpath.basename(path) in _OUTER_MEMBER_BASENAMES:
        raise DiagBundleError(CP_DIAGBUNDLE_SCHEMA, "pre-quote inventory must not reference quote/attestation members")
    _require(raw["content_kind"] in CONTENT_KINDS, CP_DIAGBUNDLE_SCHEMA, "inventory content_kind is invalid")
    _require(type(raw["size_bytes"]) is int and raw["size_bytes"] >= 0, CP_DIAGBUNDLE_SCHEMA, "inventory size_bytes is invalid")
    _require(_is_sha256(raw["sha256"]), CP_DIAGBUNDLE_SCHEMA, "inventory sha256 is invalid")
    return InnerReceiptRow(path=path, content_kind=raw["content_kind"], size_bytes=raw["size_bytes"], sha256=raw["sha256"])


def _parse_size_hash(raw: object) -> tuple[int, str]:
    _require(type(raw) is dict and set(raw) == _SIZE_HASH_KEYS, CP_DIAGBUNDLE_SCHEMA, "member record has unexpected fields")
    _require(type(raw["size_bytes"]) is int and raw["size_bytes"] >= 0, CP_DIAGBUNDLE_SCHEMA, "member size_bytes is invalid")
    _require(_is_sha256(raw["sha256"]), CP_DIAGBUNDLE_SCHEMA, "member sha256 is invalid")
    return (raw["size_bytes"], raw["sha256"])


def _require_input_roles(inventory: tuple[InputClosureRow, ...]) -> None:
    control = [row for row in inventory if row.role == ROLE_CONTROL_PLAN]
    plan_paths = [row for row in inventory if row.path == CONTROL_PLAN_PATH]
    if len(control) != 1 or control[0].path != CONTROL_PLAN_PATH or len(plan_paths) != 1 or plan_paths[0].role != ROLE_CONTROL_PLAN:
        raise DiagBundleError(CP_DIAGBUNDLE_ROLE, _MANDATORY_ROLE_MESSAGE)
    if not INPUT_CLOSURE_ROLE_SET <= {row.role for row in inventory}:
        raise DiagBundleError(CP_DIAGBUNDLE_ROLE, _MANDATORY_ROLE_MESSAGE)


def _require_strictly_increasing(paths: list[str]) -> None:
    for index in range(1, len(paths)):
        if paths[index] <= paths[index - 1]:
            raise DiagBundleError(CP_DIAGBUNDLE_SCHEMA, "inventory paths are not strictly increasing")


def _require_root_shape(snapshot) -> None:
    files = {path for path in snapshot.files if "/" not in path}
    directories = {path for path in snapshot.directories if path and "/" not in path}
    expected_files = {"manifest.json"} | OUTER_FILE_MEMBER_SET
    expected_directories = {"inner-receipt", "signed-image", "input-closure"}
    if files != expected_files or directories != expected_directories:
        raise DiagBundleError(CP_DIAGBUNDLE_GRAPH, "bundle root graph shape is invalid")


def _require_unique_identities(snapshot) -> None:
    seen: dict[tuple[int, int], str] = {}
    for path, pinned in (*snapshot.files.items(), *snapshot.directories.items()):
        key = (pinned.identity[0], pinned.identity[1])
        prior = seen.get(key)
        if prior is not None and prior != path:
            raise DiagBundleError(CP_DIAGBUNDLE_GRAPH, "duplicate node identity in bundle graph")
        seen[key] = path


def _require_subtree_budget(snapshot, prefix: str, *, max_entries: int, max_file_bytes: int, max_total_bytes: int) -> None:
    lead = prefix + "/"
    files = [pinned for path, pinned in snapshot.files.items() if path.startswith(lead)]
    directories = [pinned for path, pinned in snapshot.directories.items() if path.startswith(lead)]
    if len(files) + len(directories) > max_entries:
        raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SIZE, "subtree exceeds max_entries")
    total = 0
    for pinned in files:
        size = pinned.identity[4]
        if size > max_file_bytes:
            raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SIZE, "subtree file exceeds max_file_bytes")
        total += size
    if total > max_total_bytes:
        raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SIZE, "subtree exceeds max_total_bytes")


def _require_outer_member_budget(snapshot) -> None:
    file_members = [name for name in OUTER_FILE_MEMBER_NAMES if name in snapshot.files]
    entries = len(file_members) + (1 if "inner-receipt" in snapshot.directories else 0)
    if entries > 128:
        raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SIZE, "outer envelope exceeds max_entries")
    total = 0
    for name in file_members:
        total += snapshot.files[name].identity[4]
    if total > 20 * _GIB:
        raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SIZE, "outer envelope exceeds max_total_bytes")


def _require_signed_image_file_caps(snapshot) -> None:
    for name, cap in _SIGNED_IMAGE_FILE_CAPS.items():
        pinned = snapshot.files.get("signed-image/" + name)
        if pinned is None:
            continue
        if pinned.identity[4] > cap:
            raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SIZE, "signed-image member exceeds its size cap")


def _require_member_paths(actual: set[str], expected: set[str]) -> None:
    if actual != expected:
        raise DiagBundleError(CP_DIAGBUNDLE_MEMBER, "on-disk members do not match the declared member set")


def _pinned(snapshot, path: str):
    pinned = snapshot.files.get(path)
    if pinned is None:
        raise DiagBundleError(CP_DIAGBUNDLE_GRAPH, "required bundle graph node is missing")
    return pinned


def _subtree_files(snapshot, prefix: str) -> dict:
    lead = prefix + "/"
    return {path[len(lead) :]: pinned for path, pinned in snapshot.files.items() if path.startswith(lead)}


def _reject_forbidden_path(path: str) -> None:
    base = posixpath.basename(path).lower()
    if any(base.endswith(suffix) for suffix in _FORBIDDEN_SUFFIXES) or base in _FORBIDDEN_BASENAMES:
        raise DiagBundleError(CP_DIAGBUNDLE_FORBIDDEN, "path uses a forbidden private-key name")


def _is_relative_path(path: object) -> bool:
    if type(path) is not str or not path or path.startswith("/") or "\x00" in path:
        return False
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    return posixpath.normpath(path) == path


def _is_target_profile(value: object) -> bool:
    return type(value) is str and 1 <= len(value) <= 128 and all(0x20 <= ord(character) <= 0x7E for character in value)


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and value == value.lower() and all(c in "0123456789abcdef" for c in value)


def _require_hex_equal(left: str, right: str, code: str) -> None:
    if not hmac.compare_digest(left, right):
        raise DiagBundleError(code, "bundle graph seam mismatch")


def _loads(data: bytes) -> object:
    try:
        return canonical_loads(data)
    except ApplianceError as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_JSON_INVALID, str(exc)) from exc


def _require(condition: bool, reason_code: str, message: str) -> None:
    if not condition:
        raise DiagBundleError(reason_code, message)
