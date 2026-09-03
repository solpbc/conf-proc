#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Shared diagnostic-bundle address protocol for appraiser and appliance producer; imports no appraiser-only validation code."""

from __future__ import annotations

import hashlib
from typing import Final

from conf_proc_json import canonical_dumps


DOMAIN_INPUT_CLOSURE: Final = b"sol-spp-diagbundle-input-closure-v1\0"
DOMAIN_IMAGE_BINDING: Final = b"sol-spp-diagbundle-image-binding-v1\0"
DOMAIN_INNER_RECEIPT: Final = b"sol-spp-diagbundle-inner-receipt-v1\0"
DOMAIN_CONTROL_PLAN: Final = b"sol-spp-diagbundle-control-plan-v1\0"
DOMAIN_QUOTE_QD: Final = b"sol-spp-diagbundle-quote-qd-v1\0"
DOMAIN_OUTER_ENVELOPE: Final = b"sol-spp-diagbundle-outer-envelope-v1\0"

INPUT_CLOSURE_ROLES: Final = (
    "source_tree_manifest",
    "build_recipe",
    "toolchain_lock",
    "resolved_configuration",
    "kernel_configuration",
    "trace_policy",
    "canonical_control_plan",
    "runtime_manifest",
    "model_manifest",
    "producer_source",
    "controller_source",
    "signer_public_policy",
)


def domain_address(domain: bytes, obj: dict) -> str:
    return hashlib.sha256(domain + canonical_dumps(obj)).hexdigest()


def image_binding_address(*, schema, node_kind, artifact_state, layout, input_closure_address, members) -> str:
    return domain_address(
        DOMAIN_IMAGE_BINDING,
        {
            "schema": schema,
            "node_kind": node_kind,
            "artifact_state": artifact_state,
            "layout": layout,
            "input_closure_address": input_closure_address,
            "members": members,
        },
    )


def inner_receipt_digest(
    *,
    schema,
    node_kind,
    artifact_state,
    challenge,
    run_identity,
    signed_image_binding_address,
    target_profile_id,
    control_plan_address,
    inventory,
) -> str:
    return domain_address(
        DOMAIN_INNER_RECEIPT,
        {
            "schema": schema,
            "node_kind": node_kind,
            "artifact_state": artifact_state,
            "challenge": challenge,
            "run_identity": run_identity,
            "signed_image_binding_address": signed_image_binding_address,
            "target_profile_id": target_profile_id,
            "control_plan_address": control_plan_address,
            "inventory": inventory,
        },
    )


def quote_qualifying_data(
    *,
    challenge,
    control_plan_address,
    inner_receipt_digest,
    run_identity,
    signed_image_binding_address,
    target_profile_id,
) -> str:
    return domain_address(
        DOMAIN_QUOTE_QD,
        {
            "challenge": challenge,
            "control_plan_address": control_plan_address,
            "inner_receipt_digest": inner_receipt_digest,
            "run_identity": run_identity,
            "signed_image_binding_address": signed_image_binding_address,
            "target_profile_id": target_profile_id,
        },
    )
