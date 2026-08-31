#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Stable reason codes and failure type for the diagnostic-bundle codec."""

from __future__ import annotations

from typing import Final


NODE_ARTIFACT_STATE: Final = "diagnostic_unqualified"

CP_DIAGBUNDLE_SNAPSHOT_READ: Final = "CP_DIAGBUNDLE_SNAPSHOT_READ"
CP_DIAGBUNDLE_SNAPSHOT_SHAPE: Final = "CP_DIAGBUNDLE_SNAPSHOT_SHAPE"
CP_DIAGBUNDLE_SNAPSHOT_SIZE: Final = "CP_DIAGBUNDLE_SNAPSHOT_SIZE"
CP_DIAGBUNDLE_CONCURRENT_MUTATION: Final = "CP_DIAGBUNDLE_CONCURRENT_MUTATION"
CP_DIAGBUNDLE_INTERNAL: Final = "CP_DIAGBUNDLE_INTERNAL"
CP_DIAGBUNDLE_PE_FORMAT: Final = "CP_DIAGBUNDLE_PE_FORMAT"
CP_DIAGBUNDLE_DESCRIPTOR_MISSING: Final = "CP_DIAGBUNDLE_DESCRIPTOR_MISSING"
CP_DIAGBUNDLE_DESCRIPTOR_DUPLICATE: Final = "CP_DIAGBUNDLE_DESCRIPTOR_DUPLICATE"
CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED: Final = "CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED"
CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS: Final = "CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS"
CP_DIAGBUNDLE_DESCRIPTOR_COVERAGE: Final = "CP_DIAGBUNDLE_DESCRIPTOR_COVERAGE"
CP_DIAGBUNDLE_DESCRIPTOR_MISMATCH: Final = "CP_DIAGBUNDLE_DESCRIPTOR_MISMATCH"
CP_DIAGBUNDLE_JSON_INVALID: Final = "CP_DIAGBUNDLE_JSON_INVALID"
CP_DIAGBUNDLE_SCHEMA: Final = "CP_DIAGBUNDLE_SCHEMA"
CP_DIAGBUNDLE_NODE_KIND: Final = "CP_DIAGBUNDLE_NODE_KIND"
CP_DIAGBUNDLE_GRAPH: Final = "CP_DIAGBUNDLE_GRAPH"
CP_DIAGBUNDLE_LAYOUT: Final = "CP_DIAGBUNDLE_LAYOUT"
CP_DIAGBUNDLE_MEMBER: Final = "CP_DIAGBUNDLE_MEMBER"
CP_DIAGBUNDLE_ROLE: Final = "CP_DIAGBUNDLE_ROLE"
CP_DIAGBUNDLE_TERMINAL_FRAME: Final = "CP_DIAGBUNDLE_TERMINAL_FRAME"
CP_DIAGBUNDLE_FORBIDDEN: Final = "CP_DIAGBUNDLE_FORBIDDEN"
CP_DIAGBUNDLE_SEAM_INPUT_CLOSURE: Final = "CP_DIAGBUNDLE_SEAM_INPUT_CLOSURE"
CP_DIAGBUNDLE_SEAM_SPPDIAG: Final = "CP_DIAGBUNDLE_SEAM_SPPDIAG"
CP_DIAGBUNDLE_SEAM_IMAGE_FIELD: Final = "CP_DIAGBUNDLE_SEAM_IMAGE_FIELD"
CP_DIAGBUNDLE_SEAM_IMAGE_BINDING: Final = "CP_DIAGBUNDLE_SEAM_IMAGE_BINDING"
CP_DIAGBUNDLE_SEAM_INNER_RECEIPT: Final = "CP_DIAGBUNDLE_SEAM_INNER_RECEIPT"
CP_DIAGBUNDLE_SEAM_CONTROL_PLAN: Final = "CP_DIAGBUNDLE_SEAM_CONTROL_PLAN"
CP_DIAGBUNDLE_SEAM_QUOTE_QD: Final = "CP_DIAGBUNDLE_SEAM_QUOTE_QD"
CP_DIAGBUNDLE_SEAM_CHALLENGE: Final = "CP_DIAGBUNDLE_SEAM_CHALLENGE"
CP_DIAGBUNDLE_SEAM_RUN_IDENTITY: Final = "CP_DIAGBUNDLE_SEAM_RUN_IDENTITY"
CP_DIAGBUNDLE_SEAM_TARGET_PROFILE: Final = "CP_DIAGBUNDLE_SEAM_TARGET_PROFILE"
CP_DIAGBUNDLE_EXPECTATIONS: Final = "CP_DIAGBUNDLE_EXPECTATIONS"

RECOVERY_RETRY_AFTER_INPUT_FIX: Final = "retry_after_input_fix"
RECOVERY_RETRY_AFTER_ENVIRONMENT_FIX: Final = "retry_after_environment_fix"
RECOVERY_NOT_RECOVERABLE_STRUCTURAL: Final = "not_recoverable_structural"
RECOVERY_CALLER_EXPECTATION_MISMATCH: Final = "caller_expectation_mismatch"

ALL_REASON_CODES_DIAGBUNDLE: Final = frozenset(
    {
        CP_DIAGBUNDLE_SNAPSHOT_READ,
        CP_DIAGBUNDLE_SNAPSHOT_SHAPE,
        CP_DIAGBUNDLE_SNAPSHOT_SIZE,
        CP_DIAGBUNDLE_CONCURRENT_MUTATION,
        CP_DIAGBUNDLE_INTERNAL,
        CP_DIAGBUNDLE_PE_FORMAT,
        CP_DIAGBUNDLE_DESCRIPTOR_MISSING,
        CP_DIAGBUNDLE_DESCRIPTOR_DUPLICATE,
        CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED,
        CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS,
        CP_DIAGBUNDLE_DESCRIPTOR_COVERAGE,
        CP_DIAGBUNDLE_DESCRIPTOR_MISMATCH,
        CP_DIAGBUNDLE_JSON_INVALID,
        CP_DIAGBUNDLE_SCHEMA,
        CP_DIAGBUNDLE_NODE_KIND,
        CP_DIAGBUNDLE_GRAPH,
        CP_DIAGBUNDLE_LAYOUT,
        CP_DIAGBUNDLE_MEMBER,
        CP_DIAGBUNDLE_ROLE,
        CP_DIAGBUNDLE_TERMINAL_FRAME,
        CP_DIAGBUNDLE_FORBIDDEN,
        CP_DIAGBUNDLE_SEAM_INPUT_CLOSURE,
        CP_DIAGBUNDLE_SEAM_SPPDIAG,
        CP_DIAGBUNDLE_SEAM_IMAGE_FIELD,
        CP_DIAGBUNDLE_SEAM_IMAGE_BINDING,
        CP_DIAGBUNDLE_SEAM_INNER_RECEIPT,
        CP_DIAGBUNDLE_SEAM_CONTROL_PLAN,
        CP_DIAGBUNDLE_SEAM_QUOTE_QD,
        CP_DIAGBUNDLE_SEAM_CHALLENGE,
        CP_DIAGBUNDLE_SEAM_RUN_IDENTITY,
        CP_DIAGBUNDLE_SEAM_TARGET_PROFILE,
        CP_DIAGBUNDLE_EXPECTATIONS,
    }
)

ALL_RECOVERY_CLASSES: Final = frozenset(
    {
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        RECOVERY_RETRY_AFTER_ENVIRONMENT_FIX,
        RECOVERY_NOT_RECOVERABLE_STRUCTURAL,
        RECOVERY_CALLER_EXPECTATION_MISMATCH,
    }
)

REASON_RECOVERY: Final = {
    CP_DIAGBUNDLE_SNAPSHOT_READ: (
        RECOVERY_RETRY_AFTER_ENVIRONMENT_FIX,
        "retry the snapshot against a readable diagnostic-bundle directory",
    ),
    CP_DIAGBUNDLE_SNAPSHOT_SHAPE: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "replace symlinks, special files, and hardlinked members with regular files and directories",
    ),
    CP_DIAGBUNDLE_SNAPSHOT_SIZE: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "reduce the diagnostic-bundle tree so it fits the snapshot size budget",
    ),
    CP_DIAGBUNDLE_CONCURRENT_MUTATION: (
        RECOVERY_RETRY_AFTER_ENVIRONMENT_FIX,
        "retry the snapshot against an unchanged diagnostic-bundle directory",
    ),
    CP_DIAGBUNDLE_INTERNAL: (
        RECOVERY_NOT_RECOVERABLE_STRUCTURAL,
        "report an internal diagnostic-bundle snapshot fault",
    ),
    CP_DIAGBUNDLE_PE_FORMAT: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "rebuild the UKI PE/COFF headers so they parse as a well-formed image",
    ),
    CP_DIAGBUNDLE_DESCRIPTOR_MISSING: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "add exactly one .sppdiag section to the signed UKI",
    ),
    CP_DIAGBUNDLE_DESCRIPTOR_DUPLICATE: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "remove the extra .sppdiag sections so exactly one remains",
    ),
    CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "rebuild the .sppdiag section so its logical length, padding, and raw size are consistent",
    ),
    CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "mark the .sppdiag section as initialized, readable data that is not code, writable, shared, or executable",
    ),
    CP_DIAGBUNDLE_DESCRIPTOR_COVERAGE: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "move the .sppdiag section so it does not intersect the PE CheckSum field or Certificate Table",
    ),
    CP_DIAGBUNDLE_DESCRIPTOR_MISMATCH: (
        RECOVERY_CALLER_EXPECTATION_MISMATCH,
        "rebuild the input closure or UKI so the embedded descriptor address matches the expected address",
    ),
    CP_DIAGBUNDLE_JSON_INVALID: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "rebuild the document as valid canonical JSON with no duplicate keys",
    ),
    CP_DIAGBUNDLE_SCHEMA: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "fix the document so it matches the closed diagnostic-bundle schema",
    ),
    CP_DIAGBUNDLE_NODE_KIND: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "set node_kind to the exact discriminator this position in the bundle graph requires",
    ),
    CP_DIAGBUNDLE_GRAPH: (
        RECOVERY_NOT_RECOVERABLE_STRUCTURAL,
        "rebuild the bundle root so it has exactly the required graph nodes with no extras",
    ),
    CP_DIAGBUNDLE_LAYOUT: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "use the exact required layout identifier for this node",
    ),
    CP_DIAGBUNDLE_MEMBER: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "make the on-disk member set match the manifest's declared member set exactly",
    ),
    CP_DIAGBUNDLE_ROLE: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "declare exactly one canonical control plan row and at least one row for every mandatory role",
    ),
    CP_DIAGBUNDLE_TERMINAL_FRAME: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "set the terminal frame to the single accepted intent-to-export value",
    ),
    CP_DIAGBUNDLE_FORBIDDEN: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "remove the forbidden private-key name or content from the declared input",
    ),
    CP_DIAGBUNDLE_SEAM_INPUT_CLOSURE: (
        RECOVERY_CALLER_EXPECTATION_MISMATCH,
        "rebuild the input closure so its derived address matches the caller-expected input-closure address",
    ),
    CP_DIAGBUNDLE_SEAM_SPPDIAG: (
        RECOVERY_CALLER_EXPECTATION_MISMATCH,
        "rebuild the UKI's .sppdiag descriptor so its address matches the derived input-closure address",
    ),
    CP_DIAGBUNDLE_SEAM_IMAGE_FIELD: (
        RECOVERY_CALLER_EXPECTATION_MISMATCH,
        "rebuild the signed-image manifest so its input_closure_address field matches the derived input-closure address",
    ),
    CP_DIAGBUNDLE_SEAM_IMAGE_BINDING: (
        RECOVERY_CALLER_EXPECTATION_MISMATCH,
        "rebuild the inner receipt so its signed_image_binding_address matches the derived image-binding address",
    ),
    CP_DIAGBUNDLE_SEAM_INNER_RECEIPT: (
        RECOVERY_CALLER_EXPECTATION_MISMATCH,
        "rebuild the outer envelope so its inner_receipt_digest matches the derived inner receipt digest",
    ),
    CP_DIAGBUNDLE_SEAM_CONTROL_PLAN: (
        RECOVERY_CALLER_EXPECTATION_MISMATCH,
        "rebuild the control plan reference so every side agrees with the derived control-plan address",
    ),
    CP_DIAGBUNDLE_SEAM_QUOTE_QD: (
        RECOVERY_CALLER_EXPECTATION_MISMATCH,
        "rebuild the outer envelope so its quote_extra_data matches the derived qualifying-data value",
    ),
    CP_DIAGBUNDLE_SEAM_CHALLENGE: (
        RECOVERY_CALLER_EXPECTATION_MISMATCH,
        "rebuild the inner receipt under the caller-supplied challenge",
    ),
    CP_DIAGBUNDLE_SEAM_RUN_IDENTITY: (
        RECOVERY_CALLER_EXPECTATION_MISMATCH,
        "rebuild the inner receipt under the caller-supplied run identity",
    ),
    CP_DIAGBUNDLE_SEAM_TARGET_PROFILE: (
        RECOVERY_CALLER_EXPECTATION_MISMATCH,
        "rebuild the inner receipt under the caller-supplied target profile identifier",
    ),
    CP_DIAGBUNDLE_EXPECTATIONS: (
        RECOVERY_RETRY_AFTER_INPUT_FIX,
        "fix the caller-expectations document so it is a closed object with the required fields",
    ),
}


class DiagBundleError(RuntimeError):
    """A diagnostic-bundle failure with a stable reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        if reason_code not in ALL_REASON_CODES_DIAGBUNDLE:
            raise ValueError(f"unknown diagnostic-bundle reason code: {reason_code!r}")
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


def recovery_for(reason_code: str) -> tuple[str, str]:
    mapped = REASON_RECOVERY.get(reason_code)
    if mapped is None:
        raise DiagBundleError(CP_DIAGBUNDLE_INTERNAL, "reason code has no recovery class")
    return mapped
