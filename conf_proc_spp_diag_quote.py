#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""TPM quote invocation for the SPP diagnostic controller.

Uses the shared PCR selection (conf_proc_spp_diag_pcr) and the shared quote-qualifying-
data constructor (conf_proc_spp_diagbundle_protocol.quote_qualifying_data) -- never
re-derives either by hand, per the two-extraction requirement this lode exists to
satisfy. Never imports conf_proc_spp_diag_attest or any other appraiser module; the
quote command is constructed and issued here, appraised only later, elsewhere.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable, Final

from conf_proc_spp_diag_pcr import SPP_DIAG_PCR_SELECTION
from conf_proc_spp_diagbundle_protocol import quote_qualifying_data


# Fixed persistent AK handle convention for this appliance (senior-engineer decision;
# not given by any upstream literal spec).
FIXED_AK_HANDLE: Final = "0x81010002"
FIXED_HASH_ALGORITHM: Final = "sha256"


@dataclass(frozen=True)
class QuoteInvocation:
    argv: tuple[str, ...]
    qualifying_data: bytes


def build_quote_invocation(
    *,
    challenge: bytes,
    run_identity: bytes,
    inner_receipt_digest: str,
    signed_image_binding_address: str,
    target_profile_id: str,
    control_plan_address: str,
    quote_msg_out: str,
    quote_sig_out: str,
    quote_pcrs_out: str,
) -> QuoteInvocation:
    """Build the exact tpm2_quote argv using only the shared-module PCR selection and
    the shared quote-qualifying-data constructor -- fields fixed, no caller-declared
    command surface beyond the six output/identity parameters above."""

    qd_hex = quote_qualifying_data(
        challenge=challenge.hex(),
        control_plan_address=control_plan_address,
        inner_receipt_digest=inner_receipt_digest,
        run_identity=run_identity.hex(),
        signed_image_binding_address=signed_image_binding_address,
        target_profile_id=target_profile_id,
    )
    qualifying_data = bytes.fromhex(qd_hex)
    pcr_list = ",".join(str(index) for index in SPP_DIAG_PCR_SELECTION)
    argv = (
        "tpm2_quote",
        "-c",
        FIXED_AK_HANDLE,
        "-l",
        f"{FIXED_HASH_ALGORITHM}:{pcr_list}",
        "-q",
        qualifying_data.hex(),
        "-m",
        quote_msg_out,
        "-s",
        quote_sig_out,
        "-o",
        quote_pcrs_out,
        "-g",
        FIXED_HASH_ALGORITHM,
    )
    return QuoteInvocation(argv=argv, qualifying_data=qualifying_data)


@dataclass
class QuoteOps:
    run_tool: Callable[[tuple[str, ...]], "subprocess.CompletedProcess"]


def run_quote(ops: QuoteOps, invocation: QuoteInvocation) -> "subprocess.CompletedProcess":
    return ops.run_tool(invocation.argv)


def real_run_tool(argv: tuple[str, ...]) -> "subprocess.CompletedProcess":
    return subprocess.run(list(argv), capture_output=True, check=False)
