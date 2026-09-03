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

from dataclasses import dataclass
from typing import Callable, Final

from conf_proc_spp_diag_pcr import SPP_DIAG_PCR_SELECTION
from conf_proc_spp_diagbundle_protocol import quote_qualifying_data


FIXED_AK_HANDLE: Final = "0x81000003"
FIXED_HASH_ALGORITHM: Final = "sha256"
TPM2_QUOTE_PATH: Final = "/usr/bin/tpm2_quote"
QUOTE_OUTPUT_MSG: Final = "/run/spp-diag/quote.msg"
QUOTE_OUTPUT_SIG: Final = "/run/spp-diag/quote.sig"
QUOTE_OUTPUT_PCRS: Final = "/run/spp-diag/quote.pcrs"
QUOTE_ENVIRONMENT: Final = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
QUOTE_DEADLINE_SECONDS: Final = 30.0
QUOTE_OUTPUT_CAP_BYTES: Final = 1_048_576


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
) -> QuoteInvocation:
    """Build the exact tpm2_quote argv using only the shared-module PCR selection and
    the shared quote-qualifying-data constructor -- fields fixed, no caller-declared
    command surface beyond the identity parameters above."""

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
        TPM2_QUOTE_PATH,
        "-c",
        FIXED_AK_HANDLE,
        "-l",
        f"{FIXED_HASH_ALGORITHM}:{pcr_list}",
        "-q",
        qualifying_data.hex(),
        "-g",
        FIXED_HASH_ALGORITHM,
        "--scheme",
        "rsassa",
        "-m",
        QUOTE_OUTPUT_MSG,
        "-s",
        QUOTE_OUTPUT_SIG,
        "-o",
        QUOTE_OUTPUT_PCRS,
    )
    return QuoteInvocation(argv=argv, qualifying_data=qualifying_data)


@dataclass
class QuoteOps:
    run_tool: Callable[[tuple[str, ...], dict[str, str], float, int], object]


class SppDiagQuoteError(RuntimeError):
    pass


def run_quote(ops: QuoteOps, invocation: QuoteInvocation) -> object:
    result = ops.run_tool(
        invocation.argv,
        dict(QUOTE_ENVIRONMENT),
        QUOTE_DEADLINE_SECONDS,
        QUOTE_OUTPUT_CAP_BYTES,
    )
    if getattr(result, "returncode", None) != 0:
        raise SppDiagQuoteError("TPM quote child failed")
    return result
