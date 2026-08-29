#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Schema dispatcher for the isolated SPP boot authority v3 document."""

from __future__ import annotations

from conf_proc_json import canonical_loads
from conf_proc_spp_boot_v3 import BOOT_CONTRACT_V3_SCHEMA, BootContractV3, parse_boot_contract_v3
from conf_proc_spp_reasons_v3 import ApplianceErrorV3, CP_BOOT_V3_SCHEMA


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ApplianceErrorV3(CP_BOOT_V3_SCHEMA, message)


def parse_boot_contract_document_v3(data: bytes) -> BootContractV3:
    """Dispatch only the v3 schema, never a predecessor boot authority."""

    try:
        raw = canonical_loads(data)
    except Exception:
        raise ApplianceErrorV3(CP_BOOT_V3_SCHEMA, "boot contract schema is invalid") from None
    _require(type(raw) is dict and type(raw.get("schema")) is str, "boot contract schema is invalid")
    if raw["schema"] != BOOT_CONTRACT_V3_SCHEMA:
        raise ApplianceErrorV3(CP_BOOT_V3_SCHEMA, "unsupported v3 boot contract schema")
    return parse_boot_contract_v3(data)
