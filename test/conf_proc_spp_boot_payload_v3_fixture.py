#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Shared issued authority fixture for SPP boot v3 payload tests."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

from conf_proc_json import canonical_dumps
from conf_proc_spp_boot_payload_v3 import _PLAN_SCHEMA_V3
from conf_proc_spp_boot_v3 import BootBindingV3, bind_boot_inputs_v3, parse_boot_contract_v3
from conf_proc_spp_boot_payload_fixture import matching_h4_h5


SOURCE_ARCHIVE_PATHS_V3 = (
    "/usr/lib/spp/conf_proc_geometry.py",
    "/usr/lib/spp/conf_proc_json.py",
    "/usr/lib/spp/conf_proc_lock.py",
    "/usr/lib/spp/conf_proc_module_authority.py",
    "/usr/lib/spp/conf_proc_policy.py",
    "/usr/lib/spp/conf_proc_provenance_v2.py",
    "/usr/lib/spp/conf_proc_provenance_v2_manifest.py",
    "/usr/lib/spp/conf_proc_reasons.py",
    "/usr/lib/spp/conf_proc_spp_boot.py",
    "/usr/lib/spp/conf_proc_spp_boot_dispatch_v3.py",
    "/usr/lib/spp/conf_proc_spp_boot_v3.py",
    "/usr/lib/spp/conf_proc_spp_boot_v3_resource.py",
    "/usr/lib/spp/conf_proc_spp_boot_v3_tables.py",
    "/usr/lib/spp/conf_proc_spp_boot_v3_wire.py",
    "/usr/lib/spp/conf_proc_spp_reasons_v3.py",
)
_INPUT_NAMES = (
    "root_lock_bytes",
    "runtime_closure_bytes",
    "verity_rules_bytes",
    "tcb_identity_bytes",
    "builder_source_bytes",
    "policy_bytes",
    "accepted_manifest_bytes",
    "kernel_feature_contract_bytes",
    "trusted_certificate_bundle_bytes",
    "module_plan_bytes",
    "gpt_layout_rules_bytes",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def matching_h4_h5_v3() -> tuple[object, object, BootBindingV3]:
    """Build a real inspection paired with a freshly issued v3 binding."""

    h4_fixture, inspection, predecessor = matching_h4_h5()
    inputs = {
        name: f"spp-boot-v3-payload-fixture:{name}".encode("ascii")
        for name in _INPUT_NAMES
    }
    inputs["accepted_manifest_bytes"] = predecessor.accepted_manifest_bytes
    document = {"schema": "conf-proc-spp-boot-contract/v3", "contract_version": 3}
    document.update(
        {
            name.removesuffix("_bytes") + "_sha256": _sha256(inputs[name])
            for name in _INPUT_NAMES
        }
    )
    boot_contract_bytes = canonical_dumps(document)
    binding = bind_boot_inputs_v3(
        contract=parse_boot_contract_v3(boot_contract_bytes),
        **inputs,
        boot_contract_bytes=boot_contract_bytes,
    )
    return h4_fixture, inspection, binding


def plan_bytes_v3(binding: BootBindingV3, source_paths: list[str]) -> bytes:
    return canonical_dumps(
        {
            "schema": _PLAN_SCHEMA_V3,
            "plan_version": 3,
            "boot_contract_sha256": binding.boot_contract_sha256,
            "module_plan_sha256": _sha256(binding.module_plan_bytes),
            "entries": [
                {"archive_path": archive_path, "source_path": source_path}
                for archive_path, source_path in zip(SOURCE_ARCHIVE_PATHS_V3, source_paths, strict=True)
            ],
        }
    )
