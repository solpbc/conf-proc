#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared H4/H5 authority fixture for payload producer and inspector tests."""

from __future__ import annotations

import hashlib
import runpy
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

import conf_proc_provenance_v2_inspect as inspector
import conf_proc_spp_boot as boot
from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_provenance_v2_inspect_fixture import build_positive_fixture


SOURCE_ARCHIVE_PATHS = (
    "/usr/lib/spp/conf_proc_geometry.py",
    "/usr/lib/spp/conf_proc_json.py",
    "/usr/lib/spp/conf_proc_lock.py",
    "/usr/lib/spp/conf_proc_module_authority.py",
    "/usr/lib/spp/conf_proc_policy.py",
    "/usr/lib/spp/conf_proc_provenance_v2.py",
    "/usr/lib/spp/conf_proc_provenance_v2_manifest.py",
    "/usr/lib/spp/conf_proc_reasons.py",
    "/usr/lib/spp/conf_proc_spp_boot.py",
)

_BOOT_TEST = runpy.run_path(str(ROOT / "test" / "conf-proc-spp-boot-selftest.py"))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def matching_h4_h5() -> tuple[object, inspector.InspectionResult, boot.BootBinding]:
    """Build a real H3 bundle that is also a fresh H5 binding predecessor."""

    fixture = build_positive_fixture()
    h3 = fixture.h3
    policy = canonical_loads(h3.policy_bytes)
    policy["boot_roots"] = ["unit:h3.service"]
    policy["mounts"] = [
        {"unit_id": "unit:h3.service", "image": "models", "destination": "/mnt/spp-models", "fs_type": "squashfs", "read_only": True},
        {"unit_id": "unit:h3.service", "image": "runtime-policy", "destination": "/mnt/spp-runtime", "fs_type": "squashfs", "read_only": True},
    ]
    serve_path = "/usr/lib/modules/h3/serve.ko"
    policy["images"]["runtime-policy"]["nodes"].append(
        {
            "path": serve_path,
            "node_type": "file",
            "mode": 0o644,
            "uid": h3.uid,
            "gid": h3.gid,
            "xattrs": [],
            "source_input_id": "driver",
            "target": None,
            "content_class": "runtime_data",
        }
    )
    policy["images"]["runtime-policy"]["nodes"].sort(key=lambda item: item["path"])
    h3.policy_bytes = canonical_dumps(policy)
    Path(h3.policy_path).write_bytes(h3.policy_bytes)
    h3.contents["policy-copy.json"] = h3.policy_bytes
    Path(h3._input("policy-copy.json")).write_bytes(h3.policy_bytes)
    h3.placements.append(
        {
            "image": "runtime-policy",
            "path": serve_path,
            "node_type": "file",
            "mode": 0o644,
            "uid": h3.uid,
            "gid": h3.gid,
            "xattrs": [],
            "source_input_id": "driver",
            "target": None,
        }
    )
    h3.placements.sort(key=lambda item: (item["image"], item["path"]))
    h3._write_lock(False)

    lock = canonical_loads(Path(h3.lock_path).read_bytes())
    kernel_sha256 = next(item["sha256"] for item in lock["inputs"] if item["role"] == "kernel")
    kernel_feature_contract_bytes = canonical_dumps(
        {
            "schema": "conf-proc-kernel-features/v1",
            "kernel_input_sha256": kernel_sha256,
            "kernel_release": "h3-fixture",
            "mutable_controls": [{"name": name, "support": "required"} for name in sorted(boot._CONTROL_ORDER)],
        }
    )
    tcb = canonical_loads(Path(h3.tcb_path).read_bytes())
    tcb["kernel_feature_contract"]["sha256"] = _sha256(kernel_feature_contract_bytes)
    Path(h3.tcb_path).write_bytes(canonical_dumps(tcb))

    assembly = h3.assemble()
    inspection_kwargs = fixture.inspect_kwargs()
    inspection_kwargs["bundle"] = assembly.bundle_path
    inspection = inspector.inspect_bundle(**inspection_kwargs)
    manifest_bytes = Path(assembly.bundle_path, "appliance.manifest.json").read_bytes()
    manifest = canonical_loads(manifest_bytes)
    identities = sorted(
        (
            {
                "path": item["path"],
                "sha256": item["sha256"],
                "signer_certificate_sha256": item["signer_certificate_sha256"],
            }
            for item in manifest["module_authority"]["module_inventory"]
        ),
        key=lambda item: item["path"],
    )
    if len(identities) != 2:
        raise AssertionError("real H3 fixture did not produce the required two-module H5 inventory")
    compact = _BOOT_TEST["build_compact_fixture"]()
    source_bytes = {
        "root_lock_bytes": Path(h3.lock_path).read_bytes(),
        "runtime_closure_bytes": Path(h3.closure_path).read_bytes(),
        "verity_rules_bytes": Path(h3.rules_path).read_bytes(),
        "tcb_identity_bytes": Path(h3.tcb_path).read_bytes(),
        "builder_source_bytes": Path(h3._input("source.py")).read_bytes(),
        "policy_bytes": Path(h3.policy_path).read_bytes(),
        "accepted_manifest_bytes": manifest_bytes,
        "kernel_feature_contract_bytes": kernel_feature_contract_bytes,
        "trusted_certificate_bundle_bytes": Path(h3._input("bundle.pem")).read_bytes(),
        "gpt_layout_rules_bytes": compact["gpt_layout_rules_bytes"],
    }
    predecessor = {
        name.removesuffix("_bytes") + "_sha256": _sha256(value)
        for name, value in source_bytes.items()
        if name != "gpt_layout_rules_bytes"
    }
    contract = {
        "schema": "conf-proc-spp-boot-contract/v1",
        "contract_version": 1,
        "predecessor_sha256": predecessor,
        "image_order": ["models", "runtime-policy"],
        "module_roles": {"boot": [identities[0]], "serving": [identities[1]]},
        "non_runtime_loadable_modules": [],
        "tmpfs_mounts": [{"path": "/run/spp-state", "size_bytes": 1048576, "mode": 0o755}],
        "mutable_control_order": list(boot._CONTROL_ORDER),
        "observation_contract_sha256": boot.OBSERVATION_CONTRACT_SHA256,
        "gpt_layout_rules_sha256": _sha256(source_bytes["gpt_layout_rules_bytes"]),
    }
    boot_contract_bytes = canonical_dumps(contract)
    module_plan_bytes = canonical_dumps(
        {
            "schema": "conf-proc-spp-module-load-plan/v1",
            "plan_version": 1,
            "boot_contract_sha256": _sha256(boot_contract_bytes),
            "measurement_scope": "future-pcr4-only",
            "entries": [
                {"index": index, **identity, "predecessor_indices": list(range(index))}
                for index, identity in enumerate(identities)
            ],
        }
    )
    binding = boot.bind_boot_inputs(
        **source_bytes,
        boot_contract_bytes=boot_contract_bytes,
        module_plan_bytes=module_plan_bytes,
    )
    return fixture, inspection, binding


def plan_bytes(binding: boot.BootBinding, source_paths: list[str]) -> bytes:
    return canonical_dumps(
        {
            "schema": "conf-proc-spp-boot-payload-plan/v1",
            "plan_version": 1,
            "boot_contract_sha256": binding.boot_contract_sha256,
            "module_plan_sha256": binding.module_plan_sha256,
            "entries": [
                {"archive_path": archive_path, "source_path": source_path}
                for archive_path, source_path in zip(SOURCE_ARCHIVE_PATHS, source_paths, strict=True)
            ],
        }
    )
