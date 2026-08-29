#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent raw-byte oracle for the finite v2 boot authority vocabulary.

This file intentionally imports no producer/parser module.  It derives only
the literal byte-level claims that a separate implementation must preserve.
"""

from __future__ import annotations

import ast
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from conf_proc_reasons import CP_BOOT_BOOTSTRAP_MOUNT, CP_BOOT_JIT_POLICY, CP_BOOT_NETWORK_POLICY, CP_BOOT_SCHEMA


SHA = "a" * 64
DOMAIN = b"sol-spp-appliance-manifest-v2"
BOOTSTRAP_MOUNTS = (
    ("proc", "/proc", "proc", ("nosuid", "nodev", "noexec"), 0o555, None),
    ("sysfs", "/sys", "sysfs", ("nosuid", "nodev", "noexec"), 0o555, None),
    ("devtmpfs", "/dev", "devtmpfs", ("nosuid", "noexec"), 0o755, None),
    ("tmpfs", "/run", "tmpfs", ("nosuid", "nodev", "noexec"), 0o755, 67108864),
)
OBSERVATION_STATES = (
    "bootstrap_proc", "bootstrap_sysfs", "bootstrap_devtmpfs", "bootstrap_run", "initial_network_apply", "initial_network_readback", "cmdline", "pcr15_zero", "disk_locators", "runtime_map", "runtime_verify", "runtime_mapping_identity", "models_map", "models_verify", "models_mapping_identity", "runtime_mount", "runtime_executable_confinement", "models_mount", "mutable_roots_pre", "tmpfs_create", "mutable_roots_post", "modules", "modules_disabled", "mutable_control", "pcr15_extend", "pcr15_readback", "boot_transport_closed", "serving_transport_claimed", "jit_inputs_checked", "jit_prepare", "jit_outputs_checked", "jit_disabled", "serving_network_apply", "serving_network_readback", "listener_create", "listener_bind", "service_start", "serving_ready", "network_activate", "serving_available",
)
SERVING_NETWORK = (
    "tcp+ra-tls://0.0.0.0:9443",
    "127.0.0.1:8000",
    "127.0.0.1:8100",
    "services.solstone.app",
    "168.63.129.16",
    "/internal/spp/authorize",
    "redirects:none",
    "proxy:none",
)


def _document() -> dict:
    return {
        "schema": "conf-proc-spp-boot-contract/v2", "contract_version": 2,
        "predecessor_sha256": {key: SHA for key in (
            "root_lock_sha256", "runtime_closure_sha256", "verity_rules_sha256", "tcb_identity_sha256", "builder_source_sha256", "policy_sha256", "accepted_manifest_sha256", "kernel_feature_contract_sha256", "trusted_certificate_bundle_sha256",
        )},
        "image_order": ["models", "runtime-policy"],
        "module_roles": {"boot": [{"path": "/usr/lib/modules/a.ko", "sha256": SHA, "signer_certificate_sha256": SHA}], "serving": [{"path": "/usr/lib/modules/b.ko", "sha256": SHA, "signer_certificate_sha256": SHA}]},
        "non_runtime_loadable_modules": [], "tmpfs_mounts": [{"path": "/run/spp-state", "size_bytes": 4096, "mode": 0o700}],
        "mutable_control_order": ["kexec_loading", "sysrq", "unprivileged_bpf", "userfaultfd", "kernel_code_loading", "kernel_debug", "recovery_mode", "writable_executable_roots", "tpm_closure"],
        "observation_contract_sha256": SHA, "gpt_layout_rules_sha256": SHA, "jit_policy": None,
    }


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _frame(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _measurement(*artifacts: bytes) -> bytes:
    if len(artifacts) != 9:
        raise ValueError(CP_BOOT_SCHEMA)
    return hashlib.sha256(DOMAIN + b"\0" + b"".join(_frame(value) for value in artifacts)).digest()


def _accept_bootstrap(mounts: object) -> None:
    if mounts != BOOTSTRAP_MOUNTS:
        raise ValueError(CP_BOOT_BOOTSTRAP_MOUNT)


def _accept_serving_network(policy: object) -> None:
    if policy != SERVING_NETWORK:
        raise ValueError(CP_BOOT_NETWORK_POLICY)


def _accept_observation_states(states: object) -> None:
    if states != OBSERVATION_STATES:
        raise ValueError(CP_BOOT_SCHEMA)


def _accept_document(raw: object) -> None:
    if not isinstance(raw, dict) or raw.get("schema") != "conf-proc-spp-boot-contract/v2" or raw.get("contract_version") != 2:
        raise ValueError(CP_BOOT_SCHEMA)
    if raw.get("image_order") != ["models", "runtime-policy"] or raw.get("mutable_control_order") != ["kexec_loading", "sysrq", "unprivileged_bpf", "userfaultfd", "kernel_code_loading", "kernel_debug", "recovery_mode", "writable_executable_roots", "tpm_closure"]:
        raise ValueError(CP_BOOT_SCHEMA)
    policy = raw.get("jit_policy")
    if policy is not None and (policy.get("compiler_loader_args") != ["--jit-workspace=/run/spp-jit", "--isolated"] or policy.get("workspace", {}).get("path") != "/run/spp-jit" or policy.get("workspace", {}).get("mode") != 0o700):
        raise ValueError(CP_BOOT_JIT_POLICY)


class BootV2RawOracleTests(unittest.TestCase):
    def test_a_raw_document_and_schema_mutation(self) -> None:
        raw = _document()
        _accept_document(raw)
        raw["schema"] = "conf-proc-spp-boot-contract/v1"
        with self.assertRaisesRegex(ValueError, CP_BOOT_SCHEMA):
            _accept_document(raw)

    def test_b_bootstrap_and_network_literals_are_closed(self) -> None:
        _accept_bootstrap(BOOTSTRAP_MOUNTS)
        self.assertEqual(BOOTSTRAP_MOUNTS, (
            ("proc", "/proc", "proc", ("nosuid", "nodev", "noexec"), 0o555, None),
            ("sysfs", "/sys", "sysfs", ("nosuid", "nodev", "noexec"), 0o555, None),
            ("devtmpfs", "/dev", "devtmpfs", ("nosuid", "noexec"), 0o755, None),
            ("tmpfs", "/run", "tmpfs", ("nosuid", "nodev", "noexec"), 0o755, 67108864),
        ))
        mutated = list(BOOTSTRAP_MOUNTS)
        mutated[2] = ("devtmpfs", "/dev", "devtmpfs", ("nosuid", "nodev", "noexec"), 0o755, None)
        for changed in (tuple(mutated), BOOTSTRAP_MOUNTS[1:], BOOTSTRAP_MOUNTS + (BOOTSTRAP_MOUNTS[0],), tuple(reversed(BOOTSTRAP_MOUNTS))):
            with self.assertRaisesRegex(ValueError, CP_BOOT_BOOTSTRAP_MOUNT):
                _accept_bootstrap(changed)
        _accept_serving_network(SERVING_NETWORK)
        self.assertEqual(SERVING_NETWORK[0], "tcp+ra-tls://0.0.0.0:9443")
        self.assertNotIn("::", SERVING_NETWORK)
        for changed in (
            ("tcp+ra-tls://[::]:9443", *SERVING_NETWORK[1:]),
            (SERVING_NETWORK[0], "127.0.0.1:8100", "127.0.0.1:8000", *SERVING_NETWORK[3:]),
            (*SERVING_NETWORK[:3], "other.example", *SERVING_NETWORK[4:]),
            (*SERVING_NETWORK[:5], "/other", *SERVING_NETWORK[6:]),
        ):
            with self.assertRaisesRegex(ValueError, CP_BOOT_NETWORK_POLICY):
                _accept_serving_network(changed)

    def test_c_jit_mutations_and_observation_shape(self) -> None:
        raw = _document()
        raw["jit_policy"] = {"workspace": {"path": "/run/spp-jit", "mode": 0o700}, "compiler_loader_args": ["--jit-workspace=/run/spp-jit", "--isolated"]}
        _accept_document(raw)
        raw["jit_policy"]["compiler_loader_args"].append("--ambient-path")
        with self.assertRaisesRegex(ValueError, CP_BOOT_JIT_POLICY):
            _accept_document(raw)
        _accept_observation_states(OBSERVATION_STATES)
        for changed in (OBSERVATION_STATES[1:], tuple(reversed(OBSERVATION_STATES)), OBSERVATION_STATES + ("serving_available",)):
            with self.assertRaisesRegex(ValueError, CP_BOOT_SCHEMA):
                _accept_observation_states(changed)

    def test_d_framing_order_is_domain_separated(self) -> None:
        artifacts = tuple(bytes([index]) for index in range(9))
        self.assertNotEqual(_measurement(*artifacts), _measurement(*reversed(artifacts)))
        self.assertNotEqual(_measurement(*artifacts), hashlib.sha256(b"sol-spp-appliance-manifest-v1\0" + artifacts[0]).digest())
        self.assertEqual(len(_measurement(*artifacts)), 32)

    def test_e_no_producer_module_import(self) -> None:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        self.assertNotIn("conf_proc_spp_boot", imported)


if __name__ == "__main__":
    unittest.main()
