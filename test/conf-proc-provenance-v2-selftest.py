#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Hostile-input tests for dormant provenance-v2 contracts and derivation."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_provenance_v2 as provenance  # noqa: E402
import conf_proc_reasons as reasons  # noqa: E402
from conf_proc_json import canonical_dumps, canonical_loads  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


_SINGLE_ROLES = (
    "kernel",
    "kernel_trusted_cert_bundle",
    "final_systemd_stub",
    "final_systemd_unit",
    "nvidia_cc_driver",
    "nvidia_cc_firmware",
    "sglang_image",
    "inference_model",
    "asr_model",
    "gateway_dependency_lock",
    "asr_dependency_lock",
)
_TOOL_DIGESTS = {
    "mksquashfs": format(41, "064x"),
    "unsquashfs": format(42, "064x"),
    "veritysetup": format(43, "064x"),
    "openssl": format(44, "064x"),
}


def _sha(value: int) -> str:
    return format(value, "064x")


def _policy_bytes(*, schema: str = "conf-proc-policy/v1", variant: str = "base") -> bytes:
    return canonical_dumps({"schema": schema, "variant": variant})


def _placement(input_id: str, path: str) -> dict:
    return {
        "image": "runtime-policy",
        "path": path,
        "node_type": "file",
        "mode": 0o644,
        "uid": 0,
        "gid": 0,
        "xattrs": [],
        "source_input_id": input_id,
        "target": None,
    }


def _lock_input(
    input_id: str,
    role: str,
    digest: str,
    size_bytes: int,
    *,
    component: str | None = None,
    scheme: str = "local-fixture",
    identity: str | None = None,
    placements: list[dict] | None = None,
) -> dict:
    if placements is None:
        placements = (
            []
            if role in ("build_tool", "kernel_trusted_cert_bundle")
            else [_placement(input_id, f"/fixture/{input_id}")]
        )
    return {
        "id": input_id,
        "role": role,
        "component": component or input_id,
        "sha256": digest,
        "size_bytes": size_bytes,
        "source_local_path": f"fixtures/{input_id}",
        "source_retrieval_scheme": scheme,
        "source_retrieval_identity": identity or f"fixture:{input_id}",
        "source_retrieval_immutable_ref": f"sha256:{digest}",
        "derivation_kind": "fixture",
        "derivation_recipe_id": "fixture-recipe-v1",
        "derivation_parent_ids": [],
        "derivation_parameters_sha256": _sha(91),
        "placements": placements,
    }


def _lock_bytes(builder_source_bytes: bytes, policy_bytes: bytes) -> bytes:
    builder_digest = hashlib.sha256(builder_source_bytes).hexdigest()
    policy_digest = hashlib.sha256(policy_bytes).hexdigest()
    inputs = [
        _lock_input(
            "builder",
            "conf_proc_source",
            builder_digest,
            len(builder_source_bytes),
            component="conf-proc-source",
            scheme="git",
            identity="fixture:repository",
            placements=[_placement("builder", "/opt/conf-proc/main.py")],
        ),
        _lock_input(
            "policy",
            "policy_tree_input",
            policy_digest,
            len(policy_bytes),
            component="process-policy",
            scheme="generated",
            identity="fixture:policy",
            placements=[_placement("policy", "/etc/spp/policy.json")],
        ),
    ]
    for index, role in enumerate(_SINGLE_ROLES, start=10):
        inputs.append(_lock_input(role, role, _sha(index), 1))
    for tool, digest in _TOOL_DIGESTS.items():
        inputs.append(_lock_input(f"tool-{tool}", "build_tool", digest, 12, component=tool))
    inputs.sort(key=lambda item: item["id"])

    return canonical_dumps(
        {
            "schema": "conf-proc-lock/v1",
            "lock_version": 1,
            "base_image_record": {
                "kind": "vhd",
                "provider": "fixture",
                "identity_namespace": "fixture-ns",
                "identity_name": "fixture-image",
                "identity_immutable_revision": "fixture-revision",
                "content_sha256": _sha(3),
                "content_size_bytes": 100,
                "content_media_type": "application/octet-stream",
                "availability": "record-only",
                "recorded_retrieval_scheme": "local-fixture",
                "recorded_retrieval_identity": "fixture:base-image",
                "recorded_retrieval_immutable_ref": "fixture:immutable-base",
            },
            "future_cmdline": "console=ttyS0",
            "inputs": inputs,
            "authorized_module_signers": [],
            "image_specs": {"models": {}, "runtime-policy": {}},
            "policy_input_id": "policy",
            "tool_ids": sorted(f"tool-{tool}" for tool in _TOOL_DIGESTS),
        }
    )


def _closure_entry(
    *,
    path: str,
    digest: str,
    size_bytes: int,
    logical_role: str,
    scheme: str,
    identity: str,
    root_lock_input_id: str | None,
) -> dict:
    return {
        "path": path,
        "node_type": "file",
        "mode": 0o755,
        "uid": 0,
        "gid": 0,
        "size_bytes": size_bytes,
        "sha256": digest,
        "symlink_target": None,
        "hardlink_group": None,
        "xattrs": [],
        "capabilities": [],
        "logical_role": logical_role,
        "provenance": {
            "scheme": scheme,
            "identity": identity,
            "immutable_ref": f"sha256:{digest}",
        },
        "root_lock_input_id": root_lock_input_id,
    }


def _closure_bytes(builder_source_bytes: bytes) -> bytes:
    builder_digest = hashlib.sha256(builder_source_bytes).hexdigest()
    entries = [
        _closure_entry(
            path="/opt/conf-proc/main.py",
            digest=builder_digest,
            size_bytes=len(builder_source_bytes),
            logical_role="conf_proc_source",
            scheme="git",
            identity="fixture:repository",
            root_lock_input_id="builder",
        ),
        _closure_entry(
            path="/usr/bin/mksquashfs",
            digest=_TOOL_DIGESTS["mksquashfs"],
            size_bytes=12,
            logical_role="build_tool",
            scheme="local-fixture",
            identity="fixture:tool-mksquashfs",
            root_lock_input_id="tool-mksquashfs",
        ),
    ]
    return canonical_dumps(
        {
            "schema": "conf-proc-runtime-closure/v1",
            "status": "declared_unverified",
            "entries": entries,
        }
    )


def _rules_bytes() -> bytes:
    return canonical_dumps(
        {
            "schema": "conf-proc-verity-rules/v1",
            "image_ids": ["models", "runtime-policy"],
            "hash_algorithm": "sha256",
            "data_block_size": 4096,
            "hash_block_size": 4096,
            "image_padding_rule": "zero-to-data-block-boundary",
            "squashfs": {
                "append": False,
                "quiet": True,
                "progress": False,
                "exit_on_error": True,
                "reproducible": True,
                "processors": 1,
                "block_size": 131072,
                "fragments": True,
                "tailends": False,
                "duplicate_data_detection": True,
                "hardlink_detection": True,
                "xattrs": True,
                "export_table": True,
                "sparse_file_detection": True,
                "inode_compression": True,
                "id_table_compression": True,
                "data_compression": True,
                "fragment_compression": True,
                "xattr_compression": True,
                "filesystem_padding_4k": True,
                "output_offset_bytes": 0,
                "gzip": {"compression_level": 9, "window_size": 15, "strategies": ["default"]},
                "all_time_source": "derived-build-epoch",
                "mkfs_time_source": "derived-build-epoch",
                "compression": "gzip",
                "root_mode": 493,
                "root_uid": 0,
                "root_gid": 0,
                "pseudo_file": "required",
            },
            "verity": {
                "format": "veritysetup-format-v1",
                "superblock": True,
                "data_device_offset_bytes": 0,
                "hash_offset_bytes": 0,
                "fec": "disabled",
            },
            "build_epoch": {
                "domain_ascii": "conf-proc/build-clock/v1",
                "preimage_fields": ["domain_ascii", "artifact_input_digest_bytes"],
                "utc_range_start": 946684800,
                "utc_range_end": 4102444799,
                "digest_prefix_bytes": 8,
            },
            "salt": {
                "domain_ascii": "conf-proc/verity-salt/v1",
                "preimage_fields": ["domain_ascii", "image_id_ascii", "artifact_input_digest_bytes"],
                "length_bytes": 32,
                "encoding": "lowercase-hex",
            },
            "uuid": {
                "domain_ascii": "conf-proc/verity-uuid/v1",
                "preimage_fields": ["domain_ascii", "image_id_ascii", "artifact_input_digest_bytes"],
                "digest_prefix_bytes": 16,
                "rfc4122_version": 5,
                "rfc4122_variant": "10",
            },
        }
    )


def _executable(name: str, digest: str) -> dict:
    return {
        "logical_name": name,
        "sha256": digest,
        "linkage": "static",
        "interpreter_sha256": None,
        "loader_sha256": None,
        "library_sha256s": [],
    }


def _tcb_bytes() -> bytes:
    return canonical_dumps(
        {
            "schema": "conf-proc-pre-sandbox-tcb/v1",
            "status": "declared_unverified",
            "caller": _executable("caller", _sha(71)),
            "launcher": _executable("launcher", _sha(72)),
            "sandbox": {
                "backend": "bubblewrap",
                "executable": _executable("bwrap", _sha(73)),
                "helper": None,
            },
            "kernel_feature_contract": {"schema": "conf-proc-kernel-features/v1", "sha256": _sha(74)},
        }
    )


def _authority_bundle() -> dict[str, bytes]:
    builder_source_bytes = b"fixture-builder-source-v2"
    policy_bytes = _policy_bytes()
    return {
        "root_lock_bytes": _lock_bytes(builder_source_bytes, policy_bytes),
        "runtime_closure_bytes": _closure_bytes(builder_source_bytes),
        "verity_rules_bytes": _rules_bytes(),
        "tcb_identity_bytes": _tcb_bytes(),
        "builder_source_bytes": builder_source_bytes,
        "policy_bytes": policy_bytes,
    }


def _derive(**overrides) -> provenance.ProvenanceInputs:
    values = _authority_bundle()
    values.update(overrides)
    return provenance.derive_inputs(**values)


class ProvenanceV2Tests(unittest.TestCase):
    def assert_rejected(self, callback, expected_reason: str) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            callback()
        self.assertEqual(ctx.exception.reason_code, expected_reason)
        self.assertIn(ctx.exception.reason_code, reasons.ALL_REASON_CODES)

    def test_derives_identity_from_valid_authorities(self) -> None:
        values = _authority_bundle()
        result = provenance.derive_inputs(**values)
        digests = {key: hashlib.sha256(value).hexdigest() for key, value in values.items()}
        self.assertEqual(result.artifact_input_schema, "conf-proc-lock/v1")
        self.assertEqual(result.artifact_input_sha256, digests["root_lock_bytes"])
        self.assertEqual(result.runtime_closure_sha256, digests["runtime_closure_bytes"])
        self.assertEqual(result.verity_rules_sha256, digests["verity_rules_bytes"])
        self.assertEqual(result.tcb_identity_sha256, digests["tcb_identity_bytes"])
        self.assertEqual(result.builder_source_sha256, digests["builder_source_bytes"])
        self.assertEqual(result.policy_sha256, digests["policy_bytes"])
        envelope = {
            "schema": "conf-proc-execution-provenance/v1",
            "artifact_input_sha256": result.artifact_input_sha256,
            "runtime_closure_sha256": result.runtime_closure_sha256,
            "verity_rules_sha256": result.verity_rules_sha256,
            "tcb_identity_sha256": result.tcb_identity_sha256,
            "builder_source_sha256": result.builder_source_sha256,
            "policy_sha256": result.policy_sha256,
        }
        self.assertEqual(result.execution_provenance_sha256, hashlib.sha256(canonical_dumps(envelope)).hexdigest())
        self.assertEqual(provenance.supported_verity_rules_bytes(), values["verity_rules_bytes"])

    def test_rejects_skeletal_or_mutated_root_lock_authority(self) -> None:
        for mutate in (
            lambda raw: raw.update(schema="conf-proc-lock/v2"),
            lambda raw: raw.update(lock_version=2),
            lambda raw: raw.pop("base_image_record"),
            lambda raw: raw.update(image_specs={"models": {"block_size": 4096}, "runtime-policy": {}}),
            lambda raw: raw["tool_ids"].pop(),
            lambda raw: next(item for item in raw["inputs"] if item["id"] == "tool-unsquashfs").update(component="mksquashfs"),
            lambda raw: raw.update(inputs=[item for item in raw["inputs"] if item["role"] != "kernel"]),
        ):
            raw = canonical_loads(_authority_bundle()["root_lock_bytes"])
            mutate(raw)
            self.assert_rejected(
                lambda raw=raw: _derive(root_lock_bytes=canonical_dumps(raw)),
                "CP_PROVENANCE_AUTHORITY",
            )

    def test_rejects_policy_authority_mismatch_or_unsupported_schema(self) -> None:
        values = _authority_bundle()
        for field, value in (("sha256", _sha(201)), ("size_bytes", 1)):
            raw = canonical_loads(values["root_lock_bytes"])
            next(item for item in raw["inputs"] if item["id"] == "policy")[field] = value
            self.assert_rejected(
                lambda raw=raw: _derive(root_lock_bytes=canonical_dumps(raw)),
                "CP_PROVENANCE_AUTHORITY",
            )

        self.assert_rejected(
            lambda: _derive(policy_bytes=_policy_bytes(variant="different")),
            "CP_PROVENANCE_AUTHORITY",
        )

        unsupported_policy = _policy_bytes(schema="conf-proc-policy/v2")
        builder = values["builder_source_bytes"]
        self.assert_rejected(
            lambda: _derive(
                root_lock_bytes=_lock_bytes(builder, unsupported_policy),
                policy_bytes=unsupported_policy,
            ),
            "CP_PROVENANCE_AUTHORITY",
        )

    def test_rejects_non_singleton_builder_source_designation(self) -> None:
        raw = canonical_loads(_authority_bundle()["runtime_closure_bytes"])
        raw["entries"] = [entry for entry in raw["entries"] if entry["logical_role"] != "conf_proc_source"]
        self.assert_rejected(
            lambda: _derive(runtime_closure_bytes=canonical_dumps(raw)),
            "CP_PROVENANCE_AUTHORITY",
        )

        raw = canonical_loads(_authority_bundle()["runtime_closure_bytes"])
        duplicate = dict(raw["entries"][0])
        duplicate["path"] = "/opt/conf-proc/alternate.py"
        raw["entries"].append(duplicate)
        raw["entries"].sort(key=lambda entry: entry["path"])
        self.assert_rejected(
            lambda: _derive(runtime_closure_bytes=canonical_dumps(raw)),
            "CP_PROVENANCE_AUTHORITY",
        )

    def test_rejects_closure_to_lock_disagreements(self) -> None:
        for mutate in (
            lambda entry: entry.update(sha256=_sha(211)),
            lambda entry: entry.update(size_bytes=99),
            lambda entry: entry.update(logical_role="runtime_tree_input"),
            lambda entry: entry["provenance"].update(scheme="https"),
            lambda entry: entry["provenance"].update(identity="fixture:other"),
            lambda entry: entry["provenance"].update(immutable_ref=f"sha256:{_sha(212)}"),
            lambda entry: entry.update(root_lock_input_id="missing-input"),
        ):
            raw = canonical_loads(_authority_bundle()["runtime_closure_bytes"])
            mutate(raw["entries"][1])
            self.assert_rejected(
                lambda raw=raw: _derive(runtime_closure_bytes=canonical_dumps(raw)),
                "CP_PROVENANCE_AUTHORITY",
            )

    def test_rejects_impossible_hardlinks_and_runtime_paths(self) -> None:
        raw = canonical_loads(_authority_bundle()["runtime_closure_bytes"])
        raw["entries"][0]["hardlink_group"] = _sha(221)
        self.assert_rejected(
            lambda: provenance.parse_runtime_closure(canonical_dumps(raw)),
            "CP_RUNTIME_CLOSURE_SCHEMA",
        )

        raw = canonical_loads(_authority_bundle()["runtime_closure_bytes"])
        first = dict(raw["entries"][0])
        first.update(path="/a", hardlink_group=_sha(222), root_lock_input_id=None)
        second = dict(first)
        second.update(path="/b", uid=1)
        raw["entries"] = [first, second]
        self.assert_rejected(
            lambda: provenance.parse_runtime_closure(canonical_dumps(raw)),
            "CP_RUNTIME_CLOSURE_SCHEMA",
        )

        raw = canonical_loads(_authority_bundle()["runtime_closure_bytes"])
        raw["entries"][1].update(node_type="symlink", sha256=None, symlink_target="../../escape", root_lock_input_id=None)
        self.assert_rejected(
            lambda: provenance.parse_runtime_closure(canonical_dumps(raw)),
            "CP_RUNTIME_CLOSURE_SCHEMA",
        )

        for field, value in (("node_type", "device"), ("mode", 0o4755)):
            raw = canonical_loads(_authority_bundle()["runtime_closure_bytes"])
            raw["entries"][0][field] = value
            self.assert_rejected(
                lambda raw=raw: provenance.parse_runtime_closure(canonical_dumps(raw)),
                "CP_RUNTIME_CLOSURE_SCHEMA",
            )

    def test_rejects_empty_or_non_declared_runtime_closure(self) -> None:
        raw = canonical_loads(_authority_bundle()["runtime_closure_bytes"])
        raw["entries"] = []
        self.assert_rejected(
            lambda: provenance.parse_runtime_closure(canonical_dumps(raw)),
            "CP_RUNTIME_CLOSURE_SCHEMA",
        )

        raw = canonical_loads(_authority_bundle()["runtime_closure_bytes"])
        raw["status"] = "verified"
        self.assert_rejected(
            lambda: provenance.parse_runtime_closure(canonical_dumps(raw)),
            "CP_PROVENANCE_STATUS",
        )

    def test_rejects_nested_verity_rule_mutations(self) -> None:
        for mutate in (
            lambda raw: raw["squashfs"].update(processors=2),
            lambda raw: raw["squashfs"]["gzip"].update(compression_level=8),
            lambda raw: raw["verity"].update(hash_offset_bytes=4096),
        ):
            raw = canonical_loads(_rules_bytes())
            mutate(raw)
            self.assert_rejected(
                lambda raw=raw: provenance.parse_verity_rules(canonical_dumps(raw)),
                "CP_VERITY_RULES_SCHEMA",
            )

    def test_rejects_incomplete_dynamic_tcb_and_unknown_kernel_contract(self) -> None:
        raw = canonical_loads(_tcb_bytes())
        raw["launcher"]["linkage"] = "dynamic"
        self.assert_rejected(
            lambda: provenance.parse_tcb_identity(canonical_dumps(raw)),
            "CP_TCB_IDENTITY_SCHEMA",
        )

        raw = canonical_loads(_tcb_bytes())
        raw["kernel_feature_contract"]["schema"] = "conf-proc-kernel-features/v2"
        self.assert_rejected(
            lambda: provenance.parse_tcb_identity(canonical_dumps(raw)),
            "CP_TCB_IDENTITY_SCHEMA",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
