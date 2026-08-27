#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Known-answer and hostile-input tests for the dormant v2 provenance oracle."""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_inspect_provenance as oracle  # noqa: E402
import conf_proc_reasons as reasons  # noqa: E402
canonical_dumps = oracle.canonical_dumps
ApplianceError = oracle.ApplianceError


def _sha(value: int) -> str:
    return format(value, "064x")


def _root_placement(input_id: str, path: str) -> dict:
    return {
        "image": "runtime-policy",
        "path": path,
        "node_type": "file",
        "mode": 420,
        "uid": 0,
        "gid": 0,
        "xattrs": [],
        "source_input_id": input_id,
        "target": None,
    }


def _root_input(
    input_id: str,
    role: str,
    digest: str,
    size: int,
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
            else [_root_placement(input_id, "/fixture/" + input_id)]
        )
    return {
        "id": input_id,
        "role": role,
        "component": component or input_id,
        "sha256": digest,
        "size_bytes": size,
        "source_local_path": "fixtures/" + input_id,
        "source_retrieval_scheme": scheme,
        "source_retrieval_identity": identity or "fixture:" + input_id,
        "source_retrieval_immutable_ref": "sha256:" + digest,
        "derivation_kind": "fixture",
        "derivation_recipe_id": "literal-recipe-v1",
        "derivation_parent_ids": [],
        "derivation_parameters_sha256": _sha(90),
        "placements": placements,
    }


def _policy_bytes(boot_root: str | None = None) -> bytes:
    return canonical_dumps(
        {
            "schema": "conf-proc-policy/v1",
            "policy_version": 1,
            "images": {"models": {"nodes": []}, "runtime-policy": {"nodes": []}},
            "boot_roots": [] if boot_root is None else [boot_root],
            "process_nodes": [],
            "process_edges": [],
            "mounts": [],
            "network_policy": {},
            "capability_policy": {},
        }
    )


def _lock_bytes(
    content_sha: str = _sha(1),
    *,
    builder_source_bytes: bytes = b"literal-builder-source-v1",
    policy_bytes: bytes | None = None,
) -> bytes:
    if policy_bytes is None:
        policy_bytes = _policy_bytes()
    builder_sha = hashlib.sha256(builder_source_bytes).hexdigest()
    policy_sha = hashlib.sha256(policy_bytes).hexdigest()
    inputs = [
        _root_input(
            "builder",
            "conf_proc_source",
            builder_sha,
            len(builder_source_bytes),
            component="conf-proc-builder",
            scheme="git",
            identity="conf-proc",
            placements=[_root_placement("builder", "/opt/conf-proc/conf_proc_build.py")],
        ),
        _root_input(
            "policy",
            "policy_tree_input",
            policy_sha,
            len(policy_bytes),
            component="process-policy",
            scheme="generated",
            identity="policy",
            placements=[_root_placement("policy", "/etc/spp/policy.json")],
        ),
        _root_input("python", "build_tool", content_sha, 12, component="python3"),
    ]
    for index, role in enumerate(
        (
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
        ),
        start=10,
    ):
        inputs.append(_root_input(role, role, _sha(index), 1))
    for index, tool in enumerate(("mksquashfs", "openssl", "unsquashfs", "veritysetup"), start=30):
        inputs.append(_root_input("tool-" + tool, "build_tool", _sha(index), 1, component=tool))
    inputs.sort(key=lambda item: item["id"])
    return canonical_dumps(
        {
            "schema": "conf-proc-lock/v1",
            "lock_version": 1,
            "base_image_record": {
                "kind": "vhd",
                "provider": "fixture",
                "identity_namespace": "literal",
                "identity_name": "base",
                "identity_immutable_revision": "sha256:" + _sha(40),
                "content_sha256": _sha(40),
                "content_size_bytes": 1,
                "content_media_type": "application/octet-stream",
                "availability": "record-only",
                "recorded_retrieval_scheme": "local-fixture",
                "recorded_retrieval_identity": "fixture:base",
                "recorded_retrieval_immutable_ref": "sha256:" + _sha(40),
            },
            "future_cmdline": "console=ttyS0",
            "inputs": inputs,
            "authorized_module_signers": [],
            "image_specs": {"models": {}, "runtime-policy": {}},
            "policy_input_id": "policy",
            "tool_ids": sorted(["python"] + ["tool-" + tool for tool in ("mksquashfs", "openssl", "unsquashfs", "veritysetup")]),
        }
    )


def _closure_bytes(
    content_sha: str = _sha(1),
    *,
    builder_source_bytes: bytes = b"literal-builder-source-v1",
) -> bytes:
    builder_sha = hashlib.sha256(builder_source_bytes).hexdigest()
    return canonical_dumps(
        {
            "schema": "conf-proc-runtime-closure/v1",
            "status": "declared_unverified",
            "entries": [
                {
                    "path": "/opt/conf-proc/conf_proc_build.py",
                    "node_type": "file",
                    "mode": 420,
                    "uid": 0,
                    "gid": 0,
                    "size_bytes": len(builder_source_bytes),
                    "sha256": builder_sha,
                    "symlink_target": None,
                    "hardlink_group": None,
                    "xattrs": [],
                    "capabilities": [],
                    "logical_role": "conf_proc_source",
                    "provenance": {
                        "scheme": "git",
                        "identity": "conf-proc",
                        "immutable_ref": "sha256:" + builder_sha,
                    },
                    "root_lock_input_id": "builder",
                },
                {
                    "path": "/usr/bin/python3",
                    "node_type": "file",
                    "mode": 493,
                    "uid": 0,
                    "gid": 0,
                    "size_bytes": 12,
                    "sha256": content_sha,
                    "symlink_target": None,
                    "hardlink_group": None,
                    "xattrs": [],
                    "capabilities": [],
                    "logical_role": "build_tool",
                    "provenance": {"scheme": "local-fixture", "identity": "fixture:python", "immutable_ref": "sha256:" + content_sha},
                    "root_lock_input_id": "python",
                }
            ],
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


def _tcb_bytes(digest: str = _sha(2)) -> bytes:
    return canonical_dumps(
        {
            "schema": "conf-proc-pre-sandbox-tcb/v1",
            "status": "declared_unverified",
            "caller": _executable("caller", digest),
            "launcher": _executable("launcher", _sha(3)),
            "sandbox": {"backend": "bubblewrap", "executable": _executable("bwrap", _sha(4)), "helper": None},
            "kernel_feature_contract": {"schema": "conf-proc-kernel-features/v1", "sha256": _sha(5)},
        }
    )


def _derive(**overrides) -> oracle.ProvenanceInputs:
    values = {
        "root_lock_bytes": _lock_bytes(),
        "runtime_closure_bytes": _closure_bytes(),
        "verity_rules_bytes": oracle.supported_verity_rules_bytes(),
        "tcb_identity_bytes": _tcb_bytes(),
        "builder_source_bytes": b"literal-builder-source-v1",
        "policy_bytes": _policy_bytes(),
    }
    values.update(overrides)
    if "root_lock_bytes" not in overrides and (
        "builder_source_bytes" in overrides or "policy_bytes" in overrides
    ):
        values["root_lock_bytes"] = _lock_bytes(
            builder_source_bytes=values["builder_source_bytes"],
            policy_bytes=values["policy_bytes"],
        )
    if "runtime_closure_bytes" not in overrides and "builder_source_bytes" in overrides:
        values["runtime_closure_bytes"] = _closure_bytes(
            builder_source_bytes=values["builder_source_bytes"]
        )
    return oracle.derive_inputs(**values)


def _manifest(inputs: oracle.ProvenanceInputs) -> bytes:
    root = oracle.canonical_loads(inputs.root_lock_bytes)
    root_inputs = {item["id"]: item for item in root["inputs"]}
    manifest_inputs = [
        {key: value for key, value in item.items() if key not in {"component", "source_local_path"}}
        for item in root["inputs"]
    ]
    inventory = {"models": [], "runtime-policy": []}
    for item in root["inputs"]:
        for placement in item["placements"]:
            inventory[placement["image"]].append(
                {
                    "path": placement["path"],
                    "node_type": placement["node_type"],
                    "mode": placement["mode"],
                    "uid": placement["uid"],
                    "gid": placement["gid"],
                    "xattrs": placement["xattrs"],
                    "sha256": item["sha256"] if placement["node_type"] == "file" else None,
                    "size_bytes": item["size_bytes"] if placement["node_type"] == "file" else None,
                    "symlink_target": placement["target"],
                    "source_input_id": placement["source_input_id"],
                }
            )
    for records in inventory.values():
        records.sort(key=lambda record: record["path"])
    trusted_bundle_id = next(
        item["id"] for item in root["inputs"] if item["role"] == "kernel_trusted_cert_bundle"
    )
    image = {
        "squashfs_sha256": _sha(10),
        "squashfs_size_bytes": 4096,
        "hash_device_sha256": _sha(11),
        "hash_device_size_bytes": 4096,
        "root_hash": _sha(12),
        "data_block_size": 4096,
        "hash_block_size": 4096,
        "hash_algorithm": "sha256",
        "salt": _sha(13),
        "uuid": "00000000-0000-5000-8000-000000000000",
    }
    empty_bindings = {"executables": [], "configs": [], "models": [], "runtime_inputs": []}
    return canonical_dumps(
        {
            "schema": "conf-proc-appliance-manifest/v2",
            "manifest_version": 2,
            "lock_schema": inputs.artifact_input_schema,
            "lock_sha256": inputs.artifact_input_sha256,
            "reproducibility": {
                "build_epoch": oracle._build_epoch(inputs.artifact_input_sha256),
                "sort_order": "byte-wise-path",
                "codec": "conf-proc-canonical-json/v1",
            },
            "base_image_record": root["base_image_record"],
            "future_cmdline": root["future_cmdline"],
            "images": {"models": image, "runtime-policy": image},
            "inputs": manifest_inputs,
            "inventory": inventory,
            "bindings": {"models": empty_bindings, "runtime-policy": empty_bindings},
            "policy": {
                "policy_input_id": root["policy_input_id"],
                "policy_schema": oracle.canonical_loads(inputs.policy_bytes)["schema"],
                "process_policy_sha256": inputs.policy_sha256,
            },
            "module_authority": {
                "trusted_bundle_input_id": trusted_bundle_id,
                "authorized_signer_certificate_sha256": [
                    signer["certificate_sha256"] for signer in root["authorized_module_signers"]
                ],
                "module_inventory": [],
                "firmware_inventory": [],
            },
            "toolchain": [
                {
                    "tool_id": tool_id,
                    "component": root_inputs[tool_id]["component"],
                    "resolved_path_sha256": root_inputs[tool_id]["sha256"],
                }
                for tool_id in root["tool_ids"]
            ],
            "sbom": {
                "filename": "appliance.spdx.json",
                "sha256": hashlib.sha256(_sbom(inputs)).hexdigest(),
                "spdx_version": "SPDX-2.3",
                "document_spdx_id": "SPDXRef-DOCUMENT",
            },
            "provenance": {
                "schema": "conf-proc-execution-provenance-binding/v1",
                "artifact_input_sha256": inputs.artifact_input_sha256,
                "execution_provenance_sha256": inputs.execution_provenance_sha256,
                "runtime_closure": {"sha256": inputs.runtime_closure_sha256, "status": "declared_unverified"},
                "verity_rules_sha256": inputs.verity_rules_sha256,
                "tcb_identity": {"sha256": inputs.tcb_identity_sha256, "status": "declared_unverified"},
                "builder_source_sha256": inputs.builder_source_sha256,
                "policy_sha256": inputs.policy_sha256,
            },
        }
    )


def _sbom(inputs: oracle.ProvenanceInputs) -> bytes:
    values = {
        "conf-proc-artifact-input": inputs.artifact_input_sha256,
        "conf-proc-builder-source": inputs.builder_source_sha256,
        "conf-proc-execution-provenance": inputs.execution_provenance_sha256,
        "conf-proc-policy": inputs.policy_sha256,
        "conf-proc-runtime-closure": inputs.runtime_closure_sha256,
        "conf-proc-tcb-identity": inputs.tcb_identity_sha256,
        "conf-proc-verity-rules": inputs.verity_rules_sha256,
    }
    refs = [
        {"referenceCategory": "OTHER", "referenceType": kind, "referenceLocator": "sha256:" + values[kind]}
        for kind in sorted(values)
    ]
    appliance = {
        "SPDXID": "SPDXRef-Package-appliance",
        "name": "conf-proc-appliance",
        "downloadLocation": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "supplier": "NOASSERTION",
        "originator": "NOASSERTION",
        "checksums": [{"algorithm": "SHA256", "checksumValue": inputs.artifact_input_sha256}],
        "primaryPackagePurpose": "APPLICATION",
        "externalRefs": refs,
    }
    return canonical_dumps(
        {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "conf-proc-appliance-" + inputs.artifact_input_sha256[:16],
            "documentNamespace": oracle._spdx_namespace(inputs.artifact_input_sha256),
            "creationInfo": {
                "created": oracle._build_timestamp(inputs.artifact_input_sha256),
                "creators": ["Tool: conf-proc-sbom-v1"],
            },
            "packages": [appliance],
            "files": [],
            "relationships": [],
            "documentDescribes": ["SPDXRef-Package-appliance"],
        }
    )


class ProvenanceOracleTests(unittest.TestCase):
    def test_literal_digest_vectors(self) -> None:
        inputs = _derive()
        self.assertEqual(inputs.artifact_input_sha256, "4b125d64245bb15977d274df6c71bb40f79a3ba1fe9baebb358bf968b278b2d6")
        self.assertEqual(inputs.runtime_closure_sha256, "bcaa6ad7f1a76e1dd7a712a5837cd76737b5d4bcd274e244135fa99c04409423")
        self.assertEqual(inputs.verity_rules_sha256, "aece6264c1666c9b83f80756842ace68a9ed74a9cad42a9758699d961605e059")
        self.assertEqual(inputs.tcb_identity_sha256, "2edbe10694ed9914152a2b98ab357a1906f6a1ca2fda15fed71926ee34e479eb")
        self.assertEqual(inputs.builder_source_sha256, "9654bf8dfd2eccdce8dc5928f89d6c07402efffdd438fdeaeb2c8aa2955a08c1")
        self.assertEqual(inputs.policy_sha256, "0e6f3b9e7fc837e0af8a83ca78cc3537d24158c45686c2963b9e9560ad95ca86")
        self.assertEqual(inputs.execution_provenance_sha256, "b8db8d23981bfe474b4480508da7a911488b79cf79fd30e68950f727760de1b7")

    def test_artifact_and_execution_identity_truth_table(self) -> None:
        baseline = _derive()
        changed_lock = _derive(root_lock_bytes=_lock_bytes(_sha(9)), runtime_closure_bytes=_closure_bytes(_sha(9)))
        changed_tcb = _derive(tcb_identity_bytes=_tcb_bytes(_sha(8)))
        self.assertNotEqual(changed_lock.artifact_input_sha256, baseline.artifact_input_sha256)
        self.assertNotEqual(changed_lock.execution_provenance_sha256, baseline.execution_provenance_sha256)
        self.assertEqual(changed_tcb.artifact_input_sha256, baseline.artifact_input_sha256)
        self.assertNotEqual(changed_tcb.execution_provenance_sha256, baseline.execution_provenance_sha256)

    def test_second_literal_vector_proves_named_components(self) -> None:
        # Independent literals pin changes to two separately named components;
        # neither raw concatenation nor positional framing can substitute for
        # the canonical, field-named execution envelope.
        left = _derive(builder_source_bytes=b"ab", policy_bytes=_policy_bytes())
        right = _derive(builder_source_bytes=b"a", policy_bytes=_policy_bytes("variant"))
        self.assertEqual(left.execution_provenance_sha256, "b4a19d5c98c26811cef74c1b5dbc49f8ba6f083f10295536573122c413539364")
        self.assertEqual(right.execution_provenance_sha256, "8b8b7913c05aff0a83193c52ee6ec75a817676be3acc5f1defd4c5208a5e9c6f")
        self.assertNotEqual(left.execution_provenance_sha256, right.execution_provenance_sha256)

    def test_reject_root_lock_authority_disagreement(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            _derive(runtime_closure_bytes=_closure_bytes(_sha(7)))
        self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_AUTHORITY")

    def test_reject_policy_or_builder_bytes_outside_root_lock_authority(self) -> None:
        root = _lock_bytes()
        for override in (
            {"root_lock_bytes": root, "policy_bytes": _policy_bytes("different")},
            {"root_lock_bytes": root, "builder_source_bytes": b"different-builder"},
        ):
            with self.assertRaises(ApplianceError) as ctx:
                _derive(**override)
            self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_AUTHORITY")

    def test_reject_skeletal_or_ambiguous_root_lock_authority(self) -> None:
        for mutate in (
            lambda raw: raw.update(schema="literal-root-lock/v1"),
            lambda raw: raw.update(lock_version=True),
            lambda raw: raw.pop("base_image_record"),
            lambda raw: raw.update(image_specs={"models": {"block_size": 4096}, "runtime-policy": {}}),
            lambda raw: raw["inputs"][0].pop("component"),
            lambda raw: raw["inputs"][0].update(role=[]),
            lambda raw: raw["inputs"][0]["placements"][0].update(image={}),
            lambda raw: raw["inputs"][0]["placements"][0].update(path="//fixture/kernel"),
            lambda raw: raw["tool_ids"].pop(),
            lambda raw: next(item for item in raw["inputs"] if item["id"] == "python").update(component="mksquashfs"),
        ):
            raw = oracle.canonical_loads(_lock_bytes())
            mutate(raw)
            with self.assertRaises(ApplianceError) as ctx:
                _derive(root_lock_bytes=canonical_dumps(raw))
            self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_AUTHORITY")

    def test_reject_root_lock_role_or_provenance_disagreement(self) -> None:
        for field, value in (("logical_role", "runtime_tree_input"), ("provenance", {"scheme": "package", "identity": "other", "immutable_ref": "sha256:" + _sha(1)})):
            raw = oracle.canonical_loads(_closure_bytes())
            raw["entries"][0][field] = value
            with self.assertRaises(ApplianceError) as ctx:
                _derive(runtime_closure_bytes=canonical_dumps(raw))
            self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_AUTHORITY")

    def test_reject_multiple_designated_builder_sources(self) -> None:
        raw = oracle.canonical_loads(_closure_bytes())
        duplicate = {**raw["entries"][0], "path": "/opt/conf-proc/other.py"}
        raw["entries"] = [raw["entries"][0], duplicate, raw["entries"][1]]
        with self.assertRaises(ApplianceError) as ctx:
            _derive(runtime_closure_bytes=canonical_dumps(raw))
        self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_AUTHORITY")

    def test_reject_impossible_hardlink_metadata(self) -> None:
        raw = oracle.canonical_loads(_closure_bytes())
        first = {
            **raw["entries"][0],
            "path": "/a",
            "hardlink_group": _sha(31),
            "root_lock_input_id": None,
        }
        second = {**first, "path": "/b", "uid": 1}
        raw["entries"] = [first, second]
        with self.assertRaises(ApplianceError) as ctx:
            oracle.parse_runtime_closure(canonical_dumps(raw))
        self.assertEqual(ctx.exception.reason_code, "CP_RUNTIME_CLOSURE_SCHEMA")

    def test_reject_runtime_path_escape_and_special_node(self) -> None:
        raw = oracle.canonical_loads(_closure_bytes())
        for field, value in (
            ("path", "//usr/bin/python3"),
            ("path", "/usr/../etc/passwd"),
            ("path", "/usr/bin/python3\x00hidden"),
            ("node_type", "device"),
        ):
            changed = {**raw, "entries": [{**raw["entries"][0], field: value}]}
            with self.assertRaises(ApplianceError) as ctx:
                oracle.parse_runtime_closure(canonical_dumps(changed))
            self.assertEqual(ctx.exception.reason_code, "CP_RUNTIME_CLOSURE_SCHEMA")

    def test_reject_empty_or_false_proven_runtime_closure(self) -> None:
        for mutation in (
            {"schema": "conf-proc-runtime-closure/v1", "status": "declared_unverified", "entries": []},
            {"schema": "conf-proc-runtime-closure/v1", "status": "verified", "entries": []},
        ):
            with self.assertRaises(ApplianceError):
                oracle.parse_runtime_closure(canonical_dumps(mutation))

    def test_reject_hidden_verity_default_or_rule_mutation(self) -> None:
        rules = oracle.parse_verity_rules(oracle.supported_verity_rules_bytes())
        for path, value in (("superblock", False), ("fec", "implicit-default"), ("hash_offset_bytes", 4096)):
            changed = {**rules, "verity": {**rules["verity"], path: value}}
            with self.assertRaises(ApplianceError) as ctx:
                oracle.parse_verity_rules(canonical_dumps(changed))
            self.assertEqual(ctx.exception.reason_code, "CP_VERITY_RULES_SCHEMA")
        changed = {**rules, "squashfs": {**rules["squashfs"], "block_size": 4096}}
        with self.assertRaises(ApplianceError) as ctx:
            oracle.parse_verity_rules(canonical_dumps(changed))
        self.assertEqual(ctx.exception.reason_code, "CP_VERITY_RULES_SCHEMA")

    def test_reject_dynamic_tcb_without_loader_closure(self) -> None:
        raw = oracle.canonical_loads(_tcb_bytes())
        raw["launcher"] = {**raw["launcher"], "linkage": "dynamic"}
        with self.assertRaises(ApplianceError) as ctx:
            oracle.parse_tcb_identity(canonical_dumps(raw))
        self.assertEqual(ctx.exception.reason_code, "CP_TCB_IDENTITY_SCHEMA")

    def test_reject_unknown_kernel_feature_contract(self) -> None:
        raw = oracle.canonical_loads(_tcb_bytes())
        raw["kernel_feature_contract"]["schema"] = "conf-proc-kernel-features/v2"
        with self.assertRaises(ApplianceError) as ctx:
            oracle.parse_tcb_identity(canonical_dumps(raw))
        self.assertEqual(ctx.exception.reason_code, "CP_TCB_IDENTITY_SCHEMA")

    def test_accept_exact_manifest_and_spdx_bindings(self) -> None:
        inputs = _derive()
        oracle.inspect_bindings(manifest_bytes=_manifest(inputs), sbom_bytes=_sbom(inputs), inputs=inputs)

    def test_reject_coherent_candidate_rewrite(self) -> None:
        trusted = _derive()
        rewritten = _derive(tcb_identity_bytes=_tcb_bytes(_sha(8)))
        with self.assertRaises(ApplianceError) as ctx:
            oracle.inspect_bindings(manifest_bytes=_manifest(rewritten), sbom_bytes=_sbom(rewritten), inputs=trusted)
        self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_BINDING")

    def test_reject_legacy_omission_and_spdx_omission(self) -> None:
        inputs = _derive()
        with self.assertRaises(ApplianceError):
            oracle.inspect_bindings(manifest_bytes=canonical_dumps({"schema": "conf-proc-appliance-manifest/v1"}), sbom_bytes=_sbom(inputs), inputs=inputs)
        sbom_raw = oracle.canonical_loads(_sbom(inputs))
        sbom_raw["packages"][0]["externalRefs"] = []
        sbom = canonical_dumps(sbom_raw)
        with self.assertRaises(ApplianceError):
            oracle.inspect_bindings(manifest_bytes=_manifest(inputs), sbom_bytes=sbom, inputs=inputs)

    def test_reject_skeletal_or_extra_candidate_documents(self) -> None:
        inputs = _derive()
        skeletal_manifest = canonical_dumps({"schema": "conf-proc-appliance-manifest/v2", "provenance": oracle.canonical_loads(_manifest(inputs))["provenance"]})
        with self.assertRaises(ApplianceError):
            oracle.inspect_bindings(manifest_bytes=skeletal_manifest, sbom_bytes=_sbom(inputs), inputs=inputs)
        sbom_raw = oracle.canonical_loads(_sbom(inputs))
        sbom_raw["unrecognized"] = True
        with self.assertRaises(ApplianceError):
            oracle.inspect_bindings(manifest_bytes=_manifest(inputs), sbom_bytes=canonical_dumps(sbom_raw), inputs=inputs)

    def test_reject_contradictory_output_authorities(self) -> None:
        inputs = _derive()
        for path in ("lock", "policy", "base", "input", "inventory", "module", "toolchain"):
            manifest = oracle.canonical_loads(_manifest(inputs))
            if path == "lock":
                manifest["lock_sha256"] = _sha(45)
            elif path == "policy":
                manifest["policy"]["process_policy_sha256"] = _sha(46)
            elif path == "base":
                manifest["base_image_record"]["identity_name"] = "other"
            elif path == "input":
                manifest["inputs"][0]["sha256"] = _sha(49)
            elif path == "inventory":
                manifest["inventory"]["runtime-policy"][0]["mode"] ^= 1
            elif path == "module":
                manifest["module_authority"]["trusted_bundle_input_id"] = "other"
            else:
                manifest["toolchain"][0]["resolved_path_sha256"] = _sha(48)
            with self.assertRaises(ApplianceError):
                oracle.inspect_bindings(manifest_bytes=canonical_dumps(manifest), sbom_bytes=_sbom(inputs), inputs=inputs)
        sbom = oracle.canonical_loads(_sbom(inputs))
        sbom["packages"][0]["checksums"][0]["checksumValue"] = _sha(47)
        manifest = oracle.canonical_loads(_manifest(inputs))
        manifest["sbom"]["sha256"] = hashlib.sha256(canonical_dumps(sbom)).hexdigest()
        with self.assertRaises(ApplianceError):
            oracle.inspect_bindings(manifest_bytes=canonical_dumps(manifest), sbom_bytes=canonical_dumps(sbom), inputs=inputs)

    def test_reject_mutated_retained_root_authority(self) -> None:
        inputs = _derive()
        changed_root = oracle.canonical_loads(inputs.root_lock_bytes)
        changed_root["future_cmdline"] = "console=ttyS1"
        changed = dataclasses.replace(inputs, root_lock_bytes=canonical_dumps(changed_root))
        with self.assertRaises(ApplianceError) as ctx:
            oracle.inspect_bindings(
                manifest_bytes=_manifest(changed),
                sbom_bytes=_sbom(changed),
                inputs=changed,
            )
        self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_AUTHORITY")

    def test_reject_coordinated_cached_authority_rewrite(self) -> None:
        inputs = _derive()
        changed_root = oracle.canonical_loads(inputs.root_lock_bytes)
        changed_root["future_cmdline"] = "console=ttyS1"
        changed_root_bytes = canonical_dumps(changed_root)
        changed_policy_bytes = _policy_bytes("changed")
        for changed in (
            dataclasses.replace(
                inputs,
                root_lock_bytes=changed_root_bytes,
                artifact_input_sha256=hashlib.sha256(changed_root_bytes).hexdigest(),
            ),
            dataclasses.replace(
                inputs,
                policy_bytes=changed_policy_bytes,
                policy_sha256=hashlib.sha256(changed_policy_bytes).hexdigest(),
            ),
            dataclasses.replace(inputs, artifact_input_schema="conf-proc-lock/other"),
        ):
            with self.assertRaises(ApplianceError) as ctx:
                oracle.inspect_bindings(
                    manifest_bytes=_manifest(changed),
                    sbom_bytes=_sbom(changed),
                    inputs=changed,
                )
            self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_AUTHORITY")

    def test_reject_semantically_invalid_manifest_or_spdx(self) -> None:
        inputs = _derive()
        for field, value in (("hash_algorithm", "sha512"), ("squashfs_size_bytes", -1), ("uuid", "not-a-uuid")):
            manifest = oracle.canonical_loads(_manifest(inputs))
            manifest["images"]["models"][field] = value
            with self.assertRaises(ApplianceError):
                oracle.inspect_bindings(manifest_bytes=canonical_dumps(manifest), sbom_bytes=_sbom(inputs), inputs=inputs)
        for mutation in ("purpose", "timestamp", "relationship"):
            sbom = oracle.canonical_loads(_sbom(inputs))
            if mutation == "purpose":
                sbom["packages"][0]["primaryPackagePurpose"] = "MADE_UP"
            elif mutation == "timestamp":
                sbom["creationInfo"]["created"] = "not-a-timestamp"
            else:
                sbom["relationships"] = [
                    {
                        "spdxElementId": "SPDXRef-Package-appliance",
                        "relationshipType": "CONTAINS",
                        "relatedSpdxElement": "SPDXRef-Missing",
                    }
                ]
            manifest = oracle.canonical_loads(_manifest(inputs))
            manifest["sbom"]["sha256"] = hashlib.sha256(canonical_dumps(sbom)).hexdigest()
            with self.assertRaises(ApplianceError):
                oracle.inspect_bindings(manifest_bytes=canonical_dumps(manifest), sbom_bytes=canonical_dumps(sbom), inputs=inputs)

    def test_malformed_collections_fail_with_typed_error(self) -> None:
        inputs = _derive()
        manifest = oracle.canonical_loads(_manifest(inputs))
        manifest["inputs"] = [
            {
                "id": "bad",
                "role": "build_tool",
                "sha256": _sha(1),
                "size_bytes": 1,
                "source_retrieval_scheme": "fixture",
                "source_retrieval_identity": "fixture:bad",
                "source_retrieval_immutable_ref": "sha256:" + _sha(1),
                "derivation_kind": "fixture",
                "derivation_recipe_id": "recipe",
                "derivation_parent_ids": [1, "mixed"],
                "derivation_parameters_sha256": _sha(2),
                "placements": [],
            }
        ]
        collection_image = oracle.canonical_loads(_manifest(inputs))
        collection_image["inputs"][0]["placements"][0]["image"] = []
        for mutated in (
            manifest,
            collection_image,
            {**oracle.canonical_loads(_manifest(inputs)), "bindings": {"models": {"executables": [{}], "configs": [], "models": [], "runtime_inputs": []}, "runtime-policy": {"executables": [], "configs": [], "models": [], "runtime_inputs": []}}},
            {**oracle.canonical_loads(_manifest(inputs)), "module_authority": {"trusted_bundle_input_id": "bundle", "authorized_signer_certificate_sha256": [{}], "module_inventory": [], "firmware_inventory": []}},
        ):
            with self.assertRaises(ApplianceError) as ctx:
                oracle.inspect_bindings(manifest_bytes=canonical_dumps(mutated), sbom_bytes=_sbom(inputs), inputs=inputs)
            self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_BINDING")
        sbom = oracle.canonical_loads(_sbom(inputs))
        sbom["relationships"] = [
            {"spdxElementId": [], "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Package-appliance"}
        ]
        manifest = oracle.canonical_loads(_manifest(inputs))
        manifest["sbom"]["sha256"] = hashlib.sha256(canonical_dumps(sbom)).hexdigest()
        with self.assertRaises(ApplianceError) as ctx:
            oracle.inspect_bindings(manifest_bytes=canonical_dumps(manifest), sbom_bytes=canonical_dumps(sbom), inputs=inputs)
        self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_BINDING")

    def test_pinned_subprocess_adapter_accepts_and_rejects_content_safely(self) -> None:
        inputs = _derive()
        documents = {
            "root-lock.json": _lock_bytes(),
            "runtime-closure.json": _closure_bytes(),
            "verity-rules.json": oracle.supported_verity_rules_bytes(),
            "tcb.json": _tcb_bytes(),
            "builder.py": b"literal-builder-source-v1",
            "policy.json": _policy_bytes(),
            "manifest.json": _manifest(inputs),
            "sbom.json": _sbom(inputs),
        }
        with tempfile.TemporaryDirectory(dir="/var/tmp") as base:
            for name, data in documents.items():
                Path(base, name).write_bytes(data)
            command = [
                sys.executable,
                str(ROOT / "conf_proc_inspect_provenance_cli.py"),
                "--root-lock", str(Path(base, "root-lock.json")),
                "--runtime-closure", str(Path(base, "runtime-closure.json")),
                "--verity-rules", str(Path(base, "verity-rules.json")),
                "--tcb-identity", str(Path(base, "tcb.json")),
                "--builder-source", str(Path(base, "builder.py")),
                "--policy", str(Path(base, "policy.json")),
                "--manifest", str(Path(base, "manifest.json")),
                "--sbom", str(Path(base, "sbom.json")),
            ]
            accepted = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
            self.assertTrue(oracle.canonical_loads(accepted.stdout.rstrip(b"\n"))["accepted"])

            Path(base, "manifest.json").write_bytes(canonical_dumps({"schema": "tampered"}))
            rejected = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(rejected.returncode, 1)
            result = oracle.canonical_loads(rejected.stdout.rstrip(b"\n"))
            self.assertFalse(result["accepted"])
            self.assertNotIn(base.encode(), rejected.stdout + rejected.stderr)

            unknown = subprocess.run(
                [sys.executable, str(ROOT / "conf_proc_inspect_provenance_cli.py"), "--unexpected", "/secret/example"],
                capture_output=True,
                check=False,
            )
            self.assertEqual(unknown.returncode, 1)
            self.assertEqual(unknown.stderr, b"")
            self.assertEqual(oracle.canonical_loads(unknown.stdout.rstrip(b"\n"))["reason_code"], "CP_PROVENANCE_ARGUMENTS")
            self.assertNotIn(b"/secret/example", unknown.stdout + unknown.stderr)

            Path(base, "manifest.json").unlink()
            os.symlink(str(Path(base, "sbom.json")), str(Path(base, "manifest.json")))
            symlinked = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(symlinked.returncode, 1)
            self.assertEqual(oracle.canonical_loads(symlinked.stdout.rstrip(b"\n"))["reason_code"], "CP_PROVENANCE_INPUT_READ")

    def test_subprocess_only_import_dag_and_reason_registry(self) -> None:
        forbidden = {"conf_proc_inspect_provenance", "conf_proc_inspect_provenance_cli"}
        for path in ROOT.glob("*.py"):
            if path.name in {"conf_proc_inspect_provenance.py", "conf_proc_inspect_provenance_cli.py"}:
                continue
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = {alias.name for alias in node.names}
                elif isinstance(node, ast.ImportFrom):
                    imported = {node.module} if node.module is not None else set()
                else:
                    continue
                self.assertTrue(imported.isdisjoint(forbidden), f"{path.name} imports sealed provenance code")
        adapter_codes = {
            "CP_PROVENANCE_INPUT_SIZE",
            "CP_PROVENANCE_INPUT_READ",
            "CP_PROVENANCE_INPUT_CHANGED",
            "CP_PROVENANCE_ORACLE_DIGEST",
            "CP_PROVENANCE_ORACLE_LOAD",
            "CP_PROVENANCE_ORACLE_INTERNAL",
            "CP_PROVENANCE_ARGUMENTS",
        }
        self.assertTrue(adapter_codes <= reasons.ALL_REASON_CODES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
