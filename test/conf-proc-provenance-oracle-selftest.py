#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Known-answer and hostile-input tests for the dormant v2 provenance oracle."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_inspect_provenance as oracle  # noqa: E402
from conf_proc_json import canonical_dumps  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha(value: int) -> str:
    return format(value, "064x")


def _lock_bytes(
    content_sha: str = _sha(1),
    *,
    builder_source_bytes: bytes = b"literal-builder-source-v1",
    policy_bytes: bytes = b"literal-policy-v1",
) -> bytes:
    builder_sha = hashlib.sha256(builder_source_bytes).hexdigest()
    policy_sha = hashlib.sha256(policy_bytes).hexdigest()
    return canonical_dumps(
        {
            "inputs": [
                {
                    "id": "builder",
                    "role": "conf_proc_source",
                    "sha256": builder_sha,
                    "size_bytes": len(builder_source_bytes),
                    "source_retrieval_scheme": "git",
                    "source_retrieval_identity": "conf-proc",
                    "source_retrieval_immutable_ref": "sha256:" + builder_sha,
                },
                {
                    "id": "policy",
                    "role": "policy_tree_input",
                    "sha256": policy_sha,
                    "size_bytes": len(policy_bytes),
                    "source_retrieval_scheme": "generated",
                    "source_retrieval_identity": "policy",
                    "source_retrieval_immutable_ref": "sha256:" + policy_sha,
                },
                {
                    "id": "python",
                    "role": "build_tool",
                    "sha256": content_sha,
                    "size_bytes": 12,
                    "source_retrieval_scheme": "package",
                    "source_retrieval_identity": "python3",
                    "source_retrieval_immutable_ref": "sha256:" + content_sha,
                },
            ],
            "policy_input_id": "policy",
            "schema": "literal-root-lock/v1",
        }
    )


def _closure_bytes(content_sha: str = _sha(1)) -> bytes:
    return canonical_dumps(
        {
            "schema": "conf-proc-runtime-closure/v1",
            "status": "declared_unverified",
            "entries": [
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
                    "provenance": {"scheme": "package", "identity": "python3", "immutable_ref": "sha256:" + content_sha},
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
        "policy_bytes": b"literal-policy-v1",
    }
    values.update(overrides)
    if "root_lock_bytes" not in overrides and (
        "builder_source_bytes" in overrides or "policy_bytes" in overrides
    ):
        values["root_lock_bytes"] = _lock_bytes(
            builder_source_bytes=values["builder_source_bytes"],
            policy_bytes=values["policy_bytes"],
        )
    return oracle.derive_inputs(**values)


def _manifest(inputs: oracle.ProvenanceInputs) -> bytes:
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
            "lock_schema": "literal-root-lock/v1",
            "lock_sha256": inputs.artifact_input_sha256,
            "reproducibility": {
                "build_epoch": oracle._build_epoch(inputs.artifact_input_sha256),
                "sort_order": "byte-wise-path",
                "codec": "conf-proc-canonical-json/v1",
            },
            "base_image_record": {
                "kind": "vhd",
                "provider": "fixture",
                "identity_namespace": "fixture",
                "identity_name": "base",
                "identity_immutable_revision": "sha256:" + _sha(20),
                "content_sha256": _sha(20),
                "content_size_bytes": 1,
                "content_media_type": "application/octet-stream",
                "availability": "record-only",
                "recorded_retrieval_scheme": "local-fixture",
                "recorded_retrieval_identity": "fixture:base",
                "recorded_retrieval_immutable_ref": "sha256:" + _sha(20),
            },
            "future_cmdline": "console=ttyS0",
            "images": {"models": image, "runtime-policy": image},
            "inputs": [],
            "inventory": {"models": [], "runtime-policy": []},
            "bindings": {"models": empty_bindings, "runtime-policy": empty_bindings},
            "policy": {
                "policy_input_id": "policy",
                "policy_schema": "conf-proc-policy/v1",
                "process_policy_sha256": inputs.policy_sha256,
            },
            "module_authority": {
                "trusted_bundle_input_id": "trusted-bundle",
                "authorized_signer_certificate_sha256": [],
                "module_inventory": [],
                "firmware_inventory": [],
            },
            "toolchain": [],
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
        self.assertEqual(inputs.artifact_input_sha256, "d9ffc9c74eaa93d4e3f70710e8ef3cb50fc5ebb9b2e1016aeda42cd6b8606572")
        self.assertEqual(inputs.runtime_closure_sha256, "6d16ba7030d006121a1ccfd02594b1e0961cc6a63a290d75c9125987f8c73b8a")
        self.assertEqual(inputs.verity_rules_sha256, "aece6264c1666c9b83f80756842ace68a9ed74a9cad42a9758699d961605e059")
        self.assertEqual(inputs.tcb_identity_sha256, "2edbe10694ed9914152a2b98ab357a1906f6a1ca2fda15fed71926ee34e479eb")
        self.assertEqual(inputs.builder_source_sha256, "9654bf8dfd2eccdce8dc5928f89d6c07402efffdd438fdeaeb2c8aa2955a08c1")
        self.assertEqual(inputs.policy_sha256, "08d682587e22c75261b7466108dac1bc7ac486bf03835f986fcdb7f486587f1b")
        self.assertEqual(inputs.execution_provenance_sha256, "2a7b52b091c0bb6c0aa077d353883c8fde1d7d6072771350724eb2c0f1d9d33f")

    def test_artifact_and_execution_identity_truth_table(self) -> None:
        baseline = _derive()
        changed_lock = _derive(root_lock_bytes=_lock_bytes(_sha(9)), runtime_closure_bytes=_closure_bytes(_sha(9)))
        changed_tcb = _derive(tcb_identity_bytes=_tcb_bytes(_sha(8)))
        self.assertNotEqual(changed_lock.artifact_input_sha256, baseline.artifact_input_sha256)
        self.assertNotEqual(changed_lock.execution_provenance_sha256, baseline.execution_provenance_sha256)
        self.assertEqual(changed_tcb.artifact_input_sha256, baseline.artifact_input_sha256)
        self.assertNotEqual(changed_tcb.execution_provenance_sha256, baseline.execution_provenance_sha256)

    def test_second_literal_vector_proves_named_framing(self) -> None:
        # Both raw component pairs concatenate to b"abc".  The named,
        # digest-valued canonical envelope nevertheless gives distinct
        # execution identities; these are independently pinned literals.
        left = _derive(builder_source_bytes=b"ab", policy_bytes=b"c")
        right = _derive(builder_source_bytes=b"a", policy_bytes=b"bc")
        self.assertEqual(left.execution_provenance_sha256, "f397c8c661561461be2ed8eb097dbe21eabc6b27e63ec80db368254c937cdf5e")
        self.assertEqual(right.execution_provenance_sha256, "1ced6de9e102fe411498d6d0363030289a6c7ba4a542522a83580d359096e911")
        self.assertNotEqual(left.execution_provenance_sha256, right.execution_provenance_sha256)

    def test_reject_root_lock_authority_disagreement(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            _derive(runtime_closure_bytes=_closure_bytes(_sha(7)))
        self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_AUTHORITY")

    def test_reject_policy_or_builder_bytes_outside_root_lock_authority(self) -> None:
        root = _lock_bytes()
        for override in (
            {"root_lock_bytes": root, "policy_bytes": b"different-policy"},
            {"root_lock_bytes": root, "builder_source_bytes": b"different-builder"},
        ):
            with self.assertRaises(ApplianceError) as ctx:
                _derive(**override)
            self.assertEqual(ctx.exception.reason_code, "CP_PROVENANCE_AUTHORITY")

    def test_reject_root_lock_role_or_provenance_disagreement(self) -> None:
        for field, value in (("logical_role", "runtime_tree_input"), ("provenance", {"scheme": "package", "identity": "other", "immutable_ref": "sha256:" + _sha(1)})):
            raw = oracle.canonical_loads(_closure_bytes())
            raw["entries"][0][field] = value
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
        second = {**first, "path": "/b", "mode": 420}
        raw["entries"] = [first, second]
        with self.assertRaises(ApplianceError) as ctx:
            oracle.parse_runtime_closure(canonical_dumps(raw))
        self.assertEqual(ctx.exception.reason_code, "CP_RUNTIME_CLOSURE_SCHEMA")

    def test_reject_runtime_path_escape_and_special_node(self) -> None:
        raw = oracle.canonical_loads(_closure_bytes())
        for field, value in (("path", "/usr/../etc/passwd"), ("path", "/usr/bin/python3\x00hidden"), ("node_type", "device")):
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
        for path in ("lock", "policy"):
            manifest = oracle.canonical_loads(_manifest(inputs))
            if path == "lock":
                manifest["lock_sha256"] = _sha(45)
            else:
                manifest["policy"]["process_policy_sha256"] = _sha(46)
            with self.assertRaises(ApplianceError):
                oracle.inspect_bindings(manifest_bytes=canonical_dumps(manifest), sbom_bytes=_sbom(inputs), inputs=inputs)
        sbom = oracle.canonical_loads(_sbom(inputs))
        sbom["packages"][0]["checksums"][0]["checksumValue"] = _sha(47)
        manifest = oracle.canonical_loads(_manifest(inputs))
        manifest["sbom"]["sha256"] = hashlib.sha256(canonical_dumps(sbom)).hexdigest()
        with self.assertRaises(ApplianceError):
            oracle.inspect_bindings(manifest_bytes=canonical_dumps(manifest), sbom_bytes=canonical_dumps(sbom), inputs=inputs)

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
        for mutated in (
            manifest,
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
