#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Focused KATs for v3 closed executable provenance and JIT authority."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

from conf_proc_json import canonical_dumps, canonical_loads
import conf_proc_spp_boot_v3 as boot
import conf_proc_spp_boot_v3_semantics as semantics
import conf_proc_spp_boot_v3_fixture as fixture
from conf_proc_spp_boot_v3_fixture import build_v3_fixture, refresh_v3_contract_bindings
from conf_proc_spp_reasons_v3 import ApplianceErrorV3, CP_BOOT_V3_BINDING, CP_BOOT_V3_SCHEMA
from conf_proc_spp_boot_v3_semantics import jit_derivation_sha256_v3
from conf_proc_reasons import ApplianceError, CP_RUNTIME_CLOSURE_SCHEMA


def _mutated_docs(*, execution_mode: str = "python_jit_triton", cache_policy: str = "ephemeral_rebuild") -> tuple[dict[str, bytes], object]:
    docs, _ = build_v3_fixture(execution_mode=execution_mode, cache_policy=cache_policy)
    return docs, canonical_loads(docs["boot_contract_bytes"])


def _commit_contract(docs: dict[str, bytes], contract: dict) -> None:
    docs["boot_contract_bytes"] = canonical_dumps(contract)
    refresh_v3_contract_bindings(docs)


def _parsed_contract(docs: dict[str, bytes]) -> object:
    return boot.parse_boot_contract_v3(docs["boot_contract_bytes"])


def _rebuild_predecessors(docs: dict[str, bytes], lock: dict, policy: dict) -> None:
    policy["images"]["runtime-policy"]["nodes"].sort(key=lambda item: item["path"])
    docs["policy_bytes"] = canonical_dumps(policy)
    policy_input = next(item for item in lock["inputs"] if item["id"] == "policy")
    policy_input["sha256"] = hashlib.sha256(docs["policy_bytes"]).hexdigest()
    policy_input["size_bytes"] = len(docs["policy_bytes"])
    policy_input["source_retrieval_immutable_ref"] = "sha256:" + policy_input["sha256"]
    lock["inputs"].sort(key=lambda item: item["id"])
    docs["root_lock_bytes"] = canonical_dumps(lock)
    fixture._set_runtime_closure(docs, lock)
    manifest = canonical_loads(docs["accepted_manifest_bytes"])
    images = tuple(
        fixture._V1.ProvenanceV2ImageRecord(
            image_id, item["squashfs_sha256"], item["squashfs_size_bytes"],
            item["hash_device_sha256"], item["hash_device_size_bytes"], item["root_hash"],
        )
        for image_id, item in sorted(manifest["images"].items())
    )
    modules = tuple(
        fixture._V1.ProvenanceV2ModuleObservation(item["path"], item["sha256"], item["signer_certificate_sha256"])
        for item in manifest["module_authority"]["module_inventory"]
    )
    firmware = tuple(
        fixture._V1.ProvenanceV2FirmwareObservation(item["path"], item["sha256"])
        for item in manifest["module_authority"]["firmware_inventory"]
    )
    docs["accepted_manifest_bytes"] = fixture._V1.produce_provenance_v2(
        root_lock_bytes=docs["root_lock_bytes"], runtime_closure_bytes=docs["runtime_closure_bytes"],
        verity_rules_bytes=docs["verity_rules_bytes"], tcb_identity_bytes=docs["tcb_identity_bytes"],
        builder_source_bytes=docs["builder_source_bytes"], policy_bytes=docs["policy_bytes"],
        images=images, module_observations=modules, firmware_observations=firmware,
    ).manifest_bytes


def _alias_predecessors(lock: dict, policy: dict, path: str) -> tuple[dict, dict]:
    placement = next(
        placement
        for item in lock["inputs"] for placement in item["placements"]
        if placement["node_type"] == "symlink" and placement["path"] == path
    )
    node = next(
        item for item in policy["images"]["runtime-policy"]["nodes"]
        if item["node_type"] == "symlink" and item["path"] == path
    )
    return placement, node


def _append_graph_declaration(
    graph: dict, *, kind: str, owner_id: str, target_id: str, order_group: str,
    ordinal: int, requested_path: str | None, alias_chain: list[str],
) -> None:
    declaration = {
        "kind": kind, "owner_id": owner_id, "order_group": order_group,
        "ordinal": ordinal, "requested_path": requested_path, "target_id": target_id,
        "alias_chain": alias_chain,
    }
    declaration["id"] = semantics._graph_declaration_id_v3(
        kind=kind, owner_id=owner_id, order_group=order_group, ordinal=ordinal,
        requested_path=requested_path, target_id=target_id, alias_chain=tuple(alias_chain),
    )
    graph["declarations"].append(declaration)
    edge = {
        "kind": kind, "from_id": owner_id, "to_id": target_id,
        "order_group": order_group, "ordinal": ordinal,
        "requested_path": requested_path, "resolved_id": target_id,
        "alias_chain": alias_chain, "declaration_kind": "executable_graph",
        "declaration_ref": declaration["id"],
    }
    edge["id"] = semantics._graph_edge_id_v3(
        kind=kind, from_id=owner_id, to_id=target_id, order_group=order_group,
        ordinal=ordinal, requested_path=requested_path, resolved_id=target_id,
        alias_chain=tuple(alias_chain), declaration_kind="executable_graph",
        declaration_ref=declaration["id"],
    )
    graph["edges"].append(edge)


def _add_hop_40_alias_chain(docs: dict[str, bytes], contract: dict) -> None:
    lock = canonical_loads(docs["root_lock_bytes"])
    policy = canonical_loads(docs["policy_bytes"])
    paths = tuple(f"/usr/lib/spp/graph-hop-{index:02d}" for index in range(40))
    terminal_path = "/usr/lib/x86_64-linux-gnu"
    for index, path in enumerate(paths):
        input_id = f"runtime-graph-hop-{index:02d}"
        target = f"graph-hop-{index + 1:02d}" if index < len(paths) - 1 else terminal_path
        placement = fixture._V1._placement("runtime-policy", path, input_id)
        placement.update({"node_type": "symlink", "mode": 0o555, "source_input_id": None, "target": target})
        lock["inputs"].append(fixture._V1._record(input_id, "runtime_tree_input", input_id.encode("ascii"), [placement]))
        policy["images"]["runtime-policy"]["nodes"].append({
            "path": path, "node_type": "symlink", "mode": 0o555, "uid": 0, "gid": 0,
            "xattrs": [], "source_input_id": None, "target": target, "content_class": None,
        })
    _rebuild_predecessors(docs, lock, policy)

    graph = contract["execution_closure"]["executable_graph"]
    target_id = "dir:runtime-policy:" + terminal_path
    owner_id = "file:runtime-policy:/usr/bin/spp"
    group = "elf-search:" + owner_id
    for index, path in enumerate(paths):
        chain = list(paths[index:])
        target = f"graph-hop-{index + 1:02d}" if index < len(paths) - 1 else terminal_path
        graph["aliases"].append({
            "image": "runtime-policy", "path": path, "target": target,
            "resolved_id": target_id, "hop_count": len(chain), "chain": chain,
        })
        _append_graph_declaration(
            graph, kind="elf_search", owner_id=owner_id, target_id=target_id,
            order_group=group, ordinal=index + 1, requested_path=path, alias_chain=chain,
        )
    graph["aliases"].sort(key=lambda item: (item["image"], item["path"]))
    graph["declarations"].sort(key=lambda item: item["id"].encode("utf-8"))
    graph["edges"].sort(key=lambda item: item["id"].encode("utf-8"))


class BootV3Predicate5Selftest(unittest.TestCase):
    def test_executable_graph_shape_alias_and_relation_mutations_are_rejected(self) -> None:
        docs, raw = _mutated_docs()
        graph = raw["execution_closure"]["executable_graph"]
        graph["alias_hop_limit"] = True
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            _parsed_contract(docs)

        docs, raw = _mutated_docs()
        graph = raw["execution_closure"]["executable_graph"]
        graph["controls"][0]["phase"] = "role_pre"
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        for mutation in ("hop_41", "dangling", "cycle", "cross_image"):
            with self.subTest(alias_mutation=mutation):
                docs, raw = _mutated_docs()
                alias = raw["execution_closure"]["executable_graph"]["aliases"][0]
                if mutation == "hop_41":
                    alias["hop_count"] = 41
                elif mutation == "dangling":
                    alias["resolved_id"] = "file:runtime-policy:/missing"
                elif mutation == "cycle":
                    alias["chain"] = [alias["path"], alias["path"]]
                    alias["hop_count"] = 2
                else:
                    alias["image"] = "models"
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA if mutation in ("hop_41", "cycle") else CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_executable_graph_hop_40_alias_chain_binds(self) -> None:
        docs, raw = _mutated_docs()
        _add_hop_40_alias_chain(docs, raw)
        _commit_contract(docs, raw)
        binding = boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)
        hop_40 = next(row for row in binding.predicate5.executable_graph.aliases if row.path == "/usr/lib/spp/graph-hop-00")
        self.assertEqual((hop_40.hop_count, len(hop_40.chain)), (40, 40))

    def test_executable_graph_alias_predecessor_boundaries_are_rejected(self) -> None:
        for mutation in ("writable", "escaping", "ambiguous", "unlisted"):
            with self.subTest(alias_mutation=mutation):
                docs, raw = _mutated_docs()
                graph = raw["execution_closure"]["executable_graph"]
                if mutation in ("writable", "escaping"):
                    lock = canonical_loads(docs["root_lock_bytes"])
                    policy = canonical_loads(docs["policy_bytes"])
                    path = "/usr/lib/spp/conf_proc_spp_role_bootstrap_alias.py"
                    placement, node = _alias_predecessors(lock, policy, path)
                    alias = next(row for row in graph["aliases"] if row["path"] == path)
                    if mutation == "writable":
                        placement["mode"] = node["mode"] = 0o777
                    else:
                        target = "../../../etc/passwd"
                        placement["target"] = node["target"] = alias["target"] = target
                        alias["resolved_id"] = "file:runtime-policy:/etc/passwd"
                        with self.assertRaisesRegex(ApplianceError, CP_RUNTIME_CLOSURE_SCHEMA):
                            _rebuild_predecessors(docs, lock, policy)
                        continue
                    _rebuild_predecessors(docs, lock, policy)
                elif mutation == "ambiguous":
                    graph["aliases"].append(deepcopy(graph["aliases"][0]))
                    graph["aliases"].sort(key=lambda item: (item["image"], item["path"]))
                else:
                    alias = graph["aliases"][0]
                    alias["chain"] = [alias["path"], "/usr/lib/spp/unlisted-alias-hop.py"]
                    alias["hop_count"] = 2
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_executable_graph_every_edge_kind_rejects_reversal(self) -> None:
        docs, raw = _mutated_docs()
        graph = raw["execution_closure"]["executable_graph"]
        kinds = {edge["kind"] for edge in graph["edges"]}
        self.assertEqual(kinds, {
            "python_script", "python_import", "elf_interpreter", "elf_needed", "elf_search",
            "dlopen", "jit_invoke", "jit_compiler", "jit_loader", "jit_input", "jit_output",
        })
        for kind in sorted(kinds):
            with self.subTest(kind=kind):
                docs, raw = _mutated_docs()
                graph = raw["execution_closure"]["executable_graph"]
                edge = next(row for row in graph["edges"] if row["kind"] == kind)
                edge["from_id"], edge["to_id"] = edge["to_id"], edge["from_id"]
                edge["resolved_id"] = edge["to_id"]
                edge["id"] = semantics._graph_edge_id_v3(
                    kind=edge["kind"], from_id=edge["from_id"], to_id=edge["to_id"],
                    order_group=edge["order_group"], ordinal=edge["ordinal"],
                    requested_path=edge["requested_path"], resolved_id=edge["resolved_id"],
                    alias_chain=tuple(edge["alias_chain"]), declaration_kind=edge["declaration_kind"],
                    declaration_ref=edge["declaration_ref"],
                )
                graph["edges"].sort(key=lambda row: row["id"].encode("utf-8"))
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_executable_graph_declaration_and_node_denominators_are_closed(self) -> None:
        docs, raw = _mutated_docs()
        graph = raw["execution_closure"]["executable_graph"]
        graph["declarations"][0]["owner_id"] = graph["declarations"][0]["target_id"]
        declaration = graph["declarations"][0]
        declaration["id"] = semantics._graph_declaration_id_v3(
            kind=declaration["kind"], owner_id=declaration["owner_id"], order_group=declaration["order_group"],
            ordinal=declaration["ordinal"], requested_path=declaration["requested_path"],
            target_id=declaration["target_id"], alias_chain=tuple(declaration["alias_chain"]),
        )
        graph["declarations"].sort(key=lambda row: row["id"].encode("utf-8"))
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        docs, raw = _mutated_docs()
        graph = raw["execution_closure"]["executable_graph"]
        graph["nodes"].append(dict(graph["nodes"][0]))
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_closed_no_jit_and_two_jit_cache_modes_bind(self) -> None:
        for kwargs, expected_derivations in (
            ({}, 0),
            ({"execution_mode": "python_jit_triton", "cache_policy": "ephemeral_rebuild"}, 1),
            ({"execution_mode": "python_jit_triton", "cache_policy": "measured_read_only"}, 1),
        ):
            docs, contract = build_v3_fixture(**kwargs)
            binding = boot.bind_boot_inputs_v3(contract=contract, **docs)
            with self.subTest(kwargs=kwargs):
                self.assertEqual(len(binding.predicate5.jit_derivations), expected_derivations)
                self.assertEqual(binding.predicate5.startup_kat_sha256, "82840888819a980868766f4273456c9c81d0539a6d2642b8af32f4cb30829976")
                self.assertEqual(
                    tuple(row["name"] for row in canonical_loads(docs["boot_contract_bytes"])["execution_closure"]["startup_kat"]["packages"]),
                    ("libpython3.10-minimal", "libpython3.10-stdlib"),
                )
                self.assertEqual(
                    tuple(row["sha256"] for row in canonical_loads(docs["boot_contract_bytes"])["execution_closure"]["startup_kat"]["packages"]),
                    (
                        "d7cfecf69996a03153da25b826b422a27b52c1c4cbcb2fa67bce093c476f0d08",
                        "5cfe8bd93cde07bf977dc94fdf438e1a5fa70bc79f871147555156b14937c38d",
                    ),
                )

    def test_static_kat_is_read_from_the_byte_exact_fixture_files(self) -> None:
        kat = ROOT / "test/fixtures/spp-v3/python310-startup-kat-v1.json"
        observer = ROOT / "test/fixtures/spp-v3/python310_startup_observer_v1.py"
        self.assertEqual((len(kat.read_bytes()), hashlib.sha256(kat.read_bytes()).hexdigest()), (2836, "82840888819a980868766f4273456c9c81d0539a6d2642b8af32f4cb30829976"))
        self.assertEqual((len(observer.read_bytes()), hashlib.sha256(observer.read_bytes()).hexdigest()), (1871, "525fa4a1335a95744779ee5e627c150f194ed6e782148553be2547c4d77ee194"))
        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        raw["execution_closure"]["bootstrap"]["role_pre_importer_cache"].reverse()
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            _commit_contract(docs, raw)
            _parsed_contract(docs)

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        raw["execution_closure"]["bootstrap"]["pre_path_hooks"] = list(reversed(raw["execution_closure"]["bootstrap"]["pre_path_hooks"]))
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            _commit_contract(docs, raw)
            _parsed_contract(docs)

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        raw["execution_closure"]["bootstrap"]["pre_path_hooks"] = []
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            _commit_contract(docs, raw)
            _parsed_contract(docs)

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        raw["execution_closure"]["startup_kat"]["capture"]["argv"].remove("-S")
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            _commit_contract(docs, raw)
            _parsed_contract(docs)

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        raw["execution_closure"]["startup_kat"]["binary"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            _commit_contract(docs, raw)
            _parsed_contract(docs)

    def test_startup_kat_receipt_and_package_rows_are_closed(self) -> None:
        package_fields = ("name", "version", "local_path", "url", "sha256")
        for index in range(2):
            for field in package_fields:
                with self.subTest(package=index, field=field):
                    docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
                    package = raw["execution_closure"]["startup_kat"]["packages"][index]
                    package[field] = "0" * 64 if field == "sha256" else package[field] + "-mutated"
                    _commit_contract(docs, raw)
                    with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
                        _parsed_contract(docs)

        for mutation in ("package_order", "package_count", "unknown_field", "missing_field"):
            with self.subTest(mutation=mutation):
                docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
                kat = raw["execution_closure"]["startup_kat"]
                if mutation == "package_order":
                    kat["packages"].reverse()
                elif mutation == "package_count":
                    kat["packages"].pop()
                elif mutation == "unknown_field":
                    kat["unknown"] = True
                else:
                    del kat["binary"]
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
                    _parsed_contract(docs)

    def test_every_startup_kat_scalar_is_receipt_bound(self) -> None:
        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        closure = raw["execution_closure"]

        def scalar_paths(value: object, path: tuple[str | int, ...] = ()) -> list[tuple[str | int, ...]]:
            if type(value) is dict:
                return [item for key in sorted(value) for item in scalar_paths(value[key], (*path, key))]
            if type(value) is list:
                return [item for index, item_value in enumerate(value) for item in scalar_paths(item_value, (*path, index))]
            return [path]

        def mutate_scalar(value: object) -> object:
            if value is None:
                return "mutated"
            if type(value) is bool:
                return not value
            if type(value) is int:
                return value + 1
            assert type(value) is str
            return value + "-mutated"

        for path in scalar_paths(closure["startup_kat"]):
            with self.subTest(path=path):
                mutated_closure = deepcopy(closure)
                parent: object = mutated_closure["startup_kat"]
                for component in path[:-1]:
                    parent = parent[component]
                leaf = path[-1]
                parent[leaf] = mutate_scalar(parent[leaf])
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
                    semantics.parse_execution_closure_v3(mutated_closure)

        for mutation in ("whole_receipt", "binary_path", "binary_size", "capture_argv", "capture_basis", "observation_flags"):
            with self.subTest(mutation=mutation):
                docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
                kat = raw["execution_closure"]["startup_kat"]
                if mutation == "whole_receipt":
                    kat["binary"]["archive_sha256"] = "0" * 64
                elif mutation == "binary_path":
                    kat["binary"]["path"] = "/usr/bin/python3"
                elif mutation == "binary_size":
                    kat["binary"]["size"] += 1
                elif mutation == "capture_argv":
                    kat["capture"]["argv"].reverse()
                elif mutation == "capture_basis":
                    kat["capture"]["native_runtime_basis"] = "mutated"
                else:
                    kat["capture"]["observation"]["flags"]["isolated"] = 0
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
                    _parsed_contract(docs)

    def test_controller_and_role_bootstrap_caches_are_independent(self) -> None:
        for target, source in (
            ("controller_pre_importer_cache", "role_pre_importer_cache"),
            ("role_pre_importer_cache", "controller_pre_importer_cache"),
        ):
            with self.subTest(target=target, source=source):
                docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
                bootstrap = raw["execution_closure"]["bootstrap"]
                bootstrap[target] = [dict(entry) for entry in bootstrap[source]]
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
                    _parsed_contract(docs)

    def test_bootstrap_and_loader_control_escapes_are_rejected(self) -> None:
        docs, raw = _mutated_docs()
        raw["execution_closure"]["bootstrap"]["post_path"].append("/tmp")
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            _commit_contract(docs, raw)
            _parsed_contract(docs)

        docs, raw = _mutated_docs()
        raw["execution_closure"]["loader_controls"][0]["contributed_paths"] = ["/outside"]
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

        docs, raw = _mutated_docs()
        raw["execution_closure"]["loader_controls"][0]["read_only"] = False
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

    def test_overlap_tags_and_no_jit_compiler_injection_are_closed(self) -> None:
        docs, raw = _mutated_docs()
        entries = {entry["path"]: entry for entry in raw["execution_closure"]["eligible_files"]}
        self.assertEqual(entries["/usr/lib/spp/vendor/spp_jit.pth"]["semantic_tags"], ["python_loading_control"])
        self.assertEqual(entries["/usr/lib/spp/vendor/sitecustomize.py"]["semantic_tags"], ["importable_module", "python_loading_control"])
        self.assertEqual(entries["/usr/lib/spp/lib/plugin.so"]["semantic_tags"], ["dynamic_library", "native_extension", "plugin"])
        self.assertEqual(entries["/usr/lib/spp/bin/triton-compile"]["semantic_tags"], ["compiler", "launch_executable"])
        self.assertEqual(entries["/usr/lib/spp/vendor/triton_kernel.py"]["semantic_tags"], ["compiler_source", "importable_module"])
        measured_docs, measured_contract = build_v3_fixture(execution_mode="python_jit_triton", cache_policy="measured_read_only")
        measured = boot.bind_boot_inputs_v3(contract=measured_contract, **measured_docs)
        self.assertEqual([item.semantic_tags for item in measured.predicate5.eligible_files if "/jit-cache/" in item.path], [("dynamic_library", "jit_cache", "native_extension")])
        self.assertNotIn("/etc/spp/policy.json", {item.path for item in measured.predicate5.eligible_files})
        entries["/usr/lib/spp/lib/plugin.so"]["semantic_tags"].remove("plugin")
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        entries = {entry["path"]: entry for entry in raw["execution_closure"]["eligible_files"]}
        entries["/usr/lib/spp/conf_proc_spp_inference.py"]["semantic_tags"].remove("launch_executable")
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        entries = {entry["path"]: entry for entry in raw["execution_closure"]["eligible_files"]}
        entries["/usr/lib/spp/conf_proc_spp_role_bootstrap.py"]["semantic_tags"].remove("importable_module")
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        raw["execution_closure"]["eligible_files"][0]["semantic_tags"].append("compiler")
        raw["execution_closure"]["eligible_files"][0]["semantic_tags"].sort()
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

    def test_derivation_key_is_framed_and_output_cache_identity_is_closed(self) -> None:
        docs, raw = _mutated_docs()
        record = raw["execution_closure"]["jit_derivations"][0]
        known = jit_derivation_sha256_v3(record)
        self.assertEqual(raw["execution_closure"]["expected_outputs"][0]["derivation_sha256"], known)
        record["inputs"] = list(reversed(record["inputs"]))
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

        docs, raw = _mutated_docs()
        raw["execution_closure"]["jit_derivations"][0]["output"]["sha256"] = "0" * 64
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

        docs, raw = _mutated_docs(execution_mode="python_jit_triton", cache_policy="measured_read_only")
        raw["execution_closure"]["cache_selectors"][0]["path"] = "/usr/lib/spp/jit-cache/not-derived/kernel.so"
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

        docs, raw = _mutated_docs()
        raw["execution_closure"]["jit_derivations"][0]["output"]["output_name"] = "\u00e9.so"
        raw["execution_closure"]["jit_derivations"][0]["output"]["relative_path"] = "\u00e9.so"
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

    def test_output_name_traversal_and_predecessor_digest_substitution_fail(self) -> None:
        docs, raw = _mutated_docs()
        raw["execution_closure"]["jit_derivations"][0]["output"]["output_name"] = "../kernel.so"
        raw["execution_closure"]["jit_derivations"][0]["output"]["relative_path"] = "../kernel.so"
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

        docs, raw = _mutated_docs()
        raw["execution_closure"]["eligible_files"][0]["sha256"] = "0" * 64
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=contract, **docs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
