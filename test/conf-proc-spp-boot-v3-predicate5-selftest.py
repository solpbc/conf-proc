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


def _rebuild_fixture_graph(docs: dict[str, bytes], contract: dict) -> None:
    closure = contract["execution_closure"]
    closure["executable_graph"] = fixture._executable_graph_v3(
        docs, jit_records=closure["jit_derivations"], cache_policy=contract["cache_policy"],
        eligible=closure["eligible_files"], controls=closure["loader_controls"],
        elf_controls=closure["elf_loader_controls"],
    )


def _set_graph_declaration_group(graph: dict, declaration: dict, group: str) -> None:
    edge = next(row for row in graph["edges"] if row["declaration_ref"] == declaration["id"])
    declaration["order_group"] = group
    declaration["id"] = semantics._graph_declaration_id_v3(
        kind=declaration["kind"], owner_id=declaration["owner_id"], order_group=group,
        ordinal=declaration["ordinal"], requested_path=declaration["requested_path"],
        target_id=declaration["target_id"], alias_chain=tuple(declaration["alias_chain"]),
    )
    edge["order_group"] = group
    edge["declaration_ref"] = declaration["id"]
    edge["id"] = semantics._graph_edge_id_v3(
        kind=edge["kind"], from_id=edge["from_id"], to_id=edge["to_id"],
        order_group=group, ordinal=edge["ordinal"], requested_path=edge["requested_path"],
        resolved_id=edge["resolved_id"], alias_chain=tuple(edge["alias_chain"]),
        declaration_kind=edge["declaration_kind"], declaration_ref=edge["declaration_ref"],
    )
    graph["declarations"].sort(key=lambda row: row["id"].encode("utf-8"))
    graph["edges"].sort(key=lambda row: row["id"].encode("utf-8"))


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


def _rehash_graph_edge(edge: dict) -> None:
    edge["id"] = semantics._graph_edge_id_v3(
        kind=edge["kind"], from_id=edge["from_id"], to_id=edge["to_id"],
        order_group=edge["order_group"], ordinal=edge["ordinal"],
        requested_path=edge["requested_path"], resolved_id=edge["resolved_id"],
        alias_chain=tuple(edge["alias_chain"]), declaration_kind=edge["declaration_kind"],
        declaration_ref=edge["declaration_ref"],
    )


def _rehash_graph_declaration(declaration: dict) -> None:
    declaration["id"] = semantics._graph_declaration_id_v3(
        kind=declaration["kind"], owner_id=declaration["owner_id"],
        order_group=declaration["order_group"], ordinal=declaration["ordinal"],
        requested_path=declaration["requested_path"], target_id=declaration["target_id"],
        alias_chain=tuple(declaration["alias_chain"]),
    )


def _remap_graph_identity(graph: dict, old_id: str, new_id: str) -> None:
    for key in ("entrypoints",):
        graph[key] = [new_id if value == old_id else value for value in graph[key]]
    for alias in graph["aliases"]:
        if alias["resolved_id"] == old_id:
            alias["resolved_id"] = new_id
    for control in graph["controls"]:
        for key in ("owner_id", "resolved_id"):
            if control.get(key) == old_id:
                control[key] = new_id
    for declaration in graph["declarations"]:
        changed = False
        if declaration["owner_id"] == old_id:
            declaration["owner_id"] = new_id
            changed = True
        if declaration["target_id"] == old_id:
            declaration["target_id"] = new_id
            changed = True
        if changed:
            old_declaration_id = declaration["id"]
            _rehash_graph_declaration(declaration)
            for edge in graph["edges"]:
                if edge["declaration_ref"] == old_declaration_id:
                    edge["declaration_ref"] = declaration["id"]
    for edge in graph["edges"]:
        if edge["from_id"] == old_id:
            edge["from_id"] = new_id
        if edge["to_id"] == old_id:
            edge["to_id"] = new_id
        if edge["resolved_id"] == old_id:
            edge["resolved_id"] = new_id
        _rehash_graph_edge(edge)
    graph["declarations"].sort(key=lambda row: row["id"].encode("utf-8"))
    graph["edges"].sort(key=lambda row: row["id"].encode("utf-8"))


def _jit_relation(record: dict, kind: str, ordinal: int) -> dict:
    if kind == "jit_compiler":
        return record["compiler"]
    if kind == "jit_loader":
        return record["loader"]
    if kind == "jit_input":
        return record["inputs"][ordinal]
    if kind == "jit_output":
        return record["output"]
    raise AssertionError(kind)


def _jit_source_ref(*, kind: str, ordinal: int, payload: object) -> str:
    return fixture._source_ref(
        source_kind="jit_derivation", phase=None, kind=kind, ordinal=ordinal,
        payload=payload,
    )


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

    def test_loader_control_targets_are_exact_and_tagged(self) -> None:
        docs, contract = build_v3_fixture(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild")
        binding = boot.bind_boot_inputs_v3(contract=contract, **docs)
        self.assertEqual(
            tuple(row.kind for row in binding.predicate5.loader_controls),
            ("pth", "startup_hook", "namespace_package"),
        )
        controls = canonical_loads(docs["boot_contract_bytes"])["execution_closure"]["loader_controls"]
        self.assertEqual(controls[0]["contributed_paths"], ["/usr/lib/spp/vendor"])
        self.assertEqual(controls[0]["imports"], ["/usr/lib/spp/vendor/sitecustomize.py"])
        self.assertEqual(controls[1]["hooks"], ["/usr/lib/spp/vendor/sitecustomize.py"])

        for control_index in range(3):
            for field, value in (
                ("contributed_paths", ["/usr/lib/spp/vendor/sitecustomize.py"]),
                ("imports", ["/usr/lib/spp/vendor"]),
                ("hooks", ["/usr/lib/spp/lib/plugin.so"]),
            ):
                with self.subTest(control=control_index, field=field):
                    docs, raw = _mutated_docs()
                    raw["execution_closure"]["loader_controls"][control_index][field] = value
                    _rebuild_fixture_graph(docs, raw)
                    _commit_contract(docs, raw)
                    with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                        boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_loader_control_exact_target_negative_matrix_is_durable(self) -> None:
        file_target_mutations = {
            "ancestor_directory": "/usr/lib/spp/vendor",
            "absent_child": "/usr/lib/spp/vendor/missing.py",
            "writable_unmeasured": "/run/spp-jit-escape/owner.py",
            "prefix_only": "/usr/lib/spp/vendor/sitecustom",
        }
        directory_target_mutations = {
            "file_not_directory": "/usr/lib/spp/vendor/sitecustomize.py",
            "ancestor_unmeasured": "/usr/lib",
            "absent_child": "/usr/lib/spp/vendor/missing",
            "writable_unmeasured": "/run/spp-jit-escape",
            "prefix_only": "/usr/lib/spp/vend",
        }
        for control_index, expected_kind in enumerate(("pth", "startup_hook", "namespace_package")):
            for field in ("imports", "hooks"):
                for mutation, target in file_target_mutations.items():
                    with self.subTest(kind=expected_kind, field=field, mutation=mutation):
                        docs, raw = _mutated_docs()
                        control = raw["execution_closure"]["loader_controls"][control_index]
                        self.assertEqual(control["kind"], expected_kind)
                        control[field] = [target]
                        _rebuild_fixture_graph(docs, raw)
                        _commit_contract(docs, raw)
                        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)
            for mutation, target in directory_target_mutations.items():
                with self.subTest(kind=expected_kind, field="contributed_paths", mutation=mutation):
                    docs, raw = _mutated_docs()
                    control = raw["execution_closure"]["loader_controls"][control_index]
                    self.assertEqual(control["kind"], expected_kind)
                    control["contributed_paths"] = [target]
                    _rebuild_fixture_graph(docs, raw)
                    _commit_contract(docs, raw)
                    with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                        boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        for control_index, expected_kind in enumerate(("pth", "startup_hook", "namespace_package")):
            for field, path, node_kind in (
                ("contributed_paths", "/usr/lib/spp/vendor", "measured_directory"),
                ("imports", "/usr/lib/spp/vendor/sitecustomize.py", "measured_file"),
                ("hooks", "/usr/lib/spp/vendor/sitecustomize.py", "measured_file"),
            ):
                with self.subTest(kind=expected_kind, field=field, mutation="wrong_image"):
                    docs, raw = _mutated_docs()
                    control = raw["execution_closure"]["loader_controls"][control_index]
                    self.assertEqual(control["kind"], expected_kind)
                    control[field] = [path]
                    _rebuild_fixture_graph(docs, raw)
                    graph = raw["execution_closure"]["executable_graph"]
                    node = next(row for row in graph["nodes"] if row["kind"] == node_kind and row["path"] == path)
                    old_id = node["id"]
                    node["image"] = "models"
                    node["id"] = ("dir:" if node_kind == "measured_directory" else "file:") + "models:" + path
                    _remap_graph_identity(graph, old_id, node["id"])
                    graph["nodes"].sort(key=lambda row: row["id"].encode("utf-8"))
                    _commit_contract(docs, raw)
                    with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                        boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_elf_loader_controls_and_graph_elf_authority_are_distinct(self) -> None:
        docs, contract = build_v3_fixture(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild")
        binding = boot.bind_boot_inputs_v3(contract=contract, **docs)
        self.assertEqual(
            tuple((row.kind, row.owner_path, row.resolved_path) for row in binding.predicate5.elf_loader_controls),
            (
                ("elf_interpreter", "/usr/bin/python3.10", "/usr/lib/x86_64-linux-gnu/ld-spp"),
                ("elf_search", "/usr/bin/spp", "/usr/lib/spp/lib"),
            ),
        )
        graph = canonical_loads(docs["boot_contract_bytes"])["execution_closure"]["executable_graph"]
        self.assertTrue(any(row["kind"] == "elf_search" and row["declaration_kind"] == "executable_graph" for row in graph["edges"]))
        self.assertTrue(any(row["kind"] == "elf_search" and row["declaration_kind"] == "loader_control" for row in graph["edges"]))
        python_loader_refs = {row["declaration_ref"] for row in graph["controls"] if row["kind"].startswith("python_") and row["declaration_kind"] == "loader_control"}
        elf_loader_refs = {row["declaration_ref"] for row in graph["controls"] if row["kind"].startswith("elf_")}
        self.assertFalse(python_loader_refs & elf_loader_refs)

        docs, raw = _mutated_docs(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild")
        interpreter, search = raw["execution_closure"]["elf_loader_controls"]
        raw["execution_closure"]["elf_loader_controls"] = [
            {**search, "owner_path": "/usr/bin/python3.10"},
            {**interpreter, "owner_path": "/usr/bin/spp"},
        ]
        _rebuild_fixture_graph(docs, raw)
        _commit_contract(docs, raw)
        cross_order = boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)
        self.assertEqual(
            tuple((row.owner_path, row.kind) for row in cross_order.predicate5.elf_loader_controls),
            (("/usr/bin/python3.10", "elf_search"), ("/usr/bin/spp", "elf_interpreter")),
        )

        docs, raw = _mutated_docs()
        raw["execution_closure"]["elf_loader_controls"][0]["owner_path"] = "/usr/lib/spp/conf_proc_spp_init.py"
        raw["execution_closure"]["elf_loader_controls"].sort(
            key=lambda row: (row["owner_path"].encode("utf-8"), row["kind"].encode("utf-8"), row["ordinal"]),
        )
        _rebuild_fixture_graph(docs, raw)
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_distinct_elf_requests_may_share_one_measured_terminal(self) -> None:
        docs, raw = _mutated_docs(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild")
        controls = raw["execution_closure"]["elf_loader_controls"]
        controls.extend((
            {
                "kind": "elf_search", "owner_path": "/usr/bin/python3.10", "ordinal": 0,
                "requested_path": "/usr/lib/x86_64-linux-gnu", "resolved_image": "runtime-policy",
                "resolved_path": "/usr/lib/x86_64-linux-gnu", "alias_chain": [],
            },
            {
                "kind": "elf_search", "owner_path": "/usr/bin/python3.10", "ordinal": 1,
                "requested_path": "/lib/x86_64-linux-gnu", "resolved_image": "runtime-policy",
                "resolved_path": "/usr/lib/x86_64-linux-gnu", "alias_chain": ["/lib/x86_64-linux-gnu"],
            },
        ))
        controls.sort(key=lambda row: (row["owner_path"].encode("utf-8"), row["kind"].encode("utf-8"), row["ordinal"]))
        _rebuild_fixture_graph(docs, raw)
        _commit_contract(docs, raw)
        binding = boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)
        shared = tuple(
            row for row in binding.predicate5.elf_loader_controls
            if row.owner_path == "/usr/bin/python3.10" and row.kind == "elf_search"
        )
        self.assertEqual(tuple(row.ordinal for row in shared), (0, 1))
        self.assertEqual({row.resolved_path for row in shared}, {"/usr/lib/x86_64-linux-gnu"})
        self.assertEqual({row.requested_path for row in shared}, {"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"})

        raw = canonical_loads(docs["boot_contract_bytes"])
        duplicate = next(
            row for row in raw["execution_closure"]["elf_loader_controls"]
            if row["owner_path"] == "/usr/bin/python3.10" and row["kind"] == "elf_search" and row["ordinal"] == 1
        )
        duplicate["ordinal"] = 0
        raw["execution_closure"]["elf_loader_controls"].sort(
            key=lambda row: (row["owner_path"].encode("utf-8"), row["kind"].encode("utf-8"), row["ordinal"]),
        )
        _rebuild_fixture_graph(docs, raw)
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        docs, raw = _mutated_docs()
        graph = raw["execution_closure"]["executable_graph"]
        declaration = next(row for row in graph["declarations"] if row["kind"] == "elf_search")
        edge = next(row for row in graph["edges"] if row["declaration_ref"] == declaration["id"])
        declaration["owner_id"] = edge["from_id"] = "file:runtime-policy:/usr/lib/spp/conf_proc_spp_init.py"
        declaration["order_group"] = edge["order_group"] = "elf-search:" + edge["from_id"]
        declaration["id"] = semantics._graph_declaration_id_v3(
            kind=declaration["kind"], owner_id=declaration["owner_id"], order_group=declaration["order_group"],
            ordinal=declaration["ordinal"], requested_path=declaration["requested_path"],
            target_id=declaration["target_id"], alias_chain=tuple(declaration["alias_chain"]),
        )
        edge["declaration_ref"] = declaration["id"]
        edge["id"] = semantics._graph_edge_id_v3(
            kind=edge["kind"], from_id=edge["from_id"], to_id=edge["to_id"], order_group=edge["order_group"],
            ordinal=edge["ordinal"], requested_path=edge["requested_path"], resolved_id=edge["resolved_id"],
            alias_chain=tuple(edge["alias_chain"]), declaration_kind=edge["declaration_kind"], declaration_ref=edge["declaration_ref"],
        )
        graph["declarations"].sort(key=lambda row: row["id"].encode("utf-8"))
        graph["edges"].sort(key=lambda row: row["id"].encode("utf-8"))
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_elf_loader_control_kinds_and_cross_lane_substitution_are_rejected(self) -> None:
        for kind in ("elf_needed", "elf_preload", "elf_audit", "elf_cache"):
            with self.subTest(kind=kind):
                docs, raw = _mutated_docs()
                raw["execution_closure"]["elf_loader_controls"][0]["kind"] = kind
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        docs, raw = _mutated_docs()
        graph = raw["execution_closure"]["executable_graph"]
        edge = next(row for row in graph["edges"] if row["kind"] == "elf_interpreter" and row["declaration_kind"] == "loader_control")
        edge["declaration_kind"] = "executable_graph"
        declaration = {
            "kind": edge["kind"], "owner_id": edge["from_id"], "order_group": "elf-interpreter:" + edge["from_id"],
            "ordinal": edge["ordinal"], "requested_path": edge["requested_path"], "target_id": edge["to_id"],
            "alias_chain": edge["alias_chain"],
        }
        declaration["id"] = semantics._graph_declaration_id_v3(
            kind=declaration["kind"], owner_id=declaration["owner_id"], order_group=declaration["order_group"],
            ordinal=declaration["ordinal"], requested_path=declaration["requested_path"], target_id=declaration["target_id"], alias_chain=tuple(declaration["alias_chain"]),
        )
        edge["order_group"] = declaration["order_group"]
        edge["declaration_ref"] = declaration["id"]
        edge["id"] = semantics._graph_edge_id_v3(
            kind=edge["kind"], from_id=edge["from_id"], to_id=edge["to_id"], order_group=edge["order_group"], ordinal=edge["ordinal"], requested_path=edge["requested_path"], resolved_id=edge["resolved_id"], alias_chain=tuple(edge["alias_chain"]), declaration_kind=edge["declaration_kind"], declaration_ref=edge["declaration_ref"],
        )
        graph["declarations"].append(declaration)
        graph["declarations"].sort(key=lambda row: row["id"].encode("utf-8"))
        graph["edges"].sort(key=lambda row: row["id"].encode("utf-8"))
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_prohibited_elf_ambient_authority_negative_matrix_is_durable(self) -> None:
        ambient_cases = {
            "elf_preload": ("LD_PRELOAD", "/etc/ld.so.preload"),
            "elf_audit": ("LD_AUDIT", "/etc/ld.so.audit"),
            "elf_cache": ("LD_CONFIG_FILE", "/etc/ld.so.cache"),
        }
        for ambient_kind, (environment_name, config_path) in ambient_cases.items():
            with self.subTest(kind=ambient_kind, carrier="predecessor"):
                docs, raw = _mutated_docs()
                raw["execution_closure"]["elf_loader_controls"][0]["kind"] = ambient_kind
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

            with self.subTest(kind=ambient_kind, carrier="control"):
                docs, raw = _mutated_docs()
                graph = raw["execution_closure"]["executable_graph"]
                control = next(row for row in graph["controls"] if row["kind"] == "elf_search")
                control["kind"] = ambient_kind
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

            with self.subTest(kind=ambient_kind, carrier="declaration"):
                docs, raw = _mutated_docs()
                graph = raw["execution_closure"]["executable_graph"]
                declaration = next(row for row in graph["declarations"] if row["kind"] == "elf_search")
                declaration["kind"] = ambient_kind
                _rehash_graph_declaration(declaration)
                graph["declarations"].sort(key=lambda row: row["id"].encode("utf-8"))
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

            with self.subTest(kind=ambient_kind, carrier="edge"):
                docs, raw = _mutated_docs()
                graph = raw["execution_closure"]["executable_graph"]
                edge = next(row for row in graph["edges"] if row["kind"] == "elf_search")
                edge["kind"] = ambient_kind
                _rehash_graph_edge(edge)
                graph["edges"].sort(key=lambda row: row["id"].encode("utf-8"))
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

            with self.subTest(kind=ambient_kind, carrier="environment"):
                docs, raw = _mutated_docs()
                closure = raw["execution_closure"]
                record = closure["jit_derivations"][0]
                record["argv_env"]["environment"].append([environment_name, config_path])
                closure["expected_outputs"][0]["derivation_sha256"] = jit_derivation_sha256_v3(record)
                _rebuild_fixture_graph(docs, raw)
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

            with self.subTest(kind=ambient_kind, carrier="configuration"):
                docs, raw = _mutated_docs()
                closure = raw["execution_closure"]
                record = closure["jit_derivations"][0]
                configuration = next(row for row in record["inputs"] if row["kind"] == "configuration")
                configuration["path"] = config_path
                closure["expected_outputs"][0]["derivation_sha256"] = jit_derivation_sha256_v3(record)
                _rebuild_fixture_graph(docs, raw)
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

            with self.subTest(kind=ambient_kind, carrier="coherent_bundle"):
                docs, raw = _mutated_docs()
                control = raw["execution_closure"]["elf_loader_controls"][0]
                control["kind"] = ambient_kind
                _rebuild_fixture_graph(docs, raw)
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        raw["execution_closure"]["elf_loader_controls"].append({
            "kind": "elf_search", "owner_path": "/usr/bin/spp", "ordinal": 1,
            "requested_path": "/lib/x86_64-linux-gnu", "resolved_image": "runtime-policy",
            "resolved_path": "/usr/lib/x86_64-linux-gnu", "alias_chain": ["/lib/x86_64-linux-gnu"],
        })
        _rebuild_fixture_graph(docs, raw)
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_jit_tmpfs_source_refs_and_directory_denominator_are_closed(self) -> None:
        for kwargs, expected in (
            ({"execution_mode": "python_no_jit", "cache_policy": "absent"}, (("/run/spp-state", 1048576, 0o755),)),
            ({"execution_mode": "python_jit_triton", "cache_policy": "ephemeral_rebuild"}, (("/run/spp-state", 1048576, 0o755), ("/run/spp-jit", 1073741824, 0o700))),
            ({"execution_mode": "python_jit_triton", "cache_policy": "measured_read_only"}, (("/run/spp-state", 1048576, 0o755), ("/run/spp-jit", 1073741824, 0o700))),
        ):
            docs, contract = build_v3_fixture(**kwargs)
            with self.subTest(storage=kwargs):
                self.assertEqual(boot.bind_boot_inputs_v3(contract=contract, **docs).storage.tmpfs_mounts, expected)

        for field, mutated in (
            ("tmpfs_mounts", (("/run/spp-state", 1048576, 0o755),)),
            ("tmpfs_mounts", (("/run/spp-state", 1048576, 0o755), ("/run/spp-jit", 1073741823, 0o700))),
            ("tmpfs_mounts", (("/run/spp-state", 1048576, 0o755), ("/run/spp-jit", 1073741824, 0o755))),
            ("tmpfs_mounts", (("/run/spp-state", 1048576, 0o755), ("/run/spp-jit-wrong", 1073741824, 0o700))),
            ("mount_union", ("/run/spp-state", "/usr/lib/spp/models", "/usr/lib/spp/runtime")),
        ):
            docs, contract = build_v3_fixture(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild")
            binding = boot.bind_boot_inputs_v3(contract=contract, **docs)
            object.__setattr__(binding.storage, field, mutated)
            with self.subTest(storage_field=field, mutated=mutated):
                self.assertFalse(boot.is_issued_boot_binding_v3(binding))

        for lane, replacement in (
            ("compiler_argv", "--jit-workspace=/run/spp-jit-escape"),
            ("compiler_argv", "--jit-workspace=/run/spp-jit-escape-alt"),
            ("loader_argv", "--jit-workspace=/run/spp-jit-escape"),
            ("loader_argv", "--jit-workspace=/run/spp-jit-escape-alt"),
        ):
            docs, raw = _mutated_docs(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild")
            closure = raw["execution_closure"]
            record = closure["jit_derivations"][0]
            record["argv_env"][lane][-2] = replacement
            closure["expected_outputs"][0]["derivation_sha256"] = jit_derivation_sha256_v3(record)
            _rebuild_fixture_graph(docs, raw)
            _commit_contract(docs, raw)
            with self.subTest(argv_lane=lane, replacement=replacement):
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        for lane, mutation, replacement in (
            ("compiler_argv", "executable", "/run/spp-jit-escape/unmeasured-compiler"),
            ("loader_argv", "executable", "/run/spp-jit-escape/unmeasured-loader"),
            ("compiler_argv", "extra_input", "/run/spp-jit-escape/owner-supplied-source.py"),
            ("loader_argv", "extra_input", "/run/spp-jit-escape/owner-supplied-plugin.py"),
        ):
            docs, raw = _mutated_docs(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild")
            closure = raw["execution_closure"]
            record = closure["jit_derivations"][0]
            argv = record["argv_env"][lane]
            if mutation == "executable":
                argv[0] = replacement
            else:
                argv.insert(1, replacement)
            closure["expected_outputs"][0]["derivation_sha256"] = jit_derivation_sha256_v3(record)
            _rebuild_fixture_graph(docs, raw)
            _commit_contract(docs, raw)
            with self.subTest(argv_lane=lane, mutation=mutation):
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        docs, contract = build_v3_fixture(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild", extra_jit_derivation=True)
        binding = boot.bind_boot_inputs_v3(contract=contract, **docs)
        references = [row.declaration_ref for row in binding.predicate5.executable_graph.edges if row.kind == "jit_compiler"]
        self.assertEqual(len(references), len(set(references)), 2)

        raw = canonical_loads(docs["boot_contract_bytes"])
        graph = raw["execution_closure"]["executable_graph"]
        compiler_edges = [row for row in graph["edges"] if row["kind"] == "jit_compiler"]
        compiler_edges[1]["declaration_ref"] = compiler_edges[0]["declaration_ref"]
        compiler_edges[1]["id"] = semantics._graph_edge_id_v3(
            kind=compiler_edges[1]["kind"], from_id=compiler_edges[1]["from_id"], to_id=compiler_edges[1]["to_id"],
            order_group=compiler_edges[1]["order_group"], ordinal=compiler_edges[1]["ordinal"], requested_path=compiler_edges[1]["requested_path"], resolved_id=compiler_edges[1]["resolved_id"], alias_chain=tuple(compiler_edges[1]["alias_chain"]), declaration_kind=compiler_edges[1]["declaration_kind"], declaration_ref=compiler_edges[1]["declaration_ref"],
        )
        graph["edges"].sort(key=lambda row: row["id"].encode("utf-8"))
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_jit_storage_semantic_negative_matrix_binds_through_contract(self) -> None:
        for mode, policy, expected in (
            ("python_no_jit", "absent", (("/run/spp-state", 1048576, 0o755),)),
            (
                "python_jit_triton", "ephemeral_rebuild",
                (("/run/spp-state", 1048576, 0o755), ("/run/spp-jit", 1073741824, 0o700)),
            ),
            (
                "python_jit_triton", "measured_read_only",
                (("/run/spp-state", 1048576, 0o755), ("/run/spp-jit", 1073741824, 0o700)),
            ),
        ):
            docs, contract = build_v3_fixture(execution_mode=mode, cache_policy=policy)
            storage = boot.bind_boot_inputs_v3(contract=contract, **docs).storage
            with self.subTest(mode=mode, policy=policy, positive="exact_storage"):
                self.assertEqual(storage.tmpfs_mounts, expected)
                self.assertEqual(storage.tmpfs_mounts.count(("/run/spp-jit", 1073741824, 0o700)), 0 if mode == "python_no_jit" else 1)
                self.assertTrue(all(type(path) is str and type(size) is int and type(mount_mode) is int for path, size, mount_mode in storage.tmpfs_mounts))
                self.assertEqual(len(storage.mount_union), len(set(storage.mount_union)))

        for mutation in ("jit_records_in_no_jit", "missing_output", "duplicate_output", "duplicate_derivation"):
            with self.subTest(mutation=mutation):
                docs, raw = _mutated_docs()
                closure = raw["execution_closure"]
                if mutation == "jit_records_in_no_jit":
                    raw["execution_mode"] = "python_no_jit"
                    raw["cache_policy"] = "absent"
                elif mutation == "missing_output":
                    closure["expected_outputs"].pop()
                elif mutation == "duplicate_output":
                    closure["expected_outputs"].append(deepcopy(closure["expected_outputs"][0]))
                else:
                    closure["jit_derivations"].append(deepcopy(closure["jit_derivations"][0]))
                    closure["expected_outputs"].append(deepcopy(closure["expected_outputs"][0]))
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA if mutation == "jit_records_in_no_jit" else CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        for field, value in (("size_bytes", True), ("mode", [0o555])):
            with self.subTest(mutation="output_type", field=field):
                docs, raw = _mutated_docs()
                closure = raw["execution_closure"]
                closure["jit_derivations"][0]["output"][field] = value
                closure["expected_outputs"][0][field] = value
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_SCHEMA):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        for cache_policy, output_path in (
            ("ephemeral_rebuild", "/run/spp-jit"),
            ("ephemeral_rebuild", "/run/spp-state/kernel.so"),
            ("ephemeral_rebuild", "/run/spp-jit-escape/kernel.so"),
            ("measured_read_only", "/run/spp-jit-escape/kernel.so"),
        ):
            with self.subTest(cache_policy=cache_policy, mutation="output_path", path=output_path):
                docs, raw = _mutated_docs(cache_policy=cache_policy)
                output = next(
                    row for row in raw["execution_closure"]["executable_graph"]["nodes"]
                    if row["kind"] == "jit_output"
                )
                output["path"] = output_path
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        for lane in ("compiler_argv", "loader_argv"):
            for workspace in (
                "--jit-workspace=/run/spp-jit-escape", "--jit-workspace=/run/spp-state",
                "--jit-workspace=/run/spp-jit-escape-alt", "--jit-workspace=/usr/lib/spp/jit-cache",
            ):
                with self.subTest(lane=lane, mutation="workspace_argv", workspace=workspace):
                    docs, raw = _mutated_docs()
                    closure = raw["execution_closure"]
                    record = closure["jit_derivations"][0]
                    record["argv_env"][lane][-2] = workspace
                    closure["expected_outputs"][0]["derivation_sha256"] = jit_derivation_sha256_v3(record)
                    _rebuild_fixture_graph(docs, raw)
                    _commit_contract(docs, raw)
                    with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                        boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        for immutable_destination in ("/run/spp-jit", "/run/spp-jit/runtime", "/run"):
            with self.subTest(mutation="immutable_overlap", destination=immutable_destination):
                docs, raw = _mutated_docs()
                lock = canonical_loads(docs["root_lock_bytes"])
                policy = canonical_loads(docs["policy_bytes"])
                runtime_mount = next(row for row in policy["mounts"] if row["image"] == "runtime-policy")
                runtime_mount["destination"] = immutable_destination
                policy["mounts"].sort(key=lambda row: (row["image"], row["destination"]))
                _rebuild_predecessors(docs, lock, policy)
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_multi_derivation_source_refs_are_parent_scoped_and_collision_free(self) -> None:
        docs, contract = build_v3_fixture(
            execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild",
            extra_jit_derivation=True,
        )
        binding = boot.bind_boot_inputs_v3(contract=contract, **docs)
        derivations = binding.predicate5.jit_derivations
        self.assertEqual(len(derivations), 2)
        graph = binding.predicate5.executable_graph
        for kind in ("jit_compiler", "jit_loader", "jit_input", "jit_output"):
            refs_by_parent = {
                edge.from_id: edge.declaration_ref
                for edge in graph.edges if edge.kind == kind and edge.ordinal == 0
            }
            with self.subTest(kind=kind, positive="distinct_parent_refs"):
                self.assertEqual(len(refs_by_parent), 2)
                self.assertEqual(len(set(refs_by_parent.values())), 2)

        for kind in ("jit_compiler", "jit_loader", "jit_input", "jit_output"):
            for mutation in ("omit_parent", "swap_parent", "change_parent", "legacy_payload", "reuse_ref"):
                with self.subTest(kind=kind, mutation=mutation):
                    docs, _ = build_v3_fixture(
                        execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild",
                        extra_jit_derivation=True,
                    )
                    raw = canonical_loads(docs["boot_contract_bytes"])
                    closure = raw["execution_closure"]
                    records = closure["jit_derivations"]
                    parent_digests = [jit_derivation_sha256_v3(record) for record in records]
                    graph_raw = closure["executable_graph"]
                    parent_ids = ["derivation:" + digest for digest in parent_digests]
                    edges = [
                        edge for edge in graph_raw["edges"]
                        if edge["kind"] == kind and edge["ordinal"] == 0
                    ]
                    edge_by_parent = {edge["from_id"]: edge for edge in edges}
                    edge = edge_by_parent[parent_ids[1]]
                    relation = _jit_relation(records[1], kind, edge["ordinal"])
                    if mutation == "omit_parent":
                        payload: object = {"relation": relation}
                        edge["declaration_ref"] = _jit_source_ref(
                            kind=kind, ordinal=edge["ordinal"], payload=payload,
                        )
                    elif mutation == "swap_parent":
                        payload = {"derivation_sha256": parent_digests[0], "relation": relation}
                        edge["declaration_ref"] = _jit_source_ref(
                            kind=kind, ordinal=edge["ordinal"], payload=payload,
                        )
                    elif mutation == "change_parent":
                        payload = {"derivation_sha256": "0" * 64, "relation": relation}
                        edge["declaration_ref"] = _jit_source_ref(
                            kind=kind, ordinal=edge["ordinal"], payload=payload,
                        )
                    elif mutation == "legacy_payload":
                        edge["declaration_ref"] = _jit_source_ref(
                            kind=kind, ordinal=edge["ordinal"], payload=relation,
                        )
                    else:
                        edge["declaration_ref"] = edge_by_parent[parent_ids[0]]["declaration_ref"]
                    _rehash_graph_edge(edge)
                    graph_raw["edges"].sort(key=lambda row: row["id"].encode("utf-8"))
                    _commit_contract(docs, raw)
                    with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                        boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        docs, _ = build_v3_fixture(
            execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild",
            extra_jit_derivation=True,
        )
        raw = canonical_loads(docs["boot_contract_bytes"])
        closure = raw["execution_closure"]
        records = closure["jit_derivations"]
        parent_digest = jit_derivation_sha256_v3(records[1])
        graph_raw = closure["executable_graph"]
        inputs = sorted(
            (
                edge for edge in graph_raw["edges"]
                if edge["kind"] == "jit_input" and edge["from_id"] == "derivation:" + parent_digest
            ),
            key=lambda edge: edge["ordinal"],
        )
        self.assertGreaterEqual(len(inputs), 2)
        inputs[1]["ordinal"] = 0
        relation = _jit_relation(records[1], "jit_input", 1)
        inputs[1]["declaration_ref"] = _jit_source_ref(
            kind="jit_input", ordinal=0,
            payload={"derivation_sha256": parent_digest, "relation": relation},
        )
        _rehash_graph_edge(inputs[1])
        graph_raw["edges"].sort(key=lambda row: row["id"].encode("utf-8"))
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_every_measured_directory_requires_an_exact_consumer(self) -> None:
        docs, raw = _mutated_docs()
        graph = raw["execution_closure"]["executable_graph"]
        directories = [row for row in graph["nodes"] if row["kind"] == "measured_directory"]
        self.assertEqual(
            {row["path"] for row in directories},
            {
                "/usr/lib/python3.10", "/usr/lib/python3.10/lib-dynload", "/usr/lib/spp",
                "/usr/lib/spp/vendor", "/usr/lib/spp/lib", "/usr/lib/x86_64-linux-gnu",
            },
        )
        consumer_classes: set[str] = set()
        for directory in directories:
            path = directory["path"]
            identity = directory["id"]
            consumers: set[str] = set()
            for control in graph["controls"]:
                if control.get("path") == path and control.get("path_kind") == "measured_directory":
                    consumers.add("startup_control")
                if path in control.get("contributed_paths", []):
                    consumers.add("loading_control")
                if control.get("kind") == "elf_search" and control.get("resolved_id") == identity:
                    consumers.add("elf_control")
            if any(edge["to_id"] == identity for edge in graph["edges"]):
                consumers.add("edge")
            if any(alias["resolved_id"] == identity for alias in graph["aliases"]):
                consumers.add("alias_terminal")
            with self.subTest(path=path, positive="enumerated_consumer"):
                self.assertTrue(consumers)
            consumer_classes.update(consumers)
        self.assertEqual(
            consumer_classes,
            {"startup_control", "loading_control", "elf_control", "edge", "alias_terminal"},
        )

        for expected in directories:
            path = expected["path"]
            with self.subTest(path=path, mutation="orphan"):
                docs, raw = _mutated_docs()
                graph = raw["execution_closure"]["executable_graph"]
                identity = next(
                    row["id"] for row in graph["nodes"]
                    if row["kind"] == "measured_directory" and row["path"] == path
                )
                for control in graph["controls"]:
                    if path in control.get("contributed_paths", []):
                        control["contributed_paths"].remove(path)
                graph["controls"] = [
                    control for control in graph["controls"]
                    if not (
                        (control.get("path") == path and control.get("path_kind") == "measured_directory")
                        or (control.get("kind") == "elf_search" and control.get("resolved_id") == identity)
                    )
                ]
                removed_declarations = {
                    declaration["id"] for declaration in graph["declarations"]
                    if declaration["target_id"] == identity
                }
                graph["declarations"] = [
                    declaration for declaration in graph["declarations"]
                    if declaration["id"] not in removed_declarations
                ]
                graph["edges"] = [
                    edge for edge in graph["edges"]
                    if edge["to_id"] != identity and edge["declaration_ref"] not in removed_declarations
                ]
                graph["aliases"] = [alias for alias in graph["aliases"] if alias["resolved_id"] != identity]
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

            for mutation in ("descendant_only", "wrong_image"):
                with self.subTest(path=path, mutation=mutation):
                    docs, raw = _mutated_docs()
                    graph = raw["execution_closure"]["executable_graph"]
                    node = next(
                        row for row in graph["nodes"]
                        if row["kind"] == "measured_directory" and row["path"] == path
                    )
                    old_id = node["id"]
                    if mutation == "descendant_only":
                        node["path"] = path + "/descendant"
                    else:
                        node["image"] = "models"
                    node["id"] = "dir:" + node["image"] + ":" + node["path"]
                    _remap_graph_identity(graph, old_id, node["id"])
                    graph["nodes"].sort(key=lambda row: row["id"].encode("utf-8"))
                    _commit_contract(docs, raw)
                    with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                        boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        docs, raw = _mutated_docs()
        graph = raw["execution_closure"]["executable_graph"]
        extra = deepcopy(next(row for row in graph["nodes"] if row["kind"] == "measured_directory"))
        extra.update({"id": "dir:runtime-policy:/usr/lib/spp/unconsumed-root", "path": "/usr/lib/spp/unconsumed-root"})
        graph["nodes"].append(extra)
        graph["nodes"].sort(key=lambda row: row["id"].encode("utf-8"))
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        self.assertEqual(
            {row["path"] for row in raw["execution_closure"]["executable_graph"]["nodes"] if row["kind"] == "measured_directory"},
            {"/usr/lib/python3.10", "/usr/lib/python3.10/lib-dynload", "/usr/lib/spp", "/usr/lib/spp/vendor", "/usr/lib/spp/lib", "/usr/lib/x86_64-linux-gnu"},
        )

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        lock = canonical_loads(docs["root_lock_bytes"])
        policy = canonical_loads(docs["policy_bytes"])
        placement = next(
            placement
            for item in lock["inputs"]
            for placement in item["placements"]
            if placement["node_type"] == "directory" and placement["path"] == "/usr/lib/spp/lib"
        )
        placement["image"] = "models"
        directory = next(
            node
            for node in policy["images"]["runtime-policy"]["nodes"]
            if node["node_type"] == "directory" and node["path"] == "/usr/lib/spp/lib"
        )
        policy["images"]["runtime-policy"]["nodes"].remove(directory)
        policy["images"]["models"]["nodes"].append(directory)
        policy["images"]["models"]["nodes"].sort(key=lambda item: item["path"])
        _rebuild_predecessors(docs, lock, policy)
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        docs, raw = _mutated_docs(execution_mode="python_no_jit", cache_policy="absent")
        raw["execution_closure"]["elf_loader_controls"] = []
        _rebuild_fixture_graph(docs, raw)
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

    def test_python_import_order_groups_are_exact(self) -> None:
        for phase in ("controller_pre", "role_pre", "post_bootstrap"):
            with self.subTest(phase=phase):
                docs, raw = _mutated_docs()
                graph = raw["execution_closure"]["executable_graph"]
                declaration = next(row for row in graph["declarations"] if row["kind"] == "python_import")
                _set_graph_declaration_group(graph, declaration, "python-import:" + declaration["owner_id"] + ":" + phase)
                _commit_contract(docs, raw)
                boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        for suffix in ("middle:post_bootstrap", "post_bootstrap:extra", "not-python-import:post_bootstrap"):
            with self.subTest(suffix=suffix):
                docs, raw = _mutated_docs()
                graph = raw["execution_closure"]["executable_graph"]
                declaration = next(row for row in graph["declarations"] if row["kind"] == "python_import")
                _set_graph_declaration_group(graph, declaration, "python-import:" + declaration["owner_id"] + ":" + suffix)
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        docs, raw = _mutated_docs()
        raw["execution_closure"]["loader_controls"][0]["read_only"] = False
        _commit_contract(docs, raw)
        contract = _parsed_contract(docs)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=contract, **docs)

    def test_python_import_group_owner_phase_and_ordinal_matrix_is_closed(self) -> None:
        for mutation in (
            "empty_owner", "empty_phase", "empty_middle", "alternate_phase",
            "matching_prefix_only", "owner_swap",
        ):
            with self.subTest(mutation=mutation):
                docs, raw = _mutated_docs()
                graph = raw["execution_closure"]["executable_graph"]
                declaration = next(row for row in graph["declarations"] if row["kind"] == "python_import")
                owner = declaration["owner_id"]
                if mutation == "empty_owner":
                    group = "python-import::post_bootstrap"
                elif mutation == "empty_phase":
                    group = "python-import:" + owner + ":"
                elif mutation == "empty_middle":
                    group = "python-import:" + owner + "::post_bootstrap"
                elif mutation == "alternate_phase":
                    group = "python-import:" + owner + ":post-bootstrap"
                elif mutation == "matching_prefix_only":
                    group = "python-import:" + owner
                else:
                    alternate_owner = next(item for item in graph["entrypoints"] if item != owner)
                    group = "python-import:" + alternate_owner + ":post_bootstrap"
                _set_graph_declaration_group(graph, declaration, group)
                _commit_contract(docs, raw)
                with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
                    boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

        docs, raw = _mutated_docs()
        graph = raw["execution_closure"]["executable_graph"]
        declaration = next(row for row in graph["declarations"] if row["kind"] == "python_import")
        edge = next(row for row in graph["edges"] if row["declaration_ref"] == declaration["id"])
        declaration["ordinal"] = edge["ordinal"] = 1
        old_id = declaration["id"]
        _rehash_graph_declaration(declaration)
        edge["declaration_ref"] = declaration["id"]
        self.assertNotEqual(old_id, declaration["id"])
        _rehash_graph_edge(edge)
        graph["declarations"].sort(key=lambda row: row["id"].encode("utf-8"))
        graph["edges"].sort(key=lambda row: row["id"].encode("utf-8"))
        _commit_contract(docs, raw)
        with self.assertRaisesRegex(ApplianceErrorV3, CP_BOOT_V3_BINDING):
            boot.bind_boot_inputs_v3(contract=_parsed_contract(docs), **docs)

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
