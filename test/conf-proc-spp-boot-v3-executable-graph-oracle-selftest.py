#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent byte-level oracle for the v3 executable-graph carrier."""

from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import posixpath
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_spp_boot_v3_fixture import build_v3_fixture


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _frame(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _file(image: str, path: str) -> str:
    return f"file:{image}:{path}"


def _directory(image: str, path: str) -> str:
    return f"dir:{image}:{path}"


def _derivation(digest: str) -> str:
    return "derivation:" + digest


def _output(digest: str, name: str) -> str:
    return f"jit:{digest}:{name}"


def _source_ref(source_kind: str, phase: str | None, kind: str, ordinal: int, payload: object) -> str:
    material = {"schema": "sol-spp-executable-graph-source/v1", "source_kind": source_kind, "phase": phase, "kind": kind, "ordinal": ordinal, "payload": payload}
    return "source:" + source_kind + ":" + _sha(b"sol-spp-executable-graph-source/v1\0" + _frame(canonical_dumps(material)))


def _declaration_id(row: dict[str, object]) -> str:
    return _sha(canonical_dumps({key: row[key] for key in ("kind", "owner_id", "order_group", "ordinal", "requested_path", "target_id", "alias_chain")}))


def _edge_id(row: dict[str, object]) -> str:
    return _sha(canonical_dumps({key: row[key] for key in ("kind", "from_id", "to_id", "order_group", "ordinal", "requested_path", "resolved_id", "alias_chain", "declaration_kind", "declaration_ref")}))


def _jit_digest(record: dict[str, object]) -> str:
    compiler = record["compiler"]
    loader = record["loader"]
    argv_env = record["argv_env"]
    inputs = record["inputs"]
    output = record["output"]
    assert type(compiler) is dict and type(loader) is dict and type(argv_env) is dict and type(inputs) is list and type(output) is dict
    material = b"sol-spp-jit-output-v3\0"
    material += _frame(compiler["input_id"].encode("ascii")) + _frame(compiler["sha256"].encode("ascii"))
    material += _frame(loader["input_id"].encode("ascii")) + _frame(loader["sha256"].encode("ascii"))
    material += _frame(canonical_dumps(argv_env))
    material += b"".join(_frame(canonical_dumps(item)) for item in inputs)
    material += _frame(canonical_dumps(output)) + _frame(record["cache_policy"].encode("ascii"))
    return _sha(material)


def _fail(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _expected_controls(closure: dict[str, object]) -> list[dict[str, object]]:
    kat = closure["startup_kat"]
    bootstrap = closure["bootstrap"]
    assert type(kat) is dict and type(bootstrap) is dict
    observation = kat["capture"]["observation"]
    assert type(observation) is dict
    rows: list[dict[str, object]] = []

    def add(kind: str, phase: str, ordinal: int, payload: object, declaration_kind: str, identity: str | None = None, path: str | None = None, path_kind: str | None = None, finder: str | None = None, loader_details: object = None) -> None:
        rows.append({"kind": kind, "phase": phase, "ordinal": ordinal, "identity": identity, "path": path, "path_kind": path_kind, "finder": finder, "loader_details": loader_details, "declaration_kind": declaration_kind, "declaration_ref": _source_ref(declaration_kind, phase, kind, ordinal, payload)})

    for phase, cache_key, source_kind in (("controller_pre", "controller_pre_importer_cache", "controller_cache_projection"), ("role_pre", "role_pre_importer_cache", "role_cache_projection")):
        for ordinal, path in enumerate(observation["path"]):
            add("python_search_path", phase, ordinal, {"path": path}, "startup_receipt", path=path, path_kind="denied_zip" if path == "/usr/lib/python310.zip" else "measured_directory")
        for ordinal, identity in enumerate(observation["meta_path"]):
            add("python_meta_path", phase, ordinal, {"identity": identity}, "startup_receipt", identity=identity)
        for ordinal, hook in enumerate(observation["path_hooks"]):
            add("python_path_hook", phase, ordinal, hook, "startup_receipt", identity=hook["identity"], loader_details=hook["loader_details"])
        for ordinal, cache in enumerate(bootstrap[cache_key]):
            path = cache["path"]
            add("python_importer_cache", phase, ordinal, cache, source_kind, path=path, path_kind="denied_zip" if path == "/usr/lib/python310.zip" else ("measured_file" if cache["finder"] is None else "measured_directory"), finder=cache["finder"])
    for ordinal, path in enumerate(bootstrap["post_path"]):
        add("python_search_path", "post_bootstrap", ordinal, {"path": path}, "bootstrap_projection", path=path, path_kind="measured_directory")
    for ordinal, identity in enumerate(bootstrap["post_meta_path"]):
        add("python_meta_path", "post_bootstrap", ordinal, {"identity": identity}, "bootstrap_projection", identity=identity)
    for ordinal, hook in enumerate(bootstrap["post_path_hooks"]):
        add("python_path_hook", "post_bootstrap", ordinal, hook, "bootstrap_projection", identity=hook["identity"], loader_details=hook["loader_details"])
    for ordinal, cache in enumerate(bootstrap["post_importer_cache"]):
        add("python_importer_cache", "post_bootstrap", ordinal, cache, "bootstrap_projection", path=cache["path"], path_kind="measured_file" if cache["finder"] is None else "measured_directory", finder=cache["finder"])
    for ordinal, control in enumerate(closure["loader_controls"]):
        payload = {key: control[key] for key in ("path", "kind", "read_only", "contributed_paths", "imports", "hooks")}
        rows.append({"kind": "python_" + control["kind"], "phase": "runtime_startup", "ordinal": ordinal, "owner_id": _file("runtime-policy", control["path"]), "read_only": control["read_only"], "contributed_paths": control["contributed_paths"], "imports": control["imports"], "hooks": control["hooks"], "declaration_kind": "loader_control", "declaration_ref": _source_ref("loader_control", None, control["kind"], ordinal, payload)})
    return rows


def _validate_graph(docs: dict[str, bytes]) -> dict[str, object]:
    contract = canonical_loads(docs["boot_contract_bytes"])
    policy = canonical_loads(docs["policy_bytes"])
    lock = canonical_loads(docs["root_lock_bytes"])
    runtime = canonical_loads(docs["runtime_closure_bytes"])
    closure = contract["execution_closure"]
    graph = closure["executable_graph"]
    _fail(set(graph) == {"schema", "alias_hop_limit", "entrypoints", "nodes", "aliases", "controls", "declarations", "edges"} and graph["schema"] == "sol-spp-executable-graph/v1" and type(graph["alias_hop_limit"]) is int and graph["alias_hop_limit"] == 40, "graph carrier")
    eligible = closure["eligible_files"]
    by_path = {row["path"]: row for row in eligible}
    image = "runtime-policy"
    entry_paths = ("/usr/bin/spp", "/usr/bin/python3.10", "/usr/lib/spp/conf_proc_spp_init.py", "/usr/lib/spp/conf_proc_spp_role_bootstrap.py", "/usr/lib/spp/conf_proc_spp_attestation_broker.py", "/usr/lib/spp/conf_proc_spp_inference.py", "/usr/lib/spp/asr_shim.py", "/usr/lib/spp/ratls_gateway.py", "/usr/lib/spp/ratls_collector.py")
    _fail(graph["entrypoints"] == [_file(image, path) for path in entry_paths], "entrypoints")
    jit_records = closure["jit_derivations"]
    noncode = {item["path"] for record in jit_records for item in record["inputs"] if item["kind"] in ("configuration", "model")}
    tags = {"launch_executable", "importable_module", "python_loading_control", "native_extension", "dynamic_library", "compiler", "compiler_source", "model_code", "plugin", "jit_cache"}
    expected_nodes = [{"id": _file(row["image"], row["path"]), "kind": "measured_file", "image": row["image"], "path": row["path"], "sha256": row["sha256"], "size_bytes": row["size_bytes"], "mode": row["mode"], "content_kind": row["content_kind"], "semantic_tags": row["semantic_tags"], "input_id": row["input_id"]} for row in eligible if tags & set(row["semantic_tags"]) or row["path"] in noncode]
    roots = {"/usr/lib/python3.10", "/usr/lib/python3.10/lib-dynload", "/usr/lib/spp", "/usr/lib/spp/vendor", "/usr/lib/spp/lib", "/usr/lib/x86_64-linux-gnu"}
    expected_nodes += [{"id": _directory(image, row["path"]), "kind": "measured_directory", "image": image, "path": row["path"], "mode": row["mode"], "uid": row["uid"], "gid": row["gid"]} for row in policy["images"][image]["nodes"] if row["node_type"] == "directory" and row["path"] in roots]
    for record in jit_records:
        digest = _jit_digest(record)
        output = record["output"]
        path = "/usr/lib/spp/jit-cache/" + digest + "/" + output["output_name"] if record["cache_policy"] == "measured_read_only" else "/run/spp-jit/" + digest + "/" + output["output_name"]
        expected_nodes += [{"id": _derivation(digest), "kind": "jit_derivation", "derivation_sha256": digest}, {"id": _output(digest, output["output_name"]), "kind": "jit_output", "derivation_sha256": digest, "output_name": output["output_name"], "path": path, "sha256": output["sha256"], "size_bytes": output["size_bytes"], "mode": output["mode"]}]
    expected_nodes.sort(key=lambda row: row["id"].encode("utf-8"))
    _fail(graph["nodes"] == expected_nodes, "node denominator")
    lock_aliases = {(placement["image"], placement["path"]): placement for item in lock["inputs"] for placement in item["placements"] if placement["node_type"] == "symlink"}
    policy_aliases = {(image, row["path"]): row for row in policy["images"][image]["nodes"] if row["node_type"] == "symlink"}
    runtime_aliases = {row["path"]: row for row in runtime["entries"] if row["node_type"] == "symlink"}
    _fail(len(graph["aliases"]) == len(lock_aliases) == len(policy_aliases) == len(runtime_aliases), "alias denominator")
    for alias in graph["aliases"]:
        key = (alias["image"], alias["path"])
        _fail(key in lock_aliases and key in policy_aliases and alias["path"] in runtime_aliases, "alias predecessor")
        _fail(lock_aliases[key]["target"] == policy_aliases[key]["target"] == runtime_aliases[alias["path"]]["symlink_target"] == alias["target"] and alias["hop_count"] == len(alias["chain"]) and alias["chain"] == [alias["path"]], "alias identity")
        target = alias["target"] if alias["target"].startswith("/") else posixpath.join(posixpath.dirname(alias["path"]), alias["target"])
        terminal = posixpath.normpath(target)
        expected = _directory(image, terminal) if terminal in roots else _file(image, terminal)
        _fail(alias["resolved_id"] == expected, "alias terminal")
    _fail(graph["controls"] == _expected_controls(closure), "control denominator")
    _fail([row["id"] for row in graph["declarations"]] == sorted((row["id"] for row in graph["declarations"]), key=lambda item: item.encode("utf-8")) and all(row["id"] == _declaration_id(row) for row in graph["declarations"]), "declaration digest")
    _fail([row["id"] for row in graph["edges"]] == sorted((row["id"] for row in graph["edges"]), key=lambda item: item.encode("utf-8")) and all(row["id"] == _edge_id(row) for row in graph["edges"]), "edge digest")
    declaration_ids = {row["id"] for row in graph["declarations"]}
    graph_edges = [row for row in graph["edges"] if row["declaration_kind"] == "executable_graph"]
    _fail({row["declaration_ref"] for row in graph_edges} == declaration_ids and len(graph_edges) == len(declaration_ids), "declaration consumption")
    expected_kinds = {"python_script", "python_import", "elf_search"} | ({"elf_interpreter", "elf_needed", "dlopen", "jit_invoke", "jit_compiler", "jit_loader", "jit_input", "jit_output"} if jit_records else set())
    _fail({row["kind"] for row in graph["edges"]} == expected_kinds, "edge denominator")
    return graph


class ExecutableGraphOracleSelftest(unittest.TestCase):
    def test_real_predecessor_denominators_in_all_modes(self) -> None:
        for kwargs in ({}, {"execution_mode": "python_jit_triton", "cache_policy": "ephemeral_rebuild"}, {"execution_mode": "python_jit_triton", "cache_policy": "measured_read_only"}):
            docs, _ = build_v3_fixture(**kwargs)
            with self.subTest(kwargs=kwargs):
                _validate_graph(docs)

    def test_independent_mutation_matrix(self) -> None:
        docs, _ = build_v3_fixture(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild")
        for mutation in ("entrypoint", "alias", "control", "declaration", "edge"):
            with self.subTest(mutation=mutation):
                changed = dict(docs)
                contract = canonical_loads(changed["boot_contract_bytes"])
                graph = contract["execution_closure"]["executable_graph"]
                if mutation == "entrypoint":
                    graph["entrypoints"].pop()
                elif mutation == "alias":
                    graph["aliases"][0]["resolved_id"] = "file:runtime-policy:/missing"
                elif mutation == "control":
                    graph["controls"][0]["phase"] = "role_pre"
                elif mutation == "declaration":
                    graph["declarations"][0]["owner_id"] = graph["declarations"][0]["target_id"]
                else:
                    graph["edges"][0]["to_id"] = graph["edges"][0]["from_id"]
                changed["boot_contract_bytes"] = canonical_dumps(contract)
                with self.assertRaises(ValueError):
                    _validate_graph(changed)

    def test_known_graph_digest(self) -> None:
        docs, _ = build_v3_fixture(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild")
        graph = _validate_graph(docs)
        self.assertEqual(_sha(canonical_dumps(graph)), "21fc504b072c008218a27d0b4decfae42ea9c84deb80aa0adf4febe4a59d43b0")

    def test_z_no_v3_production_module_import(self) -> None:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        banned = {
            "conf_proc_spp_boot_v3", "conf_proc_spp_boot_v3_semantics", "conf_proc_spp_boot_v3_tables",
            "conf_proc_spp_boot_v3_wire", "conf_proc_spp_boot_v3_resource", "conf_proc_spp_boot_dispatch_v3",
            "conf_proc_spp_boot_payload_v3", "conf_proc_spp_boot_payload_v3_inspect",
        }
        imported = {
            alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
        } | {
            node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        self.assertFalse(imported & banned)


if __name__ == "__main__":
    unittest.main(verbosity=2)
