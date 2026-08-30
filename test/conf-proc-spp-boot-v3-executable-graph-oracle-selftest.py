#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent byte-level oracle for the v3 executable-graph carrier."""

from __future__ import annotations

import ast
import base64
from copy import deepcopy
import hashlib
import json
import posixpath
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

from conf_proc_json import canonical_dumps, canonical_loads


_PRODUCTION_V3_MODULES = {
    "conf_proc_spp_boot_v3", "conf_proc_spp_boot_v3_semantics", "conf_proc_spp_boot_v3_tables",
    "conf_proc_spp_boot_v3_wire", "conf_proc_spp_boot_v3_resource", "conf_proc_spp_boot_dispatch_v3",
    "conf_proc_spp_boot_payload_v3", "conf_proc_spp_boot_payload_v3_inspect",
}
_FIXTURE_CHILD = r"""
import base64
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "test"))
sys.path.insert(0, str(root))
from conf_proc_spp_boot_v3_fixture import build_v3_fixture

docs, _ = build_v3_fixture(**json.loads(sys.argv[2]))
sys.stdout.write(json.dumps({key: base64.b64encode(value).decode("ascii") for key, value in docs.items()}, sort_keys=True))
"""


def _build_v3_fixture(**kwargs: object) -> tuple[dict[str, bytes], None]:
    """Obtain raw producer bytes without loading its fixture or v3 code here."""

    _fail(not (_PRODUCTION_V3_MODULES & set(sys.modules)), "oracle process preloaded production v3 module")
    completed = subprocess.run(
        [sys.executable, "-I", "-c", _FIXTURE_CHILD, str(ROOT), json.dumps(kwargs, sort_keys=True)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "LANG": "C", "LC_ALL": "C", "PATH": "/nonexistent",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
        },
        timeout=30,
    )
    encoded = json.loads(completed.stdout)
    _fail(type(encoded) is dict and all(type(key) is str and type(value) is str for key, value in encoded.items()), "fixture child result")
    _fail(not (_PRODUCTION_V3_MODULES & set(sys.modules)), "fixture contaminated oracle process")
    return {key: base64.b64decode(value, validate=True) for key, value in encoded.items()}, None


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


def _expected_tmpfs(execution_mode: str) -> tuple[tuple[str, int, int], ...]:
    return (
        (("/run/spp-state", 1048576, 0o755), ("/run/spp-jit", 1073741824, 0o700))
        if execution_mode == "python_jit_triton"
        else (("/run/spp-state", 1048576, 0o755),)
    )


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
    for control in closure["elf_loader_controls"]:
        target_id = (
            _directory(control["resolved_image"], control["resolved_path"])
            if control["kind"] == "elf_search"
            else _file(control["resolved_image"], control["resolved_path"])
        )
        payload = {
            "control_type": "elf_loader_control", "owner_path": control["owner_path"],
            "requested_path": control["requested_path"], "resolved_image": control["resolved_image"],
            "resolved_path": control["resolved_path"], "alias_chain": control["alias_chain"],
        }
        rows.append({
            "kind": control["kind"], "owner_id": _file("runtime-policy", control["owner_path"]),
            "ordinal": control["ordinal"], "requested_path": control["requested_path"],
            "resolved_id": target_id, "alias_chain": control["alias_chain"],
            "declaration_kind": "loader_control",
            "declaration_ref": _source_ref("loader_control", None, control["kind"], control["ordinal"], payload),
        })
    return rows


def _expected_declarations_and_edges(closure: dict[str, object]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    eligible = closure["eligible_files"]
    bootstrap = closure["bootstrap"]
    startup_kat = closure["startup_kat"]
    jit_records = closure["jit_derivations"]
    assert type(eligible) is list and type(bootstrap) is dict and type(startup_kat) is dict and type(jit_records) is list
    by_path = {row["path"]: row for row in eligible}
    image = by_path["/usr/bin/python3.10"]["image"]
    assert type(image) is str

    def file_id(path: str) -> str:
        row = by_path[path]
        return _file(row["image"], path)

    declarations: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []

    def add_source_edge(kind: str, from_id: str, to_id: str, order_group: str, ordinal: int, requested_path: str | None, payload: object, source_kind: str, source_ordinal: int | None = None, alias_chain: list[str] | None = None) -> None:
        source_payload = {"derivation_sha256": from_id.removeprefix("derivation:"), "relation": payload} if source_kind == "jit_derivation" else payload
        reference = _source_ref(source_kind, None, kind, ordinal if source_ordinal is None else source_ordinal, source_payload)
        chain = [] if alias_chain is None else alias_chain
        edge = {
            "kind": kind, "from_id": from_id, "to_id": to_id, "order_group": order_group,
            "ordinal": ordinal, "requested_path": requested_path, "resolved_id": to_id,
            "alias_chain": chain, "declaration_kind": source_kind, "declaration_ref": reference,
        }
        edge["id"] = _edge_id(edge)
        edges.append(edge)

    def add_declarative_edge(kind: str, owner_id: str, target_id: str, order_group: str, ordinal: int, requested_path: str | None, alias_chain: list[str] | None = None) -> None:
        chain = [] if alias_chain is None else alias_chain
        declaration = {
            "kind": kind, "owner_id": owner_id, "order_group": order_group,
            "ordinal": ordinal, "requested_path": requested_path, "target_id": target_id,
            "alias_chain": chain,
        }
        declaration["id"] = _declaration_id(declaration)
        declarations.append(declaration)
        edge = {
            "kind": kind, "from_id": owner_id, "to_id": target_id,
            "order_group": order_group, "ordinal": ordinal,
            "requested_path": requested_path, "resolved_id": target_id,
            "alias_chain": chain, "declaration_kind": "executable_graph",
            "declaration_ref": declaration["id"],
        }
        edge["id"] = _edge_id(edge)
        edges.append(edge)

    binary = startup_kat["binary"]
    assert type(binary) is dict and type(binary["path"]) is str
    script_paths = [bootstrap["controller_entry"], bootstrap["source_path"], *(row["source_path"] for row in bootstrap["role_map"])]
    for ordinal, path in enumerate(script_paths):
        source = by_path[path]
        payload = {
            "interpreter_path": binary["path"], "source_input_id": source["input_id"],
            "source_path": path, "source_sha256": source["sha256"],
        }
        reference = _source_ref("process_authority", None, "python_script", ordinal, payload)
        add_source_edge("python_script", file_id(binary["path"]), file_id(path), "python-script:" + reference, 0, path, payload, "process_authority", ordinal)

    controller_path = bootstrap["controller_entry"]
    bootstrap_path = bootstrap["source_path"]
    assert type(controller_path) is str and type(bootstrap_path) is str
    file_alias = "/usr/lib/spp/conf_proc_spp_role_bootstrap_alias.py"
    directory_alias = "/lib/x86_64-linux-gnu"
    native_directory = "/usr/lib/x86_64-linux-gnu"
    add_declarative_edge("python_import", file_id(controller_path), file_id(bootstrap_path), "python-import:" + file_id(controller_path) + ":post_bootstrap", 0, file_alias, [file_alias])
    add_declarative_edge("elf_search", file_id("/usr/bin/spp"), _directory(image, native_directory), "elf-search:" + file_id("/usr/bin/spp"), 0, directory_alias, [directory_alias])

    for control in closure["elf_loader_controls"]:
        kind = control["kind"]
        owner_id = file_id(control["owner_path"])
        target_id = (
            _directory(control["resolved_image"], control["resolved_path"])
            if kind == "elf_search" else _file(control["resolved_image"], control["resolved_path"])
        )
        payload = {
            "control_type": "elf_loader_control", "owner_path": control["owner_path"],
            "requested_path": control["requested_path"], "resolved_image": control["resolved_image"],
            "resolved_path": control["resolved_path"], "alias_chain": control["alias_chain"],
        }
        add_source_edge(
            kind, owner_id, target_id,
            kind.replace("_", "-") + ":" + owner_id + ":loader-control",
            control["ordinal"], control["requested_path"], payload, "loader_control",
            alias_chain=control["alias_chain"],
        )

    if jit_records:
        first = jit_records[0]
        compiler = first["compiler"]
        assert type(first) is dict and type(compiler) is dict
        compiler_path = compiler["path"]
        assert type(compiler_path) is str
        add_declarative_edge("elf_interpreter", file_id(compiler_path), file_id("/usr/lib/x86_64-linux-gnu/ld-spp"), "elf-interpreter:" + file_id(compiler_path), 0, "/usr/lib/x86_64-linux-gnu/ld-spp")
        add_declarative_edge("elf_needed", file_id(compiler_path), file_id("/usr/lib/spp/lib/libtriton.so"), "elf-needed:" + file_id(compiler_path), 0, "/usr/lib/spp/lib/libtriton.so")
        add_declarative_edge("dlopen", file_id(compiler_path), file_id("/usr/lib/spp/lib/plugin.so"), "dlopen:" + file_id(compiler_path), 0, "/usr/lib/spp/lib/plugin.so")

    for invoke_ordinal, record in enumerate(jit_records):
        compiler = record["compiler"]
        loader = record["loader"]
        inputs = record["inputs"]
        output = record["output"]
        assert type(record) is dict and type(compiler) is dict and type(loader) is dict and type(inputs) is list and type(output) is dict
        digest = _jit_digest(record)
        derivation_id = _derivation(digest)
        invoke_path = "/usr/lib/spp/conf_proc_spp_inference.py"
        add_declarative_edge("jit_invoke", file_id(invoke_path), derivation_id, "jit-invoke:" + file_id(invoke_path), invoke_ordinal, None)
        add_source_edge("jit_compiler", derivation_id, file_id(compiler["path"]), "jit-compiler:" + derivation_id, 0, None, compiler, "jit_derivation")
        add_source_edge("jit_loader", derivation_id, file_id(loader["path"]), "jit-loader:" + derivation_id, 0, None, loader, "jit_derivation")
        for ordinal, item in enumerate(inputs):
            assert type(item) is dict
            add_source_edge("jit_input", derivation_id, file_id(item["path"]), "jit-input:" + derivation_id, ordinal, None, item, "jit_derivation")
        add_source_edge("jit_output", derivation_id, _output(digest, output["output_name"]), "jit-output:" + derivation_id, 0, None, output, "jit_derivation")

    declarations.sort(key=lambda row: row["id"].encode("utf-8"))
    edges.sort(key=lambda row: row["id"].encode("utf-8"))
    return declarations, edges


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
    _fail(
        (contract["execution_mode"] == "python_jit_triton" and bool(jit_records))
        or (contract["execution_mode"] == "python_no_jit" and not jit_records),
        "JIT mode denominator",
    )
    expected_outputs = []
    expected_selectors = []
    for record in jit_records:
        _fail(record["cache_policy"] == contract["cache_policy"], "JIT cache policy")
        flags = ["--jit-workspace=/run/spp-jit", "--isolated"]
        _fail(
            record["argv_env"]["compiler_argv"] == [record["compiler"]["path"], *flags]
            and record["argv_env"]["loader_argv"] == [record["loader"]["path"], *flags],
            "JIT compiler/loader argv",
        )
        digest = _jit_digest(record)
        output = record["output"]
        expected_outputs.append({"derivation_sha256": digest, **output})
        measured_path = "/usr/lib/spp/jit-cache/" + digest + "/" + output["output_name"]
        if contract["cache_policy"] == "measured_read_only":
            expected_selectors.append({"derivation_sha256": digest, "output_name": output["output_name"], "path": measured_path})
            cached = by_path.get(measured_path)
            _fail(cached is not None and "jit_cache" in cached["semantic_tags"] and (cached["sha256"], cached["size_bytes"], cached["mode"]) == (output["sha256"], output["size_bytes"], output["mode"]), "measured JIT selector target")
        else:
            _fail(measured_path not in by_path, "ephemeral JIT admits measured cache")
    _fail(closure["expected_outputs"] == expected_outputs and closure["cache_selectors"] == expected_selectors, "JIT output and selector denominator")
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
    for control in closure["loader_controls"]:
        _fail(all(path in roots for path in control["contributed_paths"]), "loader directory target")
        _fail(all(path in by_path and ({"importable_module", "native_extension"} & set(by_path[path]["semantic_tags"])) for path in control["imports"]), "loader import target")
        _fail(all(path in by_path and ({"python_loading_control", "importable_module"} & set(by_path[path]["semantic_tags"])) for path in control["hooks"]), "loader hook target")
    elf_loader_controls = closure["elf_loader_controls"]
    _fail(
        elf_loader_controls == sorted(
            elf_loader_controls,
            key=lambda row: (row["owner_path"].encode("utf-8"), row["kind"].encode("utf-8"), row["ordinal"]),
        )
        and all(control["kind"] in ("elf_interpreter", "elf_search") for control in elf_loader_controls),
        "ELF control canonical order and kind",
    )
    for control in elf_loader_controls:
        owner = by_path.get(control["owner_path"])
        _fail(owner is not None and owner["content_kind"] in ("elf_executable", "elf_shared_object") and not (owner["mode"] & 0o222), "ELF control owner")
        if control["kind"] == "elf_search":
            _fail(control["resolved_image"] == "runtime-policy" and control["resolved_path"] in roots, "ELF search target")
        else:
            target = by_path.get(control["resolved_path"])
            _fail(target is not None and target["image"] == control["resolved_image"] and target["content_kind"] in ("elf_executable", "elf_shared_object") and not (target["mode"] & 0o222), "ELF file target")
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
    expected_declarations, expected_edges = _expected_declarations_and_edges(closure)
    _fail([row["id"] for row in graph["declarations"]] == sorted((row["id"] for row in graph["declarations"]), key=lambda item: item.encode("utf-8")) and all(row["id"] == _declaration_id(row) for row in graph["declarations"]), "declaration digest")
    _fail([row["id"] for row in graph["edges"]] == sorted((row["id"] for row in graph["edges"]), key=lambda item: item.encode("utf-8")) and all(row["id"] == _edge_id(row) for row in graph["edges"]), "edge digest")
    _fail(graph["declarations"] == expected_declarations, "declaration denominator")
    _fail(graph["edges"] == expected_edges, "edge denominator")
    declaration_ids = {row["id"] for row in graph["declarations"]}
    graph_edges = [row for row in graph["edges"] if row["declaration_kind"] == "executable_graph"]
    _fail({row["declaration_ref"] for row in graph_edges} == declaration_ids and len(graph_edges) == len(declaration_ids), "declaration consumption")
    for edge in graph["edges"]:
        if edge["kind"] == "python_import":
            _fail(edge["order_group"] in tuple("python-import:" + edge["from_id"] + ":" + phase for phase in ("controller_pre", "role_pre", "post_bootstrap")), "python import group")

    directory_ids = {_directory(image, path) for path in roots}
    consumed = set(graph["entrypoints"])
    consumed.update(edge["from_id"] for edge in graph["edges"])
    consumed.update(edge["to_id"] for edge in graph["edges"])
    consumed.update(_file(by_path[row["path"]]["image"], row["path"]) for row in closure["cache_selectors"])
    for control in graph["controls"]:
        if control["kind"].startswith("python_") and "owner_id" in control:
            consumed.add(control["owner_id"])
            if "contributed_paths" in control:
                consumed.update(_directory(image, path) for path in control["contributed_paths"])
                consumed.update(_file(image, path) for path in control["imports"])
                consumed.update(_file(image, path) for path in control["hooks"])
        if control.get("path_kind") == "measured_directory":
            consumed.add(_directory(image, control["path"]))
        if control["kind"] in ("elf_interpreter", "elf_needed", "elf_search"):
            consumed.add(control["resolved_id"])
    _fail(all(node["id"] in consumed for node in graph["nodes"]), "node consumption")
    if contract["execution_mode"] == "python_jit_triton":
        _fail(jit_records and _expected_tmpfs(contract["execution_mode"])[-1] == ("/run/spp-jit", 1073741824, 0o700), "JIT tmpfs")
        _fail(all(row["path"].startswith("/run/spp-jit/") or row["path"].startswith("/usr/lib/spp/jit-cache/") for row in graph["nodes"] if row["kind"] == "jit_output"), "JIT workspace")
    else:
        _fail(not jit_records and _expected_tmpfs(contract["execution_mode"]) == (("/run/spp-state", 1048576, 0o755),), "no-JIT tmpfs")
    return graph


class ExecutableGraphOracleSelftest(unittest.TestCase):
    def test_real_predecessor_denominators_in_all_modes(self) -> None:
        for kwargs in ({}, {"execution_mode": "python_jit_triton", "cache_policy": "ephemeral_rebuild"}, {"execution_mode": "python_jit_triton", "cache_policy": "measured_read_only"}, {"execution_mode": "python_jit_triton", "cache_policy": "ephemeral_rebuild", "extra_jit_derivation": True}):
            docs, _ = _build_v3_fixture(**kwargs)
            with self.subTest(kwargs=kwargs):
                _validate_graph(docs)

    def test_independent_mutation_matrix(self) -> None:
        docs, _ = _build_v3_fixture(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild")
        for mutation in ("entrypoint", "alias", "control", "declaration", "edge", "coherent_relation"):
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
                elif mutation == "edge":
                    graph["edges"][0]["to_id"] = graph["edges"][0]["from_id"]
                else:
                    declaration = next(row for row in graph["declarations"] if row["kind"] == "elf_needed")
                    edge = next(row for row in graph["edges"] if row["declaration_ref"] == declaration["id"])
                    declaration["target_id"] = "file:runtime-policy:/usr/lib/spp/lib/plugin.so"
                    declaration["requested_path"] = "/usr/lib/spp/lib/plugin.so"
                    declaration["id"] = _declaration_id(declaration)
                    edge["to_id"] = declaration["target_id"]
                    edge["resolved_id"] = declaration["target_id"]
                    edge["requested_path"] = declaration["requested_path"]
                    edge["declaration_ref"] = declaration["id"]
                    edge["id"] = _edge_id(edge)
                    graph["declarations"].sort(key=lambda row: row["id"].encode("utf-8"))
                    graph["edges"].sort(key=lambda row: row["id"].encode("utf-8"))
                changed["boot_contract_bytes"] = canonical_dumps(contract)
                with self.assertRaises(ValueError):
                    _validate_graph(changed)

    def test_jit_argv_requires_exact_measured_executables_and_no_extra_inputs(self) -> None:
        docs, _ = _build_v3_fixture(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild")
        for lane, mutation, replacement in (
            ("compiler_argv", "executable", "/run/spp-jit-escape/unmeasured-compiler"),
            ("loader_argv", "executable", "/run/spp-jit-escape/unmeasured-loader"),
            ("compiler_argv", "extra_input", "/run/spp-jit-escape/owner-supplied-source.py"),
            ("loader_argv", "extra_input", "/run/spp-jit-escape/owner-supplied-plugin.py"),
        ):
            changed = dict(docs)
            contract = canonical_loads(changed["boot_contract_bytes"])
            argv = contract["execution_closure"]["jit_derivations"][0]["argv_env"][lane]
            if mutation == "executable":
                argv[0] = replacement
            else:
                argv.insert(1, replacement)
            changed["boot_contract_bytes"] = canonical_dumps(contract)
            with self.subTest(argv_lane=lane, mutation=mutation):
                with self.assertRaises(ValueError):
                    _validate_graph(changed)

    def test_known_graph_digest(self) -> None:
        docs, _ = _build_v3_fixture(execution_mode="python_jit_triton", cache_policy="ephemeral_rebuild")
        graph = _validate_graph(docs)
        self.assertEqual(_sha(canonical_dumps(graph)), "093ee4c487f5b3173d40524421aeb3ee3163e4e5841ba04badbce99d97644dda")

    def test_z_no_v3_production_module_import(self) -> None:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        banned = _PRODUCTION_V3_MODULES | {"conf_proc_spp_boot_v3_fixture"}
        imported = {
            alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
        } | {
            node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        self.assertFalse(imported & banned)
        self.assertFalse(_PRODUCTION_V3_MODULES & set(sys.modules))


if __name__ == "__main__":
    unittest.main(verbosity=2)
