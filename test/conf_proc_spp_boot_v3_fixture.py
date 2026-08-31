#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Real canonical predecessor fixture shared by focused v3 tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import posixpath
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_spp_boot_v3 import (
    BOOT_CONTRACT_V3_SCHEMA,
    BootTransitionEngineV3,
    LaunchReadinessBarrierV3,
    ReadinessCompletionV3,
    parse_boot_contract_v3,
)
import conf_proc_spp_boot_v3_tables as tables
from conf_proc_spp_boot_v3_semantics import jit_derivation_sha256_v3


_V1_SPEC = importlib.util.spec_from_file_location(
    "_v1_boot_fixture_v3", ROOT / "test" / "conf-proc-spp-boot-selftest.py",
)
assert _V1_SPEC is not None and _V1_SPEC.loader is not None
_V1 = importlib.util.module_from_spec(_V1_SPEC)
_V1_SPEC.loader.exec_module(_V1)


_REFERENCE_INPUTS = (
    ("root_lock_bytes", "root_lock_sha256"),
    ("runtime_closure_bytes", "runtime_closure_sha256"),
    ("verity_rules_bytes", "verity_rules_sha256"),
    ("tcb_identity_bytes", "tcb_identity_sha256"),
    ("builder_source_bytes", "builder_source_sha256"),
    ("policy_bytes", "policy_sha256"),
    ("accepted_manifest_bytes", "accepted_manifest_sha256"),
    ("kernel_feature_contract_bytes", "kernel_feature_contract_sha256"),
    ("trusted_certificate_bundle_bytes", "trusted_certificate_bundle_sha256"),
    ("gpt_layout_rules_bytes", "gpt_layout_rules_sha256"),
)
_ROLE_SOURCES = (
    ("attestation-broker", "/usr/lib/spp/conf_proc_spp_attestation_broker.py"),
    ("inference", "/usr/lib/spp/conf_proc_spp_inference.py"),
    ("asr", "/usr/lib/spp/asr_shim.py"),
    ("gateway", "/usr/lib/spp/ratls_gateway.py"),
    ("collector", "/usr/lib/spp/ratls_collector.py"),
)
_BOOTSTRAP_SOURCE = "/usr/lib/spp/conf_proc_spp_role_bootstrap.py"
_CONTROLLER_SOURCE = "/usr/lib/spp/conf_proc_spp_init.py"


def install_consumed_readiness_for_test(engine: BootTransitionEngineV3) -> None:
    """Install the exact post-barrier shape for tests outside readiness scope."""

    if type(engine) is not BootTransitionEngineV3:
        raise AssertionError("test readiness owner type")
    completion = ReadinessCompletionV3(1, 1, 1, b"\x01" * 32)
    barrier = object.__new__(LaunchReadinessBarrierV3)
    barrier._epoch = 1
    barrier._state = "consumed"
    barrier._completion = completion
    barrier._owner_engine = engine
    engine._launch_readiness_barrier = barrier
    engine._launch_readiness_completion_consumed = True
    engine._launch_readiness_consumed_completion = completion
    engine._launch_readiness_serving_eligible = True


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _graph_file_id(image: str, path: str) -> str:
    return f"file:{image}:{path}"


def _graph_directory_id(image: str, path: str) -> str:
    return f"dir:{image}:{path}"


def _graph_derivation_id(digest: str) -> str:
    return "derivation:" + digest


def _graph_output_id(digest: str, output_name: str) -> str:
    return f"jit:{digest}:{output_name}"


def _frame(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _source_ref(*, source_kind: str, phase: str | None, kind: str, ordinal: int, payload: object) -> str:
    material = {
        "schema": "sol-spp-executable-graph-source/v1", "source_kind": source_kind,
        "phase": phase, "kind": kind, "ordinal": ordinal, "payload": payload,
    }
    return "source:" + source_kind + ":" + _sha256(
        b"sol-spp-executable-graph-source/v1\0" + _frame(canonical_dumps(material)),
    )


def _declaration_id(*, kind: str, owner_id: str, order_group: str, ordinal: int, requested_path: str | None, target_id: str, alias_chain: list[str]) -> str:
    return _sha256(canonical_dumps({
        "kind": kind, "owner_id": owner_id, "order_group": order_group, "ordinal": ordinal,
        "requested_path": requested_path, "target_id": target_id, "alias_chain": alias_chain,
    }))


def _edge_id(*, kind: str, from_id: str, to_id: str, order_group: str, ordinal: int, requested_path: str | None, resolved_id: str, alias_chain: list[str], declaration_kind: str, declaration_ref: str) -> str:
    return _sha256(canonical_dumps({
        "kind": kind, "from_id": from_id, "to_id": to_id, "order_group": order_group,
        "ordinal": ordinal, "requested_path": requested_path, "resolved_id": resolved_id,
        "alias_chain": alias_chain, "declaration_kind": declaration_kind,
        "declaration_ref": declaration_ref,
    }))


def _startup_kat_v3() -> dict[str, object]:
    return json.loads((ROOT / "test/fixtures/spp-v3/python310-startup-kat-v1.json").read_bytes())


def _bootstrap_v3() -> dict[str, object]:
    kat = _startup_kat_v3()
    observation = kat["capture"]["observation"]
    cache = observation["importer_cache"]
    return {
        "source_path": "/usr/lib/spp/conf_proc_spp_role_bootstrap.py",
        "controller_entry": "/usr/lib/spp/conf_proc_spp_init.py",
        "role_map": [{"role": role, "source_path": source_path} for role, source_path in _ROLE_SOURCES],
        "flags": observation["flags"],
        "pre_path": observation["path"],
        "pre_meta_path": observation["meta_path"],
        "pre_path_hooks": observation["path_hooks"],
        "controller_pre_importer_cache": [dict(row) for row in cache[:3]] + [{"path": "/usr/lib/spp/conf_proc_spp_init.py", "finder": None}],
        "role_pre_importer_cache": [dict(row) for row in cache[:3]] + [{"path": "/usr/lib/spp/conf_proc_spp_role_bootstrap.py", "finder": None}],
        "denied_zip": "/usr/lib/python310.zip",
        "post_path": ["/usr/lib/python3.10", "/usr/lib/python3.10/lib-dynload", "/usr/lib/spp", "/usr/lib/spp/vendor"],
        "post_meta_path": observation["meta_path"],
        "post_path_hooks": [observation["path_hooks"][1]],
        "post_importer_cache": [],
    }


def _eligible_records_v3(docs: dict[str, bytes]) -> list[dict[str, object]]:
    lock = canonical_loads(docs["root_lock_bytes"])
    policy = canonical_loads(docs["policy_bytes"])
    closure = canonical_loads(docs["runtime_closure_bytes"])
    lock_paths = {
        placement["path"]: (item, placement)
        for item in lock["inputs"] for placement in item["placements"]
        if placement["node_type"] == "file"
    }
    paths = {node["path"] for node in policy["images"]["runtime-policy"]["nodes"] if node["node_type"] == "file" and node["content_class"] == "executable"}
    paths.update(edge["origin_path"] for edge in policy["process_edges"] if edge["kind"] in ("script_interpreter", "elf_interpreter", "dynamic_load"))
    paths.update(entry["path"] for entry in closure["entries"] if entry["node_type"] == "file" and (entry["path"].startswith("/usr/lib/python3.10/") or entry["path"].startswith("/usr/lib/spp/") or entry["path"].startswith("/usr/lib/spp") or entry["path"].startswith("/lib/x86_64-linux-gnu/") or entry["path"].startswith("/usr/lib/x86_64-linux-gnu/")))
    role_paths = {path for _, path in _ROLE_SOURCES} | {_BOOTSTRAP_SOURCE, _CONTROLLER_SOURCE}
    records: list[dict[str, object]] = []
    for path in sorted(paths):
        item, placement = lock_paths[path]
        if path.endswith(".py"):
            kind, tags = "python_source", ["importable_module"]
            if path in role_paths:
                tags.append("launch_executable")
            if path.endswith("sitecustomize.py"):
                tags.append("python_loading_control")
            if path.endswith("triton_kernel.py"):
                tags.append("compiler_source")
        elif path.endswith(".so"):
            kind, tags = "elf_shared_object", ["dynamic_library", "native_extension"]
            if path.endswith("plugin.so"):
                tags.append("plugin")
            if "/jit-cache/" in path:
                tags.append("jit_cache")
        elif path.endswith(".pth"):
            kind, tags = "data", ["python_loading_control"]
        elif path.endswith("model.bin"):
            kind, tags = "data", ["model_data_no_code"]
        elif path.endswith("triton.json"):
            kind, tags = "data", ["configuration_no_code"]
        else:
            kind, tags = "elf_executable", ["launch_executable"]
            if path.endswith("triton-compile"):
                tags.append("compiler")
        records.append({"input_id": item["id"], "image": placement["image"], "path": path, "sha256": item["sha256"], "size_bytes": item["size_bytes"], "mode": placement["mode"], "content_kind": kind, "semantic_tags": sorted(tags)})
    return records


def _executable_graph_v3(
    docs: dict[str, bytes], *, jit_records: list[dict[str, object]],
    cache_policy: str, eligible: list[dict[str, object]], controls: list[dict[str, object]],
    elf_controls: list[dict[str, object]],
) -> dict[str, object]:
    """Build the fixture's declarative graph from its already-created predecessor rows."""

    policy = canonical_loads(docs["policy_bytes"])
    bootstrap = _bootstrap_v3()
    observation = _startup_kat_v3()["capture"]["observation"]
    assert type(observation) is dict
    by_path = {item["path"]: item for item in eligible}
    image = "runtime-policy"
    file_id = lambda path: _graph_file_id(image, path)
    directory_id = lambda path: _graph_directory_id(image, path)
    entry_paths = (
        "/usr/bin/spp", "/usr/bin/python3.10", _CONTROLLER_SOURCE, _BOOTSTRAP_SOURCE,
        *(path for _, path in _ROLE_SOURCES),
    )
    entrypoints = [file_id(path) for path in entry_paths]
    required_tags = {
        "launch_executable", "importable_module", "python_loading_control", "native_extension",
        "dynamic_library", "compiler", "compiler_source", "model_code", "plugin", "jit_cache",
    }
    noncode_paths: set[str] = set()
    for jit_record in jit_records:
        for row in jit_record["inputs"]:
            assert type(row) is dict
            if row["kind"] in ("configuration", "model"):
                noncode_paths.add(row["path"])
    nodes: list[dict[str, object]] = []
    for row in eligible:
        if required_tags & set(row["semantic_tags"]) or row["path"] in noncode_paths:
            nodes.append({
                "id": file_id(row["path"]), "kind": "measured_file", "image": row["image"],
                "path": row["path"], "sha256": row["sha256"], "size_bytes": row["size_bytes"],
                "mode": row["mode"], "content_kind": row["content_kind"],
                "semantic_tags": row["semantic_tags"], "input_id": row["input_id"],
            })
    root_paths = {
        "/usr/lib/python3.10", "/usr/lib/python3.10/lib-dynload", "/usr/lib/spp",
        "/usr/lib/spp/vendor", "/usr/lib/spp/lib", "/usr/lib/x86_64-linux-gnu",
    }
    for row in policy["images"][image]["nodes"]:
        if row["node_type"] == "directory" and row["path"] in root_paths:
            nodes.append({"id": directory_id(row["path"]), "kind": "measured_directory", "image": image, "path": row["path"], "mode": row["mode"], "uid": row["uid"], "gid": row["gid"]})
    for jit_record in jit_records:
        derivation_digest = jit_derivation_sha256_v3(jit_record)
        output = jit_record["output"]
        assert type(output) is dict
        output_path = (
            "/usr/lib/spp/jit-cache/" + derivation_digest + "/" + output["output_name"]
            if cache_policy == "measured_read_only"
            else "/run/spp-jit/" + derivation_digest + "/" + output["output_name"]
        )
        nodes.extend((
            {"id": _graph_derivation_id(derivation_digest), "kind": "jit_derivation", "derivation_sha256": derivation_digest},
            {"id": _graph_output_id(derivation_digest, output["output_name"]), "kind": "jit_output", "derivation_sha256": derivation_digest, "output_name": output["output_name"], "path": output_path, "sha256": output["sha256"], "size_bytes": output["size_bytes"], "mode": output["mode"]},
        ))
    nodes.sort(key=lambda row: row["id"].encode("utf-8"))

    aliases: list[dict[str, object]] = []
    for row in policy["images"][image]["nodes"]:
        if row["node_type"] != "symlink":
            continue
        path = row["path"]
        target = row["target"]
        assert type(target) is str
        terminal = posixpath.normpath(target if target.startswith("/") else posixpath.join(posixpath.dirname(path), target))
        resolved_id = directory_id(terminal) if terminal in root_paths else file_id(terminal)
        aliases.append({"image": image, "path": path, "target": target, "resolved_id": resolved_id, "hop_count": 1, "chain": [path]})
    aliases.sort(key=lambda row: (row["image"], row["path"]))

    graph_controls: list[dict[str, object]] = []

    def add_startup(kind: str, phase: str, ordinal: int, payload: object, declaration_kind: str, *, identity: str | None = None, path: str | None = None, path_kind: str | None = None, finder: str | None = None, loader_details: object = None) -> None:
        graph_controls.append({
            "kind": kind, "phase": phase, "ordinal": ordinal, "identity": identity,
            "path": path, "path_kind": path_kind, "finder": finder,
            "loader_details": loader_details, "declaration_kind": declaration_kind,
            "declaration_ref": _source_ref(source_kind=declaration_kind, phase=phase, kind=kind, ordinal=ordinal, payload=payload),
        })

    for phase, cache_key, source_kind in (
        ("controller_pre", "controller_pre_importer_cache", "controller_cache_projection"),
        ("role_pre", "role_pre_importer_cache", "role_cache_projection"),
    ):
        for ordinal, path in enumerate(observation["path"]):
            add_startup("python_search_path", phase, ordinal, {"path": path}, "startup_receipt", path=path, path_kind="denied_zip" if path == "/usr/lib/python310.zip" else "measured_directory")
        for ordinal, identity in enumerate(observation["meta_path"]):
            add_startup("python_meta_path", phase, ordinal, {"identity": identity}, "startup_receipt", identity=identity)
        for ordinal, hook in enumerate(observation["path_hooks"]):
            add_startup("python_path_hook", phase, ordinal, hook, "startup_receipt", identity=hook["identity"], loader_details=hook["loader_details"])
        for ordinal, cache in enumerate(bootstrap[cache_key]):
            path = cache["path"]
            add_startup("python_importer_cache", phase, ordinal, cache, source_kind, path=path, path_kind="denied_zip" if path == "/usr/lib/python310.zip" else ("measured_file" if cache["finder"] is None else "measured_directory"), finder=cache["finder"])
    for ordinal, path in enumerate(bootstrap["post_path"]):
        add_startup("python_search_path", "post_bootstrap", ordinal, {"path": path}, "bootstrap_projection", path=path, path_kind="measured_directory")
    for ordinal, identity in enumerate(bootstrap["post_meta_path"]):
        add_startup("python_meta_path", "post_bootstrap", ordinal, {"identity": identity}, "bootstrap_projection", identity=identity)
    for ordinal, hook in enumerate(bootstrap["post_path_hooks"]):
        add_startup("python_path_hook", "post_bootstrap", ordinal, hook, "bootstrap_projection", identity=hook["identity"], loader_details=hook["loader_details"])
    for ordinal, cache in enumerate(bootstrap["post_importer_cache"]):
        add_startup("python_importer_cache", "post_bootstrap", ordinal, cache, "bootstrap_projection", path=cache["path"], path_kind="measured_file" if cache["finder"] is None else "measured_directory", finder=cache["finder"])
    for ordinal, control in enumerate(controls):
        source_payload = {key: control[key] for key in ("path", "kind", "read_only", "contributed_paths", "imports", "hooks")}
        graph_controls.append({
            "kind": "python_" + control["kind"], "phase": "runtime_startup", "ordinal": ordinal,
            "owner_id": file_id(control["path"]), "read_only": control["read_only"],
            "contributed_paths": control["contributed_paths"], "imports": control["imports"], "hooks": control["hooks"],
            "declaration_kind": "loader_control",
            "declaration_ref": _source_ref(source_kind="loader_control", phase=None, kind=control["kind"], ordinal=ordinal, payload=source_payload),
        })

    declarations: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []

    def add_source_edge(kind: str, from_id: str, to_id: str, order_group: str, ordinal: int, requested_path: str | None, payload: object, source_kind: str, alias_chain: list[str] | None = None, source_ordinal: int | None = None) -> None:
        chain = [] if alias_chain is None else alias_chain
        source_payload = {"derivation_sha256": from_id.removeprefix("derivation:"), "relation": payload} if source_kind == "jit_derivation" else payload
        reference = _source_ref(source_kind=source_kind, phase=None, kind=kind, ordinal=ordinal if source_ordinal is None else source_ordinal, payload=source_payload)
        edges.append({"id": _edge_id(kind=kind, from_id=from_id, to_id=to_id, order_group=order_group, ordinal=ordinal, requested_path=requested_path, resolved_id=to_id, alias_chain=chain, declaration_kind=source_kind, declaration_ref=reference), "kind": kind, "from_id": from_id, "to_id": to_id, "order_group": order_group, "ordinal": ordinal, "requested_path": requested_path, "resolved_id": to_id, "alias_chain": chain, "declaration_kind": source_kind, "declaration_ref": reference})

    def add_declarative_edge(kind: str, owner_id: str, target_id: str, order_group: str, ordinal: int, requested_path: str | None, alias_chain: list[str] | None = None) -> None:
        chain = [] if alias_chain is None else alias_chain
        identifier = _declaration_id(kind=kind, owner_id=owner_id, order_group=order_group, ordinal=ordinal, requested_path=requested_path, target_id=target_id, alias_chain=chain)
        declarations.append({"id": identifier, "kind": kind, "owner_id": owner_id, "order_group": order_group, "ordinal": ordinal, "requested_path": requested_path, "target_id": target_id, "alias_chain": chain})
        edges.append({"id": _edge_id(kind=kind, from_id=owner_id, to_id=target_id, order_group=order_group, ordinal=ordinal, requested_path=requested_path, resolved_id=target_id, alias_chain=chain, declaration_kind="executable_graph", declaration_ref=identifier), "kind": kind, "from_id": owner_id, "to_id": target_id, "order_group": order_group, "ordinal": ordinal, "requested_path": requested_path, "resolved_id": target_id, "alias_chain": chain, "declaration_kind": "executable_graph", "declaration_ref": identifier})

    interpreter = by_path["/usr/bin/python3.10"]
    for ordinal, path in enumerate((_CONTROLLER_SOURCE, _BOOTSTRAP_SOURCE, *(path for _, path in _ROLE_SOURCES))):
        source = by_path[path]
        payload = {"interpreter_path": interpreter["path"], "source_input_id": source["input_id"], "source_path": source["path"], "source_sha256": source["sha256"]}
        reference = _source_ref(source_kind="process_authority", phase=None, kind="python_script", ordinal=ordinal, payload=payload)
        add_source_edge("python_script", file_id(interpreter["path"]), file_id(path), "python-script:" + reference, 0, path, payload, "process_authority", source_ordinal=ordinal)
    alias_file = "/usr/lib/spp/conf_proc_spp_role_bootstrap_alias.py"
    add_declarative_edge("python_import", file_id(_CONTROLLER_SOURCE), file_id(_BOOTSTRAP_SOURCE), "python-import:" + file_id(_CONTROLLER_SOURCE) + ":post_bootstrap", 0, alias_file, [alias_file])
    alias_dir = "/lib/x86_64-linux-gnu"
    add_declarative_edge("elf_search", file_id("/usr/bin/spp"), directory_id("/usr/lib/x86_64-linux-gnu"), "elf-search:" + file_id("/usr/bin/spp"), 0, alias_dir, [alias_dir])
    for control in elf_controls:
        target_id = directory_id(control["resolved_path"]) if control["kind"] == "elf_search" else file_id(control["resolved_path"])
        payload = {
            "control_type": "elf_loader_control", "owner_path": control["owner_path"],
            "requested_path": control["requested_path"], "resolved_image": control["resolved_image"],
            "resolved_path": control["resolved_path"], "alias_chain": control["alias_chain"],
        }
        reference = _source_ref(source_kind="loader_control", phase=None, kind=control["kind"], ordinal=control["ordinal"], payload=payload)
        graph_controls.append({
            "kind": control["kind"], "owner_id": file_id(control["owner_path"]), "ordinal": control["ordinal"],
            "requested_path": control["requested_path"], "resolved_id": target_id,
            "alias_chain": control["alias_chain"], "declaration_kind": "loader_control",
            "declaration_ref": reference,
        })
        add_source_edge(control["kind"], file_id(control["owner_path"]), target_id, control["kind"].replace("_", "-") + ":" + file_id(control["owner_path"]) + ":loader-control", control["ordinal"], control["requested_path"], payload, "loader_control", control["alias_chain"])
    if jit_records:
        compiler_path = "/usr/lib/spp/bin/triton-compile"
        add_declarative_edge("elf_interpreter", file_id(compiler_path), file_id("/usr/lib/x86_64-linux-gnu/ld-spp"), "elf-interpreter:" + file_id(compiler_path), 0, "/usr/lib/x86_64-linux-gnu/ld-spp")
        add_declarative_edge("elf_needed", file_id(compiler_path), file_id("/usr/lib/spp/lib/libtriton.so"), "elf-needed:" + file_id(compiler_path), 0, "/usr/lib/spp/lib/libtriton.so")
        add_declarative_edge("dlopen", file_id(compiler_path), file_id("/usr/lib/spp/lib/plugin.so"), "dlopen:" + file_id(compiler_path), 0, "/usr/lib/spp/lib/plugin.so")
    for invoke_ordinal, jit_record in enumerate(jit_records):
        derivation_digest = jit_derivation_sha256_v3(jit_record)
        derivation_id = _graph_derivation_id(derivation_digest)
        output = jit_record["output"]
        assert type(output) is dict
        add_declarative_edge("jit_invoke", file_id("/usr/lib/spp/conf_proc_spp_inference.py"), derivation_id, "jit-invoke:" + file_id("/usr/lib/spp/conf_proc_spp_inference.py"), invoke_ordinal, None)
        compiler = jit_record["compiler"]
        loader = jit_record["loader"]
        assert type(compiler) is dict and type(loader) is dict
        add_source_edge("jit_compiler", derivation_id, file_id(compiler["path"]), "jit-compiler:" + derivation_id, 0, None, compiler, "jit_derivation")
        add_source_edge("jit_loader", derivation_id, file_id(loader["path"]), "jit-loader:" + derivation_id, 0, None, loader, "jit_derivation")
        for ordinal, source in enumerate(jit_record["inputs"]):
            assert type(source) is dict
            add_source_edge("jit_input", derivation_id, file_id(source["path"]), "jit-input:" + derivation_id, ordinal, None, source, "jit_derivation")
        add_source_edge("jit_output", derivation_id, _graph_output_id(derivation_digest, output["output_name"]), "jit-output:" + derivation_id, 0, None, output, "jit_derivation")
    declarations.sort(key=lambda row: row["id"].encode("utf-8"))
    edges.sort(key=lambda row: row["id"].encode("utf-8"))
    return {"schema": "sol-spp-executable-graph/v1", "alias_hop_limit": 40, "entrypoints": entrypoints, "nodes": nodes, "aliases": aliases, "controls": graph_controls, "declarations": declarations, "edges": edges}


def _closure_v3(docs: dict[str, bytes], *, execution_mode: str, cache_policy: str, jit_records: list[dict[str, object]]) -> dict[str, object]:
    eligible = _eligible_records_v3(docs)
    controls: list[dict[str, object]] = []
    if jit_records:
        controls = [
            {"path": "/usr/lib/spp/vendor/spp_jit.pth", "kind": "pth", "read_only": True, "contributed_paths": ["/usr/lib/spp/vendor"], "imports": ["/usr/lib/spp/vendor/sitecustomize.py"], "hooks": []},
            {"path": "/usr/lib/spp/vendor/sitecustomize.py", "kind": "startup_hook", "read_only": True, "contributed_paths": [], "imports": [], "hooks": ["/usr/lib/spp/vendor/sitecustomize.py"]},
            {"path": "/usr/lib/spp/vendor/namespace/sitecustomize.py", "kind": "namespace_package", "read_only": True, "contributed_paths": ["/usr/lib/spp/vendor"], "imports": [], "hooks": []},
        ]
    elf_controls: list[dict[str, object]] = [
        {"kind": "elf_search", "owner_path": "/usr/bin/spp", "ordinal": 0, "requested_path": "/usr/lib/spp/lib", "resolved_image": "runtime-policy", "resolved_path": "/usr/lib/spp/lib", "alias_chain": []},
    ]
    if jit_records:
        elf_controls.append({"kind": "elf_interpreter", "owner_path": "/usr/bin/python3.10", "ordinal": 0, "requested_path": "/usr/lib/x86_64-linux-gnu/ld-spp", "resolved_image": "runtime-policy", "resolved_path": "/usr/lib/x86_64-linux-gnu/ld-spp", "alias_chain": []})
    elf_controls.sort(key=lambda row: (row["owner_path"].encode("utf-8"), row["kind"].encode("utf-8"), row["ordinal"]))
    result: dict[str, object] = {
        "schema": "conf-proc-spp-execution-closure/v3",
        "startup_kat": _startup_kat_v3(),
        "bootstrap": _bootstrap_v3(),
        "launch_rows": [{"role": role, "source_path": source_path} for role, source_path in _ROLE_SOURCES],
        "import_roots": ["/usr/lib/python3.10", "/usr/lib/python3.10/lib-dynload", "/usr/lib/spp", "/usr/lib/spp/vendor"],
        "native_loader_roots": ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/usr/lib/spp/lib"],
        "loader_controls": controls,
        "elf_loader_controls": elf_controls,
        "eligible_files": eligible,
        "jit_derivations": [], "expected_outputs": [], "cache_selectors": [],
    }
    if jit_records:
        result["jit_derivations"] = jit_records
        result["expected_outputs"] = [{"derivation_sha256": jit_derivation_sha256_v3(record), **record["output"]} for record in jit_records]
        result["cache_selectors"] = ([{"derivation_sha256": jit_derivation_sha256_v3(record), "output_name": record["output"]["output_name"], "path": "/usr/lib/spp/jit-cache/" + jit_derivation_sha256_v3(record) + "/" + record["output"]["output_name"]} for record in jit_records] if cache_policy == "measured_read_only" else [])
    result["executable_graph"] = _executable_graph_v3(
        docs, jit_records=jit_records, cache_policy=cache_policy, eligible=eligible, controls=controls, elf_controls=elf_controls,
    )
    return result


def refresh_v3_contract_bindings(docs: dict[str, bytes]) -> None:
    """Refresh the acyclic contract references, then bind the separately supplied plan."""

    raw = canonical_loads(docs["boot_contract_bytes"])
    for input_name, reference_name in _REFERENCE_INPUTS:
        raw[reference_name] = _sha256(docs[input_name])
    docs["boot_contract_bytes"] = canonical_dumps(raw)
    plan = canonical_loads(docs["module_plan_bytes"])
    plan["boot_contract_sha256"] = _sha256(docs["boot_contract_bytes"])
    docs["module_plan_bytes"] = canonical_dumps(plan)


def _runtime_closure_entries(lock: dict[str, object]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for item in lock["inputs"]:
        for placement in item["placements"]:
            node_type = placement["node_type"]
            is_file = node_type == "file"
            entries.append({
                "path": placement["path"], "node_type": node_type, "mode": placement["mode"],
                "uid": placement["uid"], "gid": placement["gid"],
                "size_bytes": item["size_bytes"] if is_file else 0,
                "sha256": item["sha256"] if is_file else None,
                "symlink_target": placement["target"], "hardlink_group": None,
                "xattrs": [], "capabilities": [], "logical_role": item["role"],
                "provenance": {"scheme": item["source_retrieval_scheme"], "identity": item["source_retrieval_identity"], "immutable_ref": item["source_retrieval_immutable_ref"]},
                "root_lock_input_id": item["id"] if is_file else None,
            })
    return sorted(entries, key=lambda item: item["path"])


def _set_runtime_closure(docs: dict[str, bytes], lock: dict[str, object]) -> None:
    docs["runtime_closure_bytes"] = canonical_dumps({
        "schema": "conf-proc-runtime-closure/v1", "status": "declared_unverified",
        "entries": _runtime_closure_entries(lock),
    })


def build_v3_fixture(
    *,
    execution_mode: str = "python_no_jit",
    cache_policy: str = "absent",
    extra_jit_derivation: bool = False,
    controller_source_bytes: bytes | None = None,
) -> tuple[dict[str, bytes], object]:
    """Build the final contract first, then its one-way-bound module plan."""

    docs = _V1.build_compact_fixture()
    lock = canonical_loads(docs["root_lock_bytes"])
    policy = canonical_loads(docs["policy_bytes"])
    manifest = canonical_loads(docs["accepted_manifest_bytes"])
    stub_input = next(item for item in lock["inputs"] if item["id"] == "stub")
    stub_input["placements"][0]["mode"] = 0o555
    stub_policy = next(item for item in policy["images"]["runtime-policy"]["nodes"] if item["path"] == "/usr/bin/spp")
    stub_policy["mode"] = 0o555

    if (execution_mode, cache_policy) not in (
        ("python_no_jit", "absent"), ("python_jit_triton", "ephemeral_rebuild"), ("python_jit_triton", "measured_read_only"),
    ):
        raise ValueError("unsupported v3 fixture execution mode")
    if extra_jit_derivation and execution_mode != "python_jit_triton":
        raise ValueError("extra JIT derivation requires JIT execution mode")
    service_inputs: list[tuple[str, bytes, str, int, str]] = []
    for row in tables.LAUNCH_ROLE_ROWS_V3:
        input_id = "runtime-role-" + row.role
        service_inputs.append((input_id, ("stage2-service-source:" + row.role).encode("ascii"), row.source_path, 0o444, "executable"))
    service_inputs.extend((
        ("runtime-role-bootstrap", b"stage2-role-bootstrap-source", _BOOTSTRAP_SOURCE, 0o444, "executable"),
        (
            "runtime-stage2-controller",
            (
                (ROOT / "conf_proc_spp_init.py").read_bytes()
                if controller_source_bytes is None
                else controller_source_bytes
            ),
            _CONTROLLER_SOURCE,
            0o444,
            "executable",
        ),
    ))
    service_inputs.append(("runtime-python310", b"stage2-target-python310", "/usr/bin/python3.10", 0o555, "executable"))
    if execution_mode == "python_jit_triton":
        service_inputs.extend((
            ("runtime-jit-pth", b"/usr/lib/spp/vendor\n", "/usr/lib/spp/vendor/spp_jit.pth", 0o444, "config"),
            ("runtime-jit-site", b"# measured site control\n", "/usr/lib/spp/vendor/sitecustomize.py", 0o444, "config"),
            ("runtime-jit-namespace", b"# namespace control\n", "/usr/lib/spp/vendor/namespace/sitecustomize.py", 0o444, "config"),
            ("runtime-jit-plugin", b"plugin shared object", "/usr/lib/spp/lib/plugin.so", 0o555, "executable"),
            ("runtime-jit-compiler", b"triton compiler", "/usr/lib/spp/bin/triton-compile", 0o555, "executable"),
            ("runtime-jit-source", b"triton source", "/usr/lib/spp/vendor/triton_kernel.py", 0o444, "config"),
            ("runtime-jit-model", b"model bytes", "/usr/lib/spp/models/model.bin", 0o444, "model"),
            ("runtime-jit-config", b"{}", "/usr/lib/spp/config/triton.json", 0o444, "config"),
            ("runtime-jit-native", b"native library", "/usr/lib/spp/lib/libtriton.so", 0o555, "executable"),
            ("runtime-jit-elf-interpreter", b"SPP dynamic linker", "/usr/lib/x86_64-linux-gnu/ld-spp", 0o555, "executable"),
        ))
    for input_id, data, path, mode, content_class in service_inputs:
        placement = _V1._placement("runtime-policy", path, input_id)
        placement["mode"] = mode
        lock["inputs"].append(_V1._record(input_id, "runtime_tree_input", data, [placement]))
        policy["images"]["runtime-policy"]["nodes"].append({
            "path": path, "node_type": "file", "mode": mode, "uid": 0, "gid": 0,
            "xattrs": [], "source_input_id": input_id, "target": None, "content_class": content_class,
        })
    for input_id, path, node_type, target in (
        ("runtime-dir-python310", "/usr/lib/python3.10", "directory", None),
        ("runtime-dir-python310-lib-dynload", "/usr/lib/python3.10/lib-dynload", "directory", None),
        ("runtime-dir-spp", "/usr/lib/spp", "directory", None),
        ("runtime-dir-spp-vendor", "/usr/lib/spp/vendor", "directory", None),
        ("runtime-dir-spp-lib", "/usr/lib/spp/lib", "directory", None),
        ("runtime-dir-usr-lib", "/usr/lib/x86_64-linux-gnu", "directory", None),
        ("runtime-alias-role-bootstrap", "/usr/lib/spp/conf_proc_spp_role_bootstrap_alias.py", "symlink", "conf_proc_spp_role_bootstrap.py"),
        ("runtime-alias-usr-merge", "/lib/x86_64-linux-gnu", "symlink", "/usr/lib/x86_64-linux-gnu"),
    ):
        placement = _V1._placement("runtime-policy", path, input_id)
        placement.update({"node_type": node_type, "mode": 0o555, "source_input_id": None, "target": target})
        lock["inputs"].append(_V1._record(input_id, "runtime_tree_input", ("fixture:" + input_id).encode("ascii"), [placement]))
        policy["images"]["runtime-policy"]["nodes"].append({
            "path": path, "node_type": node_type, "mode": 0o555, "uid": 0, "gid": 0,
            "xattrs": [], "source_input_id": None, "target": target, "content_class": None,
        })
    lock["inputs"].sort(key=lambda item: item["id"])

    interpreter_digest = _sha256(b"stage2-target-python310")
    for row in tables.LAUNCH_ROLE_ROWS_V3:
        policy["process_nodes"].append({
            "id": row.role, "kind": "interpreter", "path": row.interpreter_path,
            "sha256": interpreter_digest, "argv": list(row.argv),
            "network_scope": row.expected_network_scope, "capabilities": [],
            "source_input_id": "runtime-python310",
        })
        policy["process_edges"].append({
            "from_id": "unit:spp.service", "to_id": row.role, "kind": "script_interpreter",
            "origin_path": row.source_path, "origin_key": "stage2-launch",
        })
        policy["network_policy"][row.role] = row.expected_network_scope
        policy["capability_policy"][row.role] = {
            "capability_bounding_set": [], "ambient_capabilities": [], "no_new_privileges": True,
        }
    policy["images"]["runtime-policy"]["nodes"].sort(key=lambda item: item["path"])
    policy["process_nodes"].sort(key=lambda item: item["id"])
    policy["process_edges"].sort(key=lambda item: (item["from_id"], item["to_id"], item["kind"], item["origin_path"], item["origin_key"]))
    docs["policy_bytes"] = canonical_dumps(policy)
    policy_input = next(item for item in lock["inputs"] if item["id"] == "policy")
    policy_input["sha256"] = _sha256(docs["policy_bytes"])
    policy_input["size_bytes"] = len(docs["policy_bytes"])
    policy_input["source_retrieval_immutable_ref"] = "sha256:" + policy_input["sha256"]
    docs["root_lock_bytes"] = canonical_dumps(lock)

    _set_runtime_closure(docs, lock)
    images = tuple(
        _V1.ProvenanceV2ImageRecord(
            image_id, item["squashfs_sha256"], item["squashfs_size_bytes"],
            item["hash_device_sha256"], item["hash_device_size_bytes"], item["root_hash"],
        )
        for image_id, item in sorted(manifest["images"].items())
    )
    modules = tuple(_V1.ProvenanceV2ModuleObservation(item["path"], item["sha256"], item["signer_certificate_sha256"]) for item in manifest["module_authority"]["module_inventory"])
    firmware = tuple(_V1.ProvenanceV2FirmwareObservation(item["path"], item["sha256"]) for item in manifest["module_authority"]["firmware_inventory"])
    docs["accepted_manifest_bytes"] = _V1.produce_provenance_v2(
        root_lock_bytes=docs["root_lock_bytes"], runtime_closure_bytes=docs["runtime_closure_bytes"],
        verity_rules_bytes=docs["verity_rules_bytes"], tcb_identity_bytes=docs["tcb_identity_bytes"],
        builder_source_bytes=docs["builder_source_bytes"], policy_bytes=docs["policy_bytes"],
        images=images, module_observations=modules, firmware_observations=firmware,
    ).manifest_bytes
    jit_records: list[dict[str, object]] = []
    if execution_mode == "python_jit_triton":
        records = {item["path"]: item for item in _eligible_records_v3(docs)}
        typed_paths = (
            ("source", "/usr/lib/spp/vendor/triton_kernel.py"),
            ("configuration", "/usr/lib/spp/config/triton.json"),
            ("model", "/usr/lib/spp/models/model.bin"),
            ("native_library", "/usr/lib/spp/lib/libtriton.so"),
            ("native_library", "/usr/lib/spp/lib/plugin.so"),
        )
        def identity(path: str) -> dict[str, object]:
            source = records[path]
            return {key: source[key] for key in ("input_id", "image", "path", "sha256", "size_bytes", "mode")}
        jit_record: dict[str, object] = {
            "schema": "conf-proc-spp-jit-derivation/v3",
            "compiler": identity("/usr/lib/spp/bin/triton-compile"),
            "loader": identity("/usr/bin/python3.10"),
            "argv_env": {"compiler_argv": ["/usr/lib/spp/bin/triton-compile", "--jit-workspace=/run/spp-jit", "--isolated"], "loader_argv": ["/usr/bin/python3.10", "--jit-workspace=/run/spp-jit", "--isolated"], "environment": [["LANG", "C"], ["LC_ALL", "C"], ["PATH", "/nonexistent"], ["PYTHONDONTWRITEBYTECODE", "1"], ["PYTHONNOUSERSITE", "1"]]},
            "inputs": [{"kind": kind, **identity(path)} for kind, path in typed_paths],
            "output": {"output_name": "kernel.so", "relative_path": "kernel.so", "sha256": _sha256(b"jit-output"), "size_bytes": len(b"jit-output"), "mode": 0o555},
            "cache_policy": cache_policy,
        }
        jit_records.append(jit_record)
        if extra_jit_derivation:
            extra = dict(jit_record)
            extra["output"] = {"output_name": "kernel-extra.so", "relative_path": "kernel-extra.so", "sha256": _sha256(b"jit-output-extra"), "size_bytes": len(b"jit-output-extra"), "mode": 0o555}
            jit_records.append(extra)
        if cache_policy == "measured_read_only":
            lock = canonical_loads(docs["root_lock_bytes"])
            policy = canonical_loads(docs["policy_bytes"])
            for index, record in enumerate(jit_records):
                digest = jit_derivation_sha256_v3(record)
                output = record["output"]
                assert type(output) is dict
                cache_path = "/usr/lib/spp/jit-cache/" + digest + "/" + output["output_name"]
                cache_data = b"jit-output" if index == 0 else b"jit-output-extra"
                input_id = "runtime-jit-cache" if index == 0 else "runtime-jit-cache-extra"
                placement = _V1._placement("runtime-policy", cache_path, input_id)
                placement["mode"] = 0o555
                lock["inputs"].append(_V1._record(input_id, "runtime_tree_input", cache_data, [placement]))
                policy["images"]["runtime-policy"]["nodes"].append({"path": cache_path, "node_type": "file", "mode": 0o555, "uid": 0, "gid": 0, "xattrs": [], "source_input_id": input_id, "target": None, "content_class": "executable"})
            lock["inputs"].sort(key=lambda item: item["id"])
            policy["images"]["runtime-policy"]["nodes"].sort(key=lambda item: item["path"])
            docs["policy_bytes"] = canonical_dumps(policy)
            policy_input = next(item for item in lock["inputs"] if item["id"] == "policy")
            policy_input["sha256"] = _sha256(docs["policy_bytes"])
            policy_input["size_bytes"] = len(docs["policy_bytes"])
            policy_input["source_retrieval_immutable_ref"] = "sha256:" + policy_input["sha256"]
            docs["root_lock_bytes"] = canonical_dumps(lock)
            _set_runtime_closure(docs, lock)
            docs["accepted_manifest_bytes"] = _V1.produce_provenance_v2(root_lock_bytes=docs["root_lock_bytes"], runtime_closure_bytes=docs["runtime_closure_bytes"], verity_rules_bytes=docs["verity_rules_bytes"], tcb_identity_bytes=docs["tcb_identity_bytes"], builder_source_bytes=docs["builder_source_bytes"], policy_bytes=docs["policy_bytes"], images=images, module_observations=modules, firmware_observations=firmware).manifest_bytes
    contract = {
        "schema": BOOT_CONTRACT_V3_SCHEMA,
        "contract_version": 3,
        "execution_closure": _closure_v3(docs, execution_mode=execution_mode, cache_policy=cache_policy, jit_records=jit_records),
        "execution_mode": execution_mode,
        "cache_policy": cache_policy,
    }
    contract.update({reference_name: _sha256(docs[input_name]) for input_name, reference_name in _REFERENCE_INPUTS})
    docs["boot_contract_bytes"] = canonical_dumps(contract)
    plan = canonical_loads(docs["module_plan_bytes"])
    plan["boot_contract_sha256"] = _sha256(docs["boot_contract_bytes"])
    docs["module_plan_bytes"] = canonical_dumps(plan)
    return docs, parse_boot_contract_v3(docs["boot_contract_bytes"])
