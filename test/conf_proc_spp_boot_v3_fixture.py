#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Real canonical predecessor fixture shared by focused v3 tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_spp_boot_v3 import BOOT_CONTRACT_V3_SCHEMA, parse_boot_contract_v3
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


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
        "pre_importer_cache": cache[:3] + [{"path": "/usr/lib/spp/conf_proc_spp_role_bootstrap.py", "finder": None}],
        "denied_zip": "/usr/lib/python310.zip",
        "post_path": ["/usr/lib/python3.10", "/usr/lib/python3.10/lib-dynload", "/usr/lib/spp", "/usr/lib/spp/vendor"],
        "post_meta_path": observation["meta_path"],
        "post_path_hooks": [observation["path_hooks"][1]],
        "post_importer_cache": [],
    }


def _eligible_records_v3(docs: dict[str, bytes], *, jit: bool) -> list[dict[str, object]]:
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
    role_paths = {path for _, path in _ROLE_SOURCES}
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


def _closure_v3(docs: dict[str, bytes], *, execution_mode: str, cache_policy: str, jit_record: dict[str, object] | None = None) -> dict[str, object]:
    eligible = _eligible_records_v3(docs, jit=jit_record is not None)
    controls: list[dict[str, object]] = []
    if jit_record is not None:
        controls = [
            {"path": "/usr/lib/spp/vendor/spp_jit.pth", "kind": "pth", "read_only": True, "contributed_paths": ["/usr/lib/spp/vendor"], "imports": ["/usr/lib/spp/vendor/sitecustomize.py"], "hooks": []},
            {"path": "/usr/lib/spp/vendor/sitecustomize.py", "kind": "startup_hook", "read_only": True, "contributed_paths": [], "imports": [], "hooks": ["/usr/lib/spp/vendor/sitecustomize.py"]},
        ]
    result: dict[str, object] = {
        "schema": "conf-proc-spp-execution-closure/v3",
        "startup_kat": _startup_kat_v3(),
        "bootstrap": _bootstrap_v3(),
        "launch_rows": [{"role": role, "source_path": source_path} for role, source_path in _ROLE_SOURCES],
        "import_roots": ["/usr/lib/python3.10", "/usr/lib/python3.10/lib-dynload", "/usr/lib/spp", "/usr/lib/spp/vendor"],
        "native_loader_roots": ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/usr/lib/spp/lib"],
        "loader_controls": controls,
        "eligible_files": eligible,
        "jit_derivations": [], "expected_outputs": [], "cache_selectors": [],
    }
    if jit_record is not None:
        digest = jit_derivation_sha256_v3(jit_record)
        output = jit_record["output"]
        assert type(output) is dict
        result["jit_derivations"] = [jit_record]
        result["expected_outputs"] = [{"derivation_sha256": digest, **output}]
        result["cache_selectors"] = ([{"derivation_sha256": digest, "output_name": output["output_name"], "path": "/usr/lib/spp/jit-cache/" + digest + "/" + output["output_name"]}] if cache_policy == "measured_read_only" else [])
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


def build_v3_fixture(*, execution_mode: str = "python_no_jit", cache_policy: str = "absent") -> tuple[dict[str, bytes], object]:
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
    service_inputs: list[tuple[str, bytes, str, int, str]] = []
    for row in tables.LAUNCH_ROLE_ROWS_V3:
        input_id = "runtime-role-" + row.role
        service_inputs.append((input_id, ("stage2-service-source:" + row.role).encode("ascii"), row.source_path, 0o444, "executable"))
    service_inputs.append(("runtime-python310", b"stage2-target-python310", "/usr/bin/python3.10", 0o555, "executable"))
    if execution_mode == "python_jit_triton":
        service_inputs.extend((
            ("runtime-jit-pth", b"/usr/lib/spp/vendor\n", "/usr/lib/spp/vendor/spp_jit.pth", 0o444, "config"),
            ("runtime-jit-site", b"# measured site control\n", "/usr/lib/spp/vendor/sitecustomize.py", 0o444, "config"),
            ("runtime-jit-plugin", b"plugin shared object", "/usr/lib/spp/lib/plugin.so", 0o555, "executable"),
            ("runtime-jit-compiler", b"triton compiler", "/usr/lib/spp/bin/triton-compile", 0o555, "executable"),
            ("runtime-jit-source", b"triton source", "/usr/lib/spp/vendor/triton_kernel.py", 0o444, "config"),
            ("runtime-jit-model", b"model bytes", "/usr/lib/spp/models/model.bin", 0o444, "model"),
            ("runtime-jit-config", b"{}", "/usr/lib/spp/config/triton.json", 0o444, "config"),
            ("runtime-jit-native", b"native library", "/usr/lib/spp/lib/libtriton.so", 0o555, "executable"),
        ))
    for input_id, data, path, mode, content_class in service_inputs:
        placement = _V1._placement("runtime-policy", path, input_id)
        placement["mode"] = mode
        lock["inputs"].append(_V1._record(input_id, "runtime_tree_input", data, [placement]))
        policy["images"]["runtime-policy"]["nodes"].append({
            "path": path, "node_type": "file", "mode": mode, "uid": 0, "gid": 0,
            "xattrs": [], "source_input_id": input_id, "target": None, "content_class": content_class,
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

    closure_entries = []
    for item in lock["inputs"]:
        for placement in item["placements"]:
            closure_entries.append({
                "path": placement["path"], "node_type": placement["node_type"], "mode": placement["mode"],
                "uid": placement["uid"], "gid": placement["gid"], "size_bytes": item["size_bytes"],
                "sha256": item["sha256"], "symlink_target": placement["target"], "hardlink_group": None,
                "xattrs": [], "capabilities": [], "logical_role": item["role"],
                "provenance": {"scheme": item["source_retrieval_scheme"], "identity": item["source_retrieval_identity"], "immutable_ref": item["source_retrieval_immutable_ref"]},
                "root_lock_input_id": item["id"],
            })
    docs["runtime_closure_bytes"] = canonical_dumps({
        "schema": "conf-proc-runtime-closure/v1", "status": "declared_unverified",
        "entries": sorted(closure_entries, key=lambda item: item["path"]),
    })
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
    jit_record: dict[str, object] | None = None
    if execution_mode == "python_jit_triton":
        records = {item["path"]: item for item in _eligible_records_v3(docs, jit=True)}
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
        jit_record = {
            "schema": "conf-proc-spp-jit-derivation/v3",
            "compiler": identity("/usr/lib/spp/bin/triton-compile"),
            "loader": identity("/usr/bin/python3.10"),
            "argv_env": {"compiler_argv": ["/usr/lib/spp/bin/triton-compile", "--jit-workspace=/run/spp-jit", "--isolated"], "loader_argv": ["/usr/bin/python3.10", "--jit-workspace=/run/spp-jit", "--isolated"], "environment": [["LANG", "C"], ["LC_ALL", "C"], ["PATH", "/nonexistent"], ["PYTHONDONTWRITEBYTECODE", "1"], ["PYTHONNOUSERSITE", "1"]]},
            "inputs": [{"kind": kind, **identity(path)} for kind, path in typed_paths],
            "output": {"output_name": "kernel.so", "relative_path": "kernel.so", "sha256": _sha256(b"jit-output"), "size_bytes": len(b"jit-output"), "mode": 0o555},
            "cache_policy": cache_policy,
        }
        if cache_policy == "measured_read_only":
            digest = jit_derivation_sha256_v3(jit_record)
            output = jit_record["output"]
            assert type(output) is dict
            cache_path = "/usr/lib/spp/jit-cache/" + digest + "/" + output["output_name"]
            cache_data = b"jit-output"
            placement = _V1._placement("runtime-policy", cache_path, "runtime-jit-cache")
            placement["mode"] = 0o555
            lock = canonical_loads(docs["root_lock_bytes"])
            lock["inputs"].append(_V1._record("runtime-jit-cache", "runtime_tree_input", cache_data, [placement]))
            lock["inputs"].sort(key=lambda item: item["id"])
            policy = canonical_loads(docs["policy_bytes"])
            policy["images"]["runtime-policy"]["nodes"].append({"path": cache_path, "node_type": "file", "mode": 0o555, "uid": 0, "gid": 0, "xattrs": [], "source_input_id": "runtime-jit-cache", "target": None, "content_class": "executable"})
            policy["images"]["runtime-policy"]["nodes"].sort(key=lambda item: item["path"])
            docs["policy_bytes"] = canonical_dumps(policy)
            policy_input = next(item for item in lock["inputs"] if item["id"] == "policy")
            policy_input["sha256"] = _sha256(docs["policy_bytes"])
            policy_input["size_bytes"] = len(docs["policy_bytes"])
            policy_input["source_retrieval_immutable_ref"] = "sha256:" + policy_input["sha256"]
            docs["root_lock_bytes"] = canonical_dumps(lock)
            closure_entries = []
            for item in lock["inputs"]:
                for placement in item["placements"]:
                    closure_entries.append({"path": placement["path"], "node_type": placement["node_type"], "mode": placement["mode"], "uid": placement["uid"], "gid": placement["gid"], "size_bytes": item["size_bytes"], "sha256": item["sha256"], "symlink_target": placement["target"], "hardlink_group": None, "xattrs": [], "capabilities": [], "logical_role": item["role"], "provenance": {"scheme": item["source_retrieval_scheme"], "identity": item["source_retrieval_identity"], "immutable_ref": item["source_retrieval_immutable_ref"]}, "root_lock_input_id": item["id"]})
            docs["runtime_closure_bytes"] = canonical_dumps({"schema": "conf-proc-runtime-closure/v1", "status": "declared_unverified", "entries": sorted(closure_entries, key=lambda item: item["path"])})
            docs["accepted_manifest_bytes"] = _V1.produce_provenance_v2(root_lock_bytes=docs["root_lock_bytes"], runtime_closure_bytes=docs["runtime_closure_bytes"], verity_rules_bytes=docs["verity_rules_bytes"], tcb_identity_bytes=docs["tcb_identity_bytes"], builder_source_bytes=docs["builder_source_bytes"], policy_bytes=docs["policy_bytes"], images=images, module_observations=modules, firmware_observations=firmware).manifest_bytes
    contract = {
        "schema": BOOT_CONTRACT_V3_SCHEMA,
        "contract_version": 3,
        "execution_closure": _closure_v3(docs, execution_mode=execution_mode, cache_policy=cache_policy, jit_record=jit_record),
        "execution_mode": execution_mode,
        "cache_policy": cache_policy,
    }
    contract.update({reference_name: _sha256(docs[input_name]) for input_name, reference_name in _REFERENCE_INPUTS})
    docs["boot_contract_bytes"] = canonical_dumps(contract)
    plan = canonical_loads(docs["module_plan_bytes"])
    plan["boot_contract_sha256"] = _sha256(docs["boot_contract_bytes"])
    docs["module_plan_bytes"] = canonical_dumps(plan)
    return docs, parse_boot_contract_v3(docs["boot_contract_bytes"])
