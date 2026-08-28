#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Dormant provenance-v2 root-bundle assembler.

This is deliberately separate from the live conf-proc builder.  It assembles
and exposes a locally-consistent, explicitly ``built_unverified`` bundle; it
does not invoke the sealed provenance oracle or make any inspection claim.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import posixpath
import shutil
import stat
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator

import conf_proc_provenance_render
import conf_proc_provenance_v2
from conf_proc_build_graph import extract_graph
from conf_proc_build_modules import verify_and_inventory_modules
from conf_proc_build_tree import assemble_tree
from conf_proc_geometry import pad_file_to_block_size
from conf_proc_graph_compare import compare_graph_to_policy
from conf_proc_guard import HermeticGuard, hermetic_lockdown
from conf_proc_guard_setup import build_guard
from conf_proc_json import canonical_dumps
from conf_proc_lock import Lock, parse_lock
from conf_proc_module_authority import check_authorized_signers_match_bundle
from conf_proc_policy import Policy, parse_policy
from conf_proc_provenance_v2_build_manifest import (
    ProvenanceV2FirmwareObservation,
    ProvenanceV2ImageRecord,
    ProvenanceV2ModuleObservation,
    produce_provenance_v2,
)
from conf_proc_provenance_v2_manifest import parse_manifest_v2
from conf_proc_provenance_v2_spdx import parse_spdx_v2
from conf_proc_reasons import (
    CP_FIRMWARE_INVENTORY,
    CP_MODULE_MISSING,
    CP_PROVENANCE_INPUT_CHANGED,
    CP_PROVENANCE_INPUT_READ,
    CP_PROVENANCE_INPUT_SIZE,
    CP_PROVENANCE_V2_BUNDLE_READONLY,
    CP_PROVENANCE_V2_BUNDLE_SHAPE,
    CP_PROVENANCE_V2_LEASE,
    CP_PROVENANCE_V2_LOCAL_GATE,
    CP_PROVENANCE_V2_MANIFEST_PRODUCTION,
    CP_PROVENANCE_V2_RENAME,
    CP_PROVENANCE_V2_SAME_ADDRESS_DISAGREEMENT,
    CP_PROVENANCE_V2_SCAVENGE,
    CP_PROVENANCE_V2_STAGING,
    CP_TREE_METADATA,
    CP_TREE_SYMLINK,
    CP_TREE_UNEXPECTED,
    CP_VERITY_FORMAT,
    CP_VERITY_GEOMETRY,
    ApplianceError,
)
from conf_proc_tree_rules import classify_node_type, validate_symlink_target
from conf_proc_unit_parser import parse_exec_line, parse_systemd_unit


MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 128 * 1024 * 1024
IMAGE_IDS = ("models", "runtime-policy")
BUNDLE_FILES = (
    "models.squashfs",
    "models.verity",
    "runtime-policy.squashfs",
    "runtime-policy.verity",
    "appliance.manifest.json",
    "appliance.spdx.json",
)
_UNIT_DIRS = ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system")


@dataclass(frozen=True)
class AssemblyResult:
    state: str
    artifact_input_sha256: str
    execution_provenance_sha256: str
    bundle_path: str
    models_squashfs_sha256: str
    models_verity_sha256: str
    runtime_policy_squashfs_sha256: str
    runtime_policy_verity_sha256: str
    manifest_sha256: str
    spdx_sha256: str


class _ReadBudget:
    def __init__(self, limit: int) -> None:
        self.remaining = limit

    def consume(self, size: int) -> None:
        if size > self.remaining:
            raise ApplianceError(CP_PROVENANCE_INPUT_SIZE, "provenance input aggregate exceeds its bounded-read budget")
        self.remaining -= size


def assemble(
    *,
    root_lock_path: str,
    runtime_closure_path: str,
    verity_rules_path: str,
    tcb_identity_path: str,
    builder_source_path: str,
    policy_path: str,
    input_root: str,
    tool_root: str,
    output: str,
    fault_hook: Callable[[str], None] = lambda phase: None,
) -> AssemblyResult:
    """Build one locally-gated, dormant provenance-v2 root bundle."""

    phase = "authority-read"
    stage_root: str | None = None
    moved_stage = False
    try:
        budget = _ReadBudget(MAX_TOTAL_INPUT_BYTES)
        root_lock_bytes = _read_bounded(root_lock_path, budget)
        runtime_closure_bytes = _read_bounded(runtime_closure_path, budget)
        verity_rules_bytes = _read_bounded(verity_rules_path, budget)
        tcb_identity_bytes = _read_bounded(tcb_identity_path, budget)
        builder_source_bytes = _read_bounded(builder_source_path, budget)
        policy_bytes = _read_bounded(policy_path, budget)
        inputs = conf_proc_provenance_v2.derive_inputs(
            root_lock_bytes=root_lock_bytes,
            runtime_closure_bytes=runtime_closure_bytes,
            verity_rules_bytes=verity_rules_bytes,
            tcb_identity_bytes=tcb_identity_bytes,
            builder_source_bytes=builder_source_bytes,
            policy_bytes=policy_bytes,
        )
        lock = parse_lock(root_lock_bytes)
        policy = parse_policy(policy_bytes)
        fault_hook(phase)

        phase = "guard-built"
        guard, tool_paths = build_guard(
            lock,
            hashlib.sha256(root_lock_bytes).digest(),
            input_root=input_root,
            tool_root=tool_root,
        )
        guard.resolve_tool(tool_paths["unsquashfs"])
        fault_hook(phase)

        address = (inputs.artifact_input_sha256, inputs.execution_provenance_sha256)
        with _address_lease(output, address):
            stage_root = _prepare_stage(output, address, lock)
            with _stage_owner_lease(output, address):
                work_root = os.path.join(stage_root, "work")
                try:
                    os.makedirs(work_root)
                except OSError as exc:
                    raise ApplianceError(CP_PROVENANCE_V2_STAGING, "could not create H3 work directory") from exc
                _preflight_placements(lock)

                with hermetic_lockdown():
                    trees: dict[str, str] = {}
                    pseudo_files: dict[str, str] = {}
                    closure = conf_proc_provenance_v2.parse_runtime_closure(runtime_closure_bytes)
                    for image_id in IMAGE_IDS:
                        tree_dir = os.path.join(work_root, f"{image_id}-tree")
                        pseudo_lines = assemble_tree(
                            guard,
                            lock,
                            image=image_id,
                            input_root=input_root,
                            staging_root=tree_dir,
                        )
                        _normalize_tree_metadata(lock, image_id, tree_dir)
                        _validate_tree_authorities(lock, policy, closure, image_id, tree_dir)
                        pseudo_path = os.path.join(work_root, f"{image_id}.pseudo")
                        _write_staging_text(pseudo_path, "\n".join(pseudo_lines) + "\n")
                        trees[image_id] = tree_dir
                        pseudo_files[image_id] = pseudo_path
                        phase = "tree-built"
                        fault_hook(phase)

                    phase = "trees-frozen"
                    _freeze_trees(trees.values())
                    snapshots = {image_id: _tree_snapshot(path) for image_id, path in trees.items()}
                    fault_hook(phase)

                    phase = "policy-observed"
                    _validate_runtime_service_policy(trees["runtime-policy"], policy)
                    _observe_graphs(trees, policy)
                    fault_hook(phase)

                    phase = "modules-observed"
                    trusted_bundle = next(item for item in lock.inputs if item.role == "kernel_trusted_cert_bundle")
                    trusted_bundle_path = os.path.join(input_root, trusted_bundle.source_local_path)
                    trusted_bundle_bytes = guard.read_bytes(trusted_bundle_path)
                    if _sha256(trusted_bundle_bytes) != trusted_bundle.sha256:
                        raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "trusted module bundle digest disagrees with lock")
                    check_authorized_signers_match_bundle(lock, trusted_bundle_bytes)
                    module_rows: list[dict] = []
                    firmware_rows: list[dict] = []
                    with guard.pin_tools((tool_paths["openssl"],)):
                        for image_id in IMAGE_IDS:
                            modules, firmware = verify_and_inventory_modules(
                                guard,
                                openssl_path=tool_paths["openssl"],
                                lock=lock,
                                trusted_bundle_pem_path=trusted_bundle_path,
                                staging_root=trees[image_id],
                                image=image_id,
                                work_dir=work_root,
                            )
                            module_rows.extend(modules)
                            firmware_rows.extend(firmware)
                    _reject_duplicate_inventory_paths(module_rows, firmware_rows)
                    _validate_inventory_against_lock(lock, module_rows, firmware_rows)
                    module_observations = tuple(
                        ProvenanceV2ModuleObservation(
                            path=row["path"],
                            sha256=row["sha256"],
                            signer_certificate_sha256=row["signer_certificate_sha256"],
                        )
                        for row in sorted(module_rows, key=lambda row: row["path"])
                    )
                    firmware_observations = tuple(
                        ProvenanceV2FirmwareObservation(path=row["path"], sha256=row["sha256"])
                        for row in sorted(firmware_rows, key=lambda row: row["path"])
                    )
                    fault_hook(phase)

                    image_records: list[ProvenanceV2ImageRecord] = []
                    for image_id in IMAGE_IDS:
                        phase = "image-built"
                        image_records.append(
                            _build_image(
                                guard,
                                inputs.artifact_input_sha256,
                                verity_rules_bytes,
                                image_id,
                                trees[image_id],
                                pseudo_files[image_id],
                                stage_root,
                                tool_paths,
                                snapshots[image_id],
                            )
                        )
                        fault_hook(phase)

                    phase = "documents-built"
                    _assert_tree_snapshots(trees, snapshots)
                    artifacts = produce_provenance_v2(
                        root_lock_bytes=root_lock_bytes,
                        runtime_closure_bytes=runtime_closure_bytes,
                        verity_rules_bytes=verity_rules_bytes,
                        tcb_identity_bytes=tcb_identity_bytes,
                        builder_source_bytes=builder_source_bytes,
                        policy_bytes=policy_bytes,
                        images=tuple(image_records),
                        module_observations=module_observations,
                        firmware_observations=firmware_observations,
                    )
                    _enforce_payload_budget(
                        (
                            root_lock_bytes,
                            runtime_closure_bytes,
                            verity_rules_bytes,
                            tcb_identity_bytes,
                            builder_source_bytes,
                            policy_bytes,
                            artifacts.manifest_bytes,
                            artifacts.spdx_bytes,
                        )
                    )
                    try:
                        _remove_tree(work_root)
                    except OSError as exc:
                        raise ApplianceError(CP_PROVENANCE_V2_STAGING, "could not clear H3 work directory") from exc
                    _write_staging_bytes(os.path.join(stage_root, "appliance.manifest.json"), artifacts.manifest_bytes)
                    _write_staging_bytes(os.path.join(stage_root, "appliance.spdx.json"), artifacts.spdx_bytes)
                    fault_hook(phase)

                    phase = "local-gate"
                    staged_digests = _local_gate(stage_root, inputs, image_records)
                    fault_hook(phase)

                    phase = "bundle-readonly"
                    _make_bundle_readonly(stage_root)
                    _assert_bundle_shape(stage_root, readonly=True)
                    fault_hook(phase)

            destination = os.path.join(output, "built_unverified", *address)
            _ensure_same_filesystem(stage_root, os.path.join(output, "built_unverified"))
            if os.path.lexists(destination):
                existing_digests = _bundle_digests(destination, readonly=True)
                if existing_digests != staged_digests:
                    raise ApplianceError(
                        CP_PROVENANCE_V2_SAME_ADDRESS_DISAGREEMENT,
                        "same H3 address has different bundle content",
                    )
                _remove_tree(stage_root)
                stage_root = None
                return _result(inputs, destination, existing_digests)

            try:
                os.makedirs(os.path.dirname(destination), exist_ok=True)
            except OSError as exc:
                raise ApplianceError(CP_PROVENANCE_V2_STAGING, "could not create H3 destination parents") from exc
            phase = "pre-rename"
            fault_hook(phase)
            try:
                os.rename(stage_root, destination)
            except OSError as exc:
                raise ApplianceError(CP_PROVENANCE_V2_RENAME, "could not atomically expose H3 bundle") from exc
            moved_stage = True
            stage_root = None
            try:
                os.chmod(destination, 0o555)
            except OSError:
                # rename() needs its source directory writable, so a failed
                # post-exposure directory hardening must not report failure.
                pass
            return _result(inputs, destination, staged_digests)
    except ApplianceError as exc:
        sanitized = ApplianceError(exc.reason_code, "assembly failed")
        sanitized.phase = phase
        raise sanitized from None
    except OSError:
        sanitized = ApplianceError(CP_PROVENANCE_V2_STAGING, "assembly failed")
        sanitized.phase = phase
        raise sanitized from None
    except Exception:
        sanitized = ApplianceError(CP_PROVENANCE_V2_STAGING, "assembly failed")
        sanitized.phase = phase
        raise sanitized from None
    finally:
        if stage_root is not None and not moved_stage:
            _remove_stage_quietly(stage_root)


def _read_bounded(path: str, budget: _ReadBudget) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_INPUT_READ, "could not read bounded provenance input") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > MAX_INPUT_BYTES:
            raise ApplianceError(CP_PROVENANCE_INPUT_SIZE, "provenance input exceeds bounded-read limit")
        budget.consume(before.st_size)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ApplianceError(CP_PROVENANCE_INPUT_CHANGED, "provenance input changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ApplianceError(CP_PROVENANCE_INPUT_CHANGED, "provenance input changed while being read")
        after = os.fstat(descriptor)
    except ApplianceError:
        raise
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_INPUT_READ, "could not read bounded provenance input") from exc
    finally:
        os.close(descriptor)
    if _stat_identity(before) != _stat_identity(after):
        raise ApplianceError(CP_PROVENANCE_INPUT_CHANGED, "provenance input changed while being read")
    return b"".join(chunks)


def _preflight_placements(lock: Lock) -> None:
    placement_images: dict[tuple[str, str], str] = {}
    observed: set[str] = set()
    for lock_input in lock.inputs:
        for placement in lock_input.placements:
            key = (placement.path, lock_input.id)
            previous = placement_images.setdefault(key, placement.image)
            if previous != placement.image:
                raise ApplianceError(CP_TREE_UNEXPECTED, "locked input placement is mapped into multiple images")
            if placement.node_type == "file" and (placement.path.endswith(".ko") or "/firmware/" in placement.path):
                if placement.path in observed:
                    raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "module or firmware placement path collides")
                observed.add(placement.path)


def _normalize_tree_metadata(lock: Lock, image_id: str, tree_root: str) -> None:
    for lock_input in lock.inputs:
        for placement in lock_input.placements:
            if placement.image != image_id:
                continue
            path = os.path.join(tree_root, placement.path.lstrip("/"))
            try:
                if placement.node_type != "symlink":
                    os.chmod(path, placement.mode)
            except OSError as exc:
                raise ApplianceError(CP_TREE_METADATA, "could not normalize staged tree metadata") from exc


def _validate_tree_authorities(lock: Lock, policy: Policy, closure: dict, image_id: str, tree_root: str) -> None:
    placements = [
        (lock_input, placement)
        for lock_input in lock.inputs
        for placement in lock_input.placements
        if placement.image == image_id
    ]
    lock_paths = {placement.path for _lock_input, placement in placements}
    policy_nodes = {node.path: node for node in policy.images[image_id].nodes}
    if set(policy_nodes) != lock_paths:
        raise ApplianceError(CP_TREE_UNEXPECTED, "policy tree paths do not exactly match lock placements")
    closure_entries = {entry["path"]: entry for entry in closure["entries"]}
    if set(closure_entries) != {
        placement.path
        for lock_input in lock.inputs
        for placement in lock_input.placements
    }:
        raise ApplianceError(CP_TREE_UNEXPECTED, "runtime closure does not exactly cover locked image placements")

    for lock_input, placement in placements:
        policy_node = policy_nodes[placement.path]
        if (
            policy_node.node_type != placement.node_type
            or policy_node.mode != placement.mode
            or policy_node.uid != placement.uid
            or policy_node.gid != placement.gid
            or policy_node.xattrs != placement.xattrs
            or policy_node.source_input_id != placement.source_input_id
            or policy_node.target != placement.target
        ):
            raise ApplianceError(CP_TREE_UNEXPECTED, "policy tree metadata disagrees with lock placement")
        if placement.node_type == "file" and policy_node.content_class is None:
            raise ApplianceError(CP_TREE_UNEXPECTED, "policy file has no content class")
        if placement.node_type != "file" and policy_node.content_class is not None:
            raise ApplianceError(CP_TREE_UNEXPECTED, "non-file policy node has a content class")
        if placement.node_type == "symlink":
            _validate_image_symlink(image_id, placement.path, placement.target or "")

        actual = _snapshot_path(tree_root, placement.path)
        expected = closure_entries[placement.path]
        expected_xattrs = tuple((item["name"], item["value_sha256"]) for item in expected["xattrs"])
        if (
            actual["node_type"] != placement.node_type
            or actual["mode"] != placement.mode
            or actual["xattrs"] != expected_xattrs
            or tuple(item[0] for item in expected_xattrs) != placement.xattrs
        ):
            raise ApplianceError(CP_TREE_UNEXPECTED, "staged tree metadata disagrees with authority")
        if expected["node_type"] != placement.node_type or expected["mode"] != placement.mode or expected["uid"] != placement.uid or expected["gid"] != placement.gid:
            raise ApplianceError(CP_TREE_UNEXPECTED, "runtime closure metadata disagrees with lock")
        if placement.node_type == "file":
            if actual["sha256"] != lock_input.sha256 or expected["sha256"] != lock_input.sha256 or expected["size_bytes"] != lock_input.size_bytes:
                raise ApplianceError(CP_TREE_UNEXPECTED, "staged file content disagrees with authority")
        elif placement.node_type == "symlink":
            if actual["target"] != placement.target or expected["symlink_target"] != placement.target:
                raise ApplianceError(CP_TREE_SYMLINK, "staged symlink target disagrees with authority")


def _validate_image_symlink(image_id: str, path: str, target: str) -> None:
    if target.startswith("/"):
        raise ApplianceError(CP_TREE_SYMLINK, "absolute image symlinks are forbidden")
    if image_id == "models":
        raise ApplianceError(CP_TREE_SYMLINK, "models image must not contain symlinks")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    if not resolved.startswith("/") or resolved == "/" or resolved.startswith("../"):
        raise ApplianceError(CP_TREE_SYMLINK, "runtime-policy symlink escapes its image root")


def _freeze_trees(trees: Iterable[str]) -> None:
    try:
        for tree_root in trees:
            for root, directories, files in os.walk(tree_root, topdown=False, followlinks=False):
                for name in [*files, *directories]:
                    path = os.path.join(root, name)
                    if stat.S_ISLNK(os.lstat(path).st_mode):
                        continue
                    os.chmod(path, stat.S_IMODE(os.lstat(path).st_mode) & ~0o222)
            os.chmod(tree_root, stat.S_IMODE(os.lstat(tree_root).st_mode) & ~0o222)
    except OSError as exc:
        raise ApplianceError(CP_TREE_METADATA, "could not freeze H3 staging tree") from exc


def _tree_snapshot(tree_root: str) -> tuple[dict, ...]:
    try:
        records = []
        for root, directories, files in os.walk(tree_root, topdown=True, followlinks=False):
            for name in sorted([*directories, *files]):
                path = os.path.join(root, name)
                records.append(_snapshot_path(tree_root, "/" + os.path.relpath(path, tree_root)))
        return tuple(sorted(records, key=lambda item: item["path"]))
    except OSError as exc:
        raise ApplianceError(CP_TREE_METADATA, "could not snapshot H3 staging tree") from exc


def _snapshot_path(tree_root: str, image_path: str) -> dict:
    path = os.path.join(tree_root, image_path.lstrip("/"))
    value = os.lstat(path)
    node_type = classify_node_type(value.st_mode)
    xattrs = tuple(sorted((name, _sha256(os.getxattr(path, name))) for name in os.listxattr(path)))
    record = {
        "path": image_path,
        "node_type": node_type,
        "mode": stat.S_IMODE(value.st_mode),
        "uid": value.st_uid,
        "gid": value.st_gid,
        "xattrs": xattrs,
        "sha256": None,
        "target": None,
    }
    if node_type == "file":
        record["sha256"] = _sha256_file(path)
    elif node_type == "symlink":
        record["target"] = os.readlink(path)
    return record


def _assert_tree_snapshots(trees: dict[str, str], snapshots: dict[str, tuple[dict, ...]]) -> None:
    for image_id, tree_root in trees.items():
        if _tree_snapshot(tree_root) != snapshots[image_id]:
            raise ApplianceError(CP_TREE_UNEXPECTED, "frozen staging tree changed after authority validation")


def _validate_runtime_service_policy(tree_root: str, policy: Policy) -> None:
    try:
        for root, _directories, files in os.walk(tree_root):
            for name in files:
                if name.endswith(".mount"):
                    raise ApplianceError(CP_TREE_UNEXPECTED, "mount units are forbidden in H3 runtime-policy")
                if not name.endswith((".service", ".socket", ".timer")):
                    continue
                if os.path.relpath(root, tree_root) not in _UNIT_DIRS:
                    raise ApplianceError(CP_TREE_UNEXPECTED, "runtime activation unit is outside an approved unit directory")
                if not name.endswith(".service"):
                    continue
                sections = parse_systemd_unit(Path(os.path.join(root, name)).read_text(encoding="utf-8"))
                service = sections.get("Service", {})
                bounding = tuple(sorted(service.get("CapabilityBoundingSet", [""])[0].split()))
                ambient = tuple(sorted(service.get("AmbientCapabilities", [""])[0].split()))
                if service.get("NoNewPrivileges") != ["yes"] or ambient:
                    raise ApplianceError(CP_TREE_UNEXPECTED, "runtime service capability posture is forbidden")
                expected = policy.capability_policy.get(f"unit:{name}")
                if expected is None or (
                    bounding != expected.capability_bounding_set
                    or ambient != expected.ambient_capabilities
                    or expected.no_new_privileges is not True
                ):
                    raise ApplianceError(CP_TREE_UNEXPECTED, "runtime service capability policy disagrees with tree")
    except OSError as exc:
        raise ApplianceError(CP_TREE_METADATA, "could not read H3 runtime service policy") from exc


def _observe_graphs(trees: dict[str, str], policy: Policy) -> None:
    all_nodes: dict[str, dict] = {}
    all_edges: dict[tuple[str, str, str, str, str], dict] = {}
    for image_id in IMAGE_IDS:
        _preflight_service_exec_contributions(trees[image_id])
        try:
            nodes, edges = extract_graph(trees[image_id])
        except OSError as exc:
            raise ApplianceError(CP_TREE_METADATA, "could not extract H3 activation graph") from exc
        if image_id == "models" and nodes:
            raise ApplianceError(CP_TREE_UNEXPECTED, "models tree must be data-only")
        _merge_graph(all_nodes, all_edges, nodes, edges)
    compare_graph_to_policy(list(all_nodes.values()), list(all_edges.values()), policy)


def _preflight_service_exec_contributions(tree_root: str) -> None:
    """Reject raw service contributions that extract_graph would coalesce."""

    observed: dict[str, tuple[tuple[str, ...], str]] = {}
    try:
        for unit_dir in _UNIT_DIRS:
            directory = os.path.join(tree_root, unit_dir)
            if not os.path.isdir(directory):
                continue
            for name in sorted(os.listdir(directory)):
                if not name.endswith(".service"):
                    continue
                sections = parse_systemd_unit(Path(os.path.join(directory, name)).read_text(encoding="utf-8"))
                service = sections.get("Service", {})
                network_scope = _service_network_scope(service)
                for value in service.get("ExecStart", []):
                    argv = tuple(parse_exec_line(value))
                    prior = observed.setdefault(argv[0], (argv, network_scope))
                    if prior != (argv, network_scope):
                        raise ApplianceError(CP_TREE_UNEXPECTED, "service exec path has conflicting raw contributions")
    except OSError as exc:
        raise ApplianceError(CP_TREE_METADATA, "could not preflight H3 service contributions") from exc


def _service_network_scope(service: dict[str, list[str]]) -> str:
    deny = service.get("IPAddressDeny", [])
    allow = service.get("IPAddressAllow", [])
    if deny == ["any"] and not allow:
        return "none"
    if deny == ["any"] and allow in (["127.0.0.0/8"], ["localhost"]):
        return "loopback"
    raise ApplianceError(CP_TREE_UNEXPECTED, "runtime service network policy is not statically derivable")


def _merge_graph(
    all_nodes: dict[str, dict],
    all_edges: dict[tuple[str, str, str, str, str], dict],
    nodes: list[dict],
    edges: list[dict],
) -> None:
    for node in nodes:
        prior = all_nodes.get(node["id"])
        if prior is not None and prior != node:
            raise ApplianceError(CP_TREE_UNEXPECTED, "graph node identity has conflicting contributions")
        all_nodes[node["id"]] = node
    for edge in edges:
        key = (edge["from_id"], edge["to_id"], edge["kind"], edge["origin_path"], edge["origin_key"])
        if key in all_edges:
            raise ApplianceError(CP_TREE_UNEXPECTED, "graph edge is duplicated")
        all_edges[key] = edge


def _reject_duplicate_inventory_paths(modules: list[dict], firmware: list[dict]) -> None:
    paths = [row["path"] for row in [*modules, *firmware]]
    if len(paths) != len(set(paths)):
        raise ApplianceError(CP_PROVENANCE_V2_MANIFEST_PRODUCTION, "module or firmware inventory path collides")


def _validate_inventory_against_lock(lock: Lock, modules: list[dict], firmware: list[dict]) -> None:
    expected_modules: dict[str, str] = {}
    expected_firmware: dict[str, str] = {}
    for lock_input in lock.inputs:
        for placement in lock_input.placements:
            if placement.node_type != "file":
                continue
            if placement.path.endswith(".ko"):
                expected_modules[placement.path] = lock_input.sha256
            elif "/firmware/" in placement.path:
                expected_firmware[placement.path] = lock_input.sha256
    actual_modules = {row["path"]: row["sha256"] for row in modules}
    actual_firmware = {row["path"]: row["sha256"] for row in firmware}
    if actual_modules != expected_modules:
        raise ApplianceError(CP_MODULE_MISSING, "module inventory does not exactly match lock placements")
    if actual_firmware != expected_firmware:
        raise ApplianceError(CP_FIRMWARE_INVENTORY, "firmware inventory does not exactly match lock placements")


def _build_image(
    guard: HermeticGuard,
    artifact_input_sha256: str,
    rules_bytes: bytes,
    image_id: str,
    tree_dir: str,
    pseudo_file_path: str,
    staging_dir: str,
    tool_paths: dict[str, str],
    snapshot: tuple[dict, ...],
) -> ProvenanceV2ImageRecord:
    squashfs_path = os.path.join(staging_dir, f"{image_id}.squashfs")
    hash_device_path = os.path.join(staging_dir, f"{image_id}.verity")
    build = conf_proc_provenance_render.render_build_stage(
        rules_bytes,
        artifact_input_sha256=artifact_input_sha256,
        image_id=image_id,
        mksquashfs_path=tool_paths["mksquashfs"],
        veritysetup_path=tool_paths["veritysetup"],
        tree_dir=tree_dir,
        squashfs_path=squashfs_path,
        hash_device_path=hash_device_path,
        pseudo_file_path=pseudo_file_path,
    )
    if _tree_snapshot(tree_dir) != snapshot:
        raise ApplianceError(CP_TREE_UNEXPECTED, "frozen tree changed before mksquashfs")
    with guard.pin_tools((tool_paths["mksquashfs"], tool_paths["veritysetup"])):
        guard.run_tool(list(build.mksquashfs_argv), cwd=staging_dir)
        if _tree_snapshot(tree_dir) != snapshot:
            raise ApplianceError(CP_TREE_UNEXPECTED, "frozen tree changed during mksquashfs")
        try:
            pad_file_to_block_size(squashfs_path)
        except OSError as exc:
            raise ApplianceError(CP_VERITY_GEOMETRY, "could not pad H3 squashfs image") from exc
        formatted = guard.run_tool(list(build.veritysetup_format_argv), cwd=staging_dir)
        root_hash = _parse_root_hash(formatted.stdout)
        verify = conf_proc_provenance_render.render_verify_stage(
            rules_bytes,
            artifact_input_sha256=artifact_input_sha256,
            image_id=image_id,
            veritysetup_path=tool_paths["veritysetup"],
            squashfs_path=squashfs_path,
            hash_device_path=hash_device_path,
            root_hash=root_hash,
        )
        guard.run_tool(list(verify.veritysetup_verify_argv), cwd=staging_dir)
    try:
        squashfs_size = os.path.getsize(squashfs_path)
        hash_device_size = os.path.getsize(hash_device_path)
        if squashfs_size % 4096 or hash_device_size % 4096:
            raise ApplianceError(CP_VERITY_GEOMETRY, "H3 image output is not aligned to 4096-byte geometry")
        return ProvenanceV2ImageRecord(
            image_id=image_id,
            squashfs_sha256=_sha256_file(squashfs_path),
            squashfs_size_bytes=squashfs_size,
            hash_device_sha256=_sha256_file(hash_device_path),
            hash_device_size_bytes=hash_device_size,
            root_hash=root_hash,
        )
    except OSError as exc:
        raise ApplianceError(CP_VERITY_GEOMETRY, "could not measure H3 image output") from exc


def _parse_root_hash(stdout: bytes) -> str:
    for line in stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("Root hash:"):
            value = line.split(":", 1)[1].strip()
            if len(value) == 64 and value == value.lower() and all(char in "0123456789abcdef" for char in value):
                return value
    raise ApplianceError(CP_VERITY_FORMAT, "veritysetup format did not report a valid root hash")


def _enforce_payload_budget(payloads: tuple[bytes, ...]) -> None:
    if any(len(payload) > MAX_INPUT_BYTES for payload in payloads) or sum(map(len, payloads)) > MAX_TOTAL_INPUT_BYTES:
        raise ApplianceError(CP_PROVENANCE_INPUT_SIZE, "H3 authority and document payloads exceed bounded-read budget")


def _local_gate(stage_root: str, inputs: conf_proc_provenance_v2.ProvenanceInputs, images: list[ProvenanceV2ImageRecord]) -> dict[str, str]:
    try:
        digests = _bundle_digests(stage_root, readonly=False)
        manifest = parse_manifest_v2(Path(os.path.join(stage_root, "appliance.manifest.json")).read_bytes()).raw
        parse_spdx_v2(Path(os.path.join(stage_root, "appliance.spdx.json")).read_bytes())
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_LOCAL_GATE, "could not read staged H3 bundle") from exc
    if manifest["sbom"]["sha256"] != digests["appliance.spdx.json"]:
        raise ApplianceError(CP_PROVENANCE_V2_LOCAL_GATE, "manifest does not bind staged SPDX bytes")
    for image in images:
        raw = manifest["images"][image.image_id]
        if raw["squashfs_sha256"] != digests[f"{image.image_id}.squashfs"] or raw["hash_device_sha256"] != digests[f"{image.image_id}.verity"]:
            raise ApplianceError(CP_PROVENANCE_V2_LOCAL_GATE, "manifest does not bind staged image bytes")
    fresh = conf_proc_provenance_v2.derive_inputs(
        root_lock_bytes=inputs.root_lock_bytes,
        runtime_closure_bytes=inputs.runtime_closure_bytes,
        verity_rules_bytes=inputs.verity_rules_bytes,
        tcb_identity_bytes=inputs.tcb_identity_bytes,
        builder_source_bytes=inputs.builder_source_bytes,
        policy_bytes=inputs.policy_bytes,
    )
    provenance = manifest["provenance"]
    if (
        fresh.artifact_input_sha256 != inputs.artifact_input_sha256
        or fresh.execution_provenance_sha256 != inputs.execution_provenance_sha256
        or provenance["artifact_input_sha256"] != inputs.artifact_input_sha256
        or provenance["execution_provenance_sha256"] != inputs.execution_provenance_sha256
    ):
        raise ApplianceError(CP_PROVENANCE_V2_LOCAL_GATE, "staged provenance identities disagree")
    return digests


@contextmanager
def _address_lease(output: str, address: tuple[str, str]) -> Iterator[None]:
    handle = None
    try:
        os.makedirs(os.path.join(output, ".h3-locks"), exist_ok=True)
        path = os.path.join(output, ".h3-locks", "-".join(address) + ".lock")
        handle = open(path, "a+b")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except OSError as exc:
        if handle is not None:
            _release_lease_quietly(handle)
        raise ApplianceError(CP_PROVENANCE_V2_LEASE, "could not use H3 address lease") from exc
    try:
        yield
    finally:
        # This runs after the sole visibility rename, so it must be best-effort.
        _release_lease_quietly(handle)


def _prepare_stage(output: str, address: tuple[str, str], lock: Lock | None = None) -> str:
    name = "-".join(address)
    parent = os.path.join(output, ".h3-staging")
    stage = os.path.join(parent, name)
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_STAGING, "could not create H3 staging parent") from exc
    try:
        matching = [entry.name for entry in os.scandir(parent) if entry.name.startswith(name)]
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_STAGING, "could not inspect H3 staging parent") from exc
    if matching and matching != [name]:
        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "unexpected same-address H3 staging entry")
    if os.path.lexists(stage):
        _validate_stale_stage(output, name, stage, lock)
        try:
            _remove_tree(stage)
        except OSError as exc:
            raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "could not remove stale H3 staging directory") from exc
    try:
        os.mkdir(stage, 0o700)
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_STAGING, "could not create H3 staging directory") from exc
    return stage


@contextmanager
def _stage_owner_lease(output: str, address: tuple[str, str]) -> Iterator[None]:
    name = "-".join(address)
    parent = os.path.join(output, ".h3-owners")
    handle = None
    try:
        os.makedirs(parent, exist_ok=True)
        parent_metadata = os.lstat(parent)
        if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
            raise OSError("H3 owner-lock parent is not a directory")
        handle = _open_owner_lock(os.path.join(parent, name + ".lock"), CP_PROVENANCE_V2_LEASE)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, ApplianceError) as exc:
        if handle is not None:
            _release_lease_quietly(handle)
        if isinstance(exc, ApplianceError):
            raise
        raise ApplianceError(CP_PROVENANCE_V2_LEASE, "H3 staging owner lock is held or unavailable") from exc
    try:
        yield
    finally:
        _release_lease_quietly(handle)


def _validate_stale_stage(output: str, name: str, stage: str, lock: Lock | None) -> None:
    try:
        value = os.lstat(stage)
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "could not inspect stale H3 staging node") from exc
    if not _is_same_owner_directory(value):
        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 staging node is not a same-owner directory")
    owner_path = os.path.join(output, ".h3-owners", name + ".lock")
    try:
        owner = _open_owner_lock(owner_path, CP_PROVENANCE_V2_SCAVENGE)
        fcntl.flock(owner.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, ApplianceError) as exc:
        if isinstance(exc, ApplianceError):
            raise
        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 staging owner remains live") from exc
    finally:
        if "owner" in locals():
            _release_lease_quietly(owner)
    if lock is None:
        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 staging cannot be validated without its lock")
    try:
        root_entries = set(os.listdir(stage))
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "could not inspect stale H3 staging layout") from exc
    if not root_entries <= ({"work"} | set(BUNDLE_FILES)):
        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 staging layout is unexpected")
    if "work" in root_entries:
        try:
            work_metadata = os.lstat(os.path.join(stage, "work"))
        except OSError as exc:
            raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "could not inspect stale H3 work area") from exc
        if not _is_same_owner_directory(work_metadata):
            raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 work area is malformed")
        _validate_stale_work_tree(os.path.join(stage, "work"), lock)
    for name in root_entries & set(BUNDLE_FILES):
        try:
            metadata = os.lstat(os.path.join(stage, name))
        except OSError as exc:
            raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "could not inspect stale H3 bundle item") from exc
        if not _is_same_owner_regular(metadata):
            raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 bundle item is malformed")


def _validate_stale_work_tree(work_root: str, lock: Lock) -> None:
    tree_nodes, parent_paths, module_work_files = _stale_work_expectations(lock)
    try:
        entries = list(os.scandir(work_root))
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "could not inspect stale H3 work tree") from exc
    for entry in entries:
        image_id = next((candidate for candidate in IMAGE_IDS if entry.name == f"{candidate}-tree"), None)
        if image_id is not None:
            _validate_stale_image_tree(entry.path, image_id, tree_nodes[image_id], parent_paths[image_id])
        elif entry.name in {"models.pseudo", "runtime-policy.pseudo"} or entry.name in module_work_files:
            try:
                metadata = os.lstat(entry.path)
            except OSError as exc:
                raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "could not inspect stale H3 work item") from exc
            if not _is_same_owner_regular(metadata):
                raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 work item is malformed")
        else:
            raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 work layout is unexpected")


def _stale_work_expectations(lock: Lock) -> tuple[dict[str, dict], dict[str, set[str]], set[str]]:
    tree_nodes = {image_id: {} for image_id in IMAGE_IDS}
    parent_paths = {image_id: set() for image_id in IMAGE_IDS}
    module_work_files: set[str] = set()
    for lock_input in lock.inputs:
        for placement in lock_input.placements:
            tree_nodes[placement.image][placement.path] = placement
            parent = posixpath.dirname(placement.path)
            while parent != "/":
                parent_paths[placement.image].add(parent)
                parent = posixpath.dirname(parent)
            if placement.node_type == "file" and placement.path.endswith(".ko"):
                basename = os.path.basename(placement.path)
                module_work_files.update({f"{basename}.content", f"{basename}.sig.der", f"{basename}.signer.pem"})
    return tree_nodes, parent_paths, module_work_files


def _validate_stale_image_tree(tree_root: str, image_id: str, nodes: dict, parent_paths: set[str]) -> None:
    try:
        root_metadata = os.lstat(tree_root)
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "could not inspect stale H3 image tree") from exc
    if not _is_same_owner_directory(root_metadata):
        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 image tree is malformed")
    try:
        for root, directories, files in os.walk(tree_root, followlinks=False):
            for item_name in [*directories, *files]:
                item = os.path.join(root, item_name)
                image_path = "/" + os.path.relpath(item, tree_root)
                metadata = os.lstat(item)
                placement = nodes.get(image_path)
                if stat.S_ISDIR(metadata.st_mode):
                    if not _is_same_owner_directory(metadata) or (placement is None and image_path not in parent_paths):
                        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 image directory is malformed")
                elif stat.S_ISREG(metadata.st_mode):
                    if not _is_same_owner_regular(metadata) or placement is None or placement.node_type != "file":
                        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 image file is malformed")
                elif stat.S_ISLNK(metadata.st_mode):
                    if image_id != "runtime-policy" or placement is None or placement.node_type != "symlink" or os.readlink(item) != placement.target:
                        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 image symlink is malformed")
                    try:
                        validate_symlink_target(image_path, placement.target or "")
                        _validate_image_symlink(image_id, image_path, placement.target or "")
                    except ApplianceError as exc:
                        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 image symlink is malformed") from exc
                else:
                    raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 image node is malformed")
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "could not inspect stale H3 image tree") from exc


def _is_same_owner_directory(value: os.stat_result) -> bool:
    return stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and value.st_uid == os.geteuid()


def _is_same_owner_regular(value: os.stat_result) -> bool:
    return stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == os.geteuid()


def _release_lease_quietly(handle) -> None:
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except (OSError, ValueError):
        pass
    try:
        handle.close()
    except (OSError, ValueError):
        pass


def _open_owner_lock(path: str, reason_code: str):
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise ApplianceError(reason_code, "could not open H3 owner lock") from exc
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid():
            raise ApplianceError(reason_code, "H3 owner lock is not a same-owner regular file")
        return os.fdopen(descriptor, "r+b")
    except Exception:
        os.close(descriptor)
        raise


def _ensure_same_filesystem(stage_root: str, final_parent: str) -> None:
    try:
        os.makedirs(final_parent, exist_ok=True)
        if os.stat(stage_root).st_dev != os.stat(final_parent).st_dev:
            raise ApplianceError(CP_PROVENANCE_V2_STAGING, "H3 staging and destination are on different filesystems")
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_STAGING, "could not prepare H3 destination filesystem") from exc


def _assert_bundle_shape(directory: str, *, readonly: bool) -> None:
    try:
        names = sorted(os.listdir(directory))
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "could not enumerate H3 bundle") from exc
    if names != sorted(BUNDLE_FILES):
        raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "H3 bundle does not have the exact six-file shape")
    try:
        for name in BUNDLE_FILES:
            metadata = os.lstat(os.path.join(directory, name))
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
                raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "H3 bundle contains a non-regular file")
            if readonly and (stat.S_IMODE(metadata.st_mode) & 0o333):
                raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_READONLY, "H3 bundle file remains writable or executable")
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "could not inspect H3 bundle file") from exc


def _bundle_digests(directory: str, *, readonly: bool) -> dict[str, str]:
    _assert_bundle_shape(directory, readonly=readonly)
    try:
        return {name: _sha256_file(os.path.join(directory, name)) for name in BUNDLE_FILES}
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "could not hash H3 bundle file") from exc


def _make_bundle_readonly(directory: str) -> None:
    _assert_bundle_shape(directory, readonly=False)
    try:
        for name in BUNDLE_FILES:
            os.chmod(os.path.join(directory, name), 0o444)
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_READONLY, "could not make H3 bundle files read-only") from exc


def _write_staging_text(path: str, value: str) -> None:
    try:
        Path(path).write_text(value, encoding="utf-8")
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_STAGING, "could not write H3 staging metadata") from exc


def _write_staging_bytes(path: str, value: bytes) -> None:
    try:
        Path(path).write_bytes(value)
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_STAGING, "could not write H3 staging document") from exc


def _result(inputs: conf_proc_provenance_v2.ProvenanceInputs, bundle_path: str, digests: dict[str, str]) -> AssemblyResult:
    return AssemblyResult(
        state="built_unverified",
        artifact_input_sha256=inputs.artifact_input_sha256,
        execution_provenance_sha256=inputs.execution_provenance_sha256,
        bundle_path=bundle_path,
        models_squashfs_sha256=digests["models.squashfs"],
        models_verity_sha256=digests["models.verity"],
        runtime_policy_squashfs_sha256=digests["runtime-policy.squashfs"],
        runtime_policy_verity_sha256=digests["runtime-policy.verity"],
        manifest_sha256=digests["appliance.manifest.json"],
        spdx_sha256=digests["appliance.spdx.json"],
    )


def _remove_stage_quietly(stage_root: str) -> None:
    try:
        if os.path.isdir(stage_root) and not os.path.islink(stage_root):
            _remove_tree(stage_root)
    except OSError:
        pass


def _remove_tree(path: str) -> None:
    for root, directories, files in os.walk(path, topdown=False, followlinks=False):
        for name in [*files, *directories]:
            item = os.path.join(root, name)
            try:
                metadata = os.lstat(item)
                if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                    continue
                if not stat.S_ISLNK(metadata.st_mode):
                    os.chmod(item, 0o700)
            except OSError:
                pass
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass
    shutil.rmtree(path)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _guidance(reason_code: str) -> str:
    if reason_code in {CP_PROVENANCE_INPUT_SIZE, CP_PROVENANCE_INPUT_READ, CP_PROVENANCE_INPUT_CHANGED}:
        return "rebuild from exact bounded trusted inputs"
    if reason_code.startswith("CP_TOOL_"):
        return "repair the locked build-tool installation"
    return "correct the reported assembly input and rebuild"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-lock", required=True)
    parser.add_argument("--runtime-closure", required=True)
    parser.add_argument("--verity-rules", required=True)
    parser.add_argument("--tcb-identity", required=True)
    parser.add_argument("--builder-source", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--input-root", required=True)
    parser.add_argument("--tool-root", default="/")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = assemble(
            root_lock_path=args.root_lock,
            runtime_closure_path=args.runtime_closure,
            verity_rules_path=args.verity_rules,
            tcb_identity_path=args.tcb_identity,
            builder_source_path=args.builder_source,
            policy_path=args.policy,
            input_root=args.input_root,
            tool_root=args.tool_root,
            output=args.output,
        )
    except ApplianceError as exc:
        output = {
            "reason_code": exc.reason_code,
            "stage": getattr(exc, "phase", "authority-read"),
            "guidance": _guidance(exc.reason_code),
        }
        print(canonical_dumps(output).decode("utf-8"))
        return 1
    print(canonical_dumps(asdict(result)).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
