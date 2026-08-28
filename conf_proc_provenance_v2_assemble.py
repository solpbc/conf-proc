#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Dormant provenance-v2 root-bundle assembler.

This is deliberately separate from the live conf-proc builder.  It assembles
and exposes a locally-consistent, explicitly ``built_unverified`` bundle; it
does not invoke the sealed provenance oracle or make any inspection claim.

The invoking UID and its non-shared output root are the filesystem authority
boundary.  Internal/publication parents are mode 0700 and every cooperating
assembler holds the address lease through exposure.  A malicious process
running as that same UID and deliberately ignoring the lease is outside this
rootless builder's authority: POSIX directory rename is name-based and cannot
be bound to an already-open directory inode without a stronger OS boundary.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import posixpath
import re
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
from conf_proc_unit_parser import (
    parse_crontab_lines,
    parse_exec_line,
    parse_systemd_unit,
    parse_udev_actions,
)


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
_DBUS_DIRS = ("etc/dbus-1/system-services", "usr/share/dbus-1/system-services")
_UDEV_DIRS = ("etc/udev/rules.d", "usr/lib/udev/rules.d")
_CRON_D_DIRS = ("etc/cron.d",)
_CRON_PERIOD_DIRS = ("etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly")
_GENERATOR_DIRS = ("usr/lib/systemd/system-generators", "etc/systemd/system-generators")
_UNIT_SUFFIXES = (
    ".service",
    ".socket",
    ".timer",
    ".mount",
    ".path",
    ".target",
    ".device",
    ".slice",
    ".scope",
    ".automount",
    ".swap",
)
_UNMODELED_ACTIVATION_DIRS = (
    "run/systemd/system",
    "usr/local/lib/systemd/system",
    "etc/systemd/user",
    "usr/lib/systemd/user",
    "lib/systemd/user",
    "run/systemd/user",
    "usr/local/lib/systemd/user",
    "run/systemd/system-generators",
    "usr/local/lib/systemd/system-generators",
    "usr/lib/systemd/system-generators.early",
    "usr/lib/systemd/system-generators.late",
    "etc/systemd/system-generators.early",
    "etc/systemd/system-generators.late",
    "lib/udev/rules.d",
    "run/udev/rules.d",
    "usr/local/lib/udev/rules.d",
    "run/dbus-1/system-services",
    "usr/local/share/dbus-1/system-services",
    "var/spool/cron",
    "etc/init",
    "etc/init.d",
    "etc/rc.d",
)
_UNMODELED_ACTIVATION_FILES = ("etc/rc.local", "etc/inittab", "etc/anacrontab", "etc/crontab")
_UNIT_REFERENCE_RE = re.compile(r"[A-Za-z0-9_.@:-]+")


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
        _validate_declared_roots(lock, input_root, tool_root, tool_paths)
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
                            pin_sources=True,
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
                    pseudo_snapshots = {
                        image_id: _freeze_file(path) for image_id, path in pseudo_files.items()
                    }
                    fault_hook(phase)

                    phase = "policy-observed"
                    _validate_runtime_service_policy(trees["runtime-policy"], policy)
                    _observe_graphs(trees, policy)
                    fault_hook(phase)

                    phase = "modules-observed"
                    trusted_bundle = next(item for item in lock.inputs if item.role == "kernel_trusted_cert_bundle")
                    trusted_bundle_path = os.path.join(input_root, trusted_bundle.source_local_path)
                    with guard.pin_reads((trusted_bundle_path,)):
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
                                    trusted_bundle_pem_path=guard.pinned_path(trusted_bundle_path),
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
                                pseudo_snapshots[image_id],
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

            destination_parent = _prepare_destination_parent(output, address)
            destination = os.path.join(destination_parent, address[1])
            _ensure_same_filesystem(stage_root, destination_parent)
            if _existing_real_directory(destination, CP_PROVENANCE_V2_STAGING, "H3 destination is not a real directory"):
                existing_digests = _bundle_digests(destination, readonly=True)
                if existing_digests != staged_digests:
                    raise ApplianceError(
                        CP_PROVENANCE_V2_SAME_ADDRESS_DISAGREEMENT,
                        "same H3 address has different bundle content",
                    )
                _remove_tree(stage_root)
                stage_root = None
                return _result(inputs, destination, existing_digests)

            phase = "bundle-readonly"
            fault_hook(phase)
            _make_bundle_readonly(stage_root)
            stage_root = _relocate_ready_stage(stage_root, destination_parent, address)
            _make_bundle_directory_readonly(stage_root)

            phase = "pre-rename"
            fault_hook(phase)
            _prepare_destination_parent(output, address)
            if _existing_real_directory(destination, CP_PROVENANCE_V2_STAGING, "H3 destination is not a real directory"):
                raise ApplianceError(CP_PROVENANCE_V2_SAME_ADDRESS_DISAGREEMENT, "H3 destination appeared before atomic exposure")

            def publish() -> None:
                try:
                    os.rename(stage_root, destination)
                except OSError as exc:
                    raise ApplianceError(CP_PROVENANCE_V2_RENAME, "could not atomically expose H3 bundle") from exc

            with _pinned_bundle_files(stage_root, readonly=True, after_validate=publish) as files:
                if _bundle_digests_from_files(files) != staged_digests:
                    raise ApplianceError(CP_PROVENANCE_V2_SAME_ADDRESS_DISAGREEMENT, "H3 ready bundle changed before atomic exposure")
            moved_stage = True
            stage_root = None
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


def _validate_declared_roots(lock: Lock, input_root: str, tool_root: str, tool_paths: dict[str, str]) -> None:
    input_base = _validate_supplied_root(input_root, "input")
    tool_base = _validate_supplied_root(tool_root, "tool")
    for lock_input in lock.inputs:
        if lock_input.role != "build_tool":
            _validate_rooted_regular(input_base, os.path.join(input_base, lock_input.source_local_path), "input")
    for path in tool_paths.values():
        _validate_rooted_regular(tool_base, path, "tool")


def _validate_supplied_root(path: str, label: str) -> str:
    absolute = os.path.abspath(path)
    try:
        metadata = os.lstat(absolute)
    except OSError as exc:
        raise ApplianceError(CP_TREE_UNEXPECTED, f"declared {label} root is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ApplianceError(CP_TREE_UNEXPECTED, f"declared {label} root is not a real directory")
    return absolute


def _validate_rooted_regular(root: str, path: str, label: str) -> None:
    absolute = os.path.abspath(path)
    try:
        if os.path.commonpath((root, absolute)) != root:
            raise ApplianceError(CP_TREE_UNEXPECTED, f"declared {label} path escapes its root")
        relative = os.path.relpath(absolute, root)
        current = root
        for component in relative.split(os.sep):
            current = os.path.join(current, component)
            metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode):
                raise ApplianceError(CP_TREE_UNEXPECTED, f"declared {label} path traverses a symlink")
        if not stat.S_ISREG(metadata.st_mode):
            raise ApplianceError(CP_TREE_UNEXPECTED, f"declared {label} leaf is not a regular file")
    except ValueError as exc:
        raise ApplianceError(CP_TREE_UNEXPECTED, f"declared {label} path escapes its root") from exc
    except OSError as exc:
        raise ApplianceError(CP_TREE_UNEXPECTED, f"declared {label} path is unavailable") from exc


def _normalize_tree_metadata(lock: Lock, image_id: str, tree_root: str) -> None:
    for lock_input in lock.inputs:
        for placement in lock_input.placements:
            if placement.image != image_id:
                continue
            if placement.mode & 0o6000:
                raise ApplianceError(CP_TREE_METADATA, "privileged placement mode is forbidden in H3 staging")
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
        if placement.node_type == "file" and expected["root_lock_input_id"] != lock_input.id:
            raise ApplianceError(CP_TREE_UNEXPECTED, "runtime closure path cites the wrong root-lock input")
        if placement.node_type != "file" and expected["root_lock_input_id"] is not None:
            raise ApplianceError(CP_TREE_UNEXPECTED, "non-file runtime closure path claims a content authority")
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
            if image_id == "models" and placement.mode & 0o111:
                raise ApplianceError(CP_TREE_UNEXPECTED, "models image contains an executable file")
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
    if _touches_activation_surface(path.lstrip("/")):
        raise ApplianceError(CP_TREE_SYMLINK, "runtime-policy activation surfaces must not contain symlinks")
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


def _freeze_file(path: str) -> dict:
    try:
        descriptor = _open_nofollow_regular(path, os.O_RDONLY)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
            raise ApplianceError(CP_TREE_METADATA, "H3 native metadata authority is not a regular file")
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode) & ~0o222)
        return _file_snapshot_fd(descriptor)
    except OSError as exc:
        raise ApplianceError(CP_TREE_METADATA, "could not freeze H3 native metadata authority") from exc
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _file_snapshot(path: str) -> dict:
    descriptor = _open_nofollow_regular(path, os.O_RDONLY)
    try:
        return _file_snapshot_fd(descriptor)
    finally:
        os.close(descriptor)


def _file_snapshot_fd(descriptor: int) -> dict:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ApplianceError(CP_TREE_METADATA, "H3 native metadata authority is not a regular file")
    return {
        "identity": _stat_identity(metadata),
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "sha256": _sha256_fd(descriptor),
    }


def _assert_file_snapshot(path: str, snapshot: dict) -> None:
    try:
        if _file_snapshot(path) != snapshot:
            raise ApplianceError(CP_TREE_UNEXPECTED, "frozen native metadata authority changed")
    except OSError as exc:
        raise ApplianceError(CP_TREE_METADATA, "could not recheck H3 native metadata authority") from exc


@contextmanager
def _pinned_file(path: str, snapshot: dict) -> Iterator[int]:
    """Hold a frozen staging authority on one inode for child-tool use."""

    try:
        descriptor = _open_nofollow_regular(path, os.O_RDONLY)
        if _file_snapshot_fd(descriptor) != snapshot:
            raise ApplianceError(CP_TREE_UNEXPECTED, "frozen native metadata authority changed before use")
        identity = os.fstat(descriptor)
        yield descriptor
        if _file_snapshot_fd(descriptor) != snapshot:
            raise ApplianceError(CP_TREE_UNEXPECTED, "frozen native metadata authority changed during use")
        current = _open_nofollow_regular(path, os.O_RDONLY)
        try:
            current_metadata = os.fstat(current)
            if (current_metadata.st_dev, current_metadata.st_ino) != (identity.st_dev, identity.st_ino):
                raise ApplianceError(CP_TREE_UNEXPECTED, "frozen native metadata authority path changed during use")
        finally:
            os.close(current)
    except ApplianceError:
        raise
    except OSError as exc:
        raise ApplianceError(CP_TREE_METADATA, "could not pin H3 native metadata authority") from exc
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _tree_snapshot(tree_root: str) -> tuple[dict, ...]:
    try:
        records = [_snapshot_path(tree_root, "/")]
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
        "identity": _stat_identity(value),
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


@contextmanager
def _pinned_tree(path: str, snapshot: tuple[dict, ...]) -> Iterator[int]:
    """Supply one frozen tree by directory descriptor and detect any mutation."""

    try:
        descriptor = _open_nofollow_directory(path)
        descriptor_path = f"/proc/self/fd/{descriptor}"
        if _tree_snapshot(descriptor_path) != snapshot:
            raise ApplianceError(CP_TREE_UNEXPECTED, "frozen staging tree changed before native use")
        identity = os.fstat(descriptor)
        yield descriptor
        if _tree_snapshot(descriptor_path) != snapshot:
            raise ApplianceError(CP_TREE_UNEXPECTED, "frozen staging tree changed during native use")
        current = _open_nofollow_directory(path)
        try:
            current_metadata = os.fstat(current)
            if (current_metadata.st_dev, current_metadata.st_ino) != (identity.st_dev, identity.st_ino):
                raise ApplianceError(CP_TREE_UNEXPECTED, "frozen staging tree path changed during native use")
        finally:
            os.close(current)
    except ApplianceError:
        raise
    except OSError as exc:
        raise ApplianceError(CP_TREE_METADATA, "could not pin H3 staging tree") from exc
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _validate_runtime_service_policy(tree_root: str, policy: Policy) -> None:
    try:
        for root, _directories, files in os.walk(tree_root):
            for name in files:
                path = os.path.join(root, name)
                relative = os.path.relpath(path, tree_root)
                _validate_activation_path(relative)
                if not _touches_activation_surface(relative):
                    continue
                metadata = os.lstat(path)
                if not stat.S_ISREG(metadata.st_mode):
                    raise ApplianceError(CP_TREE_UNEXPECTED, "runtime activation file is not regular")
                text = Path(path).read_text(encoding="utf-8")
                _validate_activation_file(relative, text)
                parent = posixpath.dirname(relative.replace(os.sep, "/"))
                if parent not in _UNIT_DIRS:
                    continue
                if not name.endswith(".service"):
                    continue
                sections = parse_systemd_unit(text)
                service = sections.get("Service", {})
                bounding_values = service.get("CapabilityBoundingSet", [])
                ambient_values = service.get("AmbientCapabilities", [])
                if len(bounding_values) != 1 or ambient_values != [""] or service.get("NoNewPrivileges") != ["yes"]:
                    raise ApplianceError(CP_TREE_UNEXPECTED, "runtime service capability posture is forbidden")
                bounding = tuple(sorted(bounding_values[0].split()))
                ambient: tuple[str, ...] = ()
                expected = policy.capability_policy.get(f"unit:{name}")
                if expected is None or (
                    bounding != expected.capability_bounding_set
                    or ambient != expected.ambient_capabilities
                    or expected.no_new_privileges is not True
                ):
                    raise ApplianceError(CP_TREE_UNEXPECTED, "runtime service capability policy disagrees with tree")
    except OSError as exc:
        raise ApplianceError(CP_TREE_METADATA, "could not read H3 runtime service policy") from exc


def _validate_activation_file(relative_path: str, text: str) -> None:
    """Reject every activation semantic the H3 graph does not represent."""

    normalized = relative_path.replace(os.sep, "/").strip("/")
    basename = posixpath.basename(normalized)
    parent = posixpath.dirname(normalized)
    if parent in _UNIT_DIRS:
        sections = parse_systemd_unit(text)
        allowed_sections = {"Unit", "Install"}
        allowed_keys: dict[str, set[str]] = {
            "Unit": {"Description", "After", "Requires", "Wants", "BindsTo"},
            "Install": {"WantedBy"},
        }
        if basename.endswith(".service"):
            allowed_sections.add("Service")
            allowed_keys["Service"] = {
                "ExecStart",
                "IPAddressDeny",
                "IPAddressAllow",
                "CapabilityBoundingSet",
                "AmbientCapabilities",
                "NoNewPrivileges",
            }
        elif basename.endswith((".socket", ".timer")):
            raise ApplianceError(CP_TREE_UNEXPECTED, "socket and timer activation are not modeled in H3")
        if not set(sections).issubset(allowed_sections):
            raise ApplianceError(CP_TREE_UNEXPECTED, "systemd unit section is not modeled")
        for section, values in sections.items():
            if not set(values).issubset(allowed_keys.get(section, set())):
                raise ApplianceError(CP_TREE_UNEXPECTED, "systemd unit directive is not modeled")
        for key in ("After", "Requires", "Wants", "BindsTo"):
            for value in sections.get("Unit", {}).get(key, []):
                _validate_unit_references(value)
        for value in sections.get("Install", {}).get("WantedBy", []):
            _validate_unit_references(value)
        if basename.endswith(".service"):
            exec_values = sections.get("Service", {}).get("ExecStart", [])
            if len(exec_values) != 1:
                raise ApplianceError(CP_TREE_UNEXPECTED, "runtime service must have one modeled ExecStart")
            _validate_exec_value(exec_values[0])
        return
    if parent in _DBUS_DIRS:
        sections = parse_systemd_unit(text)
        if set(sections) != {"D-BUS Service"} or set(sections["D-BUS Service"]) != {"Exec"}:
            raise ApplianceError(CP_TREE_UNEXPECTED, "D-Bus activation directive is not modeled")
        values = sections["D-BUS Service"]["Exec"]
        if len(values) != 1:
            raise ApplianceError(CP_TREE_UNEXPECTED, "D-Bus activation must have one modeled Exec")
        _validate_exec_value(values[0])
        return
    if parent in _UDEV_DIRS:
        parse_udev_actions(text, reject_unmodeled=True)
        return
    if parent in _CRON_D_DIRS:
        parse_crontab_lines(text, reject_unmodeled=True)
        return
    if parent in _CRON_PERIOD_DIRS:
        raise ApplianceError(CP_TREE_UNEXPECTED, "periodic cron script execution is not modeled")
    if parent in _GENERATOR_DIRS:
        raise ApplianceError(CP_TREE_UNEXPECTED, "systemd generator execution is not modeled in H3")


def _validate_exec_value(value: str) -> None:
    argv = parse_exec_line(value)
    if any(marker in value for marker in ("$", "`", "%", "|", "<", ">", "&", ";", "(", "'", '"', "\\")):
        raise ApplianceError(CP_TREE_UNEXPECTED, "activation command indirection is not modeled")
    if posixpath.basename(argv[0]) in ("sh", "bash", "dash", "zsh", "ksh", "busybox", "env"):
        raise ApplianceError(CP_TREE_UNEXPECTED, "activation shell or environment indirection is not modeled")


def _validate_unit_references(value: str) -> None:
    tokens = value.split(" ")
    if not value or value != " ".join(tokens) or any(not token or _UNIT_REFERENCE_RE.fullmatch(token) is None for token in tokens):
        raise ApplianceError(CP_TREE_UNEXPECTED, "systemd unit reference grammar is not modeled")


def _validate_activation_path(relative_path: str) -> None:
    normalized = relative_path.replace(os.sep, "/").strip("/")
    basename = posixpath.basename(normalized)
    parent = posixpath.dirname(normalized)
    if any(parent == directory or parent.startswith(directory + "/") for directory in _UNMODELED_ACTIVATION_DIRS):
        raise ApplianceError(CP_TREE_UNEXPECTED, "unmodeled activation directory is forbidden")
    if normalized in _UNMODELED_ACTIVATION_FILES or any(
        component.startswith("rc") and component.endswith(".d")
        for component in normalized.split("/")
    ):
        raise ApplianceError(CP_TREE_UNEXPECTED, "unmodeled activation path is forbidden")
    components = normalized.split("/")
    if any(component.endswith(tuple(suffix + ".d" for suffix in _UNIT_SUFFIXES)) for component in components):
        raise ApplianceError(CP_TREE_UNEXPECTED, "systemd unit drop-ins are forbidden")

    approved_direct: dict[str, tuple[str, ...] | None] = {
        **{directory: (".service", ".socket", ".timer") for directory in _UNIT_DIRS},
        **{directory: (".service",) for directory in _DBUS_DIRS},
        **{directory: (".rules",) for directory in _UDEV_DIRS},
        **{directory: None for directory in (*_CRON_D_DIRS, *_CRON_PERIOD_DIRS, *_GENERATOR_DIRS)},
    }
    if parent in approved_direct:
        suffixes = approved_direct[parent]
        if suffixes is not None and not basename.endswith(suffixes):
            raise ApplianceError(CP_TREE_UNEXPECTED, "unmodeled activation file is forbidden")
        return
    if any(parent.startswith(directory + "/") for directory in approved_direct):
        raise ApplianceError(CP_TREE_UNEXPECTED, "nested activation content is forbidden")

    activation_markers = (
        "system-generators",
        "system-generators.early",
        "system-generators.late",
        "rules.d",
        "system-services",
    )
    matched = next((suffix for suffix in _UNIT_SUFFIXES if basename.endswith(suffix)), None)
    if matched is not None or basename.endswith(".rules") or any(marker in components for marker in activation_markers):
        raise ApplianceError(CP_TREE_UNEXPECTED, "unmodeled activation unit is forbidden")


def _touches_activation_surface(relative_path: str) -> bool:
    normalized = relative_path.replace(os.sep, "/").strip("/")
    activation_roots = (
        *_UNIT_DIRS,
        *_DBUS_DIRS,
        *_UDEV_DIRS,
        *_CRON_D_DIRS,
        *_CRON_PERIOD_DIRS,
        *_GENERATOR_DIRS,
        *_UNMODELED_ACTIVATION_DIRS,
    )
    if any(
        normalized == root
        or normalized.startswith(root + "/")
        or root.startswith(normalized + "/")
        for root in activation_roots
    ):
        return True
    return normalized in _UNMODELED_ACTIVATION_FILES or any(
        component.endswith(tuple(suffix + ".d" for suffix in _UNIT_SUFFIXES))
        or component.startswith("rc") and component.endswith(".d")
        or component in ("system-generators", "system-generators.early", "system-generators.late", "rules.d", "system-services")
        for component in normalized.split("/")
    )


def _observe_graphs(trees: dict[str, str], policy: Policy) -> None:
    all_nodes: dict[str, dict] = {}
    all_edges: dict[tuple[str, str, str, str, str], dict] = {}
    for image_id in IMAGE_IDS:
        if image_id == "models":
            _validate_models_data_only(trees[image_id])
        try:
            nodes, edges = extract_graph(trees[image_id], reject_raw_collisions=True)
        except OSError as exc:
            raise ApplianceError(CP_TREE_METADATA, "could not extract H3 activation graph") from exc
        if image_id == "models" and nodes:
            raise ApplianceError(CP_TREE_UNEXPECTED, "models tree must be data-only")
        _merge_graph(all_nodes, all_edges, nodes, edges)
    compare_graph_to_policy(list(all_nodes.values()), list(all_edges.values()), policy)


def _validate_models_data_only(tree_root: str) -> None:
    try:
        for root, _directories, files in os.walk(tree_root):
            for name in files:
                path = os.path.join(root, name)
                relative = os.path.relpath(path, tree_root)
                _validate_activation_path(relative)
                if _touches_activation_surface(relative):
                    raise ApplianceError(CP_TREE_UNEXPECTED, "models tree contains activation content")
                metadata = os.lstat(path)
                if stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) & 0o111:
                    raise ApplianceError(CP_TREE_UNEXPECTED, "models tree contains an executable file")
    except OSError as exc:
        raise ApplianceError(CP_TREE_METADATA, "could not validate H3 models data-only tree") from exc


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
    pseudo_snapshot: dict,
) -> ProvenanceV2ImageRecord:
    squashfs_path = os.path.join(staging_dir, f"{image_id}.squashfs")
    hash_device_path = os.path.join(staging_dir, f"{image_id}.verity")
    if _tree_snapshot(tree_dir) != snapshot:
        raise ApplianceError(CP_TREE_UNEXPECTED, "frozen tree changed before mksquashfs")
    with _pinned_tree(tree_dir, snapshot) as tree_descriptor, _pinned_file(
        pseudo_file_path, pseudo_snapshot
    ) as pseudo_descriptor:
        build = conf_proc_provenance_render.render_build_stage(
            rules_bytes,
            artifact_input_sha256=artifact_input_sha256,
            image_id=image_id,
            mksquashfs_path=tool_paths["mksquashfs"],
            veritysetup_path=tool_paths["veritysetup"],
            tree_dir=".",
            squashfs_path=squashfs_path,
            hash_device_path=hash_device_path,
            pseudo_file_path=f"/proc/self/fd/{pseudo_descriptor}",
        )
        with guard.pin_tools((tool_paths["mksquashfs"], tool_paths["veritysetup"])):
            guard.run_tool(
                list(build.mksquashfs_argv),
                cwd=f"/proc/self/fd/{tree_descriptor}",
                pass_fds=(tree_descriptor, pseudo_descriptor),
            )
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
        with _pinned_bundle_files(stage_root, readonly=False) as files:
            digests = _bundle_digests_from_files(files)
            manifest = parse_manifest_v2(_read_fd(files["appliance.manifest.json"])).raw
            parse_spdx_v2(_read_fd(files["appliance.spdx.json"]))
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
        _validate_output_root(output)
        lock_parent = os.path.join(output, ".h3-locks")
        _ensure_private_directory(lock_parent, CP_PROVENANCE_V2_STAGING, "H3 address-lock parent is not private")
        path = os.path.join(lock_parent, "-".join(address) + ".lock")
        handle = _open_owner_lock(path, CP_PROVENANCE_V2_LEASE)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except (OSError, ApplianceError) as exc:
        if handle is not None:
            _release_lease_quietly(handle)
        if isinstance(exc, ApplianceError):
            raise
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
    _ensure_private_directory(parent, CP_PROVENANCE_V2_STAGING, "H3 staging parent is not private")
    _ensure_private_directory(
        os.path.join(output, ".h3-owners"),
        CP_PROVENANCE_V2_STAGING,
        "H3 owner-lock parent is not private",
    )
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
        _ensure_private_directory(parent, CP_PROVENANCE_V2_STAGING, "H3 owner-lock parent is not private")
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
    parent_path = os.path.dirname(path)
    leaf = os.path.basename(path)
    try:
        parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise ApplianceError(reason_code, "could not open H3 owner-lock directory") from exc
    try:
        parent_value = os.fstat(parent)
        if not _is_same_owner_directory(parent_value):
            raise ApplianceError(reason_code, "H3 owner-lock directory is not a same-owner real directory")
        descriptor = os.open(
            leaf,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        value = os.fstat(descriptor)
        if not _is_same_owner_regular(value):
            raise ApplianceError(reason_code, "H3 owner lock is not a same-owner single-link regular file")
        return os.fdopen(descriptor, "r+b")
    except OSError as exc:
        raise ApplianceError(reason_code, "could not open H3 owner lock") from exc
    except Exception:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def _ensure_real_directory(path: str, reason_code: str, message: str) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        try:
            os.makedirs(path, exist_ok=True)
            metadata = os.lstat(path)
        except OSError as exc:
            raise ApplianceError(reason_code, message) from exc
    except OSError as exc:
        raise ApplianceError(reason_code, message) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ApplianceError(reason_code, message)


def _validate_output_root(path: str) -> None:
    absolute = os.path.abspath(path)
    missing: list[str] = []
    existing = absolute
    while True:
        try:
            os.lstat(existing)
            break
        except FileNotFoundError:
            missing.append(existing)
            parent = os.path.dirname(existing)
            if parent == existing:
                raise ApplianceError(CP_PROVENANCE_V2_STAGING, "H3 output root is unavailable")
            existing = parent
        except OSError as exc:
            raise ApplianceError(CP_PROVENANCE_V2_STAGING, "H3 output root is unavailable") from exc
    _validate_output_ancestor_chain(existing)
    for directory in reversed(missing):
        created = False
        try:
            os.mkdir(directory, 0o700)
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise ApplianceError(CP_PROVENANCE_V2_STAGING, "H3 output root is unavailable") from exc
        if created:
            try:
                descriptor = _open_nofollow_directory(directory)
                metadata = os.fstat(descriptor)
                if not _is_same_owner_directory(metadata):
                    raise ApplianceError(CP_PROVENANCE_V2_STAGING, "H3 created output ancestor is not trusted")
                os.fchmod(descriptor, 0o700)
            except OSError as exc:
                raise ApplianceError(CP_PROVENANCE_V2_STAGING, "H3 output root is unavailable") from exc
            finally:
                if "descriptor" in locals():
                    os.close(descriptor)
                    del descriptor
        _validate_output_ancestor_chain(directory)
    try:
        metadata = os.lstat(absolute)
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_STAGING, "H3 output root is unavailable") from exc
    if (
        not _is_same_owner_directory(metadata)
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ApplianceError(CP_PROVENANCE_V2_STAGING, "H3 output root must be same-owner and non-shared")
    _validate_output_ancestor_chain(absolute)


def _validate_output_ancestor_chain(path: str) -> None:
    """Exclude path replacement by an unprivileged UID above the output root."""

    current_uid = os.geteuid()
    current = os.path.abspath(path)
    ancestors: list[str] = []
    while True:
        ancestors.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    try:
        for ancestor in reversed(ancestors):
            metadata = os.lstat(ancestor)
            mode = stat.S_IMODE(metadata.st_mode)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in (0, current_uid):
                raise ApplianceError(CP_PROVENANCE_V2_STAGING, "H3 output ancestor is not trusted")
            if mode & 0o022 and not mode & stat.S_ISVTX:
                raise ApplianceError(CP_PROVENANCE_V2_STAGING, "H3 output ancestor is replaceable by another UID")
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_STAGING, "H3 output ancestor is unavailable") from exc


def _ensure_private_directory(path: str, reason_code: str, message: str) -> None:
    _ensure_real_directory(path, reason_code, message)
    try:
        descriptor = _open_nofollow_directory(path)
        metadata = os.fstat(descriptor)
        if not _is_same_owner_directory(metadata):
            raise ApplianceError(reason_code, message)
        os.fchmod(descriptor, 0o700)
        current = _open_nofollow_directory(path)
        try:
            current_metadata = os.fstat(current)
            if (current_metadata.st_dev, current_metadata.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise ApplianceError(reason_code, message)
        finally:
            os.close(current)
    except OSError as exc:
        raise ApplianceError(reason_code, message) from exc
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _existing_real_directory(path: str, reason_code: str, message: str) -> bool:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ApplianceError(reason_code, message) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ApplianceError(reason_code, message)
    return True


def _prepare_destination_parent(output: str, address: tuple[str, str]) -> str:
    _validate_output_root(output)
    bundle_root = os.path.join(output, "built_unverified")
    _ensure_private_directory(bundle_root, CP_PROVENANCE_V2_STAGING, "H3 bundle root is not private")
    destination_parent = os.path.join(bundle_root, address[0])
    _ensure_private_directory(destination_parent, CP_PROVENANCE_V2_STAGING, "H3 bundle address parent is not private")
    return destination_parent


def _relocate_ready_stage(stage_root: str, destination_parent: str, address: tuple[str, str]) -> str:
    ready = os.path.join(destination_parent, ".h3-ready-" + address[1])
    if os.path.lexists(ready):
        try:
            metadata = os.lstat(ready)
            if not _is_same_owner_directory(metadata):
                raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "stale H3 ready node is not a same-owner directory")
            _assert_bundle_shape(ready, readonly=False)
            _remove_tree(ready)
        except ApplianceError:
            raise
        except OSError as exc:
            raise ApplianceError(CP_PROVENANCE_V2_SCAVENGE, "could not clear stale H3 ready directory") from exc
    try:
        os.rename(stage_root, ready)
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_STAGING, "could not relocate H3 bundle beside its destination") from exc
    return ready


def _ensure_same_filesystem(stage_root: str, final_parent: str) -> None:
    try:
        if os.stat(stage_root).st_dev != os.stat(final_parent).st_dev:
            raise ApplianceError(CP_PROVENANCE_V2_STAGING, "H3 staging and destination are on different filesystems")
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_STAGING, "could not prepare H3 destination filesystem") from exc


@contextmanager
def _pinned_bundle_files(
    directory: str,
    *,
    readonly: bool,
    allow_metadata_changes: bool = False,
    after_validate: Callable[[], None] | None = None,
) -> Iterator[dict[str, int]]:
    """Validate and operate on the exact bundle directory and file inodes."""

    files: dict[str, int] = {}
    try:
        root = _open_nofollow_directory(directory)
        root_metadata = os.fstat(root)
        root_identity = _stat_identity(root_metadata)
        if not _is_same_owner_directory(root_metadata):
            raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "H3 bundle root is not a same-owner real directory")
        if readonly and stat.S_IMODE(root_metadata.st_mode) != 0o555:
            raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_READONLY, "H3 bundle directory mode is not canonical readonly")
        if sorted(os.listdir(root)) != sorted(BUNDLE_FILES):
            raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "H3 bundle does not have the exact six-file shape")
        for name in BUNDLE_FILES:
            descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=root)
            metadata = os.fstat(descriptor)
            if not _is_same_owner_regular(metadata):
                os.close(descriptor)
                raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "H3 bundle contains a non-regular or linked file")
            if readonly and stat.S_IMODE(metadata.st_mode) != 0o444:
                os.close(descriptor)
                raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_READONLY, "H3 bundle file mode is not canonical readonly")
            files[name] = descriptor
        file_identities = {name: _stat_identity(os.fstat(descriptor)) for name, descriptor in files.items()}
        yield files

        if sorted(os.listdir(root)) != sorted(BUNDLE_FILES):
            raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "H3 bundle shape changed during use")
        root_after = os.fstat(root)
        if readonly and stat.S_IMODE(root_after.st_mode) != 0o555:
            raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_READONLY, "H3 bundle directory mode changed during use")
        if not allow_metadata_changes and _stat_identity(root_after) != root_identity:
            raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "H3 bundle root changed during use")
        for name, descriptor in files.items():
            current = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=root)
            try:
                pinned_metadata = os.fstat(descriptor)
                current_metadata = os.fstat(current)
                if (
                    not _is_same_owner_regular(pinned_metadata)
                    or not _is_same_owner_regular(current_metadata)
                    or (pinned_metadata.st_dev, pinned_metadata.st_ino)
                    != (current_metadata.st_dev, current_metadata.st_ino)
                ):
                    raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "H3 bundle file path changed during use")
                if readonly and (
                    stat.S_IMODE(pinned_metadata.st_mode) != 0o444
                    or stat.S_IMODE(current_metadata.st_mode) != 0o444
                ):
                    raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_READONLY, "H3 bundle file mode changed during use")
                if not allow_metadata_changes and _stat_identity(pinned_metadata) != file_identities[name]:
                    raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "H3 bundle file changed during use")
            finally:
                os.close(current)
        current_root = _open_nofollow_directory(directory)
        try:
            current_metadata = os.fstat(current_root)
            if (current_metadata.st_dev, current_metadata.st_ino) != (root_metadata.st_dev, root_metadata.st_ino):
                raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "H3 bundle root path changed during use")
        finally:
            os.close(current_root)
        if after_validate is not None:
            after_validate()
    except ApplianceError:
        raise
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "could not inspect H3 bundle") from exc
    finally:
        for descriptor in files.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        if "root" in locals():
            try:
                os.close(root)
            except OSError:
                pass


def _assert_bundle_shape(directory: str, *, readonly: bool) -> None:
    with _pinned_bundle_files(directory, readonly=readonly):
        pass


def _bundle_digests(directory: str, *, readonly: bool) -> dict[str, str]:
    try:
        with _pinned_bundle_files(directory, readonly=readonly) as files:
            return _bundle_digests_from_files(files)
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "could not hash H3 bundle file") from exc


def _make_bundle_readonly(directory: str) -> None:
    try:
        with _pinned_bundle_files(directory, readonly=False, allow_metadata_changes=True) as files:
            for descriptor in files.values():
                os.fchmod(descriptor, 0o444)
                if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o444:
                    raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_READONLY, "H3 bundle file did not become read-only")
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_READONLY, "could not make H3 bundle files read-only") from exc


def _bundle_digests_from_files(files: dict[str, int]) -> dict[str, str]:
    return {name: _sha256_fd(files[name]) for name in BUNDLE_FILES}


def _make_bundle_directory_readonly(directory: str) -> None:
    try:
        descriptor = _open_nofollow_directory(directory)
        before = os.fstat(descriptor)
        if not _is_same_owner_directory(before):
            raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "H3 bundle root is not a same-owner real directory")
        os.fchmod(descriptor, 0o555)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o555:
            raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_READONLY, "H3 bundle directory did not become read-only")
        current = _open_nofollow_directory(directory)
        try:
            if (os.fstat(current).st_dev, os.fstat(current).st_ino) != (before.st_dev, before.st_ino):
                raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "H3 bundle directory path changed during hardening")
        finally:
            os.close(current)
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_READONLY, "could not make H3 bundle directory read-only") from exc
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


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


def _sha256_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _read_fd(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks)


def _open_nofollow_regular(path: str, flags: int) -> int:
    """Open a regular file without following a symlink in any component."""

    absolute = os.path.abspath(path)
    components = [component for component in absolute.split(os.sep) if component]
    if not components:
        raise OSError("path has no leaf")
    parent = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in components[:-1]:
            next_parent = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            os.close(parent)
            parent = next_parent
        descriptor = os.open(components[-1], flags | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            os.close(descriptor)
            raise OSError("path is not a single-link regular file")
        return descriptor
    finally:
        os.close(parent)


def _open_nofollow_directory(path: str) -> int:
    """Open a directory without following a symlink in any component."""

    absolute = os.path.abspath(path)
    components = [component for component in absolute.split(os.sep) if component]
    descriptor = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in components:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


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
