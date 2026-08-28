#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Dormant independent inspector for provenance-v2 appliance bundles."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Final, Iterator

from conf_proc_graph_compare import compare_graph_to_policy
from conf_proc_guard import HermeticGuard, ToolDeclaration, hermetic_lockdown
from conf_proc_guard_setup import build_guard
from conf_proc_inspect_graph import extract_graph
from conf_proc_inspect_images import compare_against_candidate, rederive_verity, verify_candidate_pair
from conf_proc_inspect_modules import compare_module_authority, rederive_module_authority
from conf_proc_inspect_tree import build_inventory, compare_against_lock
from conf_proc_json import canonical_dumps, canonical_loads
from conf_proc_module_authority import check_authorized_signers_match_bundle
from conf_proc_prohibited import check_future_cmdline
from conf_proc_provenance_v2_inspect_documents import check_documents, derive_inspection_inputs
from conf_proc_provenance_v2_inspect_surface import check_extracted_surfaces
from conf_proc_reasons import (
    CP_PROVENANCE_INPUT_CHANGED,
    CP_PROVENANCE_INPUT_READ,
    CP_PROVENANCE_INPUT_SIZE,
    CP_PROVENANCE_V2_BUNDLE_READONLY,
    CP_PROVENANCE_V2_BUNDLE_SHAPE,
    CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION,
    CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH,
    CP_PROVENANCE_V2_INSPECT_SEALED_BINDING,
    CP_TOOL_MISSING,
    ApplianceError,
)


MAX_INPUT_BYTES: Final = 32 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES: Final = 128 * 1024 * 1024
IMAGE_IDS: Final = ("models", "runtime-policy")
BUNDLE_FILES: Final = (
    "models.squashfs",
    "models.verity",
    "runtime-policy.squashfs",
    "runtime-policy.verity",
    "appliance.manifest.json",
    "appliance.spdx.json",
)
_EVIDENCE_CEILING: Final = "No UKI, signature, PCR, boot, TPM, GPU, or Azure proof is provided."


@dataclass(frozen=True)
class InspectionResult:
    state: str
    hardware_qualification: str
    artifact_input_sha256: str
    execution_provenance_sha256: str
    models_squashfs_sha256: str
    models_verity_sha256: str
    runtime_policy_squashfs_sha256: str
    runtime_policy_verity_sha256: str
    manifest_sha256: str
    spdx_sha256: str
    evidence_ceiling: str


class _ReadBudget:
    def __init__(self, limit: int) -> None:
        self.remaining = limit

    def consume(self, size: int) -> None:
        if size > self.remaining:
            raise ApplianceError(CP_PROVENANCE_INPUT_SIZE, "authority input aggregate exceeds its bounded-read budget")
        self.remaining -= size


@contextmanager
def _pinned_authorities(paths: dict[str, str]) -> Iterator[dict[str, bytes]]:
    """Open, read, and retain the six trusted authorities without TOCTOU gaps."""

    descriptors: dict[str, int] = {}
    identities: dict[str, tuple[int, int, int, int, int]] = {}
    digests: dict[str, str] = {}
    payloads: dict[str, bytes] = {}
    budget = _ReadBudget(MAX_TOTAL_INPUT_BYTES)
    try:
        if set(paths) != {"root_lock", "runtime_closure", "verity_rules", "tcb_identity", "builder_source", "policy"}:
            raise ApplianceError(CP_PROVENANCE_INPUT_READ, "trusted authority set is incomplete")
        for name, path in paths.items():
            descriptor = _open_nofollow_regular(path)
            descriptors[name] = descriptor
            before = os.fstat(descriptor)
            if before.st_size < 0 or before.st_size > MAX_INPUT_BYTES:
                raise ApplianceError(CP_PROVENANCE_INPUT_SIZE, "authority input exceeds its bounded-read budget")
            budget.consume(before.st_size)
            payloads[name] = _read_exact(descriptor, before.st_size)
            after = os.fstat(descriptor)
            if _stat_identity(before) != _stat_identity(after):
                raise ApplianceError(CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION, "authority changed while being read")
            identities[name] = _stat_identity(before)
            digests[name] = hashlib.sha256(payloads[name]).hexdigest()
        yield payloads
        for name, descriptor in descriptors.items():
            after = os.fstat(descriptor)
            if _stat_identity(after) != identities[name] or _sha256_fd(descriptor) != digests[name]:
                raise ApplianceError(CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION, "authority changed during inspection")
            current = _open_nofollow_regular(paths[name])
            try:
                if (os.fstat(current).st_dev, os.fstat(current).st_ino) != (after.st_dev, after.st_ino):
                    raise ApplianceError(CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION, "authority path changed during inspection")
            finally:
                os.close(current)
    except ApplianceError:
        raise
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_INPUT_READ, "could not read trusted authority") from exc
    finally:
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass


@contextmanager
def _pinned_bundle_files(directory: str) -> Iterator[dict[str, int]]:
    """Pin the candidate's exact readonly six-file bundle shape."""

    root = -1
    files: dict[str, int] = {}
    try:
        root = _open_nofollow_directory(directory)
        root_before = os.fstat(root)
        root_identity = _stat_identity(root_before)
        if not _is_same_owner_directory(root_before):
            raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "candidate bundle root is not a same-owner directory")
        if stat.S_IMODE(root_before.st_mode) != 0o555:
            raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_READONLY, "candidate bundle directory is not readonly")
        if sorted(os.listdir(root)) != sorted(BUNDLE_FILES):
            raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "candidate bundle does not have the exact six-file shape")
        for name in BUNDLE_FILES:
            descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=root)
            metadata = os.fstat(descriptor)
            if not _is_same_owner_regular(metadata):
                os.close(descriptor)
                raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "candidate bundle contains an invalid leaf")
            if stat.S_IMODE(metadata.st_mode) != 0o444:
                os.close(descriptor)
                raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_READONLY, "candidate bundle leaf is not readonly")
            files[name] = descriptor
        identities = {name: _stat_identity(os.fstat(descriptor)) for name, descriptor in files.items()}
        yield files
        if sorted(os.listdir(root)) != sorted(BUNDLE_FILES) or _stat_identity(os.fstat(root)) != root_identity:
            raise ApplianceError(CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION, "candidate bundle changed during inspection")
        for name, descriptor in files.items():
            pinned = os.fstat(descriptor)
            current = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=root)
            try:
                current_stat = os.fstat(current)
                if (
                    not _is_same_owner_regular(pinned)
                    or not _is_same_owner_regular(current_stat)
                    or stat.S_IMODE(pinned.st_mode) != 0o444
                    or stat.S_IMODE(current_stat.st_mode) != 0o444
                    or _stat_identity(pinned) != identities[name]
                    or (pinned.st_dev, pinned.st_ino) != (current_stat.st_dev, current_stat.st_ino)
                ):
                    raise ApplianceError(CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION, "candidate bundle leaf changed during inspection")
            finally:
                os.close(current)
        current_root = _open_nofollow_directory(directory)
        try:
            current_stat = os.fstat(current_root)
            if (current_stat.st_dev, current_stat.st_ino) != (root_before.st_dev, root_before.st_ino):
                raise ApplianceError(CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION, "candidate bundle path changed during inspection")
        finally:
            os.close(current_root)
    except ApplianceError:
        raise
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_V2_BUNDLE_SHAPE, "could not inspect candidate bundle") from exc
    finally:
        for descriptor in files.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        if root >= 0:
            try:
                os.close(root)
            except OSError:
                pass


def inspect_bundle(
    *,
    root_lock_path: str,
    runtime_closure_path: str,
    verity_rules_path: str,
    tcb_identity_path: str,
    builder_source_path: str,
    policy_path: str,
    input_root: str,
    tool_root: str,
    bundle: str,
) -> InspectionResult:
    """Independently inspect a readonly provenance-v2 candidate bundle."""

    try:
        values = _inspect_values(
            root_lock_path=root_lock_path,
            runtime_closure_path=runtime_closure_path,
            verity_rules_path=verity_rules_path,
            tcb_identity_path=tcb_identity_path,
            builder_source_path=builder_source_path,
            policy_path=policy_path,
            input_root=input_root,
            tool_root=tool_root,
            bundle=bundle,
        )
        return InspectionResult(**values)
    except ApplianceError as exc:
        code = CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION if exc.reason_code == CP_PROVENANCE_INPUT_CHANGED else exc.reason_code
        raise ApplianceError(code, "inspection failed") from exc
    except OSError as exc:
        raise ApplianceError(CP_PROVENANCE_INPUT_READ, "inspection input is unavailable") from exc
    except Exception as exc:  # noqa: BLE001 - public boundary must never disclose internals
        raise ApplianceError(CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION, "inspection failed") from exc


def _inspect_values(**paths: str) -> dict[str, str]:
    authorities = {
        "root_lock": paths["root_lock_path"],
        "runtime_closure": paths["runtime_closure_path"],
        "verity_rules": paths["verity_rules_path"],
        "tcb_identity": paths["tcb_identity_path"],
        "builder_source": paths["builder_source_path"],
        "policy": paths["policy_path"],
    }
    with _pinned_authorities(authorities) as authority_bytes:
        inputs = derive_inspection_inputs(
            root_lock_bytes=authority_bytes["root_lock"],
            runtime_closure_bytes=authority_bytes["runtime_closure"],
            verity_rules_bytes=authority_bytes["verity_rules"],
            tcb_identity_bytes=authority_bytes["tcb_identity"],
            builder_source_bytes=authority_bytes["builder_source"],
            policy_bytes=authority_bytes["policy"],
        )
        check_future_cmdline(inputs.lock.future_cmdline)
        base_guard, tool_paths = build_guard(
            inputs.lock,
            bytes.fromhex(inputs.artifact_input_sha256),
            input_root=paths["input_root"],
            tool_root=paths["tool_root"],
        )
        _require_native_tools(tool_paths)
        trusted_input = next(item for item in inputs.lock.inputs if item.role == "kernel_trusted_cert_bundle")
        trusted_bundle_path = os.path.abspath(os.path.join(paths["input_root"], trusted_input.source_local_path))
        candidate_paths = {name: os.path.abspath(os.path.join(paths["bundle"], name)) for name in BUNDLE_FILES}
        guard = _candidate_guard(base_guard, inputs.lock, tool_paths, candidate_paths.values())
        pinned_reads = (*candidate_paths.values(), trusted_bundle_path)
        result: dict[str, str] | None = None
        with _pinned_bundle_files(paths["bundle"]) as bundle_files, guard.pin_reads(pinned_reads), guard.pin_tools(
            (tool_paths["veritysetup"], tool_paths["unsquashfs"], tool_paths["openssl"])
        ):
            for name, descriptor in bundle_files.items():
                if _stat_identity(os.fstat(descriptor)) != _stat_identity(guard.stat_read(candidate_paths[name])):
                    raise ApplianceError(CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION, "candidate pin identities disagree")
            trusted_bundle_bytes = guard.read_bytes(trusted_bundle_path)
            if hashlib.sha256(trusted_bundle_bytes).hexdigest() != trusted_input.sha256:
                raise ApplianceError(CP_PROVENANCE_INPUT_READ, "trusted certificate authority does not match the lock")
            check_authorized_signers_match_bundle(inputs.lock, trusted_bundle_bytes)
            with tempfile.TemporaryDirectory(dir="/var/tmp", prefix="conf-proc-h4-") as work_root:
                os.chmod(work_root, 0o700)
                images, inventories, modules, firmware, nodes, edges, extraction_roots = _inspect_images(
                    guard=guard,
                    tool_paths=tool_paths,
                    lock=inputs.lock,
                    lock_digest=bytes.fromhex(inputs.artifact_input_sha256),
                    candidate_paths=candidate_paths,
                    trusted_bundle_path=trusted_bundle_path,
                    work_root=work_root,
                )
                check_extracted_surfaces(
                    runtime_policy_root=extraction_roots["runtime-policy"],
                    models_root=extraction_roots["models"],
                    policy=inputs.policy,
                    graph_nodes=nodes,
                )
                compare_graph_to_policy(nodes, edges, inputs.policy)
                manifest_bytes = guard.read_bytes(candidate_paths["appliance.manifest.json"])
                spdx_bytes = guard.read_bytes(candidate_paths["appliance.spdx.json"])
                _compare_module_claims(manifest_bytes, modules, firmware)
                evidence = {
                    "images": images,
                    "inventories": inventories,
                    "module_inventory": modules,
                    "firmware_inventory": firmware,
                    "graph_nodes": nodes,
                    "graph_edges": edges,
                }
                check_documents(manifest_bytes=manifest_bytes, spdx_bytes=spdx_bytes, inputs=inputs, evidence=evidence)
                _require_sealed_binding(authorities, candidate_paths)
                result = {
                    "state": "artifact_consistent",
                    "hardware_qualification": "not_qualified",
                    "artifact_input_sha256": inputs.artifact_input_sha256,
                    "execution_provenance_sha256": inputs.execution_provenance_sha256,
                    "models_squashfs_sha256": _sha256_fd(bundle_files["models.squashfs"]),
                    "models_verity_sha256": _sha256_fd(bundle_files["models.verity"]),
                    "runtime_policy_squashfs_sha256": _sha256_fd(bundle_files["runtime-policy.squashfs"]),
                    "runtime_policy_verity_sha256": _sha256_fd(bundle_files["runtime-policy.verity"]),
                    "manifest_sha256": _sha256_fd(bundle_files["appliance.manifest.json"]),
                    "spdx_sha256": _sha256_fd(bundle_files["appliance.spdx.json"]),
                    "evidence_ceiling": _EVIDENCE_CEILING,
                }
        if result is None:
            raise ApplianceError(CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION, "inspection did not produce a result")
        return result


def _candidate_guard(base_guard: HermeticGuard, lock, tool_paths: dict[str, str], candidate_paths) -> HermeticGuard:
    tool_inputs = {item.component: item for item in lock.inputs if item.role == "build_tool"}
    declarations: dict[str, ToolDeclaration] = {}
    for component, path in tool_paths.items():
        item = tool_inputs.get(component)
        if item is None:
            raise ApplianceError(CP_TOOL_MISSING, "locked tool declaration is incomplete")
        declarations[path] = ToolDeclaration(absolute_path=path, sha256=item.sha256)
    return HermeticGuard(
        allowed_reads=frozenset((*base_guard.allowed_reads(), *candidate_paths)),
        tools=declarations,
        env=base_guard.env,
        build_epoch=base_guard.build_epoch,
    )


def _require_native_tools(tool_paths: dict[str, str]) -> None:
    if any(name not in tool_paths for name in ("veritysetup", "unsquashfs", "openssl")):
        raise ApplianceError(CP_TOOL_MISSING, "required native inspection tool is not declared")


def _inspect_images(*, guard: HermeticGuard, tool_paths: dict[str, str], lock, lock_digest: bytes, candidate_paths: dict[str, str], trusted_bundle_path: str, work_root: str):
    images: dict[str, dict] = {}
    inventories: dict[str, dict] = {}
    all_modules: list[dict] = []
    all_firmware: list[dict] = []
    all_nodes: dict[str, dict] = {}
    all_edges: dict[tuple[str, str, str, str, str], dict] = {}
    extraction_roots: dict[str, str] = {}
    with hermetic_lockdown():
        for image in IMAGE_IDS:
            work_dir = os.path.join(work_root, image)
            os.mkdir(work_dir, 0o700)
            squashfs = candidate_paths[f"{image}.squashfs"]
            verity = candidate_paths[f"{image}.verity"]
            rederivation = rederive_verity(
                guard,
                veritysetup_path=tool_paths["veritysetup"],
                candidate_squashfs_path=guard.pinned_path(squashfs),
                image_id=image,
                lock_digest=lock_digest,
                work_dir=work_dir,
            )
            compare_against_candidate(
                rederivation,
                claimed_root_hash=rederivation.recomputed_root_hash,
                candidate_hash_device_path=guard.pinned_path(verity),
            )
            verify_candidate_pair(
                guard,
                veritysetup_path=tool_paths["veritysetup"],
                candidate_squashfs_path=guard.pinned_path(squashfs),
                candidate_hash_device_path=guard.pinned_path(verity),
                claimed_root_hash=rederivation.recomputed_root_hash,
                image_id=image,
                work_dir=work_dir,
            )
            images[image] = {
                "squashfs_sha256": _sha256_file(guard.pinned_path(squashfs)),
                "squashfs_size_bytes": guard.stat_read(squashfs).st_size,
                "hash_device_sha256": _sha256_file(guard.pinned_path(verity)),
                "hash_device_size_bytes": guard.stat_read(verity).st_size,
                "root_hash": rederivation.recomputed_root_hash,
            }
            extract_root = os.path.join(work_dir, "extracted")
            inventory = build_inventory(
                guard,
                unsquashfs_path=tool_paths["unsquashfs"],
                squashfs_path=guard.pinned_path(squashfs),
                extract_dir=extract_root,
                work_dir=work_dir,
            )
            compare_against_lock(inventory, lock, image=image)
            inventories[image] = inventory
            extraction_roots[image] = extract_root
            nodes, edges = extract_graph(extract_root)
            _merge_graph(all_nodes, all_edges, nodes, edges)
            module_rows, firmware_rows = rederive_module_authority(
                guard,
                openssl_path=tool_paths["openssl"],
                lock=lock,
                trusted_bundle_pem_path=guard.pinned_path(trusted_bundle_path),
                extract_dir=extract_root,
                image=image,
                work_dir=work_dir,
            )
            all_modules.extend(module_rows)
            all_firmware.extend(firmware_rows)
    all_modules.sort(key=lambda row: row["path"])
    all_firmware.sort(key=lambda row: row["path"])
    return images, inventories, all_modules, all_firmware, list(all_nodes.values()), list(all_edges.values()), extraction_roots


def _merge_graph(nodes_by_id: dict[str, dict], edges_by_key: dict[tuple[str, str, str, str, str], dict], nodes: list[dict], edges: list[dict]) -> None:
    for node in nodes:
        prior = nodes_by_id.get(node["id"])
        if prior is not None and prior != node:
            raise ApplianceError(CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "graph identities conflict")
        nodes_by_id[node["id"]] = node
    for edge in edges:
        key = (edge["from_id"], edge["to_id"], edge["kind"], edge["origin_path"], edge["origin_key"])
        if key in edges_by_key:
            raise ApplianceError(CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "graph edge is duplicated")
        edges_by_key[key] = edge


def _compare_module_claims(manifest_bytes: bytes, modules: list[dict], firmware: list[dict]) -> None:
    try:
        manifest = canonical_loads(manifest_bytes)
        claimed = manifest["module_authority"]
        if type(claimed) is not dict:
            raise TypeError
        compare_module_authority((modules, firmware), claimed)
    except ApplianceError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ApplianceError(CP_PROVENANCE_V2_INSPECT_DOCUMENT_MISMATCH, "candidate module claim is invalid") from exc


def _require_sealed_binding(authorities: dict[str, str], candidate_paths: dict[str, str]) -> None:
    adapter = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conf_proc_inspect_provenance_cli.py")
    argv = [
        sys.executable, adapter,
        "--root-lock", authorities["root_lock"],
        "--runtime-closure", authorities["runtime_closure"],
        "--verity-rules", authorities["verity_rules"],
        "--tcb-identity", authorities["tcb_identity"],
        "--builder-source", authorities["builder_source"],
        "--policy", authorities["policy"],
        "--manifest", candidate_paths["appliance.manifest.json"],
        "--sbom", candidate_paths["appliance.spdx.json"],
    ]
    try:
        completed = subprocess.run(argv, capture_output=True, check=False)
        output = completed.stdout[:-1] if completed.stdout.endswith(b"\n") else completed.stdout
        parsed = canonical_loads(output)
        if completed.returncode != 0 or type(parsed) is not dict or parsed.get("accepted") is not True:
            raise ApplianceError(CP_PROVENANCE_V2_INSPECT_SEALED_BINDING, "sealed provenance binding was not accepted")
    except ApplianceError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise ApplianceError(CP_PROVENANCE_V2_INSPECT_SEALED_BINDING, "sealed provenance binding could not be checked") from exc


def _open_nofollow_regular(path: str) -> int:
    absolute = os.path.abspath(path)
    parts = [part for part in absolute.split(os.sep) if part]
    if not parts:
        raise OSError("path has no leaf")
    parent = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            next_parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = next_parent
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        metadata = os.fstat(descriptor)
        if not _is_same_owner_regular(metadata):
            os.close(descriptor)
            raise OSError("path is not a same-owner regular file")
        return descriptor
    finally:
        os.close(parent)


def _open_nofollow_directory(path: str) -> int:
    descriptor = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in [part for part in os.path.abspath(path).split(os.sep) if part]:
            next_descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_exact(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    os.lseek(descriptor, 0, os.SEEK_SET)
    while remaining:
        chunk = os.read(descriptor, min(remaining, 1024 * 1024))
        if not chunk:
            raise ApplianceError(CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION, "authority changed while being read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ApplianceError(CP_PROVENANCE_V2_INSPECT_CONCURRENT_MUTATION, "authority changed while being read")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks)


def _sha256_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _is_same_owner_directory(value: os.stat_result) -> bool:
    return stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and value.st_uid == os.geteuid()


def _is_same_owner_regular(value: os.stat_result) -> bool:
    return stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == os.geteuid()


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
    parser.add_argument("--bundle", required=True)
    try:
        args = parser.parse_args(argv)
        result = inspect_bundle(
            root_lock_path=args.root_lock,
            runtime_closure_path=args.runtime_closure,
            verity_rules_path=args.verity_rules,
            tcb_identity_path=args.tcb_identity,
            builder_source_path=args.builder_source,
            policy_path=args.policy,
            input_root=args.input_root,
            tool_root=args.tool_root,
            bundle=args.bundle,
        )
    except ApplianceError as exc:
        sys.stdout.buffer.write(canonical_dumps({"reason_code": exc.reason_code, "message": "inspection failed"}) + b"\n")
        return 1
    sys.stdout.buffer.write(canonical_dumps(asdict(result)) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
