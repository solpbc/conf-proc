#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent inspector entrypoint for the SPP appliance locked-root
subsystem.

Takes the caller's own original lock, policy, and locked input tree as
trusted inputs, and a built bundle directory as the untrusted candidate to
check. Never trusts the candidate's own manifest or SBOM as an oracle:
every field is independently re-derived from the trusted lock/policy and
from real re-extraction/re-verification of the candidate's images, then
compared. This module never writes to or promotes anything.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
from pathlib import Path

from conf_proc_geometry import VERITY_DATA_BLOCK_SIZE, VERITY_HASH_ALGORITHM, VERITY_HASH_BLOCK_SIZE
from conf_proc_graph_compare import compare_graph_to_policy
from conf_proc_guard_setup import build_guard
from conf_proc_inspect_graph import extract_graph
from conf_proc_inspect_images import compare_against_candidate, rederive_verity, verify_candidate_pair
from conf_proc_inspect_manifest import compare_manifest
from conf_proc_inspect_modules import compare_module_authority, rederive_module_authority
from conf_proc_inspect_sbom import compare_sbom
from conf_proc_inspect_tree import build_inventory, compare_against_lock
from conf_proc_lock import parse_lock
from conf_proc_manifest import parse_manifest
from conf_proc_module_authority import check_authorized_signers_match_bundle
from conf_proc_policy import parse_policy
from conf_proc_reasons import CP_LOCK_DIGEST_MISMATCH, CP_LOCK_ROLE, CP_SBOM_DIFF, ApplianceError
from conf_proc_sbom import parse_sbom

IMAGES = ("runtime-policy", "models")


def inspect(*, lock_path: str, policy_path: str, input_root: str, tool_root: str, bundle_dir: str) -> None:
    """Independently validate a built bundle; raise ApplianceError on any failure."""

    lock_data = Path(lock_path).read_bytes()
    lock = parse_lock(lock_data)
    lock_digest = hashlib.sha256(lock_data).digest()

    policy_lock_input = next((i for i in lock.inputs if i.id == lock.policy_input_id), None)
    if policy_lock_input is None:
        raise ApplianceError(CP_LOCK_ROLE, "lock's policy_input_id does not resolve to a known input")
    policy_data = Path(policy_path).read_bytes()
    if hashlib.sha256(policy_data).hexdigest() != policy_lock_input.sha256:
        raise ApplianceError(CP_LOCK_DIGEST_MISMATCH, "supplied policy file does not match the lock's declared digest")
    policy = parse_policy(policy_data)
    policy_sha256 = hashlib.sha256(policy_data).hexdigest()

    guard, tool_paths = build_guard(lock, lock_digest, input_root=input_root, tool_root=tool_root)

    trusted_bundle_input = next(i for i in lock.inputs if i.role == "kernel_trusted_cert_bundle")
    trusted_bundle_path = os.path.join(input_root, trusted_bundle_input.source_local_path)
    trusted_bundle_bytes = guard.read_bytes(trusted_bundle_path)
    if hashlib.sha256(trusted_bundle_bytes).hexdigest() != trusted_bundle_input.sha256:
        raise ApplianceError(CP_LOCK_DIGEST_MISMATCH, "trusted certificate bundle does not match locked digest")
    check_authorized_signers_match_bundle(lock, trusted_bundle_bytes)

    manifest_bytes = Path(os.path.join(bundle_dir, "appliance.manifest.json")).read_bytes()
    manifest = parse_manifest(manifest_bytes)

    sbom_bytes = Path(os.path.join(bundle_dir, "appliance.spdx.json")).read_bytes()
    if hashlib.sha256(sbom_bytes).hexdigest() != manifest.raw["sbom"]["sha256"]:
        raise ApplianceError(CP_SBOM_DIFF, "SBOM file content does not match the digest claimed in the manifest")
    sbom = parse_sbom(sbom_bytes)
    compare_sbom(sbom, lock)

    rederived_images: dict[str, dict] = {}
    inventories: dict[str, dict] = {}
    all_modules: list[dict] = []
    all_firmware: list[dict] = []
    all_nodes: dict[str, dict] = {}
    all_edges: dict[tuple, dict] = {}

    with tempfile.TemporaryDirectory(dir="/var/tmp") as work_root:
        for image_id in IMAGES:
            squashfs_path = os.path.join(bundle_dir, f"{image_id}.squashfs")
            hash_device_path = os.path.join(bundle_dir, f"{image_id}.verity")
            work_dir = os.path.join(work_root, image_id)
            os.makedirs(work_dir)

            rederivation = rederive_verity(
                guard, veritysetup_path=tool_paths["veritysetup"], candidate_squashfs_path=squashfs_path,
                image_id=image_id, lock_digest=lock_digest, work_dir=work_dir,
            )
            claimed_root_hash = manifest.raw["images"][image_id]["root_hash"]
            compare_against_candidate(rederivation, claimed_root_hash=claimed_root_hash, candidate_hash_device_path=hash_device_path)
            verify_candidate_pair(
                guard, veritysetup_path=tool_paths["veritysetup"], candidate_squashfs_path=squashfs_path,
                candidate_hash_device_path=hash_device_path, claimed_root_hash=claimed_root_hash,
                image_id=image_id, work_dir=work_dir,
            )
            rederived_images[image_id] = {
                "squashfs_sha256": _sha256_file(squashfs_path),
                "squashfs_size_bytes": os.path.getsize(squashfs_path),
                "hash_device_sha256": rederivation.recomputed_hash_device_sha256,
                "hash_device_size_bytes": os.path.getsize(hash_device_path),
                "root_hash": rederivation.recomputed_root_hash,
                "data_block_size": VERITY_DATA_BLOCK_SIZE,
                "hash_block_size": VERITY_HASH_BLOCK_SIZE,
                "hash_algorithm": VERITY_HASH_ALGORITHM,
                "salt": rederivation.expected_salt,
                "uuid": rederivation.expected_uuid,
            }

            extract_dir = os.path.join(work_dir, "extracted")
            inventory = build_inventory(
                guard, unsquashfs_path=tool_paths["unsquashfs"], squashfs_path=squashfs_path,
                extract_dir=extract_dir, work_dir=work_dir,
            )
            compare_against_lock(inventory, lock, image=image_id)
            inventories[image_id] = inventory

            # process_nodes/process_edges are declared globally in the
            # policy (not scoped per image), so the graph closure check
            # runs once after both images have contributed below.
            nodes, edges = extract_graph(extract_dir)
            all_nodes.update({node["id"]: node for node in nodes})
            for edge in edges:
                all_edges[(edge["from_id"], edge["to_id"], edge["kind"], edge["origin_path"], edge["origin_key"])] = edge

            modules, firmware = rederive_module_authority(
                guard, openssl_path=tool_paths["openssl"], lock=lock, trusted_bundle_pem_path=trusted_bundle_path,
                extract_dir=extract_dir, image=image_id, work_dir=work_dir,
            )
            all_modules.extend(modules)
            all_firmware.extend(firmware)

        compare_graph_to_policy(list(all_nodes.values()), list(all_edges.values()), policy)
        compare_module_authority(
            (sorted(all_modules, key=lambda e: e["path"]), sorted(all_firmware, key=lambda e: e["path"])),
            manifest.raw["module_authority"],
        )
        compare_manifest(
            manifest, lock=lock, lock_digest=lock_digest, policy=policy, policy_sha256=policy_sha256,
            rederived_images=rederived_images, inventories=inventories,
        )


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--input-root", required=True)
    parser.add_argument("--tool-root", default="/")
    parser.add_argument("--bundle", required=True)
    args = parser.parse_args(argv)
    try:
        inspect(
            lock_path=args.lock, policy_path=args.policy, input_root=args.input_root,
            tool_root=args.tool_root, bundle_dir=args.bundle,
        )
    except ApplianceError as exc:
        print(f"{exc.reason_code}: {exc}", file=sys.stderr)
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
