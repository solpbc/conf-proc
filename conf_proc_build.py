#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Builder entrypoint for the SPP appliance locked-root subsystem.

Consumes a lock file, a policy file, and the locked input tree, and
produces two dm-verity-sealed filesystem images, a canonical appliance
manifest, and an SPDX 2.3 SBOM, promoting the result atomically only after
the independent inspector (conf_proc_inspect.py) accepts it as a hard
prerequisite. This is the only entrypoint that writes or promotes
anything; conf_proc_inspect.py never does.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Callable

from conf_proc_build_graph import extract_graph
from conf_proc_build_images import build_image
from conf_proc_build_manifest import build_manifest_bytes
from conf_proc_build_modules import verify_and_inventory_modules
from conf_proc_build_sbom import build_sbom_bytes
from conf_proc_build_tree import assemble_tree
from conf_proc_graph_compare import compare_graph_to_policy
from conf_proc_guard_setup import build_guard
from conf_proc_lock import parse_lock
from conf_proc_module_authority import check_authorized_signers_match_bundle
from conf_proc_policy import parse_policy
from conf_proc_promote import promote
from conf_proc_reasons import CP_LOCK_DIGEST_MISMATCH, CP_LOCK_ROLE, CP_PROMOTE_INSPECTION, ApplianceError

IMAGES = ("runtime-policy", "models")


def build(
    *,
    lock_path: str,
    policy_path: str,
    input_root: str,
    tool_root: str,
    promote_root: str,
    fault_hook: Callable[[str], None] = lambda phase: None,
) -> str:
    """Run the full build pipeline; return the promoted destination path."""

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
    fault_hook("post_guard_built")

    staging_root = os.path.join(promote_root, ".staging", f"{lock_digest.hex()[:16]}-{uuid.uuid4().hex[:8]}")
    os.makedirs(staging_root)
    fault_hook("post_staging_created")

    trusted_bundle_input = next(i for i in lock.inputs if i.role == "kernel_trusted_cert_bundle")
    trusted_bundle_path = os.path.join(input_root, trusted_bundle_input.source_local_path)
    trusted_bundle_bytes = guard.read_bytes(trusted_bundle_path)
    if hashlib.sha256(trusted_bundle_bytes).hexdigest() != trusted_bundle_input.sha256:
        raise ApplianceError(CP_LOCK_DIGEST_MISMATCH, "trusted certificate bundle does not match locked digest")
    check_authorized_signers_match_bundle(lock, trusted_bundle_bytes)
    fault_hook("post_input_validation")

    images = {}
    all_modules: list[dict] = []
    all_firmware: list[dict] = []
    all_nodes: dict[str, dict] = {}
    all_edges: dict[tuple, dict] = {}
    for image_id in IMAGES:
        tree_dir = os.path.join(staging_root, f"{image_id}-tree")
        pseudo_lines = assemble_tree(guard, lock, image=image_id, input_root=input_root, staging_root=tree_dir)
        pseudo_path = os.path.join(staging_root, f"{image_id}.pseudo")
        Path(pseudo_path).write_text("\n".join(pseudo_lines) + "\n")

        # process_nodes/process_edges are declared globally in the policy
        # (not scoped per image), so the graph closure check runs once
        # after both images have contributed their nodes/edges below.
        nodes, edges = extract_graph(tree_dir)
        all_nodes.update({node["id"]: node for node in nodes})
        for edge in edges:
            all_edges[(edge["from_id"], edge["to_id"], edge["kind"], edge["origin_path"], edge["origin_key"])] = edge

        modules, firmware = verify_and_inventory_modules(
            guard, openssl_path=tool_paths["openssl"], lock=lock, trusted_bundle_pem_path=trusted_bundle_path,
            staging_root=tree_dir, image=image_id, work_dir=staging_root,
        )
        all_modules.extend(modules)
        all_firmware.extend(firmware)

        artifact = build_image(
            guard, mksquashfs_path=tool_paths["mksquashfs"], veritysetup_path=tool_paths["veritysetup"],
            tree_dir=tree_dir, image_id=image_id, lock_digest=lock_digest, staging_dir=staging_root,
            pseudo_file_path=pseudo_path,
        )
        images[image_id] = artifact
        # build_image() already writes directly to
        # staging_root/{image_id}.squashfs and .verity -- exactly the
        # bundle filenames conf_proc_promote.py expects.
        fault_hook(f"post_image_{image_id}")

    compare_graph_to_policy(list(all_nodes.values()), list(all_edges.values()), policy)

    module_authority = {
        "trusted_bundle_input_id": trusted_bundle_input.id,
        "authorized_signer_certificate_sha256": sorted(s.certificate_sha256 for s in lock.authorized_module_signers),
        "module_inventory": sorted(all_modules, key=lambda e: e["path"]),
        "firmware_inventory": sorted(all_firmware, key=lambda e: e["path"]),
    }
    toolchain = [
        {
            "tool_id": next(i.id for i in lock.inputs if i.role == "build_tool" and i.component == component),
            "component": component,
            "resolved_path_sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        }
        for component, path in sorted(tool_paths.items())
    ]

    sbom_bytes = build_sbom_bytes(lock, lock_digest)
    sbom_reference = {
        "filename": "appliance.spdx.json",
        "sha256": hashlib.sha256(sbom_bytes).hexdigest(),
        "spdx_version": "SPDX-2.3",
        "document_spdx_id": "SPDXRef-DOCUMENT",
    }
    manifest_bytes = build_manifest_bytes(
        lock=lock, lock_digest=lock_digest, policy=policy, policy_sha256=policy_sha256, images=images,
        toolchain=toolchain, module_authority=module_authority, sbom_reference=sbom_reference,
    )
    Path(os.path.join(staging_root, "appliance.manifest.json")).write_bytes(manifest_bytes)
    Path(os.path.join(staging_root, "appliance.spdx.json")).write_bytes(sbom_bytes)
    fault_hook("post_manifest_sbom_emission")

    def inspect_fn(bundle_dir: str) -> None:
        result = subprocess.run(
            [
                sys.executable, str(Path(__file__).with_name("conf_proc_inspect.py")),
                "--lock", lock_path, "--policy", policy_path, "--input-root", input_root,
                "--tool-root", tool_root, "--bundle", bundle_dir,
            ],
            capture_output=True,
        )
        if result.returncode != 0:
            raise ApplianceError(
                CP_PROMOTE_INSPECTION,
                f"independent inspector rejected the candidate bundle: {result.stdout.decode('utf-8', 'replace')} "
                f"{result.stderr.decode('utf-8', 'replace')}",
            )

    destination = promote(staging_root, promote_root, lock_digest.hex(), inspect_fn=inspect_fn, fault_hook=fault_hook)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--input-root", required=True)
    parser.add_argument("--tool-root", default="/")
    parser.add_argument("--promote-root", required=True)
    args = parser.parse_args(argv)
    try:
        destination = build(
            lock_path=args.lock, policy_path=args.policy, input_root=args.input_root,
            tool_root=args.tool_root, promote_root=args.promote_root,
        )
    except ApplianceError as exc:
        print(f"{exc.reason_code}: {exc}", file=sys.stderr)
        return 1
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
