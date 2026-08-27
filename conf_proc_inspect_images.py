#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent inspector-side dm-verity re-derivation and extraction.

This module never imports conf_proc_build_images.py. It treats the
candidate bundle's own emitted manifest and shipped hash device as
untrusted claims, re-derives verity salt/UUID from the caller's own
trusted lock digest (a shared pure formula, not the builder's inventory
logic), recomputes a fresh hash tree straight from the candidate's shipped
data file, and only then compares against what the candidate claims.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from conf_proc_geometry import (
    VERITY_DATA_BLOCK_SIZE,
    VERITY_HASH_ALGORITHM,
    VERITY_HASH_BLOCK_SIZE,
    derive_build_epoch,
    derive_verity_salt,
    derive_verity_uuid,
)
from conf_proc_guard import HermeticGuard
from conf_proc_reasons import (
    CP_IMAGE_DIGEST_MISMATCH,
    CP_SQUASHFS_EXTRACT,
    CP_VERITY_FORMAT,
    CP_VERITY_ROOT_MISMATCH,
    CP_VERITY_VERIFY,
    ApplianceError,
)


@dataclass(frozen=True)
class VerityRederivation:
    image_id: str
    expected_salt: str
    expected_uuid: str
    expected_build_epoch: int
    recomputed_root_hash: str
    recomputed_hash_device_sha256: str


def rederive_verity(
    guard: HermeticGuard,
    *,
    veritysetup_path: str,
    candidate_squashfs_path: str,
    image_id: str,
    lock_digest: bytes,
    work_dir: str,
) -> VerityRederivation:
    """Recompute a fresh verity hash tree from the candidate's own data file."""

    expected_salt = derive_verity_salt(lock_digest, image_id)
    expected_uuid = derive_verity_uuid(lock_digest, image_id)
    expected_build_epoch = derive_build_epoch(lock_digest)

    fresh_hash_path = os.path.join(work_dir, f"{image_id}.recomputed.verity")
    try:
        result = guard.run_tool(
            [
                veritysetup_path,
                "format",
                candidate_squashfs_path,
                fresh_hash_path,
                f"--data-block-size={VERITY_DATA_BLOCK_SIZE}",
                f"--hash-block-size={VERITY_HASH_BLOCK_SIZE}",
                f"--hash={VERITY_HASH_ALGORITHM}",
                f"--salt={expected_salt}",
                f"--uuid={expected_uuid}",
            ],
            cwd=work_dir,
        )
    except ApplianceError as exc:
        raise ApplianceError(CP_VERITY_FORMAT, f"independent re-derivation of {image_id!r} failed: {exc}") from exc
    recomputed_root_hash = _parse_root_hash(result.stdout.decode("utf-8"))

    return VerityRederivation(
        image_id=image_id,
        expected_salt=expected_salt,
        expected_uuid=expected_uuid,
        expected_build_epoch=expected_build_epoch,
        recomputed_root_hash=recomputed_root_hash,
        recomputed_hash_device_sha256=_sha256_file(fresh_hash_path),
    )


def compare_against_candidate(
    rederivation: VerityRederivation,
    *,
    claimed_root_hash: str,
    candidate_hash_device_path: str,
) -> None:
    """Fail loud on any divergence between the recomputation and the candidate."""

    if rederivation.recomputed_root_hash != claimed_root_hash:
        raise ApplianceError(
            CP_VERITY_ROOT_MISMATCH,
            f"{rederivation.image_id}: recomputed root hash {rederivation.recomputed_root_hash} "
            f"does not match claimed root hash {claimed_root_hash}",
        )
    candidate_hash_sha256 = _sha256_file(candidate_hash_device_path)
    if rederivation.recomputed_hash_device_sha256 != candidate_hash_sha256:
        raise ApplianceError(
            CP_IMAGE_DIGEST_MISMATCH,
            f"{rederivation.image_id}: recomputed hash device does not match the candidate's shipped hash device",
        )


def verify_candidate_pair(
    guard: HermeticGuard,
    *,
    veritysetup_path: str,
    candidate_squashfs_path: str,
    candidate_hash_device_path: str,
    claimed_root_hash: str,
    image_id: str,
    work_dir: str,
) -> None:
    """Run real veritysetup verify against the candidate's own shipped pair."""

    try:
        guard.run_tool(
            [veritysetup_path, "verify", candidate_squashfs_path, candidate_hash_device_path, claimed_root_hash],
            cwd=work_dir,
        )
    except ApplianceError as exc:
        raise ApplianceError(CP_VERITY_VERIFY, f"{image_id}: candidate image failed verity verification: {exc}") from exc


def extract_image(
    guard: HermeticGuard,
    *,
    unsquashfs_path: str,
    squashfs_path: str,
    dest_dir: str,
    work_dir: str,
) -> None:
    """Extract a squashfs image for independent tree inspection."""

    try:
        guard.run_tool(
            [unsquashfs_path, "-quiet", "-no-progress", "-d", dest_dir, "-f", squashfs_path],
            cwd=work_dir,
        )
    except ApplianceError as exc:
        raise ApplianceError(CP_SQUASHFS_EXTRACT, f"failed to extract {squashfs_path!r}: {exc}") from exc


def _parse_root_hash(stdout: str) -> str:
    for line in stdout.splitlines():
        if line.startswith("Root hash:"):
            value = line.split(":", 1)[1].strip()
            if value:
                return value
    raise ApplianceError(CP_VERITY_FORMAT, "veritysetup format did not report a root hash")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
