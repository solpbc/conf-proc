#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Builder-side squashfs + dm-verity image construction.

This is the ONLY place the builder constructs a filesystem image. The
independent inspector re-derives everything in conf_proc_inspect_images.py
using its own separate extraction and verity re-formatting -- it does not
import this module's construction logic.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from conf_proc_geometry import (
    SQUASHFS_COMPRESSION,
    VERITY_DATA_BLOCK_SIZE,
    VERITY_HASH_ALGORITHM,
    VERITY_HASH_BLOCK_SIZE,
    derive_build_epoch,
    derive_verity_salt,
    derive_verity_uuid,
    pad_file_to_block_size,
)
from conf_proc_guard import HermeticGuard
from conf_proc_reasons import CP_VERITY_FORMAT, CP_VERITY_VERIFY, ApplianceError


@dataclass(frozen=True)
class ImageArtifact:
    image_id: str
    squashfs_path: str
    squashfs_sha256: str
    squashfs_size: int
    hash_device_path: str
    hash_device_sha256: str
    hash_device_size: int
    root_hash: str
    data_block_size: int
    hash_block_size: int
    hash_algorithm: str
    salt: str
    uuid: str
    build_epoch: int


def build_image(
    guard: HermeticGuard,
    *,
    mksquashfs_path: str,
    veritysetup_path: str,
    tree_dir: str,
    image_id: str,
    lock_digest: bytes,
    staging_dir: str,
) -> ImageArtifact:
    """Build one deterministic squashfs + dm-verity image pair."""

    build_epoch = derive_build_epoch(lock_digest)
    salt = derive_verity_salt(lock_digest, image_id)
    uuid_str = derive_verity_uuid(lock_digest, image_id)

    squashfs_path = os.path.join(staging_dir, f"{image_id}.squashfs")
    guard.run_tool(
        [
            mksquashfs_path,
            tree_dir,
            squashfs_path,
            "-noappend",
            "-quiet",
            "-no-progress",
            "-all-time",
            str(build_epoch),
            "-mkfs-time",
            str(build_epoch),
            "-comp",
            SQUASHFS_COMPRESSION,
        ],
        cwd=staging_dir,
    )
    pad_file_to_block_size(squashfs_path, VERITY_DATA_BLOCK_SIZE)

    hash_device_path = os.path.join(staging_dir, f"{image_id}.verity")
    result = guard.run_tool(
        [
            veritysetup_path,
            "format",
            squashfs_path,
            hash_device_path,
            f"--data-block-size={VERITY_DATA_BLOCK_SIZE}",
            f"--hash-block-size={VERITY_HASH_BLOCK_SIZE}",
            f"--hash={VERITY_HASH_ALGORITHM}",
            f"--salt={salt}",
            f"--uuid={uuid_str}",
        ],
        cwd=staging_dir,
    )
    root_hash = _parse_root_hash(result.stdout.decode("utf-8"))

    try:
        guard.run_tool(
            [veritysetup_path, "verify", squashfs_path, hash_device_path, root_hash],
            cwd=staging_dir,
        )
    except ApplianceError as exc:
        raise ApplianceError(CP_VERITY_VERIFY, f"freshly built image {image_id!r} failed self-verification: {exc}") from exc

    return ImageArtifact(
        image_id=image_id,
        squashfs_path=squashfs_path,
        squashfs_sha256=_sha256_file(squashfs_path),
        squashfs_size=os.path.getsize(squashfs_path),
        hash_device_path=hash_device_path,
        hash_device_sha256=_sha256_file(hash_device_path),
        hash_device_size=os.path.getsize(hash_device_path),
        root_hash=root_hash,
        data_block_size=VERITY_DATA_BLOCK_SIZE,
        hash_block_size=VERITY_HASH_BLOCK_SIZE,
        hash_algorithm=VERITY_HASH_ALGORITHM,
        salt=salt,
        uuid=uuid_str,
        build_epoch=build_epoch,
    )


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
