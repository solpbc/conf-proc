#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Pure argv rendering for the dormant provenance-v2 image contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import conf_proc_provenance_v2
from conf_proc_geometry import (
    SQUASHFS_COMPRESSION,
    derive_build_epoch,
    derive_verity_salt,
    derive_verity_uuid,
)
from conf_proc_reasons import CP_VERITY_GEOMETRY, CP_VERITY_ROOT_MISMATCH, ApplianceError


# The frozen rules validate these enabled defaults without adding argv tokens:
# fragments, duplicate_data_detection, hardlink_detection, and
# sparse_file_detection use mksquashfs defaults; their -no-* options opt out.
# inode_compression, id_table_compression, data_compression,
# fragment_compression, and xattr_compression are likewise enabled defaults.
# filesystem_padding_4k is a post-mksquashfs padding operation outside this
# renderer.  verity superblock=True is the default, a two-device format needs
# no data-device-offset flag, and fec=disabled emits no FEC option.

_SHA_KEYS: Final = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class BuildStageArgv:
    mksquashfs_argv: tuple[str, ...]
    veritysetup_format_argv: tuple[str, ...]
    build_epoch: int
    salt: str
    uuid: str


@dataclass(frozen=True)
class VerifyStageArgv:
    veritysetup_verify_argv: tuple[str, ...]


def render_build_stage(
    rules_bytes: bytes,
    *,
    artifact_input_sha256: str,
    image_id: str,
    mksquashfs_path: str,
    veritysetup_path: str,
    tree_dir: str,
    squashfs_path: str,
    hash_device_path: str,
    pseudo_file_path: str,
) -> BuildStageArgv:
    """Render deterministic build commands without executing them."""

    rules = conf_proc_provenance_v2.parse_verity_rules(rules_bytes)
    _validate_geometry_inputs(artifact_input_sha256, image_id)
    if type(pseudo_file_path) is not str or not pseudo_file_path:
        raise ApplianceError(CP_VERITY_GEOMETRY, "pseudo_file_path is required by the v2 squashfs contract")

    lock_digest = bytes.fromhex(artifact_input_sha256)
    build_epoch = derive_build_epoch(lock_digest)
    salt = derive_verity_salt(lock_digest, image_id)
    uuid_str = derive_verity_uuid(lock_digest, image_id)
    squashfs = rules["squashfs"]

    mksquashfs_argv = (
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
        "-root-mode",
        oct(squashfs["root_mode"])[2:],
        "-root-uid",
        str(squashfs["root_uid"]),
        "-root-gid",
        str(squashfs["root_gid"]),
        "-pf",
        pseudo_file_path,
        "-exit-on-error",
        "-reproducible",
        "-processors",
        str(squashfs["processors"]),
        "-b",
        str(squashfs["block_size"]),
        "-Xcompression-level",
        str(squashfs["gzip"]["compression_level"]),
        "-Xwindow-size",
        str(squashfs["gzip"]["window_size"]),
        "-Xstrategy",
        ",".join(squashfs["gzip"]["strategies"]),
        "-no-tailends",
        "-exports",
        "-xattrs",
        "-offset",
        str(squashfs["output_offset_bytes"]),
    )
    veritysetup_format_argv = (
        veritysetup_path,
        "format",
        squashfs_path,
        hash_device_path,
        f"--data-block-size={rules['data_block_size']}",
        f"--hash-block-size={rules['hash_block_size']}",
        f"--hash={rules['hash_algorithm']}",
        f"--salt={salt}",
        f"--uuid={uuid_str}",
        "--format=1",
        f"--hash-offset={rules['verity']['hash_offset_bytes']}",
    )
    return BuildStageArgv(
        mksquashfs_argv=mksquashfs_argv,
        veritysetup_format_argv=veritysetup_format_argv,
        build_epoch=build_epoch,
        salt=salt,
        uuid=uuid_str,
    )


def render_verify_stage(
    rules_bytes: bytes,
    *,
    artifact_input_sha256: str,
    image_id: str,
    veritysetup_path: str,
    squashfs_path: str,
    hash_device_path: str,
    root_hash: str,
) -> VerifyStageArgv:
    """Render the candidate verification command without executing it."""

    conf_proc_provenance_v2.parse_verity_rules(rules_bytes)
    _validate_geometry_inputs(artifact_input_sha256, image_id)
    if not _is_sha256(root_hash):
        raise ApplianceError(CP_VERITY_ROOT_MISMATCH, "root_hash must be a lowercase sha256 digest")
    return VerifyStageArgv(
        veritysetup_verify_argv=(veritysetup_path, "verify", squashfs_path, hash_device_path, root_hash)
    )


def _validate_geometry_inputs(artifact_input_sha256: str, image_id: str) -> None:
    if not _is_sha256(artifact_input_sha256):
        raise ApplianceError(CP_VERITY_GEOMETRY, "artifact_input_sha256 must be a lowercase sha256 digest")
    if image_id not in ("models", "runtime-policy"):
        raise ApplianceError(CP_VERITY_GEOMETRY, f"unsupported image id: {image_id!r}")


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA_KEYS
