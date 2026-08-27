#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Builder-side staging tree assembly from a parsed Lock's placements.

Materializes exactly the declared placements for one image into a staging
directory, verifying source content digests as it goes, and emits a
mksquashfs pseudo-file definition list that forces every node's declared
mode/uid/gid -- required for byte-identical output regardless of which
(rootless) user or host performs the build. This module is the builder's
own tree-walk/assembly implementation; the inspector's is separate
(conf_proc_inspect_tree.py) and must not import this module.
"""

from __future__ import annotations

import hashlib
import os

from conf_proc_guard import HermeticGuard
from conf_proc_lock import Lock, LockInput, Placement
from conf_proc_reasons import CP_LOCK_DIGEST_MISMATCH, CP_TREE_UNEXPECTED, CP_TREE_XATTR, ApplianceError
from conf_proc_tree_rules import (
    ALLOWED_XATTRS,
    classify_node_type,
    validate_node_metadata,
    validate_symlink_target,
    validate_xattr_names,
)


def assemble_tree(
    guard: HermeticGuard,
    lock: Lock,
    *,
    image: str,
    input_root: str,
    staging_root: str,
) -> list[str]:
    """Materialize one image's declared tree; return sorted pseudo-file lines."""

    os.makedirs(staging_root, exist_ok=True)
    pseudo_lines: list[str] = []
    declared_dirs: set[str] = set()

    for lock_input in lock.inputs:
        for placement in lock_input.placements:
            if placement.image != image:
                continue
            _materialize(guard, lock_input, placement, input_root=input_root, staging_root=staging_root)
            pseudo_lines.append(_pseudo_line(placement))
            if placement.node_type == "directory":
                declared_dirs.add(placement.path)

    _reject_undeclared_directories(staging_root, declared_dirs)
    return sorted(pseudo_lines)


def _materialize(
    guard: HermeticGuard,
    lock_input: LockInput,
    placement: Placement,
    *,
    input_root: str,
    staging_root: str,
) -> None:
    dest = os.path.join(staging_root, placement.path.lstrip("/"))

    if placement.node_type == "directory":
        os.makedirs(dest, exist_ok=True)
        return

    os.makedirs(os.path.dirname(dest), exist_ok=True)

    if placement.node_type == "file":
        source_path = os.path.join(input_root, lock_input.source_local_path)
        source_stat = os.lstat(source_path)
        node_type = classify_node_type(source_stat.st_mode)
        validate_node_metadata(source_path, mode=source_stat.st_mode, node_type=node_type, nlink=source_stat.st_nlink)
        content = guard.read_bytes(source_path)
        actual_sha256 = hashlib.sha256(content).hexdigest()
        if actual_sha256 != lock_input.sha256:
            raise ApplianceError(
                CP_LOCK_DIGEST_MISMATCH,
                f"{lock_input.id}: source content digest {actual_sha256} does not match locked {lock_input.sha256}",
            )
        with open(dest, "wb") as handle:
            handle.write(content)

        actual_xattr_names = sorted(name for name in os.listxattr(source_path) if name in ALLOWED_XATTRS)
        validate_xattr_names(source_path, sorted(os.listxattr(source_path)))
        if set(actual_xattr_names) != set(placement.xattrs):
            raise ApplianceError(
                CP_TREE_XATTR,
                f"{lock_input.id}: source xattrs {actual_xattr_names} do not match declared {list(placement.xattrs)}",
            )
        for name in placement.xattrs:
            os.setxattr(dest, name, os.getxattr(source_path, name))
        return

    if placement.node_type == "symlink":
        validate_symlink_target(placement.path, placement.target or "")
        os.symlink(placement.target, dest)
        return

    raise ApplianceError(CP_TREE_UNEXPECTED, f"unsupported placement node_type: {placement.node_type!r}")


def _pseudo_line(placement: Placement) -> str:
    mode_octal = format(placement.mode, "04o")
    return f"{placement.path} m {mode_octal} {placement.uid} {placement.gid}"


def _reject_undeclared_directories(staging_root: str, declared_dirs: set[str]) -> None:
    """Fail loud if directory assembly implicitly created an undeclared path.

    Every intermediate directory must have its own explicit placement so
    its mode/uid/gid can be forced deterministically; otherwise mksquashfs
    would bake in the ambient (non-reproducible) build user's ownership.
    """

    for root, dirnames, _filenames in os.walk(staging_root):
        for dirname in dirnames:
            absolute = os.path.join(root, dirname)
            image_relative = "/" + os.path.relpath(absolute, staging_root)
            if image_relative not in declared_dirs:
                raise ApplianceError(
                    CP_TREE_UNEXPECTED,
                    f"directory {image_relative!r} was implicitly created but has no declared placement",
                )
