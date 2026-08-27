#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent inspector-side tree inventory and comparison.

This module never imports conf_proc_build_tree.py. It parses
`unsquashfs -lln` (numeric-uid/gid metadata listing, no privileged
extraction required) for authoritative mode/uid/gid/type, separately
extracts the image read-only to recover file content and ACL xattrs, and
compares the resulting inventory against the caller's own trusted Lock
placements -- never against the builder's emitted manifest.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass

from conf_proc_guard import HermeticGuard
from conf_proc_lock import Lock
from conf_proc_reasons import (
    CP_SQUASHFS_EXTRACT,
    CP_TREE_METADATA,
    CP_TREE_MISSING,
    CP_TREE_SOURCE_BINDING,
    CP_TREE_SYMLINK,
    CP_TREE_UNEXPECTED,
    CP_TREE_UNSUPPORTED_NODE,
    ApplianceError,
)
from conf_proc_tree_rules import (
    ALLOWED_XATTRS,
    NODE_TYPE_DIRECTORY,
    NODE_TYPE_FILE,
    NODE_TYPE_SYMLINK,
    validate_node_metadata,
    validate_symlink_target,
    validate_xattr_names,
)


_LISTING_LINE = re.compile(
    r"^(?P<perm>[a-z-]{10})\s+(?P<uid>\d+)/(?P<gid>\d+)\s+(?P<size>\d+)\s+\S+\s+\S+\s+(?P<rest>.+)$"
)
_ROOT_ENTRY_NAME = "squashfs-root"


@dataclass(frozen=True)
class InventoryNode:
    path: str
    node_type: str
    mode: int
    uid: int
    gid: int
    size: int
    xattrs: tuple[str, ...]
    sha256: str | None
    symlink_target: str | None


def build_inventory(
    guard: HermeticGuard,
    *,
    unsquashfs_path: str,
    squashfs_path: str,
    extract_dir: str,
    work_dir: str,
) -> dict[str, InventoryNode]:
    """Independently list and extract an image, returning its inventory."""

    listing = guard.run_tool([unsquashfs_path, "-lln", squashfs_path], cwd=work_dir)
    entries = _parse_listing(listing.stdout.decode("utf-8"))

    try:
        guard.run_tool(
            [unsquashfs_path, "-quiet", "-no-progress", "-d", extract_dir, "-f", squashfs_path],
            cwd=work_dir,
        )
    except ApplianceError as exc:
        raise ApplianceError(CP_SQUASHFS_EXTRACT, f"failed to extract {squashfs_path!r}: {exc}") from exc

    inventory: dict[str, InventoryNode] = {}
    for path, mode, uid, gid, size, symlink_target in entries:
        if path == "/":
            continue
        node_type = _classify(path, mode)
        # unsquashfs -lln does not report a link count, so hard-link
        # rejection cannot be independently re-derived from the packed
        # image alone; nlink=1 makes this check a deliberate no-op here.
        # It is still enforced when the builder ingests the original
        # source tree (conf_proc_build_tree.py).
        validate_node_metadata(path, mode=mode, node_type=node_type, nlink=1)

        extracted_path = os.path.join(extract_dir, path.lstrip("/"))
        xattrs: tuple[str, ...] = ()
        sha256: str | None = None
        if node_type in (NODE_TYPE_FILE, NODE_TYPE_DIRECTORY):
            xattr_names = sorted(os.listxattr(extracted_path))
            validate_xattr_names(path, xattr_names)
            xattrs = tuple(name for name in xattr_names if name in ALLOWED_XATTRS)
            if node_type == NODE_TYPE_FILE:
                sha256 = _sha256_file(extracted_path)
        elif node_type == NODE_TYPE_SYMLINK:
            validate_symlink_target(path, symlink_target or "")

        inventory[path] = InventoryNode(
            path=path,
            node_type=node_type,
            mode=mode & 0o7777,
            uid=uid,
            gid=gid,
            size=size,
            xattrs=xattrs,
            sha256=sha256,
            symlink_target=symlink_target,
        )
    return inventory


def compare_against_lock(inventory: dict[str, InventoryNode], lock: Lock, *, image: str) -> None:
    """Fail loud on any divergence between the inventory and the trusted lock."""

    declared: dict[str, tuple[object, object]] = {}
    for lock_input in lock.inputs:
        for placement in lock_input.placements:
            if placement.image == image:
                declared[placement.path] = (lock_input, placement)

    for path in inventory:
        if path not in declared:
            raise ApplianceError(CP_TREE_UNEXPECTED, f"{path}: present in built image but not declared in the lock")

    for path, (lock_input, placement) in declared.items():
        if path not in inventory:
            raise ApplianceError(CP_TREE_MISSING, f"{path}: declared in the lock but missing from the built image")
        node = inventory[path]

        if node.node_type != placement.node_type:
            raise ApplianceError(
                CP_TREE_UNSUPPORTED_NODE,
                f"{path}: built node_type {node.node_type!r} does not match declared {placement.node_type!r}",
            )
        if node.mode != placement.mode or node.uid != placement.uid or node.gid != placement.gid:
            raise ApplianceError(
                CP_TREE_METADATA,
                f"{path}: built mode/uid/gid ({oct(node.mode)}/{node.uid}/{node.gid}) does not match declared "
                f"({oct(placement.mode)}/{placement.uid}/{placement.gid})",
            )
        if set(node.xattrs) != set(placement.xattrs):
            raise ApplianceError(CP_TREE_METADATA, f"{path}: built xattrs {node.xattrs} do not match declared {placement.xattrs}")

        if placement.node_type == "file":
            if node.sha256 != lock_input.sha256:
                raise ApplianceError(
                    CP_TREE_SOURCE_BINDING,
                    f"{path}: built content digest {node.sha256} does not match locked {lock_input.sha256} for input {lock_input.id}",
                )
        elif placement.node_type == "symlink":
            if node.symlink_target != placement.target:
                raise ApplianceError(
                    CP_TREE_SYMLINK,
                    f"{path}: built symlink target {node.symlink_target!r} does not match declared {placement.target!r}",
                )


def _classify(path: str, mode: int) -> str:
    if stat.S_ISREG(mode):
        return NODE_TYPE_FILE
    if stat.S_ISDIR(mode):
        return NODE_TYPE_DIRECTORY
    if stat.S_ISLNK(mode):
        return NODE_TYPE_SYMLINK
    raise ApplianceError(CP_TREE_UNSUPPORTED_NODE, f"{path}: unsupported filesystem node type (mode={oct(mode)})")


def _parse_listing(stdout: str) -> list[tuple[str, int, int, int, int, str | None]]:
    entries: list[tuple[str, int, int, int, int, str | None]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        match = _LISTING_LINE.match(line)
        if not match:
            continue
        perm = match.group("perm")
        uid = int(match.group("uid"))
        gid = int(match.group("gid"))
        size = int(match.group("size"))
        rest = match.group("rest")

        symlink_target: str | None = None
        if " -> " in rest:
            rest, symlink_target = rest.split(" -> ", 1)

        if rest == _ROOT_ENTRY_NAME:
            path = "/"
        elif rest.startswith(_ROOT_ENTRY_NAME + "/"):
            path = "/" + rest[len(_ROOT_ENTRY_NAME) + 1 :]
        else:
            continue

        mode = _parse_permission_string(perm)
        entries.append((path, mode, uid, gid, size, symlink_target))
    return entries


_TYPE_CHAR_TO_STAT_BIT = {
    "d": stat.S_IFDIR,
    "-": stat.S_IFREG,
    "l": stat.S_IFLNK,
    "b": stat.S_IFBLK,
    "c": stat.S_IFCHR,
    "p": stat.S_IFIFO,
    "s": stat.S_IFSOCK,
}

_PERMISSION_POSITIONS = (
    (stat.S_IRUSR, "r"),
    (stat.S_IWUSR, "w"),
    (stat.S_IXUSR, "x"),
    (stat.S_IRGRP, "r"),
    (stat.S_IWGRP, "w"),
    (stat.S_IXGRP, "x"),
    (stat.S_IROTH, "r"),
    (stat.S_IWOTH, "w"),
    (stat.S_IXOTH, "x"),
)


def _parse_permission_string(perm: str) -> int:
    type_bit = _TYPE_CHAR_TO_STAT_BIT.get(perm[0])
    if type_bit is None:
        raise ApplianceError(CP_TREE_UNSUPPORTED_NODE, f"unrecognized node type character {perm[0]!r}")
    mode = type_bit
    for index, (bit, char) in enumerate(_PERMISSION_POSITIONS):
        actual = perm[1 + index]
        if actual == char:
            mode |= bit
        elif index == 2 and actual in ("s", "S"):
            mode |= stat.S_ISUID
            if actual == "s":
                mode |= stat.S_IXUSR
        elif index == 5 and actual in ("s", "S"):
            mode |= stat.S_ISGID
            if actual == "s":
                mode |= stat.S_IXGRP
        elif index == 8 and actual in ("t", "T"):
            mode |= stat.S_ISVTX
            if actual == "t":
                mode |= stat.S_IXOTH
    return mode


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
