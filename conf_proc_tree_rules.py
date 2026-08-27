#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Pure filesystem node metadata rules shared by builder and inspector.

These are generic predicates over already-obtained metadata (a stat mode
integer, a link count, an xattr name set, a symlink target string) -- not
tree-walking or inventory logic. Testable with fabricated values, so
device/socket/FIFO rejection can be exercised without ever creating a real
privileged special file on a rootless host.
"""

from __future__ import annotations

import stat
from typing import Final

from conf_proc_reasons import (
    CP_TREE_METADATA,
    CP_TREE_SYMLINK,
    CP_TREE_UNSUPPORTED_NODE,
    CP_TREE_XATTR,
    ApplianceError,
)


NODE_TYPE_FILE: Final = "file"
NODE_TYPE_DIRECTORY: Final = "directory"
NODE_TYPE_SYMLINK: Final = "symlink"

ALLOWED_XATTRS: Final = ("system.posix_acl_access", "system.posix_acl_default")
FORBIDDEN_CAPABILITY_XATTR: Final = "security.capability"


def classify_node_type(mode: int) -> str:
    """Map a stat mode integer to one of our three supported node types."""

    if stat.S_ISREG(mode):
        return NODE_TYPE_FILE
    if stat.S_ISDIR(mode):
        return NODE_TYPE_DIRECTORY
    if stat.S_ISLNK(mode):
        return NODE_TYPE_SYMLINK
    kind = (
        "a device node"
        if stat.S_ISBLK(mode) or stat.S_ISCHR(mode)
        else "a FIFO"
        if stat.S_ISFIFO(mode)
        else "a socket"
        if stat.S_ISSOCK(mode)
        else "an unrecognized node"
    )
    raise ApplianceError(CP_TREE_UNSUPPORTED_NODE, f"{kind} is not a supported filesystem node type (mode={oct(mode)})")


def validate_node_metadata(path: str, *, mode: int, node_type: str, nlink: int) -> None:
    """Reject setuid/setgid bits and hard links."""

    if mode & (stat.S_ISUID | stat.S_ISGID):
        raise ApplianceError(CP_TREE_METADATA, f"{path}: setuid/setgid bits are forbidden")
    if node_type != NODE_TYPE_DIRECTORY and nlink != 1:
        raise ApplianceError(CP_TREE_UNSUPPORTED_NODE, f"{path}: hard links are forbidden (nlink={nlink})")


def validate_xattr_names(path: str, xattr_names: list[str]) -> None:
    """Reject file capabilities and any xattr outside the ACL allowlist."""

    for name in xattr_names:
        if name == FORBIDDEN_CAPABILITY_XATTR:
            raise ApplianceError(CP_TREE_XATTR, f"{path}: file capabilities are forbidden")
        if name not in ALLOWED_XATTRS:
            raise ApplianceError(CP_TREE_XATTR, f"{path}: undeclared xattr {name!r}")


def validate_symlink_target(path: str, target: str) -> None:
    """Reject empty targets and any .. path segment."""

    if not target:
        raise ApplianceError(CP_TREE_SYMLINK, f"{path}: symlink target must not be empty")
    if any(segment == ".." for segment in target.split("/")):
        raise ApplianceError(CP_TREE_SYMLINK, f"{path}: symlink target must not contain a .. segment")


def permission_bits(mode: int) -> int:
    """The low 12 bits (including setuid/setgid/sticky) of a stat mode."""

    return mode & 0o7777
