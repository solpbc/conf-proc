#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Pure POSIX ACL v2 xattr codec for deterministic conf-proc tree metadata."""

from __future__ import annotations

import errno
import os
import struct
from dataclasses import dataclass
from os import PathLike
from typing import Final

from conf_proc_reasons import CP_TREE_ACL, ApplianceError


ACL_VERSION: Final = 2
ACL_USER_OBJ: Final = 0x01
ACL_USER: Final = 0x02
ACL_GROUP_OBJ: Final = 0x04
ACL_GROUP: Final = 0x08
ACL_MASK: Final = 0x10
ACL_OTHER: Final = 0x20
ACL_UNDEFINED_ID: Final = 0xFFFFFFFF
ACL_ACCESS_XATTR: Final = "system.posix_acl_access"
ACL_DEFAULT_XATTR: Final = "system.posix_acl_default"

_ACL_ENTRY_FORMAT: Final = "<HHI"
_ACL_ENTRY_SIZE: Final = struct.calcsize(_ACL_ENTRY_FORMAT)
_ACL_ALLOWED_TAGS: Final = frozenset(
    {ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_MASK, ACL_OTHER}
)


@dataclass(frozen=True)
class AclEntry:
    tag: int
    perm: int
    qualifier: int


def encode_acl(entries: list[AclEntry]) -> bytes:
    """Encode a canonically ordered POSIX ACL v2 xattr payload."""

    _validate_entries(entries)
    encoded = [struct.pack("<I", ACL_VERSION)]
    encoded.extend(struct.pack(_ACL_ENTRY_FORMAT, entry.tag, entry.perm, entry.qualifier) for entry in entries)
    return b"".join(encoded)


def decode_acl(data: bytes) -> list[AclEntry]:
    """Decode and validate a POSIX ACL v2 xattr payload."""

    if type(data) is not bytes or len(data) < 4 or (len(data) - 4) % _ACL_ENTRY_SIZE:
        raise ApplianceError(CP_TREE_ACL, "invalid POSIX ACL xattr length")
    version = struct.unpack("<I", data[:4])[0]
    if version != ACL_VERSION:
        raise ApplianceError(CP_TREE_ACL, f"unsupported POSIX ACL version: {version}")
    entries = [
        AclEntry(*struct.unpack(_ACL_ENTRY_FORMAT, data[offset : offset + _ACL_ENTRY_SIZE]))
        for offset in range(4, len(data), _ACL_ENTRY_SIZE)
    ]
    _validate_entries(entries)
    return entries


def read_acl(path: str | PathLike[str], default: bool = False) -> list[AclEntry] | None:
    """Read an ACL xattr, returning None when this filesystem has none."""

    try:
        data = os.getxattr(path, _xattr_name(default))
    except OSError as exc:
        absent_errors = {errno.ENODATA, errno.ENOTSUP}
        if exc.errno in absent_errors:
            return None
        raise ApplianceError(CP_TREE_ACL, f"could not read POSIX ACL: {exc}") from exc
    return decode_acl(data)


def write_acl(path: str | PathLike[str], entries: list[AclEntry], default: bool = False) -> None:
    """Write an ACL xattr after validating its deterministic representation."""

    if default and not os.path.isdir(path):
        raise ApplianceError(CP_TREE_ACL, "default POSIX ACL requires a directory")
    try:
        os.setxattr(path, _xattr_name(default), encode_acl(entries))
    except OSError as exc:
        raise ApplianceError(CP_TREE_ACL, f"could not write POSIX ACL: {exc}") from exc


def _xattr_name(default: bool) -> str:
    return ACL_DEFAULT_XATTR if default else ACL_ACCESS_XATTR


def _validate_entries(entries: list[AclEntry]) -> None:
    if type(entries) is not list or not entries:
        raise ApplianceError(CP_TREE_ACL, "POSIX ACL must be a non-empty list")
    for entry in entries:
        if type(entry) is not AclEntry:
            raise ApplianceError(CP_TREE_ACL, "POSIX ACL contains an invalid entry")
        if entry.tag not in _ACL_ALLOWED_TAGS:
            raise ApplianceError(CP_TREE_ACL, f"invalid POSIX ACL tag: {entry.tag}")
        if type(entry.perm) is not int or not 0 <= entry.perm <= 0o7:
            raise ApplianceError(CP_TREE_ACL, "POSIX ACL permission must be between 0 and 7")
        if type(entry.qualifier) is not int or not 0 <= entry.qualifier <= ACL_UNDEFINED_ID:
            raise ApplianceError(CP_TREE_ACL, "invalid POSIX ACL qualifier")
        if entry.tag in {ACL_USER, ACL_GROUP}:
            if entry.qualifier == ACL_UNDEFINED_ID:
                raise ApplianceError(CP_TREE_ACL, "named POSIX ACL entry requires a qualifier")
        elif entry.qualifier != ACL_UNDEFINED_ID:
            raise ApplianceError(CP_TREE_ACL, "base POSIX ACL entry requires undefined qualifier")

    position = 0
    if entries[position].tag != ACL_USER_OBJ:
        raise ApplianceError(CP_TREE_ACL, "POSIX ACL must start with USER_OBJ")
    position += 1
    position = _consume_named(entries, position, ACL_USER)
    if position >= len(entries) or entries[position].tag != ACL_GROUP_OBJ:
        raise ApplianceError(CP_TREE_ACL, "POSIX ACL requires GROUP_OBJ after named users")
    position += 1
    named_group_start = position
    position = _consume_named(entries, position, ACL_GROUP)
    has_named_entries = position > 1 or position > named_group_start
    if position < len(entries) and entries[position].tag == ACL_MASK:
        position += 1
    elif has_named_entries:
        raise ApplianceError(CP_TREE_ACL, "extended POSIX ACL requires MASK")
    if position != len(entries) - 1 or entries[position].tag != ACL_OTHER:
        raise ApplianceError(CP_TREE_ACL, "POSIX ACL must end with OTHER")


def _consume_named(entries: list[AclEntry], position: int, tag: int) -> int:
    previous = -1
    while position < len(entries) and entries[position].tag == tag:
        qualifier = entries[position].qualifier
        if qualifier <= previous:
            raise ApplianceError(CP_TREE_ACL, "named POSIX ACL qualifiers must be sorted uniquely")
        previous = qualifier
        position += 1
    return position
