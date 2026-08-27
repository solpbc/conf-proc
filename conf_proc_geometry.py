#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Pure, lock-digest-derived determinism formulas shared by builder and
inspector.

These are generic byte-derivation functions, not appliance inventory or
canonicalization logic, so both sides may share them (see AC7): the
inspector must independently re-derive the same values from the same
trusted lock digest, not read them from the builder's emitted manifest.
"""

from __future__ import annotations

import calendar
import hashlib
import uuid
from typing import Final


VERITY_DATA_BLOCK_SIZE: Final = 4096
VERITY_HASH_BLOCK_SIZE: Final = 4096
VERITY_HASH_ALGORITHM: Final = "sha256"
SQUASHFS_COMPRESSION: Final = "gzip"

_BUILD_EPOCH_DOMAIN: Final = b"conf-proc/build-clock/v1"
_VERITY_SALT_DOMAIN: Final = b"conf-proc/verity-salt/v1"
_VERITY_UUID_DOMAIN: Final = b"conf-proc/verity-uuid/v1"

_EPOCH_RANGE_START: Final = calendar.timegm((2000, 1, 1, 0, 0, 0))
_EPOCH_RANGE_END: Final = calendar.timegm((2099, 12, 31, 23, 59, 59))


def derive_build_epoch(lock_digest: bytes) -> int:
    """Deterministic UTC epoch seconds derived from the lock digest."""

    digest = hashlib.sha256(_BUILD_EPOCH_DOMAIN + lock_digest).digest()
    offset = int.from_bytes(digest[:8], "big") % (_EPOCH_RANGE_END - _EPOCH_RANGE_START)
    return _EPOCH_RANGE_START + offset


def derive_verity_salt(lock_digest: bytes, image_id: str) -> str:
    """Deterministic 32-byte (64 hex character) dm-verity salt."""

    return hashlib.sha256(_VERITY_SALT_DOMAIN + image_id.encode("ascii") + lock_digest).hexdigest()


def derive_verity_uuid(lock_digest: bytes, image_id: str) -> str:
    """Deterministic RFC 4122 version-5-shaped UUID string for dm-verity."""

    digest = bytearray(hashlib.sha256(_VERITY_UUID_DOMAIN + image_id.encode("ascii") + lock_digest).digest()[:16])
    digest[6] = (digest[6] & 0x0F) | 0x50
    digest[8] = (digest[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(digest)))


def padded_size(actual_size: int, block_size: int = VERITY_DATA_BLOCK_SIZE) -> int:
    """Size after deterministic zero-padding to a whole block boundary."""

    remainder = actual_size % block_size
    if remainder == 0:
        return actual_size
    return actual_size + (block_size - remainder)


def pad_file_to_block_size(path: str, block_size: int = VERITY_DATA_BLOCK_SIZE) -> int:
    """Zero-pad a file in place to a whole block boundary; return final size."""

    with open(path, "ab") as handle:
        current_size = handle.tell()
        target_size = padded_size(current_size, block_size)
        if target_size != current_size:
            handle.write(b"\x00" * (target_size - current_size))
        return target_size
