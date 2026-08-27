#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Atomic, lock-addressed, inspect-before-promote, concurrency-safe
promotion of a built staging bundle.

Staging must live on the same filesystem as ``promote_root`` -- the final
step is a single ``os.rename``, which is only atomic within one
filesystem. This is the builder's own concern; the inspector never writes
or promotes anything.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import shutil
from typing import Callable

from conf_proc_reasons import (
    CP_PROMOTE_CONFLICT,
    CP_PROMOTE_INSPECTION,
    CP_PROMOTE_RENAME,
    CP_PROMOTE_SAME_LOCK_CONTENT_DISAGREEMENT,
    ApplianceError,
)


PROMOTED_BUNDLE_FILES = (
    "runtime-policy.squashfs",
    "runtime-policy.verity",
    "models.squashfs",
    "models.verity",
    "appliance.manifest.json",
    "appliance.spdx.json",
)


def promote(
    staging_dir: str,
    promote_root: str,
    lock_digest_hex: str,
    *,
    inspect_fn: Callable[[str], None],
    fault_hook: Callable[[str], None] = lambda phase: None,
) -> str:
    """Promote ``staging_dir`` to ``<promote_root>/promoted/<lock_digest_hex>``.

    ``inspect_fn`` must raise on any inspection failure; its success is a
    hard promotion prerequisite. ``fault_hook`` is a test-only seam: it is
    called by name after each phase and may raise to simulate a crash at
    that exact point, so AC12's "fault injection at each build phase"
    claim can be exercised for real rather than asserted.
    """

    locks_dir = os.path.join(promote_root, ".locks")
    os.makedirs(locks_dir, exist_ok=True)
    lock_path = os.path.join(locks_dir, f"{lock_digest_hex}.lock")

    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            fault_hook("post_lock_acquired")

            try:
                inspect_fn(staging_dir)
            except ApplianceError:
                raise
            except Exception as exc:  # noqa: BLE001 - any inspector failure blocks promotion
                raise ApplianceError(CP_PROMOTE_INSPECTION, f"independent inspection failed: {exc}") from exc
            fault_hook("post_inspection")

            destination = os.path.join(promote_root, "promoted", lock_digest_hex)
            if os.path.isdir(destination):
                if _bundle_digests(destination) == _bundle_digests(staging_dir):
                    fault_hook("pre_idempotent_discard")
                    shutil.rmtree(staging_dir)
                    return destination
                raise ApplianceError(
                    CP_PROMOTE_SAME_LOCK_CONTENT_DISAGREEMENT,
                    f"lock digest {lock_digest_hex} already has a promoted bundle with different content; "
                    "the existing destination is left untouched",
                )

            fault_hook("pre_rename")
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            try:
                os.rename(staging_dir, destination)
            except OSError as exc:
                raise ApplianceError(CP_PROMOTE_RENAME, f"atomic rename to {destination!r} failed: {exc}") from exc
            fault_hook("post_rename")
            return destination
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _bundle_digests(directory: str) -> dict[str, str]:
    digests = {}
    for name in PROMOTED_BUNDLE_FILES:
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            raise ApplianceError(CP_PROMOTE_CONFLICT, f"{directory!r} is missing expected bundle file {name!r}")
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        digests[name] = digest.hexdigest()
    return digests
