#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Shared, pure construction of a HermeticGuard from a trusted Lock.

Both the builder and inspector CLIs build their own guard from their own
(identically-declared) lock -- this is a deterministic derivation from
already-trusted data, not inventory logic, so it is shared rather than
duplicated.
"""

from __future__ import annotations

import os
from typing import Final

from conf_proc_geometry import derive_build_epoch
from conf_proc_guard import HermeticGuard, ToolDeclaration
from conf_proc_lock import Lock
from conf_proc_reasons import CP_TOOL_MISSING, CP_TOOL_PATH_ESCAPE, ApplianceError


_TOOL_SEARCH_SUBDIRS: Final = ("usr/sbin", "usr/bin", "sbin", "bin")
_FIXED_ENV: Final = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"}


def resolve_tool_absolute_path(tool_root: str, component: str) -> str:
    """Resolve a build tool's real installed path under standard bin dirs."""

    if not component or "/" in component or component in (".", ".."):
        raise ApplianceError(CP_TOOL_PATH_ESCAPE, f"build tool component must be a bare executable name, got {component!r}")
    for subdir in _TOOL_SEARCH_SUBDIRS:
        candidate = os.path.join(tool_root, subdir, component)
        if os.path.isfile(candidate):
            return candidate
    raise ApplianceError(CP_TOOL_MISSING, f"could not resolve build tool {component!r} under tool root {tool_root!r}")


def build_guard(lock: Lock, lock_digest: bytes, *, input_root: str, tool_root: str) -> tuple[HermeticGuard, dict[str, str]]:
    """Build the guard and a component->absolute-path map for build tools."""

    allowed_reads: set[str] = set()
    tools: dict[str, ToolDeclaration] = {}
    tool_paths: dict[str, str] = {}

    for lock_input in lock.inputs:
        if lock_input.role == "build_tool":
            absolute = resolve_tool_absolute_path(tool_root, lock_input.component)
            tools[absolute] = ToolDeclaration(absolute, lock_input.sha256)
            allowed_reads.add(absolute)
            tool_paths[lock_input.component] = absolute
        else:
            allowed_reads.add(os.path.join(input_root, lock_input.source_local_path))

    guard = HermeticGuard(
        allowed_reads=frozenset(allowed_reads),
        tools=tools,
        env=dict(_FIXED_ENV),
        build_epoch=derive_build_epoch(lock_digest),
    )
    return guard, tool_paths
