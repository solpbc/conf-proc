#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Stable public failures for SPP diagnostic trace-core materialization."""

from __future__ import annotations

from typing import Final


CP_SPP_DIAG_TRACE_CORE_SCHEMA: Final = "CP_SPP_DIAG_TRACE_CORE_SCHEMA"
CP_SPP_DIAG_TRACE_CORE_TYPE: Final = "CP_SPP_DIAG_TRACE_CORE_TYPE"
CP_SPP_DIAG_TRACE_CORE_WORKTREE: Final = "CP_SPP_DIAG_TRACE_CORE_WORKTREE"
CP_SPP_DIAG_TRACE_CORE_BASE_COMMIT: Final = "CP_SPP_DIAG_TRACE_CORE_BASE_COMMIT"
CP_SPP_DIAG_TRACE_CORE_GIT_PROBE: Final = "CP_SPP_DIAG_TRACE_CORE_GIT_PROBE"
CP_SPP_DIAG_TRACE_CORE_DIRTY_STAGED: Final = "CP_SPP_DIAG_TRACE_CORE_DIRTY_STAGED"
CP_SPP_DIAG_TRACE_CORE_DIRTY_UNSTAGED: Final = "CP_SPP_DIAG_TRACE_CORE_DIRTY_UNSTAGED"
CP_SPP_DIAG_TRACE_CORE_DIRTY_UNTRACKED: Final = "CP_SPP_DIAG_TRACE_CORE_DIRTY_UNTRACKED"
CP_SPP_DIAG_TRACE_CORE_SYMLINK: Final = "CP_SPP_DIAG_TRACE_CORE_SYMLINK"
CP_SPP_DIAG_TRACE_CORE_INPUT_MISSING: Final = "CP_SPP_DIAG_TRACE_CORE_INPUT_MISSING"
CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED: Final = "CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED"
CP_SPP_DIAG_TRACE_CORE_INPUT_UNMANIFESTED: Final = "CP_SPP_DIAG_TRACE_CORE_INPUT_UNMANIFESTED"
CP_SPP_DIAG_TRACE_CORE_CREATE_COLLISION: Final = "CP_SPP_DIAG_TRACE_CORE_CREATE_COLLISION"
CP_SPP_DIAG_TRACE_CORE_REPLACE_MISSING: Final = "CP_SPP_DIAG_TRACE_CORE_REPLACE_MISSING"
CP_SPP_DIAG_TRACE_CORE_REPLACE_CHANGED: Final = "CP_SPP_DIAG_TRACE_CORE_REPLACE_CHANGED"
CP_SPP_DIAG_TRACE_CORE_PARTIAL_APPLY: Final = "CP_SPP_DIAG_TRACE_CORE_PARTIAL_APPLY"
CP_SPP_DIAG_TRACE_CORE_PATH_ESCAPE: Final = "CP_SPP_DIAG_TRACE_CORE_PATH_ESCAPE"
CP_SPP_DIAG_TRACE_CORE_STAGING: Final = "CP_SPP_DIAG_TRACE_CORE_STAGING"
CP_SPP_DIAG_TRACE_CORE_GIT_ARGV: Final = "CP_SPP_DIAG_TRACE_CORE_GIT_ARGV"
CP_SPP_DIAG_TRACE_CORE_TOOL: Final = "CP_SPP_DIAG_TRACE_CORE_TOOL"
CP_SPP_DIAG_TRACE_CORE_FORBIDDEN_COMMAND: Final = "CP_SPP_DIAG_TRACE_CORE_FORBIDDEN_COMMAND"
CP_SPP_DIAG_TRACE_CORE_HANDOFF: Final = "CP_SPP_DIAG_TRACE_CORE_HANDOFF"
CP_SPP_DIAG_TRACE_CORE_AUTHORITY: Final = "CP_SPP_DIAG_TRACE_CORE_AUTHORITY"

ALL_SPP_DIAG_TRACE_CORE_MATERIALIZE_REASONS: Final = frozenset(
    {
        CP_SPP_DIAG_TRACE_CORE_SCHEMA,
        CP_SPP_DIAG_TRACE_CORE_TYPE,
        CP_SPP_DIAG_TRACE_CORE_WORKTREE,
        CP_SPP_DIAG_TRACE_CORE_BASE_COMMIT,
        CP_SPP_DIAG_TRACE_CORE_GIT_PROBE,
        CP_SPP_DIAG_TRACE_CORE_DIRTY_STAGED,
        CP_SPP_DIAG_TRACE_CORE_DIRTY_UNSTAGED,
        CP_SPP_DIAG_TRACE_CORE_DIRTY_UNTRACKED,
        CP_SPP_DIAG_TRACE_CORE_SYMLINK,
        CP_SPP_DIAG_TRACE_CORE_INPUT_MISSING,
        CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED,
        CP_SPP_DIAG_TRACE_CORE_INPUT_UNMANIFESTED,
        CP_SPP_DIAG_TRACE_CORE_CREATE_COLLISION,
        CP_SPP_DIAG_TRACE_CORE_REPLACE_MISSING,
        CP_SPP_DIAG_TRACE_CORE_REPLACE_CHANGED,
        CP_SPP_DIAG_TRACE_CORE_PARTIAL_APPLY,
        CP_SPP_DIAG_TRACE_CORE_PATH_ESCAPE,
        CP_SPP_DIAG_TRACE_CORE_STAGING,
        CP_SPP_DIAG_TRACE_CORE_GIT_ARGV,
        CP_SPP_DIAG_TRACE_CORE_TOOL,
        CP_SPP_DIAG_TRACE_CORE_FORBIDDEN_COMMAND,
        CP_SPP_DIAG_TRACE_CORE_HANDOFF,
        CP_SPP_DIAG_TRACE_CORE_AUTHORITY,
    }
)

REASON_RECOVERY: Final = {
    CP_SPP_DIAG_TRACE_CORE_SCHEMA: "fix the manifest so it matches conf-proc-spp-diag-trace-core-manifest/v1",
    CP_SPP_DIAG_TRACE_CORE_TYPE: "pass the required types for worktree, git path, and manifest fields",
    CP_SPP_DIAG_TRACE_CORE_WORKTREE: "point --worktree at an existing directory",
    CP_SPP_DIAG_TRACE_CORE_BASE_COMMIT: "check out the pinned expected_base_commit and retry",
    CP_SPP_DIAG_TRACE_CORE_GIT_PROBE: "retry with a git binary that reports a 40-hex HEAD",
    CP_SPP_DIAG_TRACE_CORE_DIRTY_STAGED: "clear the index (staged changes) and retry",
    CP_SPP_DIAG_TRACE_CORE_DIRTY_UNSTAGED: "restore or commit unstaged worktree changes and retry",
    CP_SPP_DIAG_TRACE_CORE_DIRTY_UNTRACKED: "remove or ignore untracked files and retry",
    CP_SPP_DIAG_TRACE_CORE_SYMLINK: "replace the symlink with a real directory or file and retry",
    CP_SPP_DIAG_TRACE_CORE_INPUT_MISSING: "restore the missing manifested source file",
    CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED: "restore the manifested source bytes to the recorded sha256",
    CP_SPP_DIAG_TRACE_CORE_INPUT_UNMANIFESTED: "remove extra files from the core source directory",
    CP_SPP_DIAG_TRACE_CORE_CREATE_COLLISION: "remove the colliding destination path and retry",
    CP_SPP_DIAG_TRACE_CORE_REPLACE_MISSING: "restore the REPLACE destination file and retry",
    CP_SPP_DIAG_TRACE_CORE_REPLACE_CHANGED: "restore the REPLACE destination to its recorded base mode and sha256",
    CP_SPP_DIAG_TRACE_CORE_PARTIAL_APPLY: "check out a clean base that does not already contain the anchor line",
    CP_SPP_DIAG_TRACE_CORE_PATH_ESCAPE: "keep every destination path inside the worktree",
    CP_SPP_DIAG_TRACE_CORE_STAGING: "retry from a clean worktree after a staging failure",
    CP_SPP_DIAG_TRACE_CORE_GIT_ARGV: "use only the allowlisted git argument templates",
    CP_SPP_DIAG_TRACE_CORE_TOOL: "pin a real git binary whose sha256 matches --git-sha256",
    CP_SPP_DIAG_TRACE_CORE_FORBIDDEN_COMMAND: "remove the forbidden command from the handoff argv",
    CP_SPP_DIAG_TRACE_CORE_HANDOFF: "retry the bounded annotations/olddefconfig/make sequence",
    CP_SPP_DIAG_TRACE_CORE_AUTHORITY: "restore the protocol-authority blobs to the recorded digests",
}


class SppDiagTraceCoreMaterializeError(RuntimeError):
    """A materializer failure with a stable reason and recovery fields."""

    def __init__(
        self,
        reason_code: str,
        message: str,
        *,
        path: str = "",
        expected: str = "",
        observed: str = "",
    ) -> None:
        if reason_code not in ALL_SPP_DIAG_TRACE_CORE_MATERIALIZE_REASONS:
            raise ValueError(f"unknown SPP diagnostic trace-core materialize reason: {reason_code!r}")
        self.reason_code = reason_code
        self.path = path
        self.expected = expected
        self.observed = observed
        self.precondition = message
        self.recovery = REASON_RECOVERY[reason_code]
        super().__init__(
            f"{reason_code}: {message}\n"
            f"precondition: {message}\n"
            f"path: {path}\n"
            f"expected: {expected}\n"
            f"observed: {observed}\n"
            f"recovery: {self.recovery}"
        )
