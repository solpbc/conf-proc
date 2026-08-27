#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""In-process hermeticity choke point for the conf-proc appliance builder.

Every file read, tool invocation, and environment value the builder uses
must go through :class:`HermeticGuard`. This is real, testable enforcement
of the builder's own reads and subprocess construction -- it is not an OS
sandbox and cannot constrain undocumented reads inside a third-party tool
binary's own implementation.
"""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from conf_proc_reasons import (
    CP_HERMETIC_CLOCK,
    CP_HERMETIC_ENV,
    CP_HERMETIC_NETWORK,
    CP_HERMETIC_PATH_ESCAPE,
    CP_HERMETIC_UNLISTED_READ,
    CP_HERMETIC_UNLISTED_SUBPROCESS,
    CP_TOOL_DIGEST_MISMATCH,
    CP_TOOL_INVOCATION_FAILED,
    CP_TOOL_MISSING,
    ApplianceError,
)


ALLOWED_ENV_KEYS: frozenset[str] = frozenset({"PATH", "LC_ALL", "LANG", "TZ", "HOME"})


@dataclass(frozen=True)
class ToolDeclaration:
    """A single build-tool binary the guard is permitted to invoke."""

    absolute_path: str
    sha256: str


class HermeticGuard:
    """Chokepoint for every file read and subprocess call the builder makes."""

    def __init__(
        self,
        *,
        allowed_reads: frozenset[str],
        tools: dict[str, ToolDeclaration],
        env: dict[str, str],
        build_epoch: int,
    ) -> None:
        for key in env:
            if key not in ALLOWED_ENV_KEYS:
                raise ApplianceError(CP_HERMETIC_ENV, f"env key is not allowlisted: {key!r}")
        for name, declaration in tools.items():
            if not os.path.isabs(declaration.absolute_path):
                raise ApplianceError(CP_HERMETIC_PATH_ESCAPE, f"declared tool path is not absolute: {declaration.absolute_path!r}")
        self._allowed_reads = frozenset(os.path.realpath(path) for path in allowed_reads)
        self._tools = dict(tools)
        self._env = dict(env)
        self._build_epoch = build_epoch

    @property
    def build_epoch(self) -> int:
        return self._build_epoch

    @property
    def env(self) -> dict[str, str]:
        return dict(self._env)

    def read_bytes(self, path: str) -> bytes:
        """Read a file, failing loud if it was never declared as an input."""

        real_path = os.path.realpath(path)
        if real_path not in self._allowed_reads:
            raise ApplianceError(CP_HERMETIC_UNLISTED_READ, f"undeclared host read: {path!r}")
        with open(real_path, "rb") as handle:
            return handle.read()

    def resolve_tool(self, argv0: str) -> str:
        """Resolve and digest-verify a declared build tool absolute path."""

        if not os.path.isabs(argv0):
            raise ApplianceError(CP_HERMETIC_PATH_ESCAPE, f"tool invocation must use an absolute path: {argv0!r}")
        declaration = self._tools.get(argv0)
        if declaration is None:
            raise ApplianceError(CP_HERMETIC_UNLISTED_SUBPROCESS, f"undeclared tool invocation: {argv0!r}")
        if not os.path.isfile(declaration.absolute_path):
            raise ApplianceError(CP_TOOL_MISSING, f"declared tool is missing on disk: {declaration.absolute_path!r}")
        actual_sha256 = hashlib.sha256(self.read_bytes(declaration.absolute_path)).hexdigest()
        if actual_sha256 != declaration.sha256:
            raise ApplianceError(
                CP_TOOL_DIGEST_MISMATCH,
                f"tool {argv0!r} digest {actual_sha256} does not match declared {declaration.sha256}",
            )
        return declaration.absolute_path

    def run_tool(
        self,
        argv: list[str],
        *,
        cwd: str,
        input: bytes | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Invoke a declared tool with the guard's fixed, allowlisted environment."""

        if not argv:
            raise ApplianceError(CP_HERMETIC_UNLISTED_SUBPROCESS, "empty argv")
        self.resolve_tool(argv[0])
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=self._env,
            input=input,
            capture_output=True,
            check=False,
        )
        if check and result.returncode != 0:
            raise ApplianceError(
                CP_TOOL_INVOCATION_FAILED,
                f"{argv!r} exited {result.returncode}: {result.stderr.decode('utf-8', 'replace')}",
            )
        return result

    def allowed_reads(self) -> frozenset[str]:
        return self._allowed_reads


@contextmanager
def hermetic_lockdown() -> Iterator[None]:
    """Patch nondeterministic and network-capable stdlib entry points.

    Any code inside this context that calls ``time.time``/``time.time_ns``
    or constructs a ``socket.socket`` raises ``ApplianceError`` immediately,
    before it can influence build output. This is defensive, in-process
    enforcement, not OS-level containment.
    """

    original_time = time.time
    original_time_ns = time.time_ns
    original_socket = socket.socket

    def _blocked_time() -> float:
        raise ApplianceError(CP_HERMETIC_CLOCK, "wall-clock read is not hermetic; use the derived build epoch")

    def _blocked_time_ns() -> int:
        raise ApplianceError(CP_HERMETIC_CLOCK, "wall-clock read is not hermetic; use the derived build epoch")

    def _blocked_socket(*args: object, **kwargs: object) -> socket.socket:
        raise ApplianceError(CP_HERMETIC_NETWORK, "network socket construction is not hermetic")

    time.time = _blocked_time  # type: ignore[assignment]
    time.time_ns = _blocked_time_ns  # type: ignore[assignment]
    socket.socket = _blocked_socket  # type: ignore[assignment]
    try:
        yield
    finally:
        time.time = original_time  # type: ignore[assignment]
        time.time_ns = original_time_ns  # type: ignore[assignment]
        socket.socket = original_socket  # type: ignore[assignment]
