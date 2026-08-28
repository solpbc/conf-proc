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
import stat
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterable, Iterator

from conf_proc_reasons import (
    CP_HERMETIC_CLOCK,
    CP_HERMETIC_ENV,
    CP_HERMETIC_NETWORK,
    CP_HERMETIC_PATH_ESCAPE,
    CP_HERMETIC_UNLISTED_READ,
    CP_HERMETIC_UNLISTED_SUBPROCESS,
    CP_PROVENANCE_INPUT_CHANGED,
    CP_TOOL_DIGEST_MISMATCH,
    CP_TOOL_INVOCATION_FAILED,
    CP_TOOL_MISSING,
    CP_TOOL_PIN_CHANGED,
    CP_TOOL_PIN_UNAVAILABLE,
    ApplianceError,
)


ALLOWED_ENV_KEYS: frozenset[str] = frozenset({"PATH", "LC_ALL", "LANG", "TZ", "HOME"})


@dataclass(frozen=True)
class ToolDeclaration:
    """A single build-tool binary the guard is permitted to invoke."""

    absolute_path: str
    sha256: str


@dataclass(frozen=True)
class _PinnedTool:
    descriptor: int
    identity: tuple[int, int, int, int, int]
    sha256: str


@dataclass(frozen=True)
class _PinnedRead:
    descriptor: int
    identity: tuple[int, int, int, int, int]
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
        self._pinned_tools: dict[str, _PinnedTool] = {}
        self._pinned_reads: dict[str, _PinnedRead] = {}

    @property
    def build_epoch(self) -> int:
        return self._build_epoch

    @property
    def env(self) -> dict[str, str]:
        return dict(self._env)

    def read_bytes(self, path: str) -> bytes:
        """Read a file, failing loud if it was never declared as an input."""

        pinned = self._pinned_reads.get(os.path.abspath(path))
        if pinned is not None:
            return _read_fd(pinned.descriptor)
        real_path = os.path.realpath(path)
        if real_path not in self._allowed_reads:
            raise ApplianceError(CP_HERMETIC_UNLISTED_READ, f"undeclared host read: {path!r}")
        with open(real_path, "rb") as handle:
            return handle.read()

    def stat_read(self, path: str) -> os.stat_result:
        """Return metadata for a declared read, anchored to its pinned inode."""

        pinned = self._pinned_reads.get(os.path.abspath(path))
        if pinned is not None:
            return os.fstat(pinned.descriptor)
        real_path = self._declared_read_path(path)
        return os.stat(real_path, follow_symlinks=False)

    def listxattr_read(self, path: str) -> list[str]:
        """List xattrs for a declared read, anchored to its pinned inode."""

        pinned = self._pinned_reads.get(os.path.abspath(path))
        if pinned is not None:
            return os.listxattr(pinned.descriptor)
        return os.listxattr(self._declared_read_path(path))

    def getxattr_read(self, path: str, name: str) -> bytes:
        """Read an xattr for a declared read, anchored to its pinned inode."""

        pinned = self._pinned_reads.get(os.path.abspath(path))
        if pinned is not None:
            return os.getxattr(pinned.descriptor, name)
        return os.getxattr(self._declared_read_path(path), name)

    def pinned_path(self, path: str) -> str:
        """Return the procfs path for a currently pinned declared read."""

        pinned = self._pinned_reads.get(os.path.abspath(path))
        if pinned is None:
            raise ApplianceError(CP_PROVENANCE_INPUT_CHANGED, "declared read is not pinned")
        return f"/proc/self/fd/{pinned.descriptor}"

    def _declared_read_path(self, path: str) -> str:
        real_path = os.path.realpath(path)
        if real_path not in self._allowed_reads:
            raise ApplianceError(CP_HERMETIC_UNLISTED_READ, f"undeclared host read: {path!r}")
        return real_path

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
        pass_fds: tuple[int, ...] = (),
    ) -> subprocess.CompletedProcess:
        """Invoke a declared tool with the guard's fixed, allowlisted environment."""

        if not argv:
            raise ApplianceError(CP_HERMETIC_UNLISTED_SUBPROCESS, "empty argv")
        pinned = self._pinned_tools.get(argv[0])
        inherited_fds = tuple(dict.fromkeys((*pass_fds, *(item.descriptor for item in self._pinned_reads.values()))))
        if pinned is None:
            self.resolve_tool(argv[0])
            result = subprocess.run(
                argv,
                cwd=cwd,
                env=self._env,
                input=input,
                capture_output=True,
                check=False,
                pass_fds=inherited_fds,
            )
        else:
            try:
                result = subprocess.run(
                    [f"/proc/self/fd/{pinned.descriptor}", *argv[1:]],
                    cwd=cwd,
                    env=self._env,
                    input=input,
                    capture_output=True,
                    check=False,
                    pass_fds=tuple(dict.fromkeys((pinned.descriptor, *inherited_fds))),
                )
            except OSError as exc:
                raise ApplianceError(CP_TOOL_PIN_UNAVAILABLE, "could not execute the pinned tool inode") from exc
        if check and result.returncode != 0:
            raise ApplianceError(
                CP_TOOL_INVOCATION_FAILED,
                f"{argv!r} exited {result.returncode}: {result.stderr.decode('utf-8', 'replace')}",
            )
        return result

    def allowed_reads(self) -> frozenset[str]:
        return self._allowed_reads

    @contextmanager
    def pin_reads(self, absolute_paths: Iterable[str]) -> Iterator[None]:
        """Read selected declared inputs only from validated open inodes."""

        paths = tuple(os.path.abspath(path) for path in absolute_paths)
        if not paths or len(paths) != len(set(paths)):
            raise ApplianceError(CP_PROVENANCE_INPUT_CHANGED, "pinned read paths must be a non-empty unique set")
        if self._pinned_reads:
            raise ApplianceError(CP_PROVENANCE_INPUT_CHANGED, "nested pinned read contexts are unsupported")

        pinned: dict[str, _PinnedRead] = {}
        try:
            for path in paths:
                if os.path.realpath(path) not in self._allowed_reads:
                    raise ApplianceError(CP_HERMETIC_UNLISTED_READ, f"undeclared host read: {path!r}")
                try:
                    descriptor = _open_nofollow_regular(path)
                except OSError as exc:
                    raise ApplianceError(CP_PROVENANCE_INPUT_CHANGED, "could not pin declared read") from exc
                try:
                    before = os.fstat(descriptor)
                    if not stat.S_ISREG(before.st_mode):
                        raise ApplianceError(CP_PROVENANCE_INPUT_CHANGED, "declared read is not a regular file")
                    pinned[path] = _PinnedRead(
                        descriptor=descriptor,
                        identity=_stat_identity(before),
                        sha256=_sha256_fd(descriptor),
                    )
                except Exception:
                    os.close(descriptor)
                    raise

            self._pinned_reads = pinned
            yield
        finally:
            self._pinned_reads = {}
            pin_error: ApplianceError | None = None
            for path, pinned_read in pinned.items():
                try:
                    after = os.fstat(pinned_read.descriptor)
                    current_descriptor = _open_nofollow_regular(path)
                    try:
                        current = os.fstat(current_descriptor)
                        if (
                            _stat_identity(after) != pinned_read.identity
                            or _sha256_fd(pinned_read.descriptor) != pinned_read.sha256
                            or (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino)
                        ):
                            pin_error = ApplianceError(CP_PROVENANCE_INPUT_CHANGED, "pinned declared read changed during assembly")
                    finally:
                        os.close(current_descriptor)
                except OSError as exc:
                    pin_error = ApplianceError(CP_PROVENANCE_INPUT_CHANGED, "could not recheck pinned declared read")
                    pin_error.__cause__ = exc
                finally:
                    os.close(pinned_read.descriptor)
            if pin_error is not None:
                raise pin_error

    @contextmanager
    def pin_tools(self, absolute_paths: Iterable[str]) -> Iterator[None]:
        """Execute selected declared tools from their validated open inodes.

        This is opt-in and leaves the ordinary resolve-then-exec behavior of
        :meth:`run_tool` unchanged outside the context.  Each selected path is
        opened and verified exactly once, then rechecked on the same descriptor
        before it is closed.
        """

        paths = tuple(absolute_paths)
        if not paths or len(paths) != len(set(paths)):
            raise ApplianceError(CP_TOOL_PIN_UNAVAILABLE, "pinned tool paths must be a non-empty unique set")
        if self._pinned_tools:
            raise ApplianceError(CP_TOOL_PIN_UNAVAILABLE, "nested pinned tool contexts are unsupported")

        pinned: dict[str, _PinnedTool] = {}
        try:
            for path in paths:
                declaration = self._tools.get(path)
                if declaration is None or not os.path.isabs(path):
                    raise ApplianceError(CP_TOOL_PIN_UNAVAILABLE, "pinned tool is not a declared absolute path")
                try:
                    descriptor = _open_nofollow_regular(path)
                except OSError as exc:
                    raise ApplianceError(CP_TOOL_PIN_UNAVAILABLE, "could not open declared tool without following links") from exc
                try:
                    before = os.fstat(descriptor)
                    if not stat.S_ISREG(before.st_mode):
                        raise ApplianceError(CP_TOOL_PIN_UNAVAILABLE, "declared tool is not a regular file")
                    digest = _sha256_fd(descriptor)
                    if digest != declaration.sha256:
                        raise ApplianceError(CP_TOOL_PIN_CHANGED, "pinned tool digest does not match its declaration")
                    pinned[path] = _PinnedTool(
                        descriptor=descriptor,
                        identity=_stat_identity(before),
                        sha256=digest,
                    )
                except OSError as exc:
                    os.close(descriptor)
                    raise ApplianceError(CP_TOOL_PIN_UNAVAILABLE, "could not validate pinned tool inode") from exc
                except Exception:
                    os.close(descriptor)
                    raise

            self._pinned_tools = pinned
            yield
        finally:
            self._pinned_tools = {}
            pin_error: ApplianceError | None = None
            for pinned_tool in pinned.values():
                try:
                    after = os.fstat(pinned_tool.descriptor)
                    if _stat_identity(after) != pinned_tool.identity or _sha256_fd(pinned_tool.descriptor) != pinned_tool.sha256:
                        pin_error = ApplianceError(CP_TOOL_PIN_CHANGED, "pinned tool changed during its pin lifetime")
                except OSError as exc:
                    pin_error = ApplianceError(CP_TOOL_PIN_CHANGED, "could not recheck pinned tool")
                    pin_error.__cause__ = exc
                finally:
                    os.close(pinned_tool.descriptor)
            if pin_error is not None:
                raise pin_error


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _sha256_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _read_fd(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks)


def _open_nofollow_regular(path: str) -> int:
    """Open an absolute regular file without following any path symlink."""

    absolute = os.path.abspath(path)
    components = [component for component in absolute.split(os.sep) if component]
    if not components:
        raise OSError("path has no leaf")
    parent = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in components[:-1]:
            next_parent = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            os.close(parent)
            parent = next_parent
        return os.open(
            components[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    finally:
        os.close(parent)


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
