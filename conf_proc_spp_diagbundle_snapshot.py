#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Root-pinned, no-follow, streamed in-memory snapshot of a directory tree."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import posixpath
import stat
from dataclasses import dataclass
from typing import Iterator

from conf_proc_spp_diagbundle_reasons import (
    CP_DIAGBUNDLE_CONCURRENT_MUTATION,
    CP_DIAGBUNDLE_SNAPSHOT_READ,
    CP_DIAGBUNDLE_SNAPSHOT_SHAPE,
    CP_DIAGBUNDLE_SNAPSHOT_SIZE,
    DiagBundleError,
)


_CHUNK_BYTES = 1024 * 1024
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
_Identity = tuple[int, int, int, int, int, int, int]


@dataclass
class SnapshotBudget:
    max_entries: int
    max_depth: int
    max_file_bytes: int
    max_total_bytes: int
    entries: int = 0
    total_bytes: int = 0

    def consume_entry(self) -> None:
        if self.entries >= self.max_entries:
            raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SIZE, "bundle snapshot exceeds max_entries")
        self.entries += 1

    def consume_bytes(self, n: int) -> None:
        if n < 0 or n > self.max_total_bytes - self.total_bytes:
            raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SIZE, "bundle snapshot exceeds max_total_bytes")
        self.total_bytes += n


@dataclass(frozen=True)
class PinnedFile:
    fd: int
    relative_path: str
    identity: _Identity
    pass1_sha256: str

    def read_all(self) -> bytes:
        chunks = list(_iter_exact(self.fd, self.identity[4], CP_DIAGBUNDLE_SNAPSHOT_READ))
        _require_identity(self.fd, self.identity, CP_DIAGBUNDLE_SNAPSHOT_READ)
        return b"".join(chunks)

    def sha256_all(self) -> str:
        digest = _hash_fd(self.fd, self.identity[4], CP_DIAGBUNDLE_SNAPSHOT_READ)
        _require_identity(self.fd, self.identity, CP_DIAGBUNDLE_SNAPSHOT_READ)
        return digest


@dataclass(frozen=True)
class PinnedDirectory:
    fd: int
    relative_path: str
    identity: _Identity
    child_names: tuple[str, ...]


@dataclass
class BundleSnapshot:
    root: PinnedDirectory
    files: dict[str, PinnedFile]
    directories: dict[str, PinnedDirectory]


@contextlib.contextmanager
def pin_bundle_root(root_path: str, budget: SnapshotBudget) -> Iterator[BundleSnapshot]:
    files: dict[str, PinnedFile] = {}
    directories: dict[str, PinnedDirectory] = {}
    try:
        root_fd = _open_nofollow_directory(root_path)
        owned = False
        try:
            root_stat = os.fstat(root_fd)
            if not stat.S_ISDIR(root_stat.st_mode):
                raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SHAPE, "bundle root is not a directory")
            budget.consume_entry()
            directories[""] = PinnedDirectory(
                fd=root_fd,
                relative_path="",
                identity=_identity(root_stat),
                child_names=_child_names(root_fd),
            )
            owned = True
            _walk_children(directories[""], 0, budget, files, directories)
        finally:
            if not owned:
                _close_quiet(root_fd)
        yield BundleSnapshot(root=directories[""], files=files, directories=directories)
    except DiagBundleError:
        raise
    except OSError as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_READ, "could not pin diagnostic-bundle directory") from exc
    finally:
        _close_all(files, directories)


def read_bounded_file(path: str, max_bytes: int) -> bytes:
    """Read one regular file outside the pinned bundle graph."""

    descriptor = -1
    try:
        descriptor = _open_nofollow_regular(path)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_READ, "bounded file is not a single-link regular file")
        if before.st_size < 0 or before.st_size > max_bytes:
            raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SIZE, "bounded file exceeds its size budget")
        identity = _identity(before)
        chunks = list(_iter_exact(descriptor, before.st_size, CP_DIAGBUNDLE_SNAPSHOT_READ))
        _require_identity(descriptor, identity, CP_DIAGBUNDLE_SNAPSHOT_READ)
        return b"".join(chunks)
    except DiagBundleError:
        raise
    except OSError as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_READ, "could not read bounded file") from exc
    finally:
        if descriptor >= 0:
            _close_quiet(descriptor)


def revalidate(snapshot: BundleSnapshot) -> None:
    try:
        for directory in snapshot.directories.values():
            _require_identity(directory.fd, directory.identity, CP_DIAGBUNDLE_CONCURRENT_MUTATION)
            names = _listdir(directory.fd)
            if set(names) != set(directory.child_names):
                raise DiagBundleError(CP_DIAGBUNDLE_CONCURRENT_MUTATION, "directory members changed")
            for name in names:
                metadata = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                child_path = _join(directory.relative_path, name)
                child = snapshot.files.get(child_path)
                if child is None:
                    child_dir = snapshot.directories.get(child_path)
                    if child_dir is None:
                        raise DiagBundleError(CP_DIAGBUNDLE_CONCURRENT_MUTATION, "directory members changed")
                    child_identity = child_dir.identity
                else:
                    child_identity = child.identity
                if (metadata.st_dev, metadata.st_ino) != (child_identity[0], child_identity[1]):
                    raise DiagBundleError(CP_DIAGBUNDLE_CONCURRENT_MUTATION, "directory member was replaced")
        for pinned in snapshot.files.values():
            _require_identity(pinned.fd, pinned.identity, CP_DIAGBUNDLE_CONCURRENT_MUTATION)
            digest = _hash_fd(pinned.fd, pinned.identity[4], CP_DIAGBUNDLE_CONCURRENT_MUTATION)
            if not hmac.compare_digest(digest, pinned.pass1_sha256):
                raise DiagBundleError(CP_DIAGBUNDLE_CONCURRENT_MUTATION, "pinned file content changed")
            _require_identity(pinned.fd, pinned.identity, CP_DIAGBUNDLE_CONCURRENT_MUTATION)
    except DiagBundleError:
        raise
    except OSError as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_CONCURRENT_MUTATION, "bundle snapshot changed during revalidation") from exc


def _walk_children(
    parent: PinnedDirectory,
    depth: int,
    budget: SnapshotBudget,
    files: dict[str, PinnedFile],
    directories: dict[str, PinnedDirectory],
) -> None:
    for name in parent.child_names:
        metadata = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            _pin_directory(parent, name, depth, budget, files, directories)
        elif stat.S_ISREG(metadata.st_mode):
            _pin_file(parent, name, metadata, budget, files)
        else:
            raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SHAPE, "bundle member is not a regular file or directory")


def _pin_directory(
    parent: PinnedDirectory,
    name: str,
    depth: int,
    budget: SnapshotBudget,
    files: dict[str, PinnedFile],
    directories: dict[str, PinnedDirectory],
) -> None:
    if depth >= budget.max_depth:
        raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SIZE, "bundle snapshot exceeds max_depth")
    budget.consume_entry()
    relative_path = _join(parent.relative_path, name)
    child_fd = os.open(name, _DIR_FLAGS, dir_fd=parent.fd)
    owned = False
    try:
        child_stat = os.fstat(child_fd)
        if not stat.S_ISDIR(child_stat.st_mode):
            raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SHAPE, "bundle member is not a regular file or directory")
        directories[relative_path] = PinnedDirectory(
            fd=child_fd,
            relative_path=relative_path,
            identity=_identity(child_stat),
            child_names=_child_names(child_fd),
        )
        owned = True
        _walk_children(directories[relative_path], depth + 1, budget, files, directories)
    finally:
        if not owned:
            _close_quiet(child_fd)


def _pin_file(
    parent: PinnedDirectory,
    name: str,
    classified: os.stat_result,
    budget: SnapshotBudget,
    files: dict[str, PinnedFile],
) -> None:
    if classified.st_nlink != 1:
        raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SHAPE, "bundle file is hardlinked")
    budget.consume_entry()
    relative_path = _join(parent.relative_path, name)
    child_fd = os.open(name, _FILE_FLAGS, dir_fd=parent.fd)
    owned = False
    try:
        child_stat = os.fstat(child_fd)
        if not stat.S_ISREG(child_stat.st_mode) or child_stat.st_nlink != 1:
            raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SHAPE, "bundle file is not a single-link regular file")
        if child_stat.st_size < 0 or child_stat.st_size > budget.max_file_bytes:
            raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SIZE, "bundle file exceeds max_file_bytes")
        budget.consume_bytes(child_stat.st_size)
        identity = _identity(child_stat)
        digest = _hash_fd(child_fd, child_stat.st_size, CP_DIAGBUNDLE_SNAPSHOT_READ)
        _require_identity(child_fd, identity, CP_DIAGBUNDLE_SNAPSHOT_READ)
        files[relative_path] = PinnedFile(
            fd=child_fd,
            relative_path=relative_path,
            identity=identity,
            pass1_sha256=digest,
        )
        owned = True
    finally:
        if not owned:
            _close_quiet(child_fd)


def _open_nofollow_directory(path: str) -> int:
    descriptor = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in [part for part in os.path.abspath(path).split(os.sep) if part]:
            next_descriptor = os.open(part, _DIR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_nofollow_regular(path: str) -> int:
    parts = [part for part in os.path.abspath(path).split(os.sep) if part]
    if not parts:
        raise OSError("path has no leaf")
    parent = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            next_parent = os.open(part, _DIR_FLAGS, dir_fd=parent)
            os.close(parent)
            parent = next_parent
        return os.open(parts[-1], _FILE_FLAGS, dir_fd=parent)
    finally:
        os.close(parent)


def _child_names(dir_fd: int) -> tuple[str, ...]:
    names = _listdir(dir_fd)
    for name in names:
        if name == "" or name in (".", "..") or "/" in name or "\x00" in name:
            raise DiagBundleError(CP_DIAGBUNDLE_SNAPSHOT_SHAPE, "bundle member name is invalid")
    return tuple(sorted(names))


def _listdir(dir_fd: int) -> list[str]:
    os.lseek(dir_fd, 0, os.SEEK_SET)
    return os.listdir(dir_fd)


def _iter_exact(fd: int, size: int, reason_code: str) -> Iterator[bytes]:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        remaining = size
        while remaining:
            chunk = os.read(fd, min(remaining, _CHUNK_BYTES))
            if not chunk:
                raise DiagBundleError(reason_code, "pinned file shrank while reading")
            remaining -= len(chunk)
            yield chunk
        if os.read(fd, 1):
            raise DiagBundleError(reason_code, "pinned file grew while reading")
        os.lseek(fd, 0, os.SEEK_SET)
    except DiagBundleError:
        raise
    except OSError as exc:
        raise DiagBundleError(reason_code, "could not read pinned file") from exc


def _hash_fd(fd: int, size: int, reason_code: str) -> str:
    digest = hashlib.sha256()
    for chunk in _iter_exact(fd, size, reason_code):
        digest.update(chunk)
    return digest.hexdigest()


def _require_identity(fd: int, expected: _Identity, reason_code: str) -> None:
    if _identity(os.fstat(fd)) != expected:
        raise DiagBundleError(reason_code, "pinned member identity changed")


def _identity(value: os.stat_result) -> _Identity:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _join(parent: str, name: str) -> str:
    if parent == "":
        return name
    return posixpath.join(parent, name)


def _close_all(files: dict[str, PinnedFile], directories: dict[str, PinnedDirectory]) -> None:
    for pinned in files.values():
        _close_quiet(pinned.fd)
    for relative_path in sorted(directories, key=_directory_depth, reverse=True):
        _close_quiet(directories[relative_path].fd)


def _directory_depth(relative_path: str) -> int:
    if relative_path == "":
        return 0
    return relative_path.count("/") + 1


def _close_quiet(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass
