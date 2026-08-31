#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Capture and parse one canonical, immutable-by-use diagnostic bundle stream."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import posixpath
import stat
import struct
import tempfile
import unicodedata
from dataclasses import dataclass
from typing import BinaryIO, Final, Iterator

from conf_proc_spp_diagbundle_reasons import (
    CP_DIAGBUNDLE_FORBIDDEN,
    CP_DIAGBUNDLE_SOURCE_CHANGED,
    CP_DIAGBUNDLE_STREAM_FORMAT,
    CP_DIAGBUNDLE_STREAM_READ,
    CP_DIAGBUNDLE_STREAM_SIZE,
    DiagBundleError,
)


STREAM_MAGIC: Final = b"SPPDBN1\0"
STREAM_VERSION: Final = 1
MAX_MEMBERS: Final = 8192
MAX_PATH_BYTES: Final = 255
MAX_CAPTURE_BYTES: Final = 384 * 1024**3
_HEADER = struct.Struct(">8sII")
_RECORD = struct.Struct(">HQ32s")
_CHUNK_BYTES = 1024 * 1024
_OPEN_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY",
    b"-----BEGIN ENCRYPTED PRIVATE KEY",
    b"-----BEGIN RSA PRIVATE KEY",
    b"-----BEGIN EC PRIVATE KEY",
    b"-----BEGIN OPENSSH PRIVATE KEY",
    b"-----BEGIN DSA PRIVATE KEY",
)
_MARKER_TAIL_BYTES = max(len(marker) for marker in _PRIVATE_KEY_MARKERS) - 1
_Identity = tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True)
class StreamMember:
    """One already-hashed logical member inside a captured stream."""

    handle: BinaryIO
    path: str
    path_bytes: bytes
    payload_offset: int
    size_bytes: int
    sha256: str

    def read_all(self, max_bytes: int) -> bytes:
        if self.size_bytes > max_bytes:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_SIZE, "member exceeds its read budget")
        try:
            self.handle.seek(self.payload_offset)
            data = self.handle.read(self.size_bytes)
        except OSError as exc:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_READ, "could not read captured member") from exc
        if len(data) != self.size_bytes:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_READ, "captured member became truncated")
        if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), self.sha256):
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_READ, "captured member digest changed")
        return data

    def read_range(self, offset: int, length: int) -> bytes:
        if type(offset) is not int or type(length) is not int or offset < 0 or length < 0:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_READ, "captured member range is invalid")
        if offset > self.size_bytes or length > self.size_bytes - offset:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_READ, "captured member range is out of bounds")
        try:
            self.handle.seek(self.payload_offset + offset)
            data = self.handle.read(length)
        except OSError as exc:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_READ, "could not read captured member range") from exc
        if len(data) != length:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_READ, "captured member range became truncated")
        return data


@dataclass(frozen=True)
class BundleStream:
    """Canonical member index over one private captured byte sequence."""

    handle: BinaryIO
    members: dict[str, StreamMember]
    captured_size: int


@contextlib.contextmanager
def capture_bundle(path: str) -> Iterator[BundleStream]:
    """Copy one regular source exactly once, then parse only the private copy.

    The opening path is not a provenance or filesystem-generation claim. A
    changed source is rejected when observable; otherwise the API vouches only
    for the exact captured byte sequence indexed in the returned object.
    """

    descriptor = -1
    writable: BinaryIO | None = None
    private: BinaryIO | None = None
    try:
        descriptor = os.open(path, _OPEN_FLAGS)
        before = os.fstat(descriptor)
        _require_source(before)
        if before.st_size > MAX_CAPTURE_BYTES:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_SIZE, "bundle source exceeds its size budget")
        writable = tempfile.TemporaryFile(mode="w+b")
        captured_size = _copy_once(descriptor, writable)
        after = os.fstat(descriptor)
        if _identity(after) != _identity(before):
            raise DiagBundleError(CP_DIAGBUNDLE_SOURCE_CHANGED, "bundle source changed while it was captured")
        writable.flush()
        private = _freeze_read_only(writable)
        writable.close()
        writable = None
        private.seek(0)
        yield _parse(private, captured_size)
    except DiagBundleError:
        raise
    except OSError as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_READ, "could not capture diagnostic-bundle stream") from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if writable is not None:
            writable.close()
        if private is not None:
            private.close()


def _freeze_read_only(writable: BinaryIO) -> BinaryIO:
    """Reopen one unlinked private capture read-only, then revoke write mode."""

    reopened = -1
    try:
        os.fchmod(writable.fileno(), stat.S_IRUSR)
        reopened = os.open(f"/proc/self/fd/{writable.fileno()}", os.O_RDONLY | os.O_CLOEXEC)
        if _identity(os.fstat(reopened)) != _identity(os.fstat(writable.fileno())):
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_READ, "private capture identity changed while freezing")
        return os.fdopen(reopened, "rb", closefd=True)
    except DiagBundleError:
        if reopened >= 0:
            os.close(reopened)
        raise
    except OSError as exc:
        if reopened >= 0:
            os.close(reopened)
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_READ, "could not freeze private capture read-only") from exc


def read_bounded_regular(path: str, max_bytes: int) -> bytes:
    """Read one regular no-follow file once under an explicit byte bound."""

    descriptor = -1
    try:
        descriptor = os.open(path, _OPEN_FLAGS)
        before = os.fstat(descriptor)
        _require_source(before)
        if before.st_size > max_bytes:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_SIZE, "bounded input exceeds its size budget")
        data = _read_fd_to_eof(descriptor, max_bytes)
        after = os.fstat(descriptor)
        if _identity(after) != _identity(before):
            raise DiagBundleError(CP_DIAGBUNDLE_SOURCE_CHANGED, "bounded input changed while it was read")
        return data
    except DiagBundleError:
        raise
    except OSError as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_READ, "could not read bounded input") from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _copy_once(source_fd: int, destination: BinaryIO) -> int:
    total = 0
    while True:
        chunk = os.read(source_fd, _CHUNK_BYTES)
        if not chunk:
            return total
        if len(chunk) > MAX_CAPTURE_BYTES - total:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_SIZE, "bundle capture exceeds its size budget")
        destination.write(chunk)
        total += len(chunk)


def _read_fd_to_eof(descriptor: int, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(_CHUNK_BYTES, max_bytes - total + 1))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > max_bytes:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_SIZE, "bounded input exceeds its size budget")
        chunks.append(chunk)


def _parse(handle: BinaryIO, captured_size: int) -> BundleStream:
    header = _read_exact(handle, _HEADER.size)
    magic, version, member_count = _HEADER.unpack(header)
    if magic != STREAM_MAGIC or version != STREAM_VERSION:
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "bundle stream magic or version is invalid")
    if member_count < 1 or member_count > MAX_MEMBERS:
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_SIZE, "bundle stream member count is invalid")

    members: dict[str, StreamMember] = {}
    previous_path = b""
    for _index in range(member_count):
        path_length, payload_length, expected_digest = _RECORD.unpack(_read_exact(handle, _RECORD.size))
        if path_length < 1 or path_length > MAX_PATH_BYTES:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "bundle member path length is invalid")
        path_bytes = _read_exact(handle, path_length)
        path = _decode_path(path_bytes)
        if previous_path and path_bytes <= previous_path:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "bundle member paths are not strictly increasing")
        previous_path = path_bytes
        payload_offset = handle.tell()
        actual_digest = _hash_payload(handle, payload_length)
        if not hmac.compare_digest(actual_digest, expected_digest):
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "bundle member payload digest is invalid")
        members[path] = StreamMember(
            handle=handle,
            path=path,
            path_bytes=path_bytes,
            payload_offset=payload_offset,
            size_bytes=payload_length,
            sha256=actual_digest.hex(),
        )

    if handle.read(1):
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "bundle stream has trailing bytes")
    if handle.tell() != captured_size:
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "bundle stream length is inconsistent")
    return BundleStream(handle=handle, members=members, captured_size=captured_size)


def _hash_payload(handle: BinaryIO, size: int) -> bytes:
    digest = hashlib.sha256()
    remaining = size
    tail = b""
    while remaining:
        chunk = handle.read(min(_CHUNK_BYTES, remaining))
        if not chunk:
            raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "bundle member payload is truncated")
        digest.update(chunk)
        scan = tail + chunk
        if any(marker in scan for marker in _PRIVATE_KEY_MARKERS):
            raise DiagBundleError(CP_DIAGBUNDLE_FORBIDDEN, "bundle member contains a private-key marker")
        tail = scan[-_MARKER_TAIL_BYTES:]
        remaining -= len(chunk)
    return digest.digest()


def _read_exact(handle: BinaryIO, size: int) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "bundle stream is truncated")
    return data


def _decode_path(path_bytes: bytes) -> str:
    try:
        path = path_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "bundle member path is not UTF-8") from exc
    if path.encode("utf-8") != path_bytes or unicodedata.normalize("NFC", path) != path:
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "bundle member path is not canonical NFC UTF-8")
    if path.startswith("/") or "\\" in path or "\x00" in path:
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "bundle member path is not a relative POSIX path")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts) or posixpath.normpath(path) != path:
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "bundle member path is not normalized")
    return path


def _require_source(value: os.stat_result) -> None:
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise DiagBundleError(CP_DIAGBUNDLE_STREAM_FORMAT, "input must be a single-link regular file")


def _identity(value: os.stat_result) -> _Identity:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
