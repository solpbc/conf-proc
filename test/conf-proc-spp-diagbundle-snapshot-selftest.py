#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Filesystem selftest for the diagnostic-bundle snapshot primitive."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from conf_proc_spp_diagbundle_reasons import (  # noqa: E402
    CP_DIAGBUNDLE_CONCURRENT_MUTATION,
    CP_DIAGBUNDLE_SNAPSHOT_SHAPE,
    CP_DIAGBUNDLE_SNAPSHOT_SIZE,
    DiagBundleError,
)
from conf_proc_spp_diagbundle_snapshot import (  # noqa: E402
    SnapshotBudget,
    pin_bundle_root,
    revalidate,
)


_TMP = "/var/tmp"


def _budget(**overrides: int) -> SnapshotBudget:
    values = dict(max_entries=64, max_depth=8, max_file_bytes=1024 * 1024, max_total_bytes=10 * 1024 * 1024)
    values.update(overrides)
    return SnapshotBudget(**values)


def _fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)


def _expect(code: str, fn) -> None:
    try:
        fn()
    except DiagBundleError as exc:
        if exc.reason_code != code:
            raise AssertionError(f"expected {code}, got {exc.reason_code}: {exc}") from exc
        return
    raise AssertionError(f"expected {code}")


def test_happy_path_nested_tree_and_fd_cleanup() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-snap-", dir=_TMP) as tmp:
        root = os.path.join(tmp, "bundle")
        _write(os.path.join(root, "a.txt"), b"alpha")
        _write(os.path.join(root, "dir", "b.txt"), b"beta")
        _write(os.path.join(root, "dir", "nested", "c.txt"), b"gamma")
        expected = {
            "a.txt": b"alpha",
            "dir/b.txt": b"beta",
            "dir/nested/c.txt": b"gamma",
        }
        before = _fd_count()
        with pin_bundle_root(root, _budget()) as snapshot:
            revalidate(snapshot)
            assert snapshot.root.relative_path == ""
            assert set(snapshot.directories) == {"", "dir", "dir/nested"}
            assert set(snapshot.files) == set(expected)
            for relative, data in expected.items():
                pinned = snapshot.files[relative]
                digest = hashlib.sha256(data).hexdigest()
                assert pinned.pass1_sha256 == digest
                assert pinned.sha256_all() == digest
                assert pinned.read_all() == data
                metadata = os.lstat(os.path.join(root, relative))
                assert pinned.identity[0] == metadata.st_dev
                assert pinned.identity[1] == metadata.st_ino
                assert pinned.identity[4] == metadata.st_size
            assert snapshot.directories["dir"].child_names == ("b.txt", "nested")
        after = _fd_count()
        assert after == before, f"fd leak: before={before} after={after}"


def test_symlink_is_shape_and_not_followed() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-snap-", dir=_TMP) as tmp:
        root = os.path.join(tmp, "bundle")
        os.mkdir(root)
        os.symlink("/nonexistent/conf-proc-diagbundle-never-follow", os.path.join(root, "link"))

        def run() -> None:
            with pin_bundle_root(root, _budget()):
                pass

        _expect(CP_DIAGBUNDLE_SNAPSHOT_SHAPE, run)


def test_fifo_is_shape() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-snap-", dir=_TMP) as tmp:
        root = os.path.join(tmp, "bundle")
        os.mkdir(root)
        os.mkfifo(os.path.join(root, "pipe"))

        def run() -> None:
            with pin_bundle_root(root, _budget()):
                pass

        _expect(CP_DIAGBUNDLE_SNAPSHOT_SHAPE, run)


def test_hardlink_is_shape() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-snap-", dir=_TMP) as tmp:
        root = os.path.join(tmp, "bundle")
        os.mkdir(root)
        _write(os.path.join(root, "one"), b"same")
        os.link(os.path.join(root, "one"), os.path.join(root, "two"))
        assert os.lstat(os.path.join(root, "one")).st_nlink == 2

        def run() -> None:
            with pin_bundle_root(root, _budget()):
                pass

        _expect(CP_DIAGBUNDLE_SNAPSHOT_SHAPE, run)


def test_entry_count_over_budget() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-snap-", dir=_TMP) as tmp:
        root = os.path.join(tmp, "bundle")
        os.mkdir(root)
        _write(os.path.join(root, "one"), b"1")
        _write(os.path.join(root, "two"), b"2")

        def run() -> None:
            with pin_bundle_root(root, _budget(max_entries=2)):
                pass

        _expect(CP_DIAGBUNDLE_SNAPSHOT_SIZE, run)


def test_file_size_over_budget_uses_sparse_declared_size() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-snap-", dir=_TMP) as tmp:
        root = os.path.join(tmp, "bundle")
        os.mkdir(root)
        path = os.path.join(root, "big")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.lseek(descriptor, 8192, os.SEEK_SET)
            os.write(descriptor, b"x")
        finally:
            os.close(descriptor)
        metadata = os.lstat(path)
        assert metadata.st_size > 4096
        assert metadata.st_blocks * 512 < metadata.st_size

        def run() -> None:
            with pin_bundle_root(root, _budget(max_file_bytes=4096)):
                pass

        _expect(CP_DIAGBUNDLE_SNAPSHOT_SIZE, run)


def test_depth_over_budget() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-snap-", dir=_TMP) as tmp:
        root = os.path.join(tmp, "bundle")
        os.makedirs(os.path.join(root, "too", "deep"))

        def run() -> None:
            with pin_bundle_root(root, _budget(max_depth=1)):
                pass

        _expect(CP_DIAGBUNDLE_SNAPSHOT_SIZE, run)


def test_file_rename_swap_is_concurrent_mutation() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-snap-", dir=_TMP) as tmp:
        root = os.path.join(tmp, "bundle")
        os.mkdir(root)
        _write(os.path.join(root, "victim"), b"aaaa")
        _write(os.path.join(root, "other"), b"bbbb")
        with pin_bundle_root(root, _budget()) as snapshot:
            os.rename(os.path.join(root, "other"), os.path.join(root, "victim"))
            _expect(CP_DIAGBUNDLE_CONCURRENT_MUTATION, lambda: revalidate(snapshot))


def test_same_inode_rewrite_is_concurrent_mutation() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-snap-", dir=_TMP) as tmp:
        root = os.path.join(tmp, "bundle")
        os.mkdir(root)
        path = os.path.join(root, "payload")
        _write(path, b"1111")
        with pin_bundle_root(root, _budget()) as snapshot:
            with open(path, "wb") as handle:
                handle.write(b"2222")
            _expect(CP_DIAGBUNDLE_CONCURRENT_MUTATION, lambda: revalidate(snapshot))


def test_stable_generation_revalidate_succeeds() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-snap-", dir=_TMP) as tmp:
        root = os.path.join(tmp, "bundle")
        _write(os.path.join(root, "keep"), b"stable")
        os.mkdir(os.path.join(root, "sub"))
        _write(os.path.join(root, "sub", "inner"), b"also")
        with pin_bundle_root(root, _budget()) as snapshot:
            revalidate(snapshot)
            revalidate(snapshot)
            assert snapshot.files["keep"].read_all() == b"stable"


def test_directory_rename_swap_is_concurrent_mutation() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-snap-", dir=_TMP) as tmp:
        bundle = os.path.join(tmp, "bundle")
        os.makedirs(os.path.join(bundle, "sub"))
        _write(os.path.join(bundle, "sub", "inner"), b"old")
        with pin_bundle_root(bundle, _budget()) as snapshot:
            os.rename(os.path.join(bundle, "sub"), os.path.join(tmp, "stashed"))
            os.mkdir(os.path.join(bundle, "sub"))
            _write(os.path.join(bundle, "sub", "inner"), b"new")
            _expect(CP_DIAGBUNDLE_CONCURRENT_MUTATION, lambda: revalidate(snapshot))


def test_size_reject_does_not_read_oversized_file() -> None:
    with tempfile.TemporaryDirectory(prefix="diagbundle-snap-", dir=_TMP) as tmp:
        root = os.path.join(tmp, "bundle")
        os.mkdir(root)
        path = os.path.join(root, "big")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.lseek(descriptor, 8192, os.SEEK_SET)
            os.write(descriptor, b"x")
        finally:
            os.close(descriptor)
        opened: dict[str, int] = {}
        read_fds: set[int] = set()
        real_open = os.open
        real_read = os.read

        def spy_open(file, flags, mode=0o777, *, dir_fd=None):
            fd = real_open(file, flags, mode, dir_fd=dir_fd)
            if file == "big":
                opened["fd"] = fd
            return fd

        def spy_read(fd, n, *args):
            read_fds.add(fd)
            return real_read(fd, n)

        os.open = spy_open  # type: ignore[method-assign]
        os.read = spy_read  # type: ignore[method-assign]
        try:

            def run() -> None:
                with pin_bundle_root(root, _budget(max_file_bytes=4096)):
                    pass

            _expect(CP_DIAGBUNDLE_SNAPSHOT_SIZE, run)
            assert "fd" in opened, "oversized file was never opened for fstat"
            assert opened["fd"] not in read_fds
        finally:
            os.open = real_open  # type: ignore[method-assign]
            os.read = real_read  # type: ignore[method-assign]


TESTS = (
    test_happy_path_nested_tree_and_fd_cleanup,
    test_symlink_is_shape_and_not_followed,
    test_fifo_is_shape,
    test_hardlink_is_shape,
    test_entry_count_over_budget,
    test_file_size_over_budget_uses_sparse_declared_size,
    test_depth_over_budget,
    test_file_rename_swap_is_concurrent_mutation,
    test_same_inode_rewrite_is_concurrent_mutation,
    test_stable_generation_revalidate_succeeds,
    test_directory_rename_swap_is_concurrent_mutation,
    test_size_reject_does_not_read_oversized_file,
)


if __name__ == "__main__":
    failed = 0
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report every case before exiting
            failed += 1
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok   {test.__name__}")
    raise SystemExit(failed)
