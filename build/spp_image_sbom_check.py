#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent validator for SPP appliance image SBOM."""

from __future__ import annotations

import hashlib
from pathlib import Path

from typing import Final

SPDX_VERSION: Final = "SPDX-2.3"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def check_image_sbom(tree: Path, document: dict) -> None:
    """Validate image SBOM against the filesystem tree."""
    if document.get("spdxVersion") != SPDX_VERSION:
        raise SystemExit(
            f"SPDX version mismatch: expected {SPDX_VERSION!r}, got {document.get('spdxVersion')!r}"
        )

    files_list = document.get("files", [])
    if not isinstance(files_list, list):
        raise SystemExit("SBOM 'files' field is not a list")

    listed_file_names: set[str] = set()
    digest_diff: list[str] = []

    for entry in files_list:
        if not isinstance(entry, dict):
            continue
        file_name = entry.get("fileName")
        if not isinstance(file_name, str):
            continue
        listed_file_names.add(file_name)

        checksums = entry.get("checksums", [])
        expected_sha = None
        if isinstance(checksums, list) and checksums:
            expected_sha = checksums[0].get("checksumValue")

        target_file = tree / file_name
        if not target_file.is_file() or target_file.is_symlink():
            digest_diff.append(f"missing or non-regular file: {file_name}")
            continue

        actual_sha = _file_sha256(target_file)
        if actual_sha != expected_sha:
            digest_diff.append(
                f"sha256 mismatch for {file_name}: expected {expected_sha}, got {actual_sha}"
            )

    # Coverage diff: regular files with (mode & 0o111) != 0, or .so in name, or *.py
    coverage_diff: list[str] = []
    for path in tree.rglob("*"):
        if path.is_file() and not path.is_symlink():
            mode = path.stat().st_mode
            rel_posix = path.relative_to(tree).as_posix()
            is_executable = (mode & 0o111) != 0
            is_shared_lib = ".so" in path.name
            is_python = path.name.endswith(".py")

            if (is_executable or is_shared_lib or is_python) and rel_posix not in listed_file_names:
                coverage_diff.append(f"unlisted executable/code file: {rel_posix}")

    if digest_diff or coverage_diff:
        msg_lines = ["SBOM verification failed:"]
        if digest_diff:
            msg_lines.append(f"Digest diff ({len(digest_diff)} items):")
            for diff in sorted(digest_diff):
                msg_lines.append(f"  - {diff}")
        if coverage_diff:
            msg_lines.append(f"Coverage diff ({len(coverage_diff)} items):")
            for diff in sorted(coverage_diff):
                msg_lines.append(f"  - {diff}")
        raise SystemExit("\n".join(msg_lines))
