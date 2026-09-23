#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independently check the image SBOM against the published root filesystem.

Written apart from the build's own generator and checker: it reads only the published
`rootfs.img` (extracted with `unsquashfs`) and the published `image-sbom.json`, recomputes the
SHA-256 of every regular file, and reports:

  * every SBOM entry whose digest does not match the extracted file, or whose file is absent;
  * every executable, shared object or Python file in the image that the SBOM does not list;
  * the symlinks and set-id files, which an SPDX file list does not carry (the roothash covers
    them; this names what the SBOM leaves to it). Set-id bits are read from the squashfs listing:
    an extraction by a non-root user drops them.

Usage: verify_image_sbom.py --rootfs rootfs.img --sbom image-sbom.json --scratch DIR
Exit 0 only with zero mismatches and zero unlisted executables.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def executable_like(rel: str, mode: int) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return bool(mode & 0o111) or ".so" in name or name.endswith(".py")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rootfs", type=Path, required=True)
    ap.add_argument("--sbom", type=Path, required=True)
    ap.add_argument("--scratch", type=Path, required=True, help="empty directory to extract into")
    ap.add_argument("--reuse-extraction", action="store_true", help="SCRATCH/root is already this image")
    a = ap.parse_args(argv)
    root = a.scratch / "root"
    if a.reuse_extraction:
        if not root.is_dir():
            raise SystemExit(f"{root} is not an extraction to reuse")
    elif root.exists():
        raise SystemExit(f"{root} exists; give an empty scratch directory")
    else:
        subprocess.run(["unsquashfs", "-q", "-no-progress", "-d", str(root), str(a.rootfs)], check=True,
                       stdout=subprocess.DEVNULL)
    listing = subprocess.run(["unsquashfs", "-lls", str(a.rootfs)], check=True, capture_output=True,
                             text=True).stdout.splitlines()
    setid_files = sorted(line.split()[-1].split("squashfs-root/", 1)[-1] for line in listing
                         if line[:1] == "-" and (line[3] in "sS" or line[6] in "sS"))
    listed = {}
    for entry in json.loads(a.sbom.read_text())["files"]:
        digests = [c["checksumValue"] for c in entry["checksums"] if c["algorithm"] == "SHA256"]
        listed[entry["fileName"]] = digests[0]
    mismatched, absent, unlisted = [], [], []
    regular = symlinks = 0
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            st = path.lstat()
            if stat.S_ISLNK(st.st_mode):
                symlinks += 1
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            regular += 1
            if rel not in listed:
                if executable_like(rel, st.st_mode):
                    unlisted.append(rel)
                continue
            if sha256(path) != listed[rel]:
                mismatched.append(rel)
    present = set()
    for rel in listed:
        if (root / rel).is_file() and not (root / rel).is_symlink():
            present.add(rel)
        else:
            absent.append(rel)
    report = {
        "rootfs_sha256": sha256(a.rootfs),
        "sbom_sha256": sha256(a.sbom),
        "sbom_files": len(listed),
        "image_regular_files": regular,
        "mismatched": len(mismatched),
        "absent_from_image": len(absent),
        "unlisted_executables": len(unlisted),
        "image_symlinks_not_in_sbom": symlinks,
        "image_setid_files": setid_files,
        "examples": {"mismatched": mismatched[:5], "absent": absent[:5], "unlisted": unlisted[:5]},
    }
    print(json.dumps(report, indent=1, sort_keys=True))
    return 0 if not (mismatched or absent or unlisted) else 1


if __name__ == "__main__":
    sys.exit(main())
