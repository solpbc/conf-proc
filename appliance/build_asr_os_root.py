#!/usr/bin/env python3
"""Reconstruct the pinned CPython runtime and native ASR dependencies."""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "acquisition/packages.json"
SNAP = "https://snapshot.ubuntu.com/ubuntu/20260615T120000Z/pool/main/"
GAPS = [
    ("libmpdec3.deb", SNAP + "m/mpdecimal/libmpdec3_2.5.1-2build2_amd64.deb",
     "941ca0b2e73d26522f75a801b1bf529afa5ceb2ac9b00cbf324b59f474cae813"),
    ("libbz2-1.0.deb", SNAP + "b/bzip2/libbz2-1.0_1.0.8-5build1_amd64.deb",
     "3bfeaf4259eadbb7faa09feee86cd6cad172cd95907d7465afd0eb5aebb5433f"),
    ("libsqlite3-0.deb", SNAP + "s/sqlite3/libsqlite3-0_3.37.2-2_amd64.deb",
     "000a1d5c0df0373c75fadbfea604afb6b1325bf866a3ce637ae0138abe6d556d"),
]


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True, type=Path)
    ws = ap.parse_args().workspace.resolve()
    pkgs, gapdir = ws / "packages", ws / "serving-inputs/asr-native-gap"
    root = ws / "serving-inputs/asr-os-root"
    gapdir.mkdir(parents=True, exist_ok=True)

    debs = []
    for row in json.loads(MANIFEST.read_text())["packages"]:
        p = pkgs / row["filename"]
        if sha(p) != row["sha256"]:
            raise SystemExit(f"{p} does not match its pin")
        debs.append(p)
    for name, url, want in GAPS:
        p = gapdir / name
        if not p.exists():
            with urllib.request.urlopen(url, timeout=120) as r:
                p.write_bytes(r.read())
        if sha(p) != want:
            p.unlink()
            raise SystemExit(f"{name} does not match its pin")
        debs.append(p)

    if root.exists():
        raise SystemExit("output root already exists; use a fresh workspace")
    root.mkdir(parents=True)
    for p in debs:
        subprocess.run(["dpkg-deb", "-x", str(p), str(root)], check=True)
    # Empty mountpoints needed by isolated runtime checks.
    for d in ("proc", "dev", "tmp", "opt/asr", "fixtures"):
        (root / d).mkdir(parents=True, exist_ok=True)
    n = sum(1 for q in root.rglob("*") if q.is_file() or q.is_symlink())
    print(f"asr-os-root rebuilt from {len(debs)} pinned packages: {n} files and links")
    return 0


if __name__ == "__main__":
    sys.exit(main())
