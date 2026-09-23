#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fill an input manifest's digests from a workspace whose inputs were acquired and verified.

Run once, by whoever publishes a manifest, against a workspace populated by the acquisition
scripts (each of which checks its bytes against an upstream identity: archive SHA-256, Hugging
Face LFS oid, OCI digest). Everyone else runs the recipe, which verifies their own workspace
against the published result and refuses on any difference.

A file input records sha256 and size. A directory input records every regular file (path,
sha256, size) and every symlink (path, target); the directory's sha256 is over that list.

Usage: populate_manifest.py --workspace DIR [--manifest PATH] [--out PATH]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import spp_disk  # noqa: E402


def tree_entries(root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            rows.append({"path": rel, "symlink": os.readlink(p)})
        elif p.is_file():
            rows.append({"path": rel, "sha256": spp_disk.sha256_file(p), "size_bytes": p.stat().st_size})
    return rows


def tree_digest(rows: list[dict[str, object]]) -> str:
    ordered = sorted(rows, key=lambda item: str(item.get("path", "")))
    return spp_disk.sha256_bytes(json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def populate(manifest: dict, workspace: Path, only: list[str] | None = None) -> dict:
    if only is not None:
        manifest["inputs"] = {k: v for k, v in manifest["inputs"].items() if k in only}
        missing = sorted(set(only) - set(manifest["inputs"]))
        if missing:
            raise SystemExit(f"manifest template lacks required inputs: {missing}")
    for input_id, entry in manifest["inputs"].items():
        target = workspace / entry["path"]
        if not target.exists():
            raise SystemExit(f"{input_id}: {target} does not exist")
        if target.is_dir():
            rows = tree_entries(target)
            entry["files"] = rows
            entry["size_bytes"] = sum(int(r["size_bytes"]) for r in rows if "size_bytes" in r)
            entry["sha256"] = tree_digest(rows)
        else:
            entry.pop("files", None)
            entry["size_bytes"] = target.stat().st_size
            entry["sha256"] = spp_disk.sha256_file(target)
    manifest["status"] = "populated"
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parent / "input-manifest.json")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--stage", help="record only the inputs this stage requires")
    ap.add_argument("--compact-out", type=Path,
                    help="also write a copy with directory file lists removed (tree digests only)")
    a = ap.parse_args()
    only = None
    if a.stage:
        from spp_appliance import required_inputs
        only = required_inputs(a.stage)
    data = populate(json.loads(a.manifest.read_text()), a.workspace.resolve(), only)
    (a.out or a.manifest).write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    if a.compact_out:
        compact = json.loads(json.dumps(data))
        for entry in compact["inputs"].values():
            if "files" in entry:
                entry["files_count"] = len(entry.pop("files"))
        a.compact_out.write_text(json.dumps(compact, indent=1, sort_keys=True) + "\n")
    n = sum(len(e.get("files", [])) or 1 for e in data["inputs"].values())
    print(f"populated {len(data['inputs'])} inputs ({n} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
