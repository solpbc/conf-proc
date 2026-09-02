#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""AC12: no stray wiring of the dormant trace core outside the allowlist."""

from __future__ import annotations

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "build", "__pycache__"}
CORE_SYMBOLS = (
    "spp_diag_trace_core_init",
    "spp_diag_trace_core_append",
    "spp_diag_trace_core_snapshot",
    "spp_diag_trace_core_mark_failure",
    "struct spp_diag_trace_core",
    "CONFIG_SECURITY_SPP_DIAG_TRACE_CORE",
)
INITCALLS = ("security_init", "device_initcall", "late_initcall", "module_init")
ALLOW_PREFIXES = (
    "spp-diag-trace-core-src/security/spp_diag_trace_core/",
    "test/conf-proc-spp-diag-trace-core-",
    "test/spp-diag-trace-core-shim/",
    "conf_proc_spp_diag_trace_core_",
    "spp-diag-trace-core-src/manifest.json",
    "spp-diag-trace-core-src/config.fragment",
    "Makefile",
)


def _allowed(rel: str) -> bool:
    return any(rel == prefix or rel.startswith(prefix) for prefix in ALLOW_PREFIXES)


def _iter_files() -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for name in filenames:
            files.append(Path(dirpath) / name)
    return files


def walk(root: Path = ROOT) -> tuple[int, list[str]]:
    hits: list[str] = []
    scanned = 0
    for path in _iter_files():
        rel = str(path.relative_to(root))
        if _allowed(rel):
            scanned += 1
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        has_core = any(symbol in text for symbol in CORE_SYMBOLS)
        if not has_core:
            continue
        for symbol in CORE_SYMBOLS:
            if symbol in text:
                hits.append(f"{rel}: {symbol}")
        for initcall in INITCALLS:
            if initcall in text:
                hits.append(f"{rel}: {initcall} with core symbol")
    return scanned, hits


def main() -> int:
    scanned, hits = walk()
    if scanned == 0:
        print("FAIL source-walk scanned zero files")
        return 1
    if hits:
        print("FAIL source-walk hits on clean tree:")
        print("\n".join(hits))
        return 1
    print(f"ok   source-walk-clean scanned={scanned}")
    planted = ROOT / "zzz-k1-source-walk-plant.c"
    try:
        planted.write_text(
            "void security_init(void);\nvoid spp_diag_trace_core_init(void);\n",
            encoding="utf-8",
        )
        _scanned, planted_hits = walk()
        if not planted_hits:
            print("FAIL planted security_init+core symbol was not detected")
            return 1
        print("ok   source-walk-detects-plant")
    finally:
        try:
            planted.unlink()
        except FileNotFoundError:
            pass
    scanned_after, hits_after = walk()
    if hits_after:
        print("FAIL source-walk hits after plant cleanup:")
        print("\n".join(hits_after))
        return 1
    if scanned_after == 0:
        print("FAIL source-walk scanned zero files after cleanup")
        return 1
    print("ok   source-walk-restored")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
