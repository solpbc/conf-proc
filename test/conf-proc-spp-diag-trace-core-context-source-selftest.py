#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Reject spp_diag_trace_core_init() between IRQ save and restore in test C."""

from __future__ import annotations

import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE_KUNIT = (
    ROOT
    / "spp-diag-trace-core-src"
    / "security"
    / "spp_diag_trace_core"
    / "core_kunit.c"
)
FUNC_RE = re.compile(
    r"^(?:static\s+)?(?:void|int|size_t|unsigned|u32|u64)\s+(\w+)\s*\([^;]*\)\s*\{",
    re.M,
)
INIT_RE = re.compile(r"spp_diag_trace_core_init\s*\(")
SAVE_RE = re.compile(r"\blocal_irq_(?:save|disable)\s*\(")
RESTORE_RE = re.compile(r"\blocal_irq_(?:restore|enable)\s*\(")


def _c_files() -> list[Path]:
    files = sorted(ROOT.glob("test/conf-proc-spp-diag-trace-core*.c"))
    if CORE_KUNIT.exists():
        files.append(CORE_KUNIT)
    return files


def _functions(text: str) -> list[tuple[str, str]]:
    matches = list(FUNC_RE.finditer(text))
    bodies: list[tuple[str, str]] = []
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        bodies.append((match.group(1), text[start:end]))
    return bodies


def scan_text(text: str, rel: str) -> list[str]:
    hits: list[str] = []
    for name, body in _functions(text):
        saves = list(SAVE_RE.finditer(body))
        if not saves:
            continue
        restores = list(RESTORE_RE.finditer(body))
        inits = list(INIT_RE.finditer(body))
        for save in saves:
            restore = next(
                (item for item in restores if item.start() > save.start()),
                None,
            )
            region_end = restore.start() if restore is not None else len(body)
            for init in inits:
                if save.end() <= init.start() < region_end:
                    hits.append(f"{rel}: {name}() calls init between IRQ save and restore")
    return hits


def scan_files(files: list[Path]) -> list[str]:
    hits: list[str] = []
    for path in files:
        rel = str(path.relative_to(ROOT))
        text = path.read_text(encoding="utf-8", errors="replace")
        hits.extend(scan_text(text, rel))
    return hits


def main() -> int:
    if os.environ.get("SPP_DIAG_TRACE_CORE_FORCE_FAIL") == "1":
        print("FAIL context-source forced")
        return 1
    files = _c_files()
    if not files:
        print("FAIL context-source scanned zero files")
        return 1
    hits = scan_files(files)
    if hits:
        print("FAIL context-source IRQ-wrapped init:")
        print("\n".join(hits))
        return 1
    print(f"ok   context-source-clean files={len(files)}")

    planted = ROOT / "test" / "conf-proc-spp-diag-trace-core-zzz-irq-plant.c"
    try:
        planted.write_text(
            "static void planted_irq_init(void)\n"
            "{\n"
            "\tunsigned long flags;\n"
            "\tu8 id[32];\n"
            "\tlocal_irq_save(flags);\n"
            "\tspp_diag_trace_core_init(id, id, id, id);\n"
            "\tlocal_irq_restore(flags);\n"
            "}\n",
            encoding="utf-8",
        )
        planted_hits = scan_files(_c_files())
        if not any("zzz-irq-plant.c" in item for item in planted_hits):
            print("FAIL planted IRQ-wrapped init was not detected")
            return 1
        print("ok   context-source-detects-plant")
    finally:
        try:
            planted.unlink()
        except FileNotFoundError:
            pass

    after = scan_files(_c_files())
    if after:
        print("FAIL context-source hits after plant cleanup:")
        print("\n".join(after))
        return 1
    print("ok   context-source-restored")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
