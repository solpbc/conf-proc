#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Bounded post-stage kernel config/build handoff for the dormant trace core."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

from conf_proc_guard import HermeticGuard, ToolDeclaration, hermetic_lockdown
from conf_proc_json import canonical_dumps
from conf_proc_reasons import ApplianceError
from conf_proc_spp_diag_trace_core_manifest import CoreManifest, parse_core_manifest
from conf_proc_spp_diag_trace_core_materialize import (
    DEFAULT_MANIFEST,
    REPO_ROOT,
    build_guard,
    materialize_worktree,
)
from conf_proc_spp_diag_trace_core_materialize_reasons import (
    CP_SPP_DIAG_TRACE_CORE_FORBIDDEN_COMMAND,
    CP_SPP_DIAG_TRACE_CORE_HANDOFF,
    CP_SPP_DIAG_TRACE_CORE_TOOL,
    CP_SPP_DIAG_TRACE_CORE_TYPE,
    SppDiagTraceCoreMaterializeError,
)


FRAGMENT_SYMBOLS = (
    "CONFIG_CRYPTO_LIB_SHA256",
    "CONFIG_SECURITY_SPP_DIAG_TRACE_CORE",
)
EXPORT_NAME = ".config.export"
CONFIG_NAME = ".config"
TEMP_SUFFIX = ".spp-diag-trace-core-handoff-tmp"


def _fail(
    reason_code: str,
    message: str,
    *,
    path: str = "",
    expected: str = "",
    observed: str = "",
) -> None:
    raise SppDiagTraceCoreMaterializeError(
        reason_code, message, path=path, expected=expected, observed=observed
    )


def require_handoff_argv(
    argv: list[str],
    *,
    annotations: str,
    make: str,
    output_dir: str,
) -> None:
    """Refuse any argv that is not one of the three pinned handoff shapes."""

    o_flag = "O=" + output_dir
    allowed = (
        [annotations, "--export"],
        [make, o_flag, "olddefconfig"],
        [make, o_flag],
    )
    if argv in allowed:
        return
    _fail(
        CP_SPP_DIAG_TRACE_CORE_FORBIDDEN_COMMAND,
        "handoff argv is not allowlisted",
        expected="annotations --export | make O=<dir> olddefconfig | make O=<dir>",
        observed=" ".join(argv),
    )


def _run_handoff_tool(
    guard: HermeticGuard,
    argv: list[str],
    *,
    annotations: str,
    make: str,
    output_dir: str,
    cwd: str,
):
    require_handoff_argv(argv, annotations=annotations, make=make, output_dir=output_dir)
    try:
        return guard.run_tool(argv, cwd=cwd, check=False)
    except ApplianceError as exc:
        _fail(CP_SPP_DIAG_TRACE_CORE_TOOL, f"handoff tool invocation failed: {exc}")


def build_handoff_guard(
    *,
    git_abs: str,
    git_sha256: str,
    annotations_abs: str,
    annotations_sha256: str,
    make_abs: str,
    make_sha256: str,
    worktree: str,
    manifest: CoreManifest,
) -> HermeticGuard:
    for label, path in (
        ("annotations", annotations_abs),
        ("make", make_abs),
    ):
        if type(path) is not str or not os.path.isabs(path):
            _fail(CP_SPP_DIAG_TRACE_CORE_TYPE, f"{label} path must be absolute", path=str(path))
        if type(annotations_sha256 if label == "annotations" else make_sha256) is not str:
            _fail(CP_SPP_DIAG_TRACE_CORE_TYPE, f"{label} sha256 must be a string")
    base = build_guard(git_abs, git_sha256, worktree, manifest)
    allowed = set(base.allowed_reads())
    allowed.add(annotations_abs)
    allowed.add(make_abs)
    tools = {
        git_abs: ToolDeclaration(git_abs, git_sha256),
        annotations_abs: ToolDeclaration(annotations_abs, annotations_sha256),
        make_abs: ToolDeclaration(make_abs, make_sha256),
    }
    try:
        return HermeticGuard(
            allowed_reads=frozenset(allowed),
            tools=tools,
            env=base.env,
            build_epoch=base.build_epoch,
        )
    except ApplianceError as exc:
        _fail(CP_SPP_DIAG_TRACE_CORE_TOOL, f"could not construct handoff guard: {exc}")


def _atomic_write(path: str, data: bytes) -> None:
    temp = path + TEMP_SUFFIX
    try:
        with open(temp, "wb") as handle:
            handle.write(data)
        os.rename(temp, path)
    except OSError as exc:
        try:
            os.unlink(temp)
        except OSError:
            pass
        _fail(CP_SPP_DIAG_TRACE_CORE_HANDOFF, f"could not write {path}: {exc}", path=path)


def _parse_assignments(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        result[key] = value
    return result


def _y_symbols(text: str) -> list[str]:
    assignments = _parse_assignments(text)
    return sorted(key for key, value in assignments.items() if value == "y")


def run_handoff_steps(
    guard: HermeticGuard,
    *,
    annotations: str,
    make: str,
    output_dir: str,
    fragment_path: Path,
) -> dict:
    export_path = os.path.join(output_dir, EXPORT_NAME)
    config_path = os.path.join(output_dir, CONFIG_NAME)
    with hermetic_lockdown():
        exported = _run_handoff_tool(
            guard,
            [annotations, "--export"],
            annotations=annotations,
            make=make,
            output_dir=output_dir,
            cwd=output_dir,
        )
        if exported.returncode != 0 or not exported.stdout:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "annotations --export must exit 0 with nonempty stdout",
                path=annotations,
                expected="exit 0 and nonempty export",
                observed=f"exit {exported.returncode} bytes {len(exported.stdout)}",
            )
        _atomic_write(export_path, exported.stdout)
        export_bytes = Path(export_path).read_bytes()
        fragment_bytes = fragment_path.read_bytes()
        merged = export_bytes
        if merged and not merged.endswith(b"\n"):
            merged += b"\n"
        merged += fragment_bytes
        if merged and not merged.endswith(b"\n"):
            merged += b"\n"
        _atomic_write(config_path, merged)
        olddef = _run_handoff_tool(
            guard,
            [make, "O=" + output_dir, "olddefconfig"],
            annotations=annotations,
            make=make,
            output_dir=output_dir,
            cwd=output_dir,
        )
        if olddef.returncode != 0:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "make olddefconfig failed",
                path=make,
                observed=str(olddef.returncode),
            )
        config_text = Path(config_path).read_text(encoding="utf-8")
        y_lines = _y_symbols(config_text)
        missing = [name for name in FRAGMENT_SYMBOLS if name not in y_lines]
        if missing:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "fragment symbols missing from =y closure",
                path=config_path,
                expected=" ".join(FRAGMENT_SYMBOLS),
                observed=" ".join(y_lines),
            )
        config_sha256 = hashlib.sha256(Path(config_path).read_bytes()).hexdigest()
        built = _run_handoff_tool(
            guard,
            [make, "O=" + output_dir],
            annotations=annotations,
            make=make,
            output_dir=output_dir,
            cwd=output_dir,
        )
        if built.returncode != 0:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "make build failed",
                path=make,
                observed=str(built.returncode),
            )
    return {"config_sha256": config_sha256, "config_y": y_lines}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage then hand off a bounded kernel config/build")
    parser.add_argument("--worktree", required=True)
    parser.add_argument("--git", required=True)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--annotations", required=True)
    parser.add_argument("--annotations-sha256", required=True)
    parser.add_argument("--make", required=True)
    parser.add_argument("--make-sha256", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--derivation-out", default="")
    args = parser.parse_args(argv)
    try:
        manifest = parse_core_manifest(Path(args.manifest).read_bytes())
        worktree = os.path.abspath(args.worktree)
        output_dir = os.path.abspath(args.output_dir)
        git_abs = os.path.abspath(args.git)
        annotations_abs = os.path.abspath(args.annotations)
        make_abs = os.path.abspath(args.make)
        guard = build_handoff_guard(
            git_abs=git_abs,
            git_sha256=args.git_sha256,
            annotations_abs=annotations_abs,
            annotations_sha256=args.annotations_sha256,
            make_abs=make_abs,
            make_sha256=args.make_sha256,
            worktree=worktree,
            manifest=manifest,
        )
        derivation = materialize_worktree(guard, git_abs, worktree, manifest)
        fragment = REPO_ROOT / manifest.diagnostic_config_fragment.path
        record = run_handoff_steps(
            guard,
            annotations=annotations_abs,
            make=make_abs,
            output_dir=output_dir,
            fragment_path=fragment,
        )
        record["derivation"] = derivation
    except SppDiagTraceCoreMaterializeError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    payload = canonical_dumps(record) + b"\n"
    sys.stdout.buffer.write(payload)
    if args.derivation_out:
        Path(args.derivation_out).write_bytes(canonical_dumps(derivation) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
