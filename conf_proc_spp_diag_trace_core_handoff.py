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
from conf_proc_spp_diag_trace_core_manifest import (
    BOOTSTRAP_API_SYMBOLS,
    CORE_API_SYMBOLS,
    RUNTIME_API_SYMBOLS,
    CoreManifest,
    parse_core_manifest,
)
from conf_proc_spp_diag_trace_core_materialize import (
    DEFAULT_MANIFEST,
    REPO_ROOT,
    build_guard,
    materialize_worktree,
)
from conf_proc_spp_diag_trace_core_materialize_reasons import (
    CP_SPP_DIAG_TRACE_CORE_FORBIDDEN_COMMAND,
    CP_SPP_DIAG_TRACE_CORE_HANDOFF,
    CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED,
    CP_SPP_DIAG_TRACE_CORE_TOOL,
    CP_SPP_DIAG_TRACE_CORE_TYPE,
    SppDiagTraceCoreMaterializeError,
)


K1_FRAGMENT_SYMBOLS = (
    "CONFIG_CRYPTO_LIB_SHA256",
    "CONFIG_SECURITY_SPP_DIAG_TRACE_CORE",
)
FRAGMENT_SYMBOLS = {
    "enabled": K1_FRAGMENT_SYMBOLS + ("CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP",),
    "disabled": K1_FRAGMENT_SYMBOLS,
    "runtime": K1_FRAGMENT_SYMBOLS + (
        "CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP",
        "CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME",
        "CONFIG_SECURITYFS",
        "CONFIG_SECURITY_NETWORK",
    ),
}
EXPORT_NAME = ".config.export"
CONFIG_NAME = ".config"
TEMP_SUFFIX = ".spp-diag-trace-core-handoff-tmp"
ANNOTATIONS_CONFIG = "debian.azure-fde-6.8/config/annotations"
CORE_OBJECT_TARGET = "security/spp_diag_trace_core/core.o"
RUNTIME_STATE_TARGET = "security/spp_diag_trace_core/runtime_state.o"
RUNTIME_FS_TARGET = "security/spp_diag_trace_core/runtime_fs.o"
VMLINUX_TARGET = "vmlinux"
CANONICAL_CERT_TARGETS = (
    "debian/canonical-certs.pem",
    "debian/canonical-revoked-certs.pem",
)


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
    nm: str,
    enabled_output_dir: str,
    disabled_output_dir: str,
    runtime_output_dir: str,
) -> None:
    """Refuse any argv outside the exact triple-build and inspection shapes."""

    enabled_o = "O=" + enabled_output_dir
    disabled_o = "O=" + disabled_output_dir
    runtime_o = "O=" + runtime_output_dir
    allowed = (
        [
            annotations,
            "-f",
            ANNOTATIONS_CONFIG,
            "--arch",
            "amd64",
            "--flavour",
            "azure-fde",
            "--export",
        ],
        [make, "-f", "debian/rules", *CANONICAL_CERT_TARGETS],
        [make, enabled_o, "olddefconfig"],
        [make, enabled_o, CORE_OBJECT_TARGET],
        [make, enabled_o, VMLINUX_TARGET],
        [make, disabled_o, "olddefconfig"],
        [make, disabled_o, VMLINUX_TARGET],
        [make, runtime_o, "olddefconfig"],
        [make, runtime_o, CORE_OBJECT_TARGET],
        [make, runtime_o, RUNTIME_STATE_TARGET],
        [make, runtime_o, RUNTIME_FS_TARGET],
        [make, runtime_o, VMLINUX_TARGET],
        [nm, "-g", "--defined-only", os.path.join(enabled_output_dir, VMLINUX_TARGET)],
        [nm, "-g", "--defined-only", os.path.join(disabled_output_dir, VMLINUX_TARGET)],
        [nm, "-g", "--defined-only", os.path.join(runtime_output_dir, VMLINUX_TARGET)],
    )
    if argv in allowed:
        return
    _fail(
        CP_SPP_DIAG_TRACE_CORE_FORBIDDEN_COMMAND,
        "handoff argv is not allowlisted",
        expected=(
            "annotations -f debian.azure-fde-6.8/config/annotations --arch amd64 "
            "--flavour azure-fde --export; exact certificate preparation; enabled, "
            "disabled, and runtime olddefconfig/vmlinux builds; core.o and runtime objects; final nm"
        ),
        observed=" ".join(argv),
    )


def _run_handoff_tool(
    guard: HermeticGuard,
    argv: list[str],
    *,
    annotations: str,
    make: str,
    nm: str,
    enabled_output_dir: str,
    disabled_output_dir: str,
    runtime_output_dir: str,
    cwd: str,
):
    require_handoff_argv(
        argv,
        annotations=annotations,
        make=make,
        nm=nm,
        enabled_output_dir=enabled_output_dir,
        disabled_output_dir=disabled_output_dir,
        runtime_output_dir=runtime_output_dir,
    )
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
    nm_abs: str,
    nm_sha256: str,
    worktree: str,
    manifest: CoreManifest,
) -> HermeticGuard:
    for label, path in (
        ("annotations", annotations_abs),
        ("make", make_abs),
        ("nm", nm_abs),
    ):
        if type(path) is not str or not os.path.isabs(path):
            _fail(CP_SPP_DIAG_TRACE_CORE_TYPE, f"{label} path must be absolute", path=str(path))
        digest = {
            "annotations": annotations_sha256,
            "make": make_sha256,
            "nm": nm_sha256,
        }[label]
        if type(digest) is not str:
            _fail(CP_SPP_DIAG_TRACE_CORE_TYPE, f"{label} sha256 must be a string")
    base = build_guard(git_abs, git_sha256, worktree, manifest)
    allowed = set(base.allowed_reads())
    allowed.add(annotations_abs)
    allowed.add(make_abs)
    allowed.add(nm_abs)
    tools = {
        git_abs: ToolDeclaration(git_abs, git_sha256),
        annotations_abs: ToolDeclaration(annotations_abs, annotations_sha256),
        make_abs: ToolDeclaration(make_abs, make_sha256),
        nm_abs: ToolDeclaration(nm_abs, nm_sha256),
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


def _validate_config_y(leg: str, y_lines: list[str], config_path: str) -> None:
    missing = [name for name in FRAGMENT_SYMBOLS[leg] if name not in y_lines]
    if missing:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_HANDOFF,
            f"fragment symbols missing from {leg} =y closure",
            path=config_path,
            expected=" ".join(FRAGMENT_SYMBOLS[leg]),
            observed=" ".join(y_lines),
        )
    if "CONFIG_IMA" not in y_lines:
        _fail(CP_SPP_DIAG_TRACE_CORE_HANDOFF, "IMA is absent from the annotations closure", path=config_path)
    if "CONFIG_STATIC_USERMODEHELPER" in y_lines:
        _fail(CP_SPP_DIAG_TRACE_CORE_HANDOFF, "STATIC_USERMODEHELPER is enabled", path=config_path)


def _validate_output_dirs(worktree: str, output_dirs: tuple[str, ...]) -> None:
    output_reals = tuple(os.path.realpath(path) for path in output_dirs)
    if len(set(output_reals)) != len(output_reals):
        _fail(
            CP_SPP_DIAG_TRACE_CORE_HANDOFF,
            "output directories must differ",
            observed=" ".join(output_dirs),
        )
    worktree_real = os.path.realpath(worktree)
    for path, path_real in zip(output_dirs, output_reals, strict=True):
        if os.path.islink(path) or not os.path.isdir(path):
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "output directory must be an existing regular directory",
                path=path,
            )
        if os.listdir(path):
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "output directory must be empty",
                path=path,
            )
        if os.path.commonpath((worktree_real, path_real)) == worktree_real:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "build output must remain outside the kernel worktree",
                path=path,
            )


def _capture_fragment(guard: HermeticGuard, path: Path, expected_sha256: str) -> bytes:
    try:
        fragment = guard.read_bytes(str(path))
    except ApplianceError as exc:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED,
            f"could not capture diagnostic config fragment: {exc}",
            path=str(path),
            expected=expected_sha256,
        )
    observed_sha256 = hashlib.sha256(fragment).hexdigest()
    if observed_sha256 != expected_sha256:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED,
            "diagnostic config fragment digest mismatch",
            path=str(path),
            expected=expected_sha256,
            observed=observed_sha256,
        )
    return fragment


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        _fail(CP_SPP_DIAG_TRACE_CORE_HANDOFF, f"could not hash {path}: {exc}", path=path)
    return digest.hexdigest()


def _prepare_config(
    guard: HermeticGuard,
    *,
    exported: bytes,
    fragment: bytes,
    leg: str,
    annotations: str,
    make: str,
    nm: str,
    worktree: str,
    output_dir: str,
    enabled_output_dir: str,
    disabled_output_dir: str,
    runtime_output_dir: str,
) -> dict:
    export_path = os.path.join(output_dir, EXPORT_NAME)
    config_path = os.path.join(output_dir, CONFIG_NAME)
    _atomic_write(export_path, exported)
    merged = exported
    if merged and not merged.endswith(b"\n"):
        merged += b"\n"
    merged += fragment
    if merged and not merged.endswith(b"\n"):
        merged += b"\n"
    _atomic_write(config_path, merged)
    olddef = _run_handoff_tool(
        guard,
        [make, "O=" + output_dir, "olddefconfig"],
        annotations=annotations,
        make=make,
        nm=nm,
        enabled_output_dir=enabled_output_dir,
        disabled_output_dir=disabled_output_dir,
        runtime_output_dir=runtime_output_dir,
        cwd=worktree,
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
    _validate_config_y(leg, y_lines, config_path)
    return {"config_sha256": _sha256_file(config_path), "config_y": y_lines}


def _build(
    guard: HermeticGuard,
    *,
    leg: str,
    annotations: str,
    make: str,
    nm: str,
    worktree: str,
    output_dir: str,
    enabled_output_dir: str,
    disabled_output_dir: str,
    runtime_output_dir: str,
    core_api_symbols: tuple[str, ...],
) -> dict:
    if leg == "enabled":
        targets = (CORE_OBJECT_TARGET, VMLINUX_TARGET)
    elif leg == "disabled":
        targets = (VMLINUX_TARGET,)
    elif leg == "runtime":
        targets = (CORE_OBJECT_TARGET, RUNTIME_STATE_TARGET, RUNTIME_FS_TARGET, VMLINUX_TARGET)
    else:
        targets = (VMLINUX_TARGET,)

    for target in targets:
        built = _run_handoff_tool(
            guard,
            [make, "O=" + output_dir, target],
            annotations=annotations,
            make=make,
            nm=nm,
            enabled_output_dir=enabled_output_dir,
            disabled_output_dir=disabled_output_dir,
            runtime_output_dir=runtime_output_dir,
            cwd=worktree,
        )
        if built.returncode != 0:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                f"make {target} failed",
                path=make,
                observed=str(built.returncode),
            )
    artifact = os.path.join(output_dir, VMLINUX_TARGET)
    if os.path.islink(artifact) or not os.path.isfile(artifact) or os.path.getsize(artifact) == 0:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_HANDOFF,
            "vmlinux is missing, empty, or not a regular file",
            path=artifact,
        )
    inspected = _run_handoff_tool(
        guard,
        [nm, "-g", "--defined-only", artifact],
        annotations=annotations,
        make=make,
        nm=nm,
        enabled_output_dir=enabled_output_dir,
        disabled_output_dir=disabled_output_dir,
        runtime_output_dir=runtime_output_dir,
        cwd=worktree,
    )
    if inspected.returncode != 0 or not inspected.stdout:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_HANDOFF,
            "nm final-artifact inspection failed",
            path=artifact,
            observed=f"exit {inspected.returncode} bytes {len(inspected.stdout)}",
        )
    symbols = {line.split()[-1] for line in inspected.stdout.decode("utf-8", "replace").splitlines() if line.split()}
    if "start_kernel" not in symbols:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_HANDOFF,
            "nm control symbol is absent from final vmlinux",
            path=artifact,
            expected="start_kernel",
        )

    if leg == "runtime":
        k3_core_symbols = tuple(s for s in core_api_symbols if s != "spp_diag_trace_core_append")
        present = tuple(symbol for symbol in k3_core_symbols if symbol in symbols)
        if present != k3_core_symbols:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "runtime vmlinux is missing core API symbols",
                path=artifact,
                expected=" ".join(k3_core_symbols),
                observed=" ".join(present),
            )
        if "spp_diag_trace_core_append" in symbols:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "runtime vmlinux unexpectedly exports raw append symbol",
                path=artifact,
            )
        bootstrap_present = tuple(symbol for symbol in BOOTSTRAP_API_SYMBOLS if symbol in symbols)
        if bootstrap_present != BOOTSTRAP_API_SYMBOLS:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "runtime vmlinux is missing bootstrap API symbols",
                path=artifact,
                expected=" ".join(BOOTSTRAP_API_SYMBOLS),
                observed=" ".join(bootstrap_present),
            )
        runtime_present = tuple(symbol for symbol in RUNTIME_API_SYMBOLS if symbol in symbols)
        if runtime_present != RUNTIME_API_SYMBOLS:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "runtime vmlinux is missing runtime API symbols",
                path=artifact,
                expected=" ".join(RUNTIME_API_SYMBOLS),
                observed=" ".join(runtime_present),
            )
        return {
            "vmlinux_sha256": _sha256_file(artifact),
            "vmlinux_size": os.path.getsize(artifact),
            "core_api_symbols": list(present),
            "bootstrap_api_symbols": list(bootstrap_present),
            "runtime_api_symbols": list(runtime_present),
        }

    present = tuple(symbol for symbol in core_api_symbols if symbol in symbols)
    if present != core_api_symbols:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_HANDOFF,
            "vmlinux is missing core API symbols",
            path=artifact,
            expected=" ".join(core_api_symbols),
            observed=" ".join(present),
        )
    bootstrap_present = tuple(symbol for symbol in BOOTSTRAP_API_SYMBOLS if symbol in symbols)
    if leg == "enabled" and bootstrap_present != BOOTSTRAP_API_SYMBOLS:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_HANDOFF,
            "enabled vmlinux is missing bootstrap API symbols",
            path=artifact,
            expected=" ".join(BOOTSTRAP_API_SYMBOLS),
            observed=" ".join(bootstrap_present),
        )
    if leg == "disabled" and bootstrap_present:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_HANDOFF,
            "K1-on/K2-off vmlinux contains bootstrap API symbols",
            path=artifact,
            expected="no bootstrap API symbols",
            observed=" ".join(bootstrap_present),
        )
    runtime_present = tuple(symbol for symbol in RUNTIME_API_SYMBOLS if symbol in symbols)
    if runtime_present:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_HANDOFF,
            f"{leg} vmlinux unexpectedly contains runtime API symbols",
            path=artifact,
            expected="no runtime API symbols",
            observed=" ".join(runtime_present),
        )
    return {
        "vmlinux_sha256": _sha256_file(artifact),
        "vmlinux_size": os.path.getsize(artifact),
        "core_api_symbols": list(present),
        "bootstrap_api_symbols": list(bootstrap_present),
    }


def run_handoff_steps(
    guard: HermeticGuard,
    *,
    annotations: str,
    make: str,
    nm: str,
    worktree: str,
    enabled_output_dir: str,
    disabled_output_dir: str,
    runtime_output_dir: str,
    fragments: dict[str, bytes],
    core_api_symbols: tuple[str, ...],
) -> dict:
    with hermetic_lockdown():
        exported = _run_handoff_tool(
            guard,
            [
                annotations,
                "-f",
                ANNOTATIONS_CONFIG,
                "--arch",
                "amd64",
                "--flavour",
                "azure-fde",
                "--export",
            ],
            annotations=annotations,
            make=make,
            nm=nm,
            enabled_output_dir=enabled_output_dir,
            disabled_output_dir=disabled_output_dir,
            runtime_output_dir=runtime_output_dir,
            cwd=worktree,
        )
        if exported.returncode != 0 or not exported.stdout:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "annotations export must exit 0 with nonempty stdout",
                path=annotations,
                expected="exit 0 and nonempty export",
                observed=f"exit {exported.returncode} bytes {len(exported.stdout)}",
            )
        enabled = _prepare_config(
            guard,
            exported=exported.stdout,
            fragment=fragments["enabled"],
            leg="enabled",
            annotations=annotations,
            make=make,
            nm=nm,
            worktree=worktree,
            output_dir=enabled_output_dir,
            enabled_output_dir=enabled_output_dir,
            disabled_output_dir=disabled_output_dir,
            runtime_output_dir=runtime_output_dir,
        )
        disabled = _prepare_config(
            guard,
            exported=exported.stdout,
            fragment=fragments["disabled"],
            leg="disabled",
            annotations=annotations,
            make=make,
            nm=nm,
            worktree=worktree,
            output_dir=disabled_output_dir,
            enabled_output_dir=enabled_output_dir,
            disabled_output_dir=disabled_output_dir,
            runtime_output_dir=runtime_output_dir,
        )
        runtime = _prepare_config(
            guard,
            exported=exported.stdout,
            fragment=fragments["runtime"],
            leg="runtime",
            annotations=annotations,
            make=make,
            nm=nm,
            worktree=worktree,
            output_dir=runtime_output_dir,
            enabled_output_dir=enabled_output_dir,
            disabled_output_dir=disabled_output_dir,
            runtime_output_dir=runtime_output_dir,
        )
        cert_paths = tuple(os.path.join(worktree, target) for target in CANONICAL_CERT_TARGETS)
        if any(os.path.lexists(path) for path in cert_paths):
            _fail(
                CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                "canonical certificate output already exists",
                observed=" ".join(path for path in cert_paths if os.path.lexists(path)),
            )
        try:
            certificates = _run_handoff_tool(
                guard,
                [make, "-f", "debian/rules", *CANONICAL_CERT_TARGETS],
                annotations=annotations,
                make=make,
                nm=nm,
                enabled_output_dir=enabled_output_dir,
                disabled_output_dir=disabled_output_dir,
                runtime_output_dir=runtime_output_dir,
                cwd=worktree,
            )
            if certificates.returncode != 0:
                _fail(
                    CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                    "canonical certificate preparation failed",
                    path=make,
                    observed=str(certificates.returncode),
                )
            for path in cert_paths:
                if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) == 0:
                    _fail(
                        CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                        "canonical certificate preparation produced an invalid file",
                        path=path,
                    )
            enabled.update(
                _build(
                    guard,
                    leg="enabled",
                    annotations=annotations,
                    make=make,
                    nm=nm,
                    worktree=worktree,
                    output_dir=enabled_output_dir,
                    enabled_output_dir=enabled_output_dir,
                    disabled_output_dir=disabled_output_dir,
                    runtime_output_dir=runtime_output_dir,
                    core_api_symbols=core_api_symbols,
                )
            )
            disabled.update(
                _build(
                    guard,
                    leg="disabled",
                    annotations=annotations,
                    make=make,
                    nm=nm,
                    worktree=worktree,
                    output_dir=disabled_output_dir,
                    enabled_output_dir=enabled_output_dir,
                    disabled_output_dir=disabled_output_dir,
                    runtime_output_dir=runtime_output_dir,
                    core_api_symbols=core_api_symbols,
                )
            )
            runtime.update(
                _build(
                    guard,
                    leg="runtime",
                    annotations=annotations,
                    make=make,
                    nm=nm,
                    worktree=worktree,
                    output_dir=runtime_output_dir,
                    enabled_output_dir=enabled_output_dir,
                    disabled_output_dir=disabled_output_dir,
                    runtime_output_dir=runtime_output_dir,
                    core_api_symbols=core_api_symbols,
                )
            )
        finally:
            for path in cert_paths:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    _fail(
                        CP_SPP_DIAG_TRACE_CORE_HANDOFF,
                        f"could not remove generated certificate input: {exc}",
                        path=path,
                    )
    return {"enabled": enabled, "disabled": disabled, "runtime": runtime}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage then hand off a bounded kernel config/build")
    parser.add_argument("--worktree", required=True)
    parser.add_argument("--git", required=True)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--annotations", required=True)
    parser.add_argument("--annotations-sha256", required=True)
    parser.add_argument("--make", required=True)
    parser.add_argument("--make-sha256", required=True)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--nm-sha256", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--disabled-output-dir", required=True)
    parser.add_argument("--runtime-output-dir", required=True)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--derivation-out", default="")
    args = parser.parse_args(argv)
    try:
        manifest = parse_core_manifest(Path(args.manifest).read_bytes())
        worktree = os.path.abspath(args.worktree)
        output_dir = os.path.abspath(args.output_dir)
        disabled_output_dir = os.path.abspath(args.disabled_output_dir)
        runtime_output_dir = os.path.abspath(args.runtime_output_dir)
        git_abs = os.path.abspath(args.git)
        annotations_abs = os.path.abspath(args.annotations)
        make_abs = os.path.abspath(args.make)
        nm_abs = os.path.abspath(args.nm)
        _validate_output_dirs(worktree, (output_dir, disabled_output_dir, runtime_output_dir))
        guard = build_handoff_guard(
            git_abs=git_abs,
            git_sha256=args.git_sha256,
            annotations_abs=annotations_abs,
            annotations_sha256=args.annotations_sha256,
            make_abs=make_abs,
            make_sha256=args.make_sha256,
            nm_abs=nm_abs,
            nm_sha256=args.nm_sha256,
            worktree=worktree,
            manifest=manifest,
        )
        fragments = {
            item.leg: _capture_fragment(guard, REPO_ROOT / item.path, item.sha256)
            for item in manifest.diagnostic_config_fragments
        }
        derivation = materialize_worktree(guard, git_abs, worktree, manifest)
        record = run_handoff_steps(
            guard,
            annotations=annotations_abs,
            make=make_abs,
            nm=nm_abs,
            worktree=worktree,
            enabled_output_dir=output_dir,
            disabled_output_dir=disabled_output_dir,
            runtime_output_dir=runtime_output_dir,
            fragments=fragments,
            core_api_symbols=manifest.core_api_symbols,
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
