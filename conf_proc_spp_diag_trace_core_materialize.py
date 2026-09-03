#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Stage the dormant SPP diagnostic trace core onto a kernel git worktree."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path

from conf_proc_guard import HermeticGuard, ToolDeclaration
from conf_proc_json import canonical_dumps
from conf_proc_reasons import ApplianceError
from conf_proc_spp_diag_trace_core_manifest import (
    CoreManifest,
    ReplaceTarget,
    parse_core_manifest,
)
from conf_proc_spp_diag_trace_core_materialize_reasons import (
    CP_SPP_DIAG_TRACE_CORE_AUTHORITY,
    CP_SPP_DIAG_TRACE_CORE_BASE_COMMIT,
    CP_SPP_DIAG_TRACE_CORE_CREATE_COLLISION,
    CP_SPP_DIAG_TRACE_CORE_DIRTY_STAGED,
    CP_SPP_DIAG_TRACE_CORE_DIRTY_UNSTAGED,
    CP_SPP_DIAG_TRACE_CORE_DIRTY_UNTRACKED,
    CP_SPP_DIAG_TRACE_CORE_GIT_ARGV,
    CP_SPP_DIAG_TRACE_CORE_GIT_PROBE,
    CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED,
    CP_SPP_DIAG_TRACE_CORE_INPUT_MISSING,
    CP_SPP_DIAG_TRACE_CORE_INPUT_UNMANIFESTED,
    CP_SPP_DIAG_TRACE_CORE_PARTIAL_APPLY,
    CP_SPP_DIAG_TRACE_CORE_PATH_ESCAPE,
    CP_SPP_DIAG_TRACE_CORE_REPLACE_CHANGED,
    CP_SPP_DIAG_TRACE_CORE_REPLACE_MISSING,
    CP_SPP_DIAG_TRACE_CORE_SCHEMA,
    CP_SPP_DIAG_TRACE_CORE_STAGING,
    CP_SPP_DIAG_TRACE_CORE_SYMLINK,
    CP_SPP_DIAG_TRACE_CORE_TOOL,
    CP_SPP_DIAG_TRACE_CORE_TYPE,
    CP_SPP_DIAG_TRACE_CORE_WORKTREE,
    SppDiagTraceCoreMaterializeError,
)


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_MANIFEST = REPO_ROOT / "spp-diag-trace-core-src" / "manifest.json"
SOURCE_TREE_DIR = "spp-diag-trace-core-src"
TEMP_SUFFIX = ".spp-diag-trace-core-tmp"

_TEST_EXPECTED_BASE_COMMIT_OVERRIDE: str | None = None

_ALLOWED_GIT_SUFFIXES = frozenset(
    {
        ("rev-parse", "--verify", "HEAD"),
        ("status", "--porcelain=v2"),
        ("diff", "--quiet"),
        ("diff", "--quiet", "--cached"),
        ("ls-files", "-z"),
        ("ls-files", "-z", "--others", "--exclude-standard"),
    }
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


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _resolve_expected_base_commit(manifest: CoreManifest) -> str:
    if _TEST_EXPECTED_BASE_COMMIT_OVERRIDE is not None:
        return _TEST_EXPECTED_BASE_COMMIT_OVERRIDE
    return manifest.expected_base_commit


def _resolve_repo_path(relative: str) -> Path:
    return REPO_ROOT / relative


def _inside_worktree(worktree: str, destination: str) -> str:
    if not destination or destination.startswith("/") or destination.startswith("\\"):
        _fail(
            CP_SPP_DIAG_TRACE_CORE_PATH_ESCAPE,
            "destination must be a relative path",
            path=destination,
        )
    parts = destination.split("/")
    if any(part in ("", ".", "..") for part in parts):
        _fail(
            CP_SPP_DIAG_TRACE_CORE_PATH_ESCAPE,
            "destination must not contain empty, '.', or '..' segments",
            path=destination,
        )
    joined = os.path.normpath(os.path.join(worktree, destination))
    worktree_norm = os.path.normpath(worktree)
    if joined != worktree_norm and not joined.startswith(worktree_norm + os.sep):
        _fail(
            CP_SPP_DIAG_TRACE_CORE_PATH_ESCAPE,
            "destination escapes the worktree",
            path=destination,
            expected=worktree_norm,
            observed=joined,
        )
    return joined


def _lstat(path: str) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _is_symlink(path: str) -> bool:
    info = _lstat(path)
    return info is not None and stat.S_ISLNK(info.st_mode)


def _refuse_symlink(path: str) -> None:
    if _is_symlink(path):
        _fail(
            CP_SPP_DIAG_TRACE_CORE_SYMLINK,
            "path is a symlink",
            path=path,
            expected="regular directory or file",
            observed="symlink",
        )


def _parents_to_worktree(worktree: str, dest: str) -> list[str]:
    paths = []
    current = dest
    worktree_norm = os.path.normpath(worktree)
    while True:
        parent = os.path.dirname(current)
        if parent == current or os.path.normpath(parent) == worktree_norm:
            break
        paths.append(parent)
        current = parent
    paths.append(worktree)
    return paths


def _run_git(guard: HermeticGuard, git_abs: str, worktree: str, suffix: tuple[str, ...]):
    if suffix not in _ALLOWED_GIT_SUFFIXES:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_GIT_ARGV,
            "git argv suffix is not allowlisted",
            path=git_abs,
            expected="one of the six pinned git templates",
            observed=" ".join(suffix),
        )
    try:
        return guard.run_tool([git_abs, "-C", worktree, *suffix], cwd=worktree, check=False)
    except ApplianceError as exc:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_TOOL,
            f"git invocation failed: {exc}",
            path=git_abs,
        )


def _decode_stdout(payload: bytes) -> str:
    return payload.decode("utf-8", "replace")


def _parse_head(stdout: bytes, returncode: int) -> str | None:
    text = _decode_stdout(stdout).strip()
    if returncode != 0 or not text:
        return None
    if len(text) != 40 or text != text.lower() or any(c not in "0123456789abcdef" for c in text):
        return None
    return text


def _preflight_worktree(worktree: str) -> None:
    if type(worktree) is not str or not worktree:
        _fail(CP_SPP_DIAG_TRACE_CORE_TYPE, "worktree must be a nonempty string")
    if not os.path.isabs(worktree):
        _fail(
            CP_SPP_DIAG_TRACE_CORE_WORKTREE,
            "worktree must be an absolute path",
            path=worktree,
        )
    _refuse_symlink(worktree)
    info = _lstat(worktree)
    if info is None or not stat.S_ISDIR(info.st_mode):
        _fail(
            CP_SPP_DIAG_TRACE_CORE_WORKTREE,
            "worktree is missing or not a directory",
            path=worktree,
        )


def _preflight_git(
    guard: HermeticGuard,
    git_abs: str,
    worktree: str,
    expected_base: str,
) -> str:
    _refuse_symlink(git_abs)
    head = _run_git(guard, git_abs, worktree, ("rev-parse", "--verify", "HEAD"))
    parsed = _parse_head(head.stdout, head.returncode)
    if parsed is None:
        observed = _decode_stdout(head.stdout).strip()
        _fail(
            CP_SPP_DIAG_TRACE_CORE_GIT_PROBE,
            "git HEAD probe is empty or unparseable",
            path=worktree,
            expected="40 lowercase hex characters",
            observed=observed if observed else "<empty>",
        )
    if parsed != expected_base:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_BASE_COMMIT,
            "worktree HEAD is not the expected base commit",
            path=worktree,
            expected=expected_base,
            observed=parsed,
        )
    staged = _run_git(guard, git_abs, worktree, ("diff", "--quiet", "--cached"))
    if staged.returncode == 1:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_DIRTY_STAGED,
            "worktree has staged changes",
            path=worktree,
            expected="clean index",
            observed="git diff --quiet --cached exited 1",
        )
    if staged.returncode != 0:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_GIT_PROBE,
            "could not determine staged dirt",
            path=worktree,
            observed=str(staged.returncode),
        )
    unstaged = _run_git(guard, git_abs, worktree, ("diff", "--quiet"))
    if unstaged.returncode == 1:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_DIRTY_UNSTAGED,
            "worktree has unstaged changes",
            path=worktree,
            expected="clean worktree",
            observed="git diff --quiet exited 1",
        )
    if unstaged.returncode != 0:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_GIT_PROBE,
            "could not determine unstaged dirt",
            path=worktree,
            observed=str(unstaged.returncode),
        )
    others = _run_git(
        guard, git_abs, worktree, ("ls-files", "-z", "--others", "--exclude-standard")
    )
    if others.returncode != 0:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_GIT_PROBE,
            "could not list untracked files",
            path=worktree,
            observed=str(others.returncode),
        )
    untracked = [item for item in others.stdout.split(b"\0") if item]
    if untracked:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_DIRTY_UNTRACKED,
            "worktree has untracked files",
            path=worktree,
            expected="no untracked files",
            observed=untracked[0].decode("utf-8", "replace"),
        )
    porcelain = _run_git(guard, git_abs, worktree, ("status", "--porcelain=v2"))
    if porcelain.returncode != 0:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_GIT_PROBE,
            "git status --porcelain=v2 failed",
            path=worktree,
            observed=str(porcelain.returncode),
        )
    status_text = _decode_stdout(porcelain.stdout)
    if status_text.strip():
        _fail(
            CP_SPP_DIAG_TRACE_CORE_DIRTY_UNSTAGED,
            "git status reports a dirty worktree",
            path=worktree,
            observed=status_text.splitlines()[0],
        )
    tracked = _run_git(guard, git_abs, worktree, ("ls-files", "-z"))
    if tracked.returncode != 0:
        _fail(
            CP_SPP_DIAG_TRACE_CORE_GIT_PROBE,
            "could not list tracked files",
            path=worktree,
            observed=str(tracked.returncode),
        )
    return expected_base


def _preflight_inputs(manifest: CoreManifest) -> None:
    authority = manifest.protocol_authority
    for relative, expected in (
        (authority.header, authority.header_sha256),
        (authority.source, authority.source_sha256),
    ):
        path = _resolve_repo_path(relative)
        if not path.is_file() or path.is_symlink():
            _fail(
                CP_SPP_DIAG_TRACE_CORE_AUTHORITY,
                "protocol-authority blob is missing",
                path=str(path),
                expected=expected,
            )
        actual = _sha256_file(path)
        if actual != expected:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_AUTHORITY,
                "protocol-authority blob digest mismatch",
                path=str(path),
                expected=expected,
                observed=actual,
            )
    manifested = {item.path: item for item in manifest.inputs}
    for item in manifest.inputs:
        path = _resolve_repo_path(item.path)
        if not path.is_file():
            _fail(
                CP_SPP_DIAG_TRACE_CORE_INPUT_MISSING,
                "manifested input is missing",
                path=str(path),
                expected=item.sha256,
            )
        if path.is_symlink():
            _fail(
                CP_SPP_DIAG_TRACE_CORE_SYMLINK,
                "manifested input is a symlink",
                path=str(path),
            )
        actual = _sha256_file(path)
        if actual != item.sha256:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED,
                "manifested input digest mismatch",
                path=str(path),
                expected=item.sha256,
                observed=actual,
            )
    source_dir = _resolve_repo_path(SOURCE_TREE_DIR)
    if source_dir.is_dir():
        for dirpath, _dirnames, filenames in os.walk(source_dir):
            for name in filenames:
                full = Path(dirpath) / name
                relative = str(full.relative_to(REPO_ROOT))
                if relative == "spp-diag-trace-core-src/manifest.json":
                    continue
                if relative not in manifested:
                    _fail(
                        CP_SPP_DIAG_TRACE_CORE_INPUT_UNMANIFESTED,
                        "source tree contains an unmanifested file",
                        path=relative,
                    )


def _replace_postimage(
    existing: bytes,
    anchor_line: str,
    placement: str = "eof-append",
    insertion: str = "",
) -> bytes:
    anchor = anchor_line.encode("utf-8")
    if placement == "eof-append":
        body = existing
        if body and not body.endswith(b"\n"):
            body += b"\n"
        return body + anchor + b"\n"
    if placement in ("anchor-insert", "anchor-replace"):
        if existing.count(anchor) != 1:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_PARTIAL_APPLY,
                "anchor REPLACE anchor does not occur exactly once",
                expected="one exact anchor occurrence",
                observed=str(existing.count(anchor)),
            )
        offset = existing.index(anchor)
        if placement == "anchor-replace":
            return existing[:offset] + insertion.encode("utf-8") + existing[offset + len(anchor):]
        offset += len(anchor)
        return existing[:offset] + insertion.encode("utf-8") + existing[offset:]
    _fail(CP_SPP_DIAG_TRACE_CORE_SCHEMA, "unsupported REPLACE placement")


def _validated_replace_images(
    dest: str, replaces: tuple[ReplaceTarget, ...]
) -> tuple[bytes, int, bytes]:
    _refuse_symlink(dest)
    info = _lstat(dest)
    if info is None or not stat.S_ISREG(info.st_mode):
        _fail(
            CP_SPP_DIAG_TRACE_CORE_REPLACE_MISSING,
            "REPLACE destination is missing",
            path=replaces[0].destination,
        )
    existing = Path(dest).read_bytes()
    original = existing
    mode = stat.S_IMODE(info.st_mode)
    for replace in replaces:
        if mode != replace.preimage_mode:
            _fail(CP_SPP_DIAG_TRACE_CORE_REPLACE_CHANGED,
                  "REPLACE destination mode differs from its preimage",
                  path=replace.destination, expected=oct(replace.preimage_mode),
                  observed=oct(mode))
        if replace.placement == "eof-append" and replace.anchor_line.encode("utf-8") in existing:
            _fail(CP_SPP_DIAG_TRACE_CORE_PARTIAL_APPLY,
                  "eof-append anchor line is already present",
                  path=replace.destination, expected=f"absent {replace.anchor_line!r}",
                  observed="anchor line already in file")
        digest = _sha256_bytes(existing)
        if digest != replace.preimage_sha256:
            _fail(CP_SPP_DIAG_TRACE_CORE_REPLACE_CHANGED,
                  "REPLACE destination digest differs from its preimage",
                  path=replace.destination, expected=replace.preimage_sha256,
                  observed=digest)
        postimage = _replace_postimage(existing, replace.anchor_line,
                                       replace.placement, replace.insertion)
        postimage_digest = _sha256_bytes(postimage)
        if replace.postimage_mode != mode or postimage_digest != replace.postimage_sha256:
            _fail(CP_SPP_DIAG_TRACE_CORE_SCHEMA,
                  "REPLACE postimage does not match its declared mode and digest",
                  path=replace.destination,
                  expected=f"mode={oct(replace.postimage_mode)} sha256={replace.postimage_sha256}",
                  observed=f"mode={oct(mode)} sha256={postimage_digest}")
        existing = postimage
    return original, mode, existing


def _preflight_destinations(worktree: str, manifest: CoreManifest) -> None:
    for create in manifest.creates:
        dest = _inside_worktree(worktree, create.destination)
        for parent in _parents_to_worktree(worktree, dest):
            _refuse_symlink(parent)
        if _lstat(dest) is not None:
            _fail(
                CP_SPP_DIAG_TRACE_CORE_CREATE_COLLISION,
                "CREATE destination already exists",
                path=create.destination,
            )
    grouped: dict[str, list[ReplaceTarget]] = {}
    for replace in manifest.replaces:
        grouped.setdefault(replace.destination, []).append(replace)
    for destination, replaces in grouped.items():
        dest = _inside_worktree(worktree, destination)
        _validated_replace_images(dest, tuple(replaces))


def _apply(worktree: str, manifest: CoreManifest) -> None:
    temps: list[str] = []
    created: list[str] = []
    created_dirs: list[str] = []
    replaced: list[tuple[str, bytes, int]] = []
    try:
        planned: list[tuple[str, bytes, int | None]] = []
        replace_originals: dict[str, tuple[bytes, int]] = {}
        for create in manifest.creates:
            dest = _inside_worktree(worktree, create.destination)
            source = _resolve_repo_path(create.source)
            data = source.read_bytes()
            digest = _sha256_bytes(data)
            if digest != create.sha256:
                _fail(
                    CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED,
                    "CREATE source changed before apply",
                    path=create.source,
                    expected=create.sha256,
                    observed=digest,
                )
            planned.append((dest, data, create.mode))
        grouped: dict[str, list[ReplaceTarget]] = {}
        for replace in manifest.replaces:
            grouped.setdefault(replace.destination, []).append(replace)
        for destination, replaces in grouped.items():
            dest = _inside_worktree(worktree, destination)
            existing, original_mode, postimage = _validated_replace_images(
                dest, tuple(replaces)
            )
            replace_originals[dest] = (existing, original_mode)
            planned.append(
                (
                    dest,
                    postimage,
                    replaces[-1].postimage_mode,
                )
            )
        create_dests = {
            _inside_worktree(worktree, item.destination) for item in manifest.creates
        }
        temp_paths: list[tuple[str, str, int | None]] = []
        for dest, data, mode in planned:
            parent = os.path.dirname(dest)
            if not os.path.isdir(parent):
                current = parent
                missing_dirs: list[str] = []
                while not os.path.isdir(current):
                    missing_dirs.append(current)
                    current = os.path.dirname(current)
                os.makedirs(parent, exist_ok=True)
                created_dirs.extend(reversed(missing_dirs))
            temp = dest + TEMP_SUFFIX
            with open(temp, "wb") as handle:
                handle.write(data)
            if mode is not None:
                os.chmod(temp, mode)
            temps.append(temp)
            temp_paths.append((temp, dest, mode))
        for temp, dest, mode in temp_paths:
            os.rename(temp, dest)
            temps.remove(temp)
            if dest in create_dests:
                created.append(dest)
            elif dest in replace_originals:
                original, original_mode = replace_originals[dest]
                replaced.append((dest, original, original_mode))
    except SppDiagTraceCoreMaterializeError:
        _rollback(temps, created, created_dirs, replaced)
        raise
    except OSError as exc:
        _rollback(temps, created, created_dirs, replaced)
        _fail(
            CP_SPP_DIAG_TRACE_CORE_STAGING,
            f"atomic apply failed: {exc}",
            observed=str(exc),
        )


def _rollback(
    temps: list[str],
    created: list[str],
    created_dirs: list[str],
    replaced: list[tuple[str, bytes, int]],
) -> None:
    for path in temps:
        try:
            os.unlink(path)
        except OSError:
            pass
    for dest, original, original_mode in replaced:
        restore = dest + TEMP_SUFFIX
        try:
            with open(restore, "wb") as handle:
                handle.write(original)
            os.chmod(restore, original_mode)
            os.rename(restore, dest)
        except OSError:
            try:
                os.unlink(restore)
            except OSError:
                pass
    for path in created:
        try:
            os.unlink(path)
        except OSError:
            pass
    for path in reversed(created_dirs):
        try:
            os.rmdir(path)
        except OSError:
            pass


def _derivation_record(manifest: CoreManifest, base_commit: str) -> dict:
    return {
        "base_commit": base_commit,
        "core_api_symbols": list(manifest.core_api_symbols),
        "protocol_authority": {
            "header": manifest.protocol_authority.header,
            "header_sha256": manifest.protocol_authority.header_sha256,
            "source": manifest.protocol_authority.source,
            "source_sha256": manifest.protocol_authority.source_sha256,
        },
        "inputs": [
            {"path": item.path, "sha256": item.sha256, "mode": item.mode}
            for item in manifest.inputs
        ],
        "creates": [
            {"destination": item.destination, "sha256": item.sha256, "mode": item.mode}
            for item in manifest.creates
        ],
        "replaces": [
            {
                "destination": item.destination,
                "anchor_line": item.anchor_line,
                "placement": item.placement,
                "insertion": item.insertion,
                "preimage_mode": item.preimage_mode,
                "preimage_sha256": item.preimage_sha256,
                "postimage_mode": item.postimage_mode,
                "postimage_sha256": item.postimage_sha256,
            }
            for item in manifest.replaces
        ],
        "diagnostic_config_fragments": [
            {"leg": item.leg, "path": item.path, "sha256": item.sha256}
            for item in manifest.diagnostic_config_fragments
        ],
    }


def build_guard(git_abs: str, git_sha256: str, worktree: str, manifest: CoreManifest) -> HermeticGuard:
    if type(git_abs) is not str or not os.path.isabs(git_abs):
        _fail(CP_SPP_DIAG_TRACE_CORE_TYPE, "git path must be absolute", path=str(git_abs))
    if type(git_sha256) is not str or len(git_sha256) != 64:
        _fail(CP_SPP_DIAG_TRACE_CORE_TYPE, "git sha256 must be 64 hex characters")
    allowed = {git_abs}
    for item in manifest.inputs:
        allowed.add(str(_resolve_repo_path(item.path)))
    allowed.add(str(_resolve_repo_path(manifest.protocol_authority.header)))
    allowed.add(str(_resolve_repo_path(manifest.protocol_authority.source)))
    for replace in manifest.replaces:
        allowed.add(os.path.join(worktree, replace.destination))
    try:
        return HermeticGuard(
            allowed_reads=frozenset(allowed),
            tools={git_abs: ToolDeclaration(git_abs, git_sha256)},
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"},
            build_epoch=0,
        )
    except ApplianceError as exc:
        _fail(CP_SPP_DIAG_TRACE_CORE_TOOL, f"could not construct hermetic guard: {exc}")


def materialize_worktree(
    guard: HermeticGuard,
    git_abs: str,
    worktree: str,
    manifest: CoreManifest,
) -> dict:
    _preflight_worktree(worktree)
    expected_base = _resolve_expected_base_commit(manifest)
    _preflight_git(guard, git_abs, worktree, expected_base)
    _preflight_inputs(manifest)
    _preflight_destinations(worktree, manifest)
    _apply(worktree, manifest)
    return _derivation_record(manifest, expected_base)


def _load_manifest(path: Path) -> CoreManifest:
    return parse_core_manifest(path.read_bytes())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage the SPP diagnostic trace core onto a kernel git worktree")
    parser.add_argument("--worktree", required=True)
    parser.add_argument("--git", required=True)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--derivation-out", default="")
    args = parser.parse_args(argv)
    try:
        manifest = _load_manifest(Path(args.manifest))
        worktree = os.path.abspath(args.worktree)
        git_abs = os.path.abspath(args.git)
        guard = build_guard(git_abs, args.git_sha256, worktree, manifest)
        record = materialize_worktree(guard, git_abs, worktree, manifest)
    except SppDiagTraceCoreMaterializeError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    payload = canonical_dumps(record) + b"\n"
    sys.stdout.buffer.write(payload)
    if args.derivation_out:
        Path(args.derivation_out).write_bytes(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
