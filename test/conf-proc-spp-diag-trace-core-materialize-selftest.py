#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""AC1/AC2 materializer tests against real two-commit git fixtures."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_spp_diag_trace_core_materialize as materialize  # noqa: E402
from conf_proc_json import canonical_dumps, canonical_loads  # noqa: E402
from conf_proc_spp_diag_trace_core_manifest import parse_core_manifest  # noqa: E402
from conf_proc_spp_diag_trace_core_materialize_reasons import (  # noqa: E402
    CP_SPP_DIAG_TRACE_CORE_BASE_COMMIT,
    CP_SPP_DIAG_TRACE_CORE_CREATE_COLLISION,
    CP_SPP_DIAG_TRACE_CORE_DIRTY_STAGED,
    CP_SPP_DIAG_TRACE_CORE_DIRTY_UNSTAGED,
    CP_SPP_DIAG_TRACE_CORE_DIRTY_UNTRACKED,
    CP_SPP_DIAG_TRACE_CORE_GIT_PROBE,
    CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED,
    CP_SPP_DIAG_TRACE_CORE_INPUT_MISSING,
    CP_SPP_DIAG_TRACE_CORE_INPUT_UNMANIFESTED,
    CP_SPP_DIAG_TRACE_CORE_PARTIAL_APPLY,
    CP_SPP_DIAG_TRACE_CORE_REPLACE_CHANGED,
    CP_SPP_DIAG_TRACE_CORE_SCHEMA,
    CP_SPP_DIAG_TRACE_CORE_SYMLINK,
    SppDiagTraceCoreMaterializeError,
)


GIT = os.path.realpath(shutil.which("git") or "/usr/bin/git")
GIT_SHA256 = hashlib.sha256(Path(GIT).read_bytes()).hexdigest()
FAILURES = 0
FIXTURE_MANIFESTS: dict[str, str] = {}


def _run(argv: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=cwd, check=True, capture_output=True)


def _git(cwd: str, *args: str) -> str:
    result = _run(
        [GIT, "-c", "user.name=k1-test", "-c", "user.email=k1@example.test", *args],
        cwd,
    )
    return result.stdout.decode("utf-8", "replace")


def _write_fixture_manifest(repo: str, scratch: str) -> str:
    parsed = parse_core_manifest(
        (ROOT / "spp-diag-trace-core-src" / "manifest.json").read_bytes()
    )
    raw = dict(parsed.raw)
    targets = []
    for target in parsed.raw["targets"]:
        updated = dict(target)
        if target["kind"] == "REPLACE":
            path = Path(repo) / target["destination"]
            preimage = path.read_bytes()
            mode = stat.S_IMODE(path.stat().st_mode)
            postimage = materialize._replace_postimage(preimage, target["anchor_line"])
            updated.update(
                {
                    "preimage_mode": mode,
                    "preimage_sha256": hashlib.sha256(preimage).hexdigest(),
                    "postimage_mode": mode,
                    "postimage_sha256": hashlib.sha256(postimage).hexdigest(),
                }
            )
        targets.append(updated)
    raw["targets"] = targets
    path = os.path.join(scratch, "fixture-manifest.json")
    Path(path).write_bytes(canonical_dumps(raw))
    return path


def _tree_fingerprint(root: str) -> dict[str, str]:
    records: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, root)
        info = os.lstat(dirpath)
        records["dir:" + rel_dir] = f"dir {stat.S_IMODE(info.st_mode)}"
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                records[rel] = "symlink->" + os.readlink(full)
            else:
                records[rel] = hashlib.sha256(Path(full).read_bytes()).hexdigest()
    return records


def _make_fixture(scratch: str) -> tuple[str, str, str]:
    repo = os.path.join(scratch, "repo")
    os.makedirs(os.path.join(repo, "security"))
    Path(os.path.join(repo, "security", "Kconfig")).write_text(
        'menu "Security options"\nendmenu\n', encoding="utf-8"
    )
    Path(os.path.join(repo, "security", "Makefile")).write_text("obj-y += dummy/\n", encoding="utf-8")
    Path(os.path.join(repo, "README")).write_text("fixture\n", encoding="utf-8")
    _git(repo, "init")
    _git(repo, "add", "security/Kconfig", "security/Makefile", "README")
    _git(repo, "commit", "-m", "base")
    first = _git(repo, "rev-parse", "--verify", "HEAD").strip()
    Path(os.path.join(repo, "README")).write_text("fixture-second\n", encoding="utf-8")
    _git(repo, "add", "README")
    _git(repo, "commit", "-m", "second")
    second = _git(repo, "rev-parse", "--verify", "HEAD").strip()
    _git(repo, "checkout", "-q", first)
    FIXTURE_MANIFESTS[os.path.realpath(repo)] = _write_fixture_manifest(repo, scratch)
    return repo, first, second


class _ByteStdout:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def write(self, data: object) -> int:
        if isinstance(data, bytes):
            self.buffer.write(data)
            return len(data)
        text = str(data)
        encoded = text.encode("utf-8")
        self.buffer.write(encoded)
        return len(encoded)

    def flush(self) -> None:
        return None


def _materialize(worktree: str, extra: list[str] | None = None):
    argv = [
        "--worktree",
        worktree,
        "--git",
        GIT,
        "--git-sha256",
        GIT_SHA256,
    ]
    if not extra or "--manifest" not in extra:
        argv.extend(["--manifest", FIXTURE_MANIFESTS[os.path.realpath(worktree)]])
    if extra:
        argv.extend(extra)
    stdout = _ByteStdout()
    stderr = io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = stdout, stderr
    try:
        code = materialize.main(argv)
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    return SimpleNamespace(
        returncode=code,
        stdout=stdout.buffer.getvalue(),
        stderr=stderr.getvalue().encode("utf-8"),
    )


def _expect_reason(stderr: bytes, code: str) -> None:
    text = stderr.decode("utf-8", "replace")
    if code not in text:
        raise AssertionError(f"missing reason {code} in stderr:\n{text}")
    for token in ("precondition:", "path:", "expected:", "observed:", "recovery:"):
        if token not in text:
            raise AssertionError(f"missing {token} in stderr:\n{text}")


def _assert_unchanged(before: dict[str, str], root: str) -> None:
    after = _tree_fingerprint(root)
    if after != before:
        raise AssertionError(f"worktree mutated on refusal: {before} vs {after}")


CORE_SRC_REL = "spp-diag-trace-core-src/security/spp_diag_trace_core"
REAL_MANIFEST = ROOT / "spp-diag-trace-core-src" / "manifest.json"


def _throwaway_manifest(
    scratch: str,
    repo: str,
    retarget: dict[str, str],
    *,
    authority_abs: bool = False,
) -> str:
    parsed = parse_core_manifest(Path(FIXTURE_MANIFESTS[os.path.realpath(repo)]).read_bytes())
    raw = dict(parsed.raw)
    raw["inputs"] = [
        dict(entry, path=retarget.get(entry["path"], entry["path"]))
        for entry in parsed.raw["inputs"]
    ]
    if authority_abs:
        authority = dict(parsed.raw["protocol_authority"])
        authority["header"] = str(ROOT / authority["header"])
        authority["source"] = str(ROOT / authority["source"])
        raw["protocol_authority"] = authority
    dest = os.path.join(scratch, "throwaway-manifest.json")
    Path(dest).write_bytes(canonical_dumps(raw))
    return dest


def _ok(name: str) -> None:
    print(f"ok   {name}")


def _fail(name: str, error: Exception) -> None:
    global FAILURES
    FAILURES += 1
    print(f"FAIL {name}: {error}")


def test_wrong_base(scratch: str) -> None:
    repo, first, second = _make_fixture(scratch)
    _git(repo, "checkout", "-q", second)
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    before = _tree_fingerprint(repo)
    result = _materialize(repo)
    if result.returncode == 0:
        raise AssertionError("wrong base succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_BASE_COMMIT)
    _assert_unchanged(before, repo)


def test_dirty_staged(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    Path(os.path.join(repo, "README")).write_text("staged\n", encoding="utf-8")
    _git(repo, "add", "README")
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    before = _tree_fingerprint(repo)
    result = _materialize(repo)
    if result.returncode == 0:
        raise AssertionError("dirty staged succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_DIRTY_STAGED)
    _assert_unchanged(before, repo)


def test_dirty_unstaged(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    Path(os.path.join(repo, "README")).write_text("unstaged\n", encoding="utf-8")
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    before = _tree_fingerprint(repo)
    result = _materialize(repo)
    if result.returncode == 0:
        raise AssertionError("dirty unstaged succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_DIRTY_UNSTAGED)
    _assert_unchanged(before, repo)


def test_dirty_untracked(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    Path(os.path.join(repo, "extra.txt")).write_text("untracked\n", encoding="utf-8")
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    before = _tree_fingerprint(repo)
    result = _materialize(repo)
    if result.returncode == 0:
        raise AssertionError("dirty untracked succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_DIRTY_UNTRACKED)
    _assert_unchanged(before, repo)


def test_missing_input(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    rel = f"{CORE_SRC_REL}/core.h"
    copied = Path(scratch) / "core.h"
    shutil.copy2(ROOT / rel, copied)
    copied.rename(Path(scratch) / "core.h.hidden-for-test")
    manifest = _throwaway_manifest(scratch, repo, {rel: str(copied)})
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    before = _tree_fingerprint(repo)
    result = _materialize(repo, ["--manifest", manifest])
    if result.returncode == 0:
        raise AssertionError("missing input succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_INPUT_MISSING)
    _assert_unchanged(before, repo)


def test_changed_input(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    rel = f"{CORE_SRC_REL}/Kconfig"
    copied = Path(scratch) / "Kconfig"
    shutil.copy2(ROOT / rel, copied)
    copied.write_bytes(copied.read_bytes() + b"\n# mutated\n")
    manifest = _throwaway_manifest(scratch, repo, {rel: str(copied)})
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    before = _tree_fingerprint(repo)
    result = _materialize(repo, ["--manifest", manifest])
    if result.returncode == 0:
        raise AssertionError("changed input succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED)
    _assert_unchanged(before, repo)


def test_unmanifested_input(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    isolated = Path(scratch) / "isolated-root"
    shutil.copytree(ROOT / "spp-diag-trace-core-src", isolated / "spp-diag-trace-core-src")
    extra = isolated / CORE_SRC_REL / "extra-unmanifested.c"
    extra.write_text("/* extra */\n", encoding="utf-8")
    manifest = _throwaway_manifest(scratch, repo, {}, authority_abs=True)
    previous_root = materialize.REPO_ROOT
    materialize.REPO_ROOT = isolated
    try:
        materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
        before = _tree_fingerprint(repo)
        result = _materialize(repo, ["--manifest", manifest])
        if result.returncode == 0:
            raise AssertionError("unmanifested input succeeded")
        _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_INPUT_UNMANIFESTED)
        _assert_unchanged(before, repo)
    finally:
        materialize.REPO_ROOT = previous_root


def test_create_collision(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    dest_dir = os.path.join(repo, "security", "spp_diag_trace_core")
    os.makedirs(dest_dir)
    Path(os.path.join(dest_dir, "core.c")).write_text("collision\n", encoding="utf-8")
    _git(repo, "add", "security/spp_diag_trace_core/core.c")
    _git(repo, "commit", "-m", "collision")
    colliding = _git(repo, "rev-parse", "--verify", "HEAD").strip()
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = colliding
    before = _tree_fingerprint(repo)
    result = _materialize(repo)
    if result.returncode == 0:
        raise AssertionError("create collision succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_CREATE_COLLISION)
    _assert_unchanged(before, repo)


def test_partial_apply(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    makefile = Path(os.path.join(repo, "security", "Makefile"))
    makefile.write_text(
        makefile.read_text(encoding="utf-8")
        + "obj-$(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE) += spp_diag_trace_core/\n",
        encoding="utf-8",
    )
    _git(repo, "add", "security/Makefile")
    _git(repo, "commit", "-m", "partial")
    first_partial = _git(repo, "rev-parse", "--verify", "HEAD").strip()
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first_partial
    before = _tree_fingerprint(repo)
    result = _materialize(repo)
    if result.returncode == 0:
        raise AssertionError("partial apply succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_PARTIAL_APPLY)
    _assert_unchanged(before, repo)


def test_replace_changed_digest(scratch: str) -> None:
    repo, _first, _second = _make_fixture(scratch)
    makefile = Path(repo, "security", "Makefile")
    makefile.write_bytes(makefile.read_bytes() + b"# changed base\n")
    _git(repo, "add", "security/Makefile")
    _git(repo, "commit", "-m", "changed replacement bytes")
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = _git(
        repo, "rev-parse", "--verify", "HEAD"
    ).strip()
    before = _tree_fingerprint(repo)
    result = _materialize(repo)
    if result.returncode == 0:
        raise AssertionError("changed REPLACE digest succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_REPLACE_CHANGED)
    _assert_unchanged(before, repo)


def test_replace_changed_mode(scratch: str) -> None:
    repo, _first, _second = _make_fixture(scratch)
    makefile = Path(repo, "security", "Makefile")
    os.chmod(makefile, 0o755)
    _git(repo, "add", "security/Makefile")
    _git(repo, "commit", "-m", "changed replacement mode")
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = _git(
        repo, "rev-parse", "--verify", "HEAD"
    ).strip()
    before = _tree_fingerprint(repo)
    result = _materialize(repo)
    if result.returncode == 0:
        raise AssertionError("changed REPLACE mode succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_REPLACE_CHANGED)
    _assert_unchanged(before, repo)


def test_replace_wrong_postimage(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    raw = dict(
        parse_core_manifest(
            Path(FIXTURE_MANIFESTS[os.path.realpath(repo)]).read_bytes()
        ).raw
    )
    targets = [dict(target) for target in raw["targets"]]
    targets[-1]["postimage_sha256"] = "0" * 64
    raw["targets"] = targets
    manifest = os.path.join(scratch, "wrong-postimage-manifest.json")
    Path(manifest).write_bytes(canonical_dumps(raw))
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    before = _tree_fingerprint(repo)
    result = _materialize(repo, ["--manifest", manifest])
    if result.returncode == 0:
        raise AssertionError("wrong REPLACE postimage succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_SCHEMA)
    _assert_unchanged(before, repo)


def test_replace_boundary_mutation(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    original = materialize._preflight_destinations
    boundary_state: dict[str, str] = {}

    def mutate_after_preflight(worktree: str, manifest) -> None:
        original(worktree, manifest)
        makefile = Path(worktree, "security", "Makefile")
        makefile.write_bytes(makefile.read_bytes() + b"# boundary mutation\n")
        boundary_state.update(_tree_fingerprint(worktree))

    materialize._preflight_destinations = mutate_after_preflight
    try:
        result = _materialize(repo)
    finally:
        materialize._preflight_destinations = original
    if result.returncode == 0:
        raise AssertionError("boundary-mutated REPLACE preimage succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_REPLACE_CHANGED)
    if not boundary_state:
        raise AssertionError("boundary mutation did not run")
    if _tree_fingerprint(repo) != boundary_state:
        raise AssertionError("apply changed targets after boundary mutation")


def test_symlink_worktree(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    link = os.path.join(scratch, "repo-link")
    os.symlink(repo, link)
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    before = _tree_fingerprint(repo)
    result = _materialize(link)
    if result.returncode == 0:
        raise AssertionError("symlink worktree succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_SYMLINK)
    _assert_unchanged(before, repo)


def test_git_probe_empty(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    shim = os.path.join(scratch, "git-empty")
    Path(shim).write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    os.chmod(shim, 0o755)
    digest = hashlib.sha256(Path(shim).read_bytes()).hexdigest()
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    before = _tree_fingerprint(repo)
    result = _materialize(repo, ["--git", shim, "--git-sha256", digest])
    if result.returncode == 0:
        raise AssertionError("empty git probe succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_GIT_PROBE)
    _assert_unchanged(before, repo)


def test_git_probe_unparseable(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    shim = os.path.join(scratch, "git-unparseable")
    Path(shim).write_text("#!/bin/sh\necho not-a-real-commit\nexit 0\n", encoding="utf-8")
    os.chmod(shim, 0o755)
    digest = hashlib.sha256(Path(shim).read_bytes()).hexdigest()
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    before = _tree_fingerprint(repo)
    result = _materialize(repo, ["--git", shim, "--git-sha256", digest])
    if result.returncode == 0:
        raise AssertionError("unparseable git probe succeeded")
    _expect_reason(result.stderr, CP_SPP_DIAG_TRACE_CORE_GIT_PROBE)
    _assert_unchanged(before, repo)


def test_replace_rename_rollback(scratch: str) -> None:
    repo, first, _second = _make_fixture(scratch)
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    before = _tree_fingerprint(repo)
    kconfig_dest = os.path.abspath(os.path.join(repo, "security", "Kconfig"))
    original_rename = os.rename

    def failing_rename(src: str, dst: str, *args: object, **kwargs: object) -> None:
        if os.path.abspath(dst) == kconfig_dest:
            raise OSError("injected failure on second REPLACE")
        original_rename(src, dst)

    os.rename = failing_rename  # type: ignore[assignment]
    try:
        result = _materialize(repo)
    finally:
        os.rename = original_rename
    if result.returncode == 0:
        raise AssertionError("second REPLACE failure still reported success")
    _assert_unchanged(before, repo)
    makefile = Path(repo, "security", "Makefile").read_text(encoding="utf-8")
    if "CONFIG_SECURITY_SPP_DIAG_TRACE_CORE" in makefile:
        raise AssertionError("security/Makefile still carries the appended REPLACE line")


def test_happy_path_and_determinism(scratch: str) -> None:
    repo_a, first, _second = _make_fixture(os.path.join(scratch, "a"))
    repo_b, first_b, _s = _make_fixture(os.path.join(scratch, "b"))
    if first == first_b:
        pass
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    out_a = os.path.join(scratch, "derive-a.json")
    result_a = _materialize(repo_a, ["--derivation-out", out_a])
    if result_a.returncode != 0:
        raise AssertionError(result_a.stderr.decode())
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first_b
    out_b = os.path.join(scratch, "derive-b.json")
    result_b = _materialize(repo_b, ["--derivation-out", out_b])
    if result_b.returncode != 0:
        raise AssertionError(result_b.stderr.decode())
    manifest = parse_core_manifest((ROOT / "spp-diag-trace-core-src" / "manifest.json").read_bytes())
    for create in manifest.creates:
        staged = Path(repo_a) / create.destination
        digest = hashlib.sha256(staged.read_bytes()).hexdigest()
        if digest != create.sha256:
            raise AssertionError(f"{create.destination} sha256 {digest} != {create.sha256}")
        if hashlib.sha256((Path(repo_b) / create.destination).read_bytes()).hexdigest() != digest:
            raise AssertionError("CREATE bytes differ across two staging runs")
    fixture_manifest = parse_core_manifest(
        Path(FIXTURE_MANIFESTS[os.path.realpath(repo_a)]).read_bytes()
    )
    for replace in fixture_manifest.replaces:
        staged = Path(repo_a) / replace.destination
        digest = hashlib.sha256(staged.read_bytes()).hexdigest()
        mode = stat.S_IMODE(staged.stat().st_mode)
        if digest != replace.postimage_sha256 or mode != replace.postimage_mode:
            raise AssertionError(
                f"{replace.destination} postimage mode/digest {(mode, digest)}"
            )
    makefile = (Path(repo_a) / "security/Makefile").read_text(encoding="utf-8")
    kconfig = (Path(repo_a) / "security/Kconfig").read_text(encoding="utf-8")
    if "obj-$(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE) += spp_diag_trace_core/" not in makefile:
        raise AssertionError("Makefile missing append")
    if 'source "security/spp_diag_trace_core/Kconfig"' not in kconfig:
        raise AssertionError("Kconfig missing append")
    rec_a = Path(out_a).read_bytes()
    rec_b = Path(out_b).read_bytes()
    parsed_a = canonical_loads(rec_a.rstrip(b"\n"))
    parsed_b = canonical_loads(rec_b.rstrip(b"\n"))
    parsed_a["base_commit"] = "same"
    parsed_b["base_commit"] = "same"
    if canonical_dumps(parsed_a) != canonical_dumps(parsed_b):
        raise AssertionError("derivation records differ")
    mutated = fixture_manifest
    bad_path = os.path.join(scratch, "bad-manifest.json")
    raw = dict(mutated.raw)
    raw_targets = list(raw["targets"])
    first_create = dict(raw_targets[0])
    first_create["sha256"] = "0" * 64
    raw_targets[0] = first_create
    raw["targets"] = raw_targets
    Path(bad_path).write_bytes(canonical_dumps(raw))
    repo_c, first_c, _ = _make_fixture(os.path.join(scratch, "c"))
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first_c
    bad = _materialize(repo_c, ["--manifest", bad_path])
    if bad.returncode == 0:
        raise AssertionError("mutated manifest digest still staged")


CASES = (
    ("wrong-base", test_wrong_base),
    ("dirty-staged", test_dirty_staged),
    ("dirty-unstaged", test_dirty_unstaged),
    ("dirty-untracked", test_dirty_untracked),
    ("missing-input", test_missing_input),
    ("changed-input", test_changed_input),
    ("unmanifested-input", test_unmanifested_input),
    ("create-collision", test_create_collision),
    ("partial-apply", test_partial_apply),
    ("replace-changed-digest", test_replace_changed_digest),
    ("replace-changed-mode", test_replace_changed_mode),
    ("replace-wrong-postimage", test_replace_wrong_postimage),
    ("replace-boundary-mutation", test_replace_boundary_mutation),
    ("symlink-worktree", test_symlink_worktree),
    ("git-probe-empty", test_git_probe_empty),
    ("git-probe-unparseable", test_git_probe_unparseable),
    ("replace-rename-rollback", test_replace_rename_rollback),
    ("happy-path-determinism", test_happy_path_and_determinism),
)


def main() -> int:
    if not os.path.isfile(GIT):
        print("FAIL no git binary")
        return 1
    for name, fn in CASES:
        scratch = tempfile.mkdtemp(prefix=f"k1-mat-{name}-", dir="/var/tmp")
        materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = None
        try:
            fn(scratch)
            _ok(name)
        except Exception as exc:  # noqa: BLE001
            _fail(name, exc)
        finally:
            materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = None
            shutil.rmtree(scratch, ignore_errors=True)
    if FAILURES:
        print(f"{FAILURES} failure(s)")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
