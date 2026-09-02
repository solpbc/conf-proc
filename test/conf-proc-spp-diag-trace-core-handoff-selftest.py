#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""AC11/AC10 handoff tests against instrumented tool shims."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_spp_diag_trace_core_handoff as handoff  # noqa: E402
import conf_proc_spp_diag_trace_core_materialize as materialize  # noqa: E402
from conf_proc_guard import HermeticGuard  # noqa: E402
from conf_proc_spp_diag_trace_core_materialize_reasons import (  # noqa: E402
    CP_SPP_DIAG_TRACE_CORE_FORBIDDEN_COMMAND,
    CP_SPP_DIAG_TRACE_CORE_HANDOFF,
    SppDiagTraceCoreMaterializeError,
)


def _load_materialize_selftest():
    path = ROOT / "test" / "conf-proc-spp-diag-trace-core-materialize-selftest.py"
    spec = importlib.util.spec_from_file_location("k1_mat_selftest", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load materialize selftest helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MAT = _load_materialize_selftest()
GIT = MAT.GIT
GIT_SHA256 = MAT.GIT_SHA256
FAILURES = 0


class _ByteStdout:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def write(self, data: object) -> int:
        if isinstance(data, bytes):
            self.buffer.write(data)
            return len(data)
        encoded = str(data).encode("utf-8")
        self.buffer.write(encoded)
        return len(encoded)

    def flush(self) -> None:
        return None


def _sha(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write_exec(path: str, body: str) -> None:
    Path(path).write_text(body, encoding="utf-8")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP)


def _annotations_shim(path: str, log: str, stdout_text: str, exit_code: int = 0) -> None:
    payload = path + ".stdout"
    Path(payload).write_bytes(stdout_text.encode("utf-8"))
    _write_exec(
        path,
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" >> "{log}"\n'
        f"exit_code={exit_code}\n"
        "if [ \"$1\" = --export ]; then\n"
        f'  cat "{payload}"\n'
        "fi\n"
        "exit $exit_code\n",
    )


def _make_shim(path: str, log: str, *, strip_fragment: bool = False) -> None:
    strip = "yes" if strip_fragment else "no"
    _write_exec(
        path,
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" >> "{log}"\n'
        "outdir=\n"
        "has_olddef=\n"
        "for arg in \"$@\"; do\n"
        "  case \"$arg\" in\n"
        "    O=*) outdir=${arg#O=} ;;\n"
        "    olddefconfig) has_olddef=1 ;;\n"
        "  esac\n"
        "done\n"
        f"strip={strip}\n"
        "if [ -n \"$has_olddef\" ]; then\n"
        "  if [ \"$strip\" = yes ]; then\n"
        "    printf 'CONFIG_ONLY_FOO=y\\n' > \"$outdir/.config\"\n"
        "  fi\n"
        "  exit 0\n"
        "fi\n"
        "if [ -n \"$outdir\" ]; then\n"
        "  touch \"$outdir/built\"\n"
        "fi\n"
        "exit 0\n",
    )


def _trap_shim(path: str, log: str) -> None:
    _write_exec(path, "#!/bin/sh\n" f'printf "%s\\n" "$0 $*" >> "{log}"\n' "exit 0\n")


def _run_handoff(argv: list[str]):
    stdout = _ByteStdout()
    stderr = io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = stdout, stderr
    try:
        code = handoff.main(argv)
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    return SimpleNamespace(
        returncode=code,
        stdout=stdout.buffer.getvalue(),
        stderr=stderr.getvalue().encode("utf-8"),
    )


def _ok(name: str) -> None:
    print(f"ok   {name}")


def _fail(name: str, error: Exception) -> None:
    global FAILURES
    FAILURES += 1
    print(f"FAIL {name}: {error}")


def test_happy_path(scratch: str) -> None:
    repo, first, _second = MAT._make_fixture(scratch)
    output = os.path.join(scratch, "out")
    os.makedirs(output)
    ann_log = os.path.join(scratch, "ann.log")
    make_log = os.path.join(scratch, "make.log")
    trap_log = os.path.join(scratch, "trap.log")
    Path(ann_log).write_text("", encoding="utf-8")
    Path(make_log).write_text("", encoding="utf-8")
    Path(trap_log).write_text("", encoding="utf-8")
    annotations = os.path.join(scratch, "annotations")
    make = os.path.join(scratch, "make")
    _annotations_shim(annotations, ann_log, "CONFIG_FOO=y\n")
    _make_shim(make, make_log)
    for name in ("fetch", "checkout", "reset", "clean", "sign", "package", "boot", "device"):
        _trap_shim(os.path.join(scratch, name), trap_log)
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    result = _run_handoff(
        [
            "--worktree",
            repo,
            "--git",
            GIT,
            "--git-sha256",
            GIT_SHA256,
            "--annotations",
            annotations,
            "--annotations-sha256",
            _sha(annotations),
            "--make",
            make,
            "--make-sha256",
            _sha(make),
            "--output-dir",
            output,
        ]
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode())
    ann_lines = [line for line in Path(ann_log).read_text(encoding="utf-8").splitlines() if line]
    make_lines = [line for line in Path(make_log).read_text(encoding="utf-8").splitlines() if line]
    if ann_lines != ["--export"]:
        raise AssertionError(f"annotations argv {ann_lines}")
    if make_lines != [f"O={output} olddefconfig", f"O={output}"]:
        # shims log each arg on its own line
        expected = [f"O={output}", "olddefconfig", f"O={output}"]
        if make_lines != expected:
            raise AssertionError(f"make argv {make_lines}")
    config = Path(output, ".config").read_text(encoding="utf-8")
    y_lines = handoff._y_symbols(config)
    for symbol in handoff.FRAGMENT_SYMBOLS:
        if symbol not in y_lines:
            raise AssertionError(f"missing {symbol} in {y_lines}")
    if Path(trap_log).read_text(encoding="utf-8").strip():
        raise AssertionError("forbidden trap shim was invoked")
    if not Path(output, "built").is_file():
        raise AssertionError("build shim did not run")


def test_forbidden_argv_chokepoint() -> None:
    reached = {"n": 0}

    def boom(*_args: object, **_kwargs: object):
        reached["n"] += 1
        raise AssertionError("run_tool reached")

    original = HermeticGuard.run_tool
    HermeticGuard.run_tool = boom  # type: ignore[assignment]
    try:
        for argv in (
            ["/usr/bin/git", "fetch"],
            ["/usr/bin/git", "checkout", "HEAD"],
            ["/usr/bin/git", "reset", "--hard"],
            ["/usr/bin/git", "clean", "-fdx"],
            ["/usr/bin/gpg", "--sign"],
            ["/usr/bin/dpkg", "--build", "pkg"],
            ["/usr/bin/rpm", "-ba", "spec"],
            ["/usr/bin/make", "boot"],
            ["/usr/bin/make", "O=/out", "clean"],
            ["/usr/sbin/grub-install", "/dev/sda"],
            ["/usr/bin/dd", "of=/dev/sda"],
        ):
            try:
                handoff.require_handoff_argv(
                    argv,
                    annotations="/opt/annotations",
                    make="/opt/make",
                    output_dir="/opt/out",
                )
            except SppDiagTraceCoreMaterializeError as exc:
                if exc.reason_code != CP_SPP_DIAG_TRACE_CORE_FORBIDDEN_COMMAND:
                    raise AssertionError(exc.reason_code) from exc
            else:
                raise AssertionError(f"allowed forbidden argv {argv}")
    finally:
        HermeticGuard.run_tool = original  # type: ignore[assignment]
    if reached["n"]:
        raise AssertionError("run_tool was reached for a forbidden argv")


def test_annotations_nonzero(scratch: str) -> None:
    repo, first, _second = MAT._make_fixture(scratch)
    output = os.path.join(scratch, "out")
    os.makedirs(output)
    before = sorted(os.listdir(output))
    annotations = os.path.join(scratch, "annotations")
    make = os.path.join(scratch, "make")
    _annotations_shim(annotations, os.path.join(scratch, "ann.log"), "CONFIG_FOO=y\n", exit_code=1)
    _make_shim(make, os.path.join(scratch, "make.log"))
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    result = _run_handoff(
        [
            "--worktree",
            repo,
            "--git",
            GIT,
            "--git-sha256",
            GIT_SHA256,
            "--annotations",
            annotations,
            "--annotations-sha256",
            _sha(annotations),
            "--make",
            make,
            "--make-sha256",
            _sha(make),
            "--output-dir",
            output,
        ]
    )
    if result.returncode == 0:
        raise AssertionError("nonzero annotations succeeded")
    if CP_SPP_DIAG_TRACE_CORE_HANDOFF.encode() not in result.stderr:
        raise AssertionError(result.stderr.decode())
    if sorted(os.listdir(output)) != before:
        raise AssertionError("output-dir mutated after annotations failure")


def test_annotations_empty(scratch: str) -> None:
    repo, first, _second = MAT._make_fixture(scratch)
    output = os.path.join(scratch, "out")
    os.makedirs(output)
    before = sorted(os.listdir(output))
    annotations = os.path.join(scratch, "annotations")
    make = os.path.join(scratch, "make")
    _annotations_shim(annotations, os.path.join(scratch, "ann.log"), "", exit_code=0)
    _make_shim(make, os.path.join(scratch, "make.log"))
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    result = _run_handoff(
        [
            "--worktree",
            repo,
            "--git",
            GIT,
            "--git-sha256",
            GIT_SHA256,
            "--annotations",
            annotations,
            "--annotations-sha256",
            _sha(annotations),
            "--make",
            make,
            "--make-sha256",
            _sha(make),
            "--output-dir",
            output,
        ]
    )
    if result.returncode == 0:
        raise AssertionError("empty annotations succeeded")
    if CP_SPP_DIAG_TRACE_CORE_HANDOFF.encode() not in result.stderr:
        raise AssertionError(result.stderr.decode())
    if sorted(os.listdir(output)) != before:
        raise AssertionError("output-dir mutated after empty export")


def test_missing_fragment_symbols(scratch: str) -> None:
    repo, first, _second = MAT._make_fixture(scratch)
    output = os.path.join(scratch, "out")
    os.makedirs(output)
    annotations = os.path.join(scratch, "annotations")
    make = os.path.join(scratch, "make")
    _annotations_shim(annotations, os.path.join(scratch, "ann.log"), "CONFIG_FOO=y\n")
    _make_shim(make, os.path.join(scratch, "make.log"), strip_fragment=True)
    materialize._TEST_EXPECTED_BASE_COMMIT_OVERRIDE = first
    result = _run_handoff(
        [
            "--worktree",
            repo,
            "--git",
            GIT,
            "--git-sha256",
            GIT_SHA256,
            "--annotations",
            annotations,
            "--annotations-sha256",
            _sha(annotations),
            "--make",
            make,
            "--make-sha256",
            _sha(make),
            "--output-dir",
            output,
        ]
    )
    if result.returncode == 0:
        raise AssertionError("missing fragment symbols succeeded")
    if CP_SPP_DIAG_TRACE_CORE_HANDOFF.encode() not in result.stderr:
        raise AssertionError(result.stderr.decode())


CASES = (
    ("happy-path", test_happy_path),
    ("annotations-nonzero", test_annotations_nonzero),
    ("annotations-empty", test_annotations_empty),
    ("missing-fragment-symbols", test_missing_fragment_symbols),
)


def main() -> int:
    try:
        test_forbidden_argv_chokepoint()
        _ok("forbidden-argv-chokepoint")
    except Exception as exc:  # noqa: BLE001
        _fail("forbidden-argv-chokepoint", exc)
    for name, fn in CASES:
        scratch = tempfile.mkdtemp(prefix=f"k1-handoff-{name}-", dir="/var/tmp")
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
