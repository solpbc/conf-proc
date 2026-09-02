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
from conf_proc_json import canonical_loads  # noqa: E402
from conf_proc_spp_diag_trace_core_manifest import (  # noqa: E402
    BOOTSTRAP_API_SYMBOLS,
    CORE_API_SYMBOLS,
)
from conf_proc_spp_diag_trace_core_materialize_reasons import (  # noqa: E402
    CP_SPP_DIAG_TRACE_CORE_FORBIDDEN_COMMAND,
    CP_SPP_DIAG_TRACE_CORE_HANDOFF,
    CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED,
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
        f'printf "cwd=%s\\n" "$PWD" >> "{log}"\n'
        f'printf "%s\\n" "$@" >> "{log}"\n'
        f"exit_code={exit_code}\n"
        "if [ \"$#\" -eq 7 ] && [ \"$1\" = -f ] && "
        "[ \"$2\" = debian.azure-fde-6.8/config/annotations ] && "
        "[ \"$3\" = --arch ] && [ \"$4\" = amd64 ] && "
        "[ \"$5\" = --flavour ] && [ \"$6\" = azure-fde ] && "
        "[ \"$7\" = --export ]; then\n"
        f'  cat "{payload}"\n'
        "fi\n"
        "exit $exit_code\n",
    )


def _make_shim(path: str, log: str, *, strip_fragment: bool = False) -> None:
    strip = "yes" if strip_fragment else "no"
    _write_exec(
        path,
        "#!/bin/sh\n"
        f'printf "cwd=%s\\n" "$PWD" >> "{log}"\n'
        f'printf "%s\\n" "$@" >> "{log}"\n'
        "outdir=\n"
        "has_olddef=\n"
        "target=\n"
        "for arg in \"$@\"; do\n"
        "  case \"$arg\" in\n"
        "    O=*) outdir=${arg#O=} ;;\n"
        "    olddefconfig) has_olddef=1 ;;\n"
        "    security/spp_diag_trace_core/core.o|vmlinux) target=$arg ;;\n"
        "  esac\n"
        "done\n"
        f"strip={strip}\n"
        "if [ \"$1\" = -f ]; then\n"
        "  mkdir -p debian\n"
        "  printf 'fixture cert\\n' > debian/canonical-certs.pem\n"
        "  printf 'fixture revoked cert\\n' > debian/canonical-revoked-certs.pem\n"
        "  exit 0\n"
        "fi\n"
        "if [ -n \"$has_olddef\" ]; then\n"
        "  if [ \"$strip\" = yes ]; then\n"
        "    printf 'CONFIG_ONLY_FOO=y\\n' > \"$outdir/.config\"\n"
        "  fi\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$target\" = security/spp_diag_trace_core/core.o ]; then\n"
        "  touch \"$outdir/core-built\"\n"
        "fi\n"
        "if [ \"$target\" = vmlinux ]; then\n"
        "  printf 'fixture vmlinux\\n' > \"$outdir/vmlinux\"\n"
        "fi\n"
        "exit 0\n",
    )


def _nm_shim(
    path: str,
    log: str,
    enabled_output: str,
    disabled_output: str,
    *,
    omit_enabled: bool = False,
    leak_disabled: bool = False,
) -> None:
    enabled_symbols = ":\n" if omit_enabled else "".join(
        f"printf '0000000000000001 T {symbol}\\n'\n" for symbol in CORE_API_SYMBOLS
    )
    enabled_bootstrap = "".join(
        f"printf '0000000000000001 T {symbol}\\n'\n" for symbol in BOOTSTRAP_API_SYMBOLS
    )
    disabled_core = "".join(
        f"printf '0000000000000001 T {symbol}\\n'\n" for symbol in CORE_API_SYMBOLS
    )
    disabled_symbol = (
        "printf '0000000000000001 T spp_diag_trace_bootstrap_init\\n'\n"
        if leak_disabled
        else ""
    )
    _write_exec(
        path,
        "#!/bin/sh\n"
        f'printf "cwd=%s\\n" "$PWD" >> "{log}"\n'
        f'printf "%s\\n" "$@" >> "{log}"\n'
        "printf '0000000000000001 T start_kernel\\n'\n"
        f'if [ "$3" = "{enabled_output}/vmlinux" ]; then\n'
        f"{enabled_symbols}"
        f"{enabled_bootstrap}"
        f'elif [ "$3" = "{disabled_output}/vmlinux" ]; then\n'
        f"{disabled_core}"
        f"{disabled_symbol}"
        "else\n"
        "  exit 2\n"
        "fi\n",
    )


def _trap_shim(path: str, log: str) -> None:
    _write_exec(path, "#!/bin/sh\n" f'printf "%s\\n" "$0 $*" >> "{log}"\n' "exit 0\n")


def _run_handoff(argv: list[str]):
    argv = list(argv)
    if "--manifest" not in argv:
        worktree = argv[argv.index("--worktree") + 1]
        argv.extend(
            ["--manifest", MAT.FIXTURE_MANIFESTS[os.path.realpath(worktree)]]
        )
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
    disabled_output = os.path.join(scratch, "out-disabled")
    os.makedirs(output)
    os.makedirs(disabled_output)
    ann_log = os.path.join(scratch, "ann.log")
    make_log = os.path.join(scratch, "make.log")
    nm_log = os.path.join(scratch, "nm.log")
    trap_log = os.path.join(scratch, "trap.log")
    Path(ann_log).write_text("", encoding="utf-8")
    Path(make_log).write_text("", encoding="utf-8")
    Path(nm_log).write_text("", encoding="utf-8")
    Path(trap_log).write_text("", encoding="utf-8")
    annotations = os.path.join(scratch, "annotations")
    make = os.path.join(scratch, "make")
    nm = os.path.join(scratch, "nm")
    _annotations_shim(annotations, ann_log, "CONFIG_FOO=y\nCONFIG_IMA=y\n")
    _make_shim(make, make_log)
    _nm_shim(nm, nm_log, output, disabled_output)
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
            "--nm",
            nm,
            "--nm-sha256",
            _sha(nm),
            "--output-dir",
            output,
            "--disabled-output-dir",
            disabled_output,
        ]
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode())
    record = canonical_loads(result.stdout.rstrip(b"\n"))
    if record["enabled"]["core_api_symbols"] != list(CORE_API_SYMBOLS):
        raise AssertionError(record["enabled"])
    if record["disabled"]["core_api_symbols"] != list(CORE_API_SYMBOLS):
        raise AssertionError(record["disabled"])
    if record["enabled"]["bootstrap_api_symbols"] != list(BOOTSTRAP_API_SYMBOLS):
        raise AssertionError(record["enabled"])
    if record["disabled"]["bootstrap_api_symbols"] != []:
        raise AssertionError(record["disabled"])
    ann_lines = [line for line in Path(ann_log).read_text(encoding="utf-8").splitlines() if line]
    make_lines = [line for line in Path(make_log).read_text(encoding="utf-8").splitlines() if line]
    nm_lines = [line for line in Path(nm_log).read_text(encoding="utf-8").splitlines() if line]
    expected_ann = [
        f"cwd={repo}",
        "-f",
        handoff.ANNOTATIONS_CONFIG,
        "--arch",
        "amd64",
        "--flavour",
        "azure-fde",
        "--export",
    ]
    if ann_lines != expected_ann:
        raise AssertionError(f"annotations argv {ann_lines}")
    expected_make = [
        f"cwd={repo}",
        f"O={output}",
        "olddefconfig",
        f"cwd={repo}",
        f"O={disabled_output}",
        "olddefconfig",
        f"cwd={repo}",
        "-f",
        "debian/rules",
        *handoff.CANONICAL_CERT_TARGETS,
        f"cwd={repo}",
        f"O={output}",
        handoff.CORE_OBJECT_TARGET,
        f"cwd={repo}",
        f"O={output}",
        handoff.VMLINUX_TARGET,
        f"cwd={repo}",
        f"O={disabled_output}",
        handoff.VMLINUX_TARGET,
    ]
    if make_lines != expected_make:
        raise AssertionError(f"make argv {make_lines}")
    expected_nm = [
        f"cwd={repo}",
        "-g",
        "--defined-only",
        f"{output}/vmlinux",
        f"cwd={repo}",
        "-g",
        "--defined-only",
        f"{disabled_output}/vmlinux",
    ]
    if nm_lines != expected_nm:
        raise AssertionError(f"nm argv {nm_lines}")
    config = Path(output, ".config").read_text(encoding="utf-8")
    y_lines = handoff._y_symbols(config)
    for symbol in handoff.FRAGMENT_SYMBOLS["enabled"]:
        if symbol not in y_lines:
            raise AssertionError(f"missing {symbol} in {y_lines}")
    if Path(trap_log).read_text(encoding="utf-8").strip():
        raise AssertionError("forbidden trap shim was invoked")
    if not Path(output, "core-built").is_file():
        raise AssertionError("enabled object build shim did not run")
    if not Path(output, "vmlinux").is_file() or not Path(disabled_output, "vmlinux").is_file():
        raise AssertionError("dual final-artifact build shim did not run")
    for target in handoff.CANONICAL_CERT_TARGETS:
        if Path(repo, target).exists():
            raise AssertionError(f"generated certificate input was not removed: {target}")


def test_forbidden_argv_chokepoint() -> None:
    reached = {"n": 0}

    def boom(*_args: object, **_kwargs: object):
        reached["n"] += 1
        raise AssertionError("run_tool reached")

    original = HermeticGuard.run_tool
    HermeticGuard.run_tool = boom  # type: ignore[assignment]
    try:
        for argv in (
            ["/opt/annotations", "--export"],
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
                    nm="/opt/nm",
                    enabled_output_dir="/opt/out-enabled",
                    disabled_output_dir="/opt/out-disabled",
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


def test_output_directory_alias(scratch: str) -> None:
    worktree = os.path.join(scratch, "worktree")
    real_parent = os.path.join(scratch, "real-parent")
    alias_parent = os.path.join(scratch, "alias-parent")
    shared = os.path.join(real_parent, "shared")
    os.makedirs(worktree)
    os.makedirs(shared)
    os.symlink(real_parent, alias_parent)
    try:
        handoff._validate_output_dirs(
            worktree,
            (shared, os.path.join(alias_parent, "shared")),
        )
    except SppDiagTraceCoreMaterializeError as exc:
        if exc.reason_code != CP_SPP_DIAG_TRACE_CORE_HANDOFF:
            raise
    else:
        raise AssertionError("two output aliases of one real directory were accepted")


def test_fragment_capture_mismatch(scratch: str) -> None:
    fragment = os.path.join(scratch, "config.fragment")
    declared = b"CONFIG_SECURITY_SPP_DIAG_TRACE_CORE=y\n"
    Path(fragment).write_bytes(declared + b"CONFIG_MUTATED=y\n")
    guard = HermeticGuard(
        allowed_reads=frozenset({fragment}),
        tools={},
        env={"PATH": "/usr/bin", "LC_ALL": "C", "TZ": "UTC"},
        build_epoch=0,
    )
    try:
        handoff._capture_fragment(
            guard,
            Path(fragment),
            hashlib.sha256(declared).hexdigest(),
        )
    except SppDiagTraceCoreMaterializeError as exc:
        if exc.reason_code != CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED:
            raise
    else:
        raise AssertionError("changed fragment bytes were accepted for the declared digest")


def test_static_usermodehelper_rejected(_scratch: str) -> None:
    for leg in ("enabled", "disabled"):
        y_lines = list(handoff.FRAGMENT_SYMBOLS[leg]) + [
            "CONFIG_IMA", "CONFIG_STATIC_USERMODEHELPER"
        ]
        try:
            handoff._validate_config_y(leg, y_lines, "/fixture/.config")
        except SppDiagTraceCoreMaterializeError as exc:
            if exc.reason_code != CP_SPP_DIAG_TRACE_CORE_HANDOFF:
                raise
        else:
            raise AssertionError(f"{leg} accepted STATIC_USERMODEHELPER")


def test_annotations_nonzero(scratch: str) -> None:
    repo, first, _second = MAT._make_fixture(scratch)
    output = os.path.join(scratch, "out")
    disabled_output = os.path.join(scratch, "out-disabled")
    os.makedirs(output)
    os.makedirs(disabled_output)
    before = sorted(os.listdir(output))
    annotations = os.path.join(scratch, "annotations")
    make = os.path.join(scratch, "make")
    nm = os.path.join(scratch, "nm")
    _annotations_shim(annotations, os.path.join(scratch, "ann.log"), "CONFIG_FOO=y\n", exit_code=1)
    _make_shim(make, os.path.join(scratch, "make.log"))
    _nm_shim(nm, os.path.join(scratch, "nm.log"), output, disabled_output)
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
            "--nm",
            nm,
            "--nm-sha256",
            _sha(nm),
            "--output-dir",
            output,
            "--disabled-output-dir",
            disabled_output,
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
    disabled_output = os.path.join(scratch, "out-disabled")
    os.makedirs(output)
    os.makedirs(disabled_output)
    before = sorted(os.listdir(output))
    annotations = os.path.join(scratch, "annotations")
    make = os.path.join(scratch, "make")
    nm = os.path.join(scratch, "nm")
    _annotations_shim(annotations, os.path.join(scratch, "ann.log"), "", exit_code=0)
    _make_shim(make, os.path.join(scratch, "make.log"))
    _nm_shim(nm, os.path.join(scratch, "nm.log"), output, disabled_output)
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
            "--nm",
            nm,
            "--nm-sha256",
            _sha(nm),
            "--output-dir",
            output,
            "--disabled-output-dir",
            disabled_output,
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
    disabled_output = os.path.join(scratch, "out-disabled")
    os.makedirs(output)
    os.makedirs(disabled_output)
    annotations = os.path.join(scratch, "annotations")
    make = os.path.join(scratch, "make")
    nm = os.path.join(scratch, "nm")
    _annotations_shim(annotations, os.path.join(scratch, "ann.log"), "CONFIG_FOO=y\nCONFIG_IMA=y\n")
    _make_shim(make, os.path.join(scratch, "make.log"), strip_fragment=True)
    _nm_shim(nm, os.path.join(scratch, "nm.log"), output, disabled_output)
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
            "--nm",
            nm,
            "--nm-sha256",
            _sha(nm),
            "--output-dir",
            output,
            "--disabled-output-dir",
            disabled_output,
        ]
    )
    if result.returncode == 0:
        raise AssertionError("missing fragment symbols succeeded")
    if CP_SPP_DIAG_TRACE_CORE_HANDOFF.encode() not in result.stderr:
        raise AssertionError(result.stderr.decode())


def _test_artifact_symbol_failure(
    scratch: str, *, omit_enabled: bool = False, leak_disabled: bool = False
) -> None:
    repo, first, _second = MAT._make_fixture(scratch)
    output = os.path.join(scratch, "out")
    disabled_output = os.path.join(scratch, "out-disabled")
    os.makedirs(output)
    os.makedirs(disabled_output)
    annotations = os.path.join(scratch, "annotations")
    make = os.path.join(scratch, "make")
    nm = os.path.join(scratch, "nm")
    _annotations_shim(annotations, os.path.join(scratch, "ann.log"), "CONFIG_FOO=y\nCONFIG_IMA=y\n")
    _make_shim(make, os.path.join(scratch, "make.log"))
    _nm_shim(
        nm,
        os.path.join(scratch, "nm.log"),
        output,
        disabled_output,
        omit_enabled=omit_enabled,
        leak_disabled=leak_disabled,
    )
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
            "--nm",
            nm,
            "--nm-sha256",
            _sha(nm),
            "--output-dir",
            output,
            "--disabled-output-dir",
            disabled_output,
        ]
    )
    if result.returncode == 0:
        raise AssertionError("artifact symbol mismatch succeeded")
    if CP_SPP_DIAG_TRACE_CORE_HANDOFF.encode() not in result.stderr:
        raise AssertionError(result.stderr.decode())
    if not Path(output, "core-built").is_file():
        raise AssertionError("standalone core object was not built before final-artifact refusal")
    for target in handoff.CANONICAL_CERT_TARGETS:
        if Path(repo, target).exists():
            raise AssertionError(f"generated certificate input was not removed: {target}")


def test_kbuild_inclusion_missing(scratch: str) -> None:
    _test_artifact_symbol_failure(scratch, omit_enabled=True)


def test_disabled_symbol_leak(scratch: str) -> None:
    _test_artifact_symbol_failure(scratch, leak_disabled=True)


CASES = (
    ("happy-path", test_happy_path),
    ("annotations-nonzero", test_annotations_nonzero),
    ("annotations-empty", test_annotations_empty),
    ("missing-fragment-symbols", test_missing_fragment_symbols),
    ("kbuild-inclusion-missing", test_kbuild_inclusion_missing),
    ("disabled-symbol-leak", test_disabled_symbol_leak),
)


def main() -> int:
    try:
        test_forbidden_argv_chokepoint()
        _ok("forbidden-argv-chokepoint")
    except Exception as exc:  # noqa: BLE001
        _fail("forbidden-argv-chokepoint", exc)
    for name, fn in (
        ("output-directory-alias", test_output_directory_alias),
    ("fragment-capture-mismatch", test_fragment_capture_mismatch),
    ("static-usermodehelper-rejected", test_static_usermodehelper_rejected),
    ):
        scratch = tempfile.mkdtemp(prefix=f"k1-handoff-{name}-", dir="/var/tmp")
        try:
            fn(scratch)
            _ok(name)
        except Exception as exc:  # noqa: BLE001
            _fail(name, exc)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
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
