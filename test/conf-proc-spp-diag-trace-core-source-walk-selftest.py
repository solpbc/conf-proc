#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""AC9/AC7/AC8: dormancy walk, GPL/AGPL separation, and KUnit case-list check."""

from __future__ import annotations

import os
import re
import json
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
    "spp-diag-trace-core-src/include/",
    "test/conf-proc-spp-diag-trace-core-",
    "test/spp-diag-trace-core-shim/",
    "conf_proc_spp_diag_trace_core_",
    "spp-diag-trace-core-src/manifest.json",
    "spp-diag-trace-core-src/config.fragment",
    "spp-diag-trace-core-src/config.bootstrap.fragment",
    "spp-diag-trace-core-src/config.runtime.fragment",
    "Makefile",
)

# AC7: GPL-2.0-only kernel core / host C tests that link core.c, vs.
# AGPL-3.0-only portable authority/test Python (and the field-classifier,
# which links the AGPL wire authority conf_proc_spp_diag_trace.c, never
# core.c). Non-source build/data files carry no single SPDX line and are
# excluded from classification, not from the inventory count.
LICENSE_GPL = "GPL-2.0-only"
LICENSE_AGPL = "AGPL-3.0-only"
LICENSE_OVERRIDES = {
    "test/conf-proc-spp-diag-trace-core-field-classifier.c": LICENSE_AGPL,
    # Referenced (not edited) by the field-classifier link line: the AGPL
    # policy-2 wire authority, not part of the allowlist walk but still a
    # source token the closure check must classify correctly.
    "conf_proc_spp_diag_trace.c": LICENSE_AGPL,
    "conf_proc_spp_diag_trace.h": LICENSE_AGPL,
}
NONSOURCE_PATHS = {
    "Makefile",
    "spp-diag-trace-core-src/manifest.json",
    "spp-diag-trace-core-src/config.fragment",
    "spp-diag-trace-core-src/config.bootstrap.fragment",
    "spp-diag-trace-core-src/config.runtime.fragment",
}
SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*(\S+)")

KUNIT_CORE_FILE = "spp-diag-trace-core-src/security/spp_diag_trace_core/core_kunit.c"
KUNIT_SUITE_REGISTRATION = "kunit_test_suite(spp_diag_trace_core_suite)"
KUNIT_CASE_NAMES = (
    "init_process_context",
    "append_and_query_irqs_disabled",
    "mark_failure_irqs_disabled",
)
KUNIT_BOOTSTRAP_FILE = "spp-diag-trace-core-src/security/spp_diag_trace_core/bootstrap_kunit.c"
KUNIT_BOOTSTRAP_SUITE_REGISTRATION = "kunit_test_suite(spp_diag_trace_core_bootstrap_suite)"
KUNIT_BOOTSTRAP_CASE_NAMES = (
    "parser_contract",
    "production_gate_transitions",
    "checkpoint_transitions",
)

KUNIT_RUNTIME_FILE = "spp-diag-trace-core-src/security/spp_diag_trace_core/runtime_kunit.c"
KUNIT_RUNTIME_SUITE_REGISTRATION = "kunit_test_suite(spp_diag_trace_core_runtime_suite)"
KUNIT_RUNTIME_CASE_NAMES = (
    "runtime_root_binding",
    "runtime_task_lifecycle",
    "runtime_exec_lifecycle",
    "runtime_securityfs_control",
    "runtime_sealing_kthread_race",
)

MAKE_VAR_RE = re.compile(r"^([A-Za-z0-9_]+)\s*:=\s*(.*)$")
MAKE_VAR_REF_RE = re.compile(r"\$\(([A-Za-z0-9_]+)\)")
MAKE_TARGET_RE = re.compile(r"^([A-Za-z0-9_.-]+):(?!=)")


def _allowed(rel: str) -> bool:
    return any(rel == prefix or rel.startswith(prefix) for prefix in ALLOW_PREFIXES)


def _expected_license(rel: str) -> str | None:
    if rel in NONSOURCE_PATHS:
        return None
    if rel in LICENSE_OVERRIDES:
        return LICENSE_OVERRIDES[rel]
    if rel.endswith(".py"):
        return LICENSE_AGPL
    if rel.endswith(".c") or rel.endswith(".h") or rel.endswith("/Kconfig") or rel.endswith("/Makefile"):
        return LICENSE_GPL
    return None


def _iter_files() -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for name in filenames:
            files.append(Path(dirpath) / name)
    return files


def walk(root: Path = ROOT) -> tuple[int, list[str]]:
    """AC9: no stray wiring of the dormant trace core outside the allowlist."""
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


def license_check(root: Path = ROOT) -> tuple[int, list[str]]:
    """AC7: every allowlisted (A-touched) source file's SPDX line matches its bucket."""
    violations: list[str] = []
    checked = 0
    for path in _iter_files():
        rel = str(path.relative_to(root))
        if not _allowed(rel):
            continue
        expected = _expected_license(rel)
        if expected is None:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        checked += 1
        header = "\n".join(text.splitlines()[:5])
        found = SPDX_RE.findall(header)
        if len(found) != 1:
            violations.append(f"{rel}: expected exactly one SPDX line, found {found}")
            continue
        if found[0] != expected:
            violations.append(f"{rel}: expected {expected}, found {found[0]}")
    return checked, violations


def _parse_make_variables(text: str) -> dict[str, str]:
    variables: dict[str, str] = {}
    for line in text.splitlines():
        m = MAKE_VAR_RE.match(line)
        if m:
            variables[m.group(1)] = m.group(2).strip()
    return variables


def _expand(token: str, variables: dict[str, str]) -> str:
    for _ in range(8):
        new = MAKE_VAR_REF_RE.sub(
            lambda m: variables.get(m.group(1), m.group(0)), token
        )
        if new == token:
            return new
        token = new
    return token


def _core_recipes(text: str) -> dict[str, list[str]]:
    recipes: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        target_match = MAKE_TARGET_RE.match(line)
        if target_match and not line.startswith("\t"):
            name = target_match.group(1)
            current = name if name.startswith("test-spp-diag-trace-core") else None
            if current:
                recipes.setdefault(current, [])
            continue
        if current and line.startswith("\t"):
            recipes[current].append(line.strip())
    return recipes


def closure_check(makefile_text: str) -> tuple[int, list[str]]:
    """AC7: every test-spp-diag-trace-core* compile/link line is single-license."""
    variables = _parse_make_variables(makefile_text)
    recipes = _core_recipes(makefile_text)
    checked = 0
    violations: list[str] = []
    for target, lines in recipes.items():
        for line in lines:
            if "$(CC)" not in line and "$(PYTHON)" not in line:
                continue
            expanded = _expand(line, variables)
            sources = [
                tok
                for tok in expanded.split()
                if tok.endswith(".c") or tok.endswith(".py")
            ]
            if not sources:
                continue
            checked += 1
            licenses = {src: _expected_license(src) for src in sources}
            buckets = {v for v in licenses.values() if v is not None}
            if len(buckets) > 1:
                violations.append(f"{target}: mixed-license sources {licenses}")
    return checked, violations


def kunit_case_check_text(text: str) -> tuple[int, list[str]]:
    """AC8: the named KUnit suite registers a nonzero exact case list."""
    violations: list[str] = []
    if KUNIT_SUITE_REGISTRATION not in text:
        violations.append(f"missing {KUNIT_SUITE_REGISTRATION!r}")
    found = [name for name in KUNIT_CASE_NAMES if f"KUNIT_CASE({name})" in text]
    missing = [name for name in KUNIT_CASE_NAMES if name not in found]
    if missing:
        violations.append(f"missing KUNIT_CASE entries: {missing}")
    return len(found), violations


def kunit_case_check(root: Path = ROOT) -> tuple[int, list[str]]:
    text = (root / KUNIT_CORE_FILE).read_text(encoding="utf-8")
    return kunit_case_check_text(text)


def bootstrap_kunit_case_check_text(text: str) -> tuple[int, list[str]]:
    violations: list[str] = []
    if KUNIT_BOOTSTRAP_SUITE_REGISTRATION not in text:
        violations.append(f"missing {KUNIT_BOOTSTRAP_SUITE_REGISTRATION!r}")
    if "KUNIT_EXPECT_TRUE(test, true);" in text:
        violations.append("bootstrap KUnit case has an inert true expectation")
    found = [name for name in KUNIT_BOOTSTRAP_CASE_NAMES if f"KUNIT_CASE({name})" in text]
    missing = [name for name in KUNIT_BOOTSTRAP_CASE_NAMES if name not in found]
    if missing:
        violations.append(f"missing bootstrap KUNIT_CASE entries: {missing}")
    return len(found), violations


def bootstrap_wiring_check(root: Path = ROOT) -> list[str]:
    manifest = json.loads((root / "spp-diag-trace-core-src/manifest.json").read_text(encoding="utf-8"))
    anchors = [item for item in manifest["targets"] if item["kind"] == "REPLACE" and item["placement"] == "anchor-insert"]
    expected = (
        ("security/security.c", "#include <linux/spp_diag_trace_bootstrap.h>\n"),
        ("security/security.c", "spp_diag_trace_bootstrap_init();"),
        ("security/security.c", "spp_diag_trace_bootstrap_bprm_check(bprm);"),
        ("security/integrity/ima/ima_init.c", "#include <linux/spp_diag_trace_bootstrap.h>\n"),
        ("security/integrity/ima/ima_init.c", "spp_diag_trace_bootstrap_ima_ready();"),
        ("init/main.c", "#include <linux/spp_diag_trace_bootstrap.h>\n"),
        ("init/main.c", "spp_diag_trace_bootstrap_release();"),
    )
    found = tuple(
        (item["destination"], item["insertion"])
        for item in anchors
        if "spp_diag_trace_bootstrap" in item["insertion"]
    )
    violations = []
    if len(found) != len(expected) or any(
        destination != expected_destination or needle not in insertion
        for (destination, insertion), (expected_destination, needle) in zip(found, expected)
    ):
        violations.append(f"bootstrap anchors {found!r}")
    disabled = (root / "spp-diag-trace-core-src/config.fragment").read_text(encoding="utf-8")
    if "BOOTSTRAP" in disabled:
        violations.append("K1-on/K2-off fragment enables bootstrap")
    for path in (
        root / "spp-diag-trace-core-src/security/spp_diag_trace_core/bootstrap.c",
        root / "spp-diag-trace-core-src/security/spp_diag_trace_core/gate.c",
        root / "spp-diag-trace-core-src/security/spp_diag_trace_core/release.c",
    ):
        text = path.read_text(encoding="utf-8")
        for forbidden in ("kprobe", "tracepoint", "BPF", "late_initcall", "module_init"):
            if forbidden in text:
                violations.append(f"{path.name}: forbidden {forbidden}")
    bootstrap = (root / "spp-diag-trace-core-src/security/spp_diag_trace_core/bootstrap.c").read_text(encoding="utf-8")
    gate = (root / "spp-diag-trace-core-src/security/spp_diag_trace_core/gate.c").read_text(encoding="utf-8")
    release = (root / "spp-diag-trace-core-src/security/spp_diag_trace_core/release.c").read_text(encoding="utf-8")
    core = (root / "spp-diag-trace-core-src/security/spp_diag_trace_core/core.c").read_text(encoding="utf-8")
    kunit = (root / KUNIT_BOOTSTRAP_FILE).read_text(encoding="utf-8")
    if "call_usermodehelper" in bootstrap or "ima_measure_critical_data" in bootstrap:
        violations.append("bootstrap init performs late bootstrap work")
    if release.count("call_usermodehelper(") != 1:
        violations.append("release path must contain exactly one canary call")
    if release.count("ima_measure_critical_data(") != 2:
        violations.append("release path must contain exactly two IMA calls")
    for obsolete in (
        "struct spp_diag_trace_bootstrap_state",
        "atomic_long_t denial_count",
        "static bool released",
        "spp_diag_trace_bootstrap_note_frame",
        "spp_diag_trace_bootstrap_publish_release",
    ):
        if obsolete in bootstrap or obsolete in gate or obsolete in release:
            violations.append(f"obsolete split bootstrap authority: {obsolete}")
    for required in (
        "bootstrap_denial_count",
        "bootstrap_stage",
        "bootstrap_released",
        "spp_diag_trace_core_lock",
    ):
        if required not in core:
            violations.append(f"locked core authority missing {required}")
    if "SPP_DIAG_TRACE_CORE_HOST_TEST" in kunit:
        violations.append("bootstrap KUnit body has a host-only branch")
    return violations


def runtime_kunit_case_check_text(text: str) -> tuple[int, list[str]]:
    violations: list[str] = []
    if KUNIT_RUNTIME_SUITE_REGISTRATION not in text:
        violations.append(f"missing {KUNIT_RUNTIME_SUITE_REGISTRATION!r}")
    found = [name for name in KUNIT_RUNTIME_CASE_NAMES if f"KUNIT_CASE({name})" in text]
    missing = [name for name in KUNIT_RUNTIME_CASE_NAMES if name not in found]
    if missing:
        violations.append(f"missing runtime KUNIT_CASE entries: {missing}")
    return len(found), violations


def runtime_source_walk_check(root: Path = ROOT) -> list[str]:
    violations: list[str] = []
    k3_files = (
        root / "spp-diag-trace-core-src/security/spp_diag_trace_core/runtime_state.c",
        root / "spp-diag-trace-core-src/security/spp_diag_trace_core/runtime_fs.c",
        root / "spp-diag-trace-core-src/security/spp_diag_trace_core/runtime_redirect.h",
        root / "spp-diag-trace-core-src/security/spp_diag_trace_core/runtime_types.h",
        root / "spp-diag-trace-core-src/security/spp_diag_trace_core/adapter.c",
        root / "spp-diag-trace-core-src/security/spp_diag_trace_core/runtime_kunit.c",
        root / "spp-diag-trace-core-src/include/linux/spp_diag_trace_runtime.h",
        root / "spp-diag-trace-core-src/include/linux/spp_diag_trace_adapter.h",
    )
    forbidden_lsm = (
        "LSM_HOOK_INIT",
        "security_add_hooks",
        "struct security_hook_list",
        "register_lsm",
        "call_int_hook",
        "call_void_hook",
    )
    for p in k3_files:
        if not p.exists():
            violations.append(f"missing K3 file: {p.name}")
            continue
        text = p.read_text(encoding="utf-8")
        if "SPDX-License-Identifier: GPL-2.0-only" not in text:
            violations.append(f"{p.name}: missing GPL-2.0-only SPDX header")
        if "conf_proc_spp_diag_trace.h" in text or "conf_proc_spp_diag_trace.c" in text:
            violations.append(f"{p.name}: forbidden include of conf_proc_spp_diag_trace.h/.c")
        if "conf_proc_spp_diag_trace_semantics" in text:
            violations.append(f"{p.name}: forbidden reference to semantic reducer")
        for hook_pat in forbidden_lsm:
            if hook_pat in text:
                violations.append(f"{p.name}: forbidden real LSM hook registration pattern: {hook_pat}")
    adapter = (root / "spp-diag-trace-core-src/security/spp_diag_trace_core/adapter.c").read_text(encoding="utf-8")
    for required in (
        "file->f_flags & __FMODE_EXEC",
        "size > INT_MAX",
        "spp_diag_trace_adapter_sendmsg_precheck",
        "ntohl(sin6->sin6_flowinfo)",
    ):
        if required not in adapter:
            violations.append(f"adapter.c: missing exact adapter invariant {required}")
    for forbidden in ("file->f_mode & FMODE_EXEC", "sock->ops->getname"):
        if forbidden in adapter:
            violations.append(f"adapter.c: forbidden lossy adapter path {forbidden}")
    return violations


# AC1: the K4 adapter calls are deliberately tied to the named source-function
# replacement, not merely counted somewhere in the destination file.
EXACT_SITES = (
    ("security/security.c", "ret = call_int_hook(bprm_check_security", "spp_diag_trace_adapter_exec_pass(", 1),
    ("security/security.c", "call_void_hook(bprm_committed_creds", "spp_diag_trace_adapter_exec_commit(", 1),
    ("fs/exec.c", "static int bprm_execve(", "spp_diag_trace_adapter_exec_return(", 1),
    ("fs/exec.c", "static int do_execveat_common(", "spp_diag_trace_adapter_exec_reserve(", 1),
    ("fs/exec.c", "static int do_execveat_common(", "spp_diag_trace_adapter_exec_unsupported(", 2),
    ("fs/exec.c", "static int do_execveat_common(", "spp_diag_trace_adapter_exec_return(", 1),
    ("fs/exec.c", "int kernel_execve(", "spp_diag_trace_adapter_exec_reserve(", 1),
    ("fs/exec.c", "int kernel_execve(", "spp_diag_trace_adapter_exec_unsupported(", 2),
    ("fs/exec.c", "int kernel_execve(", "spp_diag_trace_adapter_exec_return(", 1),
    ("kernel/fork.c", "INIT_HLIST_NODE(&delayed.node);", "spp_diag_trace_adapter_task_alloc(", 1),
    ("kernel/fork.c", "copy_oom_score_adj(clone_flags, p);", "spp_diag_trace_adapter_task_created(", 1),
    ("kernel/exit.c", "tsk->exit_code = code;", "spp_diag_trace_adapter_task_exit(", 1),
    ("fs/open.c", "static long do_sys_openat2(", "spp_diag_trace_adapter_file_open_attempt(", 1),
    ("fs/open.c", "static long do_sys_openat2(", "spp_diag_trace_adapter_file_open_return(", 1),
    ("fs/open.c", "error = security_file_open(f);", "spp_diag_trace_adapter_file_open_policy(", 1),
    ("mm/util.c", "unsigned long vm_mmap_pgoff(", "spp_diag_trace_adapter_mapping_policy(", 1),
    ("mm/util.c", "unsigned long vm_mmap_pgoff(", "spp_diag_trace_adapter_mapping_return(", 2),
    ("mm/mmap.c", "ret = security_mmap_file(file, prot, flags);", "spp_diag_trace_adapter_mapping_unsupported(", 1),
    ("ipc/shm.c", "err = security_mmap_file(file, prot, flags);", "spp_diag_trace_adapter_mapping_unsupported(", 1),
    ("mm/mprotect.c", "static int do_mprotect_pkey(", "spp_diag_trace_adapter_mprotect_policy(", 1),
    ("mm/mprotect.c", "static int do_mprotect_pkey(", "spp_diag_trace_adapter_mprotect_return(", 1),
    ("net/socket.c", "static int __sock_sendmsg(", "spp_diag_trace_adapter_sendmsg_policy(", 1),
    ("net/socket.c", "static int __sock_sendmsg(", "spp_diag_trace_adapter_sendmsg_precheck(", 1),
    ("net/socket.c", "static int __sock_sendmsg(", "spp_diag_trace_adapter_sendmsg_return(", 1),
    ("net/socket.c", "int __sys_connect_file(", "spp_diag_trace_adapter_connect_policy(", 1),
    ("net/socket.c", "int __sys_connect_file(", "spp_diag_trace_adapter_connect_return(", 1),
    ("net/socket.c", "err = sock_sendmsg_nosec(sock, msg_sys);", "spp_diag_trace_adapter_sendmsg_unsupported(", 1),
    ("net/socket.c", "int kernel_connect(", "spp_diag_trace_adapter_connect_unsupported(", 1),
    ("net/socket.c", "int kernel_sendmsg_locked(", "spp_diag_trace_adapter_sendmsg_unsupported(", 1),
)


def exact_site_check(manifest: dict) -> list[str]:
    violations: list[str] = []
    targets = [item for item in manifest["targets"] if item.get("kind") == "REPLACE"]
    for destination, anchor_part, call, expected_count in EXACT_SITES:
        matching = [
            item for item in targets
            if item.get("destination") == destination and anchor_part in item.get("anchor", "")
        ]
        count = sum(item.get("insertion", "").count(call) for item in matching)
        if len(matching) != 1 or count != expected_count:
            violations.append(
                f"{destination}:{anchor_part!r}: {call} count={count}, targets={len(matching)}"
            )
    return violations


def adapter_k3off_check(makefile_text: str) -> list[str]:
    required = (
        "SPP_DIAG_TRACE_CORE_RUNTIME_ADAPTER_OFF_FIXTURE",
        "spp-diag-trace-core-runtime-adapter-off.o",
        "spp_diag_trace_adapter_",
    )
    return [f"missing K3-off adapter identity check: {item}" for item in required if item not in makefile_text]


def main() -> int:
    # --- AC9: dormancy walk (unchanged behavior) ---
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

    # --- AC7: GPL/AGPL license classification ---
    checked, violations = license_check()
    if checked == 0:
        print("FAIL license-check scanned zero files")
        return 1
    if violations:
        print("FAIL license-check violations on clean tree:")
        print("\n".join(violations))
        return 1
    print(f"ok   license-check-clean checked={checked}")

    # --- AC7: mixed-body fixture must be rejected (real planted file, so the
    # allowlist walk actually reaches it) ---
    mixed = ROOT / "test" / "conf-proc-spp-diag-trace-core-zzz-mixed-license-plant.c"
    try:
        mixed.write_text(
            "/* SPDX-License-Identifier: GPL-2.0-only */\n"
            "/* SPDX-License-Identifier: AGPL-3.0-only */\n"
            "void mixed_license_marker(void) {}\n",
            encoding="utf-8",
        )
        _checked, mixed_violations = license_check()
        if not mixed_violations:
            print("FAIL planted mixed-license body was not detected")
            return 1
        print("ok   license-check-detects-mixed-body")
    finally:
        try:
            mixed.unlink()
        except FileNotFoundError:
            pass
    checked_after, violations_after = license_check()
    if violations_after:
        print("FAIL license-check violations after mixed-body cleanup:")
        print("\n".join(violations_after))
        return 1
    if checked_after == 0:
        print("FAIL license-check scanned zero files after cleanup")
        return 1
    print(f"ok   license-check-restored checked={checked_after}")

    # --- AC7: detached-executable closure (every compile/link line is
    # single-license); real red case proven against a synthetic Makefile
    # text, not the checked-in file ---
    makefile_text = (ROOT / "Makefile").read_text(encoding="utf-8")
    closure_checked, closure_violations = closure_check(makefile_text)
    if closure_checked == 0:
        print("FAIL closure-check found zero compile/link lines")
        return 1
    if closure_violations:
        print("FAIL closure-check violations on clean Makefile:")
        print("\n".join(closure_violations))
        return 1
    print(f"ok   closure-check-clean checked={closure_checked}")

    mixed_makefile = makefile_text.replace(
        "$(CC) $(C11FLAGS) $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_CORE_FIELD_CLASSIFIER) -o build/spp-diag-trace-core-field-classifier",
        "$(CC) $(C11FLAGS) $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_FIELD_CLASSIFIER) -o build/spp-diag-trace-core-field-classifier",
    )
    if mixed_makefile == makefile_text:
        print("FAIL closure-check red-case setup: anchor line not found in Makefile")
        return 1
    _mixed_checked, mixed_closure_violations = closure_check(mixed_makefile)
    if not mixed_closure_violations:
        print("FAIL closure-check did not flag a synthetic mixed-license link line")
        return 1
    print("ok   closure-check-detects-mixed-link")

    # --- AC8: KUnit suite/case-list source check ---
    case_count, kunit_violations = kunit_case_check()
    if kunit_violations:
        print("FAIL kunit-case-check violations on clean core_kunit.c:")
        print("\n".join(kunit_violations))
        return 1
    if case_count == 0:
        print("FAIL kunit-case-check found zero cases")
        return 1
    print(f"ok   kunit-case-check-clean cases={case_count}")

    clean_text = (ROOT / KUNIT_CORE_FILE).read_text(encoding="utf-8")
    mutated_text = clean_text.replace(
        f"KUNIT_CASE({KUNIT_CASE_NAMES[0]}),", "", 1
    )
    if mutated_text == clean_text:
        print("FAIL kunit-case-check red-case setup: anchor case not found")
        return 1
    mutated_count, mutated_violations = kunit_case_check_text(mutated_text)
    if not mutated_violations:
        print("FAIL kunit-case-check did not flag a removed case")
        return 1
    print(f"ok   kunit-case-check-detects-removal cases={mutated_count}")

    suite_mutated = clean_text.replace(
        "kunit_test_suite(spp_diag_trace_core_suite);", "", 1
    )
    if suite_mutated == clean_text:
        print("FAIL kunit-case-check red-case setup: suite registration not found")
        return 1
    _n, suite_violations = kunit_case_check_text(suite_mutated)
    if not suite_violations:
        print("FAIL kunit-case-check did not flag a removed suite registration")
        return 1
    print("ok   kunit-case-check-detects-suite-removal")

    bootstrap_text = (ROOT / KUNIT_BOOTSTRAP_FILE).read_text(encoding="utf-8")
    bootstrap_count, bootstrap_violations = bootstrap_kunit_case_check_text(bootstrap_text)
    if bootstrap_violations or bootstrap_count == 0:
        print(f"FAIL bootstrap-kunit-case-check {bootstrap_violations}")
        return 1
    mutated_bootstrap = bootstrap_text.replace(
        f"KUNIT_CASE({KUNIT_BOOTSTRAP_CASE_NAMES[0]}),", "", 1
    )
    if not bootstrap_kunit_case_check_text(mutated_bootstrap)[1]:
        print("FAIL bootstrap-kunit-case-check did not flag a removed case")
        return 1
    print(f"ok   bootstrap-kunit-case-check-clean cases={bootstrap_count}")

    wiring_violations = bootstrap_wiring_check()
    if wiring_violations:
        print(f"FAIL bootstrap-wiring-check {wiring_violations}")
        return 1
    print("ok   bootstrap-wiring-check")

    runtime_text = (ROOT / KUNIT_RUNTIME_FILE).read_text(encoding="utf-8")
    runtime_count, runtime_violations = runtime_kunit_case_check_text(runtime_text)
    if runtime_violations or runtime_count == 0:
        print(f"FAIL runtime-kunit-case-check {runtime_violations}")
        return 1
    mutated_runtime = runtime_text.replace(
        f"KUNIT_CASE({KUNIT_RUNTIME_CASE_NAMES[0]}),", "", 1
    )
    if not runtime_kunit_case_check_text(mutated_runtime)[1]:
        print("FAIL runtime-kunit-case-check did not flag a removed case")
        return 1
    print(f"ok   runtime-kunit-case-check-clean cases={runtime_count}")

    runtime_violations = runtime_source_walk_check()
    if runtime_violations:
        print(f"FAIL runtime-source-walk-check {runtime_violations}")
        return 1
    print("ok   runtime-source-walk-check")

    manifest = json.loads((ROOT / "spp-diag-trace-core-src/manifest.json").read_text(encoding="utf-8"))
    exact_violations = exact_site_check(manifest)
    if exact_violations:
        print(f"FAIL exact-site-check {exact_violations}")
        return 1
    print(f"ok   exact-site-check sites={len(EXACT_SITES)}")
    moved = json.loads(json.dumps(manifest))
    source = next(item for item in moved["targets"] if item.get("destination") == "security/security.c" and
                  "ret = call_int_hook(bprm_check_security" in item.get("anchor", ""))
    neighbor = next(item for item in moved["targets"] if item.get("destination") == "security/security.c" and
                    "call_void_hook(bprm_committed_creds" in item.get("anchor", ""))
    source["insertion"] = source["insertion"].replace("spp_diag_trace_adapter_exec_pass(bprm);", "")
    neighbor["insertion"] += "\tspp_diag_trace_adapter_exec_pass(bprm);\n"
    if not exact_site_check(moved):
        print("FAIL exact-site-check did not reject a moved neighbouring-function adapter call")
        return 1
    duplicate = json.loads(json.dumps(manifest))
    duplicate_target = next(item for item in duplicate["targets"] if item.get("destination") == "net/socket.c" and
                            "static int __sock_sendmsg(" in item.get("anchor", ""))
    duplicate_target["insertion"] += "\tspp_diag_trace_adapter_sendmsg_policy(sock, msg, 0, 0);\n"
    if not exact_site_check(duplicate):
        print("FAIL exact-site-check did not reject a duplicated adapter call")
        return 1
    print("ok   exact-site-check-detects-move-and-duplicate")

    adapter_off_violations = adapter_k3off_check(makefile_text)
    if adapter_off_violations:
        print(f"FAIL adapter-k3off-check {adapter_off_violations}")
        return 1
    if not adapter_k3off_check(makefile_text.replace("spp_diag_trace_adapter_", "spp_diag_trace_removed_", 1)):
        print("FAIL adapter-k3off-check did not reject a removed adapter symbol check")
        return 1
    print("ok   adapter-k3off-check")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
