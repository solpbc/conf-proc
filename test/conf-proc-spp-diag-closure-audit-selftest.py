#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Synthetic-fixture contract tests for the independent closure auditor."""

from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import conf_proc_spp_diag_closure_audit as audit  # noqa: E402
from conf_proc_elf import parse_elf  # noqa: E402
from conf_proc_spp_diag_closure_audit_reasons import (  # noqa: E402
    CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_ESCAPE,
    CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_WILDCARD,
    CP_SPP_DIAG_CLOSURE_AUDIT_DYNAMIC_IMPORT,
    CP_SPP_DIAG_CLOSURE_AUDIT_EXTERNAL,
    CP_SPP_DIAG_CLOSURE_AUDIT_RELATIVE_IMPORT,
    SppDiagClosureAuditError,
)


def _compile(root: Path, name: str, source: str, *flags: str) -> Path | None:
    source_path = root / f"{name}.c"
    binary_path = root / name
    source_path.write_text(source, encoding="utf-8")
    try:
        completed = subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", *flags, str(source_path), "-o", str(binary_path)],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print(f"skip {name}: cc is unavailable")
        return None
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        suffix = detail[-1] if detail else f"exit {completed.returncode}"
        print(f"skip {name}: compiler could not build fixture: {suffix}")
        return None
    return binary_path


def _edge(observation: audit.ClosureObservation, from_path: str, to_path: str, kind: str, external: bool) -> audit.ClosureEdge:
    wanted = audit.ClosureEdge(from_path=from_path, to_path=to_path, kind=kind, external=external)
    assert wanted in observation.edges
    return wanted


def _expect(reason_code: str, callback) -> None:
    try:
        callback()
    except SppDiagClosureAuditError as exc:
        assert exc.reason_code == reason_code
    else:
        raise AssertionError(f"expected {reason_code}")


def test_dynamic_elf_edges(root: Path) -> None:
    binary = _compile(root, "dynamic", "int main(void) { return 0; }\n")
    if binary is None:
        return
    info = parse_elf(binary.read_bytes())
    assert info.interpreter is not None
    assert info.needed
    observation = audit.audit_closure(str(root), ("dynamic",), allowed_external=frozenset())
    _edge(observation, "dynamic", info.interpreter, "elf_interp", True)
    for needed in info.needed:
        _edge(observation, "dynamic", needed, "elf_needed", True)
    assert all(edge.external for edge in observation.edges)


def test_static_elf_has_no_interpreter(root: Path) -> None:
    binary = _compile(root, "static", "int main(void) { return 0; }\n", "-static")
    if binary is None:
        return
    info = parse_elf(binary.read_bytes())
    assert info.interpreter is None
    assert not info.needed
    observation = audit.audit_closure(str(root), ("static",), allowed_external=frozenset())
    assert not {edge for edge in observation.edges if edge.kind in {"elf_interp", "elf_needed"}}


def test_dlopen_literal_edges(root: Path) -> None:
    with_literal = _compile(
        root,
        "with_cuda_literal",
        'const char *volatile x = "libcuda.so.1"; int main(void) { return x[0] == 0; }\n',
    )
    without_literal = _compile(
        root,
        "without_cuda_literal",
        'const char *volatile x = "libnotcuda.so.1"; int main(void) { return x[0] == 0; }\n',
    )
    if with_literal is None or without_literal is None:
        return
    literals = frozenset({"libcuda.so.1"})
    observed_with = audit.audit_closure(str(root), ("with_cuda_literal",), allowed_external=frozenset(), dlopen_literals=literals)
    observed_without = audit.audit_closure(str(root), ("without_cuda_literal",), allowed_external=frozenset(), dlopen_literals=literals)
    _edge(observed_with, "with_cuda_literal", "libcuda.so.1", "dlopen", True)
    assert not {edge for edge in observed_without.edges if edge.kind == "dlopen"}


def test_python_imports_are_ast_derived(root: Path) -> None:
    (root / "imports.py").write_text(
        '"""socket in documentation is not an import."""\n# socket in a comment\nimport os\nimport socket as s\n',
        encoding="utf-8",
    )
    observation = audit.audit_closure(str(root), ("imports.py",), allowed_external=frozenset())
    _edge(observation, "imports.py", "os", "python_import", True)
    _edge(observation, "imports.py", "socket", "python_import", True)
    assert len({edge for edge in observation.edges if edge.kind == "python_import"}) == 2


def test_python_rejections(root: Path) -> None:
    (root / "relative.py").write_text("from . import foo\n", encoding="utf-8")
    _expect(
        CP_SPP_DIAG_CLOSURE_AUDIT_RELATIVE_IMPORT,
        lambda: audit.audit_closure(str(root), ("relative.py",), allowed_external=frozenset()),
    )
    (root / "dynamic_importlib.py").write_text("import importlib\nimportlib.import_module('os')\n", encoding="utf-8")
    _expect(
        CP_SPP_DIAG_CLOSURE_AUDIT_DYNAMIC_IMPORT,
        lambda: audit.audit_closure(str(root), ("dynamic_importlib.py",), allowed_external=frozenset()),
    )
    (root / "dynamic_builtin.py").write_text("__import__('os')\n", encoding="utf-8")
    _expect(
        CP_SPP_DIAG_CLOSURE_AUDIT_DYNAMIC_IMPORT,
        lambda: audit.audit_closure(str(root), ("dynamic_builtin.py",), allowed_external=frozenset()),
    )


def test_python_transitive_closure(root: Path) -> None:
    (root / "main.py").write_text("import child\n", encoding="utf-8")
    (root / "child.py").write_text("import os\n", encoding="utf-8")
    observation = audit.audit_closure(str(root), ("main.py",), allowed_external=frozenset())
    assert {node.path for node in observation.nodes} == {"main.py", "child.py"}
    _edge(observation, "main.py", "child.py", "python_import", False)
    _edge(observation, "child.py", "os", "python_import", True)


def test_apparmor_includes(root: Path) -> None:
    (root / "policy").mkdir()
    (root / "local").mkdir()
    (root / "local" / "foo").write_text("opaque policy fragment\n", encoding="utf-8")
    (root / "policy" / "profile").write_text('#include <abstractions/base>\n#include "local/foo"\n', encoding="utf-8")
    policy_paths = frozenset({"policy/profile"})
    observation = audit.audit_closure(
        str(root),
        ("policy/profile",),
        allowed_external=frozenset(),
        apparmor_paths=policy_paths,
    )
    _edge(observation, "policy/profile", "abstractions/base", "apparmor_include", True)
    _edge(observation, "policy/profile", "local/foo", "apparmor_include", False)
    assert audit.ClosureNode("local/foo", hashlib.sha256(b"opaque policy fragment\n").hexdigest(), "opaque") in observation.nodes

    (root / "policy" / "escape").write_text('#include "../escape"\n', encoding="utf-8")
    _expect(
        CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_ESCAPE,
        lambda: audit.audit_closure(
            str(root), ("policy/escape",), allowed_external=frozenset(), apparmor_paths=frozenset({"policy/escape"})
        ),
    )
    (root / "policy" / "wildcard").write_text("#include <abstractions/*>\n", encoding="utf-8")
    _expect(
        CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_WILDCARD,
        lambda: audit.audit_closure(
            str(root), ("policy/wildcard",), allowed_external=frozenset(), apparmor_paths=frozenset({"policy/wildcard"})
        ),
    )


def test_allowlists() -> None:
    allowed = audit.ClosureObservation(
        nodes=frozenset(),
        edges=frozenset(
            {
                audit.ClosureEdge("main.py", "os", "python_import", True),
                audit.ClosureEdge("elf", "libc.so.6", "elf_needed", True),
                audit.ClosureEdge("elf", "libcuda.so.1", "dlopen", True),
                audit.ClosureEdge("policy", "abstractions/base", "apparmor_include", True),
            }
        ),
    )
    audit.check_closure_allowed(
        allowed,
        allowed_python_modules=frozenset({"os"}),
        allowed_elf_libraries=frozenset({"libc.so.6"}),
        allowed_dlopen=frozenset({"libcuda.so.1"}),
        allowed_apparmor_includes=frozenset({"abstractions/base"}),
    )
    rejected = replace(
        allowed,
        edges=allowed.edges | frozenset({audit.ClosureEdge("main.py", "socket", "python_import", True)}),
    )
    _expect(
        CP_SPP_DIAG_CLOSURE_AUDIT_EXTERNAL,
        lambda: audit.check_closure_allowed(
            rejected,
            allowed_python_modules=frozenset({"os"}),
            allowed_elf_libraries=frozenset({"libc.so.6"}),
            allowed_dlopen=frozenset({"libcuda.so.1"}),
            allowed_apparmor_includes=frozenset({"abstractions/base"}),
        ),
    )


def test_static_independence() -> None:
    source = (ROOT / "conf_proc_spp_diag_closure_audit.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imports = (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports = (node.module or "",)
        else:
            continue
        assert all(name != "conf_proc_spp_diag_input_closure_manifest" and "install_inventory" not in name for name in imports)


TESTS = (
    test_dynamic_elf_edges,
    test_static_elf_has_no_interpreter,
    test_dlopen_literal_edges,
    test_python_imports_are_ast_derived,
    test_python_rejections,
    test_python_transitive_closure,
    test_apparmor_includes,
)


def main() -> None:
    with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
        root = Path(temporary)
        for test in TESTS:
            test(root)
            print(f"ok   {test.__name__}")
    test_allowlists()
    print("ok   test_allowlists")
    test_static_independence()
    print("ok   test_static_independence")
    print("SPP diagnostic closure audit: ok (9 tests)")


if __name__ == "__main__":
    main()
