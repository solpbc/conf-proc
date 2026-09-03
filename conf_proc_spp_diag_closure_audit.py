#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independently derive byte-based ELF/Python/AppArmor/dlopen reachability to a fixed point; must not import producer manifests or install inventory."""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass
import hashlib
import os
import posixpath
import re

from conf_proc_elf import is_elf, parse_elf
from conf_proc_spp_diag_closure_audit_reasons import (
    CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_ESCAPE,
    CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_WILDCARD,
    CP_SPP_DIAG_CLOSURE_AUDIT_DYNAMIC_IMPORT,
    CP_SPP_DIAG_CLOSURE_AUDIT_EXTERNAL,
    CP_SPP_DIAG_CLOSURE_AUDIT_RELATIVE_IMPORT,
    CP_SPP_DIAG_CLOSURE_AUDIT_UNREADABLE,
    SppDiagClosureAuditError,
)


_APPARMOR_INCLUDE = re.compile(r'^\s*#include\s+(<([^>]+)>|"([^"]+)")\s*$')
_ELF_EDGE_KINDS = frozenset({"elf_interp", "elf_needed", "elf_rpath", "elf_runpath"})


@dataclass(frozen=True)
class ClosureNode:
    path: str
    sha256: str
    kind: str


@dataclass(frozen=True)
class ClosureEdge:
    from_path: str
    to_path: str
    kind: str
    external: bool


@dataclass(frozen=True)
class ClosureObservation:
    nodes: frozenset[ClosureNode]
    edges: frozenset[ClosureEdge]


def audit_closure(
    staged_root: str,
    entrypoints: tuple[str, ...],
    *,
    allowed_external: frozenset[str],
    dlopen_literals: frozenset[str] = frozenset(),
    apparmor_paths: frozenset[str] = frozenset(),
) -> ClosureObservation:
    """Observe the reachable closure; external allowlisting is intentionally deferred to ``check_closure_allowed``."""

    del allowed_external
    auditor = _ClosureAuditor(staged_root, dlopen_literals=dlopen_literals, apparmor_paths=apparmor_paths)
    return auditor.audit(entrypoints)


def check_closure_allowed(
    observation: ClosureObservation,
    *,
    allowed_python_modules: frozenset[str],
    allowed_elf_libraries: frozenset[str],
    allowed_dlopen: frozenset[str],
    allowed_apparmor_includes: frozenset[str],
) -> None:
    """Reject any observed external edge outside its kind-specific allowlist."""

    for edge in observation.edges:
        if not edge.external:
            continue
        if edge.kind == "python_import":
            allowed = allowed_python_modules
        elif edge.kind in _ELF_EDGE_KINDS:
            allowed = allowed_elf_libraries
        elif edge.kind == "dlopen":
            allowed = allowed_dlopen
        elif edge.kind == "apparmor_include":
            allowed = allowed_apparmor_includes
        else:
            _fail(CP_SPP_DIAG_CLOSURE_AUDIT_EXTERNAL)
        if edge.to_path not in allowed:
            _fail(CP_SPP_DIAG_CLOSURE_AUDIT_EXTERNAL)


class _ClosureAuditor:
    def __init__(self, staged_root: str, *, dlopen_literals: frozenset[str], apparmor_paths: frozenset[str]) -> None:
        self.root = os.path.realpath(staged_root)
        self.dlopen_literals = dlopen_literals
        self.apparmor_paths = apparmor_paths
        self.nodes: set[ClosureNode] = set()
        self.edges: set[ClosureEdge] = set()
        self.visited: set[str] = set()
        self.worklist: deque[str] = deque()

    def audit(self, entrypoints: tuple[str, ...]) -> ClosureObservation:
        self.worklist.extend(entrypoints)
        while self.worklist:
            path = self.worklist.popleft()
            if path in self.visited:
                continue
            data = self._read(path)
            self.visited.add(path)
            self._observe_node(path, data)
        return ClosureObservation(nodes=frozenset(self.nodes), edges=frozenset(self.edges))

    def _observe_node(self, path: str, data: bytes) -> None:
        kind = "opaque"
        if is_elf(data):
            kind = "elf"
            self._observe_elf(path, data)
        elif path.endswith(".py"):
            try:
                source = data.decode("utf-8")
            except UnicodeDecodeError:
                source = None
            if source is not None:
                kind = "python"
                self._observe_python(path, source)
        elif path in self.apparmor_paths:
            kind = "apparmor"
            self._observe_apparmor(path, data)
        self.nodes.add(ClosureNode(path=path, sha256=hashlib.sha256(data).hexdigest(), kind=kind))

    def _observe_elf(self, path: str, data: bytes) -> None:
        info = parse_elf(data)
        if info.interpreter is not None:
            internal_path = info.interpreter.lstrip("/")
            if _is_relative_path(internal_path) and self._exists(internal_path):
                self._add_internal_edge(path, internal_path, "elf_interp")
            else:
                self._add_external_edge(path, info.interpreter, "elf_interp")
        for needed in info.needed:
            self._add_external_edge(path, needed, "elf_needed")
        for rpath in info.rpath:
            self._add_external_edge(path, rpath, "elf_rpath")
        for runpath in info.runpath:
            self._add_external_edge(path, runpath, "elf_runpath")
        for literal in self.dlopen_literals:
            if _contains_nul_terminated_ascii(data, literal):
                self._add_external_edge(path, literal, "dlopen")

    def _observe_python(self, path: str, source: str) -> None:
        tree = ast.parse(source, filename=path)
        importlib_modules, import_module_names = _importlib_bindings(tree)
        imported_modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:
                    _fail(CP_SPP_DIAG_CLOSURE_AUDIT_RELATIVE_IMPORT)
                if node.module is not None:
                    imported_modules.append(node.module)
            elif isinstance(node, ast.Call) and _is_dynamic_import(node.func, importlib_modules, import_module_names):
                _fail(CP_SPP_DIAG_CLOSURE_AUDIT_DYNAMIC_IMPORT)
        for module_name in imported_modules:
            module_path = module_name.replace(".", "/") + ".py"
            if self._exists(module_path):
                self._add_internal_edge(path, module_path, "python_import")
            else:
                self._add_external_edge(path, module_name, "python_import")

    def _observe_apparmor(self, path: str, data: bytes) -> None:
        for line in data.decode("utf-8", "replace").splitlines():
            match = _APPARMOR_INCLUDE.match(line)
            if match is None:
                continue
            include_path = match.group(2) or match.group(3)
            if any(character in include_path for character in "*?$"):
                _fail(CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_WILDCARD)
            if match.group(2) is not None:
                self._add_external_edge(path, include_path, "apparmor_include")
                continue
            if not _is_relative_path(include_path):
                _fail(CP_SPP_DIAG_CLOSURE_AUDIT_APPARMOR_INCLUDE_ESCAPE)
            if self._exists(include_path):
                self._add_internal_edge(path, include_path, "apparmor_include")
            else:
                self._add_external_edge(path, include_path, "apparmor_include")

    def _add_internal_edge(self, from_path: str, to_path: str, kind: str) -> None:
        if not self._exists(to_path):
            _fail(CP_SPP_DIAG_CLOSURE_AUDIT_UNREADABLE)
        self.edges.add(ClosureEdge(from_path=from_path, to_path=to_path, kind=kind, external=False))
        if to_path not in self.visited:
            self.worklist.append(to_path)

    def _add_external_edge(self, from_path: str, to_path: str, kind: str) -> None:
        self.edges.add(ClosureEdge(from_path=from_path, to_path=to_path, kind=kind, external=True))

    def _exists(self, path: str) -> bool:
        if not _is_relative_path(path):
            return False
        return os.path.isfile(self._absolute(path))

    def _read(self, path: str) -> bytes:
        if not _is_relative_path(path):
            _fail(CP_SPP_DIAG_CLOSURE_AUDIT_UNREADABLE)
        absolute_path = self._absolute(path)
        try:
            with open(absolute_path, "rb") as handle:
                return handle.read()
        except OSError:
            _fail(CP_SPP_DIAG_CLOSURE_AUDIT_UNREADABLE)

    def _absolute(self, path: str) -> str:
        candidate = os.path.realpath(os.path.join(self.root, path))
        try:
            contained = os.path.commonpath((self.root, candidate)) == self.root
        except ValueError:
            contained = False
        if not contained:
            _fail(CP_SPP_DIAG_CLOSURE_AUDIT_UNREADABLE)
        return candidate


def _importlib_bindings(tree: ast.AST) -> tuple[frozenset[str], frozenset[str]]:
    importlib_modules: set[str] = set()
    import_module_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_modules.add(alias.asname or "importlib")
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    import_module_names.add(alias.asname or "import_module")
    return frozenset(importlib_modules), frozenset(import_module_names)


def _is_dynamic_import(func: ast.expr, importlib_modules: frozenset[str], import_module_names: frozenset[str]) -> bool:
    if isinstance(func, ast.Name):
        return func.id == "__import__" or func.id in import_module_names
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "import_module"
        and isinstance(func.value, ast.Name)
        and func.value.id in importlib_modules
    )


def _contains_nul_terminated_ascii(data: bytes, literal: str) -> bool:
    try:
        literal.encode("ascii")
    except UnicodeEncodeError:
        return False
    for candidate in data.split(b"\x00"):
        try:
            if candidate.decode("ascii") == literal:
                return True
        except UnicodeDecodeError:
            continue
    return False


def _is_relative_path(path: object) -> bool:
    if type(path) is not str or not path or path.startswith("/") or "\x00" in path:
        return False
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    return posixpath.normpath(path) == path


def _fail(reason_code: str) -> None:
    raise SppDiagClosureAuditError(reason_code)
