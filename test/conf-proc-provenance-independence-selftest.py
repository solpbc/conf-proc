#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Repository policy gates for provenance-v2 independence and dormancy."""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEALED_NAMES = ("conf_proc_inspect_provenance", "conf_proc_inspect_provenance_cli")
THIS_FILE = Path(__file__).name
THIS_FILE_ID = "test/" + THIS_FILE
REFERENCE_EXEMPT_FILES = {
    THIS_FILE_ID,
    "conf_proc_inspect_provenance_cli.py",
    "test/conf-proc-provenance-oracle-selftest.py",
}
DIRECT_IMPORT_ALLOWLIST = {
    "test/conf-proc-provenance-oracle-selftest.py": frozenset({"conf_proc_inspect_provenance"}),
}
SEALED_OPERATION_EXEMPT_FILES = {
    "conf_proc_inspect_provenance_cli.py",
    "test/conf-proc-provenance-oracle-selftest.py",
}
DYNAMIC_LOAD_CALLS = frozenset(
    {
        "__import__",
        "builtins.__import__",
        "importlib.import_module",
        "importlib.util.spec_from_file_location",
        "importlib.util.module_from_spec",
        "runpy.run_module",
        "runpy.run_path",
        "exec_module",
    }
)
SUBPROCESS_CALLS = frozenset(
    {
        "os.popen",
        "os.system",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
    }
)
PATH_CONSTRUCTION_CALLS = frozenset({"Path", "pathlib.Path", "open", "os.path.join", "posixpath.join"})
DORMANT_MODULES = frozenset({"conf_proc_provenance_v2", "conf_proc_provenance_render"})
DORMANT_POLICY_FILES = frozenset(
    {
        "conf_proc_provenance_v2.py",
        "conf_proc_provenance_render.py",
        "test/conf-proc-provenance-v2-selftest.py",
        "test/conf-proc-provenance-render-selftest.py",
        "test/conf-proc-provenance-native-kat-selftest.py",
    }
)
PROHIBITED_RUNTIME_IMPORT_ROOTS = frozenset({"builtins", "importlib", "runpy", "subprocess"})
PROHIBITED_RUNTIME_CALLS = DYNAMIC_LOAD_CALLS | SUBPROCESS_CALLS | frozenset(
    {"compile", "eval", "exec", "builtins.compile", "builtins.eval", "builtins.exec"}
)
_MAPPING_PLACEHOLDER = re.compile(r"%\(([^)]+)\)s")
_STATIC_FORMAT_PREFIX = "<static-format>:"
_STATIC_FORMAT_MAP_PREFIX = "<static-format-map>:"
PATH_ACCESS_METHODS = frozenset({"joinpath", "open", "read_bytes", "read_text"})


def _candidate_files() -> list[Path]:
    return sorted(ROOT.glob("*.py")) + sorted((ROOT / "test").glob("*.py"))


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                local_name = imported.asname or imported.name.split(".", 1)[0]
                aliases[local_name] = imported.name
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            for imported in node.names:
                local_name = imported.asname or imported.name
                aliases[local_name] = node.module + "." + imported.name
    return aliases


def _call_name(
    node: ast.AST,
    aliases: dict[str, str],
    constants: dict[str, frozenset[str]] | None = None,
    mappings: dict[str, tuple[dict[str, str], ...]] | None = None,
) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value, aliases, constants, mappings)
        return node.attr if prefix is None else prefix + "." + node.attr
    if isinstance(node, ast.Call):
        getter = _call_name(node.func, aliases, constants, mappings)
        if getter in ("getattr", "builtins.getattr") and len(node.args) >= 2:
            prefix = _call_name(node.args[0], aliases, constants, mappings)
            attributes = _static_strings(node.args[1], constants or {}, aliases, mappings or {})
            if prefix is not None and attributes:
                longest = frozenset(value for value in attributes if len(value) == max(map(len, attributes)))
                if len(longest) == 1:
                    return prefix + "." + next(iter(longest))
    return None


def _static_mappings(
    node: ast.AST,
    constants: dict[str, frozenset[str]],
    aliases: dict[str, str],
    mappings: dict[str, tuple[dict[str, str], ...]],
) -> tuple[dict[str, str], ...]:
    if isinstance(node, ast.Name):
        return mappings.get(node.id, ())
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _static_mappings(node.left, constants, aliases, mappings)
        right = _static_mappings(node.right, constants, aliases, mappings)
        return tuple({**first, **second} for first in left for second in right)
    if isinstance(node, ast.Call) and _call_name(node.func, aliases, constants, mappings) in ("dict", "builtins.dict"):
        variants: tuple[dict[str, str], ...] = ({},)
        for argument in node.args:
            extensions = _static_mappings(argument, constants, aliases, mappings)
            variants = tuple({**prior, **extension} for prior in variants for extension in extensions)
        for keyword in node.keywords:
            if keyword.arg is None:
                extensions = _static_mappings(keyword.value, constants, aliases, mappings)
                variants = tuple({**prior, **extension} for prior in variants for extension in extensions)
            else:
                values = _static_strings(keyword.value, constants, aliases, mappings)
                variants = tuple({**prior, keyword.arg: value} for prior in variants for value in values)
        return variants
    if not isinstance(node, ast.Dict):
        return ()
    variants: tuple[dict[str, str], ...] = ({},)
    for key_node, value_node in zip(node.keys, node.values, strict=True):
        if key_node is None:
            extensions = _static_mappings(value_node, constants, aliases, mappings)
            if not extensions:
                return ()
            variants = tuple({**prior, **extension} for prior in variants for extension in extensions)
            continue
        keys = _static_strings(key_node, constants, aliases, mappings)
        values = _static_strings(value_node, constants, aliases, mappings)
        if not keys or not values:
            return ()
        next_variants: list[dict[str, str]] = []
        for prior in variants:
            for key in keys:
                for value in values:
                    if key not in prior:
                        next_variants.append({**prior, key: value})
        variants = tuple(next_variants)
    return variants


def _render_static_format(
    node: ast.Call,
    templates: frozenset[str],
    constants: dict[str, frozenset[str]],
    aliases: dict[str, str],
    mappings: dict[str, tuple[dict[str, str], ...]],
    *,
    mapping_only: bool,
) -> frozenset[str]:
    rendered: set[str] = set()
    if mapping_only:
        if len(node.args) != 1 or node.keywords:
            return frozenset()
        for template in templates:
            for mapping in _static_mappings(node.args[0], constants, aliases, mappings):
                try:
                    rendered.add(template.format_map(mapping))
                except (KeyError, ValueError):
                    continue
        return frozenset(rendered)

    combinations: set[tuple[str, ...]] = {()}
    for argument in node.args:
        choices = _static_strings(argument, constants, aliases, mappings)
        combinations = {prefix + (choice,) for prefix in combinations for choice in choices}
    keyword_sets: dict[str, frozenset[str]] = {
        keyword.arg: _static_strings(keyword.value, constants, aliases, mappings)
        for keyword in node.keywords
        if keyword.arg is not None
    }
    keyword_combinations: set[tuple[tuple[str, str], ...]] = {()}
    for key, choices in keyword_sets.items():
        keyword_combinations = {
            prior + ((key, value),)
            for prior in keyword_combinations
            for value in choices
        }
    expanded_mappings: tuple[dict[str, str], ...] = ({},)
    for keyword in node.keywords:
        if keyword.arg is None:
            extensions = _static_mappings(keyword.value, constants, aliases, mappings)
            merged: list[dict[str, str]] = []
            for prior in expanded_mappings:
                for extension in extensions:
                    if set(prior).isdisjoint(extension):
                        merged.append({**prior, **extension})
            expanded_mappings = tuple(merged)
    for template in templates:
        for arguments in combinations:
            for keyword_pairs in keyword_combinations:
                for expanded in expanded_mappings:
                    try:
                        rendered.add(template.format(*arguments, **dict(keyword_pairs), **expanded))
                    except (IndexError, KeyError, TypeError, ValueError):
                        continue
    return frozenset(rendered)


def _static_strings(
    node: ast.AST,
    constants: dict[str, frozenset[str]],
    aliases: dict[str, str],
    mappings: dict[str, tuple[dict[str, str], ...]] | None = None,
) -> frozenset[str]:
    mappings = mappings or {}
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return frozenset({node.value})
    if isinstance(node, ast.Name):
        return constants.get(node.id, frozenset())
    if isinstance(node, ast.Subscript):
        keys = _static_strings(node.slice, constants, aliases, mappings)
        return frozenset(
            mapping[key]
            for mapping in _static_mappings(node.value, constants, aliases, mappings)
            for key in keys
            if key in mapping
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_strings(node.left, constants, aliases, mappings)
        right = _static_strings(node.right, constants, aliases, mappings)
        return frozenset(a + b for a in left for b in right)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _static_strings(node.left, constants, aliases, mappings)
        right = _static_strings(node.right, constants, aliases, mappings)
        if not left:
            return right
        if not right:
            return left
        return frozenset(a.rstrip("/") + "/" + b.lstrip("/") for a in left for b in right)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        formats = _static_strings(node.left, constants, aliases, mappings)
        if isinstance(node.right, ast.Tuple):
            combinations: set[tuple[str, ...]] = {()}
            for element in node.right.elts:
                choices = _static_strings(element, constants, aliases, mappings)
                combinations = {prefix + (choice,) for prefix in combinations for choice in choices}
            operands: set[object] = set(combinations)
        else:
            operands = set(_static_strings(node.right, constants, aliases, mappings))
        rendered: set[str] = set()
        for template in formats:
            for mapping in _static_mappings(node.right, constants, aliases, mappings):
                try:
                    rendered.add(template % mapping)
                except (KeyError, TypeError, ValueError):
                    continue
            for operand in operands:
                try:
                    rendered.add(template % operand)
                except (TypeError, ValueError):
                    continue
        return frozenset(rendered)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        element_values = [_static_strings(element, constants, aliases, mappings) for element in node.elts]
        values = {value for choices in element_values for value in choices}
        concatenations = {""}
        for choices in element_values:
            concatenations = {prefix + choice for prefix in concatenations for choice in choices}
        return frozenset(values | concatenations)
    if isinstance(node, ast.Dict):
        parts: set[str] = set()
        for item in [*node.keys, *node.values]:
            if item is not None:
                parts.update(_static_strings(item, constants, aliases, mappings))
        return frozenset(parts)
    if isinstance(node, ast.JoinedStr):
        pieces: list[frozenset[str]] = []
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                piece = _static_strings(value.value, constants, aliases, mappings)
            else:
                piece = _static_strings(value, constants, aliases, mappings)
            if not piece:
                return frozenset()
            pieces.append(piece)
        combined = {""}
        for piece in pieces:
            combined = {prefix + suffix for prefix in combined for suffix in piece}
        return frozenset(combined)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join" and len(node.args) == 1:
        separators = _static_strings(node.func.value, constants, aliases, mappings)
        if isinstance(node.args[0], (ast.List, ast.Tuple)):
            combinations: set[tuple[str, ...]] = {()}
            for element in node.args[0].elts:
                choices = _static_strings(element, constants, aliases, mappings)
                combinations = {prefix + (choice,) for prefix in combinations for choice in choices}
            return frozenset(separator.join(parts) for separator in separators for parts in combinations)
        bound_parts = _static_strings(node.args[0], constants, aliases, mappings)
        return frozenset(separator.join((parts,)) for separator in separators for parts in bound_parts)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
        keys = _static_strings(node.args[0], constants, aliases, mappings)
        values = {
            mapping[key]
            for mapping in _static_mappings(node.func.value, constants, aliases, mappings)
            for key in keys
            if key in mapping
        }
        if len(node.args) >= 2:
            values.update(_static_strings(node.args[1], constants, aliases, mappings))
        return frozenset(values)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        if _call_name(node.func, aliases, constants, mappings) == "str.format":
            if not node.args:
                return frozenset()
            templates = _static_strings(node.args[0], constants, aliases, mappings)
            format_call = ast.Call(func=node.func, args=node.args[1:], keywords=node.keywords)
        else:
            templates = _static_strings(node.func.value, constants, aliases, mappings)
            format_call = node
        return _render_static_format(format_call, templates, constants, aliases, mappings, mapping_only=False)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format_map" and len(node.args) == 1:
        if _call_name(node.func, aliases, constants, mappings) == "str.format_map":
            if len(node.args) != 2:
                return frozenset()
            templates = _static_strings(node.args[0], constants, aliases, mappings)
            format_call = ast.Call(func=node.func, args=node.args[1:], keywords=node.keywords)
        else:
            templates = _static_strings(node.func.value, constants, aliases, mappings)
            format_call = node
        return _render_static_format(format_call, templates, constants, aliases, mappings, mapping_only=True)
    if isinstance(node, ast.Call):
        callable_name = _call_name(node.func, aliases, constants, mappings)
        if callable_name is not None and callable_name.startswith(_STATIC_FORMAT_PREFIX):
            return _render_static_format(
                node,
                frozenset({callable_name.removeprefix(_STATIC_FORMAT_PREFIX)}),
                constants,
                aliases,
                mappings,
                mapping_only=False,
            )
        if callable_name is not None and callable_name.startswith(_STATIC_FORMAT_MAP_PREFIX):
            return _render_static_format(
                node,
                frozenset({callable_name.removeprefix(_STATIC_FORMAT_MAP_PREFIX)}),
                constants,
                aliases,
                mappings,
                mapping_only=True,
            )
        if callable_name in ("str.format", "str.format_map") and node.args:
            templates = _static_strings(node.args[0], constants, aliases, mappings)
            format_call = ast.Call(func=node.func, args=node.args[1:], keywords=node.keywords)
            return _render_static_format(
                format_call,
                templates,
                constants,
                aliases,
                mappings,
                mapping_only=callable_name == "str.format_map",
            )
    if isinstance(node, ast.Call) and _call_name(node.func, aliases, constants, mappings) in {"os.path.join", "posixpath.join"}:
        combinations: set[tuple[str, ...]] = {()}
        for argument in node.args:
            choices = _static_strings(argument, constants, aliases, mappings)
            combinations = {prefix + (choice,) for prefix in combinations for choice in choices}
        return frozenset("/".join(part.strip("/") for part in parts) for parts in combinations)
    if isinstance(node, ast.Call) and _call_name(node.func, aliases, constants, mappings) in PATH_CONSTRUCTION_CALLS and node.args:
        return _static_strings(node.args[0], constants, aliases, mappings)
    return frozenset()


def _constant_bindings(
    tree: ast.AST,
    aliases: dict[str, str],
    mappings: dict[str, tuple[dict[str, str], ...]] | None = None,
) -> dict[str, frozenset[str]]:
    constants: dict[str, frozenset[str]] = {}
    mappings = mappings or {}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            name: str | None = None
            value: ast.AST | None = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                value = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                name = node.target.id
                value = node.value
            if name is None or value is None:
                continue
            resolved = _static_strings(value, constants, aliases, mappings)
            combined = constants.get(name, frozenset()) | resolved
            if combined != constants.get(name, frozenset()):
                constants[name] = combined
                changed = True
    return constants


def _mapping_bindings(
    tree: ast.AST,
    aliases: dict[str, str],
    constants: dict[str, frozenset[str]],
    existing: dict[str, tuple[dict[str, str], ...]] | None = None,
) -> dict[str, tuple[dict[str, str], ...]]:
    mappings = dict(existing or {})

    def merge_variants(name: str, updates: tuple[dict[str, str], ...]) -> bool:
        if not updates:
            return False
        combined = [*mappings.get(name, ()), *updates]
        unique = {tuple(sorted(mapping.items())): mapping for mapping in combined}
        normalized = tuple(unique[key] for key in sorted(unique))
        if normalized == mappings.get(name, ()):
            return False
        mappings[name] = normalized
        return True

    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and isinstance(node.value.func.value, ast.Name)
                and node.value.func.attr == "update"
            ):
                name = node.value.func.value.id
                updated: tuple[dict[str, str], ...] = mappings.get(name, ({},))
                for argument in node.value.args:
                    extensions = _static_mappings(argument, constants, aliases, mappings)
                    updated = tuple({**prior, **extension} for prior in updated for extension in extensions)
                for keyword in node.value.keywords:
                    if keyword.arg is None:
                        extensions = _static_mappings(keyword.value, constants, aliases, mappings)
                        updated = tuple({**prior, **extension} for prior in updated for extension in extensions)
                    else:
                        values = _static_strings(keyword.value, constants, aliases, mappings)
                        updated = tuple({**prior, keyword.arg: value} for prior in updated for value in values)
                if merge_variants(name, updated):
                    changed = True
                continue
            if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and isinstance(node.op, ast.BitOr):
                name = node.target.id
                extensions = _static_mappings(node.value, constants, aliases, mappings)
                updated = tuple(
                    {**prior, **extension}
                    for prior in mappings.get(name, ({},))
                    for extension in extensions
                )
                if merge_variants(name, updated):
                    changed = True
                continue
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Subscript)
                and isinstance(node.targets[0].value, ast.Name)
            ):
                name = node.targets[0].value.id
                keys = _static_strings(node.targets[0].slice, constants, aliases, mappings)
                values = _static_strings(node.value, constants, aliases, mappings)
                updated = tuple(
                    {**prior, key: value}
                    for prior in mappings.get(name, ({},))
                    for key in keys
                    for value in values
                )
                if merge_variants(name, updated):
                    changed = True
                continue
            name: str | None = None
            value: ast.AST | None = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                value = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                name = node.target.id
                value = node.value
            if name is None or value is None:
                continue
            resolved = _static_mappings(value, constants, aliases, mappings)
            if merge_variants(name, resolved):
                changed = True
    return mappings


def _callable_bindings(
    tree: ast.AST,
    aliases: dict[str, str],
    constants: dict[str, frozenset[str]],
    mappings: dict[str, tuple[dict[str, str], ...]] | None = None,
) -> dict[str, str]:
    resolved_aliases = dict(aliases)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            name: str | None = None
            value: ast.AST | None = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                value = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                name = node.target.id
                value = node.value
            if name is None or value is None or name in resolved_aliases:
                continue
            resolved: str | None = None
            if isinstance(value, ast.Attribute) and value.attr in ("format", "format_map"):
                templates = _static_strings(value.value, constants, resolved_aliases, mappings)
                if len(templates) == 1:
                    prefix = _STATIC_FORMAT_PREFIX if value.attr == "format" else _STATIC_FORMAT_MAP_PREFIX
                    resolved = prefix + next(iter(templates))
            elif isinstance(value, ast.Call):
                getter = _call_name(value.func, resolved_aliases, constants, mappings)
                if getter in ("getattr", "builtins.getattr") and len(value.args) >= 2:
                    attributes = _static_strings(value.args[1], constants, resolved_aliases, mappings)
                    templates = _static_strings(value.args[0], constants, resolved_aliases, mappings)
                    if len(attributes) == 1 and len(templates) == 1:
                        attribute = next(iter(attributes))
                        if attribute in ("format", "format_map"):
                            prefix = _STATIC_FORMAT_PREFIX if attribute == "format" else _STATIC_FORMAT_MAP_PREFIX
                            resolved = prefix + next(iter(templates))
            if resolved is None:
                resolved = _call_name(value, resolved_aliases, constants, mappings)
            if resolved is not None and resolved != name:
                resolved_aliases[name] = resolved
                changed = True
    return resolved_aliases


def _analysis_context(
    tree: ast.AST,
) -> tuple[dict[str, str], dict[str, frozenset[str]], dict[str, tuple[dict[str, str], ...]]]:
    aliases = _import_aliases(tree)
    mappings: dict[str, tuple[dict[str, str], ...]] = {}
    constants: dict[str, frozenset[str]] = {}
    for _ in range(3):
        constants = _constant_bindings(tree, aliases, mappings)
        mappings = _mapping_bindings(tree, aliases, constants, mappings)
        aliases = _callable_bindings(tree, aliases, constants, mappings)
    constants = _constant_bindings(tree, aliases, mappings)
    mappings = _mapping_bindings(tree, aliases, constants, mappings)
    return aliases, constants, mappings


def _imports(node: ast.AST) -> frozenset[str]:
    if isinstance(node, ast.Import):
        return frozenset(alias.name for alias in node.names)
    if isinstance(node, ast.ImportFrom) and node.module is not None:
        return frozenset({node.module})
    return frozenset()


def _names_sealed(values: frozenset[str]) -> bool:
    return any(sealed in value for value in values for sealed in SEALED_NAMES)


def _names_contain(values: frozenset[str], names: frozenset[str] | tuple[str, ...]) -> bool:
    return any(name in value for value in values for name in names)


def _operation_references(
    tree: ast.AST,
    constants: dict[str, frozenset[str]],
    aliases: dict[str, str],
    names: frozenset[str] | tuple[str, ...],
    mappings: dict[str, tuple[dict[str, str], ...]] | None = None,
) -> list[str]:
    references: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            values = _static_strings(node, constants, aliases, mappings)
            if _names_contain(values, names):
                references.append("path-division")
            continue
        if not isinstance(node, ast.Call):
            continue
        call_name = _call_name(node.func, aliases, constants, mappings)
        path_method = isinstance(node.func, ast.Attribute) and node.func.attr in PATH_ACCESS_METHODS
        if call_name not in DYNAMIC_LOAD_CALLS | SUBPROCESS_CALLS | PATH_CONSTRUCTION_CALLS and not path_method:
            continue
        arguments: list[ast.AST] = [*node.args, *(keyword.value for keyword in node.keywords)]
        if path_method and isinstance(node.func, ast.Attribute):
            arguments.append(node.func.value)
        values = frozenset(
            value
            for argument in arguments
            for value in _static_strings(argument, constants, aliases, mappings)
        )
        if _names_contain(values, names):
            references.append(call_name or "<unknown>")
    return references


def _computed_references(
    tree: ast.AST,
    constants: dict[str, frozenset[str]],
    aliases: dict[str, str],
    names: frozenset[str] | tuple[str, ...],
    mappings: dict[str, tuple[dict[str, str], ...]] | None = None,
) -> list[str]:
    references: list[str] = []
    for node in ast.walk(tree):
        values = _static_strings(node, constants, aliases, mappings)
        if _names_contain(values, names):
            references.extend(sorted(value for value in values if _names_contain(frozenset({value}), names)))
    return references


def _violations(filename: str, source: str) -> list[str]:
    violations: list[str] = []
    tree = ast.parse(source, filename=filename)
    aliases, constants, mappings = _analysis_context(tree)
    allowed_imports = DIRECT_IMPORT_ALLOWLIST.get(filename, frozenset())

    if filename not in REFERENCE_EXEMPT_FILES:
        for sealed in SEALED_NAMES:
            if sealed in source:
                violations.append(f"forbidden sealed pathname/module reference: {sealed}")
        if _computed_references(tree, constants, aliases, SEALED_NAMES, mappings):
            violations.append("forbidden computed sealed pathname/module reference")

    for node in ast.walk(tree):
        imported = _imports(node)
        for imported_name in imported:
            for sealed in SEALED_NAMES:
                if (imported_name == sealed or imported_name.startswith(sealed + ".")) and sealed not in allowed_imports:
                    violations.append(f"forbidden direct import: {imported_name}")

    if filename not in SEALED_OPERATION_EXEMPT_FILES:
        for call_name in _operation_references(tree, constants, aliases, SEALED_NAMES, mappings):
            violations.append(f"forbidden sealed dynamic/path/subprocess operation: {call_name}")

    if filename in DORMANT_POLICY_FILES:
        for node in ast.walk(tree):
            for imported_name in _imports(node):
                if imported_name.split(".", 1)[0] in PROHIBITED_RUNTIME_IMPORT_ROOTS:
                    violations.append(f"forbidden dormant-policy runtime import: {imported_name}")
            if isinstance(node, ast.Call):
                call_name = _call_name(node.func, aliases, constants, mappings)
                if call_name in PROHIBITED_RUNTIME_CALLS:
                    violations.append(f"forbidden dormant-policy runtime call: {call_name}")
    return violations


class ProvenanceIndependenceTests(unittest.TestCase):
    def test_repository_obeys_exact_sealed_operation_allowlist(self) -> None:
        for path in _candidate_files():
            relative_path = path.relative_to(ROOT)
            self.assertEqual(
                _violations(relative_path.as_posix(), path.read_text()),
                [],
                f"{relative_path} violates the sealed provenance operation allowlist",
            )

    def test_scanner_rejects_direct_dynamic_and_subprocess_bypasses(self) -> None:
        hostile_sources = (
            "import conf_proc_inspect_provenance\n",
            "import importlib\nimportlib.import_module('conf_proc_inspect_' + 'provenance')\n",
            "import importlib\ntarget = 'conf_proc_inspect_' + 'provenance'\nimportlib.import_module(target)\n",
            "import subprocess\nsubprocess.run(['python3', 'conf_proc_inspect_' + 'provenance_cli.py'])\n",
            "import importlib as il\nil.import_module('conf_proc_inspect_' + 'provenance')\n",
            "from importlib import import_module as load\nload('conf_proc_inspect_' + 'provenance')\n",
            "import subprocess as sp\nsp.run(['python3', 'conf_proc_inspect_' + 'provenance_cli.py'])\n",
            "def hostile():\n    target = 'conf_proc_inspect_' + 'provenance'\n    return __import__(target)\n",
            "import pathlib as pl\npl.Path('conf_proc_inspect_' + 'provenance.py').read_bytes()\n",
            "import importlib\nload = importlib.import_module\ntarget = 'conf_proc_inspect_' + 'provenance'\nload(target)\n",
            "import subprocess\nrun = subprocess.run\nrun(['python3', 'conf_proc_inspect_' + 'provenance_cli.py'])\n",
            "import builtins\nload = builtins.__import__\nload('conf_proc_inspect_' + 'provenance')\n",
            "import importlib\ngetattr(importlib, 'import_' + 'module')('conf_proc_inspect_' + 'provenance')\n",
            "import pathlib\nmake_path = getattr(pathlib, 'Path')\nmake_path('conf_proc_inspect_' + 'provenance.py').read_bytes()\n",
            "import importlib\ntarget = ''.join(('conf_proc_inspect_', 'provenance'))\nimportlib.import_module(target)\n",
            "import subprocess\ntarget = '%s%s' % ('conf_proc_inspect_', 'provenance_cli.py')\nsubprocess.run(['python3', target])\n",
            "from pathlib import Path\ntarget = Path('.') / ('conf_proc_inspect_' + 'provenance.py')\ntarget.read_bytes()\n",
            "import importlib\ngetattr(importlib, ''.join(('import_', 'module')))('conf_proc_inspect_' + 'provenance')\n",
            "import importlib\nparts = ('conf_proc_inspect_', 'provenance')\ntarget = ''.join(parts)\nimportlib.import_module(target)\n",
            "import subprocess\nparts = {'a': 'conf_proc_inspect_', 'b': 'provenance_cli.py'}\ntarget = '%(a)s%(b)s' % parts\nsubprocess.run(['python3', target])\n",
            "import importlib\na = 'conf_proc_inspect_'\nb = 'provenance'\ntarget = '{a}{b}'.format(a=a, b=b)\nimportlib.import_module(target)\n",
            "from pathlib import Path\nparts = ('conf_proc_inspect_', 'provenance.py')\ntarget = Path('.') / ''.join(parts)\ntarget.read_bytes()\n",
            "import importlib\nparts = ('import_', 'module')\nload = getattr(importlib, ''.join(parts))\ntarget = ''.join(('conf_proc_inspect_', 'provenance'))\nload(target)\n",
            "import importlib\ntarget = '%(a)s%(b)s' % {'a': 'conf_proc_inspect_', 'b': 'provenance'}\nimportlib.import_module(target)\n",
            "import importlib\nparts = {'a': 'conf_proc_inspect_', 'b': 'provenance'}\ntarget = '{a}{b}'.format(**parts)\nimportlib.import_module(target)\n",
            "import importlib\nparts = {'a': 'conf_proc_inspect_', 'b': 'provenance'}\ntarget = '{a}{b}'.format_map(parts)\nimportlib.import_module(target)\n",
            "import subprocess\nparts = {'a': 'conf_proc_inspect_', 'b': 'provenance_cli.py'}\ntarget = f\"{parts['a']}{parts['b']}\"\nsubprocess.run(['python3', target])\n",
            "import importlib\nrender = '{}{}'.format\ntarget = render('conf_proc_inspect_', 'provenance')\nimportlib.import_module(target)\n",
            "import importlib\nrender = '{a}{b}'.format_map\nparts = {'a': 'conf_proc_inspect_', 'b': 'provenance'}\ntarget = render(parts)\nimportlib.import_module(target)\n",
            "import importlib\nrender = getattr('{}{}', 'format')\ntarget = render('conf_proc_inspect_', 'provenance')\nimportlib.import_module(target)\n",
            "import importlib\nleft = {'a': 'conf_proc_inspect_'}\nright = {'b': 'provenance'}\ntarget = '{a}{b}'.format(**left, **right)\nimportlib.import_module(target)\n",
            "import importlib\nleft = {'a': 'conf_proc_inspect_'}\nright = {'b': 'provenance'}\nparts = {**left, **right}\ntarget = '{a}{b}'.format(**parts)\nimportlib.import_module(target)\n",
            "import importlib\nleft = {'a': 'conf_proc_inspect_'}\nright = {'b': 'provenance'}\nparts = {**left, **right}\ntarget = '{a}{b}'.format_map(parts)\nimportlib.import_module(target)\n",
            "import importlib\nleft = {'a': 'conf_proc_inspect_'}\nright = {'b': 'provenance'}\nparts = left | right\ntarget = '{a}{b}'.format_map(parts)\nimportlib.import_module(target)\n",
            "import importlib\nparts = {'a': 'conf_proc_inspect_'}\nparts.update({'b': 'provenance'})\ntarget = '{a}{b}'.format_map(parts)\nimportlib.import_module(target)\n",
            "import importlib\nparts = {'a': 'conf_proc_inspect_'}\nparts.update(b='provenance')\ntarget = '{a}{b}'.format_map(parts)\nimportlib.import_module(target)\n",
            "import importlib\nparts = {'a': 'conf_proc_inspect_'}\nright = {'b': 'provenance'}\nparts |= right\ntarget = '{a}{b}'.format_map(parts)\nimportlib.import_module(target)\n",
            "import importlib\nparts = {'a': 'conf_proc_inspect_'}\nparts['b'] = 'provenance'\ntarget = '{a}{b}'.format_map(parts)\nimportlib.import_module(target)\n",
            "import subprocess\nleft = {'a': 'conf_proc_inspect_'}\nright = {'b': 'provenance_cli.py'}\nparts = {**left, **right}\ntarget = '%(a)s%(b)s' % parts\nsubprocess.run(['python3', target])\n",
            "import importlib\nleft = {'a': 'conf_proc_inspect_'}\nright = {'b': 'provenance'}\nparts = {**left, **right}\ntarget = f\"{parts['a']}{parts.get('b')}\"\nimportlib.import_module(target)\n",
            "import importlib\nleft = {'a': 'conf_proc_inspect_'}\nright = {'b': 'provenance'}\ntarget = '{a}{b}'.format(**{**left, **right})\nimportlib.import_module(target)\n",
            "import importlib\ntarget = str.format('{}{}', 'conf_proc_inspect_', 'provenance')\nimportlib.import_module(target)\n",
            "import importlib\nrender = str.format\ntarget = render('{}{}', 'conf_proc_inspect_', 'provenance')\nimportlib.import_module(target)\n",
        )
        for source in hostile_sources:
            self.assertTrue(_violations("synthetic-policy-test.py", source), source)

        self.assertTrue(
            _violations(THIS_FILE_ID, "import conf_proc_inspect_provenance\n"),
            "the scanner's string-needle exemption must not exempt its AST operations",
        )
        for exempt_bypass in (
            "import importlib\nparts = ('import_', 'module')\nload = getattr(importlib, ''.join(parts))\ntarget = ''.join(('conf_proc_inspect_', 'provenance'))\nload(target)\n",
            "from pathlib import Path\nparts = ('conf_proc_inspect_', 'provenance.py')\ntarget = Path('.') / ''.join(parts)\ntarget.read_bytes()\n",
            "from pathlib import Path\nROOT = Path(__file__).resolve().parents[1]\ntarget = ''.join(('conf_proc_inspect_', 'provenance.py'))\n(ROOT / target).read_bytes()\n",
            "from pathlib import Path\nROOT = Path(__file__).resolve().parents[1]\ntarget = ''.join(('conf_proc_inspect_', 'provenance.py'))\nopen(ROOT / target, 'rb')\n",
            "from pathlib import Path\nROOT = Path(__file__).resolve().parents[1]\ntarget = ''.join(('conf_proc_inspect_', 'provenance.py'))\nROOT.joinpath(target).read_bytes()\n",
        ):
            self.assertTrue(
                _violations(THIS_FILE_ID, exempt_bypass),
                "the policy-test exemption applies only to literal needles, never executable operations",
            )
        self.assertEqual(
            _violations("ordinary.py", "import importlib\nimportlib.import_module('verifier.cc_admin')\n"),
            [],
        )

    def test_dormant_policy_files_reject_all_dynamic_loading_and_subprocesses(self) -> None:
        hostile_sources = (
            "import importlib\nimportlib.import_module('ordinary_module')\n",
            "from importlib import import_module\nimport_module('ordinary_module')\n",
            "import subprocess\nsubprocess.run(['true'])\n",
            "import runpy\nrunpy.run_path('ordinary.py')\n",
            "import builtins\nload = builtins.__import__\nload('ordinary_module')\n",
            "code = 'pass'\nexec(code)\n",
            "import builtins\nbuiltins.exec('pass')\n",
            "from builtins import exec as run\nrun('pass')\n",
            "import builtins\ngetattr(builtins, 'compile')('pass', '<x>', 'exec')\n",
            "import builtins\nbuiltins.eval('1')\n",
        )
        for source in hostile_sources:
            self.assertTrue(_violations("conf_proc_provenance_v2.py", source), source)

    def test_exemption_allowlists_are_exact_and_present(self) -> None:
        self.assertEqual(
            REFERENCE_EXEMPT_FILES,
            {
                THIS_FILE_ID,
                "conf_proc_inspect_provenance_cli.py",
                "test/conf-proc-provenance-oracle-selftest.py",
            },
        )
        self.assertEqual(
            DIRECT_IMPORT_ALLOWLIST,
            {"test/conf-proc-provenance-oracle-selftest.py": frozenset({"conf_proc_inspect_provenance"})},
        )
        self.assertEqual(
            SEALED_OPERATION_EXEMPT_FILES,
            {"conf_proc_inspect_provenance_cli.py", "test/conf-proc-provenance-oracle-selftest.py"},
        )
        for filename in REFERENCE_EXEMPT_FILES:
            path = ROOT / filename
            self.assertTrue(path.is_file(), filename)
        self.assertTrue(
            _violations(
                "test/conf_proc_inspect_provenance_cli.py",
                "import importlib\ntarget = ''.join(('conf_proc_inspect_', 'provenance'))\nimportlib.import_module(target)\n",
            ),
            "an exempt basename at another repository-relative path must not inherit the exemption",
        )

    def test_dormant_modules_have_no_release_path_importer_or_reference(self) -> None:
        for path in sorted(ROOT.glob("*.py")):
            if path.stem in DORMANT_MODULES:
                continue
            source = path.read_text()
            tree = ast.parse(source, filename=str(path))
            aliases, constants, mappings = _analysis_context(tree)
            for module_name in DORMANT_MODULES:
                self.assertNotIn(
                    module_name,
                    source,
                    f"{path.name} wires dormant provenance-v2 code into a production path",
                )
            for node in ast.walk(tree):
                for imported_name in _imports(node):
                    self.assertFalse(
                        any(
                            imported_name == module_name or imported_name.startswith(module_name + ".")
                            for module_name in DORMANT_MODULES
                        ),
                        f"{path.name} imports dormant provenance-v2 code",
                    )
            self.assertEqual(
                _operation_references(tree, constants, aliases, DORMANT_MODULES, mappings),
                [],
                f"{path.name} dynamically loads or executes dormant provenance-v2 code",
            )
            self.assertEqual(
                _computed_references(tree, constants, aliases, DORMANT_MODULES, mappings),
                [],
                f"{path.name} computes a dormant provenance-v2 module or pathname reference",
            )

        renderer_source = (ROOT / "conf_proc_provenance_render.py").read_text()
        self.assertIn("import conf_proc_provenance_v2", renderer_source)

        split_dynamic = (
            "import importlib as il\n"
            "target = 'conf_proc_' + 'provenance_v2'\n"
            "il.import_module(target)\n"
        )
        split_tree = ast.parse(split_dynamic)
        split_aliases, split_constants, split_mappings = _analysis_context(split_tree)
        self.assertTrue(_operation_references(split_tree, split_constants, split_aliases, DORMANT_MODULES, split_mappings))
        joined_dynamic = (
            "import importlib\n"
            "target = ''.join(('conf_proc_', 'provenance_v2'))\n"
            "importlib.import_module(target)\n"
        )
        joined_tree = ast.parse(joined_dynamic)
        joined_aliases, joined_constants, joined_mappings = _analysis_context(joined_tree)
        self.assertTrue(_computed_references(joined_tree, joined_constants, joined_aliases, DORMANT_MODULES, joined_mappings))
        bound_dynamic = (
            "from pathlib import Path\n"
            "parts = ('conf_proc_', 'provenance_v2.py')\n"
            "target = Path('.') / ''.join(parts)\n"
            "target.read_bytes()\n"
        )
        bound_tree = ast.parse(bound_dynamic)
        bound_aliases, bound_constants, bound_mappings = _analysis_context(bound_tree)
        self.assertTrue(_computed_references(bound_tree, bound_constants, bound_aliases, DORMANT_MODULES, bound_mappings))

        for mutated_mapping in (
            "parts = {'a': 'conf_proc_'}\nparts.update(b='provenance_v2')\ntarget = '{a}{b}'.format_map(parts)\n",
            "parts = {'a': 'conf_proc_'}\nright = {'b': 'provenance_v2'}\nparts |= right\ntarget = '{a}{b}'.format_map(parts)\n",
            "parts = {'a': 'conf_proc_'}\nparts['b'] = 'provenance_v2'\ntarget = '{a}{b}'.format_map(parts)\n",
        ):
            mutation_tree = ast.parse(mutated_mapping)
            mutation_aliases, mutation_constants, mutation_mappings = _analysis_context(mutation_tree)
            self.assertTrue(
                _computed_references(
                    mutation_tree,
                    mutation_constants,
                    mutation_aliases,
                    DORMANT_MODULES,
                    mutation_mappings,
                ),
                mutated_mapping,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
