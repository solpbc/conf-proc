#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent inspector-side static process/activation graph extraction.

Deliberately does NOT import conf_proc_build_graph.py and deliberately
uses a different traversal shape (one unified tree walk with per-path
pattern dispatch, versus the builder's category-by-category directory
iteration) so the two implementations are not a copy of each other, per
AC7. Both call the same shared, pure conf_proc_unit_parser.py format
parsers -- parsing systemd/udev/cron syntax is a byte-format operation,
not appliance inventory logic.
"""

from __future__ import annotations

import hashlib
import os
import posixpath

from conf_proc_elf import is_elf, parse_elf
from conf_proc_prohibited import check_prohibited_unit
from conf_proc_reasons import CP_POLICY_UNSUPPORTED_ACTIVATION, ApplianceError
from conf_proc_unit_parser import (
    parse_crontab_lines,
    parse_exec_line,
    parse_narrow_shell_script,
    parse_no_output_generator,
    parse_shebang,
    parse_systemd_unit,
    parse_udev_actions,
)


class _GraphAccumulator:
    def __init__(self, tree_root: str, *, strict: bool = False) -> None:
        self.tree_root = tree_root
        self.strict = strict
        self.nodes: dict[str, dict] = {}
        self.edge_keys: set[tuple] = set()
        self.edges: list[dict] = []
        self._seen_unit_basenames: set[str] = set()

    def digest(self, relative_path: str) -> str:
        with open(self.resolve(relative_path), "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()

    def exists(self, relative_path: str) -> bool:
        return os.path.isfile(self.resolve(relative_path))

    def resolve(self, image_path: str) -> str:
        if not self.strict:
            return os.path.join(self.tree_root, image_path.lstrip("/"))
        if (
            not image_path.startswith("/")
            or image_path.startswith("//")
            or "\\" in image_path
            or posixpath.normpath(image_path) != image_path
        ):
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "activation path is not canonical")
        root = os.path.realpath(self.tree_root)
        candidate = os.path.realpath(os.path.join(root, image_path.lstrip("/")))
        try:
            contained = os.path.commonpath((root, candidate)) == root
        except ValueError:
            contained = False
        if not contained:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "activation path escapes the extracted image")
        return candidate

    def add_node(self, node_id: str, *, kind: str, path: str, sha256=None, argv=(), network_scope="none", capabilities=(), source_input_id=None) -> None:
        value = {
            "id": node_id, "kind": kind, "path": path, "sha256": sha256, "argv": tuple(argv),
            "network_scope": network_scope, "capabilities": tuple(capabilities), "source_input_id": source_input_id,
        }
        if self.strict and node_id in self.nodes and self.nodes[node_id] != value:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "graph node has conflicting raw contributions")
        self.nodes[node_id] = value

    def add_edge(self, from_id: str, to_id: str, kind: str, origin_path: str, origin_key: str) -> None:
        key = (from_id, to_id, kind, origin_path, origin_key)
        if key in self.edge_keys:
            if self.strict:
                raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "graph edge has duplicate raw contributions")
            return
        self.edge_keys.add(key)
        self.edges.append({"from_id": from_id, "to_id": to_id, "kind": kind, "origin_path": origin_path, "origin_key": origin_key})

    def add_exec_child(self, command: str) -> str:
        exec_id = f"exec:{command}"
        if not self.exists(command):
            if self.strict:
                raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "activation executable is missing")
            return exec_id
        self.add_node(exec_id, kind="exec", path=command, sha256=self.digest(command), argv=(command,))
        return exec_id


_UNIT_LOCATIONS = ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system")
_STRICT_LIBRARY_DIRS = (
    "/lib", "/lib64", "/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu",
    "/usr/lib", "/usr/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
)


def extract_graph(tree_root: str, *, strict: bool = False) -> tuple[list[dict], list[dict]]:
    """Statically extract (nodes, edges) from an independently-extracted image tree."""

    acc = _GraphAccumulator(tree_root, strict=strict)

    for relative_dir, basename, absolute_path in _walk_relative(tree_root):
        if relative_dir in _UNIT_LOCATIONS and (basename.endswith(".service") or basename.endswith(".socket") or basename.endswith(".timer")):
            if basename in acc._seen_unit_basenames:
                raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, f"duplicate unit basename across precedence directories: {basename!r}")
            acc._seen_unit_basenames.add(basename)
            _process_unit(acc, basename, absolute_path)
        elif relative_dir in ("etc/dbus-1/system-services", "usr/share/dbus-1/system-services"):
            _process_dbus_service(acc, basename, absolute_path)
        elif relative_dir in ("etc/udev/rules.d", "usr/lib/udev/rules.d"):
            _process_udev_rule(acc, basename, absolute_path)
        elif relative_dir == "etc/cron.d":
            _process_crontab_file(acc, relative_dir, basename, absolute_path)
        elif relative_dir in ("etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly"):
            _process_period_cron(acc, relative_dir, basename)
        elif relative_dir in ("usr/lib/systemd/system-generators", "etc/systemd/system-generators"):
            _process_generator(acc, relative_dir, basename, absolute_path)

    if strict:
        _expand_executable_closure(acc)
    return list(acc.nodes.values()), acc.edges


def _walk_relative(tree_root: str):
    for root, _dirs, files in os.walk(tree_root):
        relative_dir = os.path.relpath(root, tree_root)
        relative_dir = "" if relative_dir == "." else relative_dir
        for name in sorted(files):
            yield relative_dir, name, os.path.join(root, name)


def _process_unit(acc: _GraphAccumulator, basename: str, absolute_path: str) -> None:
    check_prohibited_unit(basename)
    with open(absolute_path, "r", encoding="utf-8") as handle:
        sections = parse_systemd_unit(handle.read())
    unit_id = f"unit:{basename}"
    service = sections.get("Service", {})
    network_scope = _derive_network_scope(service)
    capabilities = tuple(sorted(service["CapabilityBoundingSet"][0].split())) if "CapabilityBoundingSet" in service else ()
    kind = "socket" if basename.endswith(".socket") else "timer" if basename.endswith(".timer") else "unit"
    acc.add_node(unit_id, kind=kind, path=basename, network_scope=network_scope, capabilities=capabilities)

    for key in ("After", "Requires", "Wants", "BindsTo"):
        for value in sections.get("Unit", {}).get(key, []):
            for target in value.split():
                acc.add_edge(unit_id, f"unit:{target}", "unit_dependency", basename, key)
    for value in sections.get("Install", {}).get("WantedBy", []):
        for target in value.split():
            acc.add_edge(unit_id, f"unit:{target}", "install_enablement", basename, "WantedBy")

    if basename.endswith(".service"):
        for exec_value in service.get("ExecStart", []):
            argv = parse_exec_line(exec_value)
            exec_path = argv[0]
            exec_id = f"exec:{exec_path}"
            if acc.strict and not acc.exists(exec_path):
                raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "service executable is missing")
            acc.add_node(exec_id, kind="exec", path=exec_path, sha256=acc.digest(exec_path), argv=argv, network_scope=network_scope)
            acc.add_edge(unit_id, exec_id, "unit_exec", basename, "ExecStart")
            if not acc.strict:
                _process_executable(acc, exec_path, exec_id)
    elif basename.endswith(".socket"):
        acc.add_edge(unit_id, f"unit:{basename[:-len('.socket')]}.service", "socket_activation", basename, "implicit")
    elif basename.endswith(".timer"):
        acc.add_edge(unit_id, f"unit:{basename[:-len('.timer')]}.service", "timer_activation", basename, "implicit")


def _derive_network_scope(service: dict) -> str:
    deny = service.get("IPAddressDeny", [])
    allow = service.get("IPAddressAllow", [])
    if deny == ["any"] and not allow:
        return "none"
    if deny == ["any"] and allow in (["127.0.0.0/8"], ["localhost"]):
        return "loopback"
    raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "unit must explicitly declare IPAddressDeny=any plus an allowlist for network_scope to be statically derivable")


def _process_executable(acc: _GraphAccumulator, exec_path: str, exec_id: str) -> None:
    if not acc.exists(exec_path):
        if acc.strict:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "executable closure target is missing")
        return
    with open(acc.resolve(exec_path), "rb") as handle:
        data = handle.read()

    if is_elf(data):
        info = parse_elf(data)
        if acc.strict and (info.rpath or info.runpath):
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "ELF RPATH/RUNPATH resolution is not modeled")
        if info.interpreter:
            if not acc.exists(info.interpreter):
                if acc.strict:
                    raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "ELF interpreter is missing")
            else:
                interp_id = f"interpreter:{info.interpreter}"
                acc.add_node(interp_id, kind="interpreter", path=info.interpreter, sha256=acc.digest(info.interpreter))
                acc.add_edge(exec_id, interp_id, "elf_interpreter", exec_path, "PT_INTERP")
        for soname in info.needed:
            resolved = _resolve_soname(acc, soname)
            if resolved is None:
                continue
            lib_id = f"dynamic_library:{resolved}"
            acc.add_node(lib_id, kind="dynamic_library", path=resolved, sha256=acc.digest(resolved))
            acc.add_edge(exec_id, lib_id, "dynamic_load", exec_path, "DT_NEEDED")
        return

    text = data.decode("utf-8", "replace")
    interpreter = parse_shebang(text)
    if interpreter:
        if not acc.exists(interpreter):
            if acc.strict:
                raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "script interpreter is missing")
        else:
            interp_id = f"interpreter:{interpreter}"
            acc.add_node(interp_id, kind="interpreter", path=interpreter, sha256=acc.digest(interpreter))
            acc.add_edge(exec_id, interp_id, "script_interpreter", exec_path, "shebang")
    for command in parse_narrow_shell_script(text):
        child_id = acc.add_exec_child(command)
        if child_id in acc.nodes:
            acc.add_edge(exec_id, child_id, "shell_child", exec_path, "invocation")


def _expand_executable_closure(acc: _GraphAccumulator) -> None:
    expanded: set[str] = set()
    while True:
        pending = sorted(
            node_id
            for node_id, node in acc.nodes.items()
            if node.get("kind") in {"exec", "interpreter", "dynamic_library"} and node_id not in expanded
        )
        if not pending:
            return
        for node_id in pending:
            _process_executable(acc, acc.nodes[node_id]["path"], node_id)
            expanded.add(node_id)


def _resolve_soname(acc: _GraphAccumulator, soname: str) -> str | None:
    basename = os.path.basename(soname)
    if acc.strict:
        if not basename or basename != soname:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "ELF dependency name is not a supported soname")
        matches = [posixpath.join(directory, basename) for directory in _STRICT_LIBRARY_DIRS if acc.exists(posixpath.join(directory, basename))]
        if len(matches) != 1:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "ELF dependency is missing or ambiguous in fixed search paths")
        return matches[0]
    for root, _dirs, files in os.walk(acc.tree_root):
        if basename in files:
            return "/" + os.path.relpath(os.path.join(root, basename), acc.tree_root)
    return None


def _process_dbus_service(acc: _GraphAccumulator, basename: str, absolute_path: str) -> None:
    with open(absolute_path, "r", encoding="utf-8") as handle:
        sections = parse_systemd_unit(handle.read())
    exec_value = sections.get("D-BUS Service", {}).get("Exec", [None])[0]
    if not exec_value:
        return
    argv = parse_exec_line(exec_value)
    dbus_id = f"dbus_service:{basename}"
    acc.add_node(dbus_id, kind="dbus_service", path=basename)
    exec_id = acc.add_exec_child(argv[0])
    acc.add_edge(dbus_id, exec_id, "dbus_activation", basename, "Exec")


def _process_udev_rule(acc: _GraphAccumulator, basename: str, absolute_path: str) -> None:
    with open(absolute_path, "r", encoding="utf-8") as handle:
        text = handle.read()
    rule_id = f"udev_rule:{basename}"
    acc.add_node(rule_id, kind="udev_rule", path=basename)
    for command in parse_udev_actions(text):
        exec_id = acc.add_exec_child(command)
        acc.add_edge(rule_id, exec_id, "udev_activation", basename, "action")


def _process_crontab_file(acc: _GraphAccumulator, relative_dir: str, basename: str, absolute_path: str) -> None:
    with open(absolute_path, "r", encoding="utf-8") as handle:
        text = handle.read()
    job_id = f"cron_job:{relative_dir}/{basename}"
    acc.add_node(job_id, kind="cron_job", path=f"/{relative_dir}/{basename}")
    for command in parse_crontab_lines(text):
        exec_id = acc.add_exec_child(command)
        acc.add_edge(job_id, exec_id, "cron_activation", basename, "command")


def _process_period_cron(acc: _GraphAccumulator, relative_dir: str, basename: str) -> None:
    path = f"/{relative_dir}/{basename}"
    job_id = f"cron_job:{relative_dir}/{basename}"
    acc.add_node(job_id, kind="cron_job", path=path)
    exec_id = f"exec:{path}"
    if acc.exists(path):
        acc.add_node(exec_id, kind="exec", path=path, sha256=acc.digest(path), argv=(path,))
    acc.add_edge(job_id, exec_id, "cron_activation", basename, "run-parts")


def _process_generator(acc: _GraphAccumulator, relative_dir: str, basename: str, absolute_path: str) -> None:
    with open(absolute_path, "r", encoding="utf-8") as handle:
        text = handle.read()
    parse_no_output_generator(text)
    generator_id = f"generator:{basename}"
    acc.add_node(generator_id, kind="generator", path=f"/{relative_dir}/{basename}")
    acc.add_edge(generator_id, generator_id, "generator_activation", basename, "boot")
