#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Builder-side static process/activation graph extraction.

Walks the STAGING tree (before packing) and statically derives the same
node/edge shapes as conf_proc_policy.ProcessNode/ProcessEdge, so the
builder can catch a policy/reality mismatch before promotion. The
inspector's extraction (conf_proc_inspect_graph.py) walks the extracted
image tree independently and must not import this module.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import stat

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


_UNIT_DIRS = ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system")
_DBUS_DIRS = ("etc/dbus-1/system-services", "usr/share/dbus-1/system-services")
_UDEV_DIRS = ("etc/udev/rules.d", "usr/lib/udev/rules.d")
_CRON_D_DIRS = ("etc/cron.d",)
_CRON_PERIOD_DIRS = ("etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly")
_GENERATOR_DIRS = ("usr/lib/systemd/system-generators", "etc/systemd/system-generators")
_STRICT_LIBRARY_DIRS = (
    "/lib",
    "/lib64",
    "/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
)


class _ObservedNodes(dict[str, dict]):
    """Preserve the legacy projection while optionally rejecting lost input."""

    def __init__(self, *, reject_raw_collisions: bool) -> None:
        super().__init__()
        self._reject_raw_collisions = reject_raw_collisions

    def __setitem__(self, key: str, value: dict) -> None:
        if self._reject_raw_collisions and key in self and self[key] != value:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "graph node has conflicting raw contributions")
        super().__setitem__(key, value)

    def setdefault(self, key: str, default: dict | None = None) -> dict:
        if default is None:
            default = {}
        if self._reject_raw_collisions and key in self and self[key] != default:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "graph node has conflicting raw contributions")
        return super().setdefault(key, default)


class _ObservedEdges(list[tuple]):
    """Retain legacy edge ordering while optionally rejecting raw duplicates."""

    def __init__(self, *, reject_raw_collisions: bool) -> None:
        super().__init__()
        self._reject_raw_collisions = reject_raw_collisions
        self._seen: set[tuple] = set()

    def append(self, value: tuple) -> None:
        if self._reject_raw_collisions and value in self._seen:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "graph edge has duplicate raw contributions")
        self._seen.add(value)
        super().append(value)


def extract_graph(tree_root: str, *, reject_raw_collisions: bool = False) -> tuple[list[dict], list[dict]]:
    """Statically extract (nodes, edges) from a staging tree."""

    nodes: dict[str, dict] = _ObservedNodes(reject_raw_collisions=reject_raw_collisions)
    edges: list[tuple] = _ObservedEdges(reject_raw_collisions=reject_raw_collisions)

    unit_sections = _read_all_units(tree_root)
    for unit_name, sections in unit_sections.items():
        _add_unit_node_and_edges(
            unit_name,
            sections,
            tree_root,
            nodes,
            edges,
            strict_paths=reject_raw_collisions,
        )

    _handle_dbus_services(tree_root, nodes, edges, strict_paths=reject_raw_collisions)
    _handle_udev_rules(tree_root, nodes, edges, strict_paths=reject_raw_collisions)
    _handle_cron(tree_root, nodes, edges, strict_paths=reject_raw_collisions)
    _handle_generators(tree_root, nodes, edges)
    if reject_raw_collisions:
        _expand_unique_executable_closure(tree_root, nodes, edges)

    return list(nodes.values()), _dedupe_edges(edges)


def _dedupe_edges(edges: list[tuple]) -> list[dict]:
    seen = set()
    out = []
    for from_id, to_id, kind, origin_path, origin_key in edges:
        key = (from_id, to_id, kind, origin_path, origin_key)
        if key in seen:
            continue
        seen.add(key)
        out.append({"from_id": from_id, "to_id": to_id, "kind": kind, "origin_path": origin_path, "origin_key": origin_key})
    return out


def _read_all_units(tree_root: str) -> dict[str, dict]:
    units: dict[str, dict] = {}
    for unit_dir in _UNIT_DIRS:
        directory = os.path.join(tree_root, unit_dir)
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            if not (name.endswith(".service") or name.endswith(".socket") or name.endswith(".timer")):
                continue
            if name in units:
                raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, f"duplicate unit basename across precedence directories: {name!r}")
            with open(os.path.join(directory, name), "r", encoding="utf-8") as handle:
                units[name] = parse_systemd_unit(handle.read())
    return units


def _add_unit_node_and_edges(
    unit_name: str,
    sections: dict,
    tree_root: str,
    nodes: dict,
    edges: list,
    *,
    strict_paths: bool = False,
) -> None:
    check_prohibited_unit(unit_name)
    unit_id = f"unit:{unit_name}"
    service = sections.get("Service", {})
    network_scope = _network_scope_from_service(service)
    capabilities = tuple(sorted(service.get("CapabilityBoundingSet", [""])[0].split())) if "CapabilityBoundingSet" in service else ()

    nodes[unit_id] = {
        "id": unit_id, "kind": "socket" if unit_name.endswith(".socket") else "timer" if unit_name.endswith(".timer") else "unit",
        "path": unit_name, "sha256": None, "argv": (), "network_scope": network_scope,
        "capabilities": capabilities, "source_input_id": None,
    }

    for key in ("After", "Requires", "Wants", "BindsTo"):
        for value in sections.get("Unit", {}).get(key, []):
            for target in value.split():
                target_id = f"unit:{target}"
                edges.append((unit_id, target_id, "unit_dependency", unit_name, key))

    for value in sections.get("Install", {}).get("WantedBy", []):
        for target in value.split():
            edges.append((unit_id, f"unit:{target}", "install_enablement", unit_name, "WantedBy"))

    if unit_name.endswith(".service"):
        for exec_value in service.get("ExecStart", []):
            argv = parse_exec_line(exec_value)
            exec_path = argv[0]
            exec_id = f"exec:{exec_path}"
            sha256 = _sha256_relative(tree_root, exec_path, strict_paths=strict_paths)
            nodes[exec_id] = {
                "id": exec_id, "kind": "exec", "path": exec_path, "sha256": sha256, "argv": tuple(argv),
                "network_scope": network_scope, "capabilities": (), "source_input_id": None,
            }
            edges.append((unit_id, exec_id, "unit_exec", unit_name, "ExecStart"))
            if not strict_paths:
                _add_interpreter_and_dynamic_edges(tree_root, exec_path, exec_id, nodes, edges)

    if unit_name.endswith(".socket"):
        service_name = unit_name[: -len(".socket")] + ".service"
        edges.append((unit_id, f"unit:{service_name}", "socket_activation", unit_name, "implicit"))
    if unit_name.endswith(".timer"):
        service_name = unit_name[: -len(".timer")] + ".service"
        edges.append((unit_id, f"unit:{service_name}", "timer_activation", unit_name, "implicit"))


def _network_scope_from_service(service: dict) -> str:
    deny = service.get("IPAddressDeny", [])
    allow = service.get("IPAddressAllow", [])
    if deny == ["any"] and not allow:
        return "none"
    if deny == ["any"] and allow in (["127.0.0.0/8"], ["localhost"]):
        return "loopback"
    raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "unit must explicitly declare IPAddressDeny=any plus an allowlist for network_scope to be statically derivable")


def _resolve_image_path(tree_root: str, image_path: str, *, strict_paths: bool) -> str:
    if not strict_paths:
        return os.path.join(tree_root, image_path.lstrip("/"))
    if (
        not image_path.startswith("/")
        or image_path == "/"
        or "\\" in image_path
        or "//" in image_path
        or posixpath.normpath(image_path) != image_path
    ):
        raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "activation path is not canonical in-image absolute")
    root = os.path.realpath(tree_root)
    candidate = os.path.realpath(os.path.join(root, image_path.lstrip("/")))
    try:
        contained = os.path.commonpath((root, candidate)) == root
    except ValueError:
        contained = False
    if not contained:
        raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "activation path escapes the frozen image")
    return candidate


def _sha256_relative(tree_root: str, relative_path: str, *, strict_paths: bool = False) -> str:
    absolute = _resolve_image_path(tree_root, relative_path, strict_paths=strict_paths)
    with open(absolute, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _add_interpreter_and_dynamic_edges(
    tree_root: str,
    exec_path: str,
    exec_id: str,
    nodes: dict,
    edges: list,
    *,
    strict_paths: bool = False,
) -> None:
    absolute = _resolve_image_path(tree_root, exec_path, strict_paths=strict_paths)
    if not os.path.isfile(absolute):
        if strict_paths:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "executable closure target is missing")
        return
    with open(absolute, "rb") as handle:
        data = handle.read()

    if is_elf(data):
        info = parse_elf(data)
        if strict_paths and (info.rpath or info.runpath):
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "ELF RPATH/RUNPATH resolution is not modeled")
        interpreter_path = (
            _resolve_image_path(tree_root, info.interpreter, strict_paths=strict_paths)
            if info.interpreter is not None
            else None
        )
        if info.interpreter is not None:
            if interpreter_path is None or not os.path.isfile(interpreter_path):
                if strict_paths:
                    raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "ELF interpreter is missing")
            else:
                interp_id = f"interpreter:{info.interpreter}"
                nodes[interp_id] = {
                    "id": interp_id, "kind": "interpreter", "path": info.interpreter,
                    "sha256": _sha256_relative(tree_root, info.interpreter, strict_paths=strict_paths), "argv": (), "network_scope": "none",
                    "capabilities": (), "source_input_id": None,
                }
                edges.append((exec_id, interp_id, "elf_interpreter", exec_path, "PT_INTERP"))
        for needed in info.needed:
            resolved = _resolve_library(tree_root, needed, strict_paths=strict_paths)
            if resolved is None:
                continue
            lib_id = f"dynamic_library:{resolved}"
            nodes[lib_id] = {
                "id": lib_id, "kind": "dynamic_library", "path": resolved,
                "sha256": _sha256_relative(tree_root, resolved, strict_paths=strict_paths),
                "argv": (), "network_scope": "none", "capabilities": (), "source_input_id": None,
            }
            edges.append((exec_id, lib_id, "dynamic_load", exec_path, "DT_NEEDED"))
    else:
        interpreter = parse_shebang(data.decode("utf-8", "replace"))
        interpreter_path = (
            _resolve_image_path(tree_root, interpreter, strict_paths=strict_paths)
            if interpreter is not None
            else None
        )
        if interpreter is not None:
            if interpreter_path is None or not os.path.isfile(interpreter_path):
                if strict_paths:
                    raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "script interpreter is missing")
            else:
                interp_id = f"interpreter:{interpreter}"
                nodes[interp_id] = {
                    "id": interp_id, "kind": "interpreter", "path": interpreter,
                    "sha256": _sha256_relative(tree_root, interpreter, strict_paths=strict_paths), "argv": (), "network_scope": "none",
                    "capabilities": (), "source_input_id": None,
                }
                edges.append((exec_id, interp_id, "script_interpreter", exec_path, "shebang"))
        for command in parse_narrow_shell_script(data.decode("utf-8", "replace")):
            command_path = _resolve_image_path(tree_root, command, strict_paths=strict_paths)
            if not os.path.isfile(command_path):
                if strict_paths:
                    raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "shell child executable is missing")
                continue
            child_id = f"exec:{command}"
            nodes.setdefault(
                child_id,
                {
                    "id": child_id, "kind": "exec", "path": command,
                    "sha256": _sha256_relative(tree_root, command, strict_paths=strict_paths),
                    "argv": (command,), "network_scope": "none", "capabilities": (), "source_input_id": None,
                },
            )
            edges.append((exec_id, child_id, "shell_child", exec_path, "invocation"))


def _expand_unique_executable_closure(tree_root: str, nodes: dict, edges: list) -> None:
    """Expand each strict-H3 executable once after raw contributions coalesce."""

    expanded: set[str] = set()
    while True:
        pending = sorted(
            node_id
            for node_id, node in nodes.items()
            if node.get("kind") in {"exec", "interpreter", "dynamic_library"} and node_id not in expanded
        )
        if not pending:
            return
        for node_id in pending:
            node = nodes[node_id]
            _add_interpreter_and_dynamic_edges(
                tree_root,
                node["path"],
                node_id,
                nodes,
                edges,
                strict_paths=True,
            )
            expanded.add(node_id)


def _resolve_library(tree_root: str, soname: str, *, strict_paths: bool = False) -> str | None:
    basename = os.path.basename(soname)
    if strict_paths:
        if basename != soname or not basename:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "ELF dependency name is not a supported soname")
        matches = []
        for directory in _STRICT_LIBRARY_DIRS:
            image_path = posixpath.join(directory, basename)
            absolute = _resolve_image_path(tree_root, image_path, strict_paths=True)
            if os.path.isfile(absolute):
                matches.append(image_path)
        if len(matches) != 1:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "ELF dependency is missing or ambiguous in fixed search paths")
        return matches[0]
    for root, _dirs, files in os.walk(tree_root):
        if basename in files:
            return "/" + os.path.relpath(os.path.join(root, basename), tree_root)
    return None


def _handle_dbus_services(tree_root: str, nodes: dict, edges: list, *, strict_paths: bool = False) -> None:
    for dbus_dir in _DBUS_DIRS:
        directory = os.path.join(tree_root, dbus_dir)
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            with open(os.path.join(directory, name), "r", encoding="utf-8") as handle:
                sections = parse_systemd_unit(handle.read())
            exec_value = sections.get("D-BUS Service", {}).get("Exec", [None])[0]
            if not exec_value:
                continue
            argv = parse_exec_line(exec_value)
            dbus_id = f"dbus_service:{name}"
            exec_id = f"exec:{argv[0]}"
            nodes[dbus_id] = {
                "id": dbus_id, "kind": "dbus_service", "path": name, "sha256": None, "argv": (),
                "network_scope": "none", "capabilities": (), "source_input_id": None,
            }
            nodes.setdefault(
                exec_id,
                {
                    "id": exec_id, "kind": "exec", "path": argv[0],
                    "sha256": _sha256_relative(tree_root, argv[0], strict_paths=strict_paths),
                    "argv": tuple(argv), "network_scope": "none", "capabilities": (), "source_input_id": None,
                },
            )
            edges.append((dbus_id, exec_id, "dbus_activation", name, "Exec"))


def _handle_udev_rules(tree_root: str, nodes: dict, edges: list, *, strict_paths: bool = False) -> None:
    for udev_dir in _UDEV_DIRS:
        directory = os.path.join(tree_root, udev_dir)
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            with open(os.path.join(directory, name), "r", encoding="utf-8") as handle:
                text = handle.read()
            rule_id = f"udev_rule:{name}"
            nodes[rule_id] = {
                "id": rule_id, "kind": "udev_rule", "path": name, "sha256": None, "argv": (),
                "network_scope": "none", "capabilities": (), "source_input_id": None,
            }
            for command in parse_udev_actions(text):
                exec_id = f"exec:{command}"
                nodes.setdefault(
                    exec_id,
                    {
                        "id": exec_id, "kind": "exec", "path": command,
                        "sha256": _sha256_relative(tree_root, command, strict_paths=strict_paths),
                        "argv": (command,), "network_scope": "none", "capabilities": (), "source_input_id": None,
                    },
                )
                edges.append((rule_id, exec_id, "udev_activation", name, "action"))


def _handle_cron(tree_root: str, nodes: dict, edges: list, *, strict_paths: bool = False) -> None:
    for cron_dir in _CRON_D_DIRS:
        directory = os.path.join(tree_root, cron_dir)
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            with open(os.path.join(directory, name), "r", encoding="utf-8") as handle:
                text = handle.read()
            job_id = f"cron_job:{cron_dir}/{name}"
            nodes[job_id] = {
                "id": job_id, "kind": "cron_job", "path": f"/{cron_dir}/{name}", "sha256": None, "argv": (),
                "network_scope": "none", "capabilities": (), "source_input_id": None,
            }
            for command in parse_crontab_lines(text):
                exec_id = f"exec:{command}"
                nodes.setdefault(
                    exec_id,
                    {
                        "id": exec_id, "kind": "exec", "path": command,
                        "sha256": _sha256_relative(tree_root, command, strict_paths=strict_paths),
                        "argv": (command,), "network_scope": "none", "capabilities": (), "source_input_id": None,
                    },
                )
                edges.append((job_id, exec_id, "cron_activation", name, "command"))

    for period_dir in _CRON_PERIOD_DIRS:
        directory = os.path.join(tree_root, period_dir)
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            path = f"/{period_dir}/{name}"
            job_id = f"cron_job:{period_dir}/{name}"
            exec_id = f"exec:{path}"
            nodes[job_id] = {
                "id": job_id, "kind": "cron_job", "path": path, "sha256": None, "argv": (),
                "network_scope": "none", "capabilities": (), "source_input_id": None,
            }
            nodes.setdefault(
                exec_id,
                {
                    "id": exec_id, "kind": "exec", "path": path,
                    "sha256": _sha256_relative(tree_root, path, strict_paths=strict_paths),
                    "argv": (path,), "network_scope": "none", "capabilities": (), "source_input_id": None,
                },
            )
            edges.append((job_id, exec_id, "cron_activation", name, "run-parts"))


def _handle_generators(tree_root: str, nodes: dict, edges: list) -> None:
    for generator_dir in _GENERATOR_DIRS:
        directory = os.path.join(tree_root, generator_dir)
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
            parse_no_output_generator(text)
            generator_id = f"generator:{name}"
            nodes[generator_id] = {
                "id": generator_id, "kind": "generator", "path": f"/{generator_dir}/{name}", "sha256": None,
                "argv": (), "network_scope": "none", "capabilities": (), "source_input_id": None,
            }
            edges.append((generator_id, generator_id, "generator_activation", name, "boot"))
