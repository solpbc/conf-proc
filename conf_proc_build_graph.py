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
import stat

from conf_proc_elf import is_elf, parse_elf
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


def extract_graph(tree_root: str) -> tuple[list[dict], list[dict]]:
    """Statically extract (nodes, edges) from a staging tree."""

    nodes: dict[str, dict] = {}
    edges: list[tuple] = []

    unit_sections = _read_all_units(tree_root)
    for unit_name, sections in unit_sections.items():
        _add_unit_node_and_edges(unit_name, sections, tree_root, nodes, edges)

    _handle_dbus_services(tree_root, nodes, edges)
    _handle_udev_rules(tree_root, nodes, edges)
    _handle_cron(tree_root, nodes, edges)
    _handle_generators(tree_root, nodes, edges)

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


def _add_unit_node_and_edges(unit_name: str, sections: dict, tree_root: str, nodes: dict, edges: list) -> None:
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
            sha256 = _sha256_relative(tree_root, exec_path)
            nodes[exec_id] = {
                "id": exec_id, "kind": "exec", "path": exec_path, "sha256": sha256, "argv": tuple(argv),
                "network_scope": network_scope, "capabilities": (), "source_input_id": None,
            }
            edges.append((unit_id, exec_id, "unit_exec", unit_name, "ExecStart"))
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


def _sha256_relative(tree_root: str, relative_path: str) -> str:
    absolute = os.path.join(tree_root, relative_path.lstrip("/"))
    with open(absolute, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _add_interpreter_and_dynamic_edges(tree_root: str, exec_path: str, exec_id: str, nodes: dict, edges: list) -> None:
    absolute = os.path.join(tree_root, exec_path.lstrip("/"))
    if not os.path.isfile(absolute):
        return
    with open(absolute, "rb") as handle:
        data = handle.read()

    if is_elf(data):
        info = parse_elf(data)
        if info.interpreter is not None and os.path.isfile(os.path.join(tree_root, info.interpreter.lstrip("/"))):
            interp_id = f"interpreter:{info.interpreter}"
            nodes[interp_id] = {
                "id": interp_id, "kind": "interpreter", "path": info.interpreter,
                "sha256": _sha256_relative(tree_root, info.interpreter), "argv": (), "network_scope": "none",
                "capabilities": (), "source_input_id": None,
            }
            edges.append((exec_id, interp_id, "elf_interpreter", exec_path, "PT_INTERP"))
        for needed in info.needed:
            resolved = _resolve_library(tree_root, needed)
            if resolved is None:
                continue
            lib_id = f"dynamic_library:{resolved}"
            nodes[lib_id] = {
                "id": lib_id, "kind": "dynamic_library", "path": resolved, "sha256": _sha256_relative(tree_root, resolved),
                "argv": (), "network_scope": "none", "capabilities": (), "source_input_id": None,
            }
            edges.append((exec_id, lib_id, "dynamic_load", exec_path, "DT_NEEDED"))
    else:
        interpreter = parse_shebang(data.decode("utf-8", "replace"))
        if interpreter is not None and os.path.isfile(os.path.join(tree_root, interpreter.lstrip("/"))):
            interp_id = f"interpreter:{interpreter}"
            nodes[interp_id] = {
                "id": interp_id, "kind": "interpreter", "path": interpreter,
                "sha256": _sha256_relative(tree_root, interpreter), "argv": (), "network_scope": "none",
                "capabilities": (), "source_input_id": None,
            }
            edges.append((exec_id, interp_id, "script_interpreter", exec_path, "shebang"))
        for command in parse_narrow_shell_script(data.decode("utf-8", "replace")):
            if not os.path.isfile(os.path.join(tree_root, command.lstrip("/"))):
                continue
            child_id = f"exec:{command}"
            nodes.setdefault(
                child_id,
                {
                    "id": child_id, "kind": "exec", "path": command, "sha256": _sha256_relative(tree_root, command),
                    "argv": (command,), "network_scope": "none", "capabilities": (), "source_input_id": None,
                },
            )
            edges.append((exec_id, child_id, "shell_child", exec_path, "invocation"))


def _resolve_library(tree_root: str, soname: str) -> str | None:
    basename = os.path.basename(soname)
    for root, _dirs, files in os.walk(tree_root):
        if basename in files:
            return "/" + os.path.relpath(os.path.join(root, basename), tree_root)
    return None


def _handle_dbus_services(tree_root: str, nodes: dict, edges: list) -> None:
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
                    "id": exec_id, "kind": "exec", "path": argv[0], "sha256": _sha256_relative(tree_root, argv[0]),
                    "argv": tuple(argv), "network_scope": "none", "capabilities": (), "source_input_id": None,
                },
            )
            edges.append((dbus_id, exec_id, "dbus_activation", name, "Exec"))


def _handle_udev_rules(tree_root: str, nodes: dict, edges: list) -> None:
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
                        "id": exec_id, "kind": "exec", "path": command, "sha256": _sha256_relative(tree_root, command),
                        "argv": (command,), "network_scope": "none", "capabilities": (), "source_input_id": None,
                    },
                )
                edges.append((rule_id, exec_id, "udev_activation", name, "action"))


def _handle_cron(tree_root: str, nodes: dict, edges: list) -> None:
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
                        "id": exec_id, "kind": "exec", "path": command, "sha256": _sha256_relative(tree_root, command),
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
                    "id": exec_id, "kind": "exec", "path": path, "sha256": _sha256_relative(tree_root, path),
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
