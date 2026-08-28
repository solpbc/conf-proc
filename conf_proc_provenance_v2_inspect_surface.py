#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""H4-local activation grammar and prohibited-surface inspection.

The existing prohibited predicates are deliberately reused for their narrow,
shared classes.  This module adds the larger v2 activation grammar without
changing behavior for any live v1 caller.
"""

from __future__ import annotations

import os
import posixpath
import stat
from typing import Final

from conf_proc_prohibited import check_content_markers, check_prohibited_path, check_prohibited_unit
from conf_proc_reasons import CP_PROVENANCE_V2_INSPECT_PROHIBITED_SURFACE, ApplianceError
from conf_proc_unit_parser import parse_crontab_lines, parse_exec_line, parse_systemd_unit, parse_udev_actions


_UNIT_DIRS: Final = ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system")
_DBUS_DIRS: Final = ("etc/dbus-1/system-services", "usr/share/dbus-1/system-services")
_UDEV_DIRS: Final = ("etc/udev/rules.d", "usr/lib/udev/rules.d")
_CRON_D_DIRS: Final = ("etc/cron.d",)
_CRON_PERIOD_DIRS: Final = ("etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly")
_GENERATOR_DIRS: Final = ("usr/lib/systemd/system-generators", "etc/systemd/system-generators")
_UNIT_SUFFIXES: Final = (
    ".service", ".socket", ".timer", ".mount", ".path", ".target", ".device", ".slice", ".scope", ".automount", ".swap",
)
_UNMODELED_ACTIVATION_DIRS: Final = (
    "run/systemd/system", "usr/local/lib/systemd/system", "etc/systemd/user", "usr/lib/systemd/user",
    "lib/systemd/user", "run/systemd/user", "usr/local/lib/systemd/user", "run/systemd/system-generators",
    "usr/local/lib/systemd/system-generators", "usr/lib/systemd/system-generators.early",
    "usr/lib/systemd/system-generators.late", "etc/systemd/system-generators.early",
    "etc/systemd/system-generators.late", "lib/udev/rules.d", "run/udev/rules.d",
    "usr/local/lib/udev/rules.d", "run/dbus-1/system-services", "usr/local/share/dbus-1/system-services",
    "var/spool/cron", "etc/init", "etc/init.d", "etc/rc.d",
)
_UNMODELED_ACTIVATION_FILES: Final = ("etc/rc.local", "etc/inittab", "etc/anacrontab", "etc/crontab")
_UNIT_REFERENCE_CHARS: Final = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.@:-")
_SHELL_MARKERS: Final = ("$", "`", "%", "|", "<", ">", "&", ";", "(", "'", '"', "\\")
_SHELL_BASENAMES: Final = frozenset({"sh", "bash", "dash", "zsh", "ksh", "busybox", "env"})
_FETCHER_BASENAMES: Final = frozenset({"apt", "apt-get", "yum", "dnf", "curl", "wget"})
_AZURE_MARKERS: Final = ("runcommand", "run-command", "run_command", "microsoft.cplat.core", "walinuxagent", "waagent", "cloud-init")
_JOURNAL_PREFIXES: Final = ("var/log/journal", "var/lib/systemd/journal")
_CONTENT_SCAN_CHUNK: Final = 1024 * 1024
_CONTENT_SCAN_OVERLAP: Final = 64


def check_extracted_surfaces(*, runtime_policy_root: str, models_root: str, policy, graph_nodes: list[dict]) -> None:
    """Reject unmodeled activation and forbidden runtime surface classes."""

    try:
        _scan_tree(models_root, models=True, policy=policy, graph_nodes=())
        _scan_tree(runtime_policy_root, models=False, policy=policy, graph_nodes=graph_nodes)
    except ApplianceError as exc:
        if exc.reason_code == CP_PROVENANCE_V2_INSPECT_PROHIBITED_SURFACE:
            raise
        raise ApplianceError(CP_PROVENANCE_V2_INSPECT_PROHIBITED_SURFACE, "prohibited extracted surface") from exc
    except (OSError, UnicodeError) as exc:
        raise ApplianceError(CP_PROVENANCE_V2_INSPECT_PROHIBITED_SURFACE, "could not inspect extracted surface") from exc


def _scan_tree(tree_root: str, *, models: bool, policy, graph_nodes: list[dict] | tuple[()]) -> None:
    writable_dirs: set[str] = set()
    executable_or_activation: set[str] = set()
    regular_paths: list[tuple[str, str]] = []
    for root, directories, files in os.walk(tree_root, followlinks=False):
        for name in sorted([*directories, *files]):
            absolute = os.path.join(root, name)
            relative = _relative(tree_root, absolute)
            metadata = os.lstat(absolute)
            image_path = f"/{relative}"
            _check_shared_path(image_path)
            _check_named_surface(relative)
            if stat.S_ISSOCK(metadata.st_mode) or stat.S_ISFIFO(metadata.st_mode) or stat.S_ISCHR(metadata.st_mode) or stat.S_ISBLK(metadata.st_mode):
                _reject("device or socket content is prohibited")
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) & 0o022:
                    writable_dirs.add(relative)
                _validate_activation_path(relative)
                continue
            _validate_activation_path(relative)
            activation = _touches_activation_surface(relative)
            if models and activation:
                _reject("models image contains activation content")
            if stat.S_ISREG(metadata.st_mode):
                regular_paths.append((relative, absolute))
                if stat.S_IMODE(metadata.st_mode) & 0o111:
                    executable_or_activation.add(relative)
                    if models:
                        _reject("models image contains executable content")
                if activation:
                    executable_or_activation.add(relative)
            elif stat.S_ISLNK(metadata.st_mode):
                if models and activation:
                    _reject("models image contains activation content")
            else:
                _reject("unsupported extracted node")

    for node in graph_nodes:
        if type(node) is dict and type(node.get("path")) is str and node["path"].startswith("/"):
            executable_or_activation.add(node["path"].lstrip("/"))
    if not models:
        for relative, absolute in regular_paths:
            _scan_regular_content(relative, absolute, policy)
    for relative in executable_or_activation:
        if _has_writable_ancestor(relative, writable_dirs):
            _reject("writable executable or activation ancestor is prohibited")


def _scan_regular_content(relative: str, absolute: str, policy) -> None:
    normalized = relative.replace(os.sep, "/")
    parent = posixpath.dirname(normalized)
    basename = posixpath.basename(normalized)
    if basename in _FETCHER_BASENAMES:
        _reject("network fetcher is prohibited")
    if normalized in _UNMODELED_ACTIVATION_FILES or parent in _CRON_PERIOD_DIRS:
        _reject("cron activation is prohibited")
    if parent in _GENERATOR_DIRS:
        _reject("systemd generator is prohibited")
    if normalized.startswith(_JOURNAL_PREFIXES) or basename.endswith((".journal", ".journal~")):
        _reject("persistent journal surface is prohibited")
    structured = (
        parent in (*_UNIT_DIRS, *_DBUS_DIRS, *_UDEV_DIRS, *_CRON_D_DIRS)
        or normalized == "etc/systemd/journald.conf"
        or normalized.startswith("etc/systemd/journald.conf.d/")
    )
    if not structured:
        _scan_unstructured_content(absolute, f"/{normalized}")
        return
    content = _read_bounded(absolute)
    _check_shared_content(f"/{normalized}", content)
    if any(marker.encode("ascii") in content.lower() for marker in _AZURE_MARKERS):
        _reject("Azure or cloud management surface is prohibited")
    if _is_journald_config(normalized, content):
        _reject("persistent journald configuration is prohibited")
    if parent in _UNIT_DIRS:
        _validate_service_unit(basename, content, policy)
    elif parent in _DBUS_DIRS:
        _validate_dbus_service(content)
    elif parent in _UDEV_DIRS:
        _validate_udev_rule(content)
    elif parent in _CRON_D_DIRS:
        _validate_cron_file(content)


def _validate_service_unit(basename: str, content: bytes, policy) -> None:
    if not basename.endswith(".service"):
        _reject("unmodeled systemd activation form")
    _check_shared_unit(basename)
    sections = parse_systemd_unit(_decode_text(content))
    allowed = {
        "Unit": {"Description", "After", "Requires", "Wants", "BindsTo"},
        "Install": {"WantedBy"},
        "Service": {"ExecStart", "IPAddressDeny", "IPAddressAllow", "CapabilityBoundingSet", "AmbientCapabilities", "NoNewPrivileges"},
    }
    if not set(sections).issubset(allowed):
        _reject("unmodeled systemd unit section")
    for section, values in sections.items():
        if not set(values).issubset(allowed[section]):
            _reject("unmodeled systemd unit directive")
    for key in ("After", "Requires", "Wants", "BindsTo"):
        for value in sections.get("Unit", {}).get(key, []):
            _validate_unit_references(value)
    for value in sections.get("Install", {}).get("WantedBy", []):
        _validate_unit_references(value)
    exec_values = sections.get("Service", {}).get("ExecStart", [])
    if len(exec_values) != 1:
        _reject("service execution grammar is incomplete")
    _validate_exec_value(exec_values[0])
    capability = policy.capability_policy.get(f"unit:{basename}")
    bounding = sections.get("Service", {}).get("CapabilityBoundingSet", [])
    ambient = sections.get("Service", {}).get("AmbientCapabilities", [])
    if len(bounding) != 1 or ambient != [""] or sections.get("Service", {}).get("NoNewPrivileges") != ["yes"]:
        _reject("runtime capability posture is prohibited")
    if capability is None or tuple(sorted(bounding[0].split())) != capability.capability_bounding_set or capability.ambient_capabilities or not capability.no_new_privileges:
        _reject("runtime capability policy disagrees with tree")


def _validate_dbus_service(content: bytes) -> None:
    sections = parse_systemd_unit(_decode_text(content))
    if set(sections) != {"D-BUS Service"} or set(sections["D-BUS Service"]) != {"Exec"}:
        _reject("D-Bus activation indirection is prohibited")
    values = sections["D-BUS Service"]["Exec"]
    if len(values) != 1:
        _reject("D-Bus activation grammar is incomplete")
    _validate_exec_value(values[0])


def _validate_udev_rule(content: bytes) -> None:
    parse_udev_actions(_decode_text(content), reject_unmodeled=True)


def _validate_cron_file(content: bytes) -> None:
    commands = parse_crontab_lines(_decode_text(content), reject_unmodeled=True)
    if len(commands) != 1:
        _reject("cron.d must contain exactly one modeled command")


def _validate_exec_value(value: str) -> None:
    argv = parse_exec_line(value)
    if any(marker in value for marker in _SHELL_MARKERS) or posixpath.basename(argv[0]) in _SHELL_BASENAMES:
        _reject("activation command indirection is prohibited")


def _validate_unit_references(value: str) -> None:
    tokens = value.split(" ")
    if not value or value != " ".join(tokens) or any(not token or set(token) - _UNIT_REFERENCE_CHARS for token in tokens):
        _reject("systemd unit reference grammar is prohibited")


def _validate_activation_path(relative: str) -> None:
    normalized = relative.replace(os.sep, "/").strip("/")
    basename = posixpath.basename(normalized)
    parent = posixpath.dirname(normalized)
    if any(parent == directory or parent.startswith(directory + "/") for directory in _UNMODELED_ACTIVATION_DIRS):
        _reject("unmodeled activation directory is prohibited")
    if normalized in _UNMODELED_ACTIVATION_FILES or any(component.startswith("rc") and component.endswith(".d") for component in normalized.split("/")):
        _reject("unmodeled activation path is prohibited")
    if any(component.endswith(tuple(suffix + ".d" for suffix in _UNIT_SUFFIXES)) for component in normalized.split("/")):
        _reject("systemd unit drop-in is prohibited")
    approved = {
        **{directory: (".service", ".socket", ".timer") for directory in _UNIT_DIRS},
        **{directory: (".service",) for directory in _DBUS_DIRS},
        **{directory: (".rules",) for directory in _UDEV_DIRS},
        **{directory: None for directory in (*_CRON_D_DIRS, *_CRON_PERIOD_DIRS, *_GENERATOR_DIRS)},
    }
    if normalized in approved or any(directory.startswith(normalized + "/") for directory in approved):
        return
    if parent in approved:
        suffixes = approved[parent]
        if suffixes is not None and not basename.endswith(suffixes):
            _reject("unmodeled activation file is prohibited")
        return
    if any(parent.startswith(directory + "/") for directory in approved):
        _reject("nested activation content is prohibited")
    markers = {"system-generators", "system-generators.early", "system-generators.late", "rules.d", "system-services"}
    if basename.endswith(_UNIT_SUFFIXES) or basename.endswith(".rules") or any(component in markers for component in normalized.split("/")):
        _reject("unmodeled activation form is prohibited")


def _touches_activation_surface(relative: str) -> bool:
    normalized = relative.replace(os.sep, "/").strip("/")
    roots = (*_UNIT_DIRS, *_DBUS_DIRS, *_UDEV_DIRS, *_CRON_D_DIRS, *_CRON_PERIOD_DIRS, *_GENERATOR_DIRS, *_UNMODELED_ACTIVATION_DIRS)
    if any(normalized == root or normalized.startswith(root + "/") or root.startswith(normalized + "/") for root in roots):
        return True
    return normalized in _UNMODELED_ACTIVATION_FILES or any(
        component.endswith(tuple(suffix + ".d" for suffix in _UNIT_SUFFIXES))
        or component.startswith("rc") and component.endswith(".d")
        or component in {"system-generators", "system-generators.early", "system-generators.late", "rules.d", "system-services"}
        for component in normalized.split("/")
    )


def _has_writable_ancestor(relative: str, writable_dirs: set[str]) -> bool:
    current = posixpath.dirname(relative)
    while current:
        if current in writable_dirs:
            return True
        current = posixpath.dirname(current)
    return False


def _check_named_surface(relative: str) -> None:
    lowered = relative.lower()
    if any(marker in lowered for marker in _AZURE_MARKERS):
        _reject("Azure or cloud management surface is prohibited")
    if any(marker in lowered for marker in ("docker.sock", "containerd.sock", "crio.sock", "podman.sock")):
        _reject("management socket surface is prohibited")
    if lowered.endswith(("swapfile", "swap.img")) or "/swap/" in lowered:
        _reject("swap surface is prohibited")
    if any(marker in lowered for marker in ("kdump", "kexec", "coredump")):
        _reject("crash dump or kexec surface is prohibited")


def _is_journald_config(relative: str, content: bytes) -> bool:
    if relative != "etc/systemd/journald.conf" and not relative.startswith("etc/systemd/journald.conf.d/"):
        return False
    text = _decode_text(content).lower()
    return any(line.strip().replace(" ", "") == "storage=persistent" for line in text.splitlines() if not line.lstrip().startswith(("#", ";")))


def _relative(root: str, path: str) -> str:
    relative = os.path.relpath(path, root).replace(os.sep, "/")
    if relative in (".", "") or relative.startswith("../") or "\x00" in relative:
        _reject("extracted path is invalid")
    return relative


def _read_bounded(path: str) -> bytes:
    with open(path, "rb") as handle:
        data = handle.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024:
        _reject("extracted content exceeds inspection limit")
    return data


def _scan_unstructured_content(path: str, image_path: str) -> None:
    """Scan arbitrary-size runtime bytes without imposing a candidate size cap."""

    tail = b""
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(_CONTENT_SCAN_CHUNK)
            if not chunk:
                return
            window = tail + chunk
            _check_shared_content(image_path, window)
            if any(marker.encode("ascii") in window.lower() for marker in _AZURE_MARKERS):
                _reject("Azure or cloud management surface is prohibited")
            tail = window[-_CONTENT_SCAN_OVERLAP:]


def _decode_text(data: bytes) -> str:
    return data.decode("utf-8", "strict")


def _check_shared_path(path: str) -> None:
    check_prohibited_path(path)


def _check_shared_content(path: str, data: bytes) -> None:
    check_content_markers(path, data)


def _check_shared_unit(basename: str) -> None:
    check_prohibited_unit(basename)


def _reject(message: str) -> None:
    raise ApplianceError(CP_PROVENANCE_V2_INSPECT_PROHIBITED_SURFACE, message)
