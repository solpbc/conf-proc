#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Pure static-format parsers for the AC9 process/activation graph.

Parsing systemd unit INI syntax, udev rule action fields, cron lines,
shebangs, and a deliberately narrow shell-script grammar are generic
byte-format operations, not appliance inventory logic, so both the
builder and inspector graph walkers share these parsers -- what they do
NOT share is the tree walk that decides which files to feed them or how
to assemble the resulting node/edge graph (see conf_proc_build_graph.py
and conf_proc_inspect_graph.py).

Every parser here fails loud (raises ApplianceError) on any construct
outside its declared narrow grammar rather than silently approximating
it, per the design's "fail-closed" requirement for static graph
extraction.
"""

from __future__ import annotations

import re
from typing import Final

from conf_proc_reasons import CP_POLICY_UNSUPPORTED_ACTIVATION, ApplianceError


_SECTION_RE: Final = re.compile(r"^\[([A-Za-z]+)\]$")
_UDEV_ACTION_RE: Final = re.compile(r'(RUN\{[^}]*\}|RUN|PROGRAM|IMPORT\{program\})\s*[+:]?=\s*"([^"]*)"')
_FORBIDDEN_SHELL_CHARS: Final = frozenset("$`|<>&;*?~(){}[]'\"\\")
_CRON_LINE_RE: Final = re.compile(
    r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<user>\S+)\s+(?P<command>.+)$"
)


def parse_systemd_unit(text: str) -> dict[str, dict[str, list[str]]]:
    """Parse INI-style systemd unit syntax with repeated-key accumulation."""

    sections: dict[str, dict[str, list[str]]] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        section_match = _SECTION_RE.match(line)
        if section_match:
            current = section_match.group(1)
            sections.setdefault(current, {})
            continue
        if current is None or "=" not in line:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, f"unit syntax outside a section or missing '=': {line!r}")
        key, _, value = line.partition("=")
        sections[current].setdefault(key.strip(), []).append(value.strip())
    return sections


def parse_exec_line(value: str) -> list[str]:
    """Split a static ExecStart-style value into argv, absolute path only."""

    tokens = value.split()
    if not tokens or not tokens[0].startswith("/"):
        raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, f"Exec directive must be an absolute path: {value!r}")
    return tokens


def parse_udev_actions(text: str) -> list[str]:
    """Extract absolute RUN/PROGRAM/IMPORT{program} commands from udev rules."""

    commands = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for _keyword, value in _UDEV_ACTION_RE.findall(line):
            command = value.split()[0] if value.split() else ""
            if not command.startswith("/"):
                raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, f"udev action must invoke an absolute path: {value!r}")
            commands.append(command)
    return commands


def parse_crontab_lines(text: str) -> list[str]:
    """Extract absolute commands from /etc/crontab or /etc/cron.d/* syntax."""

    commands = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _CRON_LINE_RE.match(line)
        if not match:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, f"unsupported crontab line syntax: {line!r}")
        command = match.group("command").split()[0]
        if not command.startswith("/"):
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, f"cron command must be an absolute path: {command!r}")
        commands.append(command)
    return commands


def parse_shebang(text: str) -> str | None:
    """Extract an absolute interpreter path from a script's first line."""

    first_line = text.splitlines()[0] if text else ""
    if not first_line.startswith("#!"):
        return None
    interpreter_line = first_line[2:].strip()
    tokens = interpreter_line.split()
    if not tokens or not tokens[0].startswith("/"):
        raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, f"shebang interpreter must be an absolute path: {first_line!r}")
    if tokens[0].endswith("/env"):
        raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "shebang indirection via env is not statically resolvable")
    return tokens[0]


def parse_narrow_shell_script(text: str) -> list[str]:
    """Extract absolute commands invoked by a deliberately narrow shell grammar.

    Supports only: comments, blank lines, a shebang first line, bare
    ``exit``/``exit N``, ``exec /absolute/path ...``, and direct absolute
    command invocations. Anything else (expansions, conditionals,
    functions, loops, substitutions, pipelines, redirections, globs,
    relative commands) is rejected.
    """

    commands = []
    lines = text.splitlines()
    for index, raw_line in enumerate(lines):
        line = raw_line.strip()
        if index == 0 and line.startswith("#!"):
            continue
        if not line or line.startswith("#"):
            continue
        if line == "exit" or re.fullmatch(r"exit\s+\d+", line):
            continue
        if any(ch in _FORBIDDEN_SHELL_CHARS for ch in line):
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, f"unsupported shell syntax: {line!r}")
        tokens = line.split()
        if tokens[0] == "exec":
            tokens = tokens[1:]
        if not tokens or not tokens[0].startswith("/"):
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, f"only absolute command invocations are supported: {line!r}")
        commands.append(tokens[0])
    return commands


def parse_no_output_generator(text: str) -> None:
    """Validate a generator script is a strict no-op stub; raise otherwise.

    Output-producing generators (anything that could write new unit
    files at boot) cannot be independently extracted without executing
    them, so only a script that does nothing beyond exiting is accepted.
    """

    lines = text.splitlines()
    for index, raw_line in enumerate(lines):
        line = raw_line.strip()
        if index == 0 and line.startswith("#!"):
            continue
        if not line or line.startswith("#"):
            continue
        if line == "exit" or re.fullmatch(r"exit\s+\d+", line):
            continue
        raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, f"generator must be a no-output stub, found: {line!r}")
