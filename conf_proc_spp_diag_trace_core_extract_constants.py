#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Mechanically extract SPP diagnostic trace wire facts into a kernel header.

Parses ``conf_proc_spp_diag_trace.h`` and ``conf_proc_spp_diag_trace.c`` as
text.  Does not import them, compile them, or copy function bodies.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
HEADER_PATH = ROOT / "conf_proc_spp_diag_trace.h"
SOURCE_PATH = ROOT / "conf_proc_spp_diag_trace.c"
OUTPUT_PATH = (
    ROOT
    / "spp-diag-trace-core-src"
    / "security"
    / "spp_diag_trace_core"
    / "protocol_constants.h"
)

DEFINE_RE = re.compile(
    r"^#define\s+(SPP_DIAG_TRACE_[A-Z0-9_]+)\s+(.+?)\s*$", re.MULTILINE
)
ENUM_RE = re.compile(r"^\s+(WIRE_[A-Z0-9_]+)\s*=\s*(\d+)\s*,?\s*$", re.MULTILINE)
ARRAY_RE = re.compile(
    r"(?:static\s+)?const\s+uint8_t\s+(\w+)(?:\[[^\]]*\])?\s*=\s*\{([^}]+)\}",
    re.MULTILINE,
)
BYTE_RE = re.compile(
    r"0x([0-9a-fA-F]{1,2})|'((?:\\.|[^'\\]))'|(\d+)"
)


def _unescape_char(token: str) -> int:
    if token == "\\0":
        return 0
    if token == "\\n":
        return 10
    if token == "\\\\":
        return 92
    if token == "\\'":
        return 39
    if len(token) != 1:
        raise ValueError(f"unsupported character token {token!r}")
    return ord(token)


def parse_byte_array(body: str) -> tuple[int, ...]:
    values: list[int] = []
    for match in BYTE_RE.finditer(body):
        hex_token, char_token, dec_token = match.groups()
        if hex_token is not None:
            values.append(int(hex_token, 16))
        elif char_token is not None:
            values.append(_unescape_char(char_token))
        else:
            values.append(int(dec_token, 10))
    return tuple(values)


def format_byte_macro(values: tuple[int, ...]) -> str:
    parts: list[str] = []
    for index, value in enumerate(values):
        if 32 <= value < 127 and value not in (39, 92):
            token = f"'{chr(value)}'"
        else:
            token = f"0x{value:02x}"
        if index and index % 10 == 0:
            parts.append("\\\n\t" + token)
        elif index == 0:
            parts.append(token)
        else:
            parts.append(" " + token)
        if index != len(values) - 1:
            parts.append(",")
    return "".join(parts)


def parse_defines(text: str) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in DEFINE_RE.finditer(text):
        name, value = match.group(1), match.group(2).strip()
        if name in seen:
            continue
        seen.add(name)
        items.append((name, value))
    return items


def parse_enum(text: str) -> list[tuple[str, str]]:
    return [(match.group(1), match.group(2)) for match in ENUM_RE.finditer(text)]


def parse_named_array(text: str, name: str) -> tuple[int, ...]:
    for match in ARRAY_RE.finditer(text):
        if match.group(1) == name:
            return parse_byte_array(match.group(2))
    raise ValueError(f"array {name} not found")


def render_header(
    defines: list[tuple[str, str]],
    enum_items: list[tuple[str, str]],
    source_commit: tuple[int, ...],
    magic_header: tuple[int, ...],
    magic_command: tuple[int, ...],
    magic_ima: tuple[int, ...],
    preimage_domain: tuple[int, ...],
    frame_domain: tuple[int, ...],
) -> str:
    lines: list[str] = [
        "/* SPDX-License-Identifier: GPL-2.0-only */",
        "/* Mechanically generated from conf_proc_spp_diag_trace.h/.c. Do not edit. */",
        "",
        "#ifndef SPP_DIAG_TRACE_CORE_PROTOCOL_CONSTANTS_H",
        "#define SPP_DIAG_TRACE_CORE_PROTOCOL_CONSTANTS_H",
        "",
    ]
    for name, value in enum_items:
        lines.append(f"#define {name} {value}")
    lines.append("")
    for name, value in defines:
        lines.append(f"#define {name} {value}")
    lines.append("")
    lines.append(
        f"#define SPP_DIAG_TRACE_SOURCE_COMMIT_BYTES \\\n\t{format_byte_macro(source_commit)}"
    )
    lines.append("")
    lines.append(
        f"#define SPP_DIAG_TRACE_MAGIC_HEADER_BYTES \\\n\t{format_byte_macro(magic_header)}"
    )
    lines.append("")
    lines.append(
        f"#define SPP_DIAG_TRACE_MAGIC_COMMAND_BYTES \\\n\t{format_byte_macro(magic_command)}"
    )
    lines.append("")
    lines.append(
        f"#define SPP_DIAG_TRACE_MAGIC_IMA_BYTES \\\n\t{format_byte_macro(magic_ima)}"
    )
    lines.append("")
    lines.append(
        f"#define SPP_DIAG_TRACE_PREIMAGE_DOMAIN_BYTES \\\n\t{format_byte_macro(preimage_domain)}"
    )
    lines.append("")
    lines.append(
        f"#define SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_BYTES \\\n\t{format_byte_macro(frame_domain)}"
    )
    lines.append("")
    lines.extend(
        [
            "#endif",
            "",
        ]
    )
    return "\n".join(lines)


def extract(header_text: str, source_text: str) -> str:
    defines = parse_defines(header_text)
    enum_items = parse_enum(header_text)
    if not defines:
        raise ValueError("no SPP_DIAG_TRACE_ macros parsed")
    if not enum_items:
        raise ValueError("no WIRE_ enum values parsed")
    source_commit = parse_named_array(source_text, "SPP_DIAG_TRACE_SOURCE_COMMIT")
    magic_header = parse_named_array(source_text, "k_magic_header")
    magic_command = parse_named_array(source_text, "k_magic_command")
    magic_ima = parse_named_array(source_text, "k_magic_ima")
    preimage_domain = parse_named_array(source_text, "k_preimage_domain")
    frame_domain = parse_named_array(source_text, "k_frame_preimage_domain")
    if len(source_commit) != 20:
        raise ValueError("SOURCE_COMMIT length mismatch")
    if len(magic_header) != 8:
        raise ValueError("header magic length mismatch")
    if len(magic_command) != 8:
        raise ValueError("command magic length mismatch")
    if len(magic_ima) != 8:
        raise ValueError("ima magic length mismatch")
    if len(preimage_domain) != 28:
        raise ValueError("header domain length mismatch")
    if len(frame_domain) != 27:
        raise ValueError("frame domain length mismatch")
    return render_header(
        defines,
        enum_items,
        source_commit,
        magic_header,
        magic_command,
        magic_ima,
        preimage_domain,
        frame_domain,
    )


def main(argv: list[str]) -> int:
    output = OUTPUT_PATH
    if len(argv) == 2:
        output = Path(argv[1])
    elif len(argv) != 1:
        sys.stderr.write(
            "usage: conf_proc_spp_diag_trace_core_extract_constants.py [OUT]\n"
        )
        return 2
    text = extract(HEADER_PATH.read_text(encoding="utf-8"), SOURCE_PATH.read_text(encoding="utf-8"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
