#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Minimal ELF64 little-endian parser for PT_INTERP and DT_NEEDED/RPATH/
RUNPATH dynamic-load edges.

Pure byte-format parsing shared by builder and inspector -- no
pyelftools dependency is available in this environment, and this covers
exactly what AC9's static graph extraction needs, nothing more.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from conf_proc_reasons import CP_TREE_UNSUPPORTED_NODE, ApplianceError


ELF_MAGIC: Final = b"\x7fELF"
_ELFCLASS64: Final = 2
_ELFDATA2LSB: Final = 1
_PT_INTERP: Final = 3
_SHT_DYNAMIC: Final = 6
_DT_NULL: Final = 0
_DT_NEEDED: Final = 1
_DT_RPATH: Final = 15
_DT_RUNPATH: Final = 29


@dataclass(frozen=True)
class ElfInfo:
    interpreter: str | None
    needed: tuple[str, ...]
    rpath: tuple[str, ...]
    runpath: tuple[str, ...]


def is_elf(data: bytes) -> bool:
    return data[:4] == ELF_MAGIC


def parse_elf(data: bytes) -> ElfInfo:
    """Parse PT_INTERP and the .dynamic table's NEEDED/RPATH/RUNPATH entries."""

    if not is_elf(data):
        raise ApplianceError(CP_TREE_UNSUPPORTED_NODE, "not an ELF file (bad magic)")
    ei_class = data[4]
    ei_data = data[5]
    if ei_class != _ELFCLASS64 or ei_data != _ELFDATA2LSB:
        raise ApplianceError(CP_TREE_UNSUPPORTED_NODE, "only 64-bit little-endian ELF is supported")

    (
        _e_type,
        _e_machine,
        _e_version,
        _e_entry,
        e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)

    interpreter = _find_interpreter(data, e_phoff, e_phentsize, e_phnum)
    needed, rpath, runpath = _find_dynamic_entries(data, e_shoff, e_shentsize, e_shnum, e_shstrndx)
    return ElfInfo(interpreter=interpreter, needed=needed, rpath=rpath, runpath=runpath)


def _find_interpreter(data: bytes, phoff: int, phentsize: int, phnum: int) -> str | None:
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, _p_flags, p_offset, _p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = struct.unpack_from(
            "<IIQQQQQQ", data, offset
        )
        if p_type == _PT_INTERP:
            raw = data[p_offset : p_offset + p_filesz]
            return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
    return None


def _find_dynamic_entries(
    data: bytes, shoff: int, shentsize: int, shnum: int, shstrndx: int
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    if shnum == 0:
        return (), (), ()

    sections = []
    for index in range(shnum):
        offset = shoff + index * shentsize
        sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, _sh_link, _sh_info, _sh_addralign, _sh_entsize = (
            struct.unpack_from("<IIQQQQIIQQ", data, offset)
        )
        sections.append((sh_name, sh_type, sh_offset, sh_size))

    shstr_offset = sections[shstrndx][2]

    def section_name(name_offset: int) -> str:
        raw = data[shstr_offset + name_offset :]
        return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")

    dynamic_offset = dynamic_size = None
    dynstr_offset = None
    for sh_name, sh_type, sh_offset, sh_size in sections:
        name = section_name(sh_name)
        if sh_type == _SHT_DYNAMIC and name == ".dynamic":
            dynamic_offset, dynamic_size = sh_offset, sh_size
        elif name == ".dynstr":
            dynstr_offset = sh_offset

    if dynamic_offset is None or dynstr_offset is None:
        return (), (), ()

    def dynstr(name_offset: int) -> str:
        raw = data[dynstr_offset + name_offset :]
        return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")

    needed: list[str] = []
    rpath: list[str] = []
    runpath: list[str] = []
    entry_size = 16
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, entry_size):
        tag, value = struct.unpack_from("<qQ", data, offset)
        if tag == _DT_NULL:
            break
        if tag == _DT_NEEDED:
            needed.append(dynstr(value))
        elif tag == _DT_RPATH:
            rpath.append(dynstr(value))
        elif tag == _DT_RUNPATH:
            runpath.append(dynstr(value))
    return tuple(needed), tuple(rpath), tuple(runpath)
