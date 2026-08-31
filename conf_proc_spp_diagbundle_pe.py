#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Minimal PE/COFF parser for the signed-UKI .sppdiag descriptor.

Pure byte-format parsing -- no pefile dependency. Bounds-checked before every
unpack because the UKI bytes are untrusted input.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from conf_proc_json import canonical_loads
from conf_proc_reasons import ApplianceError
from conf_proc_spp_diagbundle_reasons import (
    CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS,
    CP_DIAGBUNDLE_DESCRIPTOR_COVERAGE,
    CP_DIAGBUNDLE_DESCRIPTOR_DUPLICATE,
    CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED,
    CP_DIAGBUNDLE_DESCRIPTOR_MISSING,
    CP_DIAGBUNDLE_PE_FORMAT,
    DiagBundleError,
    NODE_ARTIFACT_STATE,
)

_SPPDIAG_NAME: Final = b".sppdiag"
_DESCRIPTOR_KEYS: Final = frozenset({"schema", "artifact_state", "input_closure_address"})
_PE32: Final = 0x10B
_PE32PLUS: Final = 0x20B
_IMAGE_SCN_CNT_CODE: Final = 0x20
_IMAGE_SCN_CNT_INITIALIZED_DATA: Final = 0x40
_IMAGE_SCN_CNT_UNINITIALIZED_DATA: Final = 0x80
_IMAGE_SCN_MEM_SHARED: Final = 0x10000000
_IMAGE_SCN_MEM_EXECUTE: Final = 0x20000000
_IMAGE_SCN_MEM_READ: Final = 0x40000000
_IMAGE_SCN_MEM_WRITE: Final = 0x80000000
_COFF_FORMAT: Final = "<HHIIIHH"
_SECTION_FORMAT: Final = "<8sIIIIIIHHI"
_SECTION_SIZE: Final = 40


@dataclass(frozen=True)
class SppDiagDescriptor:
    schema: str
    input_closure_address: str


@dataclass(frozen=True)
class _Section:
    name: bytes
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    characteristics: int


def extract_sppdiag_descriptor(data: bytes) -> SppDiagDescriptor:
    """Parse and structurally validate the unique .sppdiag descriptor."""

    if type(data) is not bytes:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "PE image must be bytes")
    try:
        return _extract(data)
    except DiagBundleError:
        raise
    except (struct.error, IndexError, OverflowError) as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "PE image is malformed") from exc


def _extract(data: bytes) -> SppDiagDescriptor:
    if len(data) < 64:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "PE image is truncated")
    if data[0:2] != b"MZ":
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "invalid DOS magic")
    (e_lfanew,) = _unpack("<I", data, 60)
    if e_lfanew < 64 or e_lfanew > len(data) - 4:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "e_lfanew is out of range")
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "invalid PE signature")

    coff_offset = e_lfanew + 4
    (
        _machine,
        number_of_sections,
        _timedate_stamp,
        _pointer_to_symbol_table,
        _number_of_symbols,
        size_of_optional_header,
        _characteristics,
    ) = _unpack(_COFF_FORMAT, data, coff_offset)

    optional_start = coff_offset + 20
    if size_of_optional_header < 68:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "optional header is truncated")
    (optional_magic,) = _unpack("<H", data, optional_start)
    if optional_magic == _PE32:
        number_of_rva_offset = optional_start + 92
        directory_start = optional_start + 96
        minimum_optional = 96
    elif optional_magic == _PE32PLUS:
        number_of_rva_offset = optional_start + 108
        directory_start = optional_start + 112
        minimum_optional = 112
    else:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "unsupported optional header magic")
    if size_of_optional_header < minimum_optional:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "optional header is truncated")

    checksum_start = optional_start + 64
    _unpack("<I", data, checksum_start)
    checksum_range = (checksum_start, checksum_start + 4)

    (number_of_rva_and_sizes,) = _unpack("<I", data, number_of_rva_offset)
    excluded = [checksum_range]
    if number_of_rva_and_sizes > 4:
        cert_entry_start = directory_start + 32
        cert_entry_end = cert_entry_start + 8
        if cert_entry_end > optional_start + size_of_optional_header:
            raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "optional header is truncated")
        cert_file_offset, cert_size = _unpack("<II", data, cert_entry_start)
        excluded.append((cert_entry_start, cert_entry_end))
        if cert_size > 0:
            cert_end = cert_file_offset + cert_size
            if cert_file_offset < 0 or cert_end < cert_file_offset or cert_end > len(data):
                raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "certificate table pointer is out of file")
            excluded.append((cert_file_offset, cert_end))

    section_table_start = optional_start + size_of_optional_header
    table_size = number_of_sections * _SECTION_SIZE
    if number_of_sections < 0 or table_size < 0 or section_table_start + table_size > len(data):
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "section table is out of file")

    sections = tuple(
        _read_section(data, section_table_start + index * _SECTION_SIZE)
        for index in range(number_of_sections)
    )
    _require_unambiguous_raw_ranges(sections, len(data))

    sppdiag = [section for section in sections if section.name == _SPPDIAG_NAME]
    if not sppdiag:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MISSING, "signed UKI is missing a .sppdiag section")
    if len(sppdiag) > 1:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_DUPLICATE, "signed UKI has more than one .sppdiag section")
    section = sppdiag[0]
    _require_sppdiag_characteristics(section.characteristics)

    raw_start = section.pointer_to_raw_data
    raw_end = raw_start + section.size_of_raw_data
    if raw_start < 0 or raw_end < raw_start or raw_end > len(data):
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "section raw range is out of file")

    # Coverage is checked as soon as the raw range is known so an intersection
    # cannot be masked by later logical/JSON malformation.
    for excluded_start, excluded_end in excluded:
        if _overlaps(raw_start, raw_end, excluded_start, excluded_end):
            raise DiagBundleError(
                CP_DIAGBUNDLE_DESCRIPTOR_COVERAGE,
                ".sppdiag intersects a PE Authenticode-excluded range",
            )

    if section.size_of_raw_data < 4:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "logical length, padding, and raw size are inconsistent")
    (payload_length,) = _unpack("<I", data, raw_start)
    logical_length = 4 + payload_length
    if logical_length != section.virtual_size:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "virtual size does not match the logical descriptor length")
    if section.virtual_size > section.size_of_raw_data:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "logical section escapes its declared raw section")
    descriptor_end = raw_start + logical_length
    if descriptor_end > raw_end:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "logical section escapes its declared raw section")
    descriptor_bytes = data[raw_start + 4 : descriptor_end]
    padding = data[raw_start + section.virtual_size : raw_end]
    if padding != b"\x00" * len(padding):
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "nonzero section padding")
    return _parse_descriptor_payload(descriptor_bytes)


def _parse_descriptor_payload(descriptor_bytes: bytes) -> SppDiagDescriptor:
    try:
        raw = canonical_loads(descriptor_bytes)
    except ApplianceError as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "descriptor JSON is invalid") from exc
    if type(raw) is not dict or set(raw) != _DESCRIPTOR_KEYS:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "descriptor has unexpected fields")
    schema = raw["schema"]
    artifact_state = raw["artifact_state"]
    address = raw["input_closure_address"]
    if type(schema) is not str or not schema:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "descriptor schema is invalid")
    if artifact_state != NODE_ARTIFACT_STATE:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "descriptor artifact_state is invalid")
    if not _is_sha256(address):
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "descriptor input_closure_address is invalid")
    return SppDiagDescriptor(schema=schema, input_closure_address=address)


def _require_sppdiag_characteristics(characteristics: int) -> None:
    initialized = bool(characteristics & _IMAGE_SCN_CNT_INITIALIZED_DATA)
    readable = bool(characteristics & _IMAGE_SCN_MEM_READ)
    code = bool(characteristics & _IMAGE_SCN_CNT_CODE)
    uninitialized = bool(characteristics & _IMAGE_SCN_CNT_UNINITIALIZED_DATA)
    shared = bool(characteristics & _IMAGE_SCN_MEM_SHARED)
    executable = bool(characteristics & _IMAGE_SCN_MEM_EXECUTE)
    writable = bool(characteristics & _IMAGE_SCN_MEM_WRITE)
    if not initialized or not readable or code or uninitialized or shared or executable or writable:
        raise DiagBundleError(
            CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS,
            ".sppdiag section characteristics are not initialized readable data",
        )


def _require_unambiguous_raw_ranges(sections: tuple[_Section, ...], file_size: int) -> None:
    ranges: list[tuple[int, int]] = []
    for section in sections:
        if section.size_of_raw_data <= 0:
            continue
        start = section.pointer_to_raw_data
        end = start + section.size_of_raw_data
        if start < 0 or end < start or end > file_size:
            raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "ambiguous section table ranges")
        ranges.append((start, end))
    ranges.sort()
    for index in range(len(ranges) - 1):
        if ranges[index][1] > ranges[index + 1][0]:
            raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "ambiguous section table ranges")


def _read_section(data: bytes, offset: int) -> _Section:
    (
        name,
        virtual_size,
        virtual_address,
        size_of_raw_data,
        pointer_to_raw_data,
        _pointer_to_relocations,
        _pointer_to_linenumbers,
        _number_of_relocations,
        _number_of_linenumbers,
        characteristics,
    ) = _unpack(_SECTION_FORMAT, data, offset)
    return _Section(
        name=name,
        virtual_size=virtual_size,
        virtual_address=virtual_address,
        size_of_raw_data=size_of_raw_data,
        pointer_to_raw_data=pointer_to_raw_data,
        characteristics=characteristics,
    )


def _unpack(fmt: str, data: bytes, offset: int):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "PE image is truncated")
    try:
        return struct.unpack_from(fmt, data, offset)
    except struct.error as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "PE image is truncated") from exc


def _overlaps(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    return start_a < end_b and start_b < end_a


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and value == value.lower() and all(c in "0123456789abcdef" for c in value)
