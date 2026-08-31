#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Bounded-range PE/COFF parser for the signed-UKI .sppdiag descriptor."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final, Protocol

from conf_proc_json import canonical_loads
from conf_proc_reasons import ApplianceError
from conf_proc_spp_diagbundle_reasons import (
    CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS,
    CP_DIAGBUNDLE_DESCRIPTOR_COVERAGE,
    CP_DIAGBUNDLE_DESCRIPTOR_DUPLICATE,
    CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED,
    CP_DIAGBUNDLE_DESCRIPTOR_MISSING,
    CP_DIAGBUNDLE_PE_FORMAT,
    CP_DIAGBUNDLE_PE_SIZE,
    DiagBundleError,
    NODE_ARTIFACT_STATE,
)


_SPPDIAG_NAME: Final = b".sppdiag"
_DESCRIPTOR_SCHEMA_ID: Final = "sol-spp-diagbundle-descriptor/v1"
_DESCRIPTOR_KEYS: Final = frozenset({"schema", "artifact_state", "input_closure_address"})
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
_MAX_IMAGE_BYTES: Final = 1024**3
_MAX_DESCRIPTOR_BYTES: Final = 4 * 1024**2
_ZERO_SCAN_CHUNK: Final = 1024 * 1024


class PeRangeSource(Protocol):
    size_bytes: int

    def read_range(self, offset: int, length: int) -> bytes: ...


@dataclass(frozen=True)
class _BytesSource:
    data: bytes

    @property
    def size_bytes(self) -> int:
        return len(self.data)

    def read_range(self, offset: int, length: int) -> bytes:
        return self.data[offset : offset + length]


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


def extract_sppdiag_descriptor(value: bytes | PeRangeSource) -> SppDiagDescriptor:
    """Parse the unique descriptor without materializing the complete image."""

    source: PeRangeSource
    if type(value) is bytes:
        source = _BytesSource(value)
    else:
        source = value
    size = getattr(source, "size_bytes", None)
    reader = getattr(source, "read_range", None)
    if type(size) is not int or size < 0 or not callable(reader):
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "PE image must be a bounded range source")
    if size > _MAX_IMAGE_BYTES:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_SIZE, "PE image exceeds 1 GiB")
    try:
        return _extract(source)
    except DiagBundleError:
        raise
    except (OSError, struct.error, IndexError, OverflowError, TypeError, ValueError) as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "PE image is malformed") from exc


def _extract(source: PeRangeSource) -> SppDiagDescriptor:
    file_size = source.size_bytes
    if file_size < 64:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "PE image is truncated")
    if _read(source, 0, 2) != b"MZ":
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "invalid DOS magic")
    (e_lfanew,) = _unpack("<I", source, 60)
    if e_lfanew < 64 or e_lfanew > file_size - 4:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "e_lfanew is out of range")
    if _read(source, e_lfanew, 4) != b"PE\x00\x00":
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
    ) = _unpack(_COFF_FORMAT, source, coff_offset)

    optional_start = coff_offset + 20
    if size_of_optional_header < 68:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "optional header is truncated")
    optional_end = optional_start + size_of_optional_header
    if optional_end < optional_start or optional_end > file_size:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "optional header is out of file")
    (optional_magic,) = _unpack("<H", source, optional_start)
    if optional_magic == _PE32PLUS:
        number_of_rva_offset = optional_start + 108
        directory_start = optional_start + 112
        minimum_optional = 112
    else:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "unsupported optional header magic")
    if size_of_optional_header < minimum_optional:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "optional header is truncated")

    (file_alignment,) = _unpack("<I", source, optional_start + 36)
    (size_of_headers,) = _unpack("<I", source, optional_start + 60)
    if (
        file_alignment < 512
        or file_alignment > 64 * 1024
        or file_alignment & (file_alignment - 1)
    ):
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "FileAlignment is invalid")

    checksum_start = optional_start + 64
    _unpack("<I", source, checksum_start)
    excluded = [(checksum_start, checksum_start + 4)]

    (number_of_rva_and_sizes,) = _unpack("<I", source, number_of_rva_offset)
    if number_of_rva_and_sizes > 4:
        cert_entry_start = directory_start + 32
        cert_entry_end = cert_entry_start + 8
        if cert_entry_end > optional_end:
            raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "optional header is truncated")
        cert_file_offset, cert_size = _unpack("<II", source, cert_entry_start)
        excluded.append((cert_entry_start, cert_entry_end))
        if cert_size > 0:
            cert_end = cert_file_offset + cert_size
            if cert_end < cert_file_offset or cert_end > file_size:
                raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "certificate table pointer is out of file")
            excluded.append((cert_file_offset, cert_end))

    section_table_start = optional_end
    table_size = number_of_sections * _SECTION_SIZE
    section_table_end = section_table_start + table_size
    if section_table_end < section_table_start or section_table_end > file_size:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "section table is out of file")
    if (
        size_of_headers < section_table_end
        or size_of_headers > file_size
        or size_of_headers % file_alignment != 0
    ):
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "SizeOfHeaders does not cover the section table")
    sections = tuple(
        _read_section(source, section_table_start + index * _SECTION_SIZE)
        for index in range(number_of_sections)
    )
    _require_unambiguous_raw_ranges(sections, file_size)

    sppdiag = [section for section in sections if section.name == _SPPDIAG_NAME]
    if not sppdiag:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MISSING, "signed UKI is missing a .sppdiag section")
    if len(sppdiag) > 1:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_DUPLICATE, "signed UKI has more than one .sppdiag section")
    section = sppdiag[0]
    _require_sppdiag_characteristics(section.characteristics)

    raw_start = section.pointer_to_raw_data
    raw_end = raw_start + section.size_of_raw_data
    if raw_end < raw_start or raw_end > file_size:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "section raw range is out of file")
    for excluded_start, excluded_end in excluded:
        if _overlaps(raw_start, raw_end, excluded_start, excluded_end):
            raise DiagBundleError(
                CP_DIAGBUNDLE_DESCRIPTOR_COVERAGE,
                ".sppdiag intersects a PE Authenticode-excluded range",
            )

    if section.size_of_raw_data < 4:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "logical length, padding, and raw size are inconsistent")
    (payload_length,) = _unpack("<I", source, raw_start)
    if payload_length > _MAX_DESCRIPTOR_BYTES:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "descriptor payload exceeds 4 MiB")
    logical_length = 4 + payload_length
    if logical_length != section.virtual_size:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "virtual size does not match the logical descriptor length")
    if section.virtual_size > section.size_of_raw_data:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "logical section escapes its declared raw section")
    descriptor_end = raw_start + logical_length
    if descriptor_end < raw_start or descriptor_end > raw_end:
        raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "logical section escapes its declared raw section")
    descriptor_bytes = _read(source, raw_start + 4, payload_length)
    _require_zero_range(source, descriptor_end, raw_end - descriptor_end)
    descriptor = _parse_descriptor_payload(descriptor_bytes)
    _require_authenticode_section_layout(sections, size_of_headers, file_alignment)
    return descriptor


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
    if schema != _DESCRIPTOR_SCHEMA_ID:
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
        if end < start or end > file_size:
            raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "ambiguous section table ranges")
        ranges.append((start, end))
    ranges.sort()
    for index in range(len(ranges) - 1):
        if ranges[index][1] > ranges[index + 1][0]:
            raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "ambiguous section table ranges")


def _require_authenticode_section_layout(
    sections: tuple[_Section, ...], size_of_headers: int, file_alignment: int
) -> None:
    for section in sections:
        if section.size_of_raw_data <= 0:
            continue
        if (
            section.pointer_to_raw_data < size_of_headers
            or section.pointer_to_raw_data % file_alignment != 0
            or section.size_of_raw_data % file_alignment != 0
        ):
            raise DiagBundleError(
                CP_DIAGBUNDLE_PE_FORMAT,
                "section raw bytes overlap headers or violate FileAlignment",
            )


def _read_section(source: PeRangeSource, offset: int) -> _Section:
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
    ) = _unpack(_SECTION_FORMAT, source, offset)
    return _Section(
        name=name,
        virtual_size=virtual_size,
        virtual_address=virtual_address,
        size_of_raw_data=size_of_raw_data,
        pointer_to_raw_data=pointer_to_raw_data,
        characteristics=characteristics,
    )


def _unpack(fmt: str, source: PeRangeSource, offset: int):
    size = struct.calcsize(fmt)
    try:
        return struct.unpack(fmt, _read(source, offset, size))
    except struct.error as exc:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "PE image is truncated") from exc


def _read(source: PeRangeSource, offset: int, length: int) -> bytes:
    if offset < 0 or length < 0 or offset > source.size_bytes or length > source.size_bytes - offset:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "PE image is truncated")
    data = source.read_range(offset, length)
    if type(data) is not bytes or len(data) != length:
        raise DiagBundleError(CP_DIAGBUNDLE_PE_FORMAT, "PE range source returned a truncated range")
    return data


def _require_zero_range(source: PeRangeSource, offset: int, length: int) -> None:
    remaining = length
    cursor = offset
    while remaining:
        chunk_length = min(_ZERO_SCAN_CHUNK, remaining)
        if any(_read(source, cursor, chunk_length)):
            raise DiagBundleError(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, "nonzero section padding")
        cursor += chunk_length
        remaining -= chunk_length


def _overlaps(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    return start_a < end_b and start_b < end_a


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and value == value.lower() and all(c in "0123456789abcdef" for c in value)
