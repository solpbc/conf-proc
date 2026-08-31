#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""PE/COFF .sppdiag descriptor selftest with an independent byte builder."""

from __future__ import annotations

import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from conf_proc_json import canonical_dumps  # noqa: E402
from conf_proc_spp_diagbundle_pe import extract_sppdiag_descriptor  # noqa: E402
from conf_proc_spp_diagbundle_reasons import (  # noqa: E402
    CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS,
    CP_DIAGBUNDLE_DESCRIPTOR_COVERAGE,
    CP_DIAGBUNDLE_DESCRIPTOR_DUPLICATE,
    CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED,
    CP_DIAGBUNDLE_DESCRIPTOR_MISSING,
    CP_DIAGBUNDLE_PE_FORMAT,
    DiagBundleError,
)


SCN_CODE = 0x20
SCN_INITIALIZED = 0x40
SCN_UNINITIALIZED = 0x80
SCN_SHARED = 0x10000000
SCN_EXECUTE = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000
VALID_CHARS = SCN_INITIALIZED | SCN_READ
DEFAULT_SCHEMA = "sol-spp-diagbundle-input-closure/v1"
DEFAULT_ADDRESS = "ab" * 32
_COFF_FORMAT = "<HHIIIHH"
_SECTION_FORMAT = "<8sIIIIIIHHI"


def _descriptor_object(**updates: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema": DEFAULT_SCHEMA,
        "artifact_state": "diagnostic_unqualified",
        "input_closure_address": DEFAULT_ADDRESS,
    }
    raw.update(updates)
    return raw


def _descriptor_bytes(*, noncanonical: bool = False, **updates: object) -> bytes:
    payload = canonical_dumps(_descriptor_object(**updates))
    if noncanonical:
        return payload.replace(b":", b": ", 1)
    return payload


def _logical_section(payload: bytes, *, extra: bytes = b"") -> bytes:
    return struct.pack("<I", len(payload)) + payload + extra


def _optional_header(*, pe32plus: bool, checksum: int, n_rva: int, directories: list[tuple[int, int]]) -> bytes:
    if not pe32plus:
        header = bytearray()
        header += struct.pack("<HBB", 0x10B, 0, 0)
        header += struct.pack("<9I", 0, 0, 0, 0, 0, 0, 0, 4096, 512)
        header += struct.pack("<6H", 0, 0, 0, 0, 0, 0)
        header += struct.pack("<3I", 0, 0, 0)
        header += struct.pack("<I", checksum)
        header += struct.pack("<HH", 10, 0)
        header += struct.pack("<4I", 0, 0, 0, 0)
        header += struct.pack("<II", 0, n_rva)
    else:
        header = bytearray()
        header += struct.pack("<HBB", 0x20B, 0, 0)
        header += struct.pack("<5I", 0, 0, 0, 0, 0)
        header += struct.pack("<Q", 0)
        header += struct.pack("<II", 4096, 512)
        header += struct.pack("<6H", 0, 0, 0, 0, 0, 0)
        header += struct.pack("<3I", 0, 0, 0)
        header += struct.pack("<I", checksum)
        header += struct.pack("<HH", 10, 0)
        header += struct.pack("<4Q", 0, 0, 0, 0)
        header += struct.pack("<II", 0, n_rva)
    if len(directories) != n_rva:
        raise AssertionError("directory count must match NumberOfRvaAndSizes")
    for virtual_address, size in directories:
        header += struct.pack("<II", virtual_address, size)
    return bytes(header)


def build_pe(
    *,
    pe32plus: bool = False,
    checksum: int = 0,
    n_rva: int = 16,
    cert_offset: int = 0,
    cert_size: int = 0,
    sections: list[dict[str, object]] | None = None,
    e_magic: bytes = b"MZ",
    pe_sig: bytes = b"PE\x00\x00",
    e_lfanew: int = 64,
    size_of_optional_header: int | None = None,
    number_of_sections: int | None = None,
    machine: int = 0x8664,
    truncate: int | None = None,
) -> tuple[bytes, dict[str, int]]:
    if sections is None:
        sections = [_sppdiag_section()]
    directories = [(0, 0)] * n_rva
    if n_rva > 4:
        directories[4] = (cert_offset, cert_size)
    optional = _optional_header(pe32plus=pe32plus, checksum=checksum, n_rva=n_rva, directories=directories)
    optional_used = size_of_optional_header if size_of_optional_header is not None else len(optional)
    optional_start = e_lfanew + 4 + 20
    section_table_start = optional_start + optional_used
    declared_sections = len(sections) if number_of_sections is None else number_of_sections
    headers_end = section_table_start + 40 * max(declared_sections, len(sections))
    cursor = headers_end
    laid_out: list[dict[str, object]] = []
    for section in sections:
        raw = bytes(section["raw_bytes"])
        if "logical_size" in section:
            virtual_size = int(section["logical_size"])
        else:
            virtual_size = int(section.get("virtual_size", len(raw)))
        size_of_raw_data = int(section.get("size_of_raw_data", len(raw)))
        content_offset = cursor
        declared_pointer = int(section["pointer_to_raw_data"]) if "pointer_to_raw_data" in section else content_offset
        laid_out.append(
            {
                **section,
                "raw_bytes": raw,
                "virtual_size": virtual_size,
                "size_of_raw_data": size_of_raw_data,
                "pointer_to_raw_data": declared_pointer,
                "content_offset": content_offset,
            }
        )
        cursor = content_offset + max(len(raw), size_of_raw_data, 0)
    file_size = max(cursor, headers_end, cert_offset + cert_size, e_lfanew + 24)
    buf = bytearray(file_size)
    buf[0:2] = e_magic[:2].ljust(2, b"\x00")
    if 60 + 4 <= len(buf):
        struct.pack_into("<I", buf, 60, e_lfanew)
    if 0 <= e_lfanew <= len(buf) - 4:
        buf[e_lfanew : e_lfanew + 4] = pe_sig[:4].ljust(4, b"\x00")
    coff_offset = e_lfanew + 4
    if coff_offset + 20 <= len(buf):
        struct.pack_into(
            _COFF_FORMAT,
            buf,
            coff_offset,
            machine,
            declared_sections,
            0,
            0,
            0,
            optional_used,
            0,
        )
    packed_optional = optional if size_of_optional_header is None else optional[:optional_used].ljust(optional_used, b"\x00")
    end = optional_start + len(packed_optional)
    if optional_start >= 0 and end <= len(buf):
        buf[optional_start:end] = packed_optional
    sppdiag_offset = -1
    for index, section in enumerate(laid_out):
        header_at = section_table_start + index * 40
        name = bytes(section["name"])
        name = (name + b"\x00" * 8)[:8]
        if header_at + 40 <= len(buf):
            struct.pack_into(
                _SECTION_FORMAT,
                buf,
                header_at,
                name,
                int(section["virtual_size"]),
                0,
                int(section["size_of_raw_data"]),
                int(section["pointer_to_raw_data"]),
                0,
                0,
                0,
                0,
                int(section["characteristics"]),
            )
        content_offset = int(section["content_offset"])
        raw = bytes(section["raw_bytes"])
        if content_offset >= 0 and content_offset + len(raw) <= len(buf):
            buf[content_offset : content_offset + len(raw)] = raw
        if name == b".sppdiag" and sppdiag_offset < 0:
            sppdiag_offset = int(section["pointer_to_raw_data"])
    directory_start = optional_start + (112 if pe32plus else 96)
    info = {
        "optional_start": optional_start,
        "checksum_offset": optional_start + 64,
        "cert_dir_offset": directory_start + 32,
        "sppdiag_offset": sppdiag_offset,
        "section_table_start": section_table_start,
        "headers_end": headers_end,
    }
    data = bytes(buf[:truncate] if truncate is not None else buf)
    return data, info


def _sppdiag_section(
    *,
    payload: bytes | None = None,
    extra: bytes = b"",
    characteristics: int = VALID_CHARS,
    name: bytes = b".sppdiag",
    virtual_size: int | None = None,
    size_of_raw_data: int | None = None,
    pointer_to_raw_data: int | None = None,
    **descriptor_updates: object,
) -> dict[str, object]:
    if payload is None:
        payload = _descriptor_bytes(**descriptor_updates)
    raw = _logical_section(payload, extra=extra)
    section: dict[str, object] = {
        "name": name,
        "characteristics": characteristics,
        "raw_bytes": raw,
        "logical_size": 4 + len(payload) if virtual_size is None else virtual_size,
        "size_of_raw_data": len(raw) if size_of_raw_data is None else size_of_raw_data,
    }
    if pointer_to_raw_data is not None:
        section["pointer_to_raw_data"] = pointer_to_raw_data
    return section


def _expect(code: str, data: bytes) -> DiagBundleError:
    try:
        extract_sppdiag_descriptor(data)
    except DiagBundleError as exc:
        if exc.reason_code != code:
            raise AssertionError(f"expected {code}, got {exc.reason_code}: {exc}") from exc
        return exc
    raise AssertionError(f"expected {code}")


def _assert_pe_format_only(data: bytes) -> None:
    try:
        extract_sppdiag_descriptor(data)
    except DiagBundleError as exc:
        if exc.reason_code != CP_DIAGBUNDLE_PE_FORMAT:
            raise AssertionError(f"expected PE_FORMAT, got {exc.reason_code}: {exc}") from exc
        return
    except (struct.error, IndexError) as exc:
        raise AssertionError(f"raw {type(exc).__name__} escaped") from exc
    raise AssertionError("expected DiagBundleError")


def test_positive_pe32() -> None:
    data, _info = build_pe()
    result = extract_sppdiag_descriptor(data)
    assert result.schema == DEFAULT_SCHEMA
    assert result.input_closure_address == DEFAULT_ADDRESS


def test_missing_sppdiag() -> None:
    section = _sppdiag_section(name=b".text\x00\x00\x00")
    data, _info = build_pe(sections=[section])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_MISSING, data)


def test_duplicate_sppdiag() -> None:
    data, _info = build_pe(sections=[_sppdiag_section(), _sppdiag_section()])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_DUPLICATE, data)


def test_characteristics_missing_initialized_data() -> None:
    data, _info = build_pe(sections=[_sppdiag_section(characteristics=SCN_READ)])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS, data)


def test_characteristics_missing_mem_read() -> None:
    data, _info = build_pe(sections=[_sppdiag_section(characteristics=SCN_INITIALIZED)])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS, data)


def test_characteristics_present_code() -> None:
    data, _info = build_pe(sections=[_sppdiag_section(characteristics=VALID_CHARS | SCN_CODE)])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS, data)


def test_characteristics_present_uninitialized() -> None:
    data, _info = build_pe(sections=[_sppdiag_section(characteristics=VALID_CHARS | SCN_UNINITIALIZED)])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS, data)


def test_characteristics_present_shared() -> None:
    data, _info = build_pe(sections=[_sppdiag_section(characteristics=VALID_CHARS | SCN_SHARED)])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS, data)


def test_characteristics_present_execute() -> None:
    data, _info = build_pe(sections=[_sppdiag_section(characteristics=VALID_CHARS | SCN_EXECUTE)])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS, data)


def test_characteristics_present_write() -> None:
    data, _info = build_pe(sections=[_sppdiag_section(characteristics=VALID_CHARS | SCN_WRITE)])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_CHARACTERISTICS, data)


def test_virtual_size_mismatch() -> None:
    payload = _descriptor_bytes()
    section = _sppdiag_section(payload=payload, virtual_size=4 + len(payload) + 8)
    data, _info = build_pe(sections=[section])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, data)


def test_virtual_size_escapes_raw() -> None:
    payload = _descriptor_bytes()
    logical = 4 + len(payload)
    section = _sppdiag_section(payload=payload, virtual_size=logical, size_of_raw_data=logical - 1)
    data, _info = build_pe(sections=[section])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, data)


def test_nonzero_padding() -> None:
    data, _info = build_pe(sections=[_sppdiag_section(extra=b"\x00\x00\x01")])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, data)


def test_valid_prefix_plus_extra_data() -> None:
    data, _info = build_pe(sections=[_sppdiag_section(extra=b"TRAILER")])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, data)


def test_raw_size_less_than_virtual_size() -> None:
    payload = _descriptor_bytes()
    section = _sppdiag_section(payload=payload, size_of_raw_data=4)
    data, _info = build_pe(sections=[section])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, data)


def test_ambiguous_overlapping_sections() -> None:
    first = _sppdiag_section()
    second = {
        "name": b".data\x00\x00\x00",
        "characteristics": VALID_CHARS,
        "raw_bytes": b"XXXX",
        "logical_size": 4,
        "size_of_raw_data": 4,
        "pointer_to_raw_data": 0,
    }
    data, info = build_pe(sections=[first, second])
    second["pointer_to_raw_data"] = info["sppdiag_offset"]
    data, _info = build_pe(sections=[first, second])
    _expect(CP_DIAGBUNDLE_PE_FORMAT, data)


def test_noncanonical_descriptor_json() -> None:
    payload = _descriptor_bytes(noncanonical=True)
    data, _info = build_pe(sections=[_sppdiag_section(payload=payload)])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, data)


def test_descriptor_wrong_keys() -> None:
    extra_obj = _descriptor_object()
    extra_obj["extra"] = 1
    extra, _info = build_pe(sections=[_sppdiag_section(payload=canonical_dumps(extra_obj))])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, extra)
    missing_payload = canonical_dumps({"schema": DEFAULT_SCHEMA, "artifact_state": "diagnostic_unqualified"})
    missing, _info = build_pe(sections=[_sppdiag_section(payload=missing_payload)])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, missing)
    wrong_type = _descriptor_object()
    wrong_type["input_closure_address"] = 1
    typed, _info = build_pe(sections=[_sppdiag_section(payload=canonical_dumps(wrong_type))])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_MALFORMED, typed)


def test_coverage_checksum_field() -> None:
    _data, info = build_pe()
    section = _sppdiag_section(pointer_to_raw_data=info["checksum_offset"], size_of_raw_data=8)
    data, _info = build_pe(sections=[section])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_COVERAGE, data)


def test_coverage_certificate_directory_entry() -> None:
    _data, info = build_pe()
    section = _sppdiag_section(pointer_to_raw_data=info["cert_dir_offset"], size_of_raw_data=8)
    data, _info = build_pe(sections=[section])
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_COVERAGE, data)


def test_coverage_certificate_table_bytes() -> None:
    data, info = build_pe()
    overlapped, _info = build_pe(cert_offset=info["sppdiag_offset"], cert_size=16)
    _expect(CP_DIAGBUNDLE_DESCRIPTOR_COVERAGE, overlapped)
    del data


def test_positive_pe32plus() -> None:
    data, _info = build_pe(pe32plus=True)
    result = extract_sppdiag_descriptor(data)
    assert result.schema == DEFAULT_SCHEMA
    assert result.input_closure_address == DEFAULT_ADDRESS


def test_malformed_headers_are_pe_format() -> None:
    valid, info = build_pe()
    _assert_pe_format_only(b"XX" + valid[2:])
    rom = bytearray(valid)
    struct.pack_into("<H", rom, info["optional_start"], 0x107)
    _assert_pe_format_only(bytes(rom))
    _assert_pe_format_only(valid[:40])
    out_of_range = bytearray(valid)
    struct.pack_into("<I", out_of_range, 60, len(out_of_range) + 8)
    _assert_pe_format_only(bytes(out_of_range))
    huge_optional = bytearray(valid)
    struct.pack_into("<H", huge_optional, info["optional_start"] - 4, 50000)
    _assert_pe_format_only(bytes(huge_optional))
    bad_sig = bytearray(valid)
    bad_sig[64:68] = b"NE\x00\x00"
    _assert_pe_format_only(bytes(bad_sig))


TESTS = (
    test_positive_pe32,
    test_missing_sppdiag,
    test_duplicate_sppdiag,
    test_characteristics_missing_initialized_data,
    test_characteristics_missing_mem_read,
    test_characteristics_present_code,
    test_characteristics_present_uninitialized,
    test_characteristics_present_shared,
    test_characteristics_present_execute,
    test_characteristics_present_write,
    test_virtual_size_mismatch,
    test_virtual_size_escapes_raw,
    test_nonzero_padding,
    test_valid_prefix_plus_extra_data,
    test_raw_size_less_than_virtual_size,
    test_ambiguous_overlapping_sections,
    test_noncanonical_descriptor_json,
    test_descriptor_wrong_keys,
    test_coverage_checksum_field,
    test_coverage_certificate_directory_entry,
    test_coverage_certificate_table_bytes,
    test_positive_pe32plus,
    test_malformed_headers_are_pe_format,
)


if __name__ == "__main__":
    failed = 0
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report every case before exiting
            failed += 1
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok   {test.__name__}")
    raise SystemExit(failed)
