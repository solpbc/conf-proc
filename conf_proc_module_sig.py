#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Kernel module signature trailer codec for later offline CMS verification."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from conf_proc_reasons import CP_MODULE_TRAILER, ApplianceError


MODULE_SIG_MAGIC: Final = b"~Module signature appended~\n"
PKEY_ID_PKCS7: Final = 2
_TRAILER_FORMAT: Final = ">BBBBB3sI"
_TRAILER_SIZE: Final = struct.calcsize(_TRAILER_FORMAT)


@dataclass(frozen=True)
class ModuleSignatureTrailer:
    algo: int
    hash_algo: int
    id_type: int
    signer_len: int
    key_id_len: int
    sig_len: int


def split_module_signature(
    data: bytes,
) -> tuple[bytes, bytes, bytes, bytes, ModuleSignatureTrailer]:
    """Split a module into content, signature section fields, and trailer."""

    if type(data) is not bytes or not data.endswith(MODULE_SIG_MAGIC):
        raise ApplianceError(CP_MODULE_TRAILER, "module signature magic is missing")
    if len(data) < len(MODULE_SIG_MAGIC) + _TRAILER_SIZE:
        raise ApplianceError(CP_MODULE_TRAILER, "module is too short for a signature trailer")
    trailer_start = len(data) - len(MODULE_SIG_MAGIC) - _TRAILER_SIZE
    algo, hash_algo, id_type, signer_len, key_id_len, padding, sig_len = struct.unpack(
        _TRAILER_FORMAT, data[trailer_start : trailer_start + _TRAILER_SIZE]
    )
    if padding != b"\x00\x00\x00":
        raise ApplianceError(CP_MODULE_TRAILER, "module signature trailer padding is nonzero")
    signature_start = trailer_start - sig_len
    key_id_start = signature_start - key_id_len
    signer_start = key_id_start - signer_len
    if signer_start < 0:
        raise ApplianceError(CP_MODULE_TRAILER, "module signature section is truncated")
    trailer = ModuleSignatureTrailer(algo, hash_algo, id_type, signer_len, key_id_len, sig_len)
    return (
        data[:signer_start],
        data[signer_start:key_id_start],
        data[key_id_start:signature_start],
        data[signature_start:trailer_start],
        trailer,
    )


def build_module_signature(
    module_content: bytes,
    signer_name: bytes,
    key_id: bytes,
    signature_data: bytes,
    *,
    algo: int = 0,
    hash_algo: int = 0,
    id_type: int = PKEY_ID_PKCS7,
) -> bytes:
    """Build a module-signature suffix for deterministic test fixtures."""

    fields = (module_content, signer_name, key_id, signature_data)
    if any(type(field) is not bytes for field in fields):
        raise ApplianceError(CP_MODULE_TRAILER, "module signature fields must be bytes")
    if not all(type(value) is int and 0 <= value <= 0xFF for value in (algo, hash_algo, id_type)):
        raise ApplianceError(CP_MODULE_TRAILER, "module signature algorithm fields must fit in u8")
    if len(signer_name) > 0xFF or len(key_id) > 0xFF or len(signature_data) > 0xFFFFFFFF:
        raise ApplianceError(CP_MODULE_TRAILER, "module signature field is too large")
    trailer = struct.pack(
        _TRAILER_FORMAT,
        algo,
        hash_algo,
        id_type,
        len(signer_name),
        len(key_id),
        b"\x00\x00\x00",
        len(signature_data),
    )
    return module_content + signer_name + key_id + signature_data + trailer + MODULE_SIG_MAGIC
