# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Independent canonical IMA list parse and SHA-256 PCR10 replay."""

from dataclasses import dataclass
import hashlib
import hmac
from typing import BinaryIO

from conf_proc_spp_diag_ima_reasons import (
    CP_SPP_DIAG_IMA_BUFFER,
    CP_SPP_DIAG_IMA_CAP,
    CP_SPP_DIAG_IMA_CHECKPOINT,
    CP_SPP_DIAG_IMA_DIGEST,
    CP_SPP_DIAG_IMA_IO,
    CP_SPP_DIAG_IMA_LENGTH,
    CP_SPP_DIAG_IMA_PCR,
    CP_SPP_DIAG_IMA_PRIVACY,
    CP_SPP_DIAG_IMA_REPLAY,
    CP_SPP_DIAG_IMA_TEMPLATE,
    CP_SPP_DIAG_IMA_TYPE,
    CP_SPP_DIAG_IMA_VIOLATION,
    SppDiagImaError,
)


MAX_MEASUREMENTS_BYTES = 268_435_456
MAX_ENTRIES = 524_288
MAX_TEMPLATE_NAME_BYTES = 255
MAX_TEMPLATE_DATA_BYTES = 1_048_576

_DNG_PREFIX = b"sha256:\0"
_CHECKPOINT_NAMES = (
    b"sol-spp-diag-ready-v1",
    b"sol-spp-diag-release-v1",
    b"sol-spp-diag-terminal-v1",
)
_CHECKPOINT_PREFIX = b"sol-spp-diag-"
_ZERO_DIGEST = bytes(20)


@dataclass(frozen=True)
class SppDiagImaCheckpoint:
    event_name: bytes
    record: bytes
    entry_index: int


@dataclass(frozen=True)
class SppDiagImaReplay:
    status: str
    measurement_byte_count: int
    measurements_sha256: bytes
    entry_count: int
    pcr10_entry_count: int
    final_pcr10_sha256: bytes
    checkpoints: tuple[SppDiagImaCheckpoint, SppDiagImaCheckpoint, SppDiagImaCheckpoint]


def _fail(reason_code, entry_index, byte_offset):
    raise SppDiagImaError(reason_code, entry_index, byte_offset)


def _read_exact(reader, amount: int, entry_index, byte_offset) -> bytes:
    chunks = bytearray()
    while len(chunks) < amount:
        needed = amount - len(chunks)
        failure = None
        try:
            chunk = reader(needed)
        except Exception:
            failure = CP_SPP_DIAG_IMA_IO
            chunk = b""
        if failure is not None:
            chunks.clear()
            _fail(failure, entry_index, byte_offset)
        if type(chunk) is not bytes or len(chunk) > needed:
            chunk = b""
            chunks.clear()
            _fail(CP_SPP_DIAG_IMA_TYPE, entry_index, byte_offset)
        if not chunk:
            chunks.clear()
            _fail(CP_SPP_DIAG_IMA_LENGTH, entry_index, byte_offset)
        chunks.extend(chunk)
        chunk = b""
    result = bytes(chunks)
    chunks.clear()
    return result


def _printable_ascii(name: bytes) -> bool:
    for value in name:
        if value < 0x20 or value > 0x7E:
            return False
    return True


def _parse_fields(data: bytes, count: int, entry_index, byte_offset):
    fields = []
    offset = 0
    length = len(data)
    for _ in range(count):
        if offset + 4 > length:
            _fail(CP_SPP_DIAG_IMA_TEMPLATE, entry_index, byte_offset)
        size = int.from_bytes(data[offset : offset + 4], "little")
        offset += 4
        if size > length - offset:
            _fail(CP_SPP_DIAG_IMA_TEMPLATE, entry_index, byte_offset)
        fields.append(data[offset : offset + size])
        offset += size
    if offset != length:
        _fail(CP_SPP_DIAG_IMA_TEMPLATE, entry_index, byte_offset)
    return fields


def _replay_spp_diag_ima_pcr10(
    source: BinaryIO,
    measurement_byte_count: int,
    expected_pcr10_sha256: bytes,
) -> SppDiagImaReplay:
    if type(measurement_byte_count) is not int:
        source = None
        expected_pcr10_sha256 = None
        _fail(CP_SPP_DIAG_IMA_TYPE, None, 0)
    if type(expected_pcr10_sha256) is not bytes or len(expected_pcr10_sha256) != 32:
        source = None
        expected_pcr10_sha256 = None
        _fail(CP_SPP_DIAG_IMA_TYPE, None, 0)

    failure = None
    try:
        reader = source.read
    except AttributeError:
        failure = CP_SPP_DIAG_IMA_TYPE
        reader = None
    except Exception:
        failure = CP_SPP_DIAG_IMA_IO
        reader = None
    source = None
    if failure is not None:
        _fail(failure, None, 0)
    if not callable(reader):
        reader = None
        _fail(CP_SPP_DIAG_IMA_TYPE, None, 0)
    if measurement_byte_count < 1:
        _fail(CP_SPP_DIAG_IMA_LENGTH, None, 0)
    if measurement_byte_count > MAX_MEASUREMENTS_BYTES:
        _fail(CP_SPP_DIAG_IMA_CAP, None, 0)

    hasher = hashlib.sha256()
    remaining = measurement_byte_count
    entry_count = 0
    pcr10_entry_count = 0
    pcr = bytes(32)
    seen_checkpoints = []
    next_checkpoint_index = 0

    while remaining:
        loc_index = entry_count
        loc_offset = measurement_byte_count - remaining
        if entry_count >= MAX_ENTRIES:
            _fail(CP_SPP_DIAG_IMA_CAP, loc_index, loc_offset)
        if remaining < 4:
            _fail(CP_SPP_DIAG_IMA_LENGTH, loc_index, loc_offset)

        raw_pcr = _read_exact(reader, 4, loc_index, loc_offset)
        hasher.update(raw_pcr)
        remaining -= 4
        pcr_index = int.from_bytes(raw_pcr, "little")
        raw_pcr = b""
        if pcr_index > 23:
            _fail(CP_SPP_DIAG_IMA_PCR, loc_index, loc_offset)

        if remaining < 20:
            _fail(CP_SPP_DIAG_IMA_LENGTH, loc_index, loc_offset)
        stored = _read_exact(reader, 20, loc_index, loc_offset)
        hasher.update(stored)
        remaining -= 20

        if remaining < 4:
            _fail(CP_SPP_DIAG_IMA_LENGTH, loc_index, loc_offset)
        raw_name_length = _read_exact(reader, 4, loc_index, loc_offset)
        hasher.update(raw_name_length)
        remaining -= 4
        template_name_length = int.from_bytes(raw_name_length, "little")
        raw_name_length = b""
        if template_name_length > MAX_TEMPLATE_NAME_BYTES:
            _fail(CP_SPP_DIAG_IMA_CAP, loc_index, loc_offset)
        if template_name_length > remaining:
            _fail(CP_SPP_DIAG_IMA_LENGTH, loc_index, loc_offset)
        if template_name_length < 1:
            _fail(CP_SPP_DIAG_IMA_TEMPLATE, loc_index, loc_offset)
        template_name = _read_exact(reader, template_name_length, loc_index, loc_offset)
        hasher.update(template_name)
        remaining -= template_name_length
        if b"\x00" in template_name or not _printable_ascii(template_name):
            _fail(CP_SPP_DIAG_IMA_TEMPLATE, loc_index, loc_offset)
        if template_name == b"ima":
            _fail(CP_SPP_DIAG_IMA_TEMPLATE, loc_index, loc_offset)

        if remaining < 4:
            _fail(CP_SPP_DIAG_IMA_LENGTH, loc_index, loc_offset)
        raw_data_length = _read_exact(reader, 4, loc_index, loc_offset)
        hasher.update(raw_data_length)
        remaining -= 4
        template_data_length = int.from_bytes(raw_data_length, "little")
        raw_data_length = b""
        if template_data_length > MAX_TEMPLATE_DATA_BYTES:
            _fail(CP_SPP_DIAG_IMA_CAP, loc_index, loc_offset)
        if template_data_length > remaining:
            _fail(CP_SPP_DIAG_IMA_LENGTH, loc_index, loc_offset)
        raw_template_data = _read_exact(
            reader, template_data_length, loc_index, loc_offset
        )
        hasher.update(raw_template_data)
        remaining -= template_data_length

        if hmac.compare_digest(stored, _ZERO_DIGEST):
            _fail(CP_SPP_DIAG_IMA_VIOLATION, loc_index, loc_offset)
        if not hmac.compare_digest(hashlib.sha1(raw_template_data).digest(), stored):
            _fail(CP_SPP_DIAG_IMA_DIGEST, loc_index, loc_offset)
        stored = b""
        event_digest = hashlib.sha256(raw_template_data).digest()

        is_checkpoint_candidate = False
        event_name = b""
        buf = b""
        if template_name in (b"ima-ng", b"ima-buf"):
            wanted = 2 if template_name == b"ima-ng" else 3
            fields = _parse_fields(
                raw_template_data, wanted, loc_index, loc_offset
            )
            dng = fields[0]
            nng = fields[1]
            if len(dng) != 40 or dng[:8] != _DNG_PREFIX:
                _fail(CP_SPP_DIAG_IMA_TEMPLATE, loc_index, loc_offset)
            if not nng or nng[-1] != 0 or b"\x00" in nng[:-1]:
                _fail(CP_SPP_DIAG_IMA_TEMPLATE, loc_index, loc_offset)
            event_name = nng[:-1]
            if template_name == b"ima-buf":
                buf = fields[2]
                expected_dng = _DNG_PREFIX + hashlib.sha256(buf).digest()
                if not hmac.compare_digest(dng, expected_dng):
                    _fail(CP_SPP_DIAG_IMA_BUFFER, loc_index, loc_offset)
                is_checkpoint_candidate = True
            dng = b""
            nng = b""
            fields = None
        raw_template_data = b""
        template_name = b""

        if is_checkpoint_candidate and event_name.startswith(_CHECKPOINT_PREFIX):
            if next_checkpoint_index >= 3:
                _fail(CP_SPP_DIAG_IMA_CHECKPOINT, loc_index, loc_offset)
            expected_name = _CHECKPOINT_NAMES[next_checkpoint_index]
            if (
                event_name != expected_name
                or pcr_index != 10
                or len(buf) != 256
            ):
                _fail(CP_SPP_DIAG_IMA_CHECKPOINT, loc_index, loc_offset)
            seen_checkpoints.append(
                SppDiagImaCheckpoint(
                    event_name=bytes(bytearray(event_name)),
                    record=bytes(bytearray(buf)),
                    entry_index=entry_count,
                )
            )
            next_checkpoint_index += 1
        event_name = b""
        buf = b""

        if pcr_index == 10:
            pcr = hashlib.sha256(pcr + event_digest).digest()
            pcr10_entry_count += 1
        event_digest = b""
        entry_count += 1

    failure = None
    try:
        trailing = reader(1)
    except Exception:
        failure = CP_SPP_DIAG_IMA_IO
        trailing = b""
    reader = None
    if failure is not None:
        _fail(failure, None, measurement_byte_count)
    if type(trailing) is not bytes or len(trailing) > 1:
        trailing = b""
        _fail(CP_SPP_DIAG_IMA_TYPE, None, measurement_byte_count)
    if trailing:
        trailing = b""
        _fail(CP_SPP_DIAG_IMA_LENGTH, None, measurement_byte_count)
    trailing = b""

    if len(seen_checkpoints) != 3:
        _fail(CP_SPP_DIAG_IMA_CHECKPOINT, None, measurement_byte_count)
    if not hmac.compare_digest(pcr, expected_pcr10_sha256):
        _fail(CP_SPP_DIAG_IMA_REPLAY, None, measurement_byte_count)

    return SppDiagImaReplay(
        status="ima_pcr10_replayed",
        measurement_byte_count=measurement_byte_count,
        measurements_sha256=hasher.digest(),
        entry_count=entry_count,
        pcr10_entry_count=pcr10_entry_count,
        final_pcr10_sha256=pcr,
        checkpoints=tuple(seen_checkpoints),
    )


def replay_spp_diag_ima_pcr10(
    source: BinaryIO,
    measurement_byte_count: int,
    expected_pcr10_sha256: bytes,
) -> SppDiagImaReplay:
    """Replay PCR10 while keeping sensitive worker frames private."""

    failure = None
    location = (None, 0)
    result = None
    try:
        result = _replay_spp_diag_ima_pcr10(
            source, measurement_byte_count, expected_pcr10_sha256
        )
    except SppDiagImaError as error:
        failure = error.reason_code
        location = (error.entry_index, error.byte_offset)
        error.__traceback__ = None
    except Exception as error:
        failure = CP_SPP_DIAG_IMA_PRIVACY
        location = (None, 0)
        error.__traceback__ = None
        error.__context__ = None
        error.__cause__ = None
    if failure is None:
        return result
    source = None
    measurement_byte_count = None
    expected_pcr10_sha256 = None
    result = None
    _fail(failure, location[0], location[1])
