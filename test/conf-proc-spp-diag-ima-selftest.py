# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Frozen production contract for canonical IMA/PCR10 replay."""

import ast
import dataclasses
import gc
import hashlib
import inspect
import io
from pathlib import Path
import sys
import tracemalloc
import typing

import conf_proc_spp_diag_ima as ima_mod
import conf_proc_spp_diag_ima_fixture as fixture
from conf_proc_spp_diag_ima import (
    MAX_ENTRIES,
    MAX_MEASUREMENTS_BYTES,
    MAX_TEMPLATE_DATA_BYTES,
    MAX_TEMPLATE_NAME_BYTES,
    SppDiagImaCheckpoint,
    SppDiagImaReplay,
    replay_spp_diag_ima_pcr10,
)
from conf_proc_spp_diag_ima_reasons import (
    ALL_SPP_DIAG_IMA_REASONS,
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


TYPE = CP_SPP_DIAG_IMA_TYPE
IO = CP_SPP_DIAG_IMA_IO
LENGTH = CP_SPP_DIAG_IMA_LENGTH
CAP = CP_SPP_DIAG_IMA_CAP
TEMPLATE = CP_SPP_DIAG_IMA_TEMPLATE
DIGEST = CP_SPP_DIAG_IMA_DIGEST
VIOLATION = CP_SPP_DIAG_IMA_VIOLATION
PCR = CP_SPP_DIAG_IMA_PCR
BUFFER = CP_SPP_DIAG_IMA_BUFFER
CHECKPOINT = CP_SPP_DIAG_IMA_CHECKPOINT
REPLAY = CP_SPP_DIAG_IMA_REPLAY
PRIVACY = CP_SPP_DIAG_IMA_PRIVACY

CK_NAMES = (
    b"sol-spp-diag-ready-v1",
    b"sol-spp-diag-release-v1",
    b"sol-spp-diag-terminal-v1",
)
_VIRTUAL_BODY_BYTES = 2300
_NG_DATA = (
    (40).to_bytes(4, "little")
    + b"sha256:\0"
    + bytes(32)
    + (2).to_bytes(4, "little")
    + b"n\0"
)
_UNRELATED_EVENT = b"other-critical-v1"


class BytesSubclass(bytes):
    pass


class ChunkReader:
    def __init__(self, data: bytes, chunk: int | None = None) -> None:
        self.data = data
        self.chunk = chunk
        self.offset = 0
        self.requests: list[int] = []
        self.calls = 0

    def read(self, amount: int) -> bytes:
        self.calls += 1
        self.requests.append(amount)
        if self.offset >= len(self.data):
            return b""
        take = amount if self.chunk is None else min(amount, self.chunk)
        result = self.data[self.offset : self.offset + take]
        self.offset += len(result)
        return result


class LookupFault:
    @property
    def read(self):
        raise RuntimeError("reader-secret")


class CallFault:
    def read(self, amount: int) -> bytes:
        raise RuntimeError("reader-secret")


class ReturnReader:
    def __init__(self, value) -> None:
        self.value = value
        self.calls = 0

    def read(self, amount: int):
        self.calls += 1
        return self.value


class OverReturnReader:
    def __init__(self) -> None:
        self.calls = 0

    def read(self, amount: int) -> bytes:
        self.calls += 1
        return bytes(amount + 1)


class NonCallableReader:
    read = 1


class ProbeReader:
    def __init__(self, data: bytes, probe) -> None:
        self.data = data
        self.offset = 0
        self.probe = probe
        self.calls = 0

    def read(self, amount: int):
        self.calls += 1
        if self.offset < len(self.data):
            take = min(amount, len(self.data) - self.offset)
            result = self.data[self.offset : self.offset + take]
            self.offset += take
            return result
        if callable(self.probe):
            return self.probe(amount)
        return self.probe


class RetainedChunkReader:
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self.chunks = chunks
        self.index = 0
        self.calls = 0

    def read(self, amount: int) -> bytes:
        self.calls += 1
        if self.index >= len(self.chunks):
            return b""
        chunk = self.chunks[self.index]
        self.index += 1
        return chunk


def _le32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _field(data: bytes) -> bytes:
    return _le32(len(data)) + data


def _ima_ng_data(digest32: bytes, name: bytes) -> bytes:
    return _field(b"sha256:\0" + digest32) + _field(name + b"\0")


def _ima_buf_data(buf: bytes, name: bytes) -> bytes:
    return _field(b"sha256:\0" + hashlib.sha256(buf).digest()) + _field(name + b"\0") + _field(buf)


def _entry(pcr: int, name: bytes, data: bytes, stored: bytes | None = None) -> bytes:
    digest = hashlib.sha1(data).digest() if stored is None else stored
    return _le32(pcr) + digest + _le32(len(name)) + name + _le32(len(data)) + data


def _checkpoint(name: bytes, buf: bytes | None = None, pcr: int = 10) -> bytes:
    if buf is None:
        buf = bytes(range(256))
    return _entry(pcr, b"ima-buf", _ima_buf_data(buf, name))


def _opaque(pcr: int, data: bytes = b"opaque-body") -> bytes:
    return _entry(pcr, b"opaque", data)


def _trio(extra: tuple[bytes, ...] = (), names: tuple[bytes, ...] = CK_NAMES) -> bytes:
    parts = [_checkpoint(name) for name in names]
    parts.extend(extra)
    return b"".join(parts)


def _pcr10(raw: bytes) -> bytes:
    pcr = bytes(32)
    offset = 0
    while offset < len(raw):
        pcr_index = int.from_bytes(raw[offset : offset + 4], "little")
        offset += 4
        offset += 20
        name_length = int.from_bytes(raw[offset : offset + 4], "little")
        offset += 4 + name_length
        data_length = int.from_bytes(raw[offset : offset + 4], "little")
        offset += 4
        data = raw[offset : offset + data_length]
        offset += data_length
        if pcr_index == 10:
            pcr = hashlib.sha256(pcr + hashlib.sha256(data).digest()).digest()
    return pcr


def _fields(data: bytes) -> list[bytes]:
    fields = []
    offset = 0
    while offset < len(data):
        size = int.from_bytes(data[offset : offset + 4], "little")
        offset += 4
        fields.append(data[offset : offset + size])
        offset += size
    return fields


def _split_fields(entry: bytes) -> list[bytes]:
    name_length = int.from_bytes(entry[24:28], "little")
    name = entry[28 : 28 + name_length]
    data_at = 28 + name_length
    data_length = int.from_bytes(entry[data_at : data_at + 4], "little")
    return [
        entry[0:4],
        entry[4:24],
        entry[24:28],
        name,
        entry[data_at : data_at + 4],
        entry[data_at + 4 : data_at + 4 + data_length],
    ]


def _raw() -> bytes:
    return bytes.fromhex(fixture.MEASUREMENTS_HEX)


def _expected() -> bytes:
    return bytes.fromhex(fixture.FINAL_PCR10_SHA256)


def _replay(source, span: int, expected: bytes | None = None) -> SppDiagImaReplay:
    if expected is None:
        expected = _expected()
    return replay_spp_diag_ima_pcr10(source, span, expected)


def _expect_error(
    reason: str,
    *,
    source=None,
    raw: bytes | None = None,
    span: int | None = None,
    expected: bytes | None = None,
    entry_index=None,
    byte_offset: int = 0,
) -> SppDiagImaError:
    selected_raw = _raw() if raw is None else raw
    selected_source = io.BytesIO(selected_raw) if source is None else source
    selected_span = len(selected_raw) if span is None else span
    selected_expected = _expected() if expected is None else expected
    try:
        replay_spp_diag_ima_pcr10(selected_source, selected_span, selected_expected)
    except SppDiagImaError as exc:
        assert type(exc) is SppDiagImaError
        assert exc.reason_code == reason
        assert exc.entry_index == entry_index
        assert exc.byte_offset == byte_offset
        assert exc.args == (reason,)
        assert str(exc) == reason
        assert exc.__cause__ is None
        assert exc.__context__ is None
        return exc
    raise AssertionError(f"expected {reason}")


_NG_SHA1 = hashlib.sha1(_NG_DATA).digest()
_CK_BUF = bytes(range(256))
_CK_DATA = tuple(_ima_buf_data(_CK_BUF, name) for name in CK_NAMES)
_CK_SHA1 = tuple(hashlib.sha1(item).digest() for item in _CK_DATA)


def _virtual_body(index: int) -> bytes:
    seed = index.to_bytes(8, "little")
    block = hashlib.sha256(b"spp-memory-entry-v1\0" + seed).digest()
    repeats = (_VIRTUAL_BODY_BYTES - len(seed) + len(block) - 1) // len(block)
    return (seed + block * repeats)[:_VIRTUAL_BODY_BYTES]


def _virtual_spec(index: int) -> tuple[int, bytes, bytes, bytes]:
    if index < 3:
        return 10, b"ima-buf", _CK_DATA[index], _CK_SHA1[index]
    kind = index % 4
    body = _virtual_body(index)
    if kind == 0:
        data = _ima_buf_data(body, _UNRELATED_EVENT)
        return 10, b"ima-buf", data, hashlib.sha1(data).digest()
    if kind == 1:
        return 8, b"ima-ng", _NG_DATA, _NG_SHA1
    if kind == 2:
        return 10, b"opaque", body, hashlib.sha1(body).digest()
    return 11, b"opaque", body, hashlib.sha1(body).digest()


def _virtual_pcr(entry_count: int) -> bytes:
    pcr = bytes(32)
    for index in range(entry_count):
        pcr_index, _name, data, _digest = _virtual_spec(index)
        if pcr_index == 10:
            pcr = hashlib.sha256(pcr + hashlib.sha256(data).digest()).digest()
    return pcr


def _virtual_length(entry_count: int) -> int:
    total = 0
    for index in range(entry_count):
        _pcr, name, data, _digest = _virtual_spec(index)
        total += 4 + 20 + 4 + len(name) + 4 + len(data)
    return total


class VirtualImaReader:
    """Constant-state source for entry-count, call-budget, and memory tests."""

    def __init__(self, entry_count: int) -> None:
        self.entry_count = entry_count
        self.entry_index = 0
        self.phase = 0
        self.calls = 0
        self.max_request = 0
        self._pcr = 0
        self._name = b""
        self._data = b""
        self._sha1 = b""
        if entry_count:
            self._load(0)

    def _load(self, index: int) -> None:
        self._pcr, self._name, self._data, self._sha1 = _virtual_spec(index)

    @property
    def logical_length(self) -> int:
        return _virtual_length(self.entry_count)

    def read(self, amount: int) -> bytes:
        self.calls += 1
        self.max_request = max(self.max_request, amount)
        if amount > MAX_TEMPLATE_DATA_BYTES:
            raise AssertionError("oversized read request")
        if self.entry_index >= self.entry_count:
            return b""
        if self.phase == 0:
            assert amount == 4
            self.phase = 1
            return _le32(self._pcr)
        if self.phase == 1:
            assert amount == 20
            self.phase = 2
            return self._sha1
        if self.phase == 2:
            assert amount == 4
            self.phase = 3
            return _le32(len(self._name))
        if self.phase == 3:
            assert amount == len(self._name)
            self.phase = 4
            return self._name
        if self.phase == 4:
            assert amount == 4
            self.phase = 5
            return _le32(len(self._data))
        assert amount == len(self._data)
        result = self._data
        self.entry_index += 1
        self.phase = 0
        if self.entry_index < self.entry_count:
            self._load(self.entry_index)
        return result


class TinyImaReader:
    """Minimum valid opaque entries for the entry-count cap."""

    def __init__(self, entry_count: int) -> None:
        self.entry_count = entry_count
        self.entry_index = 0
        self.phase = 0
        self.calls = 0
        self._digest = hashlib.sha1(b"z").digest()

    @property
    def logical_length(self) -> int:
        return self.entry_count * 34

    def read(self, amount: int) -> bytes:
        self.calls += 1
        if self.entry_index >= self.entry_count:
            return b""
        if self.phase == 0:
            self.phase = 1
            return b"\x00\x00\x00\x00"
        if self.phase == 1:
            self.phase = 2
            return self._digest
        if self.phase == 2:
            self.phase = 3
            return b"\x01\x00\x00\x00"
        if self.phase == 3:
            self.phase = 4
            return b"x"
        if self.phase == 4:
            self.phase = 5
            return b"\x01\x00\x00\x00"
        self.entry_index += 1
        self.phase = 0
        return b"z"


def test_public_contract() -> None:
    assert (
        MAX_MEASUREMENTS_BYTES,
        MAX_ENTRIES,
        MAX_TEMPLATE_NAME_BYTES,
        MAX_TEMPLATE_DATA_BYTES,
    ) == (268_435_456, 524_288, 255, 1_048_576)
    assert SppDiagImaError.__bases__ == (RuntimeError,)
    assert len(ALL_SPP_DIAG_IMA_REASONS) == 12
    for cls, names, types in (
        (
            SppDiagImaCheckpoint,
            ("event_name", "record", "entry_index"),
            (bytes, bytes, int),
        ),
        (
            SppDiagImaReplay,
            (
                "status",
                "measurement_byte_count",
                "measurements_sha256",
                "entry_count",
                "pcr10_entry_count",
                "final_pcr10_sha256",
                "checkpoints",
            ),
            (
                str,
                int,
                bytes,
                int,
                int,
                bytes,
                tuple[SppDiagImaCheckpoint, SppDiagImaCheckpoint, SppDiagImaCheckpoint],
            ),
        ),
    ):
        assert dataclasses.is_dataclass(cls)
        params = cls.__dataclass_params__
        assert (params.init, params.repr, params.eq, params.frozen) == (True, True, True, True)
        fields = dataclasses.fields(cls)
        assert tuple(field.name for field in fields) == names
        assert tuple(field.type for field in fields) == types
    signature = inspect.signature(replay_spp_diag_ima_pcr10)
    assert tuple(signature.parameters) == (
        "source",
        "measurement_byte_count",
        "expected_pcr10_sha256",
    )
    assert tuple(item.annotation for item in signature.parameters.values()) == (
        typing.BinaryIO,
        int,
        bytes,
    )
    assert signature.return_annotation is SppDiagImaReplay
    try:
        SppDiagImaError("nope", None, 0)
    except ValueError as exc:
        assert str(exc) == "unknown SPP diagnostic IMA reason"
    else:
        raise AssertionError("unknown reason")
    try:
        SppDiagImaError(TYPE, True, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("bool entry_index")
    try:
        SppDiagImaError(TYPE, None, True)
    except ValueError:
        pass
    else:
        raise AssertionError("bool byte_offset")


def _assert_fixture_result(result: SppDiagImaReplay) -> None:
    assert type(result) is SppDiagImaReplay
    assert result.status == "ima_pcr10_replayed"
    assert result.measurement_byte_count == 1444
    assert result.measurements_sha256.hex() == fixture.MEASUREMENTS_SHA256
    assert result.entry_count == 6
    assert result.pcr10_entry_count == 5
    assert result.final_pcr10_sha256.hex() == fixture.FINAL_PCR10_SHA256
    assert tuple(item.event_name for item in result.checkpoints) == fixture.CHECKPOINT_EVENT_NAMES
    assert tuple(item.record.hex() for item in result.checkpoints) == fixture.CHECKPOINT_RECORD_HEX
    assert tuple(item.entry_index for item in result.checkpoints) == (1, 3, 5)


def test_positive_fixture() -> None:
    raw = _raw()
    for chunk in (None, 1, 3, 17, 191):
        reader = ChunkReader(raw, chunk)
        result = _replay(reader, len(raw))
        _assert_fixture_result(result)
        assert reader.offset == len(raw)
        assert reader.requests[-1] == 1
        if chunk is None:
            assert reader.calls <= 6 * 6 + 1
    _assert_fixture_result(_replay(io.BytesIO(raw), len(raw)))


def test_pcr8_mutation() -> None:
    raw = _raw()
    start, end = fixture.ENTRY_OFFSETS[4], fixture.ENTRY_OFFSETS[5]
    entry = raw[start:end]
    data = entry[38:]
    fields = _fields(data)
    new_data = _ima_ng_data(fields[0][8:], b"pcr8-changed")
    new_entry = _entry(8, b"ima-ng", new_data)
    mutated = raw[:start] + new_entry + raw[end:]
    result = _replay(io.BytesIO(mutated), len(mutated))
    assert result.final_pcr10_sha256.hex() == fixture.FINAL_PCR10_SHA256
    assert result.measurements_sha256.hex() != fixture.MEASUREMENTS_SHA256
    assert result.pcr10_entry_count == 5


def test_opaque_pcr10_mutation() -> None:
    raw = _raw()
    start, end = fixture.ENTRY_OFFSETS[2], fixture.ENTRY_OFFSETS[3]
    entry = raw[start:end]
    name_length = int.from_bytes(entry[24:28], "little")
    data_at = 28 + name_length
    data = entry[data_at + 4 :]
    fields = _fields(data)
    new_buf = b"other-critical-state-v2"
    new_data = _ima_buf_data(new_buf, fields[1][:-1])
    new_entry = _entry(10, b"ima-buf", new_data)
    mutated = raw[:start] + new_entry + raw[end:]
    new_pcr = _pcr10(mutated)
    assert new_pcr.hex() != fixture.FINAL_PCR10_SHA256
    result = _replay(io.BytesIO(mutated), len(mutated), new_pcr)
    assert result.final_pcr10_sha256 == new_pcr
    assert result.measurements_sha256.hex() != fixture.MEASUREMENTS_SHA256
    _expect_error(
        REPLAY,
        raw=mutated,
        expected=_expected(),
        entry_index=None,
        byte_offset=len(mutated),
    )


def test_outer_grammar() -> None:
    raw = _raw()
    prefixes = (0, 3, 4, 23, 24, 27, 28, 33, 34, 37, 38, 100, 101)
    for span in prefixes:
        if span == 0:
            _expect_error(LENGTH, raw=raw[:1], span=0, entry_index=None, byte_offset=0)
            continue
        if span < 101:
            _expect_error(LENGTH, raw=raw[:span], span=span, entry_index=0, byte_offset=0)
            _expect_error(LENGTH, raw=raw, span=span, entry_index=0, byte_offset=0)
            continue
        _expect_error(CHECKPOINT, raw=raw[:span], span=span, entry_index=None, byte_offset=span)
        _expect_error(LENGTH, raw=raw, span=span, entry_index=None, byte_offset=span)
    _expect_error(LENGTH, raw=raw[:-1], entry_index=5, byte_offset=1072)
    _expect_error(LENGTH, raw=raw + b"x", span=1444, entry_index=None, byte_offset=1444)
    _expect_error(LENGTH, raw=raw + b"x", entry_index=6, byte_offset=1444)
    swapped_pcr = b"\x00\x00\x00\x0a" + raw[4:]
    reader = ChunkReader(swapped_pcr)
    _expect_error(PCR, source=reader, raw=swapped_pcr, entry_index=0, byte_offset=0)
    assert reader.calls == 1
    swapped_name = raw[:24] + b"\x00\x00\x00\x06" + raw[28:]
    reader = ChunkReader(swapped_name)
    _expect_error(CAP, source=reader, raw=swapped_name, entry_index=0, byte_offset=0)
    assert reader.calls == 3
    _expect_error(CAP, span=MAX_MEASUREMENTS_BYTES + 1, entry_index=None, byte_offset=0)
    _expect_error(TYPE, span=True, entry_index=None, byte_offset=0)
    zero_name = _entry(10, b"x", b"body")
    zero_name = zero_name[:24] + _le32(0) + zero_name[28:]
    _expect_error(TEMPLATE, raw=zero_name, span=len(zero_name), expected=bytes(32), entry_index=0, byte_offset=0)
    over_name = _le32(10) + bytes(20) + _le32(256) + b"x" * 10
    _expect_error(CAP, raw=over_name, span=len(over_name) + 100, expected=bytes(32), entry_index=0, byte_offset=0)
    nul_name = _entry(10, b"im\x00a", b"body")
    _expect_error(TEMPLATE, raw=nul_name, expected=bytes(32), entry_index=0, byte_offset=0)
    bad_ascii = _entry(10, b"im\x01a", b"body")
    _expect_error(TEMPLATE, raw=bad_ascii, expected=bytes(32), entry_index=0, byte_offset=0)
    legacy = _entry(10, b"ima", b"body")
    _expect_error(TEMPLATE, raw=legacy, expected=bytes(32), entry_index=0, byte_offset=0)
    empty_data = _trio(extra=(_opaque(0, b""),))
    result = _replay(io.BytesIO(empty_data), len(empty_data), _pcr10(empty_data))
    assert result.entry_count == 4
    over_data = _le32(10) + bytes(20) + _le32(1) + b"x" + _le32(MAX_TEMPLATE_DATA_BYTES + 1)
    _expect_error(
        CAP,
        raw=over_data,
        span=len(over_data) + MAX_TEMPLATE_DATA_BYTES + 1,
        expected=bytes(32),
        entry_index=0,
        byte_offset=0,
    )
    exact_name = _trio(extra=(_entry(0, b"A" * MAX_TEMPLATE_NAME_BYTES, b"z"),))
    result = _replay(io.BytesIO(exact_name), len(exact_name), _pcr10(exact_name))
    assert result.entry_count == 4
    exact_data = _trio(extra=(_opaque(0, bytes(MAX_TEMPLATE_DATA_BYTES)),))
    result = _replay(io.BytesIO(exact_data), len(exact_data), _pcr10(exact_data))
    assert result.entry_count == 4
    for pcr in (0, 9, 10, 23):
        built = _trio(extra=(_opaque(pcr),))
        result = _replay(io.BytesIO(built), len(built), _pcr10(built))
        assert result.entry_count == 4
        assert result.pcr10_entry_count == (4 if pcr == 10 else 3)
    bad_pcr = _le32(24) + raw[4:]
    _expect_error(PCR, raw=bad_pcr, entry_index=0, byte_offset=0)
    tiny = TinyImaReader(MAX_ENTRIES + 1)
    _expect_error(
        CAP,
        source=tiny,
        raw=b"",
        span=tiny.logical_length,
        expected=bytes(32),
        entry_index=MAX_ENTRIES,
        byte_offset=MAX_ENTRIES * 34,
    )
    assert tiny.entry_index == MAX_ENTRIES
    tiny_exact = TinyImaReader(MAX_ENTRIES)
    _expect_error(
        CHECKPOINT,
        source=tiny_exact,
        raw=b"",
        span=tiny_exact.logical_length,
        expected=bytes(32),
        entry_index=None,
        byte_offset=tiny_exact.logical_length,
    )
    assert tiny_exact.entry_index == MAX_ENTRIES


def test_digest_violation_precedence() -> None:
    raw = _raw()
    for index in range(6):
        start = fixture.ENTRY_OFFSETS[index]
        flipped = bytearray(raw)
        flipped[start + 4] ^= 1
        _expect_error(DIGEST, raw=bytes(flipped), entry_index=index, byte_offset=start)
        name_length = int.from_bytes(raw[start + 24 : start + 28], "little")
        data_at = start + 28 + name_length + 4
        flipped = bytearray(raw)
        flipped[data_at] ^= 1
        _expect_error(DIGEST, raw=bytes(flipped), entry_index=index, byte_offset=start)
        zeroed = bytearray(raw)
        zeroed[start + 4 : start + 24] = bytes(20)
        _expect_error(VIOLATION, raw=bytes(zeroed), entry_index=index, byte_offset=start)
    malformed = b"not-a-template"
    both = _entry(10, b"ima-ng", malformed, stored=bytes(20))
    _expect_error(VIOLATION, raw=both, expected=bytes(32), entry_index=0, byte_offset=0)
    digest_and_shape = _entry(10, b"ima-ng", malformed, stored=bytes([1]) * 20)
    _expect_error(DIGEST, raw=digest_and_shape, expected=bytes(32), entry_index=0, byte_offset=0)
    matching_bad = _entry(10, b"ima-ng", malformed)
    _expect_error(TEMPLATE, raw=matching_bad, expected=bytes(32), entry_index=0, byte_offset=0)


def test_pcr_replay() -> None:
    raw = _raw()
    pcr = bytes(32)
    steps = []
    offset = 0
    index = 0
    while offset < len(raw):
        start = offset
        pcr_index = int.from_bytes(raw[offset : offset + 4], "little")
        offset += 24
        name_length = int.from_bytes(raw[offset : offset + 4], "little")
        offset += 4 + name_length
        data_length = int.from_bytes(raw[offset : offset + 4], "little")
        offset += 4
        data = raw[offset : offset + data_length]
        offset += data_length
        event = hashlib.sha256(data).digest()
        if pcr_index == 10:
            pcr = hashlib.sha256(pcr + event).digest()
            steps.append((index, event.hex(), pcr.hex()))
        else:
            assert index == 4 and pcr_index == 8
        index += 1
    assert tuple(item[2] for item in steps) == tuple(item[2] for item in fixture.PCR10_STEPS)
    assert pcr.hex() == fixture.FINAL_PCR10_SHA256
    to_pcr8 = b"\x08\x00\x00\x00" + raw[4:]
    new_pcr = _pcr10(to_pcr8)
    assert new_pcr != _expected()
    result = _replay(io.BytesIO(to_pcr8), len(to_pcr8), new_pcr)
    assert result.pcr10_entry_count == 4
    to_pcr10 = raw[:973] + b"\x0a\x00\x00\x00" + raw[977:]
    new_pcr = _pcr10(to_pcr10)
    result = _replay(io.BytesIO(to_pcr10), len(to_pcr10), new_pcr)
    assert result.pcr10_entry_count == 6
    omitted = raw[: fixture.ENTRY_OFFSETS[2]] + raw[fixture.ENTRY_OFFSETS[3] :]
    new_pcr = _pcr10(omitted)
    result = _replay(io.BytesIO(omitted), len(omitted), new_pcr)
    assert result.entry_count == 5
    duplicated = raw[: fixture.ENTRY_OFFSETS[3]] + raw[fixture.ENTRY_OFFSETS[2] : fixture.ENTRY_OFFSETS[3]] + raw[fixture.ENTRY_OFFSETS[3] :]
    new_pcr = _pcr10(duplicated)
    result = _replay(io.BytesIO(duplicated), len(duplicated), new_pcr)
    assert result.entry_count == 7
    _expect_error(REPLAY, expected=bytes(32), entry_index=None, byte_offset=1444)
    swapped = _trio(names=(CK_NAMES[1], CK_NAMES[0], CK_NAMES[2]))
    _expect_error(CHECKPOINT, raw=swapped, expected=_pcr10(swapped), entry_index=0, byte_offset=0)


def test_known_templates_and_checkpoints() -> None:
    def fail_first(data: bytes, reason: str) -> None:
        _expect_error(reason, raw=_entry(10, b"ima-ng", data), expected=bytes(32), entry_index=0, byte_offset=0)

    fail_first(_field(b"sha256:\0" + bytes(32)), TEMPLATE)
    fail_first(_ima_ng_data(bytes(32), b"n") + b"x", TEMPLATE)
    fail_first(_field(b"sha1:\0" + bytes(32)) + _field(b"n\0"), TEMPLATE)
    fail_first(_field(b"sha256:\0" + bytes(31)) + _field(b"n\0"), TEMPLATE)
    fail_first(_field(b"sha256:\0" + bytes(32)) + _field(b"n"), TEMPLATE)
    fail_first(_field(b"sha256:\0" + bytes(32)) + _field(b"n\x00x\0"), TEMPLATE)
    fail_first(_ima_buf_data(b"buf", b"n"), TEMPLATE)

    def fail_buf(data: bytes, reason: str) -> None:
        _expect_error(reason, raw=_entry(10, b"ima-buf", data), expected=bytes(32), entry_index=0, byte_offset=0)

    fail_buf(_ima_ng_data(bytes(32), b"n"), TEMPLATE)
    fail_buf(_ima_buf_data(b"buf", b"n") + b"x", TEMPLATE)
    bad_rel = _field(b"sha256:\0" + bytes(32)) + _field(b"n\0") + _field(b"buf")
    fail_buf(bad_rel, BUFFER)
    fail_buf(_field(b"sha256:\0" + bytes(32)) + _field(b"n") + _field(b"buf"), TEMPLATE)
    fail_buf(_field(b"sha256:\0" + bytes(32)) + _field(b"n\x00x\0") + _field(b"buf"), TEMPLATE)

    _expect_error(
        CHECKPOINT,
        raw=_checkpoint(CK_NAMES[0], pcr=8) + _checkpoint(CK_NAMES[1]) + _checkpoint(CK_NAMES[2]),
        expected=bytes(32),
        entry_index=0,
        byte_offset=0,
    )
    _expect_error(
        CHECKPOINT,
        raw=_checkpoint(CK_NAMES[0], buf=bytes(255)) + _checkpoint(CK_NAMES[1]) + _checkpoint(CK_NAMES[2]),
        expected=bytes(32),
        entry_index=0,
        byte_offset=0,
    )
    _expect_error(
        CHECKPOINT,
        raw=_checkpoint(CK_NAMES[0], buf=bytes(257)) + _checkpoint(CK_NAMES[1]) + _checkpoint(CK_NAMES[2]),
        expected=bytes(32),
        entry_index=0,
        byte_offset=0,
    )
    _expect_error(
        CHECKPOINT,
        raw=_trio(names=(CK_NAMES[0], CK_NAMES[0], CK_NAMES[2])),
        expected=bytes(32),
        entry_index=1,
        byte_offset=len(_checkpoint(CK_NAMES[0])),
    )
    _expect_error(
        CHECKPOINT,
        raw=_checkpoint(CK_NAMES[0]) + _checkpoint(CK_NAMES[1]),
        expected=bytes(32),
        entry_index=None,
        byte_offset=len(_checkpoint(CK_NAMES[0]) + _checkpoint(CK_NAMES[1])),
    )
    from itertools import permutations

    identity = CK_NAMES
    for names in permutations(CK_NAMES):
        built = _trio(names=names)
        if names == identity:
            result = _replay(io.BytesIO(built), len(built), _pcr10(built))
            assert tuple(item.event_name for item in result.checkpoints) == CK_NAMES
            assert tuple(item.entry_index for item in result.checkpoints) == (0, 1, 2)
        else:
            mismatch = next(
                index for index, name in enumerate(names) if name != identity[index]
            )
            offset = 0
            for index in range(mismatch):
                offset += len(_checkpoint(names[index]))
            _expect_error(
                CHECKPOINT,
                raw=built,
                expected=_pcr10(built),
                entry_index=mismatch,
                byte_offset=offset,
            )
    _expect_error(
        CHECKPOINT,
        raw=_trio(names=(b"sol-spp-diag-ready-v2", CK_NAMES[1], CK_NAMES[2])),
        expected=bytes(32),
        entry_index=0,
        byte_offset=0,
    )
    _expect_error(
        CHECKPOINT,
        raw=_trio(names=(b"sol-spp-diag-readyv1", CK_NAMES[1], CK_NAMES[2])),
        expected=bytes(32),
        entry_index=0,
        byte_offset=0,
    )
    unrelated = _entry(10, b"ima-buf", _ima_buf_data(b"state", b"other-critical-v1"))
    for extra in (
        (unrelated, _checkpoint(CK_NAMES[0]), _checkpoint(CK_NAMES[1]), _checkpoint(CK_NAMES[2])),
        (_checkpoint(CK_NAMES[0]), unrelated, _checkpoint(CK_NAMES[1]), _checkpoint(CK_NAMES[2])),
        (_checkpoint(CK_NAMES[0]), _checkpoint(CK_NAMES[1]), _checkpoint(CK_NAMES[2]), unrelated),
    ):
        built = b"".join(extra)
        result = _replay(io.BytesIO(built), len(built), _pcr10(built))
        assert result.entry_count == 4
        assert tuple(item.event_name for item in result.checkpoints) == CK_NAMES


def test_type_io_eof() -> None:
    raw = _raw()
    _expect_error(TYPE, span=True, entry_index=None, byte_offset=0)
    _expect_error(TYPE, expected=BytesSubclass(_expected()), entry_index=None, byte_offset=0)
    _expect_error(TYPE, expected=_expected()[:-1], entry_index=None, byte_offset=0)
    _expect_error(TYPE, source=object(), entry_index=None, byte_offset=0)
    _expect_error(TYPE, source=NonCallableReader(), entry_index=None, byte_offset=0)
    _expect_error(IO, source=LookupFault(), entry_index=None, byte_offset=0)
    _expect_error(IO, source=CallFault(), entry_index=0, byte_offset=0)
    _expect_error(TYPE, source=ReturnReader(bytearray()), raw=raw, entry_index=0, byte_offset=0)
    _expect_error(TYPE, source=ReturnReader(BytesSubclass(b"\x00" * 4)), raw=raw, entry_index=0, byte_offset=0)
    over = OverReturnReader()
    _expect_error(TYPE, source=over, raw=raw, entry_index=0, byte_offset=0)
    assert over.calls == 1
    _replay(ProbeReader(raw, b""), len(raw))
    _expect_error(
        LENGTH,
        source=ProbeReader(raw, b"x"),
        raw=raw,
        span=len(raw),
        entry_index=None,
        byte_offset=1444,
    )
    _expect_error(
        TYPE,
        source=ProbeReader(raw, bytearray(b"x")),
        raw=raw,
        span=len(raw),
        entry_index=None,
        byte_offset=1444,
    )
    _expect_error(
        TYPE,
        source=ProbeReader(raw, b"xy"),
        raw=raw,
        span=len(raw),
        entry_index=None,
        byte_offset=1444,
    )

    def boom(_amount: int):
        raise RuntimeError("probe-secret")

    _expect_error(
        IO,
        source=ProbeReader(raw, boom),
        raw=raw,
        span=len(raw),
        entry_index=None,
        byte_offset=1444,
    )


def test_traceback_privacy() -> None:
    secret = bytes.fromhex("aa" * 32)
    raw = _raw()
    flipped = bytearray(raw)
    flipped[fixture.ENTRY_OFFSETS[0] + 4] ^= 1
    exc = _expect_error(DIGEST, raw=bytes(flipped), entry_index=0, byte_offset=0)
    assert secret not in exc.args
    assert secret not in tuple(exc.__dict__.values())
    traceback = exc.__traceback__
    product_frames = []
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename.endswith("conf_proc_spp_diag_ima.py"):
            product_frames.append(traceback.tb_frame.f_code.co_name)
            for value in traceback.tb_frame.f_locals.values():
                if type(value) is bytes:
                    assert value not in {raw, secret, _expected()}
                    assert len(value) <= 32
                elif type(value) is bytearray:
                    assert len(value) == 0
        traceback = traceback.tb_next
    assert product_frames == ["replay_spp_diag_ima_pcr10", "_fail"]

    count_secret = "count-secret-7f3d"
    exc = _expect_error(TYPE, span=count_secret, entry_index=None, byte_offset=0)
    traceback = exc.__traceback__
    product_frames = []
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename.endswith("conf_proc_spp_diag_ima.py"):
            product_frames.append(traceback.tb_frame.f_code.co_name)
            assert count_secret not in traceback.tb_frame.f_locals.values()
            for value in traceback.tb_frame.f_locals.values():
                if type(value) is str:
                    assert count_secret not in value
        traceback = traceback.tb_next
    assert product_frames == ["replay_spp_diag_ima_pcr10", "_fail"]


def test_privacy_unexpected_exception() -> None:
    original = ima_mod.hashlib.sha256

    def boom(*_args, **_kwargs):
        raise RuntimeError("internal-secret")

    ima_mod.hashlib.sha256 = boom
    try:
        exc = _expect_error(PRIVACY, entry_index=None, byte_offset=0)
    finally:
        ima_mod.hashlib.sha256 = original
    assert "internal-secret" not in str(exc)
    assert "internal-secret" not in exc.args
    assert "internal-secret" not in tuple(exc.__dict__.values())
    traceback = exc.__traceback__
    product_frames = []
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename.endswith("conf_proc_spp_diag_ima.py"):
            product_frames.append(traceback.tb_frame.f_code.co_name)
            for value in traceback.tb_frame.f_locals.values():
                if type(value) is str:
                    assert "internal-secret" not in value
                elif type(value) is bytes:
                    assert len(value) <= 32
                elif type(value) is bytearray:
                    assert len(value) == 0
        traceback = traceback.tb_next
    assert product_frames == ["replay_spp_diag_ima_pcr10", "_fail"]


def test_entry_cap_and_memory() -> None:
    raw = _raw()
    control = ChunkReader(raw)
    tracemalloc.start()
    try:
        _replay(control, len(raw))
        _, fixture_peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert control.calls <= 6 * 6 + 1
    assert fixture_peak < 8 * 1024 * 1024

    def peak(entry_count: int) -> int:
        reader = VirtualImaReader(entry_count)
        expected = _virtual_pcr(entry_count)
        tracemalloc.start()
        try:
            result = _replay(reader, reader.logical_length, expected)
            _, measured = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert result.entry_count == entry_count
        assert reader.calls <= 6 * entry_count + 1
        assert reader.max_request <= MAX_TEMPLATE_DATA_BYTES
        return measured

    short_peak = peak(8)
    assert _virtual_spec(6)[2] != _virtual_spec(10)[2]
    long_reader = VirtualImaReader(20000)
    assert long_reader.logical_length >= 32 * 1024 * 1024
    long_peak = peak(20000)
    assert long_peak < 8 * 1024 * 1024
    assert long_peak <= short_peak + 1024 * 1024


def test_refcount() -> None:
    bufs = (
        bytes(range(256)),
        bytes((index + 3) % 256 for index in range(256)),
        bytes((index + 7) % 256 for index in range(256)),
    )
    names = list(CK_NAMES)
    entries = [_checkpoint(name, buf) for name, buf in zip(names, bufs)]
    chunks = []
    for entry in entries:
        chunks.extend(_split_fields(entry))
    chunk_tuple = tuple(chunks)
    raw = b"".join(entries)
    expected = _pcr10(raw)

    def snapshot() -> list[int]:
        gc.collect()
        return [sys.getrefcount(chunk) for chunk in chunk_tuple]

    reader = RetainedChunkReader(chunk_tuple)
    before = snapshot()
    result = _replay(reader, len(raw), expected)
    after = snapshot()
    assert after == before
    for index, item in enumerate(result.checkpoints):
        assert item.event_name is not names[index]
        assert item.record is not bufs[index]
        for chunk in chunk_tuple:
            assert item.record is not chunk
            assert item.event_name is not chunk

    flipped = list(chunk_tuple)
    damaged = bytearray(flipped[5])
    damaged[0] ^= 1
    flipped[5] = bytes(damaged)
    fail_chunks = tuple(flipped)
    fail_reader = RetainedChunkReader(fail_chunks)
    gc.collect()
    before = [sys.getrefcount(chunk) for chunk in fail_chunks]
    _expect_error(
        DIGEST,
        source=fail_reader,
        raw=raw,
        span=len(raw),
        expected=expected,
        entry_index=0,
        byte_offset=0,
    )
    gc.collect()
    after = [sys.getrefcount(chunk) for chunk in fail_chunks]
    assert after == before


def test_static_independence() -> None:
    production_path = Path(__file__).parents[1] / "conf_proc_spp_diag_ima.py"
    source = production_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"__import__", "eval", "exec", "open"}
        ):
            raise AssertionError("production dynamic or path-opening call")
    assert imports == {
        "dataclasses",
        "hashlib",
        "hmac",
        "typing",
        "conf_proc_spp_diag_ima_reasons",
    }
    forbidden = (
        "sub" + "process",
        "path" + "lib",
        "soc" + "ket",
        "conf_proc_spp_diag_ima_fixture",
        "conf_proc_spp_diag_trace_chain",
        "conf_proc_spp_diag_trace_checkpoints",
        "conf_proc_spp_diag_trace_semantics",
        "conf_proc_spp_diag_trace.c",
        "conf_proc_spp_diag_trace.h",
    )
    assert not any(token in source for token in forbidden)
    this_source = Path(__file__).read_text(encoding="utf-8")
    oracle_name = "conf-proc-spp-diag-ima-" + "oracle-selftest"
    assert oracle_name not in this_source


TESTS = (
    test_public_contract,
    test_positive_fixture,
    test_pcr8_mutation,
    test_opaque_pcr10_mutation,
    test_outer_grammar,
    test_digest_violation_precedence,
    test_pcr_replay,
    test_known_templates_and_checkpoints,
    test_type_io_eof,
    test_traceback_privacy,
    test_privacy_unexpected_exception,
    test_entry_cap_and_memory,
    test_refcount,
    test_static_independence,
)


def main() -> None:
    for test in TESTS:
        test()
    print(f"spp diagnostic canonical IMA/PCR10 production contract: ok ({len(TESTS)} tests)")


if __name__ == "__main__":
    main()
