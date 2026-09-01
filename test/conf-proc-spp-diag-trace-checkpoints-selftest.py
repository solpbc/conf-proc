# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Frozen production contract for independent SPP trace checkpoint binding."""

import ast
import dataclasses
import hashlib
import inspect
import io
from pathlib import Path
import tracemalloc
import typing

import conf_proc_spp_diag_trace_checkpoint_vectors as vectors
from conf_proc_spp_diag_trace_chain import reduce_spp_diag_trace_chain
from conf_proc_spp_diag_trace_checkpoints import (
    CP_SPP_TRACE_CHECKPOINT_ANCHOR,
    CP_SPP_TRACE_CHECKPOINT_BINDING,
    CP_SPP_TRACE_CHECKPOINT_CAP,
    CP_SPP_TRACE_CHECKPOINT_EXPECTATION,
    CP_SPP_TRACE_CHECKPOINT_FRAME,
    CP_SPP_TRACE_CHECKPOINT_HEADER,
    CP_SPP_TRACE_CHECKPOINT_IO,
    CP_SPP_TRACE_CHECKPOINT_LENGTH,
    CP_SPP_TRACE_CHECKPOINT_RECORD,
    CP_SPP_TRACE_CHECKPOINT_SEQUENCE,
    CP_SPP_TRACE_CHECKPOINT_TYPE,
    SppDiagTraceCheckpoint,
    SppDiagTraceCheckpointBinding,
    SppDiagTraceCheckpointError,
    SppDiagTraceCheckpointExpectations,
    SppDiagTraceCheckpointInput,
    bind_spp_diag_trace_checkpoints,
)


TYPE = "CP_SPP_TRACE_CHECKPOINT_TYPE"
IO = "CP_SPP_TRACE_CHECKPOINT_IO"
LENGTH = "CP_SPP_TRACE_CHECKPOINT_LENGTH"
CAP = "CP_SPP_TRACE_CHECKPOINT_CAP"
HEADER = "CP_SPP_TRACE_CHECKPOINT_HEADER"
EXPECTATION = "CP_SPP_TRACE_CHECKPOINT_EXPECTATION"
FRAME = "CP_SPP_TRACE_CHECKPOINT_FRAME"
SEQUENCE = "CP_SPP_TRACE_CHECKPOINT_SEQUENCE"
ANCHOR = "CP_SPP_TRACE_CHECKPOINT_ANCHOR"
RECORD = "CP_SPP_TRACE_CHECKPOINT_RECORD"
BINDING = "CP_SPP_TRACE_CHECKPOINT_BINDING"


class BytesSubclass(bytes):
    pass


class ChunkReader:
    def __init__(self, data: bytes, chunk: int | None = None) -> None:
        self.data = data
        self.chunk = chunk
        self.offset = 0
        self.requests: list[int] = []

    def read(self, amount: int) -> bytes:
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


class VirtualFrameReader:
    """Constant-state source for exact frame-count and memory tests."""

    def __init__(self, frame_count: int) -> None:
        self.header = _raw()[:196]
        self.frame_count = frame_count
        self.header_offset = 0
        self.frame_index = 0
        self.prefix_next = True
        self.prefix_reads = 0
        self.body_reads = 0
        self.max_request = 0

    @property
    def logical_length(self) -> int:
        return 196 + self.frame_count * 48

    def read(self, amount: int) -> bytes:
        self.max_request = max(self.max_request, amount)
        if amount > 1088:
            raise AssertionError("oversized read request")
        if self.header_offset < len(self.header):
            result = self.header[self.header_offset : self.header_offset + amount]
            self.header_offset += len(result)
            return result
        if self.frame_index >= self.frame_count:
            return b""
        if self.prefix_next:
            assert amount == 4
            self.prefix_next = False
            self.prefix_reads += 1
            return b"\x00\x00\x00\x2c"
        assert amount == 44
        sequence = self.frame_index
        self.frame_index += 1
        self.prefix_next = True
        self.body_reads += 1
        return b"".join(
            (
                b"\x00\x01\x00\x00\x00\x00\x00\x00",
                sequence.to_bytes(8, "big"),
                bytes(24),
                b"\x00\x00\x00\x00",
            )
        )


def _raw() -> bytes:
    return bytes.fromhex(vectors.STREAM_HEX)


def _expectations() -> SppDiagTraceCheckpointExpectations:
    return SppDiagTraceCheckpointExpectations(
        source_commit=bytes.fromhex(vectors.SOURCE_COMMIT_HEX),
        challenge=bytes.fromhex(vectors.CHALLENGE_HEX),
        run_identity=bytes.fromhex(vectors.RUN_IDENTITY_HEX),
        control_plan_address=bytes.fromhex(vectors.CONTROL_PLAN_ADDRESS_HEX),
        command_line_sha256=bytes.fromhex(vectors.COMMAND_LINE_SHA256_HEX),
    )


def _inputs() -> tuple[SppDiagTraceCheckpointInput, ...]:
    return tuple(
        SppDiagTraceCheckpointInput(event_name=name, record=bytes.fromhex(record_hex))
        for name, record_hex in zip(
            vectors.CHECKPOINT_EVENT_NAMES, vectors.CHECKPOINT_RECORD_HEX
        )
    )


def _flip(data: bytes, offset: int, mask: int = 1) -> bytes:
    changed = bytearray(data)
    changed[offset] ^= mask
    return bytes(changed)


def _replace_input(
    inputs: tuple[SppDiagTraceCheckpointInput, ...],
    index: int,
    *,
    event_name: bytes | None = None,
    record: bytes | None = None,
) -> tuple[SppDiagTraceCheckpointInput, ...]:
    result = list(inputs)
    current = result[index]
    result[index] = SppDiagTraceCheckpointInput(
        event_name=current.event_name if event_name is None else event_name,
        record=current.record if record is None else record,
    )
    return tuple(result)


def _entries(raw: bytes) -> list[bytes]:
    return [
        raw[start:end]
        for start, end in zip(vectors.ENTRY_OFFSETS[:-1], vectors.ENTRY_OFFSETS[1:])
    ]


def _sequence(entries: list[bytes]) -> bytes:
    result = []
    for sequence, entry in enumerate(entries):
        if sequence == 0:
            result.append(entry)
            continue
        changed = bytearray(entry)
        changed[12:20] = (sequence - 1).to_bytes(8, "big")
        result.append(bytes(changed))
    return b"".join(result)


def _opaque_entry(sequence: int, frame_length: int) -> bytes:
    payload_length = frame_length - 44
    frame = b"".join(
        (
            b"\x99\x99\x00\x00",
            payload_length.to_bytes(4, "big"),
            sequence.to_bytes(8, "big"),
            bytes(24),
            b"\x00\x00\x00\x00",
            bytes(payload_length),
        )
    )
    assert len(frame) == frame_length
    return frame_length.to_bytes(4, "big") + frame


def _expect_error(
    reason: str,
    *,
    source=None,
    raw: bytes | None = None,
    span: int | None = None,
    inputs=None,
    expectations=None,
) -> SppDiagTraceCheckpointError:
    selected_raw = _raw() if raw is None else raw
    selected_source = io.BytesIO(selected_raw) if source is None else source
    selected_span = len(selected_raw) if span is None else span
    selected_inputs = _inputs() if inputs is None else inputs
    selected_expectations = _expectations() if expectations is None else expectations
    try:
        bind_spp_diag_trace_checkpoints(
            selected_source,
            selected_span,
            selected_inputs,
            selected_expectations,
        )
    except SppDiagTraceCheckpointError as exc:
        assert type(exc) is SppDiagTraceCheckpointError
        assert exc.reason == reason
        assert exc.args == (reason,)
        assert str(exc) == reason
        assert exc.__cause__ is None
        assert exc.__context__ is None
        assert exc.__suppress_context__ is False
        return exc
    raise AssertionError(f"expected {reason}")


def test_public_contract() -> None:
    assert (
        CP_SPP_TRACE_CHECKPOINT_TYPE,
        CP_SPP_TRACE_CHECKPOINT_IO,
        CP_SPP_TRACE_CHECKPOINT_LENGTH,
        CP_SPP_TRACE_CHECKPOINT_CAP,
        CP_SPP_TRACE_CHECKPOINT_HEADER,
        CP_SPP_TRACE_CHECKPOINT_EXPECTATION,
        CP_SPP_TRACE_CHECKPOINT_FRAME,
        CP_SPP_TRACE_CHECKPOINT_SEQUENCE,
        CP_SPP_TRACE_CHECKPOINT_ANCHOR,
        CP_SPP_TRACE_CHECKPOINT_RECORD,
        CP_SPP_TRACE_CHECKPOINT_BINDING,
    ) == (
        TYPE,
        IO,
        LENGTH,
        CAP,
        HEADER,
        EXPECTATION,
        FRAME,
        SEQUENCE,
        ANCHOR,
        RECORD,
        BINDING,
    )
    assert len({TYPE, IO, LENGTH, CAP, HEADER, EXPECTATION, FRAME, SEQUENCE, ANCHOR, RECORD, BINDING}) == 11
    assert SppDiagTraceCheckpointError.__bases__ == (ValueError,)
    assert SppDiagTraceCheckpointError.__annotations__ == {"reason": str}
    for cls, names, types in (
        (
            SppDiagTraceCheckpointExpectations,
            ("source_commit", "challenge", "run_identity", "control_plan_address", "command_line_sha256"),
            (bytes, bytes, bytes, bytes, bytes),
        ),
        (
            SppDiagTraceCheckpointInput,
            ("event_name", "record"),
            (bytes, bytes),
        ),
        (
            SppDiagTraceCheckpoint,
            ("kind", "frame_count", "stream_byte_count", "chain", "raw_denied_exec_event_count", "raw_committed_exec_event_count"),
            (str, int, int, bytes, int, int),
        ),
        (
            SppDiagTraceCheckpointBinding,
            ("status", "ready", "release", "terminal", "frame_count", "stream_byte_count", "chain"),
            (str, SppDiagTraceCheckpoint, SppDiagTraceCheckpoint, SppDiagTraceCheckpoint, int, int, bytes),
        ),
    ):
        assert dataclasses.is_dataclass(cls)
        params = cls.__dataclass_params__
        assert (params.init, params.repr, params.eq, params.order, params.unsafe_hash, params.frozen) == (True, True, True, False, False, True)
        fields = dataclasses.fields(cls)
        assert tuple(field.name for field in fields) == names
        assert tuple(field.type for field in fields) == types
        assert all(field.default is dataclasses.MISSING for field in fields)
        assert all(field.default_factory is dataclasses.MISSING for field in fields)
    signature = inspect.signature(bind_spp_diag_trace_checkpoints)
    assert tuple(signature.parameters) == ("source", "stream_byte_count", "checkpoints", "expectations")
    assert tuple(item.annotation for item in signature.parameters.values()) == (
        typing.BinaryIO,
        int,
        tuple[SppDiagTraceCheckpointInput, ...],
        SppDiagTraceCheckpointExpectations,
    )
    assert signature.return_annotation is SppDiagTraceCheckpointBinding


def test_positive() -> None:
    raw = _raw()
    assert hashlib.sha256(raw).hexdigest() == vectors.STREAM_SHA256
    for chunk in (None, 1, 3, 17, 191):
        reader = ChunkReader(raw, chunk)
        result = bind_spp_diag_trace_checkpoints(
            reader, len(raw), _inputs(), _expectations()
        )
        assert type(result) is SppDiagTraceCheckpointBinding
        assert result.status == "checkpoints_bound"
        checkpoints = (result.ready, result.release, result.terminal)
        assert tuple(item.kind for item in checkpoints) == vectors.CHECKPOINT_KINDS
        assert tuple(item.frame_count for item in checkpoints) == vectors.CHECKPOINT_FRAME_COUNTS
        assert tuple(item.stream_byte_count for item in checkpoints) == vectors.CHECKPOINT_STREAM_BYTE_COUNTS
        assert tuple(item.chain.hex() for item in checkpoints) == vectors.CHECKPOINT_CHAIN_HEX
        assert tuple(item.raw_denied_exec_event_count for item in checkpoints) == vectors.CHECKPOINT_RAW_DENIED_COUNTS
        assert tuple(item.raw_committed_exec_event_count for item in checkpoints) == vectors.CHECKPOINT_RAW_COMMITTED_COUNTS
        assert (result.frame_count, result.stream_byte_count, result.chain.hex()) == (
            7,
            618,
            vectors.CHECKPOINT_CHAIN_HEX[2],
        )
        assert reader.offset == len(raw)
        assert reader.requests[-1] == 1
    reduction = reduce_spp_diag_trace_chain(io.BytesIO(raw), len(raw))
    assert (reduction.frame_count, reduction.stream_byte_count, reduction.chain.hex()) == (
        7,
        618,
        vectors.CHECKPOINT_CHAIN_HEX[2],
    )


def test_argument_types() -> None:
    _expect_error(TYPE, span=True)
    _expect_error(TYPE, span=618.0)
    _expect_error(TYPE, inputs=list(_inputs()))
    _expect_error(TYPE, inputs=tuple(_inputs()[:2]))
    _expect_error(TYPE, inputs=tuple(_inputs()) + (_inputs()[0],))
    _expect_error(TYPE, inputs=(object(), *_inputs()[1:]))
    _expect_error(TYPE, inputs=_replace_input(_inputs(), 0, event_name=BytesSubclass(vectors.CHECKPOINT_EVENT_NAMES[0])))
    _expect_error(TYPE, inputs=_replace_input(_inputs(), 0, record=BytesSubclass(_inputs()[0].record)))
    _expect_error(TYPE, expectations=object())
    base = _expectations()
    _expect_error(
        TYPE,
        expectations=SppDiagTraceCheckpointExpectations(
            BytesSubclass(base.source_commit),
            base.challenge,
            base.run_identity,
            base.control_plan_address,
            base.command_line_sha256,
        ),
    )
    _expect_error(TYPE, source=object())
    _expect_error(TYPE, source=NonCallableReader())
    short_expectation = dataclasses.replace(base, challenge=base.challenge[:-1])
    _expect_error(TYPE, expectations=short_expectation)
    short_record = _replace_input(_inputs(), 0, record=_inputs()[0].record[:-1])
    _expect_error(LENGTH, inputs=short_record)
    _expect_error(TYPE, source=ReturnReader(bytearray()))
    _expect_error(TYPE, source=ReturnReader(BytesSubclass(b"")))
    over = OverReturnReader()
    _expect_error(TYPE, source=over)
    assert over.calls == 1


def test_io_and_span() -> None:
    _expect_error(IO, source=LookupFault())
    _expect_error(IO, source=CallFault())
    _expect_error(LENGTH, span=195)
    _expect_error(CAP, span=268435457)
    _expect_error(LENGTH, raw=_raw()[:-1])
    _expect_error(LENGTH, raw=_raw() + b"x", span=618)
    _expect_error(LENGTH, raw=_raw() + b"x")


def test_header_and_expectations() -> None:
    raw = _raw()
    for offset in (4, 12, 14, 16, 18, 20, 24, 32, 36, 184, 192):
        _expect_error(HEADER, raw=_flip(raw, offset))
    base = _expectations()
    for field in ("source_commit", "challenge", "run_identity", "control_plan_address", "command_line_sha256"):
        values = dataclasses.asdict(base)
        values[field] = _flip(values[field], 0)
        _expect_error(EXPECTATION, expectations=SppDiagTraceCheckpointExpectations(**values))


def test_framing_sequence_and_anchors() -> None:
    raw = _raw()
    entries = _entries(raw)
    _expect_error(LENGTH, raw=bytes(4) + raw[4:])
    _expect_error(LENGTH, raw=b"\x00\x00\x00\x2b" + raw[4:])
    _expect_error(LENGTH, raw=raw[:196] + bytes(4) + raw[200:])
    _expect_error(LENGTH, raw=raw[:196] + b"\x00\x00\x00\x2b" + raw[200:])
    _expect_error(CAP, raw=raw[:196] + b"\x00\x00\x04\x41" + raw[200:])
    _expect_error(LENGTH, raw=_flip(raw, vectors.ENTRY_OFFSETS[2] + 4 + 7))
    _expect_error(SEQUENCE, raw=_flip(raw, vectors.ENTRY_OFFSETS[2] + 4 + 15))
    _expect_error(FRAME, raw=_flip(raw, vectors.ENTRY_OFFSETS[3] + 4 + 23))
    _expect_error(ANCHOR, raw=_flip(raw, vectors.ENTRY_OFFSETS[3] + 4 + 51))
    _expect_error(FRAME, raw=_flip(raw, vectors.ENTRY_OFFSETS[4] + 4 + 47))
    _expect_error(FRAME, raw=_flip(raw, vectors.ENTRY_OFFSETS[7] + 4 + 41))
    _expect_error(ANCHOR, raw=_sequence(entries[:3] + entries[4:]))
    _expect_error(ANCHOR, raw=_sequence(entries[:4] + entries[5:]))
    _expect_error(ANCHOR, raw=b"".join(entries[:-1]))
    _expect_error(ANCHOR, raw=_sequence(entries[:3] + [entries[3]] + entries[3:]))
    _expect_error(ANCHOR, raw=_sequence(entries[:3] + [entries[4], entries[3]] + entries[5:]))
    _expect_error(BINDING, raw=_sequence(entries[:3] + [_opaque_entry(0, 44)] + entries[3:]))
    _expect_error(BINDING, raw=_sequence(entries[:5] + [entries[6], entries[5]] + entries[7:]))
    _expect_error(BINDING, raw=_flip(raw, vectors.ENTRY_OFFSETS[1] + 5))
    max_frame_entries = entries.copy()
    max_frame_entries[5] = _opaque_entry(4, 1088)
    _expect_error(BINDING, raw=b"".join(max_frame_entries))
    terminal = entries[-1]
    extra = bytearray(entries[1])
    extra[4 + 8 : 4 + 16] = (7).to_bytes(8, "big")
    _expect_error(LENGTH, raw=b"".join(entries + [bytes(extra)]))
    _expect_error(LENGTH, raw=b"".join(entries[:-1] + [terminal, terminal]))


def test_records() -> None:
    inputs = _inputs()
    for index in range(3):
        record = inputs[index].record
        for offset in (0, 8, 10, 12, 16, 18, 20, 22, 24, 220, 244, 248, 252):
            _expect_error(RECORD, inputs=_replace_input(inputs, index, record=_flip(record, offset)))
        _expect_error(RECORD, inputs=_replace_input(inputs, index, event_name=b"wrong"))
        swapped_name = vectors.CHECKPOINT_EVENT_NAMES[(index + 1) % 3]
        _expect_error(RECORD, inputs=_replace_input(inputs, index, event_name=swapped_name))
        for offset in (44, 76, 108, 140, 179, 187, 188, 235, 243):
            _expect_error(BINDING, inputs=_replace_input(inputs, index, record=_flip(record, offset)))


def test_frame_count_cap_and_memory() -> None:
    exact = VirtualFrameReader(524288)
    _expect_error(ANCHOR, source=exact, span=exact.logical_length)
    assert exact.prefix_reads == 524288
    assert exact.body_reads == 524288
    assert exact.max_request <= 192

    plus_one = VirtualFrameReader(524289)
    _expect_error(CAP, source=plus_one, span=plus_one.logical_length)
    assert plus_one.prefix_reads == 524289
    assert plus_one.body_reads == 524288
    assert plus_one.frame_index == 524288
    assert plus_one.prefix_next is False

    def peak(frame_count: int) -> int:
        reader = VirtualFrameReader(frame_count)
        tracemalloc.start()
        try:
            _expect_error(ANCHOR, source=reader, span=reader.logical_length)
            _, measured = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        return measured

    short_peak = peak(8)
    long_peak = peak(20000)
    assert long_peak <= short_peak + 1024 * 1024


def test_traceback_privacy() -> None:
    exc = _expect_error(FRAME, raw=_flip(_raw(), vectors.ENTRY_OFFSETS[3] + 4 + 23))
    forbidden = {
        _raw(),
        bytes.fromhex(vectors.CHALLENGE_HEX),
        bytes.fromhex(vectors.RUN_IDENTITY_HEX),
        bytes.fromhex(vectors.CONTROL_PLAN_ADDRESS_HEX),
        bytes.fromhex(vectors.COMMAND_LINE_SHA256_HEX),
        *tuple(bytes.fromhex(item) for item in vectors.CHECKPOINT_RECORD_HEX),
    }
    traceback = exc.__traceback__
    product_frames = []
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename.endswith(
            "conf_proc_spp_diag_trace_checkpoints.py"
        ):
            product_frames.append(traceback.tb_frame.f_code.co_name)
            for value in traceback.tb_frame.f_locals.values():
                if type(value) is bytes:
                    assert value not in forbidden
                    assert len(value) <= 32
                elif type(value) is bytearray:
                    assert len(value) == 0
                elif callable(value):
                    owner = getattr(value, "__self__", None)
                    if owner is not None and hasattr(owner, "getvalue"):
                        assert owner.getvalue() != _raw()
                    if owner is not None and hasattr(owner, "data"):
                        assert owner.data != _raw()
        traceback = traceback.tb_next
    assert product_frames == ["bind_spp_diag_trace_checkpoints", "_fail"]


def test_static_independence() -> None:
    production_path = Path(__file__).parents[1] / "conf_proc_spp_diag_trace_checkpoints.py"
    source = production_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"__import__", "eval", "exec", "open"}:
            raise AssertionError("production dynamic or path-opening call")
    assert imports == {"dataclasses", "hashlib", "typing"}
    forbidden = (
        "sub" + "process",
        "ct" + "ypes",
        "path" + "lib",
        "conf_proc_spp_diag_trace_chain",
        "conf_proc_spp_diag_trace_checkpoint_vectors",
        "conf_proc_spp_diag_trace_checkpoints_oracle",
        "conf_proc_spp_diag_trace.c",
        "conf_proc_spp_diag_trace.h",
    )
    assert not any(token in source for token in forbidden)
    this_source = Path(__file__).read_text(encoding="utf-8")
    oracle_name = "conf-proc-spp-diag-trace-checkpoints-" + "oracle-selftest"
    assert oracle_name not in this_source


TESTS = (
    test_public_contract,
    test_positive,
    test_argument_types,
    test_io_and_span,
    test_header_and_expectations,
    test_framing_sequence_and_anchors,
    test_records,
    test_frame_count_cap_and_memory,
    test_traceback_privacy,
    test_static_independence,
)


def main() -> None:
    for test in TESTS:
        test()
    print(f"spp diagnostic trace checkpoint production contract: ok ({len(TESTS)} tests)")


if __name__ == "__main__":
    main()
