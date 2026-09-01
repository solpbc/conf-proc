# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Frozen contract tests for independent SPP trace-chain reduction."""

import ast
import dataclasses
import gc
import hashlib
import inspect
from pathlib import Path
import tracemalloc
import typing

import conf_proc_spp_diag_trace_chain_vectors as vectors
from conf_proc_spp_diag_trace_chain import (
    CP_SPP_TRACE_CHAIN_CAP,
    CP_SPP_TRACE_CHAIN_IO,
    CP_SPP_TRACE_CHAIN_LENGTH,
    CP_SPP_TRACE_CHAIN_TYPE,
    SppDiagTraceChainReduction,
    SppDiagTraceChainError,
    reduce_spp_diag_trace_chain,
)


HEADER_DOMAIN = b"sol-spp-diag-trace-header/v1"
FRAME_DOMAIN = b"sol-spp-diag-trace-frame/v1"
HEADER_ENTRY_SIZE = 196
MAX_STREAM_BYTES = 268435456
MAX_FRAMES = 524288
TYPE_REASON = "CP_SPP_TRACE_CHAIN_TYPE"
CAP_REASON = "CP_SPP_TRACE_CHAIN_CAP"
LENGTH_REASON = "CP_SPP_TRACE_CHAIN_LENGTH"
IO_REASON = "CP_SPP_TRACE_CHAIN_IO"


class ChunkReader:
    def __init__(
        self,
        data: bytes,
        chunk: int | None = None,
        declared_length: int | None = None,
    ) -> None:
        self.data = data
        self.chunk = chunk
        self.declared_length = declared_length
        self.offset = 0
        self.requests: list[int] = []

    def read(self, amount: int) -> bytes:
        if self.declared_length is not None:
            remaining = self.declared_length - self.offset
            if amount > remaining:
                raise AssertionError(f"request {amount} exceeds remaining {remaining}")
        self.requests.append(amount)
        if self.offset >= len(self.data):
            return b""
        take = amount if self.chunk is None else min(amount, self.chunk)
        result = self.data[self.offset : self.offset + take]
        self.offset += len(result)
        return result


class LookupFault:
    def __init__(self, error_type: type[BaseException]) -> None:
        self.error_type = error_type

    @property
    def read(self):
        raise self.error_type("reader-secret")


class CallFault:
    def __init__(self, error_type: type[BaseException], first: bytes | None = None) -> None:
        self.error_type = error_type
        self.first = first
        self.calls = 0

    def read(self, amount: int) -> bytes:
        self.calls += 1
        if self.first is not None:
            result = self.first
            self.first = None
            return result
        raise self.error_type("reader-secret")


class ReturnValueReader:
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


class DataThenFault:
    def __init__(self, data: bytes, error_type: type[Exception]) -> None:
        self.data = data
        self.error_type = error_type
        self.offset = 0
        self.calls = 0

    def read(self, amount: int) -> bytes:
        self.calls += 1
        if self.offset == len(self.data):
            raise self.error_type("reader-secret")
        result = self.data[self.offset : self.offset + amount]
        self.offset += len(result)
        return result


class VirtualStreamReader:
    """Constant-state stream generator for exact cap tests."""

    def __init__(
        self,
        regular_count: int,
        regular_length: int,
        *,
        final_length: int | None = None,
        tail_prefix_length: int | None = None,
        max_request: int = 1088,
        record_requests: bool = False,
    ) -> None:
        self.header = bytes.fromhex(vectors.STREAM_HEX["policy2"])
        self.regular_count = regular_count
        self.regular_length = regular_length
        self.final_length = final_length
        self.tail_prefix_length = tail_prefix_length
        self.max_request = max_request
        self.record_requests = record_requests
        self.offset = 0
        self.calls = 0
        self.max_seen_request = 0
        self.requests: list[int] = []
        self.max_body_frame = -1

    @property
    def logical_length(self) -> int:
        value = HEADER_ENTRY_SIZE + self.regular_count * (4 + self.regular_length)
        if self.final_length is not None:
            value += 4 + self.final_length
        if self.tail_prefix_length is not None:
            value += 4
        return value

    def _frame_segment(self, frame_index: int, frame_length: int, position: int, amount: int) -> bytes:
        if position < 4:
            prefix = frame_length.to_bytes(4, "big")
            return prefix[position : position + min(amount, 4 - position)]
        self.max_body_frame = max(self.max_body_frame, frame_index)
        return bytes(min(amount, 4 + frame_length - position))

    def read(self, amount: int) -> bytes:
        if amount > self.max_request:
            raise AssertionError(f"request {amount} exceeds {self.max_request}")
        remaining = self.logical_length - self.offset
        if amount > remaining:
            raise AssertionError(f"request {amount} exceeds remaining {remaining}")
        self.calls += 1
        self.max_seen_request = max(self.max_seen_request, amount)
        if self.record_requests:
            self.requests.append(amount)
        if self.offset >= self.logical_length:
            return b""
        if self.offset < HEADER_ENTRY_SIZE:
            result = self.header[self.offset : self.offset + amount]
            self.offset += len(result)
            return result
        relative = self.offset - HEADER_ENTRY_SIZE
        regular_entry = 4 + self.regular_length
        regular_bytes = self.regular_count * regular_entry
        if relative < regular_bytes:
            frame_index = relative // regular_entry
            position = relative % regular_entry
            result = self._frame_segment(frame_index, self.regular_length, position, amount)
        else:
            relative -= regular_bytes
            if self.final_length is not None and relative < 4 + self.final_length:
                result = self._frame_segment(
                    self.regular_count, self.final_length, relative, amount
                )
            elif self.tail_prefix_length is not None:
                if self.final_length is not None:
                    relative -= 4 + self.final_length
                prefix = self.tail_prefix_length.to_bytes(4, "big")
                result = prefix[relative : relative + min(amount, 4 - relative)]
            else:
                result = b""
        self.offset += len(result)
        return result


def _specs():
    return {item[0]: item for item in vectors.VECTOR_SPECS}


def _raw(name: str) -> bytes:
    _, key, span_length, _, _, _ = _specs()[name]
    raw = bytes.fromhex(vectors.STREAM_HEX[key])[:span_length]
    assert len(raw) == span_length
    return raw


def _expect_error(source, length, reason: str) -> SppDiagTraceChainError:
    try:
        reduce_spp_diag_trace_chain(source, length)
    except SppDiagTraceChainError as exc:
        assert type(exc) is SppDiagTraceChainError
        assert exc.reason == reason
        assert str(exc) == reason
        assert exc.args == (reason,)
        assert exc.__cause__ is None
        assert exc.__context__ is None
        assert exc.__suppress_context__ is False
        return exc
    raise AssertionError(f"expected {reason}")


def _expect_base_exception(source, length, error_type: type[BaseException]) -> None:
    try:
        reduce_spp_diag_trace_chain(source, length)
    except error_type as exc:
        assert str(exc) == "reader-secret"
        return
    raise AssertionError(f"expected {error_type.__name__}")


def test_frozen_vectors() -> None:
    assert (
        CP_SPP_TRACE_CHAIN_TYPE,
        CP_SPP_TRACE_CHAIN_CAP,
        CP_SPP_TRACE_CHAIN_LENGTH,
        CP_SPP_TRACE_CHAIN_IO,
    ) == (TYPE_REASON, CAP_REASON, LENGTH_REASON, IO_REASON)
    assert len({TYPE_REASON, CAP_REASON, LENGTH_REASON, IO_REASON}) == 4
    assert SppDiagTraceChainError.__bases__ == (ValueError,)
    assert SppDiagTraceChainError.__annotations__ == {"reason": str}
    assert dataclasses.is_dataclass(SppDiagTraceChainReduction)
    params = SppDiagTraceChainReduction.__dataclass_params__
    assert (
        params.init,
        params.repr,
        params.eq,
        params.order,
        params.unsafe_hash,
        params.frozen,
    ) == (True, True, True, False, False, True)
    fields = dataclasses.fields(SppDiagTraceChainReduction)
    assert tuple(field.name for field in fields) == (
        "status",
        "chain",
        "frame_count",
        "stream_byte_count",
    )
    assert tuple(field.type for field in fields) == (str, bytes, int, int)
    assert all(field.default is dataclasses.MISSING for field in fields)
    assert all(field.default_factory is dataclasses.MISSING for field in fields)
    signature = inspect.signature(reduce_spp_diag_trace_chain)
    assert tuple(signature.parameters) == ("source", "stream_byte_count")
    source_parameter = signature.parameters["source"]
    count_parameter = signature.parameters["stream_byte_count"]
    assert source_parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert count_parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert source_parameter.default is inspect.Parameter.empty
    assert count_parameter.default is inspect.Parameter.empty
    assert source_parameter.annotation is typing.BinaryIO
    assert count_parameter.annotation is int
    assert signature.return_annotation is SppDiagTraceChainReduction
    expected_chains = bytearray()
    expected_stream_hashes = bytearray()
    for name, _, span_length, frame_count, chain_hex, stream_hash_hex in vectors.VECTOR_SPECS:
        raw = _raw(name)
        assert hashlib.sha256(raw).hexdigest() == stream_hash_hex
        for chunk in (None, 1, 3, 17, 191):
            reader = ChunkReader(raw, chunk, span_length)
            result = reduce_spp_diag_trace_chain(reader, span_length)
            assert type(result) is SppDiagTraceChainReduction
            assert type(result.status) is str
            assert result.status == "chain_reduced"
            assert type(result.chain) is bytes
            assert len(result.chain) == 32
            assert result.chain == bytes.fromhex(chain_hex)
            assert type(result.frame_count) is int
            assert result.frame_count == frame_count
            assert type(result.stream_byte_count) is int
            assert result.stream_byte_count == span_length
            assert reader.offset == span_length
            try:
                result.status = "changed"
            except dataclasses.FrozenInstanceError:
                pass
            else:
                raise AssertionError("result dataclass is mutable")
        expected_chains.extend(bytes.fromhex(chain_hex))
        expected_stream_hashes.extend(bytes.fromhex(stream_hash_hex))
    assert hashlib.sha256(expected_chains).hexdigest() == vectors.ORDERED_EXPECTED_CHAINS_SHA256
    assert hashlib.sha256(expected_stream_hashes).hexdigest() == vectors.ORDERED_STREAM_HASHES_SHA256


def _variant_reduce(
    raw: bytes,
    *,
    header_domain: bytes = HEADER_DOMAIN,
    frame_domain: bytes = FRAME_DOMAIN,
    omit_prefix: bool = False,
    swap_prefix: bool = False,
    reset_previous: bool = False,
    stale_previous: bool = False,
) -> bytes:
    chain = hashlib.sha256(header_domain + raw[:196]).digest()
    initial_chain = chain
    offset = 196
    while offset < len(raw):
        prefix = raw[offset : offset + 4]
        length = int.from_bytes(prefix, "big")
        frame = raw[offset + 4 : offset + 4 + length]
        used_prefix = b"" if omit_prefix else prefix[::-1] if swap_prefix else prefix
        previous = bytes(32) if reset_previous else initial_chain if stale_previous else chain
        chain = hashlib.sha256(frame_domain + previous + used_prefix + frame).digest()
        offset += 4 + length
    return chain


def test_formula_sensitivity_and_nonvalidator_ceiling() -> None:
    raw = _raw("alternating_mixed_prefix_16")
    expected = bytes.fromhex(_specs()["alternating_mixed_prefix_16"][4])
    variants = (
        _variant_reduce(raw, header_domain=HEADER_DOMAIN[:-1] + b"2"),
        _variant_reduce(raw, header_domain=HEADER_DOMAIN + b"\x00"),
        _variant_reduce(raw, frame_domain=FRAME_DOMAIN[:-1] + b"2"),
        _variant_reduce(raw, frame_domain=FRAME_DOMAIN + b"\x00"),
        _variant_reduce(raw, omit_prefix=True),
        _variant_reduce(raw, swap_prefix=True),
        _variant_reduce(raw, reset_previous=True),
        _variant_reduce(raw, stale_previous=True),
    )
    assert all(value != expected for value in variants)

    entries = [raw[offset : offset + 48] for offset in range(196, len(raw), 48)]
    mutations = []
    mutations.append(raw[:196] + entries[1] + entries[0] + b"".join(entries[2:]))
    mutations.append(raw[:196] + b"".join(entries[1:]))
    mutations.append(raw + entries[0])
    changed = bytearray(raw)
    changed[-1] ^= 1
    mutations.append(bytes(changed))
    for value in mutations:
        result = reduce_spp_diag_trace_chain(ChunkReader(value), len(value))
        assert result.status == "chain_reduced"
        assert result.chain != expected

    for offset in (4, 208, 200):
        changed = bytearray(raw)
        if offset == 200:
            changed[offset : offset + 2] = b"\xff\xff"
        else:
            changed[offset] ^= 1
        value = bytes(changed)
        result = reduce_spp_diag_trace_chain(ChunkReader(value), len(value))
        assert result.status == "chain_reduced"
        assert result.chain != expected


def test_types_lookup_calls_and_result_atomicity() -> None:
    class NoRead:
        pass

    class IntChild(int):
        pass

    class BytesChild(bytes):
        pass

    _expect_error(None, 196, TYPE_REASON)
    _expect_error(NoRead(), 196, TYPE_REASON)
    noncallable = type("NonCallable", (), {"read": b"no"})()
    _expect_error(noncallable, MAX_STREAM_BYTES + 1, TYPE_REASON)
    for invalid in (True, False, "196", 196.0, IntChild(196)):
        reader = ChunkReader(_raw("policy2_header_only"))
        _expect_error(reader, invalid, TYPE_REASON)
        assert reader.requests == []

    for invalid, reason in ((-1, LENGTH_REASON), (0, LENGTH_REASON), (195, LENGTH_REASON), (MAX_STREAM_BYTES + 1, CAP_REASON)):
        reader = ChunkReader(b"")
        _expect_error(reader, invalid, reason)
        assert reader.requests == []

    for error_type, reason in ((AttributeError, TYPE_REASON), (ValueError, IO_REASON)):
        _expect_error(LookupFault(error_type), "bad-length", reason)
        _expect_error(LookupFault(error_type), MAX_STREAM_BYTES + 1, reason)
    for error_type in (KeyboardInterrupt, SystemExit):
        _expect_base_exception(LookupFault(error_type), "bad-length", error_type)

    for error_type in (AttributeError, ValueError):
        _expect_error(CallFault(error_type), 196, IO_REASON)
    for error_type in (KeyboardInterrupt, SystemExit):
        _expect_base_exception(CallFault(error_type), 196, error_type)

    for value in (BytesChild(b"x"), bytearray(b"x"), memoryview(b"x"), "x", 1, None):
        reader = ReturnValueReader(value)
        _expect_error(reader, 196, TYPE_REASON)
        assert reader.calls == 1
    reader = OverReturnReader()
    _expect_error(reader, 196, TYPE_REASON)
    assert reader.calls == 1

    _expect_error(ChunkReader(b"", declared_length=196), 196, LENGTH_REASON)
    _expect_error(CallFault(ValueError, b"\x00\x00\x00\xc0"), 196, IO_REASON)

    header = _raw("policy2_header_only")
    frame_prefix = (44).to_bytes(4, "big")
    short_body = ChunkReader(
        header + frame_prefix + bytes(20), declared_length=244
    )
    _expect_error(short_body, 244, LENGTH_REASON)
    _expect_error(DataThenFault(header + frame_prefix, ValueError), 244, IO_REASON)
    _expect_error(
        DataThenFault(header + frame_prefix + bytes(10), ValueError), 244, IO_REASON
    )


def test_framing_boundaries() -> None:
    header = _raw("policy2_header_only")
    result = reduce_spp_diag_trace_chain(ChunkReader(header), len(header))
    assert result.frame_count == 0
    for length in range(196):
        _expect_error(ChunkReader(header[:length], declared_length=length), length, LENGTH_REASON)
    for prefix in (191, 193):
        value = prefix.to_bytes(4, "big") + header[4:]
        _expect_error(ChunkReader(value, declared_length=len(value)), len(value), LENGTH_REASON)
    for suffix_length in (1, 2, 3):
        value = header + bytes(suffix_length)
        _expect_error(ChunkReader(value, declared_length=len(value)), len(value), LENGTH_REASON)
    for frame_length in range(44):
        value = header + frame_length.to_bytes(4, "big")
        _expect_error(ChunkReader(value, declared_length=len(value)), len(value), LENGTH_REASON)
    value = header + (1089).to_bytes(4, "big")
    _expect_error(ChunkReader(value, declared_length=len(value)), len(value), CAP_REASON)
    for body_length in range(44):
        value = header + (44).to_bytes(4, "big") + bytes(body_length)
        _expect_error(ChunkReader(value, declared_length=len(value)), len(value), LENGTH_REASON)
    value = header + (44).to_bytes(4, "big") + bytes(45)
    _expect_error(ChunkReader(value, declared_length=len(value)), len(value), LENGTH_REASON)

    wrong_then_fail = CallFault(ValueError, b"\x00\x00\x00\xbf")
    _expect_error(wrong_then_fail, 196, LENGTH_REASON)
    assert wrong_then_fail.calls == 1
    oversized_and_short = header + (1089).to_bytes(4, "big")
    _expect_error(ChunkReader(oversized_and_short, declared_length=len(oversized_and_short)), len(oversized_and_short), CAP_REASON)


def test_exact_count_cap_and_precedence() -> None:
    exact = VirtualStreamReader(MAX_FRAMES, 44)
    assert exact.logical_length == 25166020
    result = reduce_spp_diag_trace_chain(exact, exact.logical_length)
    assert result.frame_count == MAX_FRAMES
    assert result.stream_byte_count == exact.logical_length

    truncated = VirtualStreamReader(MAX_FRAMES, 44, tail_prefix_length=44)
    assert truncated.logical_length == 25166024
    _expect_error(truncated, truncated.logical_length, LENGTH_REASON)

    plus_one = VirtualStreamReader(MAX_FRAMES + 1, 44)
    assert plus_one.logical_length == 25166068
    _expect_error(plus_one, plus_one.logical_length, CAP_REASON)
    assert plus_one.max_body_frame == MAX_FRAMES - 1


def _peak_for(reader: VirtualStreamReader) -> tuple[int, object]:
    gc.collect()
    tracemalloc.start()
    result = reduce_spp_diag_trace_chain(reader, reader.logical_length)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak, result


def test_exact_stream_cap_and_constant_memory() -> None:
    short = VirtualStreamReader(16, 1088)
    short_peak, short_result = _peak_for(short)
    assert short_result.frame_count == 16

    exact = VirtualStreamReader(245819, 1088, final_length=908)
    assert exact.logical_length == MAX_STREAM_BYTES
    exact_peak, result = _peak_for(exact)
    assert result.frame_count == 245820
    assert result.stream_byte_count == MAX_STREAM_BYTES
    assert exact.max_seen_request <= 1088
    assert exact_peak <= short_peak + 1024 * 1024

    reader = VirtualStreamReader(0, 44)
    _expect_error(reader, MAX_STREAM_BYTES + 1, CAP_REASON)
    assert reader.calls == 0


def test_static_independence_and_memory_guards() -> None:
    root = Path(__file__).resolve().parents[1]
    production_path = root / "conf_proc_spp_diag_trace_chain.py"
    production_source = production_path.read_text(encoding="utf-8")
    production_tree = ast.parse(production_source)
    imports = set()
    forbidden_names = {
        "__builtins__",
        "__import__",
        "builtins",
        "compile",
        "eval",
        "exec",
        "getattr",
        "globals",
        "locals",
        "open",
        "setattr",
        "vars",
    }
    forbidden_attributes = {
        "open",
        "read_bytes",
        "read_text",
        "write_bytes",
        "write_text",
        "mkdir",
        "touch",
        "unlink",
        "rename",
        "replace",
        "stat",
        "lstat",
        "resolve",
        "glob",
        "rglob",
        "iterdir",
    }
    for node in ast.walk(production_tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add((node.module or "").split(".")[0])
        elif isinstance(node, (ast.List, ast.ListComp)):
            raise AssertionError("production list accumulator")
        elif isinstance(node, ast.Name) and node.id in forbidden_names:
            raise AssertionError("production dynamic/path name")
        elif isinstance(node, ast.Attribute) and node.attr in forbidden_attributes:
            raise AssertionError("production filesystem/path attribute")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "read":
                assert len(node.args) == 1 and not node.keywords
                arg = node.args[0]
                assert not (isinstance(arg, ast.Name) and arg.id == "stream_byte_count")
    assert imports == {"dataclasses", "hashlib", "typing"}
    forbidden = (
        "sub" + "process",
        "ct" + "ypes",
        "import" + "lib",
        "path" + "lib",
        "conf_proc_spp_diag_trace.c",
        "conf_proc_spp_diag_trace.h",
        "conf-proc-spp-diag-trace-" + "oracle",
        "conf-proc-spp-diag-trace-chain-" + "oracle",
    )
    assert not any(token in production_source for token in forbidden)

    self_path = Path(__file__)
    self_source = self_path.read_text(encoding="utf-8")
    self_tree = ast.parse(self_source)
    self_parents = {
        child: parent
        for parent in ast.walk(self_tree)
        for child in ast.iter_child_nodes(parent)
    }
    self_imports = set()
    for node in ast.walk(self_tree):
        if isinstance(node, ast.Import):
            self_imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            self_imports.add(node.module or "")
        elif isinstance(node, ast.Name):
            assert node.id not in {
                "__builtins__",
                "__import__",
                "compile",
                "eval",
                "exec",
                "getattr",
                "globals",
                "locals",
                "open",
                "setattr",
                "vars",
            }
        elif isinstance(node, ast.Attribute) and node.attr == "read_text":
            parent = self_parents.get(node)
            receiver = node.value
            assert isinstance(parent, ast.Call) and parent.func is node
            assert isinstance(receiver, ast.Name)
            assert receiver.id in {"production_path", "self_path", "vector_path"}
        elif isinstance(node, ast.Attribute):
            assert node.attr not in {
                "open",
                "read_bytes",
                "glob",
                "rglob",
                "iterdir",
            }
    assert self_imports == {
        "ast",
        "dataclasses",
        "gc",
        "hashlib",
        "inspect",
        "pathlib",
        "tracemalloc",
        "typing",
        "conf_proc_spp_diag_trace_chain_vectors",
        "conf_proc_spp_diag_trace_chain",
    }
    separate_authority = "conf-proc-spp-diag-trace-chain-" + "ora" + "cle-selftest"
    assert separate_authority not in self_source
    assert ("import" + "lib") not in self_source
    assert ("run" + "py") not in self_source

    vector_path = self_path.with_name("conf_proc_spp_diag_trace_chain_vectors.py")
    vector_source = vector_path.read_text(encoding="utf-8")
    vector_tree = ast.parse(vector_source)
    assert not any(isinstance(node, (ast.Import, ast.ImportFrom, ast.Call)) for node in ast.walk(vector_tree))


def main() -> None:
    test_frozen_vectors()
    test_formula_sensitivity_and_nonvalidator_ceiling()
    test_types_lookup_calls_and_result_atomicity()
    test_framing_boundaries()
    test_exact_count_cap_and_precedence()
    test_exact_stream_cap_and_constant_memory()
    test_static_independence_and_memory_guards()
    print(
        "spp trace chain production contract: ok "
        f"vectors={len(vectors.VECTOR_SPECS)} "
        f"chains={vectors.ORDERED_EXPECTED_CHAINS_SHA256}"
    )


if __name__ == "__main__":
    main()
