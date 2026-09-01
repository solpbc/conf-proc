# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Independent literal oracle for SPP diagnostic trace checkpoint fixtures."""

import ast
import hashlib
from pathlib import Path

import conf_proc_spp_diag_trace_checkpoint_vectors as vectors


HEADER_DOMAIN = b"sol-spp-diag-trace-header/v1"
FRAME_DOMAIN = b"sol-spp-diag-trace-frame/v1"
SOURCE_COMMIT = bytes.fromhex("91a8e826012fbb1c7f5cb2a326c08b13e390f469")


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 8], "big")


def _static_independence() -> None:
    here = Path(__file__)
    source = here.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {
                "__import__",
                "eval",
                "exec",
                "open",
            }:
                raise AssertionError("dynamic or write-capable oracle call")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "open",
                "read_bytes",
                "write_bytes",
                "write_text",
                "glob",
                "rglob",
                "iterdir",
            }:
                raise AssertionError("write-capable oracle call")
    if imports != {
        "ast",
        "hashlib",
        "pathlib",
        "conf_proc_spp_diag_trace_checkpoint_vectors",
    }:
        raise AssertionError(f"oracle import set changed: {sorted(imports)!r}")
    forbidden = (
        "sub" + "process",
        "ct" + "ypes",
        "conf_proc_spp_diag_trace_checkpoints" + ".py",
        "conf_proc_spp_diag_trace" + ".c",
        "conf_proc_spp_diag_trace" + ".h",
        "conf_proc_spp_diag_trace_chain" + ".py",
    )
    if any(token in source for token in forbidden):
        raise AssertionError("oracle reached forbidden authority")

    vector_path = here.with_name("conf_proc_spp_diag_trace_checkpoint_vectors.py")
    vector_source = vector_path.read_text(encoding="utf-8")
    vector_tree = ast.parse(vector_source)
    if any(
        isinstance(node, (ast.Import, ast.ImportFrom, ast.Call))
        for node in ast.walk(vector_tree)
    ):
        raise AssertionError("vector authority is not literal-only")
    if any(token in vector_source for token in ("hash" + "lib", "struct")):
        raise AssertionError("vector authority computes protocol values")


def _check_header(raw: bytes) -> None:
    assert vectors.SOURCE_COMMIT_HEX == SOURCE_COMMIT.hex()
    assert raw[:4] == b"\x00\x00\x00\xc0"
    header = raw[4:196]
    assert len(header) == 192
    assert header[:8] == b"SPPTRC1\0"
    assert (_u16(header, 8), _u16(header, 10), _u16(header, 12), _u16(header, 14)) == (
        1,
        192,
        2,
        1,
    )
    assert _u32(header, 16) == 524288
    assert _u64(header, 20) == 268435456
    assert _u32(header, 28) == 1088
    assert header[32:52] == SOURCE_COMMIT
    assert header[52:84].hex() == vectors.CHALLENGE_HEX
    assert header[84:116].hex() == vectors.RUN_IDENTITY_HEX
    assert header[116:148].hex() == vectors.CONTROL_PLAN_ADDRESS_HEX
    assert header[148:180].hex() == vectors.COMMAND_LINE_SHA256_HEX
    assert _u64(header, 180) == 0xFFFF
    assert _u32(header, 188) == 0


def _check_frames(raw: bytes) -> tuple[bytes, ...]:
    assert vectors.ENTRY_OFFSETS[0] == 0
    assert vectors.ENTRY_OFFSETS[-1] == len(raw)
    chain = hashlib.sha256(HEADER_DOMAIN + raw[:196]).digest()
    chains = [chain]
    denied = 0
    committed = 0
    anchors = []
    for sequence, (start, end) in enumerate(
        zip(vectors.ENTRY_OFFSETS[1:-1], vectors.ENTRY_OFFSETS[2:])
    ):
        entry = raw[start:end]
        frame_length = _u32(entry, 0)
        frame = entry[4:]
        assert frame_length == len(frame)
        assert _u32(frame, 4) == len(frame) - 44
        assert _u64(frame, 8) == sequence
        event = _u16(frame, 0)
        if event == 2:
            denied += 1
        if event == 6:
            committed += 1
        chain = hashlib.sha256(FRAME_DOMAIN + chain + entry).digest()
        chains.append(chain)
        if event in (3, 4, 10):
            anchors.append((event, sequence + 1, end, chain, denied, committed, frame))
    assert tuple(value.hex() for value in chains) == vectors.ALL_CHAIN_HEX
    assert tuple(item[0] for item in anchors) == (3, 4, 10)
    assert tuple(item[1] for item in anchors) == vectors.CHECKPOINT_FRAME_COUNTS
    assert tuple(item[2] for item in anchors) == vectors.CHECKPOINT_STREAM_BYTE_COUNTS
    assert tuple(item[3].hex() for item in anchors) == vectors.CHECKPOINT_CHAIN_HEX
    assert tuple(item[4] for item in anchors) == vectors.CHECKPOINT_RAW_DENIED_COUNTS
    assert tuple(item[5] for item in anchors) == vectors.CHECKPOINT_RAW_COMMITTED_COUNTS
    ready, release, terminal = (item[6] for item in anchors)
    assert (_u16(ready, 2), _u64(ready, 16), _u64(ready, 24), _u64(ready, 32), _u16(ready, 40), _u16(ready, 42)) == (0, 0, 0, 0, 0, 0)
    assert ready[44:] == b"\x00\x00\x00\x00\x00\x00\x00\x01"
    assert (_u16(release, 2), _u64(release, 16), _u64(release, 24), _u64(release, 32), _u16(release, 40), _u16(release, 42)) == (0, 1, 0, 0, 0, 0)
    assert release[44:] == b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01"
    assert (_u16(terminal, 2), _u64(terminal, 16), _u64(terminal, 24), _u64(terminal, 32), _u16(terminal, 40), _u16(terminal, 42)) == (0, 0, 0, 0, 15, 0)
    assert terminal[44:] == b""
    return tuple(item[3] for item in anchors)


def _check_records(chains: tuple[bytes, ...]) -> None:
    identities = (
        bytes.fromhex(vectors.CHALLENGE_HEX),
        bytes.fromhex(vectors.RUN_IDENTITY_HEX),
        bytes.fromhex(vectors.CONTROL_PLAN_ADDRESS_HEX),
        bytes.fromhex(vectors.COMMAND_LINE_SHA256_HEX),
    )
    record_digests = []
    for index, (name, raw_hex) in enumerate(
        zip(vectors.CHECKPOINT_EVENT_NAMES, vectors.CHECKPOINT_RECORD_HEX)
    ):
        raw = bytes.fromhex(raw_hex)
        record_digests.append(hashlib.sha256(raw).hexdigest())
        assert len(raw) == 256
        assert raw[:8] == b"SPPIMA1\0"
        kind = index + 1
        assert (_u16(raw, 8), _u16(raw, 10), _u32(raw, 12)) == (1, kind, 256)
        assert (_u16(raw, 16), _u16(raw, 18), _u16(raw, 20), _u16(raw, 22)) == (
            2,
            1,
            kind,
            0,
        )
        assert raw[24:44] == SOURCE_COMMIT
        assert (raw[44:76], raw[76:108], raw[108:140], raw[140:172]) == identities
        assert _u64(raw, 172) == vectors.CHECKPOINT_FRAME_COUNTS[index]
        assert _u64(raw, 180) == vectors.CHECKPOINT_STREAM_BYTE_COUNTS[index]
        assert raw[188:220] == chains[index]
        assert _u64(raw, 220) == 0xFFFF
        assert _u64(raw, 228) == vectors.CHECKPOINT_RAW_DENIED_COUNTS[index]
        assert _u64(raw, 236) == vectors.CHECKPOINT_RAW_COMMITTED_COUNTS[index]
        assert raw[244:256] == bytes(12)
        assert name == (
            b"sol-spp-diag-ready-v1",
            b"sol-spp-diag-release-v1",
            b"sol-spp-diag-terminal-v1",
        )[index]
    assert tuple(record_digests) == vectors.CHECKPOINT_RECORD_SHA256


def main() -> None:
    _static_independence()
    assert vectors.CHECKPOINT_KINDS == ("ready", "release", "terminal")
    raw = bytes.fromhex(vectors.STREAM_HEX)
    assert len(raw) == 618
    assert hashlib.sha256(raw).hexdigest() == vectors.STREAM_SHA256
    _check_header(raw)
    chains = _check_frames(raw)
    assert hashlib.sha256(b"".join(chains)).hexdigest() == vectors.ORDERED_CHECKPOINT_CHAINS_SHA256
    _check_records(chains)
    assert vectors.DERIVATION_TOOLS == (
        "/usr/bin/sha256sum — sha256sum (GNU coreutils) 9.4",
        "/usr/bin/openssl — OpenSSL 3.0.13 30 Jan 2024",
        "/usr/bin/xxd — xxd 2023-10-25 by Juergen Weigert et al.",
    )
    print("spp diagnostic trace checkpoint frozen oracle: ok")


if __name__ == "__main__":
    main()
