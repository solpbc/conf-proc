#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Self-test the independent SPP trace-semantic positive oracle."""

from __future__ import annotations

import hashlib
import json
import struct

from conf_proc_spp_diag_trace_semantic_fixture import (
    EXPECTED_LEDGER_HEX,
    STREAM_HEX,
)
from conf_proc_spp_diag_trace_semantics_oracle import accepted_vectors


def main() -> int:
    base_stream = bytes.fromhex(STREAM_HEX)
    base_ledger = bytes.fromhex(EXPECTED_LEDGER_HEX)
    vectors = accepted_vectors()
    assert len(vectors) == 23
    names = [vector.name for vector in vectors]
    assert len(names) == len(set(names))
    assert {name for name in names if name.startswith("ordinary_")} == {
        f"ordinary_{family}_phase_{phase}"
        for phase in (1, 2, 3, 13)
        for family in ("file", "mapping", "network", "postcommit_exec")
    }
    stream_hashes = []
    ledger_hashes = []
    for vector in vectors:
        assert vector.stream != base_stream
        assert vector.expected_ledger != base_ledger
        assert json.dumps(
            json.loads(vector.expected_ledger), sort_keys=True, separators=(",", ":")
        ).encode("utf-8") == vector.expected_ledger
        offset = 196
        sequence = 0
        while offset < len(vector.stream):
            length = struct.unpack_from(">I", vector.stream, offset)[0]
            assert 44 <= length <= 1088
            assert struct.unpack_from(">Q", vector.stream, offset + 12)[0] == sequence
            offset += 4 + length
            sequence += 1
        assert offset == len(vector.stream)
        ledger = json.loads(vector.expected_ledger)
        assert ledger["frame_count"] == sequence
        assert ledger["stream_byte_count"] == len(vector.stream)
        stream_hashes.append(hashlib.sha256(vector.stream).digest())
        ledger_hashes.append(hashlib.sha256(vector.expected_ledger).digest())
    print(f"semantic_oracle_vectors={len(vectors)}")
    print(f"semantic_oracle_stream_set_sha256={hashlib.sha256(b''.join(stream_hashes)).hexdigest()}")
    print(f"semantic_oracle_ledger_set_sha256={hashlib.sha256(b''.join(ledger_hashes)).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
