# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Independent literal oracle for SPP diagnostic trace-chain reduction."""

import ast
import hashlib
from pathlib import Path

import conf_proc_spp_diag_trace_chain_vectors as vectors


HEADER_DOMAIN = b"sol-spp-diag-trace-header/v1"
FRAME_DOMAIN = b"sol-spp-diag-trace-frame/v1"


def _reduce(raw: bytes) -> tuple[bytes, int]:
    if len(raw) < 196 or raw[:4] != b"\x00\x00\x00\xc0":
        raise AssertionError("fixture header framing")
    chain = hashlib.sha256(HEADER_DOMAIN + raw[:196]).digest()
    offset = 196
    count = 0
    while offset < len(raw):
        if len(raw) - offset < 4:
            raise AssertionError("fixture suffix framing")
        prefix = raw[offset : offset + 4]
        frame_length = int.from_bytes(prefix, "big")
        if frame_length < 44 or frame_length > 1088:
            raise AssertionError("fixture frame bound")
        end = offset + 4 + frame_length
        if end > len(raw):
            raise AssertionError("fixture frame truncation")
        chain = hashlib.sha256(
            FRAME_DOMAIN + chain + prefix + raw[offset + 4 : end]
        ).digest()
        offset = end
        count += 1
    return chain, count


def _static_independence() -> None:
    here = Path(__file__)
    source = here.read_text(encoding="utf-8")
    tree = ast.parse(source)
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
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
        elif isinstance(node, ast.Attribute) and node.attr == "read_text":
            parent = parents.get(node)
            receiver = node.value
            if not (
                isinstance(parent, ast.Call)
                and parent.func is node
                and isinstance(receiver, ast.Name)
                and receiver.id in {"here", "vector_path"}
            ):
                raise AssertionError("oracle read escaped self/vector files")
    expected = {
        "ast",
        "hashlib",
        "pathlib",
        "conf_proc_spp_diag_trace_chain_vectors",
    }
    if imports != expected:
        raise AssertionError(f"oracle import set changed: {sorted(imports)!r}")
    forbidden = (
        "sub" + "process",
        "ct" + "ypes",
        "oracle-" + "harness",
        "conf_proc_spp_diag_trace." + "c",
        "conf_proc_spp_diag_trace." + "h",
        "conf-proc-spp-diag-trace-" + "oracle-selftest.py",
    )
    if any(token in source for token in forbidden):
        raise AssertionError("oracle reached forbidden authority")

    vector_path = here.with_name("conf_proc_spp_diag_trace_chain_vectors.py")
    vector_source = vector_path.read_text(encoding="utf-8")
    vector_tree = ast.parse(vector_source)
    if any(isinstance(node, (ast.Import, ast.ImportFrom, ast.Call)) for node in ast.walk(vector_tree)):
        raise AssertionError("vector authority is not literal-only")
    forbidden_vector = ("hash" + "lib", "conf_proc_spp_diag_trace_chain" + ".py")
    if any(token in vector_source for token in forbidden_vector):
        raise AssertionError("vector authority computes or imports production")


def main() -> None:
    _static_independence()
    expected_chains = bytearray()
    expected_stream_hashes = bytearray()
    seen = set()
    for name, stream_key, span_length, frame_count, chain_hex, stream_hash_hex in vectors.VECTOR_SPECS:
        raw = bytes.fromhex(vectors.STREAM_HEX[stream_key])[:span_length]
        if len(raw) != span_length:
            raise AssertionError(f"{name}: literal span length")
        if hashlib.sha256(raw).hexdigest() != stream_hash_hex:
            raise AssertionError(f"{name}: literal stream hash")
        chain, count = _reduce(raw)
        if chain.hex() != chain_hex or count != frame_count:
            raise AssertionError(f"{name}: chain/count mismatch")
        expected_chains.extend(bytes.fromhex(chain_hex))
        expected_stream_hashes.extend(bytes.fromhex(stream_hash_hex))
        seen.add(name)
    required = {
        "policy1_header_only",
        "policy2_header_only",
        "one_core",
        "one_provenance",
        "all_core",
        "all_provenance",
        "alternating_mixed_prefix_16",
    }
    if not required.issubset(seen):
        raise AssertionError("required vector population missing")
    if hashlib.sha256(expected_chains).hexdigest() != vectors.ORDERED_EXPECTED_CHAINS_SHA256:
        raise AssertionError("ordered chain-set digest")
    if hashlib.sha256(expected_stream_hashes).hexdigest() != vectors.ORDERED_STREAM_HASHES_SHA256:
        raise AssertionError("ordered stream-hash-set digest")
    print(
        "spp trace chain oracle: ok "
        f"vectors={len(vectors.VECTOR_SPECS)} "
        f"chains={vectors.ORDERED_EXPECTED_CHAINS_SHA256} "
        f"streams={vectors.ORDERED_STREAM_HASHES_SHA256}"
    )


if __name__ == "__main__":
    main()
