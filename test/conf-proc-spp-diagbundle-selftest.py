#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Implementation tests for the diagnostic-bundle codec and CLI."""

from __future__ import annotations

import io
import errno
import os
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

import conf_proc_spp_diagbundle as prod  # noqa: E402
import conf_proc_spp_diagbundle_oracle as oracle  # noqa: E402
from conf_proc_json import canonical_dumps, canonical_loads  # noqa: E402
from conf_proc_spp_diagbundle_reasons import (  # noqa: E402
    CP_DIAGBUNDLE_EXPECTATIONS,
    CP_DIAGBUNDLE_FORBIDDEN,
    CP_DIAGBUNDLE_GRAPH,
    CP_DIAGBUNDLE_INTERNAL,
    CP_DIAGBUNDLE_JSON_INVALID,
    CP_DIAGBUNDLE_MEMBER,
    CP_DIAGBUNDLE_SCHEMA,
    CP_DIAGBUNDLE_STREAM_SIZE,
    CP_DIAGBUNDLE_TERMINAL_FRAME,
    DiagBundleError,
    NODE_ARTIFACT_STATE,
)
from conf_proc_spp_diagbundle_stream import (  # noqa: E402
    BundleStream,
    StreamMember,
    capture_bundle,
    read_bounded_regular,
)


_TMP = "/var/tmp"
_GIB = 1024**3
_MIB = 1024**2
_PEM_CERT = b"-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n"
_PEM_KEY = b"-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----\n"
_ZERO_HASH = "00" * 32


def _bundle(spec: oracle.BundleSpec = oracle.DEFAULT_SPEC):
    tmp = tempfile.TemporaryDirectory(prefix="diagbundle-self-", dir=_TMP)
    source_root = os.path.join(tmp.name, "bundle-source")
    bundle = os.path.join(tmp.name, "bundle.sppdbn")
    exp = os.path.join(tmp.name, "expectations.json")
    oracle.build_bundle(source_root, exp, spec)
    oracle.pack_bundle(source_root, bundle)
    return tmp, bundle, exp


def _expect(code: str, spec: oracle.BundleSpec) -> None:
    tmp, root, exp = _bundle(spec)
    try:
        try:
            prod.inspect_diagnostic_bundle(root, exp)
        except DiagBundleError as exc:
            if exc.reason_code != code:
                raise AssertionError(f"expected {code}, got {exc.reason_code}: {exc}") from exc
            return
        raise AssertionError(f"expected {code}")
    finally:
        tmp.cleanup()


def _fake_member(path: str, size: int) -> StreamMember:
    return StreamMember(
        handle=io.BytesIO(),
        path=path,
        path_bytes=path.encode("utf-8"),
        payload_offset=0,
        size_bytes=size,
        sha256=_ZERO_HASH,
    )


def _fake_bundle(files: dict[str, int]) -> BundleStream:
    return BundleStream(
        handle=io.BytesIO(),
        members={path: _fake_member(path, size) for path, size in files.items()},
        captured_size=0,
    )


def _expect_error(code: str, action) -> None:
    try:
        action()
    except DiagBundleError as exc:
        if exc.reason_code != code:
            raise AssertionError(f"expected {code}, got {exc.reason_code}: {exc}") from exc
    else:
        raise AssertionError(f"expected {code}")


def test_forbidden_status_tokens_absent() -> None:
    text = (ROOT / "conf_proc_spp_diagbundle.py").read_text() + (ROOT / "conf_proc_spp_diagbundle_cli.py").read_text()
    for token in ("quote_bound", "trace_clear", "candidate", "qualified", "serving", "admitted", "released", "production"):
        assert f'"{token}"' not in text, token
    assert '"pinned"' not in text
    assert '"claim"' not in text


def test_node_kind_distinctness() -> None:
    assert NODE_ARTIFACT_STATE not in prod.ALL_NODE_KINDS
    assert len(prod.ALL_NODE_KINDS) == 4


def test_cli_valid_and_failure_paths() -> None:
    tmp, root, exp = _bundle()
    try:
        cli = str(ROOT / "conf_proc_spp_diagbundle_cli.py")
        ok = subprocess.run([sys.executable, cli, "--bundle", root, "--expectations", exp], capture_output=True, cwd=str(ROOT))
        assert ok.returncode == 0, ok.stderr
        assert ok.stderr == b""
        line = ok.stdout.splitlines()
        assert len(line) == 1
        parsed = canonical_loads(line[0])
        assert parsed["result"] == "codec_valid"
        assert parsed["accepted"] is True
        for key in ("outer_envelope_address", "inner_receipt_digest", "image_binding_address", "input_closure_address", "control_plan_address"):
            assert key in parsed

        broken = replace(oracle.DEFAULT_SPEC, extra_root_file="surprise.bin")
        tmp2, root2, exp2 = _bundle(broken)
        try:
            bad = subprocess.run([sys.executable, cli, "--bundle", root2, "--expectations", exp2], capture_output=True, cwd=str(ROOT))
            assert bad.returncode == 1
            assert b"Traceback" not in bad.stdout and b"Traceback" not in bad.stderr
            payload = canonical_loads(bad.stdout.splitlines()[0])
            assert payload["result"] == "not_codec_valid"
            assert payload["reason_code"] == CP_DIAGBUNDLE_GRAPH
            assert "recovery_class" in payload and "safe_next_action" in payload
        finally:
            tmp2.cleanup()

        missing = subprocess.run([sys.executable, cli, "--bundle", os.path.join(tmp.name, "missing"), "--expectations", exp], capture_output=True, cwd=str(ROOT))
        assert missing.returncode == 1
        assert b"Traceback" not in missing.stdout and b"Traceback" not in missing.stderr
        payload = canonical_loads(missing.stdout.splitlines()[0])
        assert payload["result"] == "not_codec_valid"

        flags = subprocess.run([sys.executable, cli, "--bundle", root], capture_output=True, cwd=str(ROOT))
        assert flags.returncode == 1
        assert b"Traceback" not in flags.stdout and b"Traceback" not in flags.stderr
        payload = canonical_loads(flags.stdout.splitlines()[0])
        assert payload["reason_code"] == CP_DIAGBUNDLE_INTERNAL
        assert payload["result"] == "not_codec_valid"
    finally:
        tmp.cleanup()


def test_captured_uki_cannot_diverge_from_cached_image_hash() -> None:
    tmp, root, exp = _bundle()
    try:
        expectations = prod._parse_expectations(read_bounded_regular(exp, prod._MAX_EXPECTATIONS_BYTES))
        with capture_bundle(root) as captured:
            uki = captured.members["signed-image/diagnostic.efi"]
            try:
                os.pwrite(captured.handle.fileno(), b"X", uki.payload_offset)
            except OSError as exc:
                assert exc.errno == errno.EBADF
            else:
                raise AssertionError("captured UKI remained writable after its digest was cached")
            result = prod.inspect_diagnostic_members(captured, expectations)
            assert result["image_binding_address"]
    finally:
        tmp.cleanup()


def test_inventory_and_type_caps_without_large_allocations() -> None:
    def input_rows(count: int, size: int) -> tuple[prod.InputClosureRow, ...]:
        return tuple(
            prod.InputClosureRow(
                path=f"n{index:04d}",
                role="source_tree_manifest",
                content_kind="bytes",
                size_bytes=size,
                sha256=_ZERO_HASH,
            )
            for index in range(count)
        )

    exact_input_total = input_rows(4, 64 * _GIB)
    prod._require_inventory_budget(
        _fake_bundle({f"input-closure/n{index:04d}": 64 * _GIB for index in range(4)}),
        "input-closure",
        exact_input_total,
        max_entries=4096,
        max_file_bytes=64 * _GIB,
        max_total_bytes=256 * _GIB,
    )
    for bundle, rows in (
        (
            _fake_bundle({"input-closure/n0000": 64 * _GIB + 1}),
            input_rows(1, 64 * _GIB + 1),
        ),
        (
            _fake_bundle(
                {
                    "input-closure/n0000": 64 * _GIB,
                    "input-closure/n0001": 64 * _GIB,
                    "input-closure/n0002": 64 * _GIB,
                    "input-closure/n0003": 64 * _GIB,
                    "input-closure/n0004": 1,
                }
            ),
            input_rows(4, 64 * _GIB) + input_rows(1, 1),
        ),
        (
            _fake_bundle({f"input-closure/n{index:04d}": 1 for index in range(4097)}),
            input_rows(4097, 1),
        ),
    ):
        try:
            prod._require_inventory_budget(
                bundle,
                "input-closure",
                rows,
                max_entries=4096,
                max_file_bytes=64 * _GIB,
                max_total_bytes=256 * _GIB,
            )
        except DiagBundleError as exc:
            assert exc.reason_code == CP_DIAGBUNDLE_STREAM_SIZE
        else:
            raise AssertionError("expected STREAM_SIZE")

    def receipt_rows(count: int, size: int, *, start: int = 0) -> tuple[prod.InnerReceiptRow, ...]:
        return tuple(
            prod.InnerReceiptRow(
                path=f"n{index:04d}",
                content_kind="bytes",
                size_bytes=size,
                sha256=_ZERO_HASH,
            )
            for index in range(start, start + count)
        )

    exact_receipt_count = receipt_rows(1024, 1)
    prod._require_inventory_budget(
        _fake_bundle({f"inner-receipt/n{index:04d}": 1 for index in range(1024)}),
        "inner-receipt",
        exact_receipt_count,
        max_entries=1024,
        max_file_bytes=4 * _GIB,
        max_total_bytes=16 * _GIB,
    )
    exact_receipt_total = receipt_rows(4, 4 * _GIB)
    prod._require_inventory_budget(
        _fake_bundle({f"inner-receipt/n{index:04d}": 4 * _GIB for index in range(4)}),
        "inner-receipt",
        exact_receipt_total,
        max_entries=1024,
        max_file_bytes=4 * _GIB,
        max_total_bytes=16 * _GIB,
    )
    receipt_failures = (
        (
            _fake_bundle({f"inner-receipt/n{index:04d}": 1 for index in range(1025)}),
            receipt_rows(1025, 1),
        ),
        (_fake_bundle({"inner-receipt/n0000": 4 * _GIB + 1}), receipt_rows(1, 4 * _GIB + 1)),
        (
            _fake_bundle(
                {
                    "inner-receipt/n0000": 4 * _GIB,
                    "inner-receipt/n0001": 4 * _GIB,
                    "inner-receipt/n0002": 4 * _GIB,
                    "inner-receipt/n0003": 4 * _GIB,
                    "inner-receipt/n0004": 1,
                }
            ),
            receipt_rows(4, 4 * _GIB) + receipt_rows(1, 1, start=4),
        ),
    )
    for bundle, rows in receipt_failures:
        _expect_error(
            CP_DIAGBUNDLE_STREAM_SIZE,
            lambda bundle=bundle, rows=rows: prod._require_inventory_budget(
                bundle,
                "inner-receipt",
                rows,
                max_entries=1024,
                max_file_bytes=4 * _GIB,
                max_total_bytes=16 * _GIB,
            ),
        )

    for prefix, caps in (
        ("signed-image", prod._SIGNED_IMAGE_FILE_CAPS),
        ("", prod._OUTER_FILE_CAPS),
    ):
        for name, maximum in caps.items():
            path = f"{prefix}/{name}" if prefix else name
            prod._require_member_cap(_fake_member(path, maximum), maximum)
            _expect_error(
                CP_DIAGBUNDLE_STREAM_SIZE,
                lambda path=path, maximum=maximum: prod._require_member_cap(
                    _fake_member(path, maximum + 1), maximum
                ),
            )


def test_caller_expectations_closed_and_bounded() -> None:
    valid = {
        "input_closure_address": "00" * 32,
        "challenge": "11" * 32,
        "run_identity": "22" * 32,
        "target_profile_id": "az/centralus.zone-3_h100-v5",
        "control_plan_address": "33" * 32,
    }
    parsed = prod._parse_expectations(canonical_dumps(valid))
    assert parsed.target_profile_id == valid["target_profile_id"]

    closed_schema_cases = []
    missing = dict(valid)
    del missing["challenge"]
    closed_schema_cases.append(canonical_dumps(missing))
    extra = dict(valid)
    extra["extra"] = True
    closed_schema_cases.append(canonical_dumps(extra))
    for data in closed_schema_cases:
        _expect_error(CP_DIAGBUNDLE_EXPECTATIONS, lambda data=data: prod._parse_expectations(data))

    bad_values = []
    for key in ("input_closure_address", "challenge", "run_identity", "control_plan_address"):
        value = dict(valid)
        value[key] = "AA" * 32
        bad_values.append(value)
    for target in ("", "Uppercase", "-leading", "space value", "a" * 129, 7):
        value = dict(valid)
        value["target_profile_id"] = target
        bad_values.append(value)
    for value in bad_values:
        _expect_error(
            CP_DIAGBUNDLE_EXPECTATIONS,
            lambda value=value: prod._parse_expectations(canonical_dumps(value)),
        )

    invalid_json = (
        b"\xff",
        b'{"challenge":"00","challenge":"11"}',
        b'{ "challenge":"00"}',
    )
    for data in invalid_json:
        _expect_error(CP_DIAGBUNDLE_JSON_INVALID, lambda data=data: prod._parse_expectations(data))
    _expect_error(CP_DIAGBUNDLE_EXPECTATIONS, lambda: prod._parse_expectations(b"x" * 1025))


def test_forbidden_private_key_filenames_are_case_insensitive() -> None:
    for path in ("secrets/KEY.P12", "nested/ID_RSA", "nested/id_ED25519", "bundle.PFX"):
        _expect_error(CP_DIAGBUNDLE_FORBIDDEN, lambda path=path: prod._reject_forbidden_path(path))


def _receipt_manifest(paths: tuple[str, ...]) -> bytes:
    inventory = [
        {
            "path": path,
            "content_kind": "bytes",
            "size_bytes": 76 if path == prod.TERMINAL_FRAME_PATH else 1,
            "sha256": _ZERO_HASH,
        }
        for path in paths
    ]
    return canonical_dumps(
        {
            "schema": prod.INNER_RECEIPT_SCHEMA_ID,
            "node_kind": prod.NODE_KIND_INNER_RECEIPT,
            "artifact_state": NODE_ARTIFACT_STATE,
            "challenge": "11" * 32,
            "run_identity": "22" * 32,
            "signed_image_binding_address": "33" * 32,
            "target_profile_id": "profile-v1",
            "control_plan_address": "44" * 32,
            "inventory": inventory,
        }
    )


def test_terminal_inventory_semantic_finality() -> None:
    positive = prod.parse_inner_receipt_manifest(
        _receipt_manifest(("zz-evidence.bin", prod.TERMINAL_FRAME_PATH))
    )
    assert positive.inventory[-1].path == prod.TERMINAL_FRAME_PATH
    _expect_error(
        CP_DIAGBUNDLE_TERMINAL_FRAME,
        lambda: prod.parse_inner_receipt_manifest(_receipt_manifest(("evidence.bin",))),
    )
    _expect_error(
        CP_DIAGBUNDLE_TERMINAL_FRAME,
        lambda: prod.parse_inner_receipt_manifest(
            _receipt_manifest((prod.TERMINAL_FRAME_PATH, prod.TERMINAL_FRAME_PATH))
        ),
    )
    _expect_error(
        CP_DIAGBUNDLE_SCHEMA,
        lambda: prod.parse_inner_receipt_manifest(
            _receipt_manifest(("z-evidence.bin", "a-evidence.bin", prod.TERMINAL_FRAME_PATH))
        ),
    )


def test_terminal_frame_exact_bytes() -> None:
    expected = (
        oracle.TERMINAL_FRAME_PREFIX
        + bytes.fromhex(oracle.DEFAULT_SPEC.challenge)
        + bytes.fromhex(oracle.DEFAULT_SPEC.run_identity)
    )
    assert len(expected) == 76
    mutations = (
        b"X" + expected[1:],
        expected[:8] + b"\x02" + expected[9:],
        expected[:9] + b"\x02" + expected[10:],
        expected[:10] + b"\x00\x3f" + expected[12:],
        expected[:12] + bytes([expected[12] ^ 1]) + expected[13:],
        expected[:44] + bytes([expected[44] ^ 1]) + expected[45:],
        expected + b"\x00",
    )
    for frame in mutations:
        _expect(CP_DIAGBUNDLE_TERMINAL_FRAME, replace(oracle.DEFAULT_SPEC, terminal_frame=frame))

def test_content_kind_gating() -> None:
    rows = tuple((path, role, "bytes", _PEM_KEY) if path == "producer.py" else (path, role, kind, data) for path, role, kind, data in oracle.DEFAULT_SPEC.closure_rows)
    _expect(CP_DIAGBUNDLE_FORBIDDEN, replace(oracle.DEFAULT_SPEC, closure_rows=rows))
    source_rows = tuple((path, role, "source", _PEM_KEY) if path == "producer.py" else (path, role, kind, data) for path, role, kind, data in oracle.DEFAULT_SPEC.closure_rows)
    _expect(CP_DIAGBUNDLE_FORBIDDEN, replace(oracle.DEFAULT_SPEC, closure_rows=source_rows))
    json_rows = tuple((path, role, "canonical_json", _PEM_KEY) if path == "config.json" else (path, role, kind, data) for path, role, kind, data in oracle.DEFAULT_SPEC.closure_rows)
    _expect(CP_DIAGBUNDLE_FORBIDDEN, replace(oracle.DEFAULT_SPEC, closure_rows=json_rows))


def test_outer_pem_members() -> None:
    cert_files = tuple((name, _PEM_CERT if name == "ak-public.pem" else data) for name, data in oracle.DEFAULT_SPEC.outer_files)
    tmp, root, exp = _bundle(replace(oracle.DEFAULT_SPEC, outer_files=cert_files))
    try:
        prod.inspect_diagnostic_bundle(root, exp)
    finally:
        tmp.cleanup()
    key_files = tuple((name, _PEM_KEY if name == "ak-public.pem" else data) for name, data in oracle.DEFAULT_SPEC.outer_files)
    _expect(CP_DIAGBUNDLE_FORBIDDEN, replace(oracle.DEFAULT_SPEC, outer_files=key_files))


def test_root_graph_shape() -> None:
    _expect(CP_DIAGBUNDLE_GRAPH, replace(oracle.DEFAULT_SPEC, extra_root_file="surprise.bin"))
    _expect(CP_DIAGBUNDLE_GRAPH, replace(oracle.DEFAULT_SPEC, skip_signed_image_dir=True))


def test_member_set_bijection() -> None:
    _expect(CP_DIAGBUNDLE_GRAPH, replace(oracle.DEFAULT_SPEC, extra_signed_image_file="bonus.bin"))
    _expect(CP_DIAGBUNDLE_GRAPH, replace(oracle.DEFAULT_SPEC, skip_closure_file="trace.json"))


TESTS = (
    test_forbidden_status_tokens_absent,
    test_node_kind_distinctness,
    test_cli_valid_and_failure_paths,
    test_captured_uki_cannot_diverge_from_cached_image_hash,
    test_inventory_and_type_caps_without_large_allocations,
    test_caller_expectations_closed_and_bounded,
    test_forbidden_private_key_filenames_are_case_insensitive,
    test_terminal_frame_exact_bytes,
    test_terminal_inventory_semantic_finality,
    test_content_kind_gating,
    test_outer_pem_members,
    test_root_graph_shape,
    test_member_set_bijection,
)


if __name__ == "__main__":
    failed = 0
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report every case
            failed += 1
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok   {test.__name__}")
    raise SystemExit(failed)
