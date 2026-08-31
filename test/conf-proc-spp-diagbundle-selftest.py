#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Implementation tests for the diagnostic-bundle codec and CLI."""

from __future__ import annotations

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
    CP_DIAGBUNDLE_FORBIDDEN,
    CP_DIAGBUNDLE_GRAPH,
    CP_DIAGBUNDLE_INTERNAL,
    CP_DIAGBUNDLE_MEMBER,
    CP_DIAGBUNDLE_SNAPSHOT_SIZE,
    CP_DIAGBUNDLE_TERMINAL_FRAME,
    DiagBundleError,
    NODE_ARTIFACT_STATE,
)
from conf_proc_spp_diagbundle_snapshot import BundleSnapshot, PinnedDirectory, PinnedFile  # noqa: E402


_TMP = "/var/tmp"
_GIB = 1024**3
_MIB = 1024**2
_PEM_CERT = b"-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n"
_PEM_KEY = b"-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----\n"
_ZERO_HASH = "00" * 32


def _bundle(spec: oracle.BundleSpec = oracle.DEFAULT_SPEC):
    tmp = tempfile.TemporaryDirectory(prefix="diagbundle-self-", dir=_TMP)
    root = os.path.join(tmp.name, "bundle")
    exp = os.path.join(tmp.name, "expectations.json")
    oracle.build_bundle(root, exp, spec)
    return tmp, root, exp


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


def _fake_file(path: str, size: int, ino: int) -> PinnedFile:
    return PinnedFile(fd=-1, relative_path=path, identity=(1, ino, 0o100644, 1, size, 0, 0), pass1_sha256=_ZERO_HASH)


def _fake_dir(path: str, ino: int) -> PinnedDirectory:
    return PinnedDirectory(fd=-1, relative_path=path, identity=(1, ino, 0o40755, 2, 0, 0, 0), child_names=())


def _fake_snapshot(files: dict[str, int], directories: tuple[str, ...] = ()) -> BundleSnapshot:
    pinned_files = {}
    ino = 10
    for path, size in files.items():
        ino += 1
        pinned_files[path] = _fake_file(path, size, ino)
    pinned_dirs = {"": _fake_dir("", 1)}
    for path in directories:
        ino += 1
        pinned_dirs[path] = _fake_dir(path, ino)
    return BundleSnapshot(root=pinned_dirs[""], files=pinned_files, directories=pinned_dirs)


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


def test_subtree_and_image_caps_on_fake_snapshot() -> None:
    ok = _fake_snapshot({"input-closure/a": 64 * _GIB}, directories=("input-closure",))
    prod._require_subtree_budget(ok, "input-closure", max_entries=4096, max_file_bytes=64 * _GIB, max_total_bytes=256 * _GIB)
    over_file = _fake_snapshot({"input-closure/a": 64 * _GIB + 1}, directories=("input-closure",))
    try:
        prod._require_subtree_budget(over_file, "input-closure", max_entries=4096, max_file_bytes=64 * _GIB, max_total_bytes=256 * _GIB)
    except DiagBundleError as exc:
        assert exc.reason_code == CP_DIAGBUNDLE_SNAPSHOT_SIZE
    else:
        raise AssertionError("expected SNAPSHOT_SIZE")
    over_total = _fake_snapshot({"input-closure/a": 200 * _GIB, "input-closure/b": 57 * _GIB}, directories=("input-closure",))
    try:
        prod._require_subtree_budget(over_total, "input-closure", max_entries=4096, max_file_bytes=64 * _GIB, max_total_bytes=256 * _GIB)
    except DiagBundleError as exc:
        assert exc.reason_code == CP_DIAGBUNDLE_SNAPSHOT_SIZE
    else:
        raise AssertionError("expected SNAPSHOT_SIZE")

    receipt_ok = _fake_snapshot({"inner-receipt/a": 4 * _GIB}, directories=("inner-receipt",))
    prod._require_subtree_budget(receipt_ok, "inner-receipt", max_entries=1024, max_file_bytes=4 * _GIB, max_total_bytes=16 * _GIB)
    receipt_over = _fake_snapshot({"inner-receipt/a": 4 * _GIB + 1}, directories=("inner-receipt",))
    try:
        prod._require_subtree_budget(receipt_over, "inner-receipt", max_entries=1024, max_file_bytes=4 * _GIB, max_total_bytes=16 * _GIB)
    except DiagBundleError as exc:
        assert exc.reason_code == CP_DIAGBUNDLE_SNAPSHOT_SIZE
    else:
        raise AssertionError("expected SNAPSHOT_SIZE")

    files = {f"input-closure/n{index}": 1 for index in range(4096)}
    prod._require_subtree_budget(_fake_snapshot(files), "input-closure", max_entries=4096, max_file_bytes=64 * _GIB, max_total_bytes=256 * _GIB)
    files[f"input-closure/n4096"] = 1
    try:
        prod._require_subtree_budget(_fake_snapshot(files), "input-closure", max_entries=4096, max_file_bytes=64 * _GIB, max_total_bytes=256 * _GIB)
    except DiagBundleError as exc:
        assert exc.reason_code == CP_DIAGBUNDLE_SNAPSHOT_SIZE
    else:
        raise AssertionError("expected SNAPSHOT_SIZE")

    receipt_files = {f"inner-receipt/n{index}": 1 for index in range(1024)}
    prod._require_subtree_budget(_fake_snapshot(receipt_files), "inner-receipt", max_entries=1024, max_file_bytes=4 * _GIB, max_total_bytes=16 * _GIB)
    receipt_files["inner-receipt/n1024"] = 1
    try:
        prod._require_subtree_budget(_fake_snapshot(receipt_files), "inner-receipt", max_entries=1024, max_file_bytes=4 * _GIB, max_total_bytes=16 * _GIB)
    except DiagBundleError as exc:
        assert exc.reason_code == CP_DIAGBUNDLE_SNAPSHOT_SIZE
    else:
        raise AssertionError("expected SNAPSHOT_SIZE")

    outer_files = {name: 1 for name in prod.OUTER_FILE_MEMBER_NAMES}
    outer_ok = _fake_snapshot(outer_files, directories=("inner-receipt",))
    prod._require_outer_member_budget(outer_ok)
    outer_over = _fake_snapshot({name: (20 * _GIB if name == "quote.msg" else 1) + (1 if name == "quote.msg" else 0) for name in prod.OUTER_FILE_MEMBER_NAMES}, directories=("inner-receipt",))
    try:
        prod._require_outer_member_budget(outer_over)
    except DiagBundleError as exc:
        assert exc.reason_code == CP_DIAGBUNDLE_SNAPSHOT_SIZE
    else:
        raise AssertionError("expected SNAPSHOT_SIZE")

    image_ok = _fake_snapshot({
        "signed-image/diagnostic.efi": 1 * _GIB,
        "signed-image/rootfs.img": 64 * _GIB,
        "signed-image/rootfs.verity": 8 * _GIB,
        "signed-image/verity-root-hash.bin": 128,
        "signed-image/signer-cert.der": 1 * _MIB,
    })
    prod._require_signed_image_file_caps(image_ok)
    for name, size in (
        ("diagnostic.efi", 1 * _GIB + 1),
        ("rootfs.img", 64 * _GIB + 1),
        ("rootfs.verity", 8 * _GIB + 1),
        ("verity-root-hash.bin", 129),
        ("signer-cert.der", 1 * _MIB + 1),
    ):
        over = _fake_snapshot({**{f"signed-image/{item}": 1 for item in prod.SIGNED_IMAGE_MEMBER_NAMES}, f"signed-image/{name}": size})
        try:
            prod._require_signed_image_file_caps(over)
        except DiagBundleError as exc:
            assert exc.reason_code == CP_DIAGBUNDLE_SNAPSHOT_SIZE
        else:
            raise AssertionError(f"expected SNAPSHOT_SIZE for {name}")


def test_terminal_intent_values() -> None:
    for value in ("export_complete", "halted", "deallocated", "resource_absent", "unknown"):
        _expect(CP_DIAGBUNDLE_TERMINAL_FRAME, replace(oracle.DEFAULT_SPEC, terminal_intent=value))


def test_content_kind_gating() -> None:
    rows = tuple((path, role, "bytes", _PEM_KEY) if path == "producer.py" else (path, role, kind, data) for path, role, kind, data in oracle.DEFAULT_SPEC.closure_rows)
    tmp, root, exp = _bundle(replace(oracle.DEFAULT_SPEC, closure_rows=rows))
    try:
        prod.inspect_diagnostic_bundle(root, exp)
    finally:
        tmp.cleanup()
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
    _expect(CP_DIAGBUNDLE_MEMBER, replace(oracle.DEFAULT_SPEC, extra_signed_image_file="bonus.bin"))
    _expect(CP_DIAGBUNDLE_MEMBER, replace(oracle.DEFAULT_SPEC, skip_closure_file="trace.json"))


TESTS = (
    test_forbidden_status_tokens_absent,
    test_node_kind_distinctness,
    test_cli_valid_and_failure_paths,
    test_subtree_and_image_caps_on_fake_snapshot,
    test_terminal_intent_values,
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
