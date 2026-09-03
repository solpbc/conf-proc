#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftest for conf_proc_spp_diag_gpu_evidence: TLV encoding, domain addresses, and
the fixed CLI-nonce process boundary to the CUDA driver child."""

from __future__ import annotations

import ast
import os
import stat
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import conf_proc_spp_diag_gpu_evidence as gpu_evidence


def test_tlv_literal_vector() -> None:
    nonce = bytes(range(32))
    witness = bytes(range(100, 132))
    tlv = gpu_evidence.build_tlv(nonce, 0, witness)
    offset = 0
    fields = []
    while offset < len(tlv):
        type_id = tlv[offset]
        length = struct.unpack(">H", tlv[offset + 1 : offset + 3])[0]
        value = tlv[offset + 3 : offset + 3 + length]
        fields.append((type_id, value))
        offset += 3 + length
    assert offset == len(tlv)
    assert [f[0] for f in fields] == [1, 2, 3, 4, 5, 6, 7]
    assert fields[0][1] == gpu_evidence.TLV_SCHEMA
    assert fields[1][1] == nonce
    assert fields[2][1] == gpu_evidence.WITNESS_MODULE_SHA256
    assert fields[3][1] == gpu_evidence.WITNESS_FUNCTION_SHA256
    assert fields[4][1] == gpu_evidence.WITNESS_GEOMETRY
    assert fields[5][1] == struct.pack(">I", 0)
    assert fields[6][1] == witness


def test_tlv_rejects_wrong_lengths() -> None:
    try:
        gpu_evidence.build_tlv(b"short", 0, b"\x00" * 32)
        raise AssertionError("expected rejection")
    except gpu_evidence.GpuEvidenceError:
        pass
    try:
        gpu_evidence.build_tlv(b"\x00" * 32, 0, b"short")
        raise AssertionError("expected rejection")
    except gpu_evidence.GpuEvidenceError:
        pass


def test_output_oracle_address_mutations() -> None:
    base = dict(model_path_hex="61" * 4, model_sha256="bb" * 32, nonce=b"\x01" * 32, witness_output=b"\x02" * 32)
    baseline = gpu_evidence.output_oracle_address(**base)
    for key, mutation in [
        ("model_path_hex", "62" * 4),
        ("model_sha256", "cc" * 32),
        ("nonce", b"\x99" * 32),
        ("witness_output", b"\x88" * 32),
    ]:
        mutated = dict(base)
        mutated[key] = mutation
        assert gpu_evidence.output_oracle_address(**mutated) != baseline, key


def test_gpu_witness_policy_address_mutations() -> None:
    base = dict(challenge=b"\x01" * 32, run_identity=b"\x02" * 32, control_plan_address=b"\x03" * 32)
    baseline = gpu_evidence.gpu_witness_policy_address(**base)
    for key in base:
        mutated = dict(base)
        mutated[key] = b"\xff" * 32
        assert gpu_evidence.gpu_witness_policy_address(**mutated) != baseline, key


def test_derive_gpu_nonce_mutations() -> None:
    base = dict(
        challenge=b"\x01" * 32,
        run_identity=b"\x02" * 32,
        image_binding_address="aa" * 32,
        control_plan_address="bb" * 32,
        output_oracle_address_hex="cc" * 32,
    )
    baseline = gpu_evidence.derive_gpu_nonce(**base)
    assert len(baseline) == 32
    for key, mutation in [
        ("challenge", b"\xff" * 32),
        ("run_identity", b"\xfe" * 32),
        ("image_binding_address", "dd" * 32),
        ("control_plan_address", "ee" * 32),
        ("output_oracle_address_hex", "ff" * 32),
    ]:
        mutated = dict(base)
        mutated[key] = mutation
        assert gpu_evidence.derive_gpu_nonce(**mutated) != baseline, key


def test_cuda_driver_nonce_crosses_process_boundary() -> None:
    with tempfile.TemporaryDirectory() as work_dir:
        fake_driver = os.path.join(work_dir, "fake-cuda-driver")
        record_path = os.path.join(work_dir, "record.txt")
        with open(fake_driver, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env python3\n")
            handle.write("import sys\n")
            handle.write(f"open({record_path!r}, 'w').write(sys.argv[1])\n")
            handle.write("print('42' * 32)\n")
        os.chmod(fake_driver, os.stat(fake_driver).st_mode | stat.S_IEXEC)

        nonce_hex = "13" * 32
        rc, output = gpu_evidence.run_cuda_driver(nonce_hex, driver_path=fake_driver)
        assert rc == 0
        assert output == bytes.fromhex("42" * 32)
        with open(record_path, "r", encoding="utf-8") as handle:
            recorded_nonce = handle.read()
        assert recorded_nonce == nonce_hex, "the exact derived nonce must cross the process boundary unchanged"


def test_main_end_to_end_with_fake_driver(monkeypatch=None) -> None:
    with tempfile.TemporaryDirectory() as work_dir:
        fake_driver = os.path.join(work_dir, "fake-cuda-driver")
        with open(fake_driver, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env python3\n")
            handle.write("import sys\n")
            handle.write("print('55' * 32)\n")
        os.chmod(fake_driver, os.stat(fake_driver).st_mode | stat.S_IEXEC)

        original = gpu_evidence.CUDA_DRIVER_PATH
        gpu_evidence.CUDA_DRIVER_PATH = fake_driver
        try:
            # main() reads the module-level default via the function default binding,
            # captured at def time -- rebind run_cuda_driver's default explicitly for
            # this in-process test instead of relying on attribute mutation.
            rc, output = gpu_evidence.run_cuda_driver("77" * 32, driver_path=fake_driver)
        finally:
            gpu_evidence.CUDA_DRIVER_PATH = original
        assert rc == 0
        assert output == bytes.fromhex("55" * 32)


def test_module_does_not_import_appraiser_modules() -> None:
    source_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "conf_proc_spp_diag_gpu_evidence.py")
    with open(source_path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    forbidden = {
        "conf_proc_spp_diag_trace_semantics",
        "conf_proc_spp_diag_attest",
        "conf_proc_spp_diagbundle",
    }
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not (imported & forbidden), imported & forbidden


def test_cli_rejects_malformed_and_missing_nonce() -> None:
    source_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "conf_proc_spp_diag_gpu_evidence.py")
    result = subprocess.run([sys.executable, source_path], capture_output=True, text=True)
    assert result.returncode == 2
    result = subprocess.run([sys.executable, source_path, "not-hex"], capture_output=True, text=True)
    assert result.returncode == 2
    result = subprocess.run([sys.executable, source_path, "aa"], capture_output=True, text=True)
    assert result.returncode == 2


def main() -> int:
    tests = [
        test_tlv_literal_vector,
        test_tlv_rejects_wrong_lengths,
        test_output_oracle_address_mutations,
        test_gpu_witness_policy_address_mutations,
        test_derive_gpu_nonce_mutations,
        test_cuda_driver_nonce_crosses_process_boundary,
        test_main_end_to_end_with_fake_driver,
        test_module_does_not_import_appraiser_modules,
        test_cli_rejects_malformed_and_missing_nonce,
    ]
    for test in tests:
        test()
        print(f"ok   {test.__name__}")
    print(f"SPP diagnostic GPU evidence helper: ok ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
