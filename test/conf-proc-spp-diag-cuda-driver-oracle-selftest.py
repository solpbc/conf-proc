#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent build/oracle for the SPP diagnostic CUDA child."""

from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
import tempfile


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER_SOURCE = os.path.join(ROOT, "spp-diag-runtime-src", "spp_diag_cuda_driver.c")
FAKE_SOURCE = os.path.join(ROOT, "test", "spp-diag-runtime-shim", "fake_libcuda.c")
MODEL_BYTES = b"sol-spp-semantic-fixture-model-v1"
MODEL_SHA256 = "1ae959386fcd1dff3db63e50a9ebba5376d5d83f08ef98a2e584e7b0f878d6c8"
PRODUCTION_MODEL_PATH = "/opt/solstone/models/synthetic-fixture-v1.bin"
MAX_MODEL_BYTES = 8 * 1024 * 1024


def expected_result(model: bytes, seed: bytes) -> bytes:
    assert len(seed) == 32
    output = bytearray(seed)
    for offset, value in enumerate(model):
        output[offset % 32] ^= value
    return bytes(output)


def expected_record(model: bytes, seed: bytes) -> bytes:
    return struct.pack(">8sHHI32s", b"SPPGPUO1", 1, 1, 32, expected_result(model, seed))


def compile_one(output: str, source: str, arguments: list[str]) -> None:
    result = subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", *arguments, "-o", output, source],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or result.stdout or result.stderr:
        raise AssertionError(f"compile failed or warned:\n{result.stdout}\n{result.stderr}")


def build(build_dir: str, model_path: str, *, sanitized: bool = False) -> tuple[str, str]:
    variant_dir = os.path.join(build_dir, "sanitized" if sanitized else "plain")
    os.mkdir(variant_dir)
    driver = os.path.join(variant_dir, "spp-diag-cuda-driver")
    fake = os.path.join(variant_dir, "libcuda.so.1")
    sanitizer = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if sanitized else []
    compile_one(
        driver,
        DRIVER_SOURCE,
        [*sanitizer, f'-DSPP_DIAG_MODEL_PATH="{model_path}"', "-ldl"],
    )
    compile_one(fake, FAKE_SOURCE, [*sanitizer, "-fPIC", "-shared"])
    return driver, fake


def run_driver(
    driver: str,
    fake: str,
    arguments: list[str],
    extra_env: dict[str, str] | None = None,
    timeout: float = 3.0,
) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = os.path.dirname(fake)
    if extra_env:
        env.update(extra_env)
    return subprocess.run([driver, *arguments], env=env, capture_output=True, timeout=timeout, check=False)


def test_cold_and_two_inference_vectors(driver: str, fake: str) -> None:
    cold = run_driver(driver, fake, ["cold"])
    assert cold.returncode == 0 and cold.stdout == b"" and cold.stderr == b""
    for seed in (bytes(range(32)), bytes(reversed(range(32)))):
        result = run_driver(driver, fake, ["infer", seed.hex()])
        assert result.returncode == 0, result.stderr
        assert result.stderr == b""
        assert result.stdout == expected_record(MODEL_BYTES, seed)


def test_mutations_and_driver_faults(driver: str, fake: str) -> None:
    seed = bytes(range(32))
    stale = run_driver(driver, fake, ["infer", seed.hex()], {"SPP_DIAG_CUDA_FAKE_FORCE_CONSTANT_OUTPUT": "1"})
    assert stale.returncode == 0 and stale.stdout != expected_record(MODEL_BYTES, seed)
    faults = (
        "SPP_DIAG_CUDA_FAKE_FORCE_TWO_DEVICES",
        "SPP_DIAG_CUDA_FAKE_FORCE_MODULE_MISMATCH",
        "SPP_DIAG_CUDA_FAKE_FORCE_FUNCTION_MISMATCH",
        "SPP_DIAG_CUDA_FAKE_FORCE_GEOMETRY_MISMATCH",
        "SPP_DIAG_CUDA_FAKE_FORCE_DRIVER_RESULT",
        "SPP_DIAG_CUDA_FAKE_FORCE_SYNC_FAIL",
        "SPP_DIAG_CUDA_FAKE_FORCE_CLEANUP_FAIL",
    )
    for name in faults:
        value = "719" if name.endswith("DRIVER_RESULT") else "1"
        result = run_driver(driver, fake, ["infer", seed.hex()], {name: value})
        assert result.returncode != 0, name
        assert result.stdout == b"", (name, result.stdout)
    try:
        run_driver(driver, fake, ["infer", seed.hex()], {"SPP_DIAG_CUDA_FAKE_FORCE_TIMEOUT": "1"}, timeout=1.0)
        raise AssertionError("CUDA timeout unexpectedly passed")
    except subprocess.TimeoutExpired:
        pass


def test_cli_and_model_failures(driver: str, fake: str, model_path: str) -> None:
    bad_invocations = ([], ["infer"], ["infer", "AA" * 32], ["infer", "00" * 31], ["unknown"])
    for arguments in bad_invocations:
        result = run_driver(driver, fake, list(arguments))
        assert result.returncode != 0 and result.stdout == b""
    os.unlink(model_path)
    missing = run_driver(driver, fake, ["infer", "00" * 32])
    assert missing.returncode != 0 and missing.stdout == b""


def test_model_path_and_size_boundaries(driver: str, fake: str, model_path: str) -> None:
    seed = b"\x3c" * 32
    target = model_path + ".target"
    with open(target, "wb") as handle:
        handle.write(MODEL_BYTES)
    os.unlink(model_path)
    os.symlink(target, model_path)
    assert run_driver(driver, fake, ["infer", seed.hex()]).returncode != 0
    os.unlink(model_path)

    with open(model_path, "wb"):
        pass
    assert run_driver(driver, fake, ["infer", seed.hex()]).returncode != 0
    os.unlink(model_path)

    os.mkdir(model_path)
    assert run_driver(driver, fake, ["infer", seed.hex()]).returncode != 0
    os.rmdir(model_path)

    boundary = b"\x5a" * MAX_MODEL_BYTES
    with open(model_path, "wb") as handle:
        handle.write(boundary)
    accepted = run_driver(driver, fake, ["infer", seed.hex()])
    assert accepted.returncode == 0, accepted.stderr
    assert accepted.stdout == expected_record(boundary, seed)

    with open(model_path, "ab") as handle:
        handle.write(b"\x00")
    rejected = run_driver(driver, fake, ["infer", seed.hex()])
    assert rejected.returncode != 0 and rejected.stdout == b""
    with open(model_path, "wb") as handle:
        handle.write(MODEL_BYTES)


def test_semantic_ptx_mutants_reject(build_dir: str, model_path: str, fake: str) -> None:
    source = open(DRIVER_SOURCE, "r", encoding="utf-8").read()
    mutations = (
        ('"    add.u64 %rd5, %rd5, 32;\\n"', '"    add.u64 %rd5, %rd5, 31;\\n"'),
        ('"    xor.b32 %r2, %r2, %r3;\\n"', '"    mov.b32 %r2, %r3;\\n"'),
        ('"    @%p1 bra STORE;\\n"', '"    @%p1 bra DONE;\\n"'),
    )
    for index, (old, new) in enumerate(mutations):
        assert source.count(old) == 1
        mutant_source = os.path.join(build_dir, f"mutant-{index}.c")
        with open(mutant_source, "w", encoding="utf-8") as handle:
            handle.write(source.replace(old, new))
        mutant = os.path.join(build_dir, f"mutant-{index}")
        compile_one(mutant, mutant_source, [f'-DSPP_DIAG_MODEL_PATH="{model_path}"', "-ldl"])
        result = run_driver(mutant, fake, ["infer", (b"\x12" * 32).hex()])
        assert result.returncode != 0 and result.stdout == b""


def test_source_and_sanitized_build(build_dir: str, model_path: str) -> None:
    assert hashlib.sha256(MODEL_BYTES).hexdigest() == MODEL_SHA256
    source = open(DRIVER_SOURCE, "r", encoding="utf-8").read()
    assert f'#define SPP_DIAG_MODEL_PATH "{PRODUCTION_MODEL_PATH}"' in source
    for required in (
        ".target sm_90",
        "xor.b32",
        "cuDeviceGetCount",
        "cuCtxSynchronize",
        "O_NOFOLLOW",
        "MAP_PRIVATE",
        'dlopen("libcuda.so.1"',
    ):
        assert required in source
    driver, fake = build(build_dir, model_path, sanitized=True)
    result = run_driver(driver, fake, ["infer", (b"\xa5" * 32).hex()])
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected_record(MODEL_BYTES, b"\xa5" * 32)


def main() -> int:
    with tempfile.TemporaryDirectory() as build_dir:
        model_path = os.path.join(build_dir, "synthetic-fixture-v1.bin")
        with open(model_path, "wb") as handle:
            handle.write(MODEL_BYTES)
        driver, fake = build(build_dir, model_path)
        tests = (
            ("cold_and_two_inference_vectors", lambda: test_cold_and_two_inference_vectors(driver, fake)),
            ("mutations_and_driver_faults", lambda: test_mutations_and_driver_faults(driver, fake)),
            ("semantic_ptx_mutants_reject", lambda: test_semantic_ptx_mutants_reject(build_dir, model_path, fake)),
            ("source_and_sanitized_build", lambda: test_source_and_sanitized_build(build_dir, model_path)),
            ("model_path_and_size_boundaries", lambda: test_model_path_and_size_boundaries(driver, fake, model_path)),
            ("cli_and_model_failures", lambda: test_cli_and_model_failures(driver, fake, model_path)),
        )
        for name, test in tests:
            test()
            print(f"ok   {name}")
        print(f"SPP diagnostic CUDA driver: ok ({len(tests)} groups)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
