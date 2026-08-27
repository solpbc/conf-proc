#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Pinned subprocess boundary for the independent provenance-v2 oracle.

This adapter is the only production code permitted to load the VPE-authored
oracle.  It verifies the oracle source bytes before loading them, reads bounded
exact inputs once, and emits canonical content-safe JSON.  Builders, producers,
and production schema modules must invoke this file as a subprocess and must
never import the oracle or this adapter.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import types
from pathlib import Path


ORACLE_SHA256 = "5c1a0f9f470732268cb3f3bcf575fbbfd728ace87397c7d7771da5e7e3124410"
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 128 * 1024 * 1024


class AdapterFailure(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise AdapterFailure("CP_PROVENANCE_ARGUMENTS")


class ReadBudget:
    def __init__(self, limit: int) -> None:
        self.remaining = limit

    def consume(self, size: int) -> None:
        if size > self.remaining:
            raise AdapterFailure("CP_PROVENANCE_INPUT_SIZE")
        self.remaining -= size


def _read_bounded(path: str, budget: ReadBudget) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AdapterFailure("CP_PROVENANCE_INPUT_READ") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > MAX_INPUT_BYTES:
            raise AdapterFailure("CP_PROVENANCE_INPUT_SIZE")
        budget.consume(before.st_size)
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise AdapterFailure("CP_PROVENANCE_INPUT_CHANGED")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise AdapterFailure("CP_PROVENANCE_INPUT_CHANGED")
        after = os.fstat(descriptor)
    except AdapterFailure:
        raise
    except OSError as exc:
        raise AdapterFailure("CP_PROVENANCE_INPUT_READ") from exc
    finally:
        os.close(descriptor)
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if before_identity != after_identity:
        raise AdapterFailure("CP_PROVENANCE_INPUT_CHANGED")
    return b"".join(chunks)


def _load_oracle():
    oracle_path = Path(__file__).with_name("conf_proc_inspect_provenance.py")
    source = _read_bounded(str(oracle_path), ReadBudget(MAX_INPUT_BYTES))
    if hashlib.sha256(source).hexdigest() != ORACLE_SHA256:
        raise AdapterFailure("CP_PROVENANCE_ORACLE_DIGEST")
    name = "_conf_proc_pinned_provenance_oracle"
    module = types.ModuleType(name)
    module.__file__ = "<pinned-provenance-oracle>"
    module.__package__ = ""
    sys.modules[name] = module
    try:
        code = compile(source, module.__file__, "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except Exception as exc:
        sys.modules.pop(name, None)
        raise AdapterFailure("CP_PROVENANCE_ORACLE_LOAD") from exc
    return module


def main(argv: list[str] | None = None) -> int:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--root-lock", required=True)
    parser.add_argument("--runtime-closure", required=True)
    parser.add_argument("--verity-rules", required=True)
    parser.add_argument("--tcb-identity", required=True)
    parser.add_argument("--builder-source", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--sbom", required=True)
    oracle = None
    try:
        args = parser.parse_args(argv)
        oracle = _load_oracle()
        budget = ReadBudget(MAX_TOTAL_INPUT_BYTES)
        exact = {
            "root_lock_bytes": _read_bounded(args.root_lock, budget),
            "runtime_closure_bytes": _read_bounded(args.runtime_closure, budget),
            "verity_rules_bytes": _read_bounded(args.verity_rules, budget),
            "tcb_identity_bytes": _read_bounded(args.tcb_identity, budget),
            "builder_source_bytes": _read_bounded(args.builder_source, budget),
            "policy_bytes": _read_bounded(args.policy, budget),
        }
        inputs = oracle.derive_inputs(**exact)
        oracle.inspect_bindings(
            manifest_bytes=_read_bounded(args.manifest, budget),
            sbom_bytes=_read_bounded(args.sbom, budget),
            inputs=inputs,
        )
        output = {
            "accepted": True,
            "artifact_input_sha256": inputs.artifact_input_sha256,
            "execution_provenance_sha256": inputs.execution_provenance_sha256,
            "closure_status": "declared_unverified",
            "tcb_status": "declared_unverified",
        }
        sys.stdout.buffer.write(oracle.canonical_dumps(output) + b"\n")
        return 0
    except Exception as exc:  # noqa: BLE001 - boundary must serialize every failure safely
        reason_code = getattr(exc, "reason_code", "CP_PROVENANCE_ORACLE_INTERNAL")
        output = {
            "accepted": False,
            "reason_code": reason_code,
            "stage": "provenance-v2",
            "promotion_state": "not_attempted",
            "guidance": "rebuild from the exact trusted inputs and pinned oracle",
        }
        if oracle is None:
            sys.stdout.write(
                '{"accepted":false,"guidance":"rebuild from the exact trusted inputs and pinned oracle",'
                f'"promotion_state":"not_attempted","reason_code":"{reason_code}","stage":"provenance-v2"}}\n'
            )
        else:
            sys.stdout.buffer.write(oracle.canonical_dumps(output) + b"\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
