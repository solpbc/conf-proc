#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""AC6 oracle: real adapters reproduce the established K3 byte vector."""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path


def load_families_oracle():
    path = Path(__file__).with_name("conf-proc-spp-diag-trace-core-runtime-families-oracle-selftest.py")
    spec = importlib.util.spec_from_file_location("families_oracle", path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load established families oracle")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: runtime-integration-oracle-selftest.py FIXTURE")
    fixture = sys.argv[1]
    oracle = load_families_oracle()
    actual = oracle.decode_blob(subprocess.check_output([fixture]))
    expected = oracle.expected()
    if actual != expected:
        print("FAIL adapter integration stream differs from independent K3 vector")
        return 1
    mutation = subprocess.run([fixture, "--wrong-token"], check=False)
    if mutation.returncode != 42:
        print(f"FAIL adapter integration wrong-token mutation exit={mutation.returncode}, want 42")
        return 1
    digest = hashlib.sha256(actual).hexdigest()
    if len(actual) != 1822 or digest != "5fa08ba4084f2edffd2558b02ba26fca82528e8d056ce6d4c5181212f157b361":
        print(f"FAIL adapter integration vector bytes={len(actual)} sha256={digest}")
        return 1
    print(f"ok   adapter integration 20-frame vector bytes={len(actual)} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
