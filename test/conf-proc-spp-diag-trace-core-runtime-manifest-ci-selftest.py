#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""AC8 closure check for the complete K4 source manifest and input hashes."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_spp_diag_trace_core_materialize as materialize  # noqa: E402
from conf_proc_spp_diag_trace_core_manifest import parse_core_manifest  # noqa: E402
from conf_proc_spp_diag_trace_core_materialize_reasons import (  # noqa: E402
    CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED,
    SppDiagTraceCoreMaterializeError,
)


def main() -> int:
    manifest_path = ROOT / "spp-diag-trace-core-src/manifest.json"
    manifest = parse_core_manifest(manifest_path.read_bytes())
    if len(manifest.creates) != 19 or len(manifest.replaces) != 38:
        print(f"FAIL K4 manifest closure creates={len(manifest.creates)} replaces={len(manifest.replaces)}")
        return 1
    materialize._preflight_inputs(manifest)
    first = manifest.inputs[0]
    corrupt = replace(first, sha256="0" * 64)
    bad = replace(manifest, inputs=(corrupt, *manifest.inputs[1:]))
    try:
        materialize._preflight_inputs(bad)
    except SppDiagTraceCoreMaterializeError as exc:
        if exc.reason_code != CP_SPP_DIAG_TRACE_CORE_INPUT_CHANGED:
            print(f"FAIL preimage mutation wrong reason {exc.reason_code}")
            return 1
    else:
        print("FAIL preimage hash mutation was accepted")
        return 1
    print("ok   K4 manifest closure all targets and input-hash mutation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
