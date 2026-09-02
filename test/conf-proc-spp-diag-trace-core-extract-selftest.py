#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Rerun the protocol-constants extractor and require a byte-identical header."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR = ROOT / "conf_proc_spp_diag_trace_core_extract_constants.py"
COMMITTED = (
    ROOT
    / "spp-diag-trace-core-src"
    / "security"
    / "spp_diag_trace_core"
    / "protocol_constants.h"
)


def main() -> int:
    regenerated = Path("/var/tmp/spp-diag-trace-core-protocol_constants.h")
    completed = subprocess.run(
        [sys.executable, str(EXTRACTOR), str(regenerated)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stderr)
        raise SystemExit(f"extractor exited {completed.returncode}")
    expected = COMMITTED.read_bytes()
    actual = regenerated.read_bytes()
    if actual != expected:
        raise SystemExit(
            f"extracted header drifted: committed {len(expected)} bytes, "
            f"regenerated {len(actual)} bytes"
        )
    print("ok   spp-diag-trace-core-extract-selftest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
