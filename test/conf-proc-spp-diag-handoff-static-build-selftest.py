#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Schema and authority checks for the handoff static-build requirement."""

from __future__ import annotations

import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DECLARATION = ROOT / "spp-diag-runtime-src/spp_diag_handoff_static_build.json"


def main() -> None:
    data = json.loads(DECLARATION.read_text(encoding="utf-8"))
    assert data["schema"] == "sol-spp-diag-static-native-build-requirements-v1"
    assert data["source_set"] == ["spp-diag-runtime-src/spp_diag_handoff.c"]
    assert data["target"] == "x86_64-unknown-linux-musl"
    for artifact in data["artifacts"].values():
        assert set(artifact) == {"artifact", "sha256"}
        assert re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])
    compile_argv = data["compile"]["argv"]
    link = data["link"]
    link_argv = link["argv"]
    assert "-static" in link_argv and "-nostdlib" in link_argv
    assert "--sysroot={sysroot}" in compile_argv and "--sysroot={sysroot}" in link_argv
    assert set(link["explicit_static_inputs"]) <= set(link_argv)
    assert any(value.endswith("crt1.o") for value in link["explicit_static_inputs"])
    assert any(value.endswith("libc.a") for value in link["explicit_static_inputs"])
    assert any(value.endswith("libgcc.a") for value in link["explicit_static_inputs"])
    assert link["forbidden_dependencies"] == ["libfdisk", "libblkid", "libudev"]
    assert not any(value.startswith("/usr/") or value.startswith("/lib") for value in compile_argv + link_argv)
    assert data["output"] == {
        "path": "/spp-diag-handoff", "mode": "0755",
        "expectations": {"elf_type": "ET_EXEC", "static": True, "interpreter": None, "dt_needed": []},
    }
    print("SPP handoff static-build declaration: ok")


if __name__ == "__main__":
    main()
