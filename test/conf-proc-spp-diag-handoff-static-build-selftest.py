#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Schema and authority checks for the handoff static-build requirement."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DECLARATION = ROOT / "spp-diag-runtime-src/spp_diag_handoff_static_build.json"


def main() -> None:
    data = json.loads(DECLARATION.read_text(encoding="utf-8"))
    assert data["schema"] == "sol-spp-diag-static-native-build-requirements-v1"
    inputs = data["in_repo_inputs"]
    assert set(inputs) == {"sources", "headers"}
    assert inputs["headers"] == []
    assert inputs["sources"] and len({item["path"] for item in inputs["sources"]}) == len(inputs["sources"])
    for item in inputs["sources"] + inputs["headers"]:
        assert set(item) == {"path", "sha256"}
        path = ROOT / item["path"]
        assert path.is_file() and not path.is_symlink()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
    assert [item["path"] for item in inputs["sources"]] == ["spp-diag-runtime-src/spp_diag_handoff.c"]
    assert data["target"] == "x86_64-unknown-linux-musl"
    materialization = data["external_materialization"]
    assert materialization["required_manifest_reference"] == "sol-spp-diag-static-toolchain-materialization-v1"
    for artifact in materialization["required_artifacts"].values():
        assert set(artifact) == {"artifact", "sha256"}
        assert re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])
        assert artifact["sha256"] != "0" * 64
        assert not artifact["artifact"].startswith("/")
        assert "placeholder" not in artifact["artifact"].lower()
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
    _nonhermetic_static_smoke()
    print("SPP handoff static-build declaration: ok")


def _nonhermetic_static_smoke() -> None:
    """Optionally check a host static link; it is not the hermetic build."""

    compiler = shutil.which("cc")
    readelf = shutil.which("readelf")
    if compiler is None or readelf is None:
        print("skip non-hermetic static smoke: cc/readelf unavailable")
        return
    with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
        output = Path(directory) / "spp-diag-handoff"
        built = subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-static", "-o", str(output),
             str(ROOT / "spp-diag-runtime-src/spp_diag_handoff.c")],
            capture_output=True,
            text=True,
        )
        if built.returncode != 0:
            print("skip non-hermetic static smoke: host static libc unavailable")
            return
        program_headers = subprocess.run([readelf, "-l", str(output)], capture_output=True, text=True, check=True).stdout
        dynamic = subprocess.run([readelf, "-d", str(output)], capture_output=True, text=True, check=True).stdout
        assert "Requesting program interpreter" not in program_headers
        assert "(NEEDED)" not in dynamic
        print("ok   non-hermetic host static-link smoke")


if __name__ == "__main__":
    main()
