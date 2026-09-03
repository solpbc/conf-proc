#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""AC3 oracle, including a scratch-build removal of the pre-bind branch."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "spp-diag-trace-core-src/security/spp_diag_trace_core/core.c"
SHIM = ROOT / "test/spp-diag-trace-core-shim"


def mutation_proves_prebind_red() -> bool:
    source = CORE.read_text(encoding="utf-8")
    branch = (
        "\tif (core.runtime_phase < SPP_DIAG_TRACE_PHASE_INIT)\n"
        "\t\treturn SPP_DIAG_TRACE_ERR_INACTIVE;\n"
    )
    if source.count(branch) != 1:
        raise AssertionError("pre-bind interval branch is not uniquely mutable")
    mutated = source.replace(branch, "", 1)
    probe = """#include <linux/sched.h>
#include \"core.h\"
int main(void) {
  struct task_struct task = { .flags = PF_KTHREAD };
  spp_diag_trace_core_reset();
  return !spp_diag_trace_core_is_green() &&
         spp_diag_trace_core_runtime_task_exit(&task, 0) != SPP_DIAG_TRACE_ERR_INACTIVE ? 0 : 1;
}
"""
    with tempfile.TemporaryDirectory(prefix="k4-interval-", dir="/var/tmp") as tmp:
        tmp_path = Path(tmp)
        mutated_core = tmp_path / "core.c"
        probe_path = tmp_path / "probe.c"
        binary = tmp_path / "probe"
        mutated_core.write_text(mutated, encoding="utf-8")
        probe_path.write_text(probe, encoding="utf-8")
        command = [
            "cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
            "-DCONFIG_KUNIT=1", "-DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1",
            "-DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1",
            "-I", str(SHIM / "include"), "-I", str(ROOT / "spp-diag-trace-core-src/include"),
            "-I", str(CORE.parent), str(mutated_core),
            str(SHIM / "host_sha256.c"), str(SHIM / "host_vmalloc.c"),
            str(SHIM / "host_bootstrap.c"), str(SHIM / "host_ima.c"),
            str(CORE.parent / "runtime_fs.c"), str(SHIM / "host_securityfs.c"),
            str(probe_path), "-o", str(binary),
        ]
        built = subprocess.run(command, check=False, cwd=ROOT, capture_output=True, text=True)
        if built.returncode:
            raise AssertionError(f"scratch mutation build failed: {built.stderr}")
        return subprocess.run([str(binary)], check=False).returncode == 0


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: runtime-interval-boundary-oracle-selftest.py FIXTURE")
    output = subprocess.check_output([sys.argv[1]], text=True).strip()
    if output != "prebind=-108 active=0 sealing=12 sealed=-108":
        print(f"FAIL interval boundary output {output!r}")
        return 1
    if not mutation_proves_prebind_red():
        print("FAIL removing the pre-bind interval branch did not red the scratch fixture")
        return 1
    print("ok   runtime interval pre-bind inactive, sealing red, sealed inactive, mutation-red")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
