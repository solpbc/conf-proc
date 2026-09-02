#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fixed-point call-graph walk of the dormant SPP diagnostic trace core."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path


ENTRIES = (
    "spp_diag_trace_core_is_green",
    "spp_diag_trace_core_append",
    "spp_diag_trace_core_mark_failure",
)
BOOTSTRAP_ENTRIES = (
    "spp_diag_trace_bootstrap_init",
    "spp_diag_trace_bootstrap_bprm_check",
    "spp_diag_trace_bootstrap_ima_ready",
    "spp_diag_trace_bootstrap_release",
)
ALLOWED_LOCK = "spp_diag_trace_core_shim_lock"
LOCK_LEAVES = {
    "spp_diag_trace_core_shim_lock",
    "spp_diag_trace_core_shim_unlock",
}
FORBIDDEN = (
    "vmalloc",
    "vfree",
    "kmalloc",
    "kzalloc",
    "kvmalloc",
    "mutex_lock",
    "might_sleep",
    "down",
    "schedule",
    "pthread_mutex_lock",
    "raw_spin_lock",
)

FUNC_HEADER = re.compile(r"^[0-9a-f]+ <([^>]+)>:\s*$")
CALL_LINE = re.compile(r"\bcallq?\b")
LOCAL_CALLEE = re.compile(r"<([^>+]+)>\s*$")
RELOC = re.compile(r"R_X86_64_(?:PLT32|PC32)\s*([^\s]+)")


def _symbol_name(raw: str) -> str:
    name = raw.split("-", 1)[0].split("+", 1)[0]
    if name.startswith(".data") or name.startswith(".bss") or name.startswith(".rodata"):
        return ""
    if name.startswith(".text"):
        return ""
    return name


def parse_calls(obj_path: Path) -> dict[str, list[str]]:
    output = subprocess.check_output(
        ["objdump", "-d", "--reloc", str(obj_path)],
        text=True,
        stderr=subprocess.STDOUT,
    )
    graph: dict[str, list[str]] = defaultdict(list)
    current: str | None = None
    pending_call = False
    seen_in_fn: set[tuple[str, str]] = set()

    def add(callee: str) -> None:
        if current is None or not callee or callee == current:
            return
        key = (current, callee)
        if key in seen_in_fn:
            return
        seen_in_fn.add(key)
        graph[current].append(callee)

    for line in output.splitlines():
        header = FUNC_HEADER.match(line)
        if header:
            current = header.group(1)
            graph.setdefault(current, [])
            pending_call = False
            continue
        if current is None:
            continue
        reloc = RELOC.search(line)
        if pending_call and reloc:
            add(_symbol_name(reloc.group(1)))
            pending_call = False
            continue
        if not CALL_LINE.search(line):
            pending_call = False
            continue
        local = LOCAL_CALLEE.search(line)
        if local and "+" not in local.group(0):
            add(local.group(1))
            pending_call = False
            continue
        pending_call = True
        if reloc:
            add(_symbol_name(reloc.group(1)))
            pending_call = False
    return graph


def walk(graph: dict[str, list[str]], entries: tuple[str, ...]) -> tuple[set[str], set[str]]:
    reachable_fns: set[str] = set()
    reachable_callees: set[str] = set()
    queue = deque()
    for entry in entries:
        if entry in graph:
            queue.append(entry)
    visited: set[str] = set()
    while queue:
        name = queue.popleft()
        if name in visited:
            continue
        visited.add(name)
        reachable_fns.add(name)
        if name in LOCK_LEAVES:
            continue
        for callee in graph.get(name, []):
            reachable_callees.add(callee)
            if callee in graph and callee not in visited:
                queue.append(callee)
            elif callee not in graph:
                reachable_fns.add(callee)
    return reachable_fns, reachable_callees


def analyze(obj_path: Path) -> tuple[set[str], list[str], int]:
    graph = parse_calls(obj_path)
    missing = [name for name in ENTRIES if name not in graph]
    if missing:
        raise AssertionError(f"{obj_path.name}: missing entries {missing}")
    reachable, callees = walk(graph, ENTRIES)
    forbidden_hits = sorted(
        name for name in FORBIDDEN if name in reachable or name in callees
    )
    return reachable, forbidden_hits, len(FORBIDDEN)


def undefined_symbols(obj_path: Path) -> set[str]:
    output = subprocess.check_output(
        ["nm", "-u", str(obj_path)], text=True, stderr=subprocess.STDOUT
    )
    return {line.split()[-1] for line in output.splitlines() if line.split()}


def main() -> int:
    if os.environ.get("SPP_DIAG_TRACE_CORE_FORCE_FAIL") == "1":
        print("FAIL callgraph forced")
        return 1
    if len(sys.argv) not in (6, 7):
        raise SystemExit(
            "usage: conf-proc-spp-diag-trace-core-callgraph-selftest.py "
            "CORE.O NEG_VMALLOC.O NEG_SLEEP.O NEG_MUTEX.O NEG_ALT_LOCK.O [BOOTSTRAP.O]"
        )
    core_obj = Path(sys.argv[1])
    neg_objs = [
        (Path(sys.argv[2]), "vmalloc"),
        (Path(sys.argv[3]), "might_sleep"),
        (Path(sys.argv[4]), "mutex_lock"),
        (Path(sys.argv[5]), "raw_spin_lock"),
    ]
    graph = parse_calls(core_obj)
    reachable, forbidden_hits, forbidden_n = analyze(core_obj)
    if forbidden_hits:
        print(f"FAIL callgraph forbidden in production: {forbidden_hits}")
        return 1
    for entry in ENTRIES:
        fns, callees = walk(graph, (entry,))
        if ALLOWED_LOCK not in fns and ALLOWED_LOCK not in callees:
            print(f"FAIL callgraph {entry} does not reach {ALLOWED_LOCK}")
            return 1
    append_fns, append_callees = walk(graph, ("spp_diag_trace_core_append",))
    if "sha256" not in append_fns and "sha256" not in append_callees:
        print("FAIL callgraph append does not reach sha256")
        return 1
    if "sha256" not in undefined_symbols(core_obj):
        print("FAIL callgraph sha256 is not an unresolved production reference")
        return 1
    print(
        f"ok   callgraph reachable_functions={len(reachable)} "
        f"forbidden_checked={forbidden_n} entries={len(ENTRIES)} "
        "sha256=reachable-unresolved"
    )

    for path, expected in neg_objs:
        _reachable, hits, _n = analyze(path)
        if expected not in hits:
            print(
                f"FAIL callgraph negative {path.name} missed {expected}: hits={hits}"
            )
            return 1
        print(f"ok   callgraph-negative {path.name} caught={expected} hits={hits}")
    if len(sys.argv) == 7:
        bootstrap_obj = Path(sys.argv[6])
        bootstrap_graph = parse_calls(bootstrap_obj)
        missing = [name for name in BOOTSTRAP_ENTRIES if name not in bootstrap_graph]
        if missing:
            print(f"FAIL bootstrap callgraph missing entries {missing}")
            return 1
        reachable, callees = walk(bootstrap_graph, BOOTSTRAP_ENTRIES)
        forbidden = sorted(name for name in FORBIDDEN if name in reachable or name in callees)
        if forbidden:
            print(f"FAIL bootstrap callgraph forbidden {forbidden}")
            return 1
        print(f"ok   bootstrap-callgraph entries={len(BOOTSTRAP_ENTRIES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
