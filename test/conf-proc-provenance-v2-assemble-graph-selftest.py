#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Graph and runtime-policy observation checks for dormant H3."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_provenance_v2_assemble as assembler  # noqa: E402
from conf_proc_build_graph import extract_graph  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    Path(path).write_bytes(data)


def _unit(*, exec_path: str = "/usr/bin/app", deny: bool = True, no_new_privileges: str = "yes", ambient: str = "", bounding: str = "CAP_NET_BIND_SERVICE") -> bytes:
    lines = ["[Service]", "ExecStart=" + exec_path]
    if deny:
        lines.append("IPAddressDeny=any")
    lines.extend(
        [
            "CapabilityBoundingSet=" + bounding,
            "AmbientCapabilities=" + ambient,
            "NoNewPrivileges=" + no_new_privileges,
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _policy(payload: bytes) -> SimpleNamespace:
    unit = SimpleNamespace(
        id="unit:h3.service", kind="unit", path="h3.service", sha256=None, argv=(), network_scope="none",
        capabilities=("CAP_NET_BIND_SERVICE",), source_input_id=None,
    )
    executable = SimpleNamespace(
        id="exec:/usr/bin/app", kind="exec", path="/usr/bin/app", sha256=_sha(payload), argv=("/usr/bin/app",),
        network_scope="none", capabilities=(), source_input_id=None,
    )
    edge = SimpleNamespace(
        from_id="unit:h3.service", to_id="exec:/usr/bin/app", kind="unit_exec", origin_path="h3.service", origin_key="ExecStart"
    )
    capability = SimpleNamespace(
        capability_bounding_set=("CAP_NET_BIND_SERVICE",), ambient_capabilities=(), no_new_privileges=True
    )
    return SimpleNamespace(
        process_nodes=(executable, unit), process_edges=(edge,), capability_policy={"unit:h3.service": capability}
    )


class H3GraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)

    def _runtime_tree(self, body: bytes | None = None) -> tuple[str, bytes]:
        tree = os.path.join(self.base, "runtime")
        payload = b"#!/bin/sh\nexit 0\n"
        _write(os.path.join(tree, "usr/bin/app"), payload)
        _write(os.path.join(tree, "etc/systemd/system/h3.service"), body or _unit())
        return tree, payload

    def test_models_activation_content_is_rejected(self) -> None:
        models = os.path.join(self.base, "models")
        runtime = os.path.join(self.base, "runtime-empty")
        _write(os.path.join(models, "etc/systemd/system/model.service"), _unit())
        _write(os.path.join(models, "usr/bin/app"), b"#!/bin/sh\nexit 0\n")
        os.makedirs(runtime)
        with self.assertRaises(ApplianceError) as context:
            assembler._observe_graphs({"models": models, "runtime-policy": runtime}, SimpleNamespace(process_nodes=(), process_edges=()))
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")

    def test_collision_preflight_rejects_conflicting_nodes_and_duplicate_edges(self) -> None:
        first = {"id": "unit:h3.service", "kind": "unit", "path": "h3.service"}
        changed = {"id": "unit:h3.service", "kind": "unit", "path": "other.service"}
        with self.assertRaises(ApplianceError) as context:
            assembler._merge_graph({}, {}, [first, changed], [])
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")
        edge = {"from_id": "a", "to_id": "b", "kind": "unit_exec", "origin_path": "a.service", "origin_key": "ExecStart"}
        with self.assertRaises(ApplianceError) as context:
            assembler._merge_graph({}, {}, [], [edge, edge])
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")

    def test_unlisted_activation_and_mount_are_rejected(self) -> None:
        tree = os.path.join(self.base, "bad-activation")
        _write(os.path.join(tree, "opt/hidden.socket"), b"[Socket]\n")
        with self.assertRaises(ApplianceError) as context:
            assembler._validate_runtime_service_policy(tree, SimpleNamespace(capability_policy={}))
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")
        mounted = os.path.join(self.base, "mount")
        _write(os.path.join(mounted, "anywhere/forbidden.mount"), b"[Mount]\n")
        with self.assertRaises(ApplianceError) as context:
            assembler._validate_runtime_service_policy(mounted, SimpleNamespace(capability_policy={}))
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")

    def test_policy_reality_rejects_weakened_unit_bodies(self) -> None:
        tree, payload = self._runtime_tree()
        policy = _policy(payload)
        assembler._validate_runtime_service_policy(tree, policy)
        assembler._observe_graphs({"models": os.path.join(self.base, "models-empty"), "runtime-policy": tree}, policy)

        _write(os.path.join(tree, "usr/bin/other"), payload)
        _write(os.path.join(tree, "etc/systemd/system/h3.service"), _unit(exec_path="/usr/bin/other"))
        with self.assertRaises(ApplianceError) as context:
            assembler._observe_graphs({"models": os.path.join(self.base, "models-empty"), "runtime-policy": tree}, policy)
        self.assertEqual(context.exception.reason_code, "CP_POLICY_GRAPH_MISMATCH")

        _write(os.path.join(tree, "etc/systemd/system/h3.service"), _unit(deny=False))
        with self.assertRaises(ApplianceError) as context:
            extract_graph(tree)
        self.assertEqual(context.exception.reason_code, "CP_POLICY_UNSUPPORTED_ACTIVATION")

        _write(os.path.join(tree, "etc/systemd/system/h3.service"), _unit(no_new_privileges="no"))
        with self.assertRaises(ApplianceError) as context:
            assembler._validate_runtime_service_policy(tree, policy)
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")

        _write(os.path.join(tree, "etc/systemd/system/h3.service"), _unit(ambient="CAP_SYS_ADMIN"))
        with self.assertRaises(ApplianceError) as context:
            assembler._validate_runtime_service_policy(tree, policy)
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")

        _write(os.path.join(tree, "etc/systemd/system/h3.service"), _unit(bounding="CAP_SYS_ADMIN"))
        with self.assertRaises(ApplianceError) as context:
            assembler._validate_runtime_service_policy(tree, policy)
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
