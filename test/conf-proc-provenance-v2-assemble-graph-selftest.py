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
from conf_proc_build_graph import _resolve_library, extract_graph  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    Path(path).write_bytes(data)


def _unit(*, exec_path: str = "/usr/bin/app", deny: bool = True, network_scope: str = "none", no_new_privileges: str = "yes", ambient: str = "", bounding: str = "CAP_NET_BIND_SERVICE") -> bytes:
    lines = ["[Service]", "ExecStart=" + exec_path]
    if deny:
        lines.append("IPAddressDeny=any")
        if network_scope == "loopback":
            lines.append("IPAddressAllow=127.0.0.0/8")
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
        payload = b""
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

        data_only = os.path.join(self.base, "models-executable")
        executable = os.path.join(data_only, "weights.bin")
        _write(executable, b"model")
        os.chmod(executable, 0o755)
        with self.assertRaises(ApplianceError) as context:
            assembler._validate_models_data_only(data_only)
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

    def test_raw_service_exec_collisions_are_rejected_before_graph_projection(self) -> None:
        tree, payload = self._runtime_tree()
        _write(os.path.join(tree, "etc/systemd/system/other.service"), _unit(network_scope="loopback"))
        with self.assertRaises(ApplianceError) as context:
            assembler._observe_graphs(
                {"models": os.path.join(self.base, "models-empty"), "runtime-policy": tree},
                _policy(payload),
            )
        self.assertEqual(context.exception.reason_code, "CP_POLICY_UNSUPPORTED_ACTIVATION")

    def test_strict_closure_expands_once_for_every_activation_kind(self) -> None:
        payload = b"#!/bin/sh\nexit 0\n"
        tree = os.path.join(self.base, "all-activation-kinds")
        _write(os.path.join(tree, "usr/bin/app"), b"#!/usr/bin/interpreter\nexit 0\n")
        _write(os.path.join(tree, "usr/bin/interpreter"), b"")
        _write(
            os.path.join(tree, "etc/dbus-1/system-services/org.example.service"),
            b"[D-BUS Service]\nExec=/usr/bin/app\n",
        )
        _write(
            os.path.join(tree, "etc/udev/rules.d/99-app.rules"),
            b'SUBSYSTEM=="fixture", PROGRAM=="/usr/bin/app"\n',
        )
        _write(os.path.join(tree, "etc/cron.d/app"), b"* * * * * root /usr/bin/app\n")
        nodes, edges = extract_graph(tree, reject_raw_collisions=True)
        interpreter_edges = [edge for edge in edges if edge["kind"] == "script_interpreter"]
        self.assertEqual(len(interpreter_edges), 1)
        self.assertEqual(interpreter_edges[0]["to_id"], "interpreter:/usr/bin/interpreter")
        self.assertEqual(
            {edge["kind"] for edge in edges if edge["to_id"] == "exec:/usr/bin/app"},
            {"dbus_activation", "udev_activation", "cron_activation"},
        )

        shared = os.path.join(self.base, "shared-systemd-exec")
        _write(os.path.join(shared, "usr/bin/app"), b"#!/usr/bin/interpreter\nexit 0\n")
        _write(os.path.join(shared, "usr/bin/interpreter"), b"")
        _write(os.path.join(shared, "etc/systemd/system/first.service"), _unit())
        _write(os.path.join(shared, "etc/systemd/system/second.service"), _unit())
        _nodes, shared_edges = extract_graph(shared, reject_raw_collisions=True)
        self.assertEqual(len([edge for edge in shared_edges if edge["kind"] == "script_interpreter"]), 1)

        cross_kind = os.path.join(self.base, "cross-kind")
        _write(os.path.join(cross_kind, "usr/bin/app"), payload)
        _write(os.path.join(cross_kind, "etc/systemd/system/h3.service"), _unit(exec_path="/usr/bin/app --service"))
        _write(
            os.path.join(cross_kind, "etc/udev/rules.d/99-h3.rules"),
            b'SUBSYSTEM=="fixture", RUN+="/usr/bin/app --udev"\n',
        )
        with self.assertRaises(ApplianceError) as context:
            extract_graph(cross_kind, reject_raw_collisions=True)
        self.assertEqual(context.exception.reason_code, "CP_POLICY_UNSUPPORTED_ACTIVATION")

        duplicate_edge = os.path.join(self.base, "duplicate-edge")
        _write(os.path.join(duplicate_edge, "usr/bin/app"), payload)
        _write(
            os.path.join(duplicate_edge, "etc/systemd/system/h3.service"),
            _unit() + b"[Unit]\nAfter=network.target\nAfter=network.target\n",
        )
        with self.assertRaises(ApplianceError) as context:
            extract_graph(duplicate_edge, reject_raw_collisions=True)
        self.assertEqual(context.exception.reason_code, "CP_POLICY_UNSUPPORTED_ACTIVATION")

    def test_strict_closure_is_recursive_and_missing_interpreters_fail_closed(self) -> None:
        missing = os.path.join(self.base, "missing-interpreter")
        _write(os.path.join(missing, "usr/bin/app"), b"#!/usr/bin/not-present\nexit 0\n")
        _write(os.path.join(missing, "etc/systemd/system/h3.service"), _unit())
        with self.assertRaises(ApplianceError) as context:
            extract_graph(missing, reject_raw_collisions=True)
        self.assertEqual(context.exception.reason_code, "CP_POLICY_UNSUPPORTED_ACTIVATION")
        legacy_nodes, legacy_edges = extract_graph(missing)
        self.assertIn("exec:/usr/bin/app", {node["id"] for node in legacy_nodes})
        self.assertNotIn("script_interpreter", {edge["kind"] for edge in legacy_edges})

        nested = os.path.join(self.base, "nested-interpreters")
        _write(os.path.join(nested, "usr/bin/app"), b"#!/usr/bin/middle\nexit 0\n")
        _write(os.path.join(nested, "usr/bin/middle"), b"#!/usr/bin/final\nexit 0\n")
        _write(os.path.join(nested, "usr/bin/final"), b"")
        _write(os.path.join(nested, "etc/systemd/system/h3.service"), _unit())
        _nodes, nested_edges = extract_graph(nested, reject_raw_collisions=True)
        self.assertEqual(
            {
                (edge["from_id"], edge["to_id"])
                for edge in nested_edges
                if edge["kind"] == "script_interpreter"
            },
            {
                ("exec:/usr/bin/app", "interpreter:/usr/bin/middle"),
                ("interpreter:/usr/bin/middle", "interpreter:/usr/bin/final"),
            },
        )

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

        for relative in (
            "etc/systemd/system/h3.service.d/override.conf",
            "usr/lib/systemd/user/user.service",
            "etc/init.d/legacy",
            "etc/systemd/system/trigger.path",
            "usr/local/lib/systemd/system-generators/evil",
            "usr/lib/systemd/system-generators.early/evil",
            "lib/udev/rules.d/99-evil.rules",
            "etc/crontab",
            "etc/rc.local",
            "etc/inittab",
            "etc/init/evil.conf",
        ):
            unmodeled = os.path.join(self.base, "unmodeled-" + str(len(relative)))
            _write(os.path.join(unmodeled, relative), b"[Service]\nNoNewPrivileges=no\n")
            with self.assertRaises(ApplianceError) as context:
                assembler._validate_runtime_service_policy(unmodeled, SimpleNamespace(capability_policy={}))
            self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")

        assembler._validate_activation_path("etc/dbus-1/system-services/org.example.service")
        assembler._validate_activation_path("usr/lib/systemd/system-generators/allowed")

    def test_unmodeled_activation_directives_and_indirection_are_rejected(self) -> None:
        tree, _payload = self._runtime_tree(_unit() + b"ExecStartPre=/usr/bin/evil --hidden\n")
        with self.assertRaises(ApplianceError) as context:
            assembler._validate_runtime_service_policy(tree, _policy(b"#!/bin/sh\nexit 0\n"))
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")

        for relative, body in (
            ("etc/systemd/system/fail.service", _unit() + b"[Unit]\nOnFailure=rescue.service\n"),
            ("etc/systemd/system/shell.service", _unit(exec_path="/bin/sh -c /usr/bin/evil")),
            ("etc/systemd/system/hidden.socket", b"[Socket]\nService=evil.service\n"),
            ("etc/systemd/system/hidden.timer", b"[Timer]\nUnit=evil.service\n"),
            ("etc/udev/rules.d/99-hidden.rules", b'ENV{SYSTEMD_WANTS}+="evil.service"\n'),
            ("etc/cron.d/hidden", b"* * * * * root /usr/bin/app --hidden\n"),
            ("etc/cron.hourly/hidden", b"#!/bin/sh\n/usr/bin/evil\n"),
            ("etc/systemd/system/quoted.service", _unit(exec_path='/usr/bin/app "arg with spaces"')),
            ("etc/dbus-1/system-services/escaped.service", b"[D-BUS Service]\nExec=/usr/bin/app arg\\ with\\ spaces\n"),
            ("etc/systemd/system/quoted-dependency.service", _unit() + b"[Unit]\nRequires=\"evil.service\"\n"),
            ("etc/systemd/system/specifier.service", _unit() + b"[Unit]\nAfter=worker@%i.service\n"),
            ("etc/udev/rules.d/99-spaced-tag.rules", b'TAG += "systemd"\n'),
            ("etc/udev/rules.d/99-builtin.rules", b'IMPORT{builtin}="systemd"\n'),
            ("etc/udev/rules.d/99-import.rules", b'IMPORT{program}="/usr/bin/app"\n'),
            ("usr/lib/systemd/system-generators/hidden", b"#!/usr/bin/env -S sh -c /usr/bin/evil\nexit 0\n"),
        ):
            with self.assertRaises(ApplianceError):
                assembler._validate_activation_file(relative, body.decode("utf-8"))

        assembler._validate_activation_file(
            "etc/dbus-1/system-services/org.example.service",
            "[D-BUS Service]\nExec=/usr/bin/app\n",
        )
        assembler._validate_activation_file(
            "etc/udev/rules.d/99-program.rules",
            'PROGRAM=="/usr/bin/app"\n',
        )

    def test_strict_graph_paths_cannot_escape_the_frozen_image(self) -> None:
        escape = os.path.join(self.base, "escape")
        _write(os.path.join(escape, "etc/systemd/system/h3.service"), _unit(exec_path="/../../etc/passwd"))
        with self.assertRaises(ApplianceError) as context:
            extract_graph(escape, reject_raw_collisions=True)
        self.assertEqual(context.exception.reason_code, "CP_POLICY_UNSUPPORTED_ACTIVATION")

        interpreter = os.path.join(self.base, "interpreter-escape")
        _write(os.path.join(interpreter, "etc/systemd/system/h3.service"), _unit())
        _write(os.path.join(interpreter, "usr/bin/app"), b"#!/../../etc/passwd\n")
        with self.assertRaises(ApplianceError) as context:
            extract_graph(interpreter, reject_raw_collisions=True)
        self.assertEqual(context.exception.reason_code, "CP_POLICY_UNSUPPORTED_ACTIVATION")

        libraries = os.path.join(self.base, "ambiguous-libraries")
        _write(os.path.join(libraries, "lib/libx.so.1"), b"first")
        _write(os.path.join(libraries, "usr/lib/libx.so.1"), b"second")
        with self.assertRaises(ApplianceError) as context:
            _resolve_library(libraries, "libx.so.1", strict_paths=True)
        self.assertEqual(context.exception.reason_code, "CP_POLICY_UNSUPPORTED_ACTIVATION")

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

        repeated_ambient = _unit() + b"AmbientCapabilities=CAP_SYS_ADMIN\n"
        _write(os.path.join(tree, "etc/systemd/system/h3.service"), repeated_ambient)
        with self.assertRaises(ApplianceError) as context:
            assembler._validate_runtime_service_policy(tree, policy)
        self.assertEqual(context.exception.reason_code, "CP_TREE_UNEXPECTED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
