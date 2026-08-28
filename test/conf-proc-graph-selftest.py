#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftests for static process/activation graph extraction (AC9): pure
format parsers, the independent builder/inspector walkers agreeing on a
real fixture tree, and policy-closure comparison mutation cases."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_build_graph as build_graph  # noqa: E402
import conf_proc_elf as elf  # noqa: E402
import conf_proc_graph_compare as graph_compare  # noqa: E402
import conf_proc_inspect_graph as inspect_graph  # noqa: E402
import conf_proc_unit_parser as unit_parser  # noqa: E402
from conf_proc_policy import CapabilityPolicy, ImagePolicy, Policy, ProcessEdge, ProcessNode  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


class UnitParserTests(unittest.TestCase):
    def test_parse_systemd_unit_sections(self) -> None:
        text = "[Unit]\nAfter=a.service b.service\n\n[Service]\nExecStart=/usr/bin/x\n"
        sections = unit_parser.parse_systemd_unit(text)
        self.assertEqual(sections["Unit"]["After"], ["a.service b.service"])
        self.assertEqual(sections["Service"]["ExecStart"], ["/usr/bin/x"])

    def test_reject_line_outside_section(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            unit_parser.parse_systemd_unit("ExecStart=/usr/bin/x\n")
        self.assertEqual(ctx.exception.reason_code, "CP_POLICY_UNSUPPORTED_ACTIVATION")

    def test_parse_exec_line_requires_absolute(self) -> None:
        self.assertEqual(unit_parser.parse_exec_line("/usr/bin/x --flag"), ["/usr/bin/x", "--flag"])
        with self.assertRaises(ApplianceError):
            unit_parser.parse_exec_line("relative-cmd")

    def test_parse_udev_actions(self) -> None:
        text = 'SUBSYSTEM=="foo", RUN+="/usr/bin/bar --flag"\n'
        self.assertEqual(unit_parser.parse_udev_actions(text), ["/usr/bin/bar"])
        self.assertEqual(unit_parser.parse_udev_actions('PROGRAM=="/usr/bin/check"\n'), ["/usr/bin/check"])
        self.assertEqual(unit_parser.parse_udev_actions('PROGRAM!="/usr/bin/check"\n'), ["/usr/bin/check"])
        for unmodeled in (
            'TAG += "systemd"\n',
            'TAG = "systemd"\n',
            'TAG := "systemd"\n',
            'IMPORT{builtin}="systemd"\n',
            'IMPORT{program}="/usr/bin/check"\n',
            'ENV{SYSTEMD_\\\nWANTS}+="evil.service"\n',
        ):
            with self.assertRaises(ApplianceError):
                unit_parser.parse_udev_actions(unmodeled, reject_unmodeled=True)

    def test_systemd_section_extension_is_exactly_dbus(self) -> None:
        self.assertEqual(
            unit_parser.parse_systemd_unit("[D-BUS Service]\nExec=/usr/bin/app\n"),
            {"D-BUS Service": {"Exec": ["/usr/bin/app"]}},
        )
        with self.assertRaises(ApplianceError):
            unit_parser.parse_systemd_unit("[X-Foo]\nKey=value\n")

    def test_parse_crontab_lines(self) -> None:
        text = "*/5 * * * * root /usr/bin/cronjob --x\n"
        self.assertEqual(unit_parser.parse_crontab_lines(text), ["/usr/bin/cronjob"])
        with self.assertRaises(ApplianceError):
            unit_parser.parse_crontab_lines("garbage line\n")

    def test_parse_shebang(self) -> None:
        self.assertEqual(unit_parser.parse_shebang("#!/usr/bin/spp-shell\necho hi\n"), "/usr/bin/spp-shell")
        self.assertIsNone(unit_parser.parse_shebang("no shebang here\n"))
        with self.assertRaises(ApplianceError):
            unit_parser.parse_shebang("#!/usr/bin/env python3\n")

    def test_parse_narrow_shell_script(self) -> None:
        text = "#!/usr/bin/spp-shell\n# comment\n\nexec /usr/bin/worker --flag\nexit 0\n"
        self.assertEqual(unit_parser.parse_narrow_shell_script(text), ["/usr/bin/worker"])
        with self.assertRaises(ApplianceError):
            unit_parser.parse_narrow_shell_script("#!/usr/bin/spp-shell\nfoo=$(bar)\n")

    def test_parse_no_output_generator(self) -> None:
        unit_parser.parse_no_output_generator("#!/usr/bin/spp-shell\n# noop\nexit 0\n")
        with self.assertRaises(ApplianceError):
            unit_parser.parse_no_output_generator("#!/usr/bin/spp-shell\necho hi > /run/generated.unit\n")


class ElfParserTests(unittest.TestCase):
    def test_parse_real_binary(self) -> None:
        data = Path("/bin/true").read_bytes() if Path("/bin/true").exists() else Path("/usr/bin/true").read_bytes()
        info = elf.parse_elf(data)
        self.assertTrue(info.interpreter and info.interpreter.startswith("/"))
        self.assertIn("libc.so.6", info.needed)

    def test_reject_non_elf(self) -> None:
        with self.assertRaises(ApplianceError):
            elf.parse_elf(b"not an elf file")


def _write(path: str, content: bytes, *, mode: int = 0o644) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(content)
    os.chmod(path, mode)


class GraphExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.tree = os.path.join(self.base, "tree")

        _write(
            os.path.join(self.tree, "etc/systemd/system/conf-proc-final.service"),
            (
                b"[Unit]\nAfter=multi-user.target\n\n"
                b"[Service]\nExecStart=/usr/bin/spp-runner\n"
                b"IPAddressDeny=any\nIPAddressAllow=127.0.0.0/8\n"
                b"CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\n"
                b"[Install]\nWantedBy=multi-user.target\n"
            ),
        )
        _write(
            os.path.join(self.tree, "usr/bin/spp-runner"),
            b"#!/usr/bin/spp-shell-fixture\nexec /usr/bin/spp-worker\n",
            mode=0o755,
        )
        _write(os.path.join(self.tree, "usr/bin/spp-shell-fixture"), b"fake interpreter binary\n", mode=0o755)
        _write(os.path.join(self.tree, "usr/bin/spp-worker"), b"fake worker binary\n", mode=0o755)
        _write(
            os.path.join(self.tree, "etc/udev/rules.d/99-fixture.rules"),
            b'SUBSYSTEM=="fixture", RUN+="/usr/bin/spp-worker"\n',
        )
        _write(
            os.path.join(self.tree, "etc/cron.d/spp-fixture"),
            b"*/5 * * * * root /usr/bin/spp-worker\n",
        )

    def test_build_and_inspect_extraction_agree(self) -> None:
        build_nodes, build_edges = build_graph.extract_graph(self.tree)
        inspect_nodes, inspect_edges = inspect_graph.extract_graph(self.tree)

        build_node_keys = {n["id"]: n for n in build_nodes}
        inspect_node_keys = {n["id"]: n for n in inspect_nodes}
        self.assertEqual(set(build_node_keys), set(inspect_node_keys))
        for node_id in build_node_keys:
            self.assertEqual(build_node_keys[node_id], inspect_node_keys[node_id])

        build_edge_set = {(e["from_id"], e["to_id"], e["kind"], e["origin_path"], e["origin_key"]) for e in build_edges}
        inspect_edge_set = {(e["from_id"], e["to_id"], e["kind"], e["origin_path"], e["origin_key"]) for e in inspect_edges}
        self.assertEqual(build_edge_set, inspect_edge_set)

        expected_node_ids = {
            "unit:conf-proc-final.service", "exec:/usr/bin/spp-runner", "interpreter:/usr/bin/spp-shell-fixture",
            "exec:/usr/bin/spp-worker", "udev_rule:99-fixture.rules", "cron_job:etc/cron.d/spp-fixture",
        }
        self.assertEqual(set(build_node_keys), expected_node_ids)

        expected_edges = {
            ("unit:conf-proc-final.service", "unit:multi-user.target", "unit_dependency", "conf-proc-final.service", "After"),
            ("unit:conf-proc-final.service", "unit:multi-user.target", "install_enablement", "conf-proc-final.service", "WantedBy"),
            ("unit:conf-proc-final.service", "exec:/usr/bin/spp-runner", "unit_exec", "conf-proc-final.service", "ExecStart"),
            ("exec:/usr/bin/spp-runner", "interpreter:/usr/bin/spp-shell-fixture", "script_interpreter", "/usr/bin/spp-runner", "shebang"),
            ("exec:/usr/bin/spp-runner", "exec:/usr/bin/spp-worker", "shell_child", "/usr/bin/spp-runner", "invocation"),
            ("udev_rule:99-fixture.rules", "exec:/usr/bin/spp-worker", "udev_activation", "99-fixture.rules", "action"),
            ("cron_job:etc/cron.d/spp-fixture", "exec:/usr/bin/spp-worker", "cron_activation", "spp-fixture", "command"),
        }
        self.assertEqual(build_edge_set, expected_edges)

    def _build_policy(self, nodes: list[dict], edges: list[dict]) -> Policy:
        process_nodes = tuple(
            sorted(
                (
                    ProcessNode(
                        id=n["id"], kind=n["kind"], path=n["path"], sha256=n["sha256"], argv=tuple(n["argv"]),
                        network_scope=n["network_scope"], capabilities=tuple(n["capabilities"]), source_input_id=None,
                    )
                    for n in nodes
                ),
                key=lambda node: node.id,
            )
        )
        process_edges = tuple(
            sorted(
                (ProcessEdge(from_id=e["from_id"], to_id=e["to_id"], kind=e["kind"], origin_path=e["origin_path"], origin_key=e["origin_key"]) for e in edges),
                key=lambda edge: (edge.from_id, edge.to_id, edge.kind, edge.origin_path, edge.origin_key),
            )
        )
        return Policy(
            schema="conf-proc-policy/v1", policy_version=1,
            images={"runtime-policy": ImagePolicy(nodes=()), "models": ImagePolicy(nodes=())},
            boot_roots=(), process_nodes=process_nodes, process_edges=process_edges, mounts=(),
            network_policy={}, capability_policy={},
        )

    def test_matching_policy_closes_cleanly(self) -> None:
        nodes, edges = build_graph.extract_graph(self.tree)
        policy = self._build_policy(nodes, edges)
        graph_compare.compare_graph_to_policy(nodes, edges, policy)

    def test_extra_actual_node_is_rejected(self) -> None:
        nodes, edges = build_graph.extract_graph(self.tree)
        policy = self._build_policy([n for n in nodes if n["id"] != "udev_rule:99-fixture.rules"], edges)
        with self.assertRaises(ApplianceError) as ctx:
            graph_compare.compare_graph_to_policy(nodes, edges, policy)
        self.assertEqual(ctx.exception.reason_code, "CP_POLICY_GRAPH_MISMATCH")

    def test_missing_actual_node_is_rejected(self) -> None:
        nodes, edges = build_graph.extract_graph(self.tree)
        extra_node = dict(nodes[0])
        extra_node["id"] = "unit:phantom.service"
        extra_node["path"] = "phantom.service"
        policy = self._build_policy(nodes + [extra_node], edges)
        with self.assertRaises(ApplianceError) as ctx:
            graph_compare.compare_graph_to_policy(nodes, edges, policy)
        self.assertEqual(ctx.exception.reason_code, "CP_POLICY_GRAPH_MISMATCH")

    def test_extra_actual_edge_is_rejected(self) -> None:
        nodes, edges = build_graph.extract_graph(self.tree)
        trimmed_edges = [e for e in edges if e["kind"] != "cron_activation"]
        policy = self._build_policy(nodes, trimmed_edges)
        with self.assertRaises(ApplianceError) as ctx:
            graph_compare.compare_graph_to_policy(nodes, edges, policy)
        self.assertEqual(ctx.exception.reason_code, "CP_POLICY_GRAPH_MISMATCH")


if __name__ == "__main__":
    unittest.main(verbosity=2)
