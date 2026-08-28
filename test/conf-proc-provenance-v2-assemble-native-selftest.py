#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Native-tool and inode-pinning checks for dormant H3 assembly."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_geometry as geometry  # noqa: E402
import conf_proc_provenance_render as render  # noqa: E402
import conf_proc_provenance_v2 as provenance  # noqa: E402
import conf_proc_provenance_v2_assemble as assembler  # noqa: E402
from conf_proc_guard import HermeticGuard, ToolDeclaration  # noqa: E402
from conf_proc_guard_setup import resolve_tool_absolute_path  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


TOOLS = {
    "mksquashfs": "/usr/bin/mksquashfs",
    "unsquashfs": "/usr/bin/unsquashfs",
    "veritysetup": "/usr/sbin/veritysetup",
    "openssl": "/usr/bin/openssl",
}


def _sha_file(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _guard(paths: dict[str, str] = TOOLS) -> HermeticGuard:
    declarations = {path: ToolDeclaration(path, _sha_file(path)) for path in paths.values()}
    return HermeticGuard(
        allowed_reads=frozenset(paths.values()),
        tools=declarations,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"},
        build_epoch=946684800,
    )


class H3NativeToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)

    def test_pinned_descriptor_executes_after_path_replacement(self) -> None:
        original = os.path.join(self.base, "tool")
        replacement = os.path.join(self.base, "replacement")
        shutil.copy2("/bin/true", original)
        Path(replacement).write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
        os.chmod(replacement, 0o755)
        guard = HermeticGuard(
            allowed_reads=frozenset({original}),
            tools={original: ToolDeclaration(original, _sha_file(original))},
            env={"PATH": "/usr/bin", "LC_ALL": "C", "TZ": "UTC"},
            build_epoch=946684800,
        )
        with self.assertRaises(ApplianceError) as context:
            with guard.pin_tools((original,)):
                self.assertIn(original, guard._pinned_tools)
                os.rename(replacement, original)
                result = guard.run_tool([original], cwd=self.base)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(context.exception.reason_code, "CP_TOOL_PIN_CHANGED")

    def test_real_squashfs_verity_cycle_and_unsquash_validation(self) -> None:
        guard = _guard()
        guard.resolve_tool(TOOLS["unsquashfs"])
        tree = os.path.join(self.base, "tree")
        os.makedirs(tree)
        Path(os.path.join(tree, "payload")).write_bytes(b"native H3 payload\n")
        pseudo = os.path.join(self.base, "tree.pseudo")
        Path(pseudo).write_text("/payload m 0644 0 0\n", encoding="utf-8")
        squashfs = os.path.join(self.base, "models.squashfs")
        hash_device = os.path.join(self.base, "models.verity")
        artifact = "1" * 64
        build = render.render_build_stage(
            provenance.supported_verity_rules_bytes(),
            artifact_input_sha256=artifact,
            image_id="models",
            mksquashfs_path=TOOLS["mksquashfs"],
            veritysetup_path=TOOLS["veritysetup"],
            tree_dir=tree,
            squashfs_path=squashfs,
            hash_device_path=hash_device,
            pseudo_file_path=pseudo,
        )
        with guard.pin_tools((TOOLS["mksquashfs"], TOOLS["veritysetup"], TOOLS["openssl"])):
            self.assertEqual(guard.run_tool(list(build.mksquashfs_argv), cwd=self.base).returncode, 0)
            geometry.pad_file_to_block_size(squashfs)
            formatted = guard.run_tool(list(build.veritysetup_format_argv), cwd=self.base)
            root_hash = assembler._parse_root_hash(formatted.stdout)
            verify = render.render_verify_stage(
                provenance.supported_verity_rules_bytes(),
                artifact_input_sha256=artifact,
                image_id="models",
                veritysetup_path=TOOLS["veritysetup"],
                squashfs_path=squashfs,
                hash_device_path=hash_device,
                root_hash=root_hash,
            )
            self.assertEqual(guard.run_tool(list(verify.veritysetup_verify_argv), cwd=self.base).returncode, 0)
            self.assertEqual(guard.run_tool([TOOLS["openssl"], "version"], cwd=self.base).returncode, 0)
        self.assertEqual(os.path.getsize(squashfs) % 4096, 0)
        self.assertTrue(os.path.getsize(hash_device) > 0)

    def test_malformed_native_result_and_missing_tool_fail_hard(self) -> None:
        fake = os.path.join(self.base, "veritysetup")
        Path(fake).write_text("#!/bin/sh\nprintf 'Root hash: not-a-digest\\n'\n", encoding="utf-8")
        os.chmod(fake, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        guard = _guard({"veritysetup": fake})
        with guard.pin_tools((fake,)):
            result = guard.run_tool([fake, "format"], cwd=self.base)
        with self.assertRaises(ApplianceError) as context:
            assembler._parse_root_hash(result.stdout)
        self.assertEqual(context.exception.reason_code, "CP_VERITY_FORMAT")
        empty = os.path.join(self.base, "empty-tools")
        os.mkdir(empty)
        with self.assertRaises(ApplianceError) as context:
            resolve_tool_absolute_path(empty, "mksquashfs")
        self.assertEqual(context.exception.reason_code, "CP_TOOL_MISSING")


if __name__ == "__main__":
    unittest.main(verbosity=2)
