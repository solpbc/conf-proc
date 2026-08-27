#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Known-answer and hostile-input tests for provenance-v2 argv rendering."""

from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_provenance_render as renderer  # noqa: E402
import conf_proc_provenance_v2 as provenance  # noqa: E402
import conf_proc_reasons as reasons  # noqa: E402
from conf_proc_json import canonical_dumps, canonical_loads  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


_ARTIFACT_INPUT_SHA256 = "fa7c7bdf2d900a9cf3d83a75bce2a3a8abe3742cff75cf6cd322c271975178d5"
_ROOT_HASH = "b" * 64


def _build_stage(**overrides) -> renderer.BuildStageArgv:
    values = {
        "rules_bytes": provenance.supported_verity_rules_bytes(),
        "artifact_input_sha256": _ARTIFACT_INPUT_SHA256,
        "image_id": "runtime-policy",
        "mksquashfs_path": "/tools/mksquashfs",
        "veritysetup_path": "/tools/veritysetup",
        "tree_dir": "/work/tree",
        "squashfs_path": "/work/runtime-policy.squashfs",
        "hash_device_path": "/work/runtime-policy.verity",
        "pseudo_file_path": "/work/runtime-policy.pseudo",
    }
    values.update(overrides)
    return renderer.render_build_stage(**values)


def _verify_stage(**overrides) -> renderer.VerifyStageArgv:
    values = {
        "rules_bytes": provenance.supported_verity_rules_bytes(),
        "artifact_input_sha256": _ARTIFACT_INPUT_SHA256,
        "image_id": "runtime-policy",
        "veritysetup_path": "/tools/veritysetup",
        "squashfs_path": "/work/runtime-policy.squashfs",
        "hash_device_path": "/work/runtime-policy.verity",
        "root_hash": _ROOT_HASH,
    }
    values.update(overrides)
    return renderer.render_verify_stage(**values)


class ProvenanceRenderTests(unittest.TestCase):
    def assert_rejected(self, callback, expected_reason: str) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            callback()
        self.assertEqual(ctx.exception.reason_code, expected_reason)
        self.assertIn(ctx.exception.reason_code, reasons.ALL_REASON_CODES)

    def test_known_answer_geometry_fixture(self) -> None:
        runtime_policy = _build_stage()
        self.assertEqual(runtime_policy.build_epoch, 3157307227)
        self.assertEqual(runtime_policy.salt, "6264054e5d018c2ac028cb220f426fcc86516e93e6eeecc18ceb8a55aad24cf6")
        self.assertEqual(runtime_policy.uuid, "140be099-97dd-5845-9c61-6755ce1976b6")

        models = _build_stage(image_id="models")
        self.assertEqual(models.salt, "653164b98d60decf1523fe68b05b3f3f7cf63593a0834a728800a372fcd37d17")
        self.assertEqual(models.uuid, "a5640a08-4b9c-529b-9591-a86493dc41cd")

    def test_renders_exact_build_and_verify_argv(self) -> None:
        build = _build_stage()
        self.assertEqual(
            build.mksquashfs_argv,
            (
                "/tools/mksquashfs",
                "/work/tree",
                "/work/runtime-policy.squashfs",
                "-noappend",
                "-quiet",
                "-no-progress",
                "-all-time",
                "3157307227",
                "-mkfs-time",
                "3157307227",
                "-comp",
                "gzip",
                "-root-mode",
                "755",
                "-root-uid",
                "0",
                "-root-gid",
                "0",
                "-pf",
                "/work/runtime-policy.pseudo",
                "-exit-on-error",
                "-reproducible",
                "-processors",
                "1",
                "-b",
                "131072",
                "-Xcompression-level",
                "9",
                "-Xwindow-size",
                "15",
                "-Xstrategy",
                "default",
                "-no-tailends",
                "-exports",
                "-xattrs",
                "-offset",
                "0",
            ),
        )
        self.assertEqual(
            build.veritysetup_format_argv,
            (
                "/tools/veritysetup",
                "format",
                "/work/runtime-policy.squashfs",
                "/work/runtime-policy.verity",
                "--data-block-size=4096",
                "--hash-block-size=4096",
                "--hash=sha256",
                "--salt=6264054e5d018c2ac028cb220f426fcc86516e93e6eeecc18ceb8a55aad24cf6",
                "--uuid=140be099-97dd-5845-9c61-6755ce1976b6",
                "--format=1",
                "--hash-offset=0",
            ),
        )
        self.assertEqual(
            _verify_stage().veritysetup_verify_argv,
            (
                "/tools/veritysetup",
                "verify",
                "/work/runtime-policy.squashfs",
                "/work/runtime-policy.verity",
                _ROOT_HASH,
            ),
        )

    def test_rejects_rules_mutations_from_both_stages(self) -> None:
        for mutate in (
            lambda raw: raw["squashfs"].update(processors=2),
            lambda raw: raw["verity"].update(hash_offset_bytes=4096),
        ):
            raw = canonical_loads(provenance.supported_verity_rules_bytes())
            mutate(raw)
            rules_bytes = canonical_dumps(raw)
            self.assert_rejected(
                lambda rules_bytes=rules_bytes: _build_stage(rules_bytes=rules_bytes),
                "CP_VERITY_RULES_SCHEMA",
            )
            self.assert_rejected(
                lambda rules_bytes=rules_bytes: _verify_stage(rules_bytes=rules_bytes),
                "CP_VERITY_RULES_SCHEMA",
            )

    def test_rejects_invalid_geometry_inputs_from_both_stages(self) -> None:
        for digest in ("a" * 63, "A" * 64, "g" * 64):
            self.assert_rejected(
                lambda digest=digest: _build_stage(artifact_input_sha256=digest),
                "CP_VERITY_GEOMETRY",
            )
            self.assert_rejected(
                lambda digest=digest: _verify_stage(artifact_input_sha256=digest),
                "CP_VERITY_GEOMETRY",
            )
        self.assert_rejected(lambda: _build_stage(image_id="unknown"), "CP_VERITY_GEOMETRY")
        self.assert_rejected(lambda: _verify_stage(image_id="unknown"), "CP_VERITY_GEOMETRY")

    def test_rejects_invalid_root_hash(self) -> None:
        for root_hash in ("a" * 63, "A" * 64, "g" * 64):
            self.assert_rejected(
                lambda root_hash=root_hash: _verify_stage(root_hash=root_hash),
                "CP_VERITY_ROOT_MISMATCH",
            )

    def test_requires_a_pseudo_file(self) -> None:
        self.assert_rejected(lambda: _build_stage(pseudo_file_path=""), "CP_VERITY_GEOMETRY")
        self.assert_rejected(lambda: _build_stage(pseudo_file_path=None), "CP_VERITY_GEOMETRY")

    def test_has_no_derived_value_override_parameters(self) -> None:
        for function in (renderer.render_build_stage, renderer.render_verify_stage):
            parameters = inspect.signature(function).parameters
            for name in ("build_epoch", "salt", "uuid"):
                self.assertNotIn(name, parameters)


if __name__ == "__main__":
    unittest.main(verbosity=2)
