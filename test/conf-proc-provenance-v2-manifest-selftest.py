#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Focused producer tests for dormant provenance-v2 manifests."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_provenance_v2 as provenance  # noqa: E402
import conf_proc_reasons as reasons  # noqa: E402
from conf_proc_json import canonical_dumps, canonical_loads  # noqa: E402
from conf_proc_lock import parse_lock  # noqa: E402
from conf_proc_provenance_v2_build_manifest import (  # noqa: E402
    ProvenanceV2FirmwareObservation,
    ProvenanceV2ImageRecord,
    ProvenanceV2ModuleObservation,
    _selfcheck,
    produce_provenance_v2,
)
from conf_proc_provenance_v2_manifest import parse_manifest_v2  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


_SINGLE_ROLES = (
    "kernel",
    "kernel_trusted_cert_bundle",
    "final_systemd_stub",
    "final_systemd_unit",
    "nvidia_cc_driver",
    "nvidia_cc_firmware",
    "sglang_image",
    "inference_model",
    "asr_model",
    "gateway_dependency_lock",
    "asr_dependency_lock",
)
_SIGNER = format(401, "064x")


def _sha(value: int) -> str:
    return format(value, "064x")


def _placement(input_id: str, path: str, image: str = "runtime-policy") -> dict:
    return {
        "image": image,
        "path": path,
        "node_type": "file",
        "mode": 0o644,
        "uid": 0,
        "gid": 0,
        "xattrs": [],
        "source_input_id": input_id,
        "target": None,
    }


def _lock_input(
    input_id: str,
    role: str,
    digest: str,
    size_bytes: int,
    *,
    component: str | None = None,
    identity: str | None = None,
    placements: list[dict] | None = None,
) -> dict:
    if placements is None:
        placements = [] if role in ("build_tool", "kernel_trusted_cert_bundle") else [_placement(input_id, f"/fixture/{input_id}")]
    return {
        "id": input_id,
        "role": role,
        "component": component or input_id,
        "sha256": digest,
        "size_bytes": size_bytes,
        "source_local_path": f"fixtures/{input_id}",
        "source_retrieval_scheme": "local-fixture",
        "source_retrieval_identity": identity or f"fixture:{input_id}",
        "source_retrieval_immutable_ref": f"sha256:{digest}",
        "derivation_kind": "fixture",
        "derivation_recipe_id": "fixture-recipe-v1",
        "derivation_parent_ids": [],
        "derivation_parameters_sha256": _sha(90),
        "placements": placements,
    }


def _policy_bytes() -> bytes:
    return canonical_dumps(
        {
            "schema": "conf-proc-policy/v1",
            "policy_version": 1,
            "images": {
                "models": {
                    "nodes": [
                        {
                            "path": "/models/model.bin",
                            "node_type": "file",
                            "mode": 0o644,
                            "uid": 0,
                            "gid": 0,
                            "xattrs": [],
                            "source_input_id": "policy",
                            "target": None,
                            "content_class": "model",
                        }
                    ]
                },
                "runtime-policy": {
                    "nodes": [
                        {
                            "path": "/etc/spp/policy.json",
                            "node_type": "file",
                            "mode": 0o644,
                            "uid": 0,
                            "gid": 0,
                            "xattrs": [],
                            "source_input_id": "policy",
                            "target": None,
                            "content_class": "config",
                        },
                        {
                            "path": "/usr/lib/modules/fixture.ko",
                            "node_type": "file",
                            "mode": 0o644,
                            "uid": 0,
                            "gid": 0,
                            "xattrs": [],
                            "source_input_id": "driver",
                            "target": None,
                            "content_class": "executable",
                        },
                        {
                            "path": "/var/lib/fixture.data",
                            "node_type": "file",
                            "mode": 0o644,
                            "uid": 0,
                            "gid": 0,
                            "xattrs": [],
                            "source_input_id": "policy",
                            "target": None,
                            "content_class": "runtime_data",
                        },
                    ]
                },
            },
            "boot_roots": [],
            "process_nodes": [],
            "process_edges": [],
            "mounts": [],
            "network_policy": {},
            "capability_policy": {},
        }
    )


def _lock_bytes(builder_source_bytes: bytes, policy_bytes: bytes, *, ip_identity: bool = False) -> bytes:
    builder_sha = hashlib.sha256(builder_source_bytes).hexdigest()
    policy_sha = hashlib.sha256(policy_bytes).hexdigest()
    inputs = [
        _lock_input(
            "builder",
            "conf_proc_source",
            builder_sha,
            len(builder_source_bytes),
            component="conf-proc-source",
            identity="fixture:source",
            placements=[_placement("builder", "/opt/conf-proc/main.py")],
        ),
        _lock_input(
            "policy",
            "policy_tree_input",
            policy_sha,
            len(policy_bytes),
            component="process-policy",
            placements=[_placement("policy", "/etc/spp/policy.json")],
        ),
        _lock_input(
            "driver",
            "nvidia_cc_driver",
            _sha(201),
            1,
            placements=[_placement("driver", "/usr/lib/modules/fixture.ko")],
        ),
        _lock_input(
            "firmware",
            "nvidia_cc_firmware",
            _sha(202),
            1,
            placements=[_placement("firmware", "/usr/lib/firmware/fixture.bin")],
        ),
    ]
    for index, role in enumerate(_SINGLE_ROLES, start=10):
        if role in ("nvidia_cc_driver", "nvidia_cc_firmware"):
            continue
        identity = "fixture:host-203.0.113.7" if ip_identity and role == "kernel" else None
        inputs.append(_lock_input(role, role, _sha(index), 1, identity=identity))
    for index, tool in enumerate(("mksquashfs", "openssl", "unsquashfs", "veritysetup"), start=30):
        inputs.append(_lock_input(f"tool-{tool}", "build_tool", _sha(index), 1, component=tool))
    inputs.sort(key=lambda item: item["id"])
    return canonical_dumps(
        {
            "schema": "conf-proc-lock/v1",
            "lock_version": 1,
            "base_image_record": {
                "kind": "vhd",
                "provider": "fixture",
                "identity_namespace": "fixture",
                "identity_name": "base",
                "identity_immutable_revision": "fixture-revision",
                "content_sha256": _sha(60),
                "content_size_bytes": 1,
                "content_media_type": "application/octet-stream",
                "availability": "record-only",
                "recorded_retrieval_scheme": "local-fixture",
                "recorded_retrieval_identity": "fixture:base",
                "recorded_retrieval_immutable_ref": "fixture:base-revision",
            },
            "future_cmdline": "console=ttyS0",
            "inputs": inputs,
            "authorized_module_signers": [
                {
                    "certificate_sha256": _SIGNER,
                    "spki_sha256": _sha(402),
                    "subject_sha256": _sha(403),
                    "usage": "kernel-module-signing",
                }
            ],
            "image_specs": {"models": {}, "runtime-policy": {}},
            "policy_input_id": "policy",
            "tool_ids": sorted(f"tool-{tool}" for tool in ("mksquashfs", "openssl", "unsquashfs", "veritysetup")),
        }
    )


def _closure_bytes(builder_source_bytes: bytes, *, extra: bool = False) -> bytes:
    builder_sha = hashlib.sha256(builder_source_bytes).hexdigest()
    entries = [
        {
            "path": "/opt/conf-proc/main.py",
            "node_type": "file",
            "mode": 0o644,
            "uid": 0,
            "gid": 0,
            "size_bytes": len(builder_source_bytes),
            "sha256": builder_sha,
            "symlink_target": None,
            "hardlink_group": None,
            "xattrs": [],
            "capabilities": [],
            "logical_role": "conf_proc_source",
            "provenance": {"scheme": "local-fixture", "identity": "fixture:source", "immutable_ref": f"sha256:{builder_sha}"},
            "root_lock_input_id": "builder",
        }
    ]
    if extra:
        entries.append(
            {
                "path": "/usr/bin/extra",
                "node_type": "file",
                "mode": 0o755,
                "uid": 0,
                "gid": 0,
                "size_bytes": 1,
                "sha256": _sha(404),
                "symlink_target": None,
                "hardlink_group": None,
                "xattrs": [],
                "capabilities": [],
                "logical_role": "extra",
                "provenance": {"scheme": "local-fixture", "identity": "fixture:extra", "immutable_ref": f"sha256:{_sha(404)}"},
                "root_lock_input_id": None,
            }
        )
    return canonical_dumps({"schema": "conf-proc-runtime-closure/v1", "status": "declared_unverified", "entries": entries})


def _tcb_bytes(digest: str = _sha(405)) -> bytes:
    executable = lambda name, value: {
        "logical_name": name,
        "sha256": value,
        "linkage": "static",
        "interpreter_sha256": None,
        "loader_sha256": None,
        "library_sha256s": [],
    }
    return canonical_dumps(
        {
            "schema": "conf-proc-pre-sandbox-tcb/v1",
            "status": "declared_unverified",
            "caller": executable("caller", digest),
            "launcher": executable("launcher", _sha(406)),
            "sandbox": {"backend": "bubblewrap", "executable": executable("bwrap", _sha(407)), "helper": None},
            "kernel_feature_contract": {"schema": "conf-proc-kernel-features/v1", "sha256": _sha(408)},
        }
    )


def _bundle(*, ip_identity: bool = False, closure_extra: bool = False, tcb_digest: str = _sha(405)) -> dict:
    builder_source_bytes = b"fixture-builder-source"
    policy_bytes = _policy_bytes()
    return {
        "root_lock_bytes": _lock_bytes(builder_source_bytes, policy_bytes, ip_identity=ip_identity),
        "runtime_closure_bytes": _closure_bytes(builder_source_bytes, extra=closure_extra),
        "verity_rules_bytes": provenance.supported_verity_rules_bytes(),
        "tcb_identity_bytes": _tcb_bytes(tcb_digest),
        "builder_source_bytes": builder_source_bytes,
        "policy_bytes": policy_bytes,
    }


def _images() -> tuple[ProvenanceV2ImageRecord, ProvenanceV2ImageRecord]:
    return (
        ProvenanceV2ImageRecord("models", _sha(501), 4096, _sha(502), 4096, _sha(503)),
        ProvenanceV2ImageRecord("runtime-policy", _sha(504), 4096, _sha(505), 4096, _sha(506)),
    )


def _module_observations() -> tuple[ProvenanceV2ModuleObservation, ...]:
    return (ProvenanceV2ModuleObservation("/usr/lib/modules/fixture.ko", _sha(201), _SIGNER),)


def _firmware_observations() -> tuple[ProvenanceV2FirmwareObservation, ...]:
    return (ProvenanceV2FirmwareObservation("/usr/lib/firmware/fixture.bin", _sha(202)),)


def _produce(**overrides):
    values = _bundle()
    values.update(
        {
            "images": _images(),
            "module_observations": _module_observations(),
            "firmware_observations": _firmware_observations(),
        }
    )
    values.update(overrides)
    return produce_provenance_v2(**values)


class ProvenanceV2ManifestTests(unittest.TestCase):
    def assert_rejected(self, callback, expected_reason: str) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            callback()
        self.assertEqual(ctx.exception.reason_code, expected_reason)
        self.assertIn(ctx.exception.reason_code, reasons.ALL_REASON_CODES)

    def test_produces_exact_binding_geometry_and_policy_categories(self) -> None:
        values = _bundle(ip_identity=True)
        artifact = produce_provenance_v2(
            **values,
            images=_images(),
            module_observations=_module_observations(),
            firmware_observations=_firmware_observations(),
        )
        manifest = parse_manifest_v2(artifact.manifest_bytes).raw
        inputs = provenance.derive_inputs(**values)
        self.assertEqual(manifest["lock_sha256"], inputs.artifact_input_sha256)
        self.assertEqual(manifest["provenance"]["execution_provenance_sha256"], inputs.execution_provenance_sha256)
        self.assertEqual(manifest["reproducibility"]["build_epoch"], 1192808402)
        self.assertEqual(manifest["images"]["models"]["salt"], "d2f786b50e67d6dc0731b3d5545e5dad9f704469cc8af8b9343c92ae7c453413")
        self.assertEqual(manifest["bindings"]["runtime-policy"], {
            "executables": ["/usr/lib/modules/fixture.ko"],
            "configs": ["/etc/spp/policy.json"],
            "models": [],
            "runtime_inputs": ["/var/lib/fixture.data"],
        })
        kernel = next(item for item in manifest["inputs"] if item["id"] == "kernel")
        self.assertEqual(kernel["source_retrieval_identity"], "fixture:host-203.0.113.7")
        self.assertEqual(manifest["module_authority"]["module_inventory"], [
            {"path": "/usr/lib/modules/fixture.ko", "sha256": _sha(201), "signer_certificate_sha256": _SIGNER}
        ])

    def test_output_is_byte_identical_when_image_tuple_order_changes(self) -> None:
        first = _produce()
        second = _produce(images=tuple(reversed(_images())))
        self.assertEqual(first, second)

    def test_rejects_invalid_image_records_and_observations(self) -> None:
        self.assert_rejected(
            lambda: _produce(images=(ProvenanceV2ImageRecord("models", "A" * 64, 1, _sha(2), 1, _sha(3)), _images()[1])),
            "CP_PROVENANCE_V2_IMAGE_GEOMETRY",
        )
        self.assert_rejected(
            lambda: _produce(module_observations=()),
            "CP_PROVENANCE_V2_MANIFEST_PRODUCTION",
        )
        self.assert_rejected(
            lambda: _produce(firmware_observations=()),
            "CP_PROVENANCE_V2_MANIFEST_PRODUCTION",
        )
        self.assert_rejected(
            lambda: _produce(module_observations=(ProvenanceV2ModuleObservation("/usr/lib/modules/fixture.ko", _sha(201), _sha(99)),)),
            "CP_MODULE_SIGNER",
        )
        self.assert_rejected(
            lambda: _produce(firmware_observations=(ProvenanceV2FirmwareObservation("/extra", _sha(1)),)),
            "CP_PROVENANCE_V2_MANIFEST_PRODUCTION",
        )
        self.assert_rejected(
            lambda: _produce(module_observations=(ProvenanceV2ModuleObservation("/usr/lib/modules/fixture.ko", _sha(99), _SIGNER),)),
            "CP_PROVENANCE_V2_MANIFEST_PRODUCTION",
        )
        self.assert_rejected(
            lambda: _produce(
                firmware_observations=(ProvenanceV2FirmwareObservation("/usr/lib/firmware/fixture.bin", _sha(99)),)
            ),
            "CP_PROVENANCE_V2_MANIFEST_PRODUCTION",
        )

    def test_rejects_qualifying_collisions_and_compressed_modules(self) -> None:
        raw = canonical_loads(_bundle()["root_lock_bytes"])
        raw["inputs"].append(_lock_input("extra", "runtime_tree_input", _sha(601), 1, placements=[_placement("extra", "/usr/lib/modules/fixture.ko", "models")]))
        raw["inputs"].sort(key=lambda item: item["id"])
        self.assert_rejected(
            lambda: _produce(root_lock_bytes=canonical_dumps(raw)),
            "CP_PROVENANCE_V2_MANIFEST_PRODUCTION",
        )
        raw = canonical_loads(_bundle()["root_lock_bytes"])
        raw["inputs"].append(_lock_input("extra", "runtime_tree_input", _sha(602), 1, placements=[_placement("extra", "/usr/lib/modules/fixture.ko")]))
        raw["inputs"].sort(key=lambda item: item["id"])
        self.assert_rejected(
            lambda: _produce(root_lock_bytes=canonical_dumps(raw)),
            "CP_PROVENANCE_V2_MANIFEST_PRODUCTION",
        )
        raw = canonical_loads(_bundle()["root_lock_bytes"])
        next(item for item in raw["inputs"] if item["id"] == "driver")["placements"][0]["path"] = "/usr/lib/modules/fixture.ko.zst"
        self.assert_rejected(
            lambda: _produce(root_lock_bytes=canonical_dumps(raw)),
            "CP_MODULE_COMPRESSED_UNSUPPORTED",
        )

    def test_manifest_structure_rejects_fields_without_scanning_values(self) -> None:
        artifact = _produce()
        raw = canonical_loads(artifact.manifest_bytes)
        raw["unexpected"] = "203.0.113.9"
        self.assert_rejected(
            lambda: parse_manifest_v2(canonical_dumps(raw)),
            "CP_PROVENANCE_V2_MANIFEST_FORBIDDEN_FIELD",
        )
        raw = canonical_loads(artifact.manifest_bytes)
        raw["inputs"][0]["source_retrieval_identity"] = "allowed-192.0.2.1"
        self.assertEqual(parse_manifest_v2(canonical_dumps(raw)).raw["inputs"][0]["source_retrieval_identity"], "allowed-192.0.2.1")

    def test_manifest_schema_rejects_tampered_image_geometry(self) -> None:
        artifact = _produce()
        for field, value in (
            ("uuid", "550e8400-e29b-41d4-a716-446655440000"),
            ("data_block_size", 512),
            ("hash_block_size", 512),
            ("squashfs_sha256", "A" * 64),
            ("squashfs_sha256", "a" * 63),
        ):
            raw = canonical_loads(artifact.manifest_bytes)
            raw["images"]["models"][field] = value
            self.assert_rejected(
                lambda raw=raw: parse_manifest_v2(canonical_dumps(raw)),
                "CP_PROVENANCE_V2_MANIFEST_PRODUCTION",
            )

    def test_root_lock_projection_matches_parsed_lock_field_by_field(self) -> None:
        values = _bundle(ip_identity=True)
        manifest = parse_manifest_v2(
            produce_provenance_v2(
                **values,
                images=_images(),
                module_observations=_module_observations(),
                firmware_observations=_firmware_observations(),
            ).manifest_bytes
        ).raw
        lock = parse_lock(values["root_lock_bytes"])
        self.assertEqual(manifest["lock_schema"], lock.schema)
        self.assertEqual(manifest["future_cmdline"], lock.future_cmdline)
        self.assertEqual(
            manifest["base_image_record"],
            {
                name: getattr(lock.base_image_record, name)
                for name in (
                    "kind",
                    "provider",
                    "identity_namespace",
                    "identity_name",
                    "identity_immutable_revision",
                    "content_sha256",
                    "content_size_bytes",
                    "content_media_type",
                    "availability",
                    "recorded_retrieval_scheme",
                    "recorded_retrieval_identity",
                    "recorded_retrieval_immutable_ref",
                )
            },
        )
        self.assertEqual(
            manifest["inputs"],
            [
                {
                    "id": item.id,
                    "role": item.role,
                    "sha256": item.sha256,
                    "size_bytes": item.size_bytes,
                    "source_retrieval_scheme": item.source_retrieval_scheme,
                    "source_retrieval_identity": item.source_retrieval_identity,
                    "source_retrieval_immutable_ref": item.source_retrieval_immutable_ref,
                    "derivation_kind": item.derivation_kind,
                    "derivation_recipe_id": item.derivation_recipe_id,
                    "derivation_parent_ids": list(item.derivation_parent_ids),
                    "derivation_parameters_sha256": item.derivation_parameters_sha256,
                    "placements": [
                        {
                            "image": placement.image,
                            "path": placement.path,
                            "node_type": placement.node_type,
                            "mode": placement.mode,
                            "uid": placement.uid,
                            "gid": placement.gid,
                            "xattrs": list(placement.xattrs),
                            "source_input_id": placement.source_input_id,
                            "target": placement.target,
                        }
                        for placement in item.placements
                    ],
                }
                for item in lock.inputs
            ],
        )
        self.assertEqual(
            manifest["inventory"],
            {
                image_id: sorted(
                    [
                        {
                            "path": placement.path,
                            "node_type": placement.node_type,
                            "mode": placement.mode,
                            "uid": placement.uid,
                            "gid": placement.gid,
                            "xattrs": list(placement.xattrs),
                            "sha256": item.sha256 if placement.node_type == "file" else None,
                            "size_bytes": item.size_bytes if placement.node_type == "file" else None,
                            "symlink_target": placement.target,
                            "source_input_id": placement.source_input_id,
                        }
                        for item in lock.inputs
                        for placement in item.placements
                        if placement.image == image_id
                    ],
                    key=lambda item: item["path"],
                )
                for image_id in ("models", "runtime-policy")
            },
        )
        inputs_by_id = {item.id: item for item in lock.inputs}
        self.assertEqual(
            manifest["toolchain"],
            [
                {
                    "tool_id": tool_id,
                    "component": inputs_by_id[tool_id].component,
                    "resolved_path_sha256": inputs_by_id[tool_id].sha256,
                }
                for tool_id in lock.tool_ids
            ],
        )

    def test_runtime_and_tcb_changes_change_execution_but_not_image_geometry(self) -> None:
        baseline = parse_manifest_v2(_produce().manifest_bytes).raw
        runtime_values = _bundle(closure_extra=True)
        runtime = parse_manifest_v2(produce_provenance_v2(
            **runtime_values,
            images=_images(), module_observations=_module_observations(), firmware_observations=_firmware_observations(),
        ).manifest_bytes).raw
        tcb_values = _bundle(tcb_digest=_sha(602))
        tcb = parse_manifest_v2(produce_provenance_v2(
            **tcb_values,
            images=_images(), module_observations=_module_observations(), firmware_observations=_firmware_observations(),
        ).manifest_bytes).raw
        self.assertEqual(baseline["images"], runtime["images"])
        self.assertEqual(baseline["images"], tcb["images"])
        self.assertNotEqual(baseline["provenance"]["execution_provenance_sha256"], runtime["provenance"]["execution_provenance_sha256"])
        self.assertNotEqual(baseline["provenance"]["execution_provenance_sha256"], tcb["provenance"]["execution_provenance_sha256"])

    def test_root_lock_change_flows_to_geometry_and_selfcheck_detects_tampering(self) -> None:
        baseline = parse_manifest_v2(_produce().manifest_bytes).raw
        values = _bundle()
        lock = canonical_loads(values["root_lock_bytes"])
        lock["future_cmdline"] = "console=ttyS1"
        changed = parse_manifest_v2(_produce(root_lock_bytes=canonical_dumps(lock)).manifest_bytes).raw
        self.assertNotEqual(baseline["lock_sha256"], changed["lock_sha256"])
        self.assertNotEqual(baseline["images"]["models"]["salt"], changed["images"]["models"]["salt"])

        artifact = _produce()
        raw = canonical_loads(artifact.manifest_bytes)
        raw["images"]["models"]["salt"] = _sha(700)
        derived = provenance.derive_inputs(**values)
        self.assert_rejected(
            lambda: _selfcheck(
                manifest_bytes=canonical_dumps(raw),
                spdx_bytes=artifact.spdx_bytes,
                images=_images(),
                module_observations=_module_observations(),
                firmware_observations=_firmware_observations(),
                initial_inputs=derived,
                **values,
            ),
            "CP_PROVENANCE_V2_MANIFEST_SELFCHECK",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
