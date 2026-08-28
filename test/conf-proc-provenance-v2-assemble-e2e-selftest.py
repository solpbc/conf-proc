#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Real-tool proof of life for the dormant provenance-v2 H3 assembler."""

from __future__ import annotations

import datetime
import hashlib
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_json as cj  # noqa: E402
import conf_proc_module_sig as module_sig  # noqa: E402
import conf_proc_provenance_v2 as provenance  # noqa: E402
import conf_proc_provenance_v2_assemble as assembler  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha(path: str) -> str:
    return _sha(Path(path).read_bytes())


def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    Path(path).write_bytes(data)


def _placement(image: str, path: str, node_type: str, uid: int, gid: int, *, source: str | None = None) -> dict:
    return {
        "image": image,
        "path": path,
        "node_type": node_type,
        "mode": 0o755 if node_type == "directory" or path == "/usr/bin/spp-systemd-stub" else 0o644,
        "uid": uid,
        "gid": gid,
        "xattrs": [],
        "source_input_id": source,
        "target": None,
    }


def _parents(paths: list[str], image: str, uid: int, gid: int) -> list[dict]:
    directories: set[str] = set()
    for path in paths:
        pieces = path.strip("/").split("/")
        for index in range(1, len(pieces)):
            directories.add("/" + "/".join(pieces[:index]))
    return [_placement(image, path, "directory", uid, gid) for path in sorted(directories)]


class _Fixture:
    def __init__(self, base: str, *, fake_mksquashfs: bool = False) -> None:
        self.base = base
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.input_root = os.path.join(base, "inputs")
        self.output = os.path.join(base, "output")
        self.tool_root = os.path.join(base, "tools") if fake_mksquashfs else "/"
        os.makedirs(self.input_root)
        os.makedirs(self.output)
        self._make_certificate()
        self._write_inputs()
        self._write_policy()
        self._write_lock(fake_mksquashfs)

    def _make_certificate(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "H3 fixture signer")])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.key, hashes.SHA256())
        )
        self.cert_sha = self.cert.fingerprint(hashes.SHA256()).hex()
        spki = self.cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.spki_sha = _sha(spki)
        self.subject_sha = _sha(self.cert.subject.public_bytes())

    def _input(self, name: str) -> str:
        return os.path.join(self.input_root, name)

    def _write_inputs(self) -> None:
        self.contents = {
            "kernel.bin": b"fixture kernel\n",
            "stub.sh": b"#!/bin/sh\nexit 0\n",
            "unit.service": b"[Service]\nExecStart=/usr/bin/spp-systemd-stub\nIPAddressDeny=any\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=\nNoNewPrivileges=yes\n",
            "firmware.bin": b"fixture firmware\n",
            "sglang.bin": b"fixture sglang\n",
            "model.bin": b"fixture model\n",
            "asr.bin": b"fixture asr\n",
            "gateway.lock": b"gateway\n",
            "asr.lock": b"asr\n",
            "source.py": b"# H3 builder source\n",
            "dirs.bin": b"directories\n",
        }
        module_payload = b"fixture kernel module payload\n"
        signature = pkcs7.PKCS7SignatureBuilder().set_data(module_payload).add_signer(
            self.cert, self.key, hashes.SHA256()
        ).sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary, pkcs7.PKCS7Options.DetachedSignature])
        self.contents["driver.ko"] = module_sig.build_module_signature(
            module_payload, b"", b"", signature, id_type=module_sig.PKEY_ID_PKCS7
        )
        self.contents["bundle.pem"] = self.cert.public_bytes(serialization.Encoding.PEM)
        for name, content in self.contents.items():
            _write(self._input(name), content)

    def _tree_node(self, placement: dict, content_class: str | None) -> dict:
        return {
            "path": placement["path"],
            "node_type": placement["node_type"],
            "mode": placement["mode"],
            "uid": placement["uid"],
            "gid": placement["gid"],
            "xattrs": [],
            "source_input_id": placement["source_input_id"],
            "target": None,
            "content_class": content_class,
        }

    def _write_policy(self) -> None:
        runtime_files = {
            "/usr/bin/spp-systemd-stub": "executable",
            "/etc/systemd/system/h3.service": "config",
            "/usr/lib/modules/h3/driver.ko": "runtime_data",
            "/usr/lib/firmware/h3/firmware.bin": "runtime_data",
            "/opt/conf-proc/source.py": "runtime_data",
            "/etc/spp/policy.json": "config",
        }
        models_files = {
            "/models/asr.lock": "model",
            "/models/sglang/image.bin": "model",
            "/models/inference.bin": "model",
            "/models/asr.bin": "model",
            "/models/kernel.bin": "model",
            "/models/gateway.lock": "model",
        }
        runtime_placements = _parents(list(runtime_files), "runtime-policy", self.uid, self.gid) + [
            _placement("runtime-policy", path, "file", self.uid, self.gid, source=self._source_id(path))
            for path in sorted(runtime_files)
        ]
        models_placements = _parents(list(models_files), "models", self.uid, self.gid) + [
            _placement("models", path, "file", self.uid, self.gid, source=self._source_id(path))
            for path in sorted(models_files)
        ]
        self.placements = sorted(runtime_placements + models_placements, key=lambda value: (value["image"], value["path"]))
        policy = {
            "schema": "conf-proc-policy/v1",
            "policy_version": 1,
            "images": {
                "models": {"nodes": sorted([self._tree_node(item, models_files.get(item["path"])) for item in models_placements], key=lambda item: item["path"])},
                "runtime-policy": {"nodes": sorted([self._tree_node(item, runtime_files.get(item["path"])) for item in runtime_placements], key=lambda item: item["path"])},
            },
            "boot_roots": [],
            "process_nodes": [
                {
                    "id": "exec:/usr/bin/spp-systemd-stub",
                    "kind": "exec",
                    "path": "/usr/bin/spp-systemd-stub",
                    "sha256": _sha(self.contents["stub.sh"]),
                    "argv": ["/usr/bin/spp-systemd-stub"],
                    "network_scope": "none",
                    "capabilities": [],
                    "source_input_id": None,
                },
                {
                    "id": "unit:h3.service",
                    "kind": "unit",
                    "path": "h3.service",
                    "sha256": None,
                    "argv": [],
                    "network_scope": "none",
                    "capabilities": ["CAP_NET_BIND_SERVICE"],
                    "source_input_id": None,
                },
            ],
            "process_edges": [
                {
                    "from_id": "unit:h3.service",
                    "to_id": "exec:/usr/bin/spp-systemd-stub",
                    "kind": "unit_exec",
                    "origin_path": "h3.service",
                    "origin_key": "ExecStart",
                }
            ],
            "mounts": [],
            "network_policy": {"unit:h3.service": "none"},
            "capability_policy": {
                "unit:h3.service": {
                    "capability_bounding_set": ["CAP_NET_BIND_SERVICE"],
                    "ambient_capabilities": [],
                    "no_new_privileges": True,
                }
            },
        }
        self.policy_bytes = cj.canonical_dumps(policy)
        self.policy_path = os.path.join(self.base, "policy.json")
        Path(self.policy_path).write_bytes(self.policy_bytes)
        _write(self._input("policy-copy.json"), self.policy_bytes)
        self.contents["policy-copy.json"] = self.policy_bytes

    @staticmethod
    def _source_id(path: str) -> str:
        return {
            "/usr/bin/spp-systemd-stub": "stub",
            "/etc/systemd/system/h3.service": "unit",
            "/usr/lib/modules/h3/driver.ko": "driver",
            "/usr/lib/firmware/h3/firmware.bin": "firmware",
            "/opt/conf-proc/source.py": "source",
            "/etc/spp/policy.json": "policy",
            "/models/sglang/image.bin": "sglang",
            "/models/inference.bin": "inference",
            "/models/asr.bin": "asrmodel",
            "/models/asr.lock": "asrlock",
            "/models/gateway.lock": "gateway",
            "/models/kernel.bin": "kernel",
        }[path]

    def _input_record(self, input_id: str, role: str, source: str, placements: list[dict], *, component: str | None = None) -> dict:
        data = self.contents[source]
        digest = _sha(data)
        return {
            "id": input_id,
            "role": role,
            "component": component or input_id,
            "sha256": digest,
            "size_bytes": len(data),
            "source_local_path": source,
            "source_retrieval_scheme": "local-fixture",
            "source_retrieval_identity": f"fixture:{input_id}",
            "source_retrieval_immutable_ref": f"sha256:{digest}",
            "derivation_kind": "fixture",
            "derivation_recipe_id": "fixture-v1",
            "derivation_parent_ids": [],
            "derivation_parameters_sha256": _sha(b"params"),
            "placements": sorted(placements, key=lambda item: (item["image"], item["path"])),
        }

    def _write_lock(self, fake_mksquashfs: bool) -> None:
        placements_by_source = {
            name: []
            for name in (
                "kernel",
                "stub",
                "unit",
                "driver",
                "firmware",
                "source",
                "policy",
                "sglang",
                "inference",
                "asrmodel",
                "gateway",
                "asrlock",
                "dirs",
            )
        }
        for placement in self.placements:
            source = placement["source_input_id"]
            placements_by_source[source or "dirs"].append(placement)
        inputs = [
            self._input_record("kernel", "kernel", "kernel.bin", placements_by_source["kernel"]),
            self._input_record("bundle", "kernel_trusted_cert_bundle", "bundle.pem", []),
            self._input_record("stub", "final_systemd_stub", "stub.sh", placements_by_source["stub"]),
            self._input_record("unit", "final_systemd_unit", "unit.service", placements_by_source["unit"]),
            self._input_record("driver", "nvidia_cc_driver", "driver.ko", placements_by_source["driver"]),
            self._input_record("firmware", "nvidia_cc_firmware", "firmware.bin", placements_by_source["firmware"]),
            self._input_record("sglang", "sglang_image", "sglang.bin", placements_by_source["sglang"]),
            self._input_record("inference", "inference_model", "model.bin", placements_by_source["inference"]),
            self._input_record("asrmodel", "asr_model", "asr.bin", placements_by_source["asrmodel"]),
            self._input_record("gateway", "gateway_dependency_lock", "gateway.lock", placements_by_source["gateway"]),
            self._input_record("asrlock", "asr_dependency_lock", "asr.lock", placements_by_source["asrlock"]),
            self._input_record("source", "conf_proc_source", "source.py", placements_by_source["source"]),
            self._input_record("policy", "policy_tree_input", "policy-copy.json", placements_by_source["policy"]),
            self._input_record("dirs", "runtime_tree_input", "dirs.bin", placements_by_source["dirs"]),
        ]
        tool_ids = []
        for component in ("mksquashfs", "unsquashfs", "veritysetup", "openssl"):
            path = self._tool_path(component, fake_mksquashfs)
            data = Path(path).read_bytes()
            tool_id = "tool-" + component
            tool_ids.append(tool_id)
            inputs.append(
                {
                    "id": tool_id,
                    "role": "build_tool",
                    "component": component,
                    "sha256": _sha(data),
                    "size_bytes": len(data),
                    "source_local_path": "tools/" + component,
                    "source_retrieval_scheme": "local-fixture",
                    "source_retrieval_identity": "fixture:" + component,
                    "source_retrieval_immutable_ref": "sha256:" + _sha(data),
                    "derivation_kind": "fixture",
                    "derivation_recipe_id": "fixture-v1",
                    "derivation_parent_ids": [],
                    "derivation_parameters_sha256": _sha(b"params"),
                    "placements": [],
                }
            )
        lock = {
            "schema": "conf-proc-lock/v1",
            "lock_version": 1,
            "base_image_record": {
                "kind": "vhd",
                "provider": "fixture",
                "identity_namespace": "fixture",
                "identity_name": "h3",
                "identity_immutable_revision": "1",
                "content_sha256": _sha(b"base"),
                "content_size_bytes": 4,
                "content_media_type": "application/octet-stream",
                "availability": "record-only",
                "recorded_retrieval_scheme": "local-fixture",
                "recorded_retrieval_identity": "fixture:base",
                "recorded_retrieval_immutable_ref": "sha256:" + _sha(b"base"),
            },
            "future_cmdline": "console=ttyS0",
            "inputs": sorted(inputs, key=lambda item: item["id"]),
            "authorized_module_signers": [
                {
                    "certificate_sha256": self.cert_sha,
                    "spki_sha256": self.spki_sha,
                    "subject_sha256": self.subject_sha,
                    "usage": "kernel-module-signing",
                }
            ],
            "image_specs": {"models": {}, "runtime-policy": {}},
            "policy_input_id": "policy",
            "tool_ids": sorted(tool_ids),
        }
        self.lock_bytes = cj.canonical_dumps(lock)
        self.lock_path = os.path.join(self.base, "root-lock.json")
        Path(self.lock_path).write_bytes(self.lock_bytes)
        self.closure_path = os.path.join(self.base, "runtime-closure.json")
        Path(self.closure_path).write_bytes(self._closure(lock))
        self.rules_path = os.path.join(self.base, "verity-rules.json")
        Path(self.rules_path).write_bytes(provenance.supported_verity_rules_bytes())
        self.tcb_path = os.path.join(self.base, "tcb-identity.json")
        Path(self.tcb_path).write_bytes(self._tcb())

    def _tool_path(self, component: str, fake: bool) -> str:
        system = {
            "mksquashfs": "/usr/bin/mksquashfs",
            "unsquashfs": "/usr/bin/unsquashfs",
            "veritysetup": "/usr/sbin/veritysetup",
            "openssl": "/usr/bin/openssl",
        }[component]
        if not fake:
            return system
        subdir = "usr/sbin" if component == "veritysetup" else "usr/bin"
        target = os.path.join(self.tool_root, subdir, component)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if component == "mksquashfs":
            Path(target).write_bytes(("#!/bin/sh\necho H3-HOSTILE " + self.base + " $@ >&2\nexit 7\n").encode())
            os.chmod(target, 0o755)
        else:
            shutil.copy2(system, target)
            os.chmod(target, stat.S_IMODE(os.lstat(target).st_mode) | 0o111)
        return target

    def _closure(self, lock: dict) -> bytes:
        inputs = {item["id"]: item for item in lock["inputs"]}
        entries = []
        for lock_input in lock["inputs"]:
            for placement in lock_input["placements"]:
                is_file = placement["node_type"] == "file"
                entries.append(
                    {
                        "path": placement["path"],
                        "node_type": placement["node_type"],
                        "mode": placement["mode"],
                        "uid": placement["uid"],
                        "gid": placement["gid"],
                        "size_bytes": lock_input["size_bytes"] if is_file else 0,
                        "sha256": lock_input["sha256"] if is_file else None,
                        "symlink_target": None,
                        "hardlink_group": None,
                        "xattrs": [],
                        "capabilities": [],
                        "logical_role": lock_input["role"],
                        "provenance": {
                            "scheme": lock_input["source_retrieval_scheme"],
                            "identity": lock_input["source_retrieval_identity"],
                            "immutable_ref": lock_input["source_retrieval_immutable_ref"],
                        },
                        "root_lock_input_id": lock_input["id"] if is_file else None,
                    }
                )
        return cj.canonical_dumps({"schema": "conf-proc-runtime-closure/v1", "status": "declared_unverified", "entries": sorted(entries, key=lambda item: item["path"])})

    @staticmethod
    def _tcb() -> bytes:
        def executable(name: str, marker: int) -> dict:
            return {
                "logical_name": name,
                "sha256": format(marker, "064x"),
                "linkage": "static",
                "interpreter_sha256": None,
                "loader_sha256": None,
                "library_sha256s": [],
            }

        return cj.canonical_dumps(
            {
                "schema": "conf-proc-pre-sandbox-tcb/v1",
                "status": "declared_unverified",
                "caller": executable("caller", 1),
                "launcher": executable("launcher", 2),
                "sandbox": {"backend": "bubblewrap", "executable": executable("sandbox", 3), "helper": None},
                "kernel_feature_contract": {"schema": "conf-proc-kernel-features/v1", "sha256": format(4, "064x")},
            }
        )

    def assemble(self, **overrides):
        values = {
            "root_lock_path": self.lock_path,
            "runtime_closure_path": self.closure_path,
            "verity_rules_path": self.rules_path,
            "tcb_identity_path": self.tcb_path,
            "builder_source_path": self._input("source.py"),
            "policy_path": self.policy_path,
            "input_root": self.input_root,
            "tool_root": self.tool_root,
            "output": self.output,
        }
        values.update(overrides)
        return assembler.assemble(**values)


class H3AssemblyEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.fixture = _Fixture(self.base)

    def test_real_tool_build_idempotence_and_context_determinism(self) -> None:
        first = self.fixture.assemble()
        expected = os.path.join(
            self.fixture.output,
            "built_unverified",
            first.artifact_input_sha256,
            first.execution_provenance_sha256,
        )
        self.assertEqual(first.state, "built_unverified")
        self.assertEqual(first.bundle_path, expected)
        self.assertEqual(sorted(os.listdir(expected)), sorted(assembler.BUNDLE_FILES))
        for name in assembler.BUNDLE_FILES:
            metadata = os.lstat(os.path.join(expected, name))
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode) & 0o333, 0)

        second = self.fixture.assemble()
        self.assertEqual(second, first)

        old_cwd = os.getcwd()
        old_umask = os.umask(0o077)
        old_tz = os.environ.get("TZ")
        alternate_output = os.path.join(self.base, "alternate-output")
        try:
            os.chdir(self.base)
            os.environ["TZ"] = "Pacific/Kiritimati"
            third = self.fixture.assemble(output=alternate_output)
        finally:
            os.chdir(old_cwd)
            os.umask(old_umask)
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
        self.assertEqual(third.state, first.state)
        self.assertEqual(third.artifact_input_sha256, first.artifact_input_sha256)
        self.assertEqual(third.execution_provenance_sha256, first.execution_provenance_sha256)
        self.assertEqual(third.models_squashfs_sha256, first.models_squashfs_sha256)
        self.assertEqual(third.models_verity_sha256, first.models_verity_sha256)
        self.assertEqual(third.runtime_policy_squashfs_sha256, first.runtime_policy_squashfs_sha256)
        self.assertEqual(third.runtime_policy_verity_sha256, first.runtime_policy_verity_sha256)
        self.assertEqual(third.manifest_sha256, first.manifest_sha256)
        self.assertEqual(third.spdx_sha256, first.spdx_sha256)
        self.assertEqual(_file_sha(os.path.join(expected, "models.squashfs")), first.models_squashfs_sha256)
        self.assertEqual(_file_sha(os.path.join(expected, "appliance.manifest.json")), first.manifest_sha256)

    def test_child_diagnostics_are_sanitized(self) -> None:
        hostile_base = os.path.join(self.base, "hostile")
        fixture = _Fixture(hostile_base, fake_mksquashfs=True)
        with self.assertRaises(ApplianceError) as context:
            fixture.assemble()
        self.assertEqual(context.exception.reason_code, "CP_TOOL_INVOCATION_FAILED")
        self.assertNotIn("H3-HOSTILE", str(context.exception))
        self.assertNotIn(hostile_base, str(context.exception))

    def test_post_rename_directory_hardening_failure_is_nonfatal(self) -> None:
        inputs = provenance.derive_inputs(
            root_lock_bytes=self.fixture.lock_bytes,
            runtime_closure_bytes=Path(self.fixture.closure_path).read_bytes(),
            verity_rules_bytes=Path(self.fixture.rules_path).read_bytes(),
            tcb_identity_bytes=Path(self.fixture.tcb_path).read_bytes(),
            builder_source_bytes=Path(self.fixture._input("source.py")).read_bytes(),
            policy_bytes=Path(self.fixture.policy_path).read_bytes(),
        )
        destination = os.path.join(
            self.fixture.output,
            "built_unverified",
            inputs.artifact_input_sha256,
            inputs.execution_provenance_sha256,
        )
        original_chmod = assembler.os.chmod

        def reject_visible_directory(path: str, mode: int, *args, **kwargs) -> None:
            if path == destination and mode == 0o555:
                raise OSError("test-only visible-directory hardening failure")
            original_chmod(path, mode, *args, **kwargs)

        assembler.os.chmod = reject_visible_directory
        try:
            result = self.fixture.assemble()
        finally:
            assembler.os.chmod = original_chmod
        self.assertEqual(result.bundle_path, destination)
        self.assertEqual(sorted(os.listdir(destination)), sorted(assembler.BUNDLE_FILES))
        for name in assembler.BUNDLE_FILES:
            self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(destination, name)).st_mode) & 0o333, 0)

    def test_authority_size_boundaries_and_missing_tool_are_hard_failures(self) -> None:
        exact = os.path.join(self.base, "exact-32m")
        over = os.path.join(self.base, "over-32m")
        Path(exact).write_bytes(b"x" * (32 * 1024 * 1024))
        Path(over).write_bytes(b"x" * (32 * 1024 * 1024 + 1))
        with self.assertRaises(ApplianceError) as context:
            self.fixture.assemble(root_lock_path=exact)
        self.assertNotEqual(context.exception.reason_code, "CP_PROVENANCE_INPUT_SIZE")
        with self.assertRaises(ApplianceError) as context:
            self.fixture.assemble(root_lock_path=over)
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_INPUT_SIZE")

        missing_tools = os.path.join(self.base, "empty-tools")
        os.makedirs(missing_tools)
        with self.assertRaises(ApplianceError) as context:
            self.fixture.assemble(tool_root=missing_tools)
        self.assertEqual(context.exception.reason_code, "CP_TOOL_MISSING")


if __name__ == "__main__":
    unittest.main(verbosity=2)
