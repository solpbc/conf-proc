#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""End-to-end selftest driving the real conf_proc_build.py /
conf_proc_inspect.py CLI entrypoints over a complete, minimal, rootless
fixture lock/policy/input-tree: covers AC12 (atomic/concurrency-safe
promotion, fault injection), AC13 (reproducibility), and ties together
every subsystem exercised in isolation by the other conf-proc-*-selftest
files. No real production model weights, credentials, or keys anywhere."""

from __future__ import annotations

import datetime
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_build as build_cli  # noqa: E402
import conf_proc_inspect as inspect_cli  # noqa: E402
import conf_proc_json as cj  # noqa: E402
import conf_proc_module_sig as module_sig  # noqa: E402
from conf_proc_promote import PROMOTED_BUNDLE_FILES  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str) -> str:
    return _sha256_bytes(Path(path).read_bytes())


def _all_parent_dirs(paths: list[str]) -> list[str]:
    dirs: set[str] = set()
    for path in paths:
        parts = path.strip("/").split("/")
        for i in range(1, len(parts)):
            dirs.add("/" + "/".join(parts[:i]))
    return sorted(dirs)


def _write(path: str, content: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(content)


def _lock_input(id_, role, source_local_path, content_sha256, size_bytes, placements, *, component=None, parent_ids=()):
    return {
        "id": id_,
        "role": role,
        "component": component or id_,
        "sha256": content_sha256,
        "size_bytes": size_bytes,
        "source_local_path": source_local_path,
        "source_retrieval_scheme": "local-fixture",
        "source_retrieval_identity": f"fixture:{id_}",
        "source_retrieval_immutable_ref": "v1",
        "derivation_kind": "fixture",
        "derivation_recipe_id": "r1",
        "derivation_parent_ids": list(parent_ids),
        "derivation_parameters_sha256": _sha256_bytes(b"params"),
        "placements": placements,
    }


def _placement(image, path, node_type, mode, uid, gid, *, source_input_id=None, target=None):
    return {
        "image": image, "path": path, "node_type": node_type, "mode": mode, "uid": uid, "gid": gid,
        "xattrs": [], "source_input_id": source_input_id, "target": target,
    }


def _dir_placements(image: str, paths: list[str]) -> list[dict]:
    return [_placement(image, path, "directory", 0o755, 0, 0) for path in _all_parent_dirs(paths)]


class _Fixture:
    """Builds one complete, real, on-disk lock/policy/input-tree fixture."""

    def __init__(self, base: str) -> None:
        self.base = base
        self.input_root = os.path.join(base, "inputs")
        self.tool_root = "/"
        self.promote_root = os.path.join(base, "promote")
        os.makedirs(self.input_root)
        os.makedirs(self.promote_root)

        self._make_signer()
        self._write_input_files()
        self._write_policy()
        self._write_lock()

    def _make_signer(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "conf-proc e2e fixture signer")])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(self.key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.key, hashes.SHA256())
        )
        self.cert_sha256 = self.cert.fingerprint(hashes.SHA256()).hex()
        spki_der = self.cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.spki_sha256 = hashlib.sha256(spki_der).hexdigest()
        self.subject_sha256 = hashlib.sha256(self.cert.subject.public_bytes()).hexdigest()

    def _input(self, relative: str) -> str:
        return os.path.join(self.input_root, relative)

    def _write_input_files(self) -> None:
        self.files: dict[str, bytes] = {
            "kernel.bin": b"fake fixture kernel bytes, not real\n",
            "stub.sh": b"#!/bin/sh\nexit 0\n",
            "unit.service": (b"[Service]\nExecStart=/usr/bin/spp-systemd-stub\nIPAddressDeny=any\n"),
            "firmware.fw": b"fake fixture firmware bytes, not real NVIDIA content\n",
            "sglang.bin": b"fake fixture sglang image bytes\n",
            "inference-model.bin": b"fake fixture inference model bytes\n",
            "asr-model.bin": b"fake fixture asr model bytes\n",
            "gateway-lock.txt": b"fake fixture gateway dependency lock\n",
            "asr-lock.txt": b"fake fixture asr dependency lock\n",
            "source.py": b"# fake fixture conf-proc source file\n",
        }
        for name, content in self.files.items():
            _write(self._input(name), content)

        module_payload = b"fake fixture module payload, not real NVIDIA or kernel content\n"
        signed = pkcs7.PKCS7SignatureBuilder().set_data(module_payload).add_signer(self.cert, self.key, hashes.SHA256()).sign(
            serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary, pkcs7.PKCS7Options.DetachedSignature]
        )
        self.signed_module = module_sig.build_module_signature(module_payload, b"", b"", signed, id_type=module_sig.PKEY_ID_PKCS7)
        _write(self._input("driver.ko"), self.signed_module)

        self.trusted_bundle_bytes = self.cert.public_bytes(serialization.Encoding.PEM)
        _write(self._input("bundle.pem"), self.trusted_bundle_bytes)

        self.policy_path = os.path.join(self.base, "policy.json")

    def _write_policy(self) -> None:
        policy = {
            "schema": "conf-proc-policy/v1",
            "policy_version": 1,
            "images": {"runtime-policy": {"nodes": []}, "models": {"nodes": []}},
            "boot_roots": [],
            "process_nodes": [
                {
                    "id": "exec:/usr/bin/spp-systemd-stub", "kind": "exec", "path": "/usr/bin/spp-systemd-stub",
                    "sha256": _sha256_bytes(self.files["stub.sh"]), "argv": ["/usr/bin/spp-systemd-stub"],
                    "network_scope": "none", "capabilities": [], "source_input_id": None,
                },
                {
                    "id": "unit:conf-proc-final.service", "kind": "unit", "path": "conf-proc-final.service",
                    "sha256": None, "argv": [], "network_scope": "none", "capabilities": [], "source_input_id": None,
                },
            ],
            "process_edges": [
                {
                    "from_id": "unit:conf-proc-final.service", "to_id": "exec:/usr/bin/spp-systemd-stub",
                    "kind": "unit_exec", "origin_path": "conf-proc-final.service", "origin_key": "ExecStart",
                },
            ],
            "mounts": [],
            "network_policy": {},
            "capability_policy": {},
        }
        Path(self.policy_path).write_bytes(cj.canonical_dumps(policy))
        self.policy_sha256 = _sha256_file(self.policy_path)

    def _write_lock(self) -> None:
        runtime_paths = [
            "/etc/systemd/system/conf-proc-final.service", "/usr/bin/spp-systemd-stub", "/boot/vmlinuz-fixture",
            "/lib/modules/conf-proc-fixture/kernel/drivers/video/nvidia-cc-fixture.ko",
            "/lib/firmware/nvidia/cc/fixture-gsp.fw", "/etc/spp/gateway-lock.txt", "/etc/spp/asr-lock.txt",
            "/opt/conf-proc/source.py", "/etc/spp/policy.json",
        ]
        models_paths = ["/opt/sglang/fixture-image.bin", "/models/fixture-inference.bin", "/models/fixture-asr.bin"]

        all_dir_placements = sorted(
            _dir_placements("runtime-policy", runtime_paths) + _dir_placements("models", models_paths),
            key=lambda p: (p["image"], p["path"]),
        )
        dirs_input = _lock_input(
            "dirs-1", "runtime_tree_input", "gateway-lock.txt", _sha256_bytes(self.files["gateway-lock.txt"]),
            len(self.files["gateway-lock.txt"]),
            all_dir_placements,
        )

        inputs = [
            _lock_input("kernel-1", "kernel", "kernel.bin", _sha256_bytes(self.files["kernel.bin"]), len(self.files["kernel.bin"]),
                        [_placement("runtime-policy", "/boot/vmlinuz-fixture", "file", 0o644, 0, 0, source_input_id="kernel-1")]),
            _lock_input("bundle-1", "kernel_trusted_cert_bundle", "bundle.pem", _sha256_bytes(self.trusted_bundle_bytes),
                        len(self.trusted_bundle_bytes), []),
            _lock_input("stub-1", "final_systemd_stub", "stub.sh", _sha256_bytes(self.files["stub.sh"]), len(self.files["stub.sh"]),
                        [_placement("runtime-policy", "/usr/bin/spp-systemd-stub", "file", 0o755, 0, 0, source_input_id="stub-1")]),
            _lock_input("unit-1", "final_systemd_unit", "unit.service", _sha256_bytes(self.files["unit.service"]), len(self.files["unit.service"]),
                        [_placement("runtime-policy", "/etc/systemd/system/conf-proc-final.service", "file", 0o644, 0, 0, source_input_id="unit-1")]),
            _lock_input("driver-1", "nvidia_cc_driver", "driver.ko", _sha256_bytes(self.signed_module), len(self.signed_module),
                        [_placement("runtime-policy", "/lib/modules/conf-proc-fixture/kernel/drivers/video/nvidia-cc-fixture.ko", "file", 0o644, 0, 0, source_input_id="driver-1")]),
            _lock_input("firmware-1", "nvidia_cc_firmware", "firmware.fw", _sha256_bytes(self.files["firmware.fw"]), len(self.files["firmware.fw"]),
                        [_placement("runtime-policy", "/lib/firmware/nvidia/cc/fixture-gsp.fw", "file", 0o644, 0, 0, source_input_id="firmware-1")]),
            _lock_input("sglang-1", "sglang_image", "sglang.bin", _sha256_bytes(self.files["sglang.bin"]), len(self.files["sglang.bin"]),
                        [_placement("models", "/opt/sglang/fixture-image.bin", "file", 0o644, 0, 0, source_input_id="sglang-1")]),
            _lock_input("model-inference-1", "inference_model", "inference-model.bin", _sha256_bytes(self.files["inference-model.bin"]), len(self.files["inference-model.bin"]),
                        [_placement("models", "/models/fixture-inference.bin", "file", 0o644, 0, 0, source_input_id="model-inference-1")]),
            _lock_input("model-asr-1", "asr_model", "asr-model.bin", _sha256_bytes(self.files["asr-model.bin"]), len(self.files["asr-model.bin"]),
                        [_placement("models", "/models/fixture-asr.bin", "file", 0o644, 0, 0, source_input_id="model-asr-1")]),
            _lock_input("gw-lock-1", "gateway_dependency_lock", "gateway-lock.txt", _sha256_bytes(self.files["gateway-lock.txt"]), len(self.files["gateway-lock.txt"]),
                        [_placement("runtime-policy", "/etc/spp/gateway-lock.txt", "file", 0o644, 0, 0, source_input_id="gw-lock-1")]),
            _lock_input("asr-lock-1", "asr_dependency_lock", "asr-lock.txt", _sha256_bytes(self.files["asr-lock.txt"]), len(self.files["asr-lock.txt"]),
                        [_placement("runtime-policy", "/etc/spp/asr-lock.txt", "file", 0o644, 0, 0, source_input_id="asr-lock-1")]),
            _lock_input("src-1", "conf_proc_source", "source.py", _sha256_bytes(self.files["source.py"]), len(self.files["source.py"]),
                        [_placement("runtime-policy", "/opt/conf-proc/source.py", "file", 0o644, 0, 0, source_input_id="src-1")]),
            _lock_input("policy-1", "policy_tree_input", "policy-copy.json", self.policy_sha256, os.path.getsize(self.policy_path),
                        [_placement("runtime-policy", "/etc/spp/policy.json", "file", 0o644, 0, 0, source_input_id="policy-1")]),
            dirs_input,
        ]
        shutil.copy(self.policy_path, self._input("policy-copy.json"))

        for component in ("mksquashfs", "unsquashfs", "veritysetup", "openssl"):
            tool_path = self._resolve_system_tool(component)
            inputs.append(
                _lock_input(f"tool-{component}", "build_tool", f"tools/{component}", _sha256_file(tool_path),
                            os.path.getsize(tool_path), [], component=component)
            )

        inputs.sort(key=lambda entry: entry["id"])

        lock = {
            "schema": "conf-proc-lock/v1",
            "lock_version": 1,
            "base_image_record": {
                "kind": "vhd", "provider": "fixture", "identity_namespace": "fixture-ns", "identity_name": "fixture-image",
                "identity_immutable_revision": "1.0.0", "content_sha256": _sha256_bytes(b"base-image-fixture"),
                "content_size_bytes": 100, "content_media_type": "application/octet-stream", "availability": "record-only",
                "recorded_retrieval_scheme": "local-fixture", "recorded_retrieval_identity": "fixture:base-image",
                "recorded_retrieval_immutable_ref": "v1",
            },
            "future_cmdline": "console=ttyS0",
            "inputs": inputs,
            "authorized_module_signers": [
                {"certificate_sha256": self.cert_sha256, "spki_sha256": self.spki_sha256, "subject_sha256": self.subject_sha256, "usage": "kernel-module-signing"},
            ],
            "image_specs": {"runtime-policy": {}, "models": {}},
            "policy_input_id": "policy-1",
            "tool_ids": sorted(f"tool-{c}" for c in ("mksquashfs", "unsquashfs", "veritysetup", "openssl")),
        }
        self.lock_path = os.path.join(self.base, "lock.json")
        Path(self.lock_path).write_bytes(cj.canonical_dumps(lock))
        self.lock_digest_hex = _sha256_file(self.lock_path)

    @staticmethod
    def _resolve_system_tool(component: str) -> str:
        for prefix in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"):
            candidate = os.path.join(prefix, component)
            if os.path.isfile(candidate):
                return candidate
        raise unittest.SkipTest(f"required tool {component!r} not present on this host")


class EndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.fixture = _Fixture(self.base)

    def _build(self, **kwargs):
        return build_cli.build(
            lock_path=self.fixture.lock_path, policy_path=self.fixture.policy_path,
            input_root=self.fixture.input_root, tool_root=self.fixture.tool_root,
            promote_root=self.fixture.promote_root, **kwargs,
        )

    def test_full_build_and_promote_succeeds(self) -> None:
        destination = self._build()
        self.assertTrue(os.path.isdir(destination))
        for name in PROMOTED_BUNDLE_FILES:
            self.assertTrue(os.path.isfile(os.path.join(destination, name)), f"missing {name}")
        self.assertEqual(os.path.basename(destination), self.fixture.lock_digest_hex)

    def test_inspector_cli_accepts_promoted_bundle_directly(self) -> None:
        destination = self._build()
        inspect_cli.inspect(
            lock_path=self.fixture.lock_path, policy_path=self.fixture.policy_path,
            input_root=self.fixture.input_root, tool_root=self.fixture.tool_root, bundle_dir=destination,
        )

    def test_second_build_is_idempotent(self) -> None:
        first = self._build()
        first_digests = {name: _sha256_file(os.path.join(first, name)) for name in PROMOTED_BUNDLE_FILES}
        second = self._build()
        self.assertEqual(first, second)
        second_digests = {name: _sha256_file(os.path.join(second, name)) for name in PROMOTED_BUNDLE_FILES}
        self.assertEqual(first_digests, second_digests)

    def test_reproducible_under_different_umask_and_cwd(self) -> None:
        first = self._build()
        first_digests = {name: _sha256_file(os.path.join(first, name)) for name in PROMOTED_BUNDLE_FILES}
        shutil.rmtree(first)

        old_cwd = os.getcwd()
        old_umask = os.umask(0o027)
        try:
            os.chdir(tempfile.gettempdir())
            second = self._build()
        finally:
            os.umask(old_umask)
            os.chdir(old_cwd)
        second_digests = {name: _sha256_file(os.path.join(second, name)) for name in PROMOTED_BUNDLE_FILES}
        self.assertEqual(first_digests, second_digests)

    def test_reproducible_under_different_timezone_and_locale(self) -> None:
        first = self._build()
        first_digests = {name: _sha256_file(os.path.join(first, name)) for name in PROMOTED_BUNDLE_FILES}
        shutil.rmtree(first)

        old_tz = os.environ.get("TZ")
        old_locale = os.environ.get("LC_ALL")
        os.environ["TZ"] = "Pacific/Kiritimati"
        os.environ["LC_ALL"] = "C.UTF-8"
        try:
            second = self._build()
        finally:
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            if old_locale is None:
                os.environ.pop("LC_ALL", None)
            else:
                os.environ["LC_ALL"] = old_locale
        second_digests = {name: _sha256_file(os.path.join(second, name)) for name in PROMOTED_BUNDLE_FILES}
        self.assertEqual(first_digests, second_digests)

    def test_concurrent_builds_same_digest_produce_exactly_one_bundle(self) -> None:
        results = [None, None]
        errors = [None, None]

        def run(index: int) -> None:
            try:
                results[index] = self._build()
            except Exception as exc:  # noqa: BLE001
                errors[index] = exc

        threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertIsNone(errors[0], errors[0])
        self.assertIsNone(errors[1], errors[1])
        self.assertEqual(results[0], results[1])
        promoted_root = os.path.join(self.fixture.promote_root, "promoted")
        self.assertEqual(os.listdir(promoted_root), [self.fixture.lock_digest_hex])

    def test_fault_injection_before_rename_leaves_no_promoted_bundle(self) -> None:
        def fault_hook(phase: str) -> None:
            if phase == "pre_rename":
                raise RuntimeError("injected fault before rename")

        with self.assertRaises(RuntimeError):
            self._build(fault_hook=fault_hook)
        promoted_root = os.path.join(self.fixture.promote_root, "promoted")
        self.assertFalse(os.path.isdir(promoted_root) and os.listdir(promoted_root))

    def test_fault_injection_after_rename_leaves_exactly_one_complete_bundle(self) -> None:
        def fault_hook(phase: str) -> None:
            if phase == "post_rename":
                raise RuntimeError("injected fault after rename")

        with self.assertRaises(RuntimeError):
            self._build(fault_hook=fault_hook)
        promoted_root = os.path.join(self.fixture.promote_root, "promoted")
        self.assertEqual(os.listdir(promoted_root), [self.fixture.lock_digest_hex])
        destination = os.path.join(promoted_root, self.fixture.lock_digest_hex)
        for name in PROMOTED_BUNDLE_FILES:
            self.assertTrue(os.path.isfile(os.path.join(destination, name)))

    def test_differing_content_same_digest_is_rejected_without_overwrite(self) -> None:
        first = self._build()
        first_digests = {name: _sha256_file(os.path.join(first, name)) for name in PROMOTED_BUNDLE_FILES}

        # Simulate a second builder with a non-deterministic bug: mutate
        # a byte in an already-promoted file and re-run promote() against
        # a hand-crafted staging dir claiming the SAME lock digest.
        import conf_proc_promote as promote_mod

        tampered_staging = os.path.join(self.fixture.promote_root, ".staging", "tampered")
        shutil.copytree(first, tampered_staging)
        target_file = os.path.join(tampered_staging, "runtime-policy.squashfs")
        with open(target_file, "r+b") as handle:
            byte = handle.read(1)
            handle.seek(0)
            handle.write(bytes([byte[0] ^ 0xFF]))

        with self.assertRaises(ApplianceError) as ctx:
            promote_mod.promote(
                tampered_staging, self.fixture.promote_root, self.fixture.lock_digest_hex,
                inspect_fn=lambda staging_dir: None,
            )
        self.assertEqual(ctx.exception.reason_code, "CP_PROMOTE_SAME_LOCK_CONTENT_DISAGREEMENT")

        # The original destination must be untouched.
        after_digests = {name: _sha256_file(os.path.join(first, name)) for name in PROMOTED_BUNDLE_FILES}
        self.assertEqual(first_digests, after_digests)

    def test_missing_required_tool_fails_loud_not_skips(self) -> None:
        # AC15: absence of a required tool must be a hard, reason-coded
        # failure -- never a silently-skipped green run.
        empty_tool_root = os.path.join(self.base, "empty-tool-root")
        os.makedirs(empty_tool_root)
        with self.assertRaises(ApplianceError) as ctx:
            build_cli.build(
                lock_path=self.fixture.lock_path, policy_path=self.fixture.policy_path,
                input_root=self.fixture.input_root, tool_root=empty_tool_root,
                promote_root=self.fixture.promote_root,
            )
        self.assertEqual(ctx.exception.reason_code, "CP_TOOL_MISSING")
        promoted_root = os.path.join(self.fixture.promote_root, "promoted")
        self.assertFalse(os.path.isdir(promoted_root) and os.listdir(promoted_root))


if __name__ == "__main__":
    unittest.main(verbosity=2)
