#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fault, shape, lease, and staging exposure checks for dormant H3."""

from __future__ import annotations

import datetime
import fcntl
import hashlib
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_json as cj  # noqa: E402
import conf_proc_provenance_v2 as provenance  # noqa: E402
import conf_proc_provenance_v2_assemble as assembler  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tcb() -> bytes:
    def executable(name: str, marker: int) -> dict:
        return {"logical_name": name, "sha256": format(marker, "064x"), "linkage": "static", "interpreter_sha256": None, "loader_sha256": None, "library_sha256s": []}
    return cj.canonical_dumps({"schema": "conf-proc-pre-sandbox-tcb/v1", "status": "declared_unverified", "caller": executable("caller", 1), "launcher": executable("launcher", 2), "sandbox": {"backend": "bubblewrap", "executable": executable("sandbox", 3), "helper": None}, "kernel_feature_contract": {"schema": "conf-proc-kernel-features/v1", "sha256": format(4, "064x")}})


def _stale_lock() -> object:
    placements = (
        SimpleNamespace(image="runtime-policy", path="/etc", node_type="directory", target=None),
        SimpleNamespace(image="runtime-policy", path="/etc/target", node_type="file", target=None),
        SimpleNamespace(image="runtime-policy", path="/etc/link", node_type="symlink", target="target"),
    )
    return SimpleNamespace(inputs=(SimpleNamespace(placements=placements),))


def _stale_stage(output: str, address: tuple[str, str]) -> str:
    name = "-".join(address)
    stage = os.path.join(output, ".h3-staging", name)
    os.makedirs(os.path.join(stage, "work", "runtime-policy-tree", "etc"))
    os.makedirs(os.path.join(output, ".h3-owners"), exist_ok=True)
    open(os.path.join(output, ".h3-owners", name + ".lock"), "a+b").close()
    return stage


class _Fixture:
    def __init__(self, base: str) -> None:
        self.base = base
        self.input_root = os.path.join(base, "inputs")
        self.output = os.path.join(base, "output")
        os.makedirs(self.input_root)
        os.makedirs(self.output)
        self.uid, self.gid = 0, 0
        self._write_authorities()

    def _certificate(self) -> tuple[bytes, dict]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "H3 exposure signer")])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)).not_valid_after(datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
        return certificate.public_bytes(serialization.Encoding.PEM), {"certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex(), "spki_sha256": _sha(certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)), "subject_sha256": _sha(certificate.subject.public_bytes()), "usage": "kernel-module-signing"}

    def _write_authorities(self) -> None:
        roles = ("kernel", "kernel_trusted_cert_bundle", "final_systemd_stub", "final_systemd_unit", "nvidia_cc_driver", "nvidia_cc_firmware", "conf_proc_source", "sglang_image", "inference_model", "asr_model", "gateway_dependency_lock", "asr_dependency_lock", "runtime_tree_input", "policy_tree_input")
        ids = ["policy" if role == "policy_tree_input" else "input" + str(index) for index, role in enumerate(roles)]
        nodes = [{"path": "/" + item, "node_type": "file", "mode": 0o644, "uid": self.uid, "gid": self.gid, "xattrs": [], "source_input_id": item, "target": None, "content_class": "runtime_data"} for item, role in zip(ids, roles) if role != "kernel_trusted_cert_bundle"]
        self.policy_bytes = cj.canonical_dumps({"schema": "conf-proc-policy/v1", "policy_version": 1, "images": {"models": {"nodes": sorted(nodes, key=lambda item: item["path"])}, "runtime-policy": {"nodes": []}}, "boot_roots": [], "process_nodes": [], "process_edges": [], "mounts": [], "network_policy": {}, "capability_policy": {}})
        bundle, signer = self._certificate()
        contents = {item: (self.policy_bytes if role == "policy_tree_input" else (b"builder" if role == "conf_proc_source" else (bundle if role == "kernel_trusted_cert_bundle" else item.encode("ascii")))) for item, role in zip(ids, roles)}
        inputs, closure = [], []
        for item, role in zip(ids, roles):
            data = contents[item]
            Path(os.path.join(self.input_root, item)).write_bytes(data)
            placements = []
            if role != "kernel_trusted_cert_bundle":
                placements = [{"image": "models", "path": "/" + item, "node_type": "file", "mode": 0o644, "uid": self.uid, "gid": self.gid, "xattrs": [], "source_input_id": item, "target": None}]
                closure.append({"path": "/" + item, "node_type": "file", "mode": 0o644, "uid": self.uid, "gid": self.gid, "size_bytes": len(data), "sha256": _sha(data), "symlink_target": None, "hardlink_group": None, "xattrs": [], "capabilities": [], "logical_role": role, "provenance": {"scheme": "local-fixture", "identity": item, "immutable_ref": "sha256:" + _sha(data)}, "root_lock_input_id": item})
            inputs.append({"id": item, "role": role, "component": item, "sha256": _sha(data), "size_bytes": len(data), "source_local_path": item, "source_retrieval_scheme": "local-fixture", "source_retrieval_identity": item, "source_retrieval_immutable_ref": "sha256:" + _sha(data), "derivation_kind": "fixture", "derivation_recipe_id": "fixture-v1", "derivation_parent_ids": [], "derivation_parameters_sha256": _sha(b"params"), "placements": placements})
        tool_ids = []
        for component, path in (("mksquashfs", "/usr/bin/mksquashfs"), ("unsquashfs", "/usr/bin/unsquashfs"), ("veritysetup", "/usr/sbin/veritysetup"), ("openssl", "/usr/bin/openssl")):
            item = "tool-" + component
            tool_ids.append(item)
            binary = Path(path).read_bytes()
            inputs.append({"id": item, "role": "build_tool", "component": component, "sha256": _sha(binary), "size_bytes": len(binary), "source_local_path": "tools/" + component, "source_retrieval_scheme": "local-fixture", "source_retrieval_identity": component, "source_retrieval_immutable_ref": "sha256:" + _sha(binary), "derivation_kind": "fixture", "derivation_recipe_id": "fixture-v1", "derivation_parent_ids": [], "derivation_parameters_sha256": _sha(b"params"), "placements": []})
        self.lock_bytes = cj.canonical_dumps({"schema": "conf-proc-lock/v1", "lock_version": 1, "base_image_record": {"kind": "vhd", "provider": "fixture", "identity_namespace": "fixture", "identity_name": "exposure", "identity_immutable_revision": "1", "content_sha256": _sha(b"base"), "content_size_bytes": 4, "content_media_type": "application/octet-stream", "availability": "record-only", "recorded_retrieval_scheme": "local-fixture", "recorded_retrieval_identity": "base", "recorded_retrieval_immutable_ref": "sha256:" + _sha(b"base")}, "future_cmdline": "console=ttyS0", "inputs": sorted(inputs, key=lambda value: value["id"]), "authorized_module_signers": [signer], "image_specs": {"models": {}, "runtime-policy": {}}, "policy_input_id": "policy", "tool_ids": sorted(tool_ids)})
        self.paths = {"root_lock_path": os.path.join(self.base, "root-lock.json"), "runtime_closure_path": os.path.join(self.base, "closure.json"), "verity_rules_path": os.path.join(self.base, "rules.json"), "tcb_identity_path": os.path.join(self.base, "tcb.json"), "builder_source_path": os.path.join(self.input_root, ids[roles.index("conf_proc_source")]), "policy_path": os.path.join(self.base, "policy.json")}
        Path(self.paths["root_lock_path"]).write_bytes(self.lock_bytes)
        Path(self.paths["runtime_closure_path"]).write_bytes(cj.canonical_dumps({"schema": "conf-proc-runtime-closure/v1", "status": "declared_unverified", "entries": sorted(closure, key=lambda value: value["path"])}))
        Path(self.paths["verity_rules_path"]).write_bytes(provenance.supported_verity_rules_bytes())
        Path(self.paths["tcb_identity_path"]).write_bytes(_tcb())
        Path(self.paths["policy_path"]).write_bytes(self.policy_bytes)
        self.inputs = provenance.derive_inputs(root_lock_bytes=self.lock_bytes, runtime_closure_bytes=Path(self.paths["runtime_closure_path"]).read_bytes(), verity_rules_bytes=Path(self.paths["verity_rules_path"]).read_bytes(), tcb_identity_bytes=Path(self.paths["tcb_identity_path"]).read_bytes(), builder_source_bytes=Path(self.paths["builder_source_path"]).read_bytes(), policy_bytes=self.policy_bytes)

    @property
    def address(self) -> tuple[str, str]:
        return self.inputs.artifact_input_sha256, self.inputs.execution_provenance_sha256

    def assemble(self, **kwargs):
        return assembler.assemble(**self.paths, input_root=self.input_root, tool_root="/", output=self.output, **kwargs)


class H3ExposureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.fixture = _Fixture(self.base)

    def test_output_root_creation_is_private_and_unsafe_ancestor_is_rejected(self) -> None:
        created = os.path.join(self.base, "created-output")
        old_umask = os.umask(0)
        try:
            assembler._validate_output_root(created)
        finally:
            os.umask(old_umask)
        self.assertEqual(stat.S_IMODE(os.lstat(created).st_mode), 0o700)

        nested = os.path.join(self.base, "nested", "one", "two", "output")
        old_umask = os.umask(0)
        try:
            assembler._validate_output_root(nested)
        finally:
            os.umask(old_umask)
        current = os.path.join(self.base, "nested")
        for component in ("one", "two", "output"):
            self.assertEqual(stat.S_IMODE(os.lstat(current).st_mode), 0o700)
            current = os.path.join(current, component)
        self.assertEqual(stat.S_IMODE(os.lstat(current).st_mode), 0o700)

        unsafe_parent = os.path.join(self.base, "unsafe-parent")
        os.mkdir(unsafe_parent, 0o700)
        unsafe_output = os.path.join(unsafe_parent, "output")
        os.mkdir(unsafe_output, 0o700)
        os.chmod(unsafe_parent, 0o777)
        with self.assertRaises(ApplianceError) as context:
            assembler._validate_output_root(unsafe_output)
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_STAGING")

    def test_every_fault_phase_cleans_private_stage_and_exposes_nothing(self) -> None:
        phases = (("authority-read", 1), ("guard-built", 1), ("tree-built", 1), ("tree-built", 2), ("trees-frozen", 1), ("policy-observed", 1), ("modules-observed", 1), ("image-built", 1), ("image-built", 2), ("documents-built", 1), ("local-gate", 1), ("bundle-readonly", 1), ("pre-rename", 1))
        for phase, occurrence in phases:
            seen = 0
            def fault(current: str) -> None:
                nonlocal seen
                if current == phase:
                    seen += 1
                    if seen == occurrence:
                        raise ApplianceError("CP_TREE_UNEXPECTED", "test fault")
            with self.assertRaises(ApplianceError):
                self.fixture.assemble(fault_hook=fault)
            public = os.path.join(self.fixture.output, "built_unverified", *self.fixture.address)
            self.assertFalse(os.path.exists(public))
            staging = os.path.join(self.fixture.output, ".h3-staging")
            self.assertFalse(os.path.exists(staging) and os.listdir(staging))

    def test_existing_disagreement_and_bundle_shape_fail_closed(self) -> None:
        destination = os.path.join(self.fixture.output, "built_unverified", *self.fixture.address)
        os.makedirs(destination)
        original = {}
        for name in assembler.BUNDLE_FILES:
            path = os.path.join(destination, name)
            Path(path).write_bytes(("different-" + name).encode())
            os.chmod(path, 0o444)
            original[name] = Path(path).read_bytes()
        os.chmod(destination, 0o555)
        with self.assertRaises(ApplianceError) as context:
            self.fixture.assemble()
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_SAME_ADDRESS_DISAGREEMENT")
        self.assertEqual({name: Path(os.path.join(destination, name)).read_bytes() for name in assembler.BUNDLE_FILES}, original)

        shape = os.path.join(self.base, "shape")
        os.mkdir(shape)
        for name in assembler.BUNDLE_FILES:
            Path(os.path.join(shape, name)).write_bytes(b"x")
        Path(os.path.join(shape, "extra")).write_bytes(b"x")
        with self.assertRaises(ApplianceError):
            assembler._assert_bundle_shape(shape, readonly=False)
        os.unlink(os.path.join(shape, "extra"))
        os.unlink(os.path.join(shape, assembler.BUNDLE_FILES[0]))
        with self.assertRaises(ApplianceError):
            assembler._assert_bundle_shape(shape, readonly=False)
        Path(os.path.join(shape, assembler.BUNDLE_FILES[0])).mkdir()
        with self.assertRaises(ApplianceError):
            assembler._assert_bundle_shape(shape, readonly=False)
        shutil.rmtree(os.path.join(shape, assembler.BUNDLE_FILES[0]))
        os.symlink("target", os.path.join(shape, assembler.BUNDLE_FILES[0]))
        with self.assertRaises(ApplianceError):
            assembler._assert_bundle_shape(shape, readonly=False)

    def test_existing_bundle_directory_must_remain_readonly(self) -> None:
        result = self.fixture.assemble()
        os.chmod(result.bundle_path, 0o755)
        with self.assertRaises(ApplianceError) as context:
            self.fixture.assemble()
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_BUNDLE_READONLY")

    def test_bundle_hash_and_hardening_use_pinned_file_descriptors(self) -> None:
        digest_shape = os.path.join(self.base, "digest-race")
        os.mkdir(digest_shape)
        for name in assembler.BUNDLE_FILES:
            Path(os.path.join(digest_shape, name)).write_bytes(name.encode("ascii"))
        digest_target = os.path.join(digest_shape, assembler.BUNDLE_FILES[0])
        digest_saved = digest_target + ".saved"
        external_digest = os.path.join(self.base, "external-digest")
        Path(external_digest).write_bytes(b"external")
        original_sha256_fd = assembler._sha256_fd
        raced = False

        def race_digest(descriptor: int) -> str:
            nonlocal raced
            if not raced:
                raced = True
                os.rename(digest_target, digest_saved)
                os.symlink(external_digest, digest_target)
            return original_sha256_fd(descriptor)

        assembler._sha256_fd = race_digest
        try:
            with self.assertRaises(ApplianceError) as context:
                assembler._bundle_digests(digest_shape, readonly=False)
        finally:
            assembler._sha256_fd = original_sha256_fd
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_BUNDLE_SHAPE")
        self.assertEqual(Path(external_digest).read_bytes(), b"external")

        mode_shape = os.path.join(self.base, "mode-race")
        os.mkdir(mode_shape)
        for name in assembler.BUNDLE_FILES:
            path = os.path.join(mode_shape, name)
            Path(path).write_bytes(name.encode("ascii"))
            os.chmod(path, 0o600)
        mode_target = os.path.join(mode_shape, assembler.BUNDLE_FILES[0])
        mode_saved = mode_target + ".saved"
        external_mode = os.path.join(self.base, "external-mode")
        Path(external_mode).write_bytes(b"external")
        os.chmod(external_mode, 0o600)
        original_fchmod = assembler.os.fchmod
        raced = False

        def race_mode(descriptor: int, mode: int) -> None:
            nonlocal raced
            if not raced:
                raced = True
                os.rename(mode_target, mode_saved)
                os.symlink(external_mode, mode_target)
            original_fchmod(descriptor, mode)

        assembler.os.fchmod = race_mode
        try:
            with self.assertRaises(ApplianceError) as context:
                assembler._make_bundle_readonly(mode_shape)
        finally:
            assembler.os.fchmod = original_fchmod
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_BUNDLE_SHAPE")
        self.assertEqual(stat.S_IMODE(os.lstat(external_mode).st_mode), 0o600)

    def test_readonly_digest_rechecks_modes_after_hashing(self) -> None:
        shape = os.path.join(self.base, "readonly-race")
        os.mkdir(shape)
        for name in assembler.BUNDLE_FILES:
            path = os.path.join(shape, name)
            Path(path).write_bytes(name.encode("ascii"))
            os.chmod(path, 0o444)
        os.chmod(shape, 0o555)
        target = os.path.join(shape, assembler.BUNDLE_FILES[0])
        original_sha256_fd = assembler._sha256_fd
        raced = False

        def race_modes(descriptor: int) -> str:
            nonlocal raced
            if not raced:
                raced = True
                os.chmod(shape, 0o755)
                os.chmod(target, 0o644)
            return original_sha256_fd(descriptor)

        assembler._sha256_fd = race_modes
        try:
            with self.assertRaises(ApplianceError) as context:
                assembler._bundle_digests(shape, readonly=True)
        finally:
            assembler._sha256_fd = original_sha256_fd
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_BUNDLE_READONLY")

        tight = os.path.join(self.base, "readonly-tight")
        os.mkdir(tight)
        for name in assembler.BUNDLE_FILES:
            path = os.path.join(tight, name)
            Path(path).write_bytes(name.encode("ascii"))
            os.chmod(path, 0o400)
        os.chmod(tight, 0o500)
        with self.assertRaises(ApplianceError) as context:
            assembler._bundle_digests(tight, readonly=True)
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_BUNDLE_READONLY")

    def test_stale_scavenging_and_suspicious_or_live_nodes_fail_closed(self) -> None:
        name = "-".join(self.fixture.address)
        stage_parent = os.path.join(self.fixture.output, ".h3-staging")
        stale = os.path.join(stage_parent, name)
        os.makedirs(os.path.join(stale, "work"), mode=0o700)
        os.makedirs(os.path.join(self.fixture.output, ".h3-owners"))
        open(os.path.join(self.fixture.output, ".h3-owners", name + ".lock"), "a+b").close()
        result = self.fixture.assemble()
        self.assertTrue(os.path.isdir(result.bundle_path))

        stale_output = os.path.join(self.base, "stale-symlink")
        stale_address = ("a" * 64, "b" * 64)
        stale = _stale_stage(stale_output, stale_address)
        Path(os.path.join(stale, "work", "runtime-policy-tree", "etc", "target")).write_bytes(b"target")
        os.symlink("target", os.path.join(stale, "work", "runtime-policy-tree", "etc", "link"))
        recreated = assembler._prepare_stage(stale_output, stale_address, _stale_lock())
        self.assertEqual(recreated, stale)
        self.assertEqual(os.listdir(recreated), [])

        for kind in ("hard-link", "fifo"):
            unsafe_output = os.path.join(self.base, "unsafe-" + kind)
            unsafe_address = ("c" * 64, "d" * 64)
            unsafe = _stale_stage(unsafe_output, unsafe_address)
            target = os.path.join(unsafe, "work", "runtime-policy-tree", "etc", "target")
            external = os.path.join(unsafe_output, "external")
            if kind == "hard-link":
                Path(external).write_bytes(b"outside")
                os.chmod(external, 0o640)
                os.link(external, target)
            else:
                os.mkfifo(target)
            with self.assertRaises(ApplianceError) as context:
                assembler._prepare_stage(unsafe_output, unsafe_address, _stale_lock())
            self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_SCAVENGE")
            self.assertTrue(os.path.lexists(unsafe))
            if kind == "hard-link":
                self.assertEqual(Path(external).read_bytes(), b"outside")
                self.assertEqual(stat.S_IMODE(os.lstat(external).st_mode), 0o640)

        other = _Fixture(os.path.join(self.base, "other"))
        other_name = "-".join(other.address)
        os.makedirs(os.path.join(other.output, ".h3-staging"))
        suspicious = os.path.join(other.output, ".h3-staging", other_name)
        Path(suspicious).write_bytes(b"not a stage")
        with self.assertRaises(ApplianceError) as context:
            assembler._prepare_stage(other.output, other.address)
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_SCAVENGE")
        self.assertTrue(os.path.isfile(suspicious))

        live_output = os.path.join(self.base, "live-output")
        live_name = "live-address"
        live_stage = os.path.join(live_output, ".h3-staging", live_name)
        os.makedirs(os.path.join(live_stage, "work"))
        owner_path = os.path.join(live_output, ".h3-owners", live_name + ".lock")
        os.makedirs(os.path.dirname(owner_path))
        handle = open(owner_path, "a+b")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(ApplianceError) as context:
                assembler._prepare_stage(live_output, ("live", "address"))
            self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_SCAVENGE")
            self.assertTrue(os.path.isdir(live_stage))
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    def test_symlinked_infrastructure_is_rejected_without_following_it(self) -> None:
        external = os.path.join(self.base, "outside-staging")
        os.mkdir(external)
        staging = os.path.join(self.fixture.output, ".h3-staging")
        os.symlink(external, staging)
        with self.assertRaises(ApplianceError) as context:
            self.fixture.assemble()
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_STAGING")
        self.assertEqual(os.listdir(external), [])

        other = _Fixture(os.path.join(self.base, "symlinked-bundle-root"))
        outside_bundle = os.path.join(self.base, "outside-bundle")
        os.mkdir(outside_bundle)
        os.symlink(outside_bundle, os.path.join(other.output, "built_unverified"))
        with self.assertRaises(ApplianceError) as context:
            assembler._prepare_destination_parent(other.output, other.address)
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_STAGING")
        self.assertEqual(os.listdir(outside_bundle), [])

        lock_target = os.path.join(self.base, "outside-lock-target")
        Path(lock_target).write_bytes(b"unchanged")
        os.makedirs(os.path.join(other.output, ".h3-locks"), exist_ok=True)
        lock_path = os.path.join(other.output, ".h3-locks", "-".join(other.address) + ".lock")
        os.symlink(lock_target, lock_path)
        with self.assertRaises(ApplianceError) as context:
            with assembler._address_lease(other.output, other.address):
                self.fail("symlinked address lock must not be acquired")
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_LEASE")
        self.assertEqual(Path(lock_target).read_bytes(), b"unchanged")

        hardlink_fixture = _Fixture(os.path.join(self.base, "hardlinked-lock"))
        hardlink_target = os.path.join(self.base, "outside-hardlink-target")
        Path(hardlink_target).write_bytes(b"unchanged")
        os.makedirs(os.path.join(hardlink_fixture.output, ".h3-locks"), exist_ok=True)
        hardlink_path = os.path.join(
            hardlink_fixture.output,
            ".h3-locks",
            "-".join(hardlink_fixture.address) + ".lock",
        )
        os.link(hardlink_target, hardlink_path)
        with self.assertRaises(ApplianceError) as context:
            with assembler._address_lease(hardlink_fixture.output, hardlink_fixture.address):
                self.fail("hardlinked address lock must not be acquired")
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_LEASE")
        self.assertEqual(Path(hardlink_target).read_bytes(), b"unchanged")


if __name__ == "__main__":
    unittest.main(verbosity=2)
