#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftests for kernel module signature verification: builds a real,
self-signed CMS/PKCS#7 signature over a fake module payload and verifies
it with real `openssl cms -verify`, exercising both the builder-side and
independent inspector-side code paths. No real NVIDIA or kernel content."""

from __future__ import annotations

import datetime
import hashlib
import os
import shutil
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

import conf_proc_build_modules as build_modules  # noqa: E402
import conf_proc_inspect_modules as inspect_modules  # noqa: E402
import conf_proc_module_authority as module_authority  # noqa: E402
import conf_proc_module_sig as module_sig  # noqa: E402
from conf_proc_guard import HermeticGuard, ToolDeclaration  # noqa: E402
from conf_proc_lock import AuthorizedModuleSigner, Lock, LockInput, Placement  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _find_tool(*candidates: str) -> str:
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    raise AssertionError(f"required real tool missing: none of {candidates} is present")


OPENSSL = _find_tool("/usr/bin/openssl")


def _sha256_file(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _sha(n: int) -> str:
    return format(n, "064x")


def _generate_signer(common_name: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_signed_module(payload: bytes, key, cert) -> bytes:
    signed = pkcs7.PKCS7SignatureBuilder().set_data(payload).add_signer(cert, key, hashes.SHA256()).sign(
        serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary, pkcs7.PKCS7Options.DetachedSignature]
    )
    return module_sig.build_module_signature(payload, b"", b"", signed, id_type=module_sig.PKEY_ID_PKCS7)


def _placement(image, path, node_type, mode, uid, gid, *, source_input_id=None, target=None):
    return Placement(image=image, path=path, node_type=node_type, mode=mode, uid=uid, gid=gid, xattrs=(), source_input_id=source_input_id, target=target)


class ModuleVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)

        self.key, self.cert = _generate_signer("conf-proc fixture signer")
        self.other_key, self.other_cert = _generate_signer("conf-proc unauthorized signer")

        self.trusted_bundle_pem_path = os.path.join(self.base, "trusted-bundle.pem")
        with open(self.trusted_bundle_pem_path, "wb") as handle:
            handle.write(self.cert.public_bytes(serialization.Encoding.PEM))
        with open(self.trusted_bundle_pem_path, "rb") as handle:
            self.trusted_bundle_bytes = handle.read()

        certificate_sha256 = self.cert.fingerprint(hashes.SHA256()).hex()
        spki_der = self.cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        spki_sha256 = hashlib.sha256(spki_der).hexdigest()
        subject_sha256 = hashlib.sha256(self.cert.subject.public_bytes()).hexdigest()

        self.payload = b"fake fixture module payload, not real NVIDIA or kernel content\n"
        signed_module = _build_signed_module(self.payload, self.key, self.cert)

        self.staging_root = os.path.join(self.base, "staging")
        module_dir = os.path.join(self.staging_root, "lib", "modules", "conf-proc-fixture", "kernel", "drivers", "video")
        os.makedirs(module_dir)
        module_path = os.path.join(module_dir, "nvidia-cc-fixture.ko")
        with open(module_path, "wb") as handle:
            handle.write(signed_module)
        self.module_relative_path = "/lib/modules/conf-proc-fixture/kernel/drivers/video/nvidia-cc-fixture.ko"

        firmware_dir = os.path.join(self.staging_root, "lib", "firmware", "nvidia", "cc")
        os.makedirs(firmware_dir)
        with open(os.path.join(firmware_dir, "fixture-gsp.fw"), "wb") as handle:
            handle.write(b"fake fixture firmware bytes, not real NVIDIA content\n")
        self.firmware_relative_path = "/lib/firmware/nvidia/cc/fixture-gsp.fw"

        driver_input = LockInput(
            id="driver-1", role="nvidia_cc_driver", component="nvidia-cc-fixture", sha256=hashlib.sha256(signed_module).hexdigest(),
            size_bytes=len(signed_module), source_local_path="driver.ko", source_retrieval_scheme="generated",
            source_retrieval_identity="fixture:driver", source_retrieval_immutable_ref="v1", derivation_kind="fixture",
            derivation_recipe_id="r1", derivation_parent_ids=(), derivation_parameters_sha256=_sha(2),
            placements=(_placement("runtime-policy", self.module_relative_path, "file", 0o644, 0, 0, source_input_id="driver-1"),),
        )
        firmware_bytes = b"fake fixture firmware bytes, not real NVIDIA content\n"
        firmware_input = LockInput(
            id="firmware-1", role="nvidia_cc_firmware", component="fixture-gsp-fw", sha256=hashlib.sha256(firmware_bytes).hexdigest(),
            size_bytes=len(firmware_bytes), source_local_path="firmware.fw", source_retrieval_scheme="generated",
            source_retrieval_identity="fixture:firmware", source_retrieval_immutable_ref="v1", derivation_kind="fixture",
            derivation_recipe_id="r1", derivation_parent_ids=(), derivation_parameters_sha256=_sha(2),
            placements=(_placement("runtime-policy", self.firmware_relative_path, "file", 0o644, 0, 0, source_input_id="firmware-1"),),
        )
        bundle_input = LockInput(
            id="bundle-1", role="kernel_trusted_cert_bundle", component="trusted-bundle", sha256=hashlib.sha256(self.trusted_bundle_bytes).hexdigest(),
            size_bytes=len(self.trusted_bundle_bytes), source_local_path="bundle.pem", source_retrieval_scheme="generated",
            source_retrieval_identity="fixture:bundle", source_retrieval_immutable_ref="v1", derivation_kind="fixture",
            derivation_recipe_id="r1", derivation_parent_ids=(), derivation_parameters_sha256=_sha(2), placements=(),
        )
        self.lock = Lock(
            schema="conf-proc-lock/v1", lock_version=1, base_image_record=None, future_cmdline="console=ttyS0",
            inputs=(driver_input, firmware_input, bundle_input),
            authorized_module_signers=(
                AuthorizedModuleSigner(certificate_sha256=certificate_sha256, spki_sha256=spki_sha256, subject_sha256=subject_sha256, usage="kernel-module-signing"),
            ),
            image_specs={"runtime-policy": {}, "models": {}}, policy_input_id="p", tool_ids=(),
        )

        self.guard = HermeticGuard(
            allowed_reads=frozenset({OPENSSL}),
            tools={OPENSSL: ToolDeclaration(OPENSSL, _sha256_file(OPENSSL))},
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"},
            build_epoch=1700000000,
        )

    def test_build_side_verifies_and_inventories(self) -> None:
        modules, firmware = build_modules.verify_and_inventory_modules(
            self.guard, openssl_path=OPENSSL, lock=self.lock, trusted_bundle_pem_path=self.trusted_bundle_pem_path,
            staging_root=self.staging_root, image="runtime-policy", work_dir=self.base,
        )
        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0]["path"], self.module_relative_path)
        self.assertEqual(len(firmware), 1)
        self.assertEqual(firmware[0]["path"], self.firmware_relative_path)

    def test_inspector_independently_reaches_the_same_result(self) -> None:
        build_result = build_modules.verify_and_inventory_modules(
            self.guard, openssl_path=OPENSSL, lock=self.lock, trusted_bundle_pem_path=self.trusted_bundle_pem_path,
            staging_root=self.staging_root, image="runtime-policy", work_dir=self.base,
        )
        # The inspector re-derives from its OWN extracted tree (here, the
        # same staging tree stands in for "independently extracted image
        # content" since this test isolates module verification from
        # squashfs extraction, already covered in conf-proc-image-selftest.py).
        inspect_result = inspect_modules.rederive_module_authority(
            self.guard, openssl_path=OPENSSL, lock=self.lock, trusted_bundle_pem_path=self.trusted_bundle_pem_path,
            extract_dir=self.staging_root, image="runtime-policy", work_dir=self.base,
        )
        self.assertEqual(build_result, inspect_result)
        inspect_modules.compare_module_authority(
            inspect_result, {"module_inventory": build_result[0], "firmware_inventory": build_result[1]}
        )

    def test_reject_unauthorized_signer(self) -> None:
        signed_module = _build_signed_module(self.payload, self.other_key, self.other_cert)
        module_path = os.path.join(
            self.staging_root, "lib", "modules", "conf-proc-fixture", "kernel", "drivers", "video", "nvidia-cc-fixture.ko"
        )
        with open(module_path, "wb") as handle:
            handle.write(signed_module)
        with self.assertRaises(ApplianceError) as ctx:
            build_modules.verify_and_inventory_modules(
                self.guard, openssl_path=OPENSSL, lock=self.lock, trusted_bundle_pem_path=self.trusted_bundle_pem_path,
                staging_root=self.staging_root, image="runtime-policy", work_dir=self.base,
            )
        self.assertEqual(ctx.exception.reason_code, "CP_MODULE_SIGNER")

    def test_reject_tampered_module_content(self) -> None:
        signed_module = _build_signed_module(self.payload, self.key, self.cert)
        tampered = bytearray(signed_module)
        tampered[0] ^= 0xFF
        module_path = os.path.join(
            self.staging_root, "lib", "modules", "conf-proc-fixture", "kernel", "drivers", "video", "nvidia-cc-fixture.ko"
        )
        with open(module_path, "wb") as handle:
            handle.write(bytes(tampered))
        with self.assertRaises(ApplianceError) as ctx:
            build_modules.verify_and_inventory_modules(
                self.guard, openssl_path=OPENSSL, lock=self.lock, trusted_bundle_pem_path=self.trusted_bundle_pem_path,
                staging_root=self.staging_root, image="runtime-policy", work_dir=self.base,
            )
        self.assertEqual(ctx.exception.reason_code, "CP_MODULE_CMS_VERIFY")

    def test_authorized_signers_must_exactly_match_bundle(self) -> None:
        module_authority.check_authorized_signers_match_bundle(self.lock, self.trusted_bundle_bytes)

        extra_signer_key, extra_signer_cert = _generate_signer("conf-proc extra bundle-only signer")
        bigger_bundle = self.trusted_bundle_bytes + extra_signer_cert.public_bytes(serialization.Encoding.PEM)
        with self.assertRaises(ApplianceError) as ctx:
            module_authority.check_authorized_signers_match_bundle(self.lock, bigger_bundle)
        self.assertEqual(ctx.exception.reason_code, "CP_MODULE_KEYRING")


if __name__ == "__main__":
    unittest.main(verbosity=2)
