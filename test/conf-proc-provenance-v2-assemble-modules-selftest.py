#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Module and firmware observation checks for dormant H3."""

from __future__ import annotations

import datetime
import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_module_sig as module_sig  # noqa: E402
import conf_proc_provenance_v2_assemble as assembler  # noqa: E402
from conf_proc_build_modules import verify_and_inventory_modules  # noqa: E402
from conf_proc_guard import HermeticGuard, ToolDeclaration  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


OPENSSL = "/usr/bin/openssl"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _certificate(common_name: str) -> tuple[object, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
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
    return key, certificate


def _signed_module(key: object, certificate: x509.Certificate) -> bytes:
    payload = b"H3 signed module\n"
    signature = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(payload)
        .add_signer(certificate, key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary, pkcs7.PKCS7Options.DetachedSignature])
    )
    return module_sig.build_module_signature(payload, b"", b"", signature, id_type=module_sig.PKEY_ID_PKCS7)


def _guard(bundle_path: str) -> HermeticGuard:
    return HermeticGuard(
        allowed_reads=frozenset({OPENSSL, bundle_path}),
        tools={OPENSSL: ToolDeclaration(OPENSSL, _sha(Path(OPENSSL).read_bytes()))},
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"},
        build_epoch=946684800,
    )


def _placement(image: str, path: str) -> object:
    return SimpleNamespace(image=image, path=path, node_type="file")


class H3ModuleObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.key, self.certificate = _certificate("authorized signer")
        self.bundle = os.path.join(self.base, "trusted.pem")
        Path(self.bundle).write_bytes(self.certificate.public_bytes(serialization.Encoding.PEM))
        self.signer = SimpleNamespace(certificate_sha256=self.certificate.fingerprint(hashes.SHA256()).hex())

    def _inventory(self, placements: tuple[tuple[str, str, bytes], ...], *, signer: object | None = None) -> tuple[list[dict], list[dict]]:
        tree = os.path.join(self.base, "tree")
        os.makedirs(tree, exist_ok=True)
        inputs = []
        for index, (image, path, data) in enumerate(placements):
            if data:
                destination = os.path.join(tree, path.lstrip("/"))
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                Path(destination).write_bytes(data)
            inputs.append(SimpleNamespace(sha256=_sha(data), placements=(_placement(image, path),)))
        lock = SimpleNamespace(inputs=tuple(inputs), authorized_module_signers=(signer or self.signer,))
        guard = _guard(self.bundle)
        with guard.pin_tools((OPENSSL,)):
            return verify_and_inventory_modules(
                guard, openssl_path=OPENSSL, lock=lock, trusted_bundle_pem_path=self.bundle,
                staging_root=tree, image="models", work_dir=self.base,
            )

    def test_signed_module_and_firmware_are_observed_once_and_sorted(self) -> None:
        module = _signed_module(self.key, self.certificate)
        modules, firmware = self._inventory(
            (("models", "/z/modules/driver.ko", module), ("models", "/a/firmware/device.bin", b"firmware"))
        )
        self.assertEqual([row["path"] for row in modules], ["/z/modules/driver.ko"])
        self.assertEqual([row["path"] for row in firmware], ["/a/firmware/device.bin"])
        observations = tuple(
            assembler.ProvenanceV2ModuleObservation(**row) for row in sorted(modules, key=lambda row: row["path"])
        )
        firmware_observations = tuple(
            assembler.ProvenanceV2FirmwareObservation(**row) for row in sorted(firmware, key=lambda row: row["path"])
        )
        self.assertEqual(tuple(item.path for item in observations), tuple(sorted(item.path for item in observations)))
        self.assertEqual(tuple(item.path for item in firmware_observations), tuple(sorted(item.path for item in firmware_observations)))

    def test_unauthorized_missing_and_compressed_modules_fail(self) -> None:
        other_key, other_certificate = _certificate("unauthorized signer")
        with self.assertRaises(ApplianceError) as context:
            self._inventory((("models", "/modules/driver.ko", _signed_module(other_key, other_certificate)),))
        self.assertEqual(context.exception.reason_code, "CP_MODULE_SIGNER")
        with self.assertRaises(FileNotFoundError):
            self._inventory((("models", "/modules/missing.ko", b""),))
        with self.assertRaises(ApplianceError) as context:
            self._inventory((("models", "/modules/driver.ko.zst", b"compressed"),))
        self.assertEqual(context.exception.reason_code, "CP_MODULE_COMPRESSED_UNSUPPORTED")

    def test_lock_backed_inventory_rejects_extra_and_cross_image_collision(self) -> None:
        module = _signed_module(self.key, self.certificate)
        lock_input = SimpleNamespace(sha256=_sha(module), placements=(_placement("models", "/modules/driver.ko"),))
        lock = SimpleNamespace(inputs=(lock_input,))
        valid = [{"path": "/modules/driver.ko", "sha256": _sha(module), "signer_certificate_sha256": self.signer.certificate_sha256}]
        assembler._validate_inventory_against_lock(lock, valid, [])
        with self.assertRaises(ApplianceError) as context:
            assembler._validate_inventory_against_lock(lock, valid + [{"path": "/modules/extra.ko", "sha256": _sha(module), "signer_certificate_sha256": self.signer.certificate_sha256}], [])
        self.assertEqual(context.exception.reason_code, "CP_MODULE_MISSING")
        collision = SimpleNamespace(
            inputs=(
                SimpleNamespace(id="models-driver", placements=(_placement("models", "/modules/driver.ko"),)),
                SimpleNamespace(id="runtime-driver", placements=(_placement("runtime-policy", "/modules/driver.ko"),)),
            )
        )
        with self.assertRaises(ApplianceError) as context:
            assembler._preflight_placements(collision)
        self.assertEqual(context.exception.reason_code, "CP_PROVENANCE_V2_MANIFEST_PRODUCTION")


if __name__ == "__main__":
    unittest.main(verbosity=2)
