#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Builder-side kernel module signature verification and inventory.

Locates every packaged kernel module and firmware blob from the lock's own
declared placements, verifies each module's signature against the lock's
authorized signer set using real `openssl cms -verify` (never a Python
reimplementation of signature verification), and produces the
module_authority manifest section. The inspector's independent
re-verification lives in conf_proc_inspect_modules.py and does not import
this module.
"""

from __future__ import annotations

import os

from conf_proc_guard import HermeticGuard
from conf_proc_lock import Lock
from conf_proc_module_authority import decode_certificate_bundle
from conf_proc_module_sig import PKEY_ID_PKCS7, split_module_signature
from conf_proc_reasons import CP_MODULE_CMS_VERIFY, CP_MODULE_COMPRESSED_UNSUPPORTED, CP_MODULE_SIGNER, ApplianceError


def verify_and_inventory_modules(
    guard: HermeticGuard,
    *,
    openssl_path: str,
    lock: Lock,
    trusted_bundle_pem_path: str,
    staging_root: str,
    image: str,
    work_dir: str,
) -> tuple[list[dict], list[dict]]:
    """Verify every module and inventory every firmware blob for one image.

    Returns ``(module_inventory, firmware_inventory)`` -- lists of dicts
    ready to slot into the manifest's ``module_authority`` section.
    """

    authorized = {signer.certificate_sha256 for signer in lock.authorized_module_signers}
    module_inventory: list[dict] = []
    firmware_inventory: list[dict] = []

    for lock_input in lock.inputs:
        for placement in lock_input.placements:
            if placement.image != image or placement.node_type != "file":
                continue
            path = placement.path
            staged_path = os.path.join(staging_root, path.lstrip("/"))

            if path.endswith(".ko.zst"):
                raise ApplianceError(
                    CP_MODULE_COMPRESSED_UNSUPPORTED,
                    f"{path}: .ko.zst modules require a declared zstdcat build tool, which is not yet supported",
                )
            if path.endswith(".ko"):
                signer_sha256 = _verify_module(
                    guard, openssl_path=openssl_path, module_path=staged_path,
                    trusted_bundle_pem_path=trusted_bundle_pem_path, authorized=authorized, work_dir=work_dir,
                )
                module_inventory.append({"path": path, "sha256": lock_input.sha256, "signer_certificate_sha256": signer_sha256})
            elif "/firmware/" in path:
                firmware_inventory.append({"path": path, "sha256": lock_input.sha256})

    module_inventory.sort(key=lambda entry: entry["path"])
    firmware_inventory.sort(key=lambda entry: entry["path"])
    return module_inventory, firmware_inventory


def _verify_module(
    guard: HermeticGuard,
    *,
    openssl_path: str,
    module_path: str,
    trusted_bundle_pem_path: str,
    authorized: set[str],
    work_dir: str,
) -> str:
    with open(module_path, "rb") as handle:
        data = handle.read()
    module_content, signer_name, key_id, signature_data, trailer = split_module_signature(data)

    if trailer.id_type != PKEY_ID_PKCS7 or trailer.algo != 0 or trailer.hash_algo != 0 or signer_name or key_id:
        raise ApplianceError(CP_MODULE_SIGNER, f"{module_path}: unsupported module signature trailer shape")

    basename = os.path.basename(module_path)
    content_path = os.path.join(work_dir, f"{basename}.content")
    sig_path = os.path.join(work_dir, f"{basename}.sig.der")
    extracted_signer_path = os.path.join(work_dir, f"{basename}.signer.pem")
    with open(content_path, "wb") as handle:
        handle.write(module_content)
    with open(sig_path, "wb") as handle:
        handle.write(signature_data)

    try:
        guard.run_tool(
            [
                openssl_path, "cms", "-verify", "-binary", "-inform", "DER",
                "-in", sig_path, "-content", content_path,
                "-noverify", "-signer", extracted_signer_path, "-out", os.devnull,
            ],
            cwd=work_dir,
        )
    except ApplianceError as exc:
        raise ApplianceError(CP_MODULE_CMS_VERIFY, f"{module_path}: CMS signature is not internally valid: {exc}") from exc
    with open(extracted_signer_path, "rb") as handle:
        extracted_signer_bytes = handle.read()
    fingerprints = decode_certificate_bundle(extracted_signer_bytes)
    if len(fingerprints) != 1:
        raise ApplianceError(CP_MODULE_SIGNER, f"{module_path}: expected exactly one embedded signer certificate, found {len(fingerprints)}")
    signer_sha256 = fingerprints[0].certificate_sha256
    if signer_sha256 not in authorized:
        raise ApplianceError(CP_MODULE_SIGNER, f"{module_path}: signer {signer_sha256} is not in the lock's authorized signer set")

    try:
        guard.run_tool(
            [
                openssl_path, "cms", "-verify", "-binary", "-inform", "DER",
                "-in", sig_path, "-content", content_path,
                "-CAfile", trusted_bundle_pem_path, "-no-CApath", "-purpose", "any", "-out", os.devnull,
            ],
            cwd=work_dir,
        )
    except ApplianceError as exc:
        raise ApplianceError(CP_MODULE_CMS_VERIFY, f"{module_path}: CMS trust-path verification against the locked bundle failed: {exc}") from exc
    return signer_sha256
