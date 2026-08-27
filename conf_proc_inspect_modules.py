#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent inspector-side kernel module signature re-verification.

Deliberately does NOT import conf_proc_build_modules.py. Locates modules
from the inspector's own extracted tree inventory, independently re-runs
real `openssl cms -verify`, and compares the result against the emitted
manifest's claimed module_authority section -- the manifest's claims are
never trusted without this independent recomputation.
"""

from __future__ import annotations

import os

from conf_proc_guard import HermeticGuard
from conf_proc_lock import Lock
from conf_proc_module_authority import check_authorized_signers_match_bundle, decode_certificate_bundle  # noqa: F401
from conf_proc_module_sig import PKEY_ID_PKCS7, split_module_signature
from conf_proc_reasons import CP_MODULE_KEYRING, CP_MODULE_SIGNER, ApplianceError


def rederive_module_authority(
    guard: HermeticGuard,
    *,
    openssl_path: str,
    lock: Lock,
    trusted_bundle_pem_path: str,
    extract_dir: str,
    image: str,
    work_dir: str,
) -> tuple[list[dict], list[dict]]:
    """Independently re-verify and inventory modules/firmware for one image."""

    authorized = {signer.certificate_sha256 for signer in lock.authorized_module_signers}
    module_inventory: list[dict] = []
    firmware_inventory: list[dict] = []

    for lock_input in lock.inputs:
        for placement in lock_input.placements:
            if placement.image != image or placement.node_type != "file":
                continue
            path = placement.path
            extracted_path = os.path.join(extract_dir, path.lstrip("/"))

            if path.endswith(".ko"):
                signer_sha256 = _reverify_module(
                    guard, openssl_path=openssl_path, module_path=extracted_path,
                    trusted_bundle_pem_path=trusted_bundle_pem_path, authorized=authorized, work_dir=work_dir,
                )
                module_inventory.append({"path": path, "sha256": lock_input.sha256, "signer_certificate_sha256": signer_sha256})
            elif "/firmware/" in path:
                firmware_inventory.append({"path": path, "sha256": lock_input.sha256})

    module_inventory.sort(key=lambda entry: entry["path"])
    firmware_inventory.sort(key=lambda entry: entry["path"])
    return module_inventory, firmware_inventory


def compare_module_authority(
    rederived: tuple[list[dict], list[dict]],
    claimed_module_authority: dict,
) -> None:
    """Fail loud on any divergence between re-derivation and the manifest's claim."""

    rederived_modules, rederived_firmware = rederived
    if rederived_modules != claimed_module_authority["module_inventory"]:
        raise ApplianceError(CP_MODULE_KEYRING, "emitted module_inventory does not match independent re-verification")
    if rederived_firmware != claimed_module_authority["firmware_inventory"]:
        raise ApplianceError(CP_MODULE_KEYRING, "emitted firmware_inventory does not match independent inventory")


def _reverify_module(
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
    content_path = os.path.join(work_dir, f"{basename}.rederived.content")
    sig_path = os.path.join(work_dir, f"{basename}.rederived.sig.der")
    extracted_signer_path = os.path.join(work_dir, f"{basename}.rederived.signer.pem")
    with open(content_path, "wb") as handle:
        handle.write(module_content)
    with open(sig_path, "wb") as handle:
        handle.write(signature_data)

    guard.run_tool(
        [
            openssl_path, "cms", "-verify", "-binary", "-inform", "DER",
            "-in", sig_path, "-content", content_path,
            "-noverify", "-signer", extracted_signer_path, "-out", os.devnull,
        ],
        cwd=work_dir,
    )
    with open(extracted_signer_path, "rb") as handle:
        extracted_signer_bytes = handle.read()
    fingerprints = decode_certificate_bundle(extracted_signer_bytes)
    if len(fingerprints) != 1:
        raise ApplianceError(CP_MODULE_SIGNER, f"{module_path}: expected exactly one embedded signer certificate, found {len(fingerprints)}")
    signer_sha256 = fingerprints[0].certificate_sha256
    if signer_sha256 not in authorized:
        raise ApplianceError(CP_MODULE_SIGNER, f"{module_path}: signer {signer_sha256} is not in the lock's authorized signer set")

    guard.run_tool(
        [
            openssl_path, "cms", "-verify", "-binary", "-inform", "DER",
            "-in", sig_path, "-content", content_path,
            "-CAfile", trusted_bundle_pem_path, "-no-CApath", "-purpose", "any", "-out", os.devnull,
        ],
        cwd=work_dir,
    )
    return signer_sha256
