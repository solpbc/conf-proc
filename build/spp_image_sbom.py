#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""SPDX 2.3 Image SBOM generator for SPP sealed appliance."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Final

from spp_disk import BUILD_EPOCH, sha256_bytes, sha256_file

SPDX_VERSION: Final = "SPDX-2.3"
DATA_LICENSE: Final = "CC0-1.0"
DOCUMENT_SPDX_ID: Final = "SPDXRef-DOCUMENT"
IMAGE_PACKAGE_ID: Final = "SPDXRef-Package-spp-sealed-image"
CREATOR_TOOL: Final = "Tool: spp-image-sbom-v1"

_SANITIZE_RE: Final = re.compile(r"[^A-Za-z0-9.-]")


def _sanitize(value: str) -> str:
    return _SANITIZE_RE.sub("-", value)


def _file_spdx_id(rel_path: str) -> str:
    return f"SPDXRef-File-{_sanitize(rel_path)}"


def _pkg_purpose(kind: str, name: str) -> str:
    if kind == "deb":
        return "FIRMWARE" if "firmware" in name.lower() else "APPLICATION"
    if kind in ("wheel", "model", "recipe"):
        return "APPLICATION"
    if kind in ("git", "tree"):
        return "FILE"
    if kind == "boot_kernel":
        return "OPERATING-SYSTEM"
    if kind in ("boot_stub", "boot_initrd", "boot_ukify"):
        return "APPLICATION"
    return "APPLICATION"


def generate_image_sbom(
    tree: Path,
    origins: list[dict[str, object]],
    boot: dict[str, object],
    *,
    build_epoch: int = BUILD_EPOCH,
) -> dict[str, object]:
    created_str = datetime.fromtimestamp(build_epoch, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    # Walk all regular files in tree, sorted by relative posix path
    tree_resolved = tree.resolve()
    file_entries: list[dict[str, object]] = []
    file_spdx_by_path: dict[str, str] = {}
    regular_file_rel_paths: set[str] = set()

    for path in sorted(tree.rglob("*"), key=lambda p: p.relative_to(tree).as_posix()):
        if path.is_file() and not path.is_symlink():
            rel_posix = path.relative_to(tree).as_posix()
            regular_file_rel_paths.add(rel_posix)
            digest = sha256_file(path)
            spdx_id = _file_spdx_id(rel_posix)
            file_spdx_by_path[rel_posix] = spdx_id
            file_entries.append(
                {
                    "SPDXID": spdx_id,
                    "fileName": rel_posix,
                    "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                }
            )

    # Check that every regular file belongs to exactly one origin
    origin_files_seen: set[str] = set()
    for origin in origins:
        orig_files = origin.get("files", [])
        if isinstance(orig_files, list):
            for rel in orig_files:
                if rel in origin_files_seen:
                    raise RuntimeError(f"file {rel!r} claimed by multiple origins")
                origin_files_seen.add(rel)

    unaccounted = regular_file_rel_paths - origin_files_seen
    if unaccounted:
        first_missing = sorted(unaccounted)[0]
        raise RuntimeError(
            f"regular file {first_missing!r} has no origin record (total unaccounted: {len(unaccounted)})"
        )

    # Packages
    packages: list[dict[str, object]] = []

    # Appliance top-level package
    packages.append(
        {
            "SPDXID": IMAGE_PACKAGE_ID,
            "name": "spp-sealed-image",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
            "originator": "NOASSERTION",
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": sha256_bytes(
                        json.dumps(file_entries, sort_keys=True, separators=(",", ":")).encode()
                    ),
                }
            ],
            "primaryPackagePurpose": "APPLICATION",
            "versionInfo": "1.0",
        }
    )

    # Origin packages
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": DOCUMENT_SPDX_ID,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": IMAGE_PACKAGE_ID,
        }
    ]

    for idx, origin in enumerate(origins, start=1):
        kind = str(origin.get("kind", "unknown"))
        name = str(origin.get("name", f"origin-{idx}"))
        version = str(origin.get("version", "unversioned"))
        sha = str(origin.get("sha256", ""))
        if not sha:
            sha = sha256_bytes(f"{kind}:{name}:{version}".encode("utf-8"))
        pkg_spdx_id = f"SPDXRef-Package-{kind}-{_sanitize(name)}"
        purpose = _pkg_purpose(kind, name)

        packages.append(
            {
                "SPDXID": pkg_spdx_id,
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "supplier": "NOASSERTION",
                "originator": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": sha}],
                "primaryPackagePurpose": purpose,
            }
        )

        orig_files = origin.get("files", [])
        if isinstance(orig_files, list):
            for rel in orig_files:
                if rel in file_spdx_by_path:
                    relationships.append(
                        {
                            "spdxElementId": pkg_spdx_id,
                            "relationshipType": "CONTAINS",
                            "relatedSpdxElement": file_spdx_by_path[rel],
                        }
                    )

    # Boot packages
    if "kernel_bzimage" in boot:
        kb_path = Path(str(boot["kernel_bzimage"]))
        if not kb_path.is_file():
            raise SystemExit(f"boot input 'kernel_bzimage' is not a regular file: {kb_path}")
        kb_sha = sha256_file(kb_path)
        k_rel = str(boot.get("kernel_release", "unknown"))
        k_pkg_id = "SPDXRef-Package-boot-kernel"
        packages.append(
            {
                "SPDXID": k_pkg_id,
                "name": "kernel-bzimage",
                "versionInfo": k_rel,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "supplier": "NOASSERTION",
                "originator": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": kb_sha}],
                "primaryPackagePurpose": _pkg_purpose("boot_kernel", "kernel"),
            }
        )

    if "stub" in boot:
        stub_path = Path(str(boot["stub"]))
        if not stub_path.is_file():
            raise SystemExit(f"boot input 'stub' is not a regular file: {stub_path}")
        stub_sha = sha256_file(stub_path)
        stub_pkg_id = "SPDXRef-Package-boot-stub"
        packages.append(
            {
                "SPDXID": stub_pkg_id,
                "name": "systemd-stub",
                "versionInfo": "unversioned",
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "supplier": "NOASSERTION",
                "originator": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": stub_sha}],
                "primaryPackagePurpose": _pkg_purpose("boot_stub", "stub"),
            }
        )

    if "initrd" in boot:
        initrd_path = Path(str(boot["initrd"]))
        if not initrd_path.is_file():
            raise SystemExit(f"boot input 'initrd' is not a regular file: {initrd_path}")
        initrd_sha = sha256_file(initrd_path)
        initrd_pkg_id = "SPDXRef-Package-boot-initrd"
        packages.append(
            {
                "SPDXID": initrd_pkg_id,
                "name": "initramfs",
                "versionInfo": "unversioned",
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "supplier": "NOASSERTION",
                "originator": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": initrd_sha}],
                "primaryPackagePurpose": _pkg_purpose("boot_initrd", "initrd"),
            }
        )

    if "ukify" in boot:
        ukify_path = Path(str(boot["ukify"]))
        if not ukify_path.is_file():
            raise SystemExit(f"boot input 'ukify' is not a regular file: {ukify_path}")
        ukify_sha = sha256_file(ukify_path)
        ukify_pkg_id = "SPDXRef-Package-boot-ukify"
        packages.append(
            {
                "SPDXID": ukify_pkg_id,
                "name": "ukify",
                "versionInfo": "unversioned",
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "supplier": "NOASSERTION",
                "originator": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": ukify_sha}],
                "primaryPackagePurpose": _pkg_purpose("boot_ukify", "ukify"),
            }
        )

    files_canonical_bytes = json.dumps(
        file_entries, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    doc_namespace = (
        "https://spp.solstone.app/image-sbom/" + hashlib.sha256(files_canonical_bytes).hexdigest()
    )

    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": DOCUMENT_SPDX_ID,
        "name": "spp-sealed-image",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": created_str,
            "creators": [CREATOR_TOOL],
        },
        "packages": packages,
        "files": file_entries,
        "relationships": relationships,
        "documentDescribes": [IMAGE_PACKAGE_ID],
    }
