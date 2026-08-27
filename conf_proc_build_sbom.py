#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Builder-side SPDX 2.3 SBOM assembly from a parsed Lock.

Maps every locked component and every filesystem placement to SPDX
packages/files/relationships. The inspector's independent re-derivation
lives in conf_proc_inspect_sbom.py and does not import this module.
"""

from __future__ import annotations

from datetime import datetime, timezone

from conf_proc_geometry import derive_build_epoch
from conf_proc_json import canonical_dumps
from conf_proc_lock import Lock
from conf_proc_sbom import (
    APPLIANCE_PACKAGE_ID,
    CREATOR_TOOL,
    DATA_LICENSE,
    DOCUMENT_SPDX_ID,
    RELATIONSHIP_BUILD_TOOL_OF,
    RELATIONSHIP_CONTAINS,
    RELATIONSHIP_GENERATED_FROM,
    RELATIONSHIP_RUNTIME_DEPENDENCY_OF,
    SPDX_VERSION,
    document_name,
    document_namespace,
    file_id,
    package_id,
    parse_sbom,
    symlink_checksum,
)


_PACKAGE_PURPOSE_BY_ROLE = {
    "kernel": "OPERATING-SYSTEM",
    "kernel_trusted_cert_bundle": "FILE",
    "final_systemd_stub": "APPLICATION",
    "final_systemd_unit": "APPLICATION",
    "nvidia_cc_driver": "DEVICE",
    "nvidia_cc_firmware": "FIRMWARE",
    "conf_proc_source": "FILE",
    "sglang_image": "APPLICATION",
    "inference_model": "APPLICATION",
    "asr_model": "APPLICATION",
    "gateway_dependency_lock": "APPLICATION",
    "asr_dependency_lock": "APPLICATION",
    "runtime_tree_input": "FILE",
    "policy_tree_input": "FILE",
    "models_tree_input": "FILE",
    "build_tool": "APPLICATION",
}
_RUNTIME_DEPENDENCY_ROLES = frozenset(
    {"sglang_image", "inference_model", "asr_model", "gateway_dependency_lock", "asr_dependency_lock"}
)


def build_sbom_bytes(lock: Lock, lock_digest: bytes) -> bytes:
    """Assemble and canonically encode the SPDX 2.3 appliance SBOM."""

    build_epoch = derive_build_epoch(lock_digest)
    created = datetime.fromtimestamp(build_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    packages = [
        {
            "SPDXID": APPLIANCE_PACKAGE_ID,
            "name": "conf-proc-appliance",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
            "originator": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": lock_digest.hex()}],
            "primaryPackagePurpose": "APPLICATION",
        }
    ]
    relationships = []
    files = []

    for lock_input in lock.inputs:
        pid = package_id(lock_input.id)
        packages.append(
            {
                "SPDXID": pid,
                "name": lock_input.component,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "supplier": "NOASSERTION",
                "originator": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": lock_input.sha256}],
                "primaryPackagePurpose": _PACKAGE_PURPOSE_BY_ROLE[lock_input.role],
            }
        )
        if lock_input.role == "build_tool":
            relationships.append(
                {"spdxElementId": pid, "relationshipType": RELATIONSHIP_BUILD_TOOL_OF, "relatedSpdxElement": APPLIANCE_PACKAGE_ID}
            )
        elif lock_input.role in _RUNTIME_DEPENDENCY_ROLES:
            relationships.append(
                {"spdxElementId": pid, "relationshipType": RELATIONSHIP_RUNTIME_DEPENDENCY_OF, "relatedSpdxElement": APPLIANCE_PACKAGE_ID}
            )
        else:
            relationships.append(
                {"spdxElementId": pid, "relationshipType": RELATIONSHIP_CONTAINS, "relatedSpdxElement": APPLIANCE_PACKAGE_ID}
            )

        for placement in lock_input.placements:
            if placement.node_type == "directory":
                continue
            fid = file_id(placement.image, placement.path)
            checksum = lock_input.sha256 if placement.node_type == "file" else symlink_checksum(placement.target or "")
            files.append(
                {
                    "SPDXID": fid,
                    "fileName": f"{placement.image}{placement.path}",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}],
                }
            )
            relationships.append(
                {"spdxElementId": APPLIANCE_PACKAGE_ID, "relationshipType": RELATIONSHIP_CONTAINS, "relatedSpdxElement": fid}
            )
            relationships.append(
                {"spdxElementId": fid, "relationshipType": RELATIONSHIP_GENERATED_FROM, "relatedSpdxElement": pid}
            )

    packages.sort(key=lambda entry: entry["SPDXID"])
    files.sort(key=lambda entry: entry["fileName"])
    relationships.sort(key=lambda entry: (entry["spdxElementId"], entry["relationshipType"], entry["relatedSpdxElement"]))

    raw = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": DOCUMENT_SPDX_ID,
        "name": document_name(lock_digest),
        "documentNamespace": document_namespace(lock_digest),
        "creationInfo": {"created": created, "creators": [CREATOR_TOOL]},
        "packages": packages,
        "files": files,
        "relationships": relationships,
        "documentDescribes": [APPLIANCE_PACKAGE_ID],
    }
    data = canonical_dumps(raw)
    parse_sbom(data)
    return data
