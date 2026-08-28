#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Internal SPDX assembly for the dormant provenance-v2 producer."""

from __future__ import annotations

from datetime import datetime, timezone

from conf_proc_geometry import derive_build_epoch
from conf_proc_json import canonical_dumps
from conf_proc_lock import Lock
from conf_proc_provenance_v2 import ProvenanceInputs
from conf_proc_provenance_v2_spdx import SPDX_REFERENCE_TYPES
from conf_proc_reasons import CP_PROVENANCE_V2_SPDX_PRODUCTION, ApplianceError
from conf_proc_sbom import (
    APPLIANCE_PACKAGE_ID,
    CREATOR_TOOL,
    DATA_LICENSE,
    DOCUMENT_SPDX_ID,
    PACKAGE_PURPOSE_BY_ROLE,
    RELATIONSHIP_BUILD_TOOL_OF,
    RELATIONSHIP_CONTAINS,
    RELATIONSHIP_GENERATED_FROM,
    RELATIONSHIP_RUNTIME_DEPENDENCY_OF,
    SPDX_VERSION,
    document_name,
    document_namespace,
    file_id,
    package_id,
    symlink_checksum,
)


_RUNTIME_DEPENDENCY_ROLES = frozenset(
    {"sglang_image", "inference_model", "asr_model", "gateway_dependency_lock", "asr_dependency_lock"}
)


def _build_spdx_v2_bytes(*, lock: Lock, inputs: ProvenanceInputs) -> bytes:
    """Assemble canonical SPDX bytes from parsed trusted authorities."""

    lock_digest = bytes.fromhex(inputs.artifact_input_sha256)
    build_epoch = derive_build_epoch(lock_digest)
    created = datetime.fromtimestamp(build_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    references = _provenance_references(inputs)
    packages = [_appliance_package(inputs.artifact_input_sha256, references)]
    files: list[dict] = []
    relationships: list[dict] = []
    package_ids = {APPLIANCE_PACKAGE_ID}
    file_ids: set[str] = set()
    file_names: set[str] = set()

    for lock_input in lock.inputs:
        package_spdx_id = package_id(lock_input.id)
        if package_spdx_id == APPLIANCE_PACKAGE_ID or package_spdx_id in package_ids:
            raise ApplianceError(CP_PROVENANCE_V2_SPDX_PRODUCTION, "SPDX package ID collision")
        package_ids.add(package_spdx_id)
        packages.append(
            {
                "SPDXID": package_spdx_id,
                "name": lock_input.component,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "supplier": "NOASSERTION",
                "originator": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": lock_input.sha256}],
                "primaryPackagePurpose": PACKAGE_PURPOSE_BY_ROLE[lock_input.role],
            }
        )
        relationship_type = _package_relationship_type(lock_input.role)
        relationships.append(
            {
                "spdxElementId": package_spdx_id,
                "relationshipType": relationship_type,
                "relatedSpdxElement": APPLIANCE_PACKAGE_ID,
            }
        )

        for placement in lock_input.placements:
            if placement.node_type == "directory":
                continue
            placement_file_id = file_id(placement.image, placement.path)
            placement_file_name = f"{placement.image}{placement.path}"
            if placement_file_id in file_ids or placement_file_name in file_names:
                raise ApplianceError(CP_PROVENANCE_V2_SPDX_PRODUCTION, "SPDX file ID collision")
            file_ids.add(placement_file_id)
            file_names.add(placement_file_name)
            checksum = (
                lock_input.sha256
                if placement.node_type == "file"
                else symlink_checksum(placement.target or "")
            )
            files.append(
                {
                    "SPDXID": placement_file_id,
                    "fileName": placement_file_name,
                    "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}],
                }
            )
            relationships.extend(
                (
                    {
                        "spdxElementId": APPLIANCE_PACKAGE_ID,
                        "relationshipType": RELATIONSHIP_CONTAINS,
                        "relatedSpdxElement": placement_file_id,
                    },
                    {
                        "spdxElementId": placement_file_id,
                        "relationshipType": RELATIONSHIP_GENERATED_FROM,
                        "relatedSpdxElement": package_spdx_id,
                    },
                )
            )

    packages.sort(key=lambda item: item["SPDXID"])
    files.sort(key=lambda item: item["fileName"])
    relationships.sort(
        key=lambda item: (item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"])
    )
    relationship_keys = [
        (item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"])
        for item in relationships
    ]
    if len(relationship_keys) != len(set(relationship_keys)):
        raise ApplianceError(CP_PROVENANCE_V2_SPDX_PRODUCTION, "SPDX relationship collision")
    return canonical_dumps(
        {
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
    )


def _appliance_package(artifact_input_sha256: str, references: list[dict]) -> dict:
    return {
        "SPDXID": APPLIANCE_PACKAGE_ID,
        "name": "conf-proc-appliance",
        "downloadLocation": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "supplier": "NOASSERTION",
        "originator": "NOASSERTION",
        "checksums": [{"algorithm": "SHA256", "checksumValue": artifact_input_sha256}],
        "primaryPackagePurpose": "APPLICATION",
        "externalRefs": references,
    }


def _provenance_references(inputs: ProvenanceInputs) -> list[dict]:
    values = {
        "conf-proc-artifact-input": inputs.artifact_input_sha256,
        "conf-proc-builder-source": inputs.builder_source_sha256,
        "conf-proc-execution-provenance": inputs.execution_provenance_sha256,
        "conf-proc-policy": inputs.policy_sha256,
        "conf-proc-runtime-closure": inputs.runtime_closure_sha256,
        "conf-proc-tcb-identity": inputs.tcb_identity_sha256,
        "conf-proc-verity-rules": inputs.verity_rules_sha256,
    }
    return [
        {"referenceCategory": "OTHER", "referenceType": name, "referenceLocator": f"sha256:{values[name]}"}
        for name in SPDX_REFERENCE_TYPES
    ]


def _package_relationship_type(role: str) -> str:
    if role == "build_tool":
        return RELATIONSHIP_BUILD_TOOL_OF
    if role in _RUNTIME_DEPENDENCY_ROLES:
        return RELATIONSHIP_RUNTIME_DEPENDENCY_OF
    return RELATIONSHIP_CONTAINS
