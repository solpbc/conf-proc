#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Independent inspector-side SBOM validation and diff.

Deliberately does NOT import conf_proc_build_sbom.py. Every expected
package/file/relationship is re-derived here from the caller's own
trusted Lock; the emitted SBOM is parsed only for its literal bytes and
then compared set-by-set, so an omitted package, omitted transitive
dependency, or omitted file fails even when the rest of the document is
internally coherent.
"""

from __future__ import annotations

from conf_proc_lock import Lock
from conf_proc_reasons import CP_SBOM_DIFF, ApplianceError
from conf_proc_sbom import (
    APPLIANCE_PACKAGE_ID,
    RELATIONSHIP_BUILD_TOOL_OF,
    RELATIONSHIP_CONTAINS,
    RELATIONSHIP_GENERATED_FROM,
    RELATIONSHIP_RUNTIME_DEPENDENCY_OF,
    Sbom,
    file_id,
    package_id,
    symlink_checksum,
)


_RUNTIME_DEPENDENCY_ROLES = frozenset(
    {"sglang_image", "inference_model", "asr_model", "gateway_dependency_lock", "asr_dependency_lock"}
)


def compare_sbom(sbom: Sbom, lock: Lock) -> None:
    """Fail loud on any omitted package, file, or relationship."""

    raw = sbom.raw
    actual_package_ids = {entry["SPDXID"] for entry in raw["packages"]}
    actual_package_checksum = {entry["SPDXID"]: entry["checksums"][0]["checksumValue"] for entry in raw["packages"]}
    actual_file_ids = {entry["SPDXID"] for entry in raw["files"]}
    actual_file_checksum = {entry["SPDXID"]: entry["checksums"][0]["checksumValue"] for entry in raw["files"]}
    actual_relationships = {
        (entry["spdxElementId"], entry["relationshipType"], entry["relatedSpdxElement"]) for entry in raw["relationships"]
    }

    for lock_input in lock.inputs:
        pid = package_id(lock_input.id)
        if pid not in actual_package_ids:
            raise ApplianceError(CP_SBOM_DIFF, f"missing SPDX package for locked input {lock_input.id!r}")
        if actual_package_checksum[pid] != lock_input.sha256:
            raise ApplianceError(CP_SBOM_DIFF, f"SPDX package {pid} checksum does not match locked sha256 for {lock_input.id!r}")

        expected_relationship_type = (
            RELATIONSHIP_BUILD_TOOL_OF
            if lock_input.role == "build_tool"
            else RELATIONSHIP_RUNTIME_DEPENDENCY_OF
            if lock_input.role in _RUNTIME_DEPENDENCY_ROLES
            else RELATIONSHIP_CONTAINS
        )
        if (pid, expected_relationship_type, APPLIANCE_PACKAGE_ID) not in actual_relationships:
            raise ApplianceError(
                CP_SBOM_DIFF, f"missing {expected_relationship_type} relationship for package {pid} to the appliance"
            )

        for placement in lock_input.placements:
            if placement.node_type == "directory":
                continue
            fid = file_id(placement.image, placement.path)
            if fid not in actual_file_ids:
                raise ApplianceError(CP_SBOM_DIFF, f"missing SPDX file entry for {placement.image}{placement.path}")
            expected_checksum = lock_input.sha256 if placement.node_type == "file" else symlink_checksum(placement.target or "")
            if actual_file_checksum[fid] != expected_checksum:
                raise ApplianceError(CP_SBOM_DIFF, f"SPDX file {fid} checksum does not match the expected content digest")
            if (APPLIANCE_PACKAGE_ID, RELATIONSHIP_CONTAINS, fid) not in actual_relationships:
                raise ApplianceError(CP_SBOM_DIFF, f"missing CONTAINS relationship from the appliance to file {fid}")
            if (fid, RELATIONSHIP_GENERATED_FROM, pid) not in actual_relationships:
                raise ApplianceError(CP_SBOM_DIFF, f"missing GENERATED_FROM relationship from file {fid} to package {pid}")
