#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Strict schema for dormant provenance-v2 SPDX-2.3 documents."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final
import uuid

from conf_proc_json import canonical_loads
from conf_proc_reasons import CP_PROVENANCE_V2_SPDX_PRODUCTION, ApplianceError
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
)


SPDX_REFERENCE_TYPES: Final = (
    "conf-proc-artifact-input",
    "conf-proc-builder-source",
    "conf-proc-execution-provenance",
    "conf-proc-policy",
    "conf-proc-runtime-closure",
    "conf-proc-tcb-identity",
    "conf-proc-verity-rules",
)

_TOP_KEYS: Final = frozenset(
    {
        "spdxVersion",
        "dataLicense",
        "SPDXID",
        "name",
        "documentNamespace",
        "creationInfo",
        "packages",
        "files",
        "relationships",
        "documentDescribes",
    }
)
_CREATION_INFO_KEYS: Final = frozenset({"created", "creators"})
_PACKAGE_KEYS: Final = frozenset(
    {
        "SPDXID",
        "name",
        "downloadLocation",
        "licenseConcluded",
        "licenseDeclared",
        "copyrightText",
        "supplier",
        "originator",
        "checksums",
        "primaryPackagePurpose",
    }
)
_EXTERNAL_REF_KEYS: Final = frozenset({"referenceCategory", "referenceType", "referenceLocator"})
_FILE_KEYS: Final = frozenset({"SPDXID", "fileName", "checksums"})
_CHECKSUM_KEYS: Final = frozenset({"algorithm", "checksumValue"})
_RELATIONSHIP_KEYS: Final = frozenset({"spdxElementId", "relationshipType", "relatedSpdxElement"})
_PACKAGE_PURPOSES: Final = frozenset({"OPERATING-SYSTEM", "APPLICATION", "DEVICE", "FIRMWARE", "FILE"})
_RELATIONSHIP_TYPES: Final = frozenset(
    {
        RELATIONSHIP_CONTAINS,
        RELATIONSHIP_GENERATED_FROM,
        RELATIONSHIP_BUILD_TOOL_OF,
        RELATIONSHIP_RUNTIME_DEPENDENCY_OF,
    }
)
_SHA_KEYS: Final = frozenset("0123456789abcdef")
_SPDX_ID_KEYS: Final = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-")


@dataclass(frozen=True)
class ProvenanceV2Spdx:
    raw: dict


def parse_spdx_v2(data: bytes) -> ProvenanceV2Spdx:
    """Parse the exact dormant provenance-v2 SPDX document shape."""

    raw = canonical_loads(data)
    _require(type(raw) is dict, "SPDX document must be an object")
    _require_keys(raw, _TOP_KEYS, "SPDX document")
    _require(
        raw["spdxVersion"] == SPDX_VERSION
        and raw["dataLicense"] == DATA_LICENSE
        and raw["SPDXID"] == DOCUMENT_SPDX_ID,
        "SPDX document identity is invalid",
    )
    _require(type(raw["name"]) is str and raw["name"], "SPDX name is invalid")
    _require(_valid_uuid_urn(raw["documentNamespace"]), "SPDX namespace is invalid")

    creation_info = raw["creationInfo"]
    _require(type(creation_info) is dict, "SPDX creationInfo is invalid")
    _require_keys(creation_info, _CREATION_INFO_KEYS, "SPDX creationInfo")
    _require(
        _valid_timestamp(creation_info["created"]) and creation_info["creators"] == [CREATOR_TOOL],
        "SPDX creationInfo values are invalid",
    )

    packages = raw["packages"]
    _require(type(packages) is list and packages, "SPDX packages are missing")
    package_ids: list[str] = []
    for package in packages:
        _require(type(package) is dict, "SPDX package must be an object")
        is_appliance = package.get("SPDXID") == APPLIANCE_PACKAGE_ID
        expected_keys = _PACKAGE_KEYS | ({"externalRefs"} if is_appliance else set())
        _require_keys(package, expected_keys, "SPDX package")
        _require(
            _valid_spdx_id(package["SPDXID"])
            and all(
                type(package[key]) is str and package[key]
                for key in (
                    "name",
                    "downloadLocation",
                    "licenseConcluded",
                    "licenseDeclared",
                    "copyrightText",
                    "supplier",
                    "originator",
                )
            )
            and package["primaryPackagePurpose"] in _PACKAGE_PURPOSES,
            "SPDX package values are invalid",
        )
        _validate_checksums(package["checksums"])
        if is_appliance:
            _validate_external_refs(package["externalRefs"])
        package_ids.append(package["SPDXID"])
    _require(
        package_ids == sorted(package_ids) and len(package_ids) == len(set(package_ids)),
        "SPDX package IDs must be sorted and unique",
    )
    _require(package_ids.count(APPLIANCE_PACKAGE_ID) == 1, "SPDX appliance package is not unique")

    files = raw["files"]
    _require(type(files) is list, "SPDX files must be an array")
    file_ids: list[str] = []
    file_names: list[str] = []
    for item in files:
        _require(type(item) is dict, "SPDX file must be an object")
        _require_keys(item, _FILE_KEYS, "SPDX file")
        _require(
            _valid_spdx_id(item["SPDXID"])
            and type(item["fileName"]) is str
            and item["fileName"]
            and "\x00" not in item["fileName"],
            "SPDX file values are invalid",
        )
        _validate_checksums(item["checksums"])
        file_ids.append(item["SPDXID"])
        file_names.append(item["fileName"])
    _require(
        file_names == sorted(file_names) and len(file_ids) == len(set(file_ids)),
        "SPDX files must be sorted with unique IDs",
    )

    relationships = raw["relationships"]
    _require(type(relationships) is list, "SPDX relationships must be an array")
    known_ids = set(package_ids) | set(file_ids)
    relationship_keys: list[tuple[str, str, str]] = []
    for item in relationships:
        _require(type(item) is dict, "SPDX relationship must be an object")
        _require_keys(item, _RELATIONSHIP_KEYS, "SPDX relationship")
        key = (item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"])
        _require(
            all(type(value) is str for value in key)
            and item["spdxElementId"] in known_ids
            and item["relatedSpdxElement"] in known_ids
            and item["relationshipType"] in _RELATIONSHIP_TYPES,
            "SPDX relationship values are invalid",
        )
        relationship_keys.append(key)
    _require(
        relationship_keys == sorted(relationship_keys)
        and len(relationship_keys) == len(set(relationship_keys)),
        "SPDX relationships must be sorted and unique",
    )
    _require(raw["documentDescribes"] == [APPLIANCE_PACKAGE_ID], "SPDX documentDescribes is invalid")
    return ProvenanceV2Spdx(raw=raw)


def _validate_external_refs(value: object) -> None:
    _require(type(value) is list and len(value) == len(SPDX_REFERENCE_TYPES), "SPDX externalRefs are invalid")
    reference_types: list[str] = []
    for item in value:
        _require(type(item) is dict, "SPDX externalRef must be an object")
        _require_keys(item, _EXTERNAL_REF_KEYS, "SPDX externalRef")
        _require(
            item["referenceCategory"] == "OTHER"
            and type(item["referenceType"]) is str
            and type(item["referenceLocator"]) is str
            and item["referenceLocator"].startswith("sha256:")
            and _is_sha256(item["referenceLocator"][7:]),
            "SPDX externalRef values are invalid",
        )
        reference_types.append(item["referenceType"])
    _require(reference_types == list(SPDX_REFERENCE_TYPES), "SPDX externalRefs have unexpected types or order")


def _validate_checksums(value: object) -> None:
    _require(type(value) is list and len(value) == 1, "SPDX checksum is invalid")
    checksum = value[0]
    _require(type(checksum) is dict, "SPDX checksum must be an object")
    _require_keys(checksum, _CHECKSUM_KEYS, "SPDX checksum")
    _require(
        checksum["algorithm"] == "SHA256" and _is_sha256(checksum["checksumValue"]),
        "SPDX checksum values are invalid",
    )


def _valid_uuid_urn(value: object) -> bool:
    if type(value) is not str or not value.startswith("urn:uuid:"):
        return False
    try:
        return f"urn:uuid:{uuid.UUID(value[9:])}" == value
    except ValueError:
        return False


def _valid_timestamp(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value


def _valid_spdx_id(value: object) -> bool:
    return type(value) is str and value.startswith("SPDXRef-") and len(value) > 8 and set(value[8:]) <= _SPDX_ID_KEYS


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA_KEYS


def _require_keys(value: dict, expected: frozenset[str] | set[str], label: str) -> None:
    if set(value) != expected:
        raise ApplianceError(CP_PROVENANCE_V2_SPDX_PRODUCTION, f"{label} has unexpected fields")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ApplianceError(CP_PROVENANCE_V2_SPDX_PRODUCTION, message)
