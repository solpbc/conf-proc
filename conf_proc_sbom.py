#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Structural schema for the hand-emitted SPDX 2.3 appliance SBOM.

No SPDX library dependency: this repo has none available/declared, and
hand-emission keeps the SBOM canonical-JSON-compatible and independently
re-derivable by the inspector (see conf_proc_inspect_sbom.py).
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import Final

from conf_proc_json import canonical_loads
from conf_proc_reasons import CP_SBOM_SCHEMA, ApplianceError


SPDX_VERSION: Final = "SPDX-2.3"
DATA_LICENSE: Final = "CC0-1.0"
DOCUMENT_SPDX_ID: Final = "SPDXRef-DOCUMENT"
CREATOR_TOOL: Final = "Tool: conf-proc-sbom-v1"
APPLIANCE_PACKAGE_ID: Final = "SPDXRef-Package-appliance"

RELATIONSHIP_CONTAINS: Final = "CONTAINS"
RELATIONSHIP_GENERATED_FROM: Final = "GENERATED_FROM"
RELATIONSHIP_BUILD_TOOL_OF: Final = "BUILD_TOOL_OF"
RELATIONSHIP_RUNTIME_DEPENDENCY_OF: Final = "RUNTIME_DEPENDENCY_OF"

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
_FILE_KEYS: Final = frozenset({"SPDXID", "fileName", "checksums"})
_CHECKSUM_KEYS: Final = frozenset({"algorithm", "checksumValue"})
_RELATIONSHIP_KEYS: Final = frozenset({"spdxElementId", "relationshipType", "relatedSpdxElement"})
_PACKAGE_PURPOSES: Final = frozenset({"OPERATING-SYSTEM", "APPLICATION", "DEVICE", "FIRMWARE", "FILE"})
_RELATIONSHIP_TYPES: Final = frozenset(
    {RELATIONSHIP_CONTAINS, RELATIONSHIP_GENERATED_FROM, RELATIONSHIP_BUILD_TOOL_OF, RELATIONSHIP_RUNTIME_DEPENDENCY_OF}
)

_SYMLINK_CHECKSUM_DOMAIN: Final = b"conf-proc/spdx-symlink-checksum/v1"
_NAMESPACE_DOMAIN: Final = b"conf-proc/spdx-document-namespace/v1"
_SANITIZE_RE: Final = re.compile(r"[^A-Za-z0-9.-]")


def _sanitize(value: str) -> str:
    return _SANITIZE_RE.sub("-", value)


def package_id(input_id: str) -> str:
    """Deterministic SPDX package ID for a lock input -- pure formula,
    shared by builder and inspector so both refer to the same element."""

    return f"SPDXRef-Package-{_sanitize(input_id)}"


def file_id(image: str, path: str) -> str:
    """Deterministic SPDX file ID for a placement -- pure formula."""

    return f"SPDXRef-File-{_sanitize(image)}-{_sanitize(path)}"


def symlink_checksum(target: str) -> str:
    """Deterministic stand-in checksum for a symlink's SPDX file entry."""

    return hashlib.sha256(_SYMLINK_CHECKSUM_DOMAIN + target.encode("utf-8")).hexdigest()


def document_namespace(lock_digest: bytes) -> str:
    """Deterministic RFC-4122-shaped document namespace URN from the lock digest."""

    digest = bytearray(hashlib.sha256(_NAMESPACE_DOMAIN + lock_digest).digest()[:16])
    digest[6] = (digest[6] & 0x0F) | 0x50
    digest[8] = (digest[8] & 0x3F) | 0x80
    return f"urn:uuid:{uuid.UUID(bytes=bytes(digest))}"


def document_name(lock_digest: bytes) -> str:
    """Deterministic document name from the lock digest prefix."""

    return f"conf-proc-appliance-{lock_digest.hex()[:16]}"


@dataclass(frozen=True)
class Sbom:
    raw: dict


def parse_sbom(data: bytes) -> Sbom:
    """Structurally validate an SPDX 2.3 document; never trust its content
    as ground truth -- callers must independently re-derive and compare."""

    raw = canonical_loads(data)
    _require(type(raw) is dict, CP_SBOM_SCHEMA, "SBOM must be a JSON object")
    _require(set(raw) == _TOP_KEYS, CP_SBOM_SCHEMA, "SBOM has unexpected top-level fields")
    _require(raw["spdxVersion"] == SPDX_VERSION, CP_SBOM_SCHEMA, "unexpected spdxVersion")
    _require(raw["dataLicense"] == DATA_LICENSE, CP_SBOM_SCHEMA, "unexpected dataLicense")
    _require(raw["SPDXID"] == DOCUMENT_SPDX_ID, CP_SBOM_SCHEMA, "unexpected document SPDXID")
    _require(type(raw["name"]) is str and raw["name"], CP_SBOM_SCHEMA, "name must be nonempty")
    _require(type(raw["documentNamespace"]) is str and raw["documentNamespace"].startswith("urn:uuid:"), CP_SBOM_SCHEMA, "documentNamespace must be a urn:uuid")

    creation_info = raw["creationInfo"]
    _require(type(creation_info) is dict and set(creation_info) == _CREATION_INFO_KEYS, CP_SBOM_SCHEMA, "creationInfo has unexpected fields")
    _require(creation_info["creators"] == [CREATOR_TOOL], CP_SBOM_SCHEMA, "creationInfo.creators must be exactly one fixed tool identity")

    packages = raw["packages"]
    _require(type(packages) is list and packages, CP_SBOM_SCHEMA, "packages must be a nonempty array")
    package_ids = []
    for package in packages:
        _require(type(package) is dict and set(package) == _PACKAGE_KEYS, CP_SBOM_SCHEMA, "package has unexpected fields")
        _require(package["primaryPackagePurpose"] in _PACKAGE_PURPOSES, CP_SBOM_SCHEMA, "unrecognized primaryPackagePurpose")
        _validate_checksums(package["checksums"])
        package_ids.append(package["SPDXID"])
    _require(package_ids == sorted(package_ids), CP_SBOM_SCHEMA, "packages must be sorted by SPDXID")
    _require(len(package_ids) == len(set(package_ids)), CP_SBOM_SCHEMA, "duplicate package SPDXID")
    _require(APPLIANCE_PACKAGE_ID in package_ids, CP_SBOM_SCHEMA, "missing the appliance package")

    files = raw["files"]
    _require(type(files) is list, CP_SBOM_SCHEMA, "files must be an array")
    file_ids = []
    file_names = []
    for file_entry in files:
        _require(type(file_entry) is dict and set(file_entry) == _FILE_KEYS, CP_SBOM_SCHEMA, "file entry has unexpected fields")
        _validate_checksums(file_entry["checksums"])
        file_ids.append(file_entry["SPDXID"])
        file_names.append(file_entry["fileName"])
    _require(file_names == sorted(file_names), CP_SBOM_SCHEMA, "files must be sorted by fileName")
    _require(len(file_ids) == len(set(file_ids)), CP_SBOM_SCHEMA, "duplicate file SPDXID")

    relationships = raw["relationships"]
    _require(type(relationships) is list, CP_SBOM_SCHEMA, "relationships must be an array")
    known_ids = set(package_ids) | set(file_ids)
    rel_keys = []
    for relationship in relationships:
        _require(type(relationship) is dict and set(relationship) == _RELATIONSHIP_KEYS, CP_SBOM_SCHEMA, "relationship has unexpected fields")
        _require(relationship["relationshipType"] in _RELATIONSHIP_TYPES, CP_SBOM_SCHEMA, "unrecognized relationshipType")
        _require(relationship["spdxElementId"] in known_ids, CP_SBOM_SCHEMA, "relationship references an unknown element")
        _require(relationship["relatedSpdxElement"] in known_ids, CP_SBOM_SCHEMA, "relationship references an unknown element")
        rel_keys.append((relationship["spdxElementId"], relationship["relationshipType"], relationship["relatedSpdxElement"]))
    _require(rel_keys == sorted(rel_keys), CP_SBOM_SCHEMA, "relationships must be sorted by (spdxElementId, relationshipType, relatedSpdxElement)")
    _require(len(rel_keys) == len(set(rel_keys)), CP_SBOM_SCHEMA, "duplicate relationship")

    described = raw["documentDescribes"]
    _require(described == [APPLIANCE_PACKAGE_ID], CP_SBOM_SCHEMA, "documentDescribes must reference exactly the appliance package")

    return Sbom(raw=raw)


def _validate_checksums(value: object) -> None:
    _require(type(value) is list and len(value) == 1, CP_SBOM_SCHEMA, "checksums must contain exactly one entry")
    checksum = value[0]
    _require(type(checksum) is dict and set(checksum) == _CHECKSUM_KEYS, CP_SBOM_SCHEMA, "checksum has unexpected fields")
    _require(checksum["algorithm"] == "SHA256", CP_SBOM_SCHEMA, "checksum algorithm must be SHA256")
    digest = checksum["checksumValue"]
    _require(
        type(digest) is str and len(digest) == 64 and digest == digest.lower() and all(c in "0123456789abcdef" for c in digest),
        CP_SBOM_SCHEMA,
        "checksumValue must be 64 lowercase hex characters",
    )


def _require(condition: bool, reason_code: str, message: str) -> None:
    if not condition:
        raise ApplianceError(reason_code, message)
