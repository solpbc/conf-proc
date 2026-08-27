#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Structural schema and validator for the conf-proc-policy/v1 document.

This module only validates the declarative shape of a policy document. It
does not extract or compare an actual built image's process graph -- that
is a separate, independent builder-side and inspector-side concern.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from conf_proc_json import canonical_loads
from conf_proc_reasons import (
    CP_POLICY_CAPABILITY,
    CP_POLICY_DUPLICATE,
    CP_POLICY_FORBIDDEN_NETWORK,
    CP_POLICY_SCHEMA,
    CP_POLICY_TREE_RULE,
    CP_POLICY_UNSUPPORTED_ACTIVATION,
    ApplianceError,
)


POLICY_SCHEMA_ID: Final = "conf-proc-policy/v1"
POLICY_VERSION: Final = 1

_IMAGES: Final = ("runtime-policy", "models")
_NODE_TYPES: Final = ("file", "directory", "symlink")
_ALLOWED_XATTRS: Final = ("system.posix_acl_access", "system.posix_acl_default")
_CONTENT_CLASSES: Final = ("executable", "config", "model", "runtime_data")
_PROCESS_KINDS: Final = (
    "unit",
    "socket",
    "timer",
    "dbus_service",
    "udev_rule",
    "generator",
    "cron_job",
    "exec",
    "interpreter",
    "dynamic_library",
)
_FILE_BACKED_KINDS: Final = ("exec", "interpreter", "dynamic_library")
_NETWORK_SCOPES: Final = ("none", "loopback")
_EDGE_KINDS: Final = (
    "unit_dependency",
    "install_enablement",
    "socket_activation",
    "timer_activation",
    "dbus_activation",
    "udev_activation",
    "generator_activation",
    "cron_activation",
    "unit_exec",
    "shell_child",
    "script_interpreter",
    "elf_interpreter",
    "dynamic_load",
)

_POLICY_TOP_KEYS: Final = frozenset(
    {
        "schema",
        "policy_version",
        "images",
        "boot_roots",
        "process_nodes",
        "process_edges",
        "mounts",
        "network_policy",
        "capability_policy",
    }
)
_TREE_NODE_KEYS: Final = frozenset(
    {"path", "node_type", "mode", "uid", "gid", "xattrs", "source_input_id", "target", "content_class"}
)
_PROCESS_NODE_KEYS: Final = frozenset(
    {"id", "kind", "path", "sha256", "argv", "network_scope", "capabilities", "source_input_id"}
)
_PROCESS_EDGE_KEYS: Final = frozenset({"from_id", "to_id", "kind", "origin_path", "origin_key"})
_MOUNT_KEYS: Final = frozenset({"unit_id", "image", "destination", "fs_type", "read_only"})
_CAPABILITY_KEYS: Final = frozenset({"capability_bounding_set", "ambient_capabilities", "no_new_privileges"})


@dataclass(frozen=True)
class TreeNodePolicy:
    path: str
    node_type: str
    mode: int
    uid: int
    gid: int
    xattrs: tuple[str, ...]
    source_input_id: str | None
    target: str | None
    content_class: str | None


@dataclass(frozen=True)
class ImagePolicy:
    nodes: tuple[TreeNodePolicy, ...]


@dataclass(frozen=True)
class ProcessNode:
    id: str
    kind: str
    path: str
    sha256: str | None
    argv: tuple[str, ...]
    network_scope: str
    capabilities: tuple[str, ...]
    source_input_id: str | None


@dataclass(frozen=True)
class ProcessEdge:
    from_id: str
    to_id: str
    kind: str
    origin_path: str
    origin_key: str


@dataclass(frozen=True)
class MountPolicy:
    unit_id: str
    image: str
    destination: str
    fs_type: str
    read_only: bool


@dataclass(frozen=True)
class CapabilityPolicy:
    capability_bounding_set: tuple[str, ...]
    ambient_capabilities: tuple[str, ...]
    no_new_privileges: bool


@dataclass(frozen=True)
class Policy:
    schema: str
    policy_version: int
    images: dict
    boot_roots: tuple[str, ...]
    process_nodes: tuple[ProcessNode, ...]
    process_edges: tuple[ProcessEdge, ...]
    mounts: tuple[MountPolicy, ...]
    network_policy: dict
    capability_policy: dict


def parse_policy(data: bytes) -> Policy:
    """Parse and structurally validate a conf-proc-policy/v1 document."""

    raw = canonical_loads(data)
    _require(type(raw) is dict, CP_POLICY_SCHEMA, "policy document must be a JSON object")
    _require(set(raw) == _POLICY_TOP_KEYS, CP_POLICY_SCHEMA, "policy document has unexpected top-level fields")
    _require(raw["schema"] == POLICY_SCHEMA_ID, CP_POLICY_SCHEMA, "unexpected policy schema identifier")
    _require(raw["policy_version"] == POLICY_VERSION, CP_POLICY_SCHEMA, "unexpected policy version")

    raw_images = raw["images"]
    _require(type(raw_images) is dict and set(raw_images) == set(_IMAGES), CP_POLICY_SCHEMA, "images must cover exactly runtime-policy and models")
    images = {name: _parse_image_policy(value) for name, value in raw_images.items()}

    raw_boot_roots = raw["boot_roots"]
    _require(type(raw_boot_roots) is list and all(type(item) is str for item in raw_boot_roots), CP_POLICY_SCHEMA, "boot_roots must be an array of strings")

    raw_nodes = raw["process_nodes"]
    _require(type(raw_nodes) is list, CP_POLICY_SCHEMA, "process_nodes must be an array")
    nodes = [_parse_process_node(entry) for entry in raw_nodes]
    node_ids = [node.id for node in nodes]
    if len(node_ids) != len(set(node_ids)):
        raise ApplianceError(CP_POLICY_DUPLICATE, "duplicate process_nodes id")
    if node_ids != sorted(node_ids):
        raise ApplianceError(CP_POLICY_SCHEMA, "process_nodes must be sorted by id")
    known_node_ids = set(node_ids)

    raw_edges = raw["process_edges"]
    _require(type(raw_edges) is list, CP_POLICY_SCHEMA, "process_edges must be an array")
    edges = [_parse_process_edge(entry, known_node_ids) for entry in raw_edges]
    edge_keys = [(e.from_id, e.to_id, e.kind, e.origin_path, e.origin_key) for e in edges]
    if len(edge_keys) != len(set(edge_keys)):
        raise ApplianceError(CP_POLICY_DUPLICATE, "duplicate process_edges entry")
    if edge_keys != sorted(edge_keys):
        raise ApplianceError(CP_POLICY_SCHEMA, "process_edges must be sorted")

    raw_mounts = raw["mounts"]
    _require(type(raw_mounts) is list, CP_POLICY_SCHEMA, "mounts must be an array")
    mounts = [_parse_mount(entry) for entry in raw_mounts]
    mount_keys = [(m.image, m.destination) for m in mounts]
    if mount_keys != sorted(mount_keys):
        raise ApplianceError(CP_POLICY_SCHEMA, "mounts must be sorted by (image, destination)")
    if len(mount_keys) != len(set(mount_keys)):
        raise ApplianceError(CP_POLICY_DUPLICATE, "duplicate mount destination")

    raw_network_policy = raw["network_policy"]
    _require(type(raw_network_policy) is dict, CP_POLICY_SCHEMA, "network_policy must be a JSON object")
    for node_id, scope in raw_network_policy.items():
        if node_id not in known_node_ids:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "network_policy references an unknown process node")
        if scope not in _NETWORK_SCOPES:
            raise ApplianceError(CP_POLICY_FORBIDDEN_NETWORK, f"network_policy scope must be none or loopback, got {scope!r}")

    raw_capability_policy = raw["capability_policy"]
    _require(type(raw_capability_policy) is dict, CP_POLICY_SCHEMA, "capability_policy must be a JSON object")
    capability_policy = {}
    for node_id, value in raw_capability_policy.items():
        if node_id not in known_node_ids:
            raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "capability_policy references an unknown process node")
        capability_policy[node_id] = _parse_capability_policy(value)

    return Policy(
        schema=raw["schema"],
        policy_version=raw["policy_version"],
        images=images,
        boot_roots=tuple(raw_boot_roots),
        process_nodes=tuple(nodes),
        process_edges=tuple(edges),
        mounts=tuple(mounts),
        network_policy=dict(raw_network_policy),
        capability_policy=capability_policy,
    )


def _parse_image_policy(raw: object) -> ImagePolicy:
    _require(type(raw) is dict and set(raw) == {"nodes"}, CP_POLICY_SCHEMA, "image policy must contain exactly 'nodes'")
    raw_nodes = raw["nodes"]
    _require(type(raw_nodes) is list, CP_POLICY_SCHEMA, "image policy nodes must be an array")
    nodes = [_parse_tree_node(entry) for entry in raw_nodes]
    paths = [node.path for node in nodes]
    if paths != sorted(paths):
        raise ApplianceError(CP_POLICY_SCHEMA, "image policy nodes must be sorted by path")
    if len(paths) != len(set(paths)):
        raise ApplianceError(CP_POLICY_TREE_RULE, "image policy nodes must not repeat a path")
    return ImagePolicy(nodes=tuple(nodes))


def _parse_tree_node(raw: object) -> TreeNodePolicy:
    _require(type(raw) is dict, CP_POLICY_TREE_RULE, "tree node policy must be a JSON object")
    _require(set(raw) == _TREE_NODE_KEYS, CP_POLICY_TREE_RULE, "tree node policy has unexpected fields")
    path = raw["path"]
    _require(type(path) is str and path.startswith("/"), CP_POLICY_TREE_RULE, "tree node path must be absolute")
    node_type = raw["node_type"]
    _require(node_type in _NODE_TYPES, CP_POLICY_TREE_RULE, "tree node node_type is not recognized")
    _require(type(raw["mode"]) is int and 0 <= raw["mode"] <= 0o7777, CP_POLICY_TREE_RULE, "tree node mode must be 0-0o7777")
    _require(type(raw["uid"]) is int and raw["uid"] >= 0, CP_POLICY_TREE_RULE, "tree node uid must be nonnegative")
    _require(type(raw["gid"]) is int and raw["gid"] >= 0, CP_POLICY_TREE_RULE, "tree node gid must be nonnegative")
    xattrs = raw["xattrs"]
    _require(type(xattrs) is list and all(item in _ALLOWED_XATTRS for item in xattrs), CP_POLICY_TREE_RULE, "tree node xattrs contains an unsupported name")

    source_input_id = raw["source_input_id"]
    target = raw["target"]
    content_class = raw["content_class"]
    if node_type == "file":
        _require(type(source_input_id) is str and source_input_id, CP_POLICY_TREE_RULE, "file tree node requires source_input_id")
        _require(target is None, CP_POLICY_TREE_RULE, "file tree node must not declare a target")
        _require(content_class in _CONTENT_CLASSES, CP_POLICY_TREE_RULE, "file tree node requires a recognized content_class")
    elif node_type == "symlink":
        _require(source_input_id is None, CP_POLICY_TREE_RULE, "symlink tree node must not declare source_input_id")
        _require(type(target) is str and target, CP_POLICY_TREE_RULE, "symlink tree node requires a nonempty target")
        _require(content_class is None, CP_POLICY_TREE_RULE, "symlink tree node must not declare content_class")
    else:
        _require(source_input_id is None and target is None and content_class is None, CP_POLICY_TREE_RULE, "directory tree node must not declare source_input_id, target, or content_class")

    return TreeNodePolicy(
        path=path,
        node_type=node_type,
        mode=raw["mode"],
        uid=raw["uid"],
        gid=raw["gid"],
        xattrs=tuple(xattrs),
        source_input_id=source_input_id,
        target=target,
        content_class=content_class,
    )


def _parse_process_node(raw: object) -> ProcessNode:
    _require(type(raw) is dict, CP_POLICY_SCHEMA, "process node must be a JSON object")
    _require(set(raw) == _PROCESS_NODE_KEYS, CP_POLICY_SCHEMA, "process node has unexpected fields")
    node_id = raw["id"]
    _require(type(node_id) is str and node_id, CP_POLICY_SCHEMA, "process node id must be nonempty")
    kind = raw["kind"]
    _require(kind in _PROCESS_KINDS, CP_POLICY_UNSUPPORTED_ACTIVATION, f"unsupported process node kind: {kind!r}")
    path = raw["path"]
    _require(type(path) is str and path, CP_POLICY_SCHEMA, "process node path/activation name must be nonempty")
    sha256 = raw["sha256"]
    if kind in _FILE_BACKED_KINDS:
        _require(_is_sha256(sha256), CP_POLICY_SCHEMA, "file-backed process node requires a sha256 digest")
    else:
        _require(sha256 is None, CP_POLICY_SCHEMA, "non-file-backed process node must not declare sha256")
    argv = raw["argv"]
    _require(type(argv) is list and all(type(item) is str for item in argv), CP_POLICY_SCHEMA, "argv must be an array of strings")
    network_scope = raw["network_scope"]
    _require(network_scope in _NETWORK_SCOPES, CP_POLICY_FORBIDDEN_NETWORK, "process node network_scope must be none or loopback")
    capabilities = raw["capabilities"]
    _require(type(capabilities) is list and all(type(item) is str for item in capabilities), CP_POLICY_SCHEMA, "capabilities must be an array of strings")
    if list(capabilities) != sorted(capabilities) or len(capabilities) != len(set(capabilities)):
        raise ApplianceError(CP_POLICY_SCHEMA, "capabilities must be sorted and unique")
    source_input_id = raw["source_input_id"]
    _require(source_input_id is None or type(source_input_id) is str, CP_POLICY_SCHEMA, "source_input_id must be a string or null")

    return ProcessNode(
        id=node_id,
        kind=kind,
        path=path,
        sha256=sha256,
        argv=tuple(argv),
        network_scope=network_scope,
        capabilities=tuple(capabilities),
        source_input_id=source_input_id,
    )


def _parse_process_edge(raw: object, known_node_ids: set[str]) -> ProcessEdge:
    _require(type(raw) is dict, CP_POLICY_SCHEMA, "process edge must be a JSON object")
    _require(set(raw) == _PROCESS_EDGE_KEYS, CP_POLICY_SCHEMA, "process edge has unexpected fields")
    from_id = raw["from_id"]
    to_id = raw["to_id"]
    if from_id not in known_node_ids or to_id not in known_node_ids:
        raise ApplianceError(CP_POLICY_UNSUPPORTED_ACTIVATION, "process edge references an unknown process node")
    kind = raw["kind"]
    _require(kind in _EDGE_KINDS, CP_POLICY_UNSUPPORTED_ACTIVATION, f"unsupported process edge kind: {kind!r}")
    origin_path = raw["origin_path"]
    origin_key = raw["origin_key"]
    _require(type(origin_path) is str, CP_POLICY_SCHEMA, "process edge origin_path must be a string")
    _require(type(origin_key) is str, CP_POLICY_SCHEMA, "process edge origin_key must be a string")
    return ProcessEdge(from_id=from_id, to_id=to_id, kind=kind, origin_path=origin_path, origin_key=origin_key)


def _parse_mount(raw: object) -> MountPolicy:
    _require(type(raw) is dict, CP_POLICY_SCHEMA, "mount policy must be a JSON object")
    _require(set(raw) == _MOUNT_KEYS, CP_POLICY_SCHEMA, "mount policy has unexpected fields")
    _require(type(raw["unit_id"]) is str and raw["unit_id"], CP_POLICY_SCHEMA, "mount unit_id must be nonempty")
    _require(raw["image"] in _IMAGES, CP_POLICY_SCHEMA, "mount image must be runtime-policy or models")
    destination = raw["destination"]
    _require(type(destination) is str and destination.startswith("/"), CP_POLICY_SCHEMA, "mount destination must be absolute")
    _require(raw["fs_type"] == "squashfs", CP_POLICY_SCHEMA, "mount fs_type must be squashfs")
    _require(raw["read_only"] is True, CP_POLICY_SCHEMA, "mount read_only must be true")
    return MountPolicy(unit_id=raw["unit_id"], image=raw["image"], destination=destination, fs_type=raw["fs_type"], read_only=True)


def _parse_capability_policy(raw: object) -> CapabilityPolicy:
    _require(type(raw) is dict, CP_POLICY_SCHEMA, "capability policy must be a JSON object")
    _require(set(raw) == _CAPABILITY_KEYS, CP_POLICY_SCHEMA, "capability policy has unexpected fields")
    bounding = raw["capability_bounding_set"]
    ambient = raw["ambient_capabilities"]
    _require(type(bounding) is list and all(type(item) is str for item in bounding), CP_POLICY_SCHEMA, "capability_bounding_set must be an array of strings")
    _require(type(ambient) is list and all(type(item) is str for item in ambient), CP_POLICY_SCHEMA, "ambient_capabilities must be an array of strings")
    if list(bounding) != sorted(bounding) or len(bounding) != len(set(bounding)):
        raise ApplianceError(CP_POLICY_SCHEMA, "capability_bounding_set must be sorted and unique")
    if list(ambient) != sorted(ambient) or len(ambient) != len(set(ambient)):
        raise ApplianceError(CP_POLICY_SCHEMA, "ambient_capabilities must be sorted and unique")
    if not set(ambient) <= set(bounding):
        raise ApplianceError(CP_POLICY_CAPABILITY, "ambient_capabilities must be a subset of capability_bounding_set")
    _require(raw["no_new_privileges"] is True, CP_POLICY_CAPABILITY, "no_new_privileges must be true")
    return CapabilityPolicy(capability_bounding_set=tuple(bounding), ambient_capabilities=tuple(ambient), no_new_privileges=True)


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and value == value.lower() and all(c in "0123456789abcdef" for c in value)


def _require(condition: bool, reason_code: str, message: str) -> None:
    if not condition:
        raise ApplianceError(reason_code, message)
