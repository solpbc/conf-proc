#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Pure comparison between an extracted process/activation graph and a
declared Policy. Both the builder and inspector independently extract
their own (nodes, edges) -- via separate tree-walk implementations -- and
then call this identical, pure set-equality check, so a policy/reality
mismatch is caught the same way regardless of who is asking.
"""

from __future__ import annotations

from conf_proc_policy import Policy
from conf_proc_reasons import CP_POLICY_GRAPH_MISMATCH, ApplianceError


def compare_graph_to_policy(nodes: list[dict], edges: list[dict], policy: Policy) -> None:
    actual_nodes = {node["id"]: node for node in nodes}
    declared_nodes = {node.id: node for node in policy.process_nodes}

    extra_nodes = set(actual_nodes) - set(declared_nodes)
    if extra_nodes:
        raise ApplianceError(CP_POLICY_GRAPH_MISMATCH, f"actual graph has nodes with no policy entry: {sorted(extra_nodes)}")
    missing_nodes = set(declared_nodes) - set(actual_nodes)
    if missing_nodes:
        raise ApplianceError(CP_POLICY_GRAPH_MISMATCH, f"policy declares nodes absent from the actual graph: {sorted(missing_nodes)}")

    for node_id, actual in actual_nodes.items():
        declared = declared_nodes[node_id]
        if actual["kind"] != declared.kind or actual["path"] != declared.path:
            raise ApplianceError(CP_POLICY_GRAPH_MISMATCH, f"node {node_id}: kind/path does not match policy")
        if (actual["sha256"] or None) != (declared.sha256 or None):
            raise ApplianceError(CP_POLICY_GRAPH_MISMATCH, f"node {node_id}: sha256 does not match policy")
        if tuple(actual["argv"]) != tuple(declared.argv):
            raise ApplianceError(CP_POLICY_GRAPH_MISMATCH, f"node {node_id}: argv does not match policy")
        if actual["network_scope"] != declared.network_scope:
            raise ApplianceError(CP_POLICY_GRAPH_MISMATCH, f"node {node_id}: network_scope does not match policy")
        if tuple(sorted(actual["capabilities"])) != tuple(declared.capabilities):
            raise ApplianceError(CP_POLICY_GRAPH_MISMATCH, f"node {node_id}: capabilities do not match policy")

    actual_edge_keys = {(e["from_id"], e["to_id"], e["kind"], e["origin_path"], e["origin_key"]) for e in edges}
    declared_edge_keys = {(e.from_id, e.to_id, e.kind, e.origin_path, e.origin_key) for e in policy.process_edges}

    extra_edges = actual_edge_keys - declared_edge_keys
    if extra_edges:
        raise ApplianceError(CP_POLICY_GRAPH_MISMATCH, f"actual graph has edges with no policy entry: {sorted(extra_edges)}")
    missing_edges = declared_edge_keys - actual_edge_keys
    if missing_edges:
        raise ApplianceError(CP_POLICY_GRAPH_MISMATCH, f"policy declares edges absent from the actual graph: {sorted(missing_edges)}")
