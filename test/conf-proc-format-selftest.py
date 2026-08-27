#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Selftests for the conf-proc shared format primitives (Phase 1)."""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import conf_proc_acl as acl  # noqa: E402
import conf_proc_json as cj  # noqa: E402
import conf_proc_lock as lk  # noqa: E402
import conf_proc_module_sig as msig  # noqa: E402
import conf_proc_policy as pol  # noqa: E402
from conf_proc_reasons import ApplianceError  # noqa: E402


def _sha(n: int) -> str:
    return format(n, "064x")


class CanonicalJsonTests(unittest.TestCase):
    def test_object_key_ordering(self) -> None:
        self.assertEqual(cj.canonical_dumps({"b": 1, "a": 2}), b'{"a":2,"b":1}')

    def test_safe_integer_array(self) -> None:
        value = {"v": [True, False, None, -7, 0, 9007199254740991]}
        self.assertEqual(
            cj.canonical_dumps(value),
            b'{"v":[true,false,null,-7,0,9007199254740991]}',
        )

    def test_utf16_sort_distinction(self) -> None:
        bmp_key = ""
        astral_key = "\U00010000"
        out = cj.canonical_dumps({bmp_key: 1, astral_key: 2})
        astral_encoded = astral_key.encode("utf-8")
        bmp_encoded = bmp_key.encode("utf-8")
        self.assertLess(out.index(astral_encoded), out.index(bmp_encoded))
        self.assertEqual(out, b'{"' + astral_encoded + b'":2,"' + bmp_encoded + b'":1}')

    def test_control_and_escaping_vector(self) -> None:
        value = (
            "\x00" + "\x08" + "\x09" + "\x0a" + "\x0c" + "\x0d"
            + "\"" + "\\" + "/" + "\x1f" + " " + "é"
        )
        out = cj.canonical_dumps({"s": value})
        expected = (
            b'{"s":"'
            + b"\\u0000\\b\\t\\n\\f\\r\\\"\\\\/\\u001f"
            + " ".encode("utf-8")
            + "é".encode("utf-8")
            + b'"}'
        )
        self.assertEqual(out, expected)

    def test_non_bmp_literal_utf8(self) -> None:
        out = cj.canonical_dumps({"emoji": "\U0001f600"})
        self.assertEqual(out, b'{"emoji":"' + "\U0001f600".encode("utf-8") + b'"}')
        self.assertNotIn(b"\\ud83d", out.lower())

    def test_round_trip(self) -> None:
        value = {"z": [1, 2, {"a": "x", "b": [True, False, None]}], "a": True}
        dumped = cj.canonical_dumps(value)
        self.assertEqual(cj.canonical_loads(dumped), value)
        self.assertEqual(cj.canonical_dumps(cj.canonical_loads(dumped)), dumped)

    def test_reject_duplicate_key(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            cj.canonical_loads(b'{"a":1,"a":2}')
        self.assertEqual(ctx.exception.reason_code, "CP_JSON_DUPLICATE_KEY")

    def test_reject_invalid_utf8(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            cj.canonical_loads(b'{"a":"\xff"}')
        self.assertEqual(ctx.exception.reason_code, "CP_JSON_INVALID_UTF8")

    def test_reject_floats(self) -> None:
        json_reason_codes = {"CP_JSON_UNSUPPORTED_NUMBER", "CP_JSON_UNSUPPORTED_TYPE"}
        for payload in (b'{"n":1.0}', b'{"n":1e0}', b'{"n":-0.0}'):
            with self.assertRaises(ApplianceError) as ctx:
                cj.canonical_loads(payload)
            self.assertIn(ctx.exception.reason_code, json_reason_codes)
        with self.assertRaises(ApplianceError) as ctx:
            cj.canonical_dumps({"n": 1.0})
        self.assertIn(ctx.exception.reason_code, json_reason_codes)

    def test_reject_out_of_range_integers(self) -> None:
        for value in (9007199254740992, -9007199254740992):
            with self.assertRaises(ApplianceError) as ctx:
                cj.canonical_dumps({"n": value})
            self.assertEqual(ctx.exception.reason_code, "CP_JSON_UNSUPPORTED_NUMBER")
        for payload in (b'{"n":9007199254740992}', b'{"n":-9007199254740992}'):
            with self.assertRaises(ApplianceError) as ctx:
                cj.canonical_loads(payload)
            self.assertEqual(ctx.exception.reason_code, "CP_JSON_UNSUPPORTED_NUMBER")

    def test_reject_noncanonical_key_order(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            cj.canonical_loads(b'{"b":1,"a":2}')
        self.assertEqual(ctx.exception.reason_code, "CP_JSON_NONCANONICAL")

    def test_reject_noncanonical_escape(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            cj.canonical_loads(b'{"a":"\\u0061"}')
        self.assertEqual(ctx.exception.reason_code, "CP_JSON_NONCANONICAL")

    def test_reject_trailing_byte(self) -> None:
        canonical = cj.canonical_dumps({"a": 2, "b": 1})
        with self.assertRaises(ApplianceError) as ctx:
            cj.canonical_loads(canonical + b"\n")
        self.assertEqual(ctx.exception.reason_code, "CP_JSON_NONCANONICAL")


class AclCodecTests(unittest.TestCase):
    def test_round_trip_nontrivial_acl(self) -> None:
        entries = [
            acl.AclEntry(acl.ACL_USER_OBJ, 0o7, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_USER, 0o5, 5555),
            acl.AclEntry(acl.ACL_GROUP_OBJ, 0o5, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_MASK, 0o5, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_OTHER, 0o0, acl.ACL_UNDEFINED_ID),
        ]
        encoded = acl.encode_acl(entries)
        self.assertEqual(acl.decode_acl(encoded), entries)

    def test_reject_bad_version(self) -> None:
        payload = struct.pack("<I", 3) + struct.pack("<HHI", acl.ACL_USER_OBJ, 0o7, acl.ACL_UNDEFINED_ID)
        with self.assertRaises(ApplianceError) as ctx:
            acl.decode_acl(payload)
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_ACL")

    def test_reject_truncated(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            acl.decode_acl(struct.pack("<I", 2) + b"\x00\x00\x00")
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_ACL")

    def test_reject_out_of_order_entries(self) -> None:
        entries = [
            acl.AclEntry(acl.ACL_USER_OBJ, 0o7, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_GROUP_OBJ, 0o5, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_OTHER, 0o0, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_MASK, 0o5, acl.ACL_UNDEFINED_ID),
        ]
        with self.assertRaises(ApplianceError) as ctx:
            acl.encode_acl(entries)
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_ACL")

    def test_reject_named_entry_with_undefined_qualifier(self) -> None:
        entries = [
            acl.AclEntry(acl.ACL_USER_OBJ, 0o7, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_USER, 0o5, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_GROUP_OBJ, 0o5, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_MASK, 0o5, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_OTHER, 0o0, acl.ACL_UNDEFINED_ID),
        ]
        with self.assertRaises(ApplianceError) as ctx:
            acl.encode_acl(entries)
        self.assertEqual(ctx.exception.reason_code, "CP_TREE_ACL")

    def test_live_round_trip(self) -> None:
        base = tempfile.mkdtemp(dir="/var/tmp")
        entries = [
            acl.AclEntry(acl.ACL_USER_OBJ, 0o7, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_USER, 0o5, os.getuid()),
            acl.AclEntry(acl.ACL_GROUP_OBJ, 0o5, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_MASK, 0o5, acl.ACL_UNDEFINED_ID),
            acl.AclEntry(acl.ACL_OTHER, 0o0, acl.ACL_UNDEFINED_ID),
        ]
        target_file = os.path.join(base, "acl-file")
        with open(target_file, "wb") as handle:
            handle.write(b"acl fixture")
        try:
            acl.write_acl(target_file, entries)
        except ApplianceError as exc:
            if "ENOTSUP" not in str(exc) and not isinstance(exc.__cause__, OSError):
                raise
            self.skipTest("filesystem does not support xattrs")
            return
        self.assertEqual(acl.read_acl(target_file), entries)

        acl.write_acl(base, entries, default=True)
        self.assertEqual(acl.read_acl(base, default=True), entries)


class ModuleSignatureTests(unittest.TestCase):
    def test_magic_is_28_bytes(self) -> None:
        self.assertEqual(len(msig.MODULE_SIG_MAGIC), 28)
        self.assertEqual(msig.MODULE_SIG_MAGIC, b"~Module signature appended~\n")

    def test_round_trip(self) -> None:
        content = b"fake module content"
        signature = b"fake-signature-bytes" * 5
        built = msig.build_module_signature(content, b"", b"", signature, id_type=msig.PKEY_ID_PKCS7)
        module_content, signer_name, key_id, signature_data, trailer = msig.split_module_signature(built)
        self.assertEqual(module_content, content)
        self.assertEqual(signer_name, b"")
        self.assertEqual(key_id, b"")
        self.assertEqual(signature_data, signature)
        self.assertEqual(trailer.id_type, msig.PKEY_ID_PKCS7)
        self.assertEqual(trailer.sig_len, len(signature))

    def test_reject_missing_magic(self) -> None:
        with self.assertRaises(ApplianceError) as ctx:
            msig.split_module_signature(b"not a signed module")
        self.assertEqual(ctx.exception.reason_code, "CP_MODULE_TRAILER")

    def test_reject_nonzero_padding(self) -> None:
        trailer = struct.pack(">BBBBB3sI", 0, 0, 2, 0, 0, b"\x01\x00\x00", 4)
        payload = b"content" + b"abcd" + trailer + msig.MODULE_SIG_MAGIC
        with self.assertRaises(ApplianceError) as ctx:
            msig.split_module_signature(payload)
        self.assertEqual(ctx.exception.reason_code, "CP_MODULE_TRAILER")

    def test_reject_truncated(self) -> None:
        trailer = struct.pack(">BBBBB3sI", 0, 0, 2, 0, 0, b"\x00\x00\x00", 999)
        payload = b"short" + trailer + msig.MODULE_SIG_MAGIC
        with self.assertRaises(ApplianceError) as ctx:
            msig.split_module_signature(payload)
        self.assertEqual(ctx.exception.reason_code, "CP_MODULE_TRAILER")


def _lock_input(
    id_: str,
    role: str,
    *,
    component: str = "x",
    parent_ids=(),
    derivation_kind: str = "fixture",
    placements=(),
) -> dict:
    return {
        "id": id_,
        "role": role,
        "component": component,
        "sha256": _sha(abs(hash(id_)) % (2**32) + 1),
        "size_bytes": 10,
        "source_local_path": f"fixtures/{id_}",
        "source_retrieval_scheme": "local-fixture",
        "source_retrieval_identity": f"fixture:{id_}",
        "source_retrieval_immutable_ref": "v1",
        "derivation_kind": derivation_kind,
        "derivation_recipe_id": "recipe-1",
        "derivation_parent_ids": list(parent_ids),
        "derivation_parameters_sha256": _sha(2),
        "placements": list(placements),
    }


def _placement(image: str, path: str, *, node_type: str = "file", source_input_id=None, target=None, xattrs=()) -> dict:
    return {
        "image": image,
        "path": path,
        "node_type": node_type,
        "mode": 0o644,
        "uid": 0,
        "gid": 0,
        "xattrs": list(xattrs),
        "source_input_id": source_input_id,
        "target": target,
    }


_SINGLE_ROLES = (
    "kernel",
    "kernel_trusted_cert_bundle",
    "final_systemd_stub",
    "final_systemd_unit",
    "nvidia_cc_driver",
    "nvidia_cc_firmware",
    "sglang_image",
    "inference_model",
    "asr_model",
    "gateway_dependency_lock",
    "asr_dependency_lock",
)


def _minimal_lock() -> dict:
    inputs = []
    for role in _SINGLE_ROLES:
        if role == "kernel_trusted_cert_bundle":
            inputs.append(_lock_input(role, role, placements=[]))
        else:
            inputs.append(
                _lock_input(role, role, placements=[_placement("runtime-policy", f"/opt/{role}", source_input_id=role)])
            )
    inputs.append(
        _lock_input("src-1", "conf_proc_source", placements=[_placement("runtime-policy", "/opt/src/a.py", source_input_id="src-1")])
    )
    inputs.append(
        _lock_input("policy-1", "policy_tree_input", placements=[_placement("runtime-policy", "/opt/policy.json", source_input_id="policy-1")])
    )
    for tool in ("mksquashfs", "unsquashfs", "veritysetup", "openssl"):
        inputs.append(_lock_input(f"tool-{tool}", "build_tool", component=tool, placements=[]))
    inputs.sort(key=lambda entry: entry["id"])

    return {
        "schema": "conf-proc-lock/v1",
        "lock_version": 1,
        "base_image_record": {
            "kind": "vhd",
            "provider": "fixture",
            "identity_namespace": "fixture-ns",
            "identity_name": "fixture-image",
            "identity_immutable_revision": "1.0.0",
            "content_sha256": _sha(3),
            "content_size_bytes": 100,
            "content_media_type": "application/octet-stream",
            "availability": "record-only",
            "recorded_retrieval_scheme": "local-fixture",
            "recorded_retrieval_identity": "fixture:base-image",
            "recorded_retrieval_immutable_ref": "v1",
        },
        "future_cmdline": "console=ttyS0",
        "inputs": inputs,
        "authorized_module_signers": [],
        "image_specs": {"runtime-policy": {}, "models": {}},
        "policy_input_id": "policy-1",
        "tool_ids": sorted(f"tool-{t}" for t in ("mksquashfs", "unsquashfs", "veritysetup", "openssl")),
    }


class LockSchemaTests(unittest.TestCase):
    def test_minimal_valid_lock(self) -> None:
        parsed = lk.parse_lock(cj.canonical_dumps(_minimal_lock()))
        self.assertEqual(len(parsed.inputs), len(_minimal_lock()["inputs"]))

    def test_reject_wrong_schema(self) -> None:
        lock = _minimal_lock()
        lock["schema"] = "conf-proc-lock/v2"
        with self.assertRaises(ApplianceError) as ctx:
            lk.parse_lock(cj.canonical_dumps(lock))
        self.assertEqual(ctx.exception.reason_code, "CP_LOCK_SCHEMA")

    def test_reject_duplicate_id(self) -> None:
        lock = _minimal_lock()
        lock["inputs"].append(dict(lock["inputs"][0]))
        lock["inputs"].sort(key=lambda entry: entry["id"])
        with self.assertRaises(ApplianceError) as ctx:
            lk.parse_lock(cj.canonical_dumps(lock))
        self.assertEqual(ctx.exception.reason_code, "CP_LOCK_DUPLICATE_ID")

    def test_reject_invalid_role(self) -> None:
        lock = _minimal_lock()
        lock["inputs"][0]["role"] = "not_a_real_role"
        with self.assertRaises(ApplianceError) as ctx:
            lk.parse_lock(cj.canonical_dumps(lock))
        self.assertEqual(ctx.exception.reason_code, "CP_LOCK_ROLE")

    def test_reject_dotdot_local_path(self) -> None:
        lock = _minimal_lock()
        lock["inputs"][0]["source_local_path"] = "../escape"
        with self.assertRaises(ApplianceError) as ctx:
            lk.parse_lock(cj.canonical_dumps(lock))
        self.assertEqual(ctx.exception.reason_code, "CP_LOCK_INPUT_PATH_ESCAPE")

    def test_reject_absolute_local_path(self) -> None:
        lock = _minimal_lock()
        lock["inputs"][0]["source_local_path"] = "/etc/passwd"
        with self.assertRaises(ApplianceError) as ctx:
            lk.parse_lock(cj.canonical_dumps(lock))
        self.assertEqual(ctx.exception.reason_code, "CP_LOCK_INPUT_PATH_ESCAPE")

    def test_reject_dangling_parent_id(self) -> None:
        lock = _minimal_lock()
        lock["inputs"][0]["derivation_parent_ids"] = ["does-not-exist"]
        lock["inputs"][0]["derivation_kind"] = "built"
        with self.assertRaises(ApplianceError) as ctx:
            lk.parse_lock(cj.canonical_dumps(lock))
        self.assertEqual(ctx.exception.reason_code, "CP_LOCK_INPUT_MISSING")

    def test_reject_missing_required_role(self) -> None:
        lock = _minimal_lock()
        lock["inputs"] = [entry for entry in lock["inputs"] if entry["role"] != "kernel"]
        with self.assertRaises(ApplianceError) as ctx:
            lk.parse_lock(cj.canonical_dumps(lock))
        self.assertEqual(ctx.exception.reason_code, "CP_LOCK_PROVENANCE")

    def test_reject_runtime_substitution_marker(self) -> None:
        lock = _minimal_lock()
        lock["future_cmdline"] = "root=${DEVICE}"
        with self.assertRaises(ApplianceError) as ctx:
            lk.parse_lock(cj.canonical_dumps(lock))
        self.assertEqual(ctx.exception.reason_code, "CP_LOCK_SCHEMA")

    def test_reject_duplicate_placement_key(self) -> None:
        lock = _minimal_lock()
        entry = next(e for e in lock["inputs"] if e["id"] == "src-1")
        entry["placements"].append(_placement("runtime-policy", "/opt/src/a.py", source_input_id="src-1"))
        with self.assertRaises(ApplianceError) as ctx:
            lk.parse_lock(cj.canonical_dumps(lock))
        self.assertEqual(ctx.exception.reason_code, "CP_LOCK_SCHEMA")

    def test_reject_policy_input_wrong_role(self) -> None:
        lock = _minimal_lock()
        lock["policy_input_id"] = "src-1"
        with self.assertRaises(ApplianceError) as ctx:
            lk.parse_lock(cj.canonical_dumps(lock))
        self.assertEqual(ctx.exception.reason_code, "CP_LOCK_ROLE")


def _minimal_policy() -> dict:
    return {
        "schema": "conf-proc-policy/v1",
        "policy_version": 1,
        "images": {
            "runtime-policy": {
                "nodes": [
                    {
                        "path": "/etc/spp.conf",
                        "node_type": "file",
                        "mode": 0o644,
                        "uid": 0,
                        "gid": 0,
                        "xattrs": [],
                        "source_input_id": "cfg-1",
                        "target": None,
                        "content_class": "config",
                    }
                ]
            },
            "models": {"nodes": []},
        },
        "boot_roots": [],
        "process_nodes": [
            {
                "id": "exec-1",
                "kind": "exec",
                "path": "/usr/bin/spp-systemd-stub",
                "sha256": _sha(1),
                "argv": ["/usr/bin/spp-systemd-stub"],
                "network_scope": "none",
                "capabilities": [],
                "source_input_id": "stub-1",
            },
            {
                "id": "svc-1",
                "kind": "unit",
                "path": "conf-proc-final.service",
                "sha256": None,
                "argv": [],
                "network_scope": "none",
                "capabilities": [],
                "source_input_id": None,
            },
        ],
        "process_edges": [
            {"from_id": "svc-1", "to_id": "exec-1", "kind": "unit_exec", "origin_path": "conf-proc-final.service", "origin_key": "ExecStart"},
        ],
        "mounts": [
            {"unit_id": "mnt-1", "image": "models", "destination": "/opt/models", "fs_type": "squashfs", "read_only": True},
        ],
        "network_policy": {"svc-1": "none", "exec-1": "none"},
        "capability_policy": {
            "svc-1": {"capability_bounding_set": [], "ambient_capabilities": [], "no_new_privileges": True},
        },
    }


class PolicySchemaTests(unittest.TestCase):
    def test_minimal_valid_policy(self) -> None:
        parsed = pol.parse_policy(cj.canonical_dumps(_minimal_policy()))
        self.assertEqual(len(parsed.process_nodes), 2)

    def test_reject_wrong_schema(self) -> None:
        policy = _minimal_policy()
        policy["schema"] = "conf-proc-policy/v2"
        with self.assertRaises(ApplianceError) as ctx:
            pol.parse_policy(cj.canonical_dumps(policy))
        self.assertEqual(ctx.exception.reason_code, "CP_POLICY_SCHEMA")

    def test_reject_duplicate_process_node_id(self) -> None:
        policy = _minimal_policy()
        policy["process_nodes"].append(dict(policy["process_nodes"][0]))
        policy["process_nodes"].sort(key=lambda node: node["id"])
        with self.assertRaises(ApplianceError) as ctx:
            pol.parse_policy(cj.canonical_dumps(policy))
        self.assertEqual(ctx.exception.reason_code, "CP_POLICY_DUPLICATE")

    def test_reject_dangling_edge_reference(self) -> None:
        policy = _minimal_policy()
        policy["process_edges"].append(
            {"from_id": "svc-1", "to_id": "does-not-exist", "kind": "unit_exec", "origin_path": "x", "origin_key": "y"}
        )
        with self.assertRaises(ApplianceError) as ctx:
            pol.parse_policy(cj.canonical_dumps(policy))
        self.assertEqual(ctx.exception.reason_code, "CP_POLICY_UNSUPPORTED_ACTIVATION")

    def test_reject_literal_ip_network_scope(self) -> None:
        policy = _minimal_policy()
        policy["network_policy"]["svc-1"] = "10.0.0.1"
        with self.assertRaises(ApplianceError) as ctx:
            pol.parse_policy(cj.canonical_dumps(policy))
        self.assertEqual(ctx.exception.reason_code, "CP_POLICY_FORBIDDEN_NETWORK")

    def test_reject_writable_mount(self) -> None:
        policy = _minimal_policy()
        policy["mounts"][0]["read_only"] = False
        with self.assertRaises(ApplianceError):
            pol.parse_policy(cj.canonical_dumps(policy))

    def test_reject_new_privileges_allowed(self) -> None:
        policy = _minimal_policy()
        policy["capability_policy"]["svc-1"]["no_new_privileges"] = False
        with self.assertRaises(ApplianceError):
            pol.parse_policy(cj.canonical_dumps(policy))

    def test_reject_ambient_not_subset_of_bounding(self) -> None:
        policy = _minimal_policy()
        policy["capability_policy"]["svc-1"]["ambient_capabilities"] = ["CAP_NET_ADMIN"]
        with self.assertRaises(ApplianceError) as ctx:
            pol.parse_policy(cj.canonical_dumps(policy))
        self.assertEqual(ctx.exception.reason_code, "CP_POLICY_CAPABILITY")


if __name__ == "__main__":
    unittest.main(verbosity=2)
