#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Hermetic acceptance tests for the declaration-only A3.1c resume anchor."""

from __future__ import annotations

import dataclasses
import hashlib
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "test") not in sys.path:
    sys.path.insert(0, str(ROOT / "test"))

import conf_proc_spp_boot_v3 as boot
import conf_proc_spp_boot_v3_tables as tables
import conf_proc_spp_boot_v3_resume_oracle as oracle
from conf_proc_spp_boot_v3_fixture import build_v3_fixture


_EXPECTED_STATE_HEX = (
    "dd79cdd3198de0782d1639b2cb4ac08930f6d90f6c32a219216bdac0b7a0f808",
    "58162bdb8d7f753456b59ffe883f34f299c8c7f4c83e676db1e2dfb6169fb767",
    "8ef22e0f431ae6bb6ac008be7b6854427c9b0d5c93448fe638a6e2fa9b5d7f57",
    "6a051d47214f72ff43e72e7e0e5f221ed5f106976364f855d98a244eca88dd7b",
    "a12c8c45900542b3deb295f5aeb771439651bf3f246fcc560a31a5165c55d745",
    "1f48f5dd3e767da6a51bbc265eb6f16e6199b05bb15880c6eae849a61339aa07",
    "b5fc8cdeddc3618da83ef4e04cabef0a45943bda23dcd5d4aeeafccfe75a572d",
    "c8ee7472ce5833c9e5f8d2c26db41c42f4ac3c3795bace5a15072f526cbda396",
)
_SOURCE_NAMES = (
    "conf_proc_geometry.py", "conf_proc_json.py", "conf_proc_lock.py",
    "conf_proc_module_authority.py", "conf_proc_policy.py",
    "conf_proc_provenance_v2.py", "conf_proc_provenance_v2_manifest.py",
    "conf_proc_reasons.py", "conf_proc_spp_boot.py",
    "conf_proc_spp_boot_dispatch_v3.py", "conf_proc_spp_boot_v3.py",
    "conf_proc_spp_boot_v3_resource.py", "conf_proc_spp_boot_v3_semantics.py",
    "conf_proc_spp_boot_v3_tables.py", "conf_proc_spp_boot_v3_wire.py",
    "conf_proc_spp_init.py", "conf_proc_spp_reasons_v3.py",
)


def _product_sources() -> dict[str, str]:
    return {name: (ROOT / name).read_text(encoding="utf-8") for name in _SOURCE_NAMES}


def _synthetic() -> str:
    return """
def stage2_consumed_s2_accepted():
    stage2_extend_consumed()
    stage2_read_consumed()

def stage2_resume_entry_v3():
    binding = resume_only_binding_constructor()
    stage2_read_staged()
    consume_fd3()
    stage2_consumed_s2_accepted()
    stage2_pcr15_read()
    evidence = Stage2ResumeEvidenceV3(binding)
    _resume_boot_transition_from_consumed_v3(binding, evidence)
    Stage2ResumeEngineV3(evidence)
"""


def _replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise AssertionError((old, source.count(old)))
    return source.replace(old, new)


class ResumeDeclarationTests(unittest.TestCase):
    def test_a_exact_frozen_row_counts_orders_and_target_receipts(self) -> None:
        self.assertEqual(tuple(row.row_id for row in tables.RESUME_ANCHOR_ROWS_V3), ("tpm_pcr16_stage2_once",))
        self.assertEqual(tuple(row.row_id for row in tables.RESUME_DOMAIN_ROWS_V3), ("stage1_staged", "stage2_consumed"))
        self.assertEqual(tuple(row.row_id for row in tables.PCR16_OPERATION_ROWS_V3), oracle.OPERATION_IDS)
        self.assertEqual(tuple(row.row_id for row in tables.SUPPORTING_MEMFD_ROWS_V3), ("sealed_handoff_fd3_evidence",))
        self.assertEqual(tuple(row.row_id for row in tables.RESUME_CALL_GRAPH_ROWS_V3), ("production_entry_dominance",))
        self.assertEqual(tuple(row.row_id for row in tables.RESUME_CLOSURE_ORACLE_ROWS_V3), ("independent_resume_closure",))
        anchor = tables.RESUME_ANCHOR_ROWS_V3[0]
        self.assertEqual(anchor.reset_start, b"\0" * 32)
        self.assertEqual(anchor.reset_receipt_sha256, "2ebf2a8e0625ed5866aee4394238f4819270a3b7401028b0d170b5261dd1b8c1")
        self.assertEqual(anchor.transport_receipt_sha256, "e1fe6f2206c8e945faddeacf9d6089bb3a89515195415ecdaa2cc53f10772b1d")
        self.assertEqual((anchor.bank, anchor.pcr_index, anchor.device_path, anchor.inherited_fd), ("sha256", 16, "/dev/tpmrm0", 5))
        self.assertEqual(tuple((name, width) for name, width, _source in anchor.lineage_input_rows), oracle.INPUT_ROWS)
        self.assertEqual(anchor.target_reset_counts, (4, 5, 6))
        self.assertEqual(anchor.target_restart_counts, (0, 0, 0))
        self.assertEqual(len(anchor.target_boot_ids), 3)
        self.assertIn("quote_and_PCR_read_only", anchor.post_transfer_authority_rule)

    def test_b_exact_domains_transport_and_dominance_handoff(self) -> None:
        self.assertEqual(tuple(row.domain for row in tables.RESUME_DOMAIN_ROWS_V3), (oracle.STAGED_DOMAIN, oracle.CONSUMED_DOMAIN))
        self.assertEqual(
            tuple(row.field_widths for row in tables.RESUME_DOMAIN_ROWS_V3),
            ((36, 2, 4, 32, 32, 32), (38, 2, 32, 32, 32, 32, 32)),
        )
        self.assertEqual(
            tuple((len(row.domain), row.field_widths[0]) for row in tables.RESUME_DOMAIN_ROWS_V3),
            ((36, 36), (38, 38)),
        )
        anchor = tables.RESUME_ANCHOR_ROWS_V3[0]
        transport_values = dict(anchor.transport_identity_fields)
        transport = oracle.Transport(
            transport_values["st_dev_major_u32be"], transport_values["st_dev_minor_u32be"],
            transport_values["st_ino_u64be"], transport_values["st_rdev_major_u32be"],
            transport_values["st_rdev_minor_u32be"],
            transport_values["F_GETFL_without_O_CLOEXEC_u32be"],
            transport_values["F_GETFD_u32be"], transport_values["fdinfo_mnt_id_u64be"],
            transport_values["fdinfo_ino_u64be"], transport_values["registration_identity_sha256_raw"],
        )
        self.assertEqual(oracle.transport_identity(transport).hex(), "58162bdb8d7f753456b59ffe883f34f299c8c7f4c83e676db1e2dfb6169fb767")
        dominance = tables.RESUME_CALL_GRAPH_ROWS_V3[0]
        self.assertEqual(dominance.canonical_bytes, oracle.DOMINANCE_BYTES)
        self.assertEqual(dominance.canonical_sha256, oracle.DOMINANCE_SHA256)
        self.assertEqual(hashlib.sha256(dominance.canonical_bytes).hexdigest(), dominance.canonical_sha256)
        self.assertEqual(dominance.schema, oracle.DOMINANCE_OBJECT["schema"])
        self.assertEqual(list(dominance.authorization_sink_kinds), oracle.DOMINANCE_OBJECT["authorization_sink_kinds"])
        declarations = {
            "resume_anchor": tables.RESUME_ANCHOR_ROWS_V3,
            "resume_domains": tables.RESUME_DOMAIN_ROWS_V3,
            "pcr16_operations": tables.PCR16_OPERATION_ROWS_V3,
            "supporting_memfd": tables.SUPPORTING_MEMFD_ROWS_V3,
            "resume_call_graph": tables.RESUME_CALL_GRAPH_ROWS_V3,
            "resume_closure_oracle": tables.RESUME_CLOSURE_ORACLE_ROWS_V3,
        }
        self.assertEqual(
            {name: oracle.declaration_digest(rows) for name, rows in declarations.items()},
            oracle.DECLARATION_SHA256,
        )
        for name, rows in declarations.items():
            changed = dataclasses.replace(rows[0], **{dataclasses.fields(rows[0])[0].name: "mutated"})
            with self.subTest(declaration=name):
                self.assertNotEqual(oracle.declaration_digest((changed, *rows[1:])), oracle.DECLARATION_SHA256[name])

    def test_c_exact_packets_closed_inventory_and_no_reset(self) -> None:
        rows = tables.PCR16_OPERATION_ROWS_V3
        authority_sources = _product_sources()
        source_authority = (ROOT / "conf_proc_spp_boot_payload_v3.py").read_text(encoding="utf-8")
        self.assertEqual(tuple(authority_sources), oracle.A3_PRODUCTION_SOURCE_PATHS)
        self.assertEqual(oracle.a3_shipped_source_paths(source_authority), oracle.A3_PRODUCTION_SOURCE_PATHS)
        self.assertEqual(oracle.a3_shipped_source_pins(source_authority), oracle.A3_PRODUCTION_SOURCE_PINS)
        oracle.validate_a3_tpm_authority_declarations(authority_sources, source_authority)
        self.assertEqual(tuple(row.ordinal for row in rows), tuple(range(1, 7)))
        self.assertEqual(tuple(row.request_prefix for row in rows[::3]), (oracle.READ_REQUEST, oracle.READ_REQUEST))
        self.assertTrue(all(row.maximum_packet_bytes == 4096 and row.timeout_ms == 5000 for row in rows))
        self.assertTrue(all(row.poll_events == ("POLLIN",) and row.accepted_return_codes == (0,) for row in rows))
        for index in (0, 2, 3, 5):
            self.assertEqual(rows[index].response_prefix, bytes.fromhex("80010000003e00000000"))
            self.assertEqual(rows[index].response_dynamic_fields[0], "pcr_update_counter_u32be")
        for index in (1, 4):
            self.assertEqual(rows[index].fixed_response, oracle.EXTEND_SUCCESS)
        self.assertEqual(oracle.extend_request(b"\x11" * 32), oracle.EXTEND_PREFIX + b"\x11" * 32)
        self.assertEqual(
            oracle.read_response(oracle.S0, 264).hex(),
            "80010000003e000000000000010800000001000b030000010000000100200000000000000000000000000000000000000000000000000000000000000000",
        )
        oracle.validate_command_inventory(tuple(zip(oracle.OPERATION_IDS, oracle.OPERATION_KINDS, strict=True)), ())
        product = "\n".join(_product_sources().values()).casefold()
        self.assertNotIn("tpm2_pcr_reset", product)
        self.assertNotIn("0000013d", product)
        for bad in (
            tuple(zip(oracle.OPERATION_IDS, oracle.OPERATION_KINDS, strict=True)) + (("reset", "reset"),),
            tuple(zip(oracle.OPERATION_IDS, oracle.OPERATION_KINDS, strict=True)) + (("generic", "passthrough"),),
            tuple(zip(oracle.OPERATION_IDS[:-1], oracle.OPERATION_KINDS[:-1], strict=True)),
        ):
            with self.assertRaises(ValueError):
                oracle.validate_command_inventory(bad, ())
        with self.assertRaises(ValueError):
            oracle.validate_command_inventory(tuple(zip(oracle.OPERATION_IDS, oracle.OPERATION_KINDS, strict=True)), ("consumer",))
        for path in oracle.A3_PRODUCTION_SOURCE_PATHS:
            mutated_sources = dict(authority_sources)
            mutated_sources[path] += (
                "\nGENERIC_TPM_AUTHORITY_ROWS_V3 = "
                "((\"generic_passthrough\", \"/dev/tpmrm0\", \"caller_command_buffer\"),)\n"
            )
            with self.subTest(generic_injection=path), self.assertRaises(ValueError):
                oracle.validate_a3_tpm_authority_declarations(mutated_sources, source_authority)
        identifier_only = dict(authority_sources)
        identifier_only["conf_proc_spp_boot_v3_semantics.py"] += (
            "\nclass TpmOpaqueAuthorityV3:\n"
            "    pass\n"
            "\nOPAQUE_AUTHORITY_ROWS_V3 = (TpmOpaqueAuthorityV3(),)\n"
        )
        with self.assertRaises(ValueError):
            oracle.validate_a3_tpm_authority_declarations(identifier_only, source_authority)
        neutral_reset_writer = dict(authority_sources)
        neutral_reset_writer["conf_proc_spp_boot_v3_semantics.py"] += (
            "\ndef neutral_writer(fd):\n"
            "    __import__('os').write(fd, bytes((128,1,0,0,0,10,0,0,1,61)))\n"
        )
        with self.assertRaises(ValueError):
            oracle.reject_dangerous_tpm_command_authority(neutral_reset_writer)
        for expression in (
            "bytearray([128,1,0,0,0,10,0,0,1,61])",
            "struct.pack('>HII', 32769, 10, 317)",
            "bytes.fromhex('80010000000a0000013d')",
        ):
            changed = dict(authority_sources)
            changed["conf_proc_spp_boot_v3_semantics.py"] += (
                "\ndef neutral_packet():\n    return " + expression + "\n"
            )
            with self.subTest(reset_construction=expression), self.assertRaises(ValueError):
                oracle.reject_dangerous_tpm_command_authority(changed)
        tracked_tpm_writer = dict(authority_sources)
        tracked_tpm_writer["conf_proc_spp_boot_v3_semantics.py"] += (
            "\ndef neutral_writer():\n"
            "    channel = open('/dev/tpmrm0', 'rb+')\n"
            "    channel.write(b'opaque')\n"
        )
        with self.assertRaises(ValueError):
            oracle.reject_dangerous_tpm_command_authority(tracked_tpm_writer)
        with self.assertRaises(ValueError):
            oracle.validate_a3_tpm_authority_declarations(
                authority_sources,
                source_authority.replace(
                    '"/usr/lib/spp/conf_proc_spp_boot_v3_semantics.py"',
                    '"/usr/lib/spp/conf_proc_spp_boot_v3_semantics_replaced.py"',
                    1,
                ),
            )
        first_row = (
            '_SourceAuthorityV3("/usr/lib/spp/conf_proc_geometry.py", "support", 0o444, '
            '2725, "f8273165758c6460bb10d840cb67097a423df819c449119ad15d57b21e05205a")'
        )
        indirect_authority = source_authority.replace(
            "BOOT_PAYLOAD_SOURCE_AUTHORITY_V3: Final = (",
            "_INDIRECT_SOURCE_ROWS_V3 = (" + first_row + ",)\n"
            "BOOT_PAYLOAD_SOURCE_AUTHORITY_V3: Final = _INDIRECT_SOURCE_ROWS_V3 + (",
            1,
        )
        with self.assertRaises(ValueError):
            oracle.a3_shipped_source_pins(indirect_authority)
        with self.assertRaises(ValueError):
            oracle.a3_shipped_source_pins(source_authority + "\n" + first_row + "\n")
        with self.assertRaises(ValueError):
            oracle.a3_shipped_source_pins(
                source_authority + "\nIndirectSourceAuthority = _SourceAuthorityV3\n"
            )
        with self.assertRaises(ValueError):
            oracle.a3_shipped_source_pins(
                source_authority + "\ngetattr(module, '_SourceAuthorityV3')\n"
            )

    def test_d_literal_shape_binding_fingerprint_and_canonical_bytes_are_pinned(self) -> None:
        values, contract = build_v3_fixture()
        binding = boot.bind_boot_inputs_v3(contract=contract, **values)
        shape = binding.literal_v3_observation_shape_bytes
        for label in (b"resume_anchor", b"resume_domains", b"pcr16_operations", b"resume_call_graph", b"resume_closure_oracle"):
            self.assertIn(label, shape)
        self.assertIn(oracle.DOMINANCE_SHA256.encode(), shape)
        baseline = boot._literal_v3_observation_shape_bytes(binding.process_authority)
        row = tables.RESUME_CALL_GRAPH_ROWS_V3[0]
        with patch.object(tables, "RESUME_CALL_GRAPH_ROWS_V3", (dataclasses.replace(row, canonical_bytes=row.canonical_bytes + b"x"),)):
            self.assertNotEqual(boot._literal_v3_observation_shape_bytes(binding.process_authority), baseline)

    def test_e_resume_declarations_do_not_add_runtime_authority(self) -> None:
        source = (ROOT / "conf_proc_spp_boot_v3.py").read_text(encoding="utf-8")
        for name in ("stage2_resume_entry_v3", "Stage2ResumeEvidenceV3", "_resume_boot_transition_from_consumed_v3"):
            self.assertNotIn("def " + name, source)
            self.assertNotIn("class " + name, source)
        self.assertEqual(oracle.analyze_source_corpus(_product_sources(), "declared_unissuable"), ())


class ResumeKatTests(unittest.TestCase):
    def test_f_known_answer_and_every_raw_input_byte(self) -> None:
        vector = oracle.vector_inputs()
        expected = oracle.calculate(vector)
        self.assertEqual(tuple(getattr(expected, field).hex() for field in expected.__dataclass_fields__), _EXPECTED_STATE_HEX)
        coordinates = []
        for field in ("frame", "nonce", "binding", "measurement", "pcr15"):
            coordinates.extend((field, index, None) for index in range(len(getattr(vector, field))))
        for row_index, row in enumerate(vector.authority_inputs):
            coordinates.extend(("authority_inputs", row_index, index) for index in range(len(row)))
        for coordinate in coordinates:
            with self.subTest(coordinate=coordinate):
                self.assertNotEqual(oracle.calculate(oracle.mutate_input_byte(vector, coordinate)).s2, expected.s2)
        transport_widths = {
            "st_dev_major": 4, "st_dev_minor": 4, "st_ino": 8,
            "st_rdev_major": 4, "st_rdev_minor": 4,
            "f_getfl_without_o_cloexec": 4, "f_getfd": 4,
            "fdinfo_mnt_id": 8, "fdinfo_ino": 8,
        }
        for field in dataclasses.fields(oracle.Transport):
            transport = vector.transport
            value = getattr(transport, field.name)
            byte_count = len(value) if type(value) is bytes else transport_widths[field.name]
            for byte_index in range(byte_count):
                if type(value) is bytes:
                    member = bytearray(value)
                    member[byte_index] ^= 1
                    changed = bytes(member)
                else:
                    changed = value ^ (1 << (8 * byte_index))
                with self.subTest(transport=field.name, byte=byte_index):
                    self.assertNotEqual(oracle.calculate(dataclasses.replace(vector, transport=dataclasses.replace(transport, **{field.name: changed}))).s2, expected.s2)
        domains = (oracle.NONCE_DOMAIN, oracle.LINEAGE_DOMAIN, oracle.TRANSPORT_DOMAIN, oracle.STAGED_DOMAIN, oracle.CONSUMED_DOMAIN)
        for domain_index, domain in enumerate(domains):
            for byte_index in range(len(domain)):
                changed_domains = list(domains)
                changed = bytearray(domain)
                changed[byte_index] ^= 1
                changed_domains[domain_index] = bytes(changed)
                with self.subTest(domain=domain_index, byte=byte_index):
                    self.assertNotEqual(oracle.calculate_with_domains(vector, tuple(changed_domains)).s2, expected.s2)
        for index in range(4):
            for byte_index in range(8):
                namespaces = list(vector.namespaces)
                namespaces[index] ^= 1 << (8 * byte_index)
                self.assertNotEqual(oracle.calculate(dataclasses.replace(vector, namespaces=tuple(namespaces))).s2, expected.s2)

    def test_g_length_type_endian_order_and_state_mutations_fail(self) -> None:
        vector = oracle.vector_inputs()
        for field in ("frame", "nonce", "binding", "measurement", "pcr15"):
            for delta in (-1, 1):
                value = getattr(vector, field)
                changed = value[:delta] if delta == -1 else value + b"x"
                with self.subTest(field=field, delta=delta):
                    with self.assertRaises(ValueError):
                        oracle.calculate(dataclasses.replace(vector, **{field: changed}))
        self.assertNotEqual(
            oracle.calculate(dataclasses.replace(vector, authority_inputs=vector.authority_inputs[::-1])).s2,
            oracle.calculate(vector).s2,
        )
        with self.assertRaises(ValueError):
            oracle.calculate(dataclasses.replace(vector, namespaces=(True, *vector.namespaces[1:])))
        with self.assertRaises(ValueError):
            oracle.transport_identity(vector.transport, endian="little")
        for index, member in enumerate(vector.authority_inputs):
            changed = list(vector.authority_inputs)
            changed[index] = member[:-1]
            with self.subTest(short_authority=index), self.assertRaises(ValueError):
                oracle.calculate(dataclasses.replace(vector, authority_inputs=tuple(changed)))
        reversed_authorities = list(vector.authority_inputs)
        reversed_authorities[0], reversed_authorities[1] = reversed_authorities[1], reversed_authorities[0]
        self.assertNotEqual(oracle.calculate(dataclasses.replace(vector, authority_inputs=tuple(reversed_authorities))).s2, oracle.calculate(vector).s2)
        self.assertNotEqual(oracle.calculate(dataclasses.replace(vector, namespaces=vector.namespaces[::-1])).s2, oracle.calculate(vector).s2)
        self.assertNotEqual(hashlib.sha256(b"x" + oracle.calculate(vector).d1).digest(), oracle.calculate(vector).s1)

    def test_h_replay_crash_ambiguity_and_operation_matrix(self) -> None:
        vector = oracle.vector_inputs()
        self.assertEqual(oracle.simulate_trace(vector), "synthetic_helper_sink")
        for field in ("copied_bytes", "fresh_process", "second_entry", "duplicate_memfd", "pread", "reset_offset", "live_fd3"):
            with self.subTest(field=field), self.assertRaises(oracle.TerminalTrace):
                oracle.simulate_trace(vector, oracle.TraceOptions(**{field: True}))
        for index in range(1, 7):
            for boundary in (index, -index):
                with self.subTest(crash_at=boundary), self.assertRaises(oracle.TerminalTrace):
                    oracle.simulate_trace(vector, oracle.TraceOptions(crash_at=boundary))
            with self.subTest(ambiguous_at=index), self.assertRaises(oracle.TerminalTrace):
                oracle.simulate_trace(vector, oracle.TraceOptions(ambiguous_at=index))
        with self.assertRaises(oracle.TerminalTrace):
            oracle.simulate_trace(vector, oracle.TraceOptions(crash_after_memfd_consume=True))
        states = oracle.calculate(vector)
        for byte_index in range(32):
            wrong_s0 = bytearray(oracle.S0)
            wrong_s0[byte_index] ^= 1
            with self.assertRaises(oracle.TerminalTrace):
                oracle.simulate_trace(vector, oracle.TraceOptions(initial_pcr=bytes(wrong_s0)))
            for step, state in ((3, states.s1), (4, states.s1), (6, states.s2)):
                wrong_state = bytearray(state)
                wrong_state[byte_index] ^= 1
                with self.subTest(step=step, byte=byte_index), self.assertRaises(oracle.TerminalTrace):
                    oracle.simulate_trace(vector, oracle.TraceOptions(forced_state_at=(step, bytes(wrong_state))))
        for operations in (oracle.OPERATION_IDS[:-1], oracle.OPERATION_IDS[::-1], oracle.OPERATION_IDS + (oracle.OPERATION_IDS[-1],)):
            with self.assertRaises(oracle.TerminalTrace):
                oracle.simulate_trace(vector, oracle.TraceOptions(operation_ids=operations))


class ResumeGraphTests(unittest.TestCase):
    def test_i_synthetic_production_enforced_positive_and_zero_denominator_negative(self) -> None:
        self.assertEqual(oracle.analyze_source_corpus({"conf_proc_spp_init.py": _synthetic()}, "production_enforced"), (oracle._EXPECTED_PATH,))
        imported = _synthetic().replace(
            "def stage2_consumed_s2_accepted():\n    stage2_extend_consumed()\n    stage2_read_consumed()\n\n",
            "from resume_anchor import stage2_consumed_s2_accepted as accept_consumed\n\n",
        ).replace("    stage2_consumed_s2_accepted()\n", "    accept_consumed()\n")
        anchor = """
def stage2_consumed_s2_accepted():
    stage2_extend_consumed()
    stage2_read_consumed()
"""
        self.assertEqual(
            oracle.analyze_source_corpus(
                {"conf_proc_spp_init.py": imported, "resume_anchor.py": anchor},
                "production_enforced",
            ),
            (oracle._EXPECTED_PATH,),
        )
        with self.assertRaises(ValueError):
            oracle.analyze_source_corpus(
                {"conf_proc_spp_init.py": imported, "resume_anchor.py": "def stage2_consumed_s2_accepted():\n    pass\n"},
                "production_enforced",
            )
        full_sources = _product_sources()
        full_sources["conf_proc_spp_init.py"] += _synthetic()
        self.assertEqual(oracle.analyze_source_corpus(full_sources, "production_enforced"), (oracle._EXPECTED_PATH,))
        with self.assertRaises(ValueError):
            oracle.analyze_source_corpus({"conf_proc_spp_init.py": "def unrelated():\n    pass\n"}, "production_enforced")

    def test_j_bypass_alias_reflection_public_evidence_and_handoff_vectors_fail(self) -> None:
        source = _synthetic()
        bad_sources = (
            _replace_once(source, "    stage2_consumed_s2_accepted()\n", ""),
            _replace_once(source, "def stage2_consumed_s2_accepted():\n    stage2_extend_consumed()\n    stage2_read_consumed()", "def stage2_consumed_s2_accepted():\n    pass"),
            _replace_once(source, "    stage2_extend_consumed()\n    stage2_read_consumed()", "    return\n    stage2_extend_consumed()\n    stage2_read_consumed()"),
            _replace_once(source, "    stage2_extend_consumed()\n    stage2_read_consumed()", "    stage2_extend_consumed(stage2_read_consumed())"),
            _replace_once(source, "    stage2_extend_consumed()\n    stage2_read_consumed()", "    stage2_read_consumed()\n    stage2_extend_consumed()"),
            _replace_once(source, "    stage2_read_consumed()\n", ""),
            _replace_once(source, "    consume_fd3()\n", ""),
            _replace_once(source, "    stage2_read_staged()\n", ""),
            _replace_once(source, "    stage2_pcr15_read()\n", "    stage2_boot_transport()\n"),
            _replace_once(source, "def stage2_resume_entry_v3():", "def stage2_resume_entry_v3(evidence):"),
            _replace_once(source, "def stage2_resume_entry_v3():", "def stage2_resume_entry_v3(stage2_consumed_s2_accepted):"),
            _replace_once(source, "    binding = resume_only_binding_constructor()", "    stage2_consumed_s2_accepted = lambda: None\n    binding = resume_only_binding_constructor()"),
            source + "\nalias = _resume_boot_transition_from_consumed_v3\n",
            source + "\nstage2_resume_entry_v3 = eval('lambda: None')\n",
            source + "\nglobals()['stage2_resume_entry_v3'] = lambda: None\n",
            source + "\nif True:\n    stage2_resume_entry_v3 = lambda: None\n",
            source + "\nmodule.__dict__.update({'stage2_resume_entry_v3': lambda: None})\n",
            source + "\ndef stage2_resume_entry_v3():\n    pass\n",
            source + "\nregister(_resume_boot_transition_from_consumed_v3)\n",
            source + "\ndef alternate():\n    Stage2ResumeEvidenceV3(None)\n",
            source + "\ndef captured(callback=_resume_boot_transition_from_consumed_v3):\n    pass\n",
            source + "\ndef leak():\n    evidence = Stage2ResumeEvidenceV3(None)\n    return evidence\n",
            _replace_once(source, "    stage2_read_staged()", "    getattr(x, 'stage2_read_staged')()"),
            _replace_once(source, "    binding = resume_only_binding_constructor()", "    binding = resume_only_binding_constructor()\n    resume_only_binding_constructor()"),
            _replace_once(source, "    Stage2ResumeEngineV3(evidence)", "    InitialBootTransitionEngineV3(evidence)"),
            _replace_once(source, "    stage2_consumed_s2_accepted()", "    stage2_consumed_s1_accepted()"),
            _replace_once(source, "    stage2_consumed_s2_accepted()", "    stage2_consumed_s0_accepted()"),
        )
        for index, bad in enumerate(bad_sources):
            with self.subTest(index=index), self.assertRaises((ValueError, SyntaxError)):
                oracle.analyze_source_corpus({"conf_proc_spp_init.py": bad}, "production_enforced")

    def test_k_coherent_delete_of_operation_and_ordinary_test_still_fails_oracle(self) -> None:
        table_path = ROOT / "conf_proc_spp_boot_v3_tables.py"
        test_path = Path(__file__)
        table_source = table_path.read_text(encoding="utf-8")
        test_source = test_path.read_text(encoding="utf-8")
        oracle.verify_closed_source_witness(table_source, test_source)
        with tempfile.TemporaryDirectory() as directory:
            copied_table = Path(directory) / table_path.name
            copied_test = Path(directory) / test_path.name
            copied_table.write_text(table_source, encoding="utf-8")
            copied_test.write_text(test_source, encoding="utf-8")
            operation = "stage2_read_consumed"
            mutated_table = re.sub(r'^\s*Pcr16OperationRowV3\("' + operation + r'"[^\n]*\n', "", copied_table.read_text(), count=1, flags=re.MULTILINE)
            mutated_test = re.sub(r'^\s*def test_' + operation + r'\(self\).*?(?=^\s*def |^class |\Z)', "", copied_test.read_text(), count=1, flags=re.MULTILINE | re.DOTALL)
            copied_table.write_text(mutated_table, encoding="utf-8")
            copied_test.write_text(mutated_test, encoding="utf-8")
            with self.assertRaises(ValueError):
                oracle.verify_closed_source_witness(copied_table.read_text(), copied_test.read_text())
            graph_source = _synthetic()
            graph_test = "def test_stage2_consumed_s2_accepted():\n    pass\n"
            copied_table.write_text(graph_source.replace("    stage2_consumed_s2_accepted()\n", ""), encoding="utf-8")
            copied_test.write_text(graph_test.replace("def test_stage2_consumed_s2_accepted():\n    pass\n", ""), encoding="utf-8")
            with self.assertRaises(ValueError):
                oracle.analyze_source_corpus({"conf_proc_spp_init.py": copied_table.read_text()}, "production_enforced")

    def test_stage1_read_start(self) -> None:
        self.assertEqual(tables.PCR16_OPERATION_ROWS_V3[0].expected_state, "S0")

    def test_stage1_extend_staged(self) -> None:
        self.assertEqual(tables.PCR16_OPERATION_ROWS_V3[1].request_digest, "D1")

    def test_stage1_read_staged(self) -> None:
        self.assertEqual(tables.PCR16_OPERATION_ROWS_V3[2].expected_state, "S1")

    def test_stage2_read_staged(self) -> None:
        self.assertEqual(tables.PCR16_OPERATION_ROWS_V3[3].expected_state, "S1")

    def test_stage2_extend_consumed(self) -> None:
        self.assertEqual(tables.PCR16_OPERATION_ROWS_V3[4].request_digest, "D2")

    def test_stage2_read_consumed(self) -> None:
        self.assertEqual(tables.PCR16_OPERATION_ROWS_V3[5].expected_state, "S2")


if __name__ == "__main__":
    unittest.main()
