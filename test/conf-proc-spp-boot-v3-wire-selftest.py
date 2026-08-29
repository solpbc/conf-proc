#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Focused raw self-tests for the SPP boot authority v3 wire codec."""

from __future__ import annotations

import struct
import sys
import unittest
from math import ceil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import conf_proc_spp_boot_v3_wire as wire
from conf_proc_spp_boot_v3_tables import ServingWireMessageTypeV3


TOKEN = b"s" * 32
OTHER_TOKEN = b"t" * 32
DIGEST = b"d" * 32
PERMIT = b"p" * 32


def _session_token(message_type: ServingWireMessageTypeV3) -> bytes:
    if message_type in (
        ServingWireMessageTypeV3.GATEWAY_READINESS_PROBE,
        ServingWireMessageTypeV3.GATEWAY_READINESS_RESULT,
        ServingWireMessageTypeV3.CHUNK_ACK,
    ):
        return b"\0" * 32
    return TOKEN


def _flags(message_type: ServingWireMessageTypeV3) -> int:
    return wire.FLAG_START_V3 | wire.FLAG_END_V3 | (
        wire.FLAG_HAS_FD_V3 if message_type is ServingWireMessageTypeV3.SESSION_FD else 0
    )


def _frame(
    message_type: ServingWireMessageTypeV3,
    payload: bytes,
    *,
    session_token: bytes | None = None,
    sequence: int = 7,
    chunk_index: int = 0,
    chunk_count: int = 1,
    total_length: int | None = None,
    flags: int | None = None,
) -> bytes:
    return wire.encode_serving_wire_frame_v3(
        message_type,
        session_token=_session_token(message_type) if session_token is None else session_token,
        sequence=sequence,
        chunk_index=chunk_index,
        chunk_count=chunk_count,
        chunk_length=len(payload),
        total_length=len(payload) if total_length is None else total_length,
        flags=_flags(message_type) if flags is None else flags,
        payload_bytes=payload,
    )


def _payload_cases() -> tuple[tuple[ServingWireMessageTypeV3, object, object], ...]:
    request_json = b'{"request":"certificate"}'
    response_json = b'{"certificate":"ok"}'
    session_fd = wire.SessionFdPayloadV3(1, 2, b"\x7f\0\0\x01", 9443, b"\xc0\0\x02\x01", 50000, 9)
    collector_response = wire.CollectorResponsePayloadV3(
        wire.CollectorGenerationV3.CERTIFICATE, wire.CollectorResultV3.SUCCESS,
        0, 123, 0, DIGEST, response_json,
    )
    work_begin = wire.WorkBeginPayloadV3(5, wire.RouteV3.INFERENCE, PERMIT, OTHER_TOKEN)
    work_finish = wire.WorkFinishPayloadV3(
        5, wire.RouteV3.ASR, wire.WorkFinishOutcomeV3.ORDINARY, PERMIT, OTHER_TOKEN,
    )
    return (
        (ServingWireMessageTypeV3.SESSION_FD, session_fd, wire.encode_session_fd_payload_v3),
        (ServingWireMessageTypeV3.COLLECTOR_REQUEST, wire.CollectorRequestPayloadV3(wire.CollectorGenerationV3.CERTIFICATE, request_json), wire.encode_collector_request_payload_v3),
        (ServingWireMessageTypeV3.COLLECTOR_RESPONSE, collector_response, wire.encode_collector_response_payload_v3),
        (ServingWireMessageTypeV3.COLLECTOR_ACK_VALID, wire.CollectorAckValidPayloadV3(wire.CollectorGenerationV3.CERTIFICATE, 123, 0, DIGEST), wire.encode_collector_ack_valid_payload_v3),
        (ServingWireMessageTypeV3.COLLECTOR_ACK_INVALID, wire.CollectorAckInvalidPayloadV3(wire.CollectorGenerationV3.EXPORTER, 123, 1, DIGEST, wire.CollectorAckInvalidReasonV3.SHAPE), wire.encode_collector_ack_invalid_payload_v3),
        (ServingWireMessageTypeV3.COLLECTOR_CANCEL, wire.CollectorCancelPayloadV3(wire.CollectorGenerationV3.CERTIFICATE, wire.CollectorCancelReasonV3.TIMEOUT), wire.encode_collector_cancel_payload_v3),
        (ServingWireMessageTypeV3.REQUEST_ACQUIRE, wire.RequestAcquirePayloadV3(5, wire.RouteV3.INFERENCE, TOKEN), wire.encode_request_acquire_payload_v3),
        (ServingWireMessageTypeV3.REQUEST_ADMIT, wire.RequestAdmitPayloadV3(5, wire.RouteV3.INFERENCE, 2097152, PERMIT, OTHER_TOKEN, DIGEST), wire.encode_request_admit_payload_v3),
        (ServingWireMessageTypeV3.REQUEST_REJECT, wire.RequestRejectPayloadV3(5, wire.RouteV3.ASR, wire.RequestRejectReasonV3.DUPLICATE_REQUEST), wire.encode_request_reject_payload_v3),
        (ServingWireMessageTypeV3.WORK_BEGIN, work_begin, wire.encode_work_begin_payload_v3),
        (ServingWireMessageTypeV3.WORK_BEGUN, work_begin, wire.encode_work_begin_payload_v3),
        (ServingWireMessageTypeV3.WORK_FINISH, work_finish, wire.encode_work_finish_payload_v3),
        (ServingWireMessageTypeV3.WORK_FINISHED, work_finish, wire.encode_work_finish_payload_v3),
        (ServingWireMessageTypeV3.REQUEST_RELEASE, wire.RequestReleasePayloadV3(5, wire.RouteV3.INFERENCE, wire.RequestReleaseStateV3.WORK_FINISHED, PERMIT, OTHER_TOKEN, DIGEST), wire.encode_request_release_payload_v3),
        (ServingWireMessageTypeV3.REQUEST_RELEASED, wire.RequestReleasedPayloadV3(5, wire.RouteV3.INFERENCE, PERMIT), wire.encode_request_released_payload_v3),
        (ServingWireMessageTypeV3.SESSION_RELEASE, wire.SessionReleasePayloadV3(5, 0b111, wire.SessionReleaseReasonV3.NORMAL_CLIENT_CLOSE, PERMIT, OTHER_TOKEN, DIGEST), wire.encode_session_release_payload_v3),
        (ServingWireMessageTypeV3.SESSION_RELEASED, wire.SessionReleasedPayloadV3(5, 0b111, wire.SessionReleaseReasonV3.NORMAL_CLIENT_CLOSE), wire.encode_session_released_payload_v3),
        (ServingWireMessageTypeV3.PRE_REQUEST_REJECTED, wire.PreRequestRejectedPayloadV3(6, wire.PreRequestRejectedReasonV3.MALFORMED), wire.encode_pre_request_rejected_payload_v3),
        (ServingWireMessageTypeV3.GLOBAL_FAULT, wire.GlobalFaultPayloadV3(5, wire.GlobalFaultReasonV3.READINESS, TOKEN), wire.encode_global_fault_payload_v3),
        (ServingWireMessageTypeV3.CHUNK_ACK, wire.ChunkAckPayloadV3(7, 0, 44, DIGEST), wire.encode_chunk_ack_payload_v3),
        (ServingWireMessageTypeV3.SESSION_FD_ACK, wire.SessionFdAckPayloadV3(1, 9, TOKEN), wire.encode_session_fd_ack_payload_v3),
        (ServingWireMessageTypeV3.GATEWAY_READINESS_PROBE, wire.GatewayReadinessProbePayloadV3(1, 2), wire.encode_gateway_readiness_probe_payload_v3),
        (ServingWireMessageTypeV3.GATEWAY_READINESS_RESULT, wire.GatewayReadinessResultPayloadV3(1, 100, 2, 1, DIGEST, 9), wire.encode_gateway_readiness_result_payload_v3),
    )


class ServingWireCodecTests(unittest.TestCase):
    def test_a_all_message_types_round_trip(self) -> None:
        self.assertEqual(set(wire.WIRE_PAYLOAD_DECODERS_V3), set(ServingWireMessageTypeV3))
        for message_type, payload, encoder in _payload_cases():
            with self.subTest(message_type=message_type.name):
                encoded_payload = encoder(payload)
                decoded = wire.decode_serving_wire_frame_v3(_frame(message_type, encoded_payload))
                self.assertEqual(decoded.header.message_type, message_type)
                self.assertEqual(decoded.payload, payload)

    def test_b_header_rejections(self) -> None:
        header = wire.ServingWireHeaderV3(
            3, ServingWireMessageTypeV3.COLLECTOR_CANCEL, 0, 1, 0, 1, 4, 4, TOKEN,
        )
        raw = bytearray(wire.encode_serving_wire_header_v3(header))
        variants = []
        bad_magic = bytearray(raw)
        bad_magic[0] ^= 1
        variants.append(bytes(bad_magic))
        bad_version = bytearray(raw)
        struct.pack_into(">H", bad_version, 8, 4)
        variants.append(bytes(bad_version))
        bad_reserved = bytearray(raw)
        struct.pack_into(">H", bad_reserved, 14, 1)
        variants.append(bytes(bad_reserved))
        bad_flags = bytearray(raw)
        struct.pack_into(">H", bad_flags, 12, 8)
        variants.append(bytes(bad_flags))
        bad_type = bytearray(raw)
        struct.pack_into(">H", bad_type, 10, 24)
        variants.append(bytes(bad_type))
        for value in variants + [bytes(raw[:-1]), bytes(raw) + b"x"]:
            with self.subTest(length=len(value)):
                with self.assertRaises(wire.ApplianceErrorV3):
                    wire.decode_serving_wire_header_v3(value)
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.encode_serving_wire_header_v3(wire.ServingWireHeaderV3(
                3, ServingWireMessageTypeV3.COLLECTOR_CANCEL, 0, 1, 0, 1, 4, 4, b"x",
            ))
        payload = wire.encode_collector_cancel_payload_v3(
            wire.CollectorCancelPayloadV3(wire.CollectorGenerationV3.CERTIFICATE, wire.CollectorCancelReasonV3.TIMEOUT),
        )
        malformed = _frame(ServingWireMessageTypeV3.COLLECTOR_CANCEL, payload) + b"x"
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.decode_serving_wire_frame_v3(malformed)

    def test_c_session_scope_and_cross_field_rules(self) -> None:
        cancel = wire.encode_collector_cancel_payload_v3(
            wire.CollectorCancelPayloadV3(wire.CollectorGenerationV3.CERTIFICATE, wire.CollectorCancelReasonV3.TIMEOUT),
        )
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.decode_serving_wire_frame_v3(_frame(ServingWireMessageTypeV3.COLLECTOR_CANCEL, cancel, session_token=b"\0" * 32))
        probe = wire.encode_gateway_readiness_probe_payload_v3(wire.GatewayReadinessProbePayloadV3(1, 2))
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.decode_serving_wire_frame_v3(_frame(ServingWireMessageTypeV3.GATEWAY_READINESS_PROBE, probe, session_token=TOKEN))
        session_fd = wire.encode_session_fd_payload_v3(
            wire.SessionFdPayloadV3(1, 2, b"\x7f\0\0\x01", 1, b"\x7f\0\0\x01", 2, 3),
        )
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.decode_serving_wire_frame_v3(_frame(ServingWireMessageTypeV3.SESSION_FD, session_fd, flags=wire.FLAG_START_V3 | wire.FLAG_END_V3))
        fault_zero = wire.encode_global_fault_payload_v3(
            wire.GlobalFaultPayloadV3(0, wire.GlobalFaultReasonV3.READINESS, TOKEN),
        )
        self.assertIsInstance(
            wire.decode_serving_wire_frame_v3(_frame(ServingWireMessageTypeV3.GLOBAL_FAULT, fault_zero, session_token=b"\0" * 32)).payload,
            wire.GlobalFaultPayloadV3,
        )
        fault_nonzero = wire.encode_global_fault_payload_v3(
            wire.GlobalFaultPayloadV3(1, wire.GlobalFaultReasonV3.READINESS, TOKEN),
        )
        self.assertIsInstance(
            wire.decode_serving_wire_frame_v3(_frame(ServingWireMessageTypeV3.GLOBAL_FAULT, fault_nonzero)).payload,
            wire.GlobalFaultPayloadV3,
        )
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.decode_serving_wire_frame_v3(_frame(ServingWireMessageTypeV3.GLOBAL_FAULT, fault_nonzero, session_token=b"\0" * 32))
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.decode_serving_wire_frame_v3(_frame(ServingWireMessageTypeV3.GLOBAL_FAULT, fault_zero))

    def test_d_payload_cross_field_rejections(self) -> None:
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.encode_collector_response_payload_v3(wire.CollectorResponsePayloadV3(
                wire.CollectorGenerationV3.CERTIFICATE, wire.CollectorResultV3.SUCCESS,
                1, 1, 0, DIGEST, b'{"x":1}',
            ))
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.encode_request_admit_payload_v3(wire.RequestAdmitPayloadV3(
                1, wire.RouteV3.INFERENCE, 1, PERMIT, OTHER_TOKEN, DIGEST,
            ))
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.encode_work_begin_payload_v3(wire.WorkBeginPayloadV3(
                1, wire.RouteV3.INFERENCE, b"\0" * 32, OTHER_TOKEN,
            ))
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.encode_session_release_payload_v3(wire.SessionReleasePayloadV3(
                1, 0b001, wire.SessionReleaseReasonV3.NORMAL_CLIENT_CLOSE,
                PERMIT, OTHER_TOKEN, b"\0" * 32,
            ))
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.encode_gateway_readiness_result_payload_v3(wire.GatewayReadinessResultPayloadV3(
                1, 2, 3, 2, DIGEST, 4,
            ))

    def test_e_chunk_reassembly_and_mutations(self) -> None:
        json_bytes = b'{"certificate":"' + b"a" * 40000 + b'"}'
        payload = wire.encode_collector_response_payload_v3(wire.CollectorResponsePayloadV3(
            wire.CollectorGenerationV3.CERTIFICATE, wire.CollectorResultV3.SUCCESS,
            0, 1, 0, DIGEST, json_bytes,
        ))
        count = ceil(len(payload) / wire.MAX_CHUNK_PAYLOAD_BYTES_V3)

        def train(*, reported_count: int = count, wrong_start: bool = False, wrong_end: bool = False) -> list[wire.ServingWireFrameV3]:
            frames = []
            for index in range(count):
                chunk = payload[index * wire.MAX_CHUNK_PAYLOAD_BYTES_V3:(index + 1) * wire.MAX_CHUNK_PAYLOAD_BYTES_V3]
                flags = 0
                if index == 0 and not wrong_start:
                    flags |= wire.FLAG_START_V3
                if index == count - 1 and not wrong_end:
                    flags |= wire.FLAG_END_V3
                frames.append(wire.decode_serving_wire_frame_v3(_frame(
                    ServingWireMessageTypeV3.COLLECTOR_RESPONSE, chunk, session_token=TOKEN,
                    sequence=99, chunk_index=index, chunk_count=reported_count,
                    total_length=len(payload), flags=flags,
                )))
            return frames

        good = train()
        self.assertEqual(len(good), 3)
        self.assertEqual(wire.reassemble_chunked_payload_v3(good), payload)
        for changed in (
            good[:1] + good[2:],
            [good[0], good[1], good[1], good[2]],
            [good[1], good[0], good[2]],
            train(reported_count=4),
            train(wrong_start=True),
            train(wrong_end=True),
        ):
            with self.subTest(frame_count=len(changed)):
                with self.assertRaises(wire.ApplianceErrorV3):
                    wire.reassemble_chunked_payload_v3(changed)

    def test_f_payload_boundaries(self) -> None:
        cancel = wire.encode_collector_cancel_payload_v3(
            wire.CollectorCancelPayloadV3(wire.CollectorGenerationV3.CERTIFICATE, wire.CollectorCancelReasonV3.TIMEOUT),
        )
        self.assertEqual(len(cancel), 4)
        self.assertEqual(
            wire.decode_serving_wire_frame_v3(_frame(ServingWireMessageTypeV3.COLLECTOR_CANCEL, cancel)).payload,
            wire.CollectorCancelPayloadV3(wire.CollectorGenerationV3.CERTIFICATE, wire.CollectorCancelReasonV3.TIMEOUT),
        )
        with self.assertRaises(wire.ApplianceErrorV3):
            wire.decode_collector_cancel_payload_v3(b"")
        json_bytes = b'{"x":"' + b"a" * (wire.MAX_CHUNK_PAYLOAD_BYTES_V3 - 44 - 8) + b'"}'
        maximum = wire.encode_collector_response_payload_v3(wire.CollectorResponsePayloadV3(
            wire.CollectorGenerationV3.CERTIFICATE, wire.CollectorResultV3.SUCCESS,
            0, 1, 0, DIGEST, json_bytes,
        ))
        self.assertEqual(len(maximum), wire.MAX_CHUNK_PAYLOAD_BYTES_V3)
        wire.decode_serving_wire_frame_v3(_frame(ServingWireMessageTypeV3.COLLECTOR_RESPONSE, maximum))
        with self.assertRaises(wire.ApplianceErrorV3):
            _frame(ServingWireMessageTypeV3.COLLECTOR_RESPONSE, maximum + b"x")


if __name__ == "__main__":
    unittest.main()
