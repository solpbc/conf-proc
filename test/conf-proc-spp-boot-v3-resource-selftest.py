#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Focused self-tests for SPP boot authority v3 resource authority."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import conf_proc_spp_boot as boot
from conf_proc_spp_boot_v3_resource import ServingAuthorityWrapperV3, ServingResourceReducerV3
from conf_proc_spp_boot_v3_wire import (
    CollectorGenerationV3,
    RequestRejectReasonV3,
    RouteV3,
    WorkFinishOutcomeV3,
)
from conf_proc_spp_reasons_v3 import ApplianceErrorV3


def _completed_session(reducer: ServingResourceReducerV3) -> bytes:
    session = reducer.session_acquire()
    assert session is not None
    for generation in (CollectorGenerationV3.CERTIFICATE, CollectorGenerationV3.EXPORTER):
        permit = reducer.collector_acquire(session, generation)
        assert permit is not None
        reducer.collector_finish(session, generation, permit)
    return session


class _SessionTransport:
    def __init__(self, handle: object) -> None:
        self._handle = handle

    def execute(self, effect: boot.BootEffect) -> boot.BootObservation:
        assert type(effect) is boot.ServingSessionEffect
        if effect.action == "credential_observed":
            return boot.CredentialObservedV2(effect.contract_sha256, self._handle, "a" * 64)
        if effect.action == "entitlement_dns_result":
            return boot.EntitlementDnsResultV2(effect.contract_sha256, effect.token, "203.0.113.8", 60)
        if effect.action == "entitlement_tls_connect":
            return boot.EntitlementTlsConnectedV2(
                effect.contract_sha256, effect.token, effect.ipv4_address, 0
            )
        return boot.ServingSessionReadback(effect.contract_sha256, effect.action)


class ServingResourceReducerV3SelfTest(unittest.TestCase):
    def test_session_capacity_releases_a_slot(self) -> None:
        reducer = ServingResourceReducerV3()
        sessions = [reducer.session_acquire() for _ in range(4)]
        self.assertTrue(all(sessions))
        self.assertIsNone(reducer.session_acquire())
        reducer.session_release(sessions[0])
        self.assertIsInstance(reducer.session_acquire(), bytes)

    def test_collector_order_global_exclusivity_and_abort(self) -> None:
        reducer = ServingResourceReducerV3()
        first = reducer.session_acquire()
        blocked = reducer.session_acquire()
        assert first is not None and blocked is not None
        certificate = reducer.collector_acquire(first, CollectorGenerationV3.CERTIFICATE)
        assert certificate is not None
        self.assertIsNone(reducer.collector_acquire(blocked, CollectorGenerationV3.CERTIFICATE))
        with self.assertRaises(ApplianceErrorV3):
            reducer.collector_acquire(first, CollectorGenerationV3.EXPORTER)
        reducer.collector_finish(first, CollectorGenerationV3.CERTIFICATE, certificate)
        with self.assertRaises(ApplianceErrorV3):
            reducer.request_acquire(first, RouteV3.INFERENCE)
        exporter = reducer.collector_acquire(first, CollectorGenerationV3.EXPORTER)
        assert exporter is not None
        reducer.collector_finish(first, CollectorGenerationV3.EXPORTER, exporter)
        self.assertIsInstance(reducer.request_acquire(first, RouteV3.INFERENCE), tuple)
        with self.assertRaises(ApplianceErrorV3):
            reducer.request_acquire(blocked, RouteV3.ASR)

        aborted = reducer.session_acquire()
        assert aborted is not None
        permit = reducer.collector_acquire(aborted, CollectorGenerationV3.CERTIFICATE)
        assert permit is not None
        reducer.collector_abort(aborted, CollectorGenerationV3.CERTIFICATE, permit)
        with self.assertRaises(ApplianceErrorV3):
            reducer.collector_acquire(aborted, CollectorGenerationV3.CERTIFICATE)
        self.assertEqual(reducer.session_release(aborted), (0, None, None, None))

    def test_request_rejections_and_route_capacity(self) -> None:
        reducer = ServingResourceReducerV3()
        first = _completed_session(reducer)
        second = _completed_session(reducer)
        first_request = reducer.request_acquire(first, RouteV3.INFERENCE)
        self.assertIsInstance(first_request, tuple)
        self.assertEqual(
            reducer.request_acquire(first, RouteV3.INFERENCE),
            RequestRejectReasonV3.DUPLICATE_REQUEST,
        )
        self.assertEqual(
            reducer.request_acquire(second, RouteV3.INFERENCE),
            RequestRejectReasonV3.ROUTE_SLOT_SATURATED,
        )
        reducer.session_release(first)
        reducer.session_release(second)

        inference = _completed_session(reducer)
        asr = _completed_session(reducer)
        inference_result = reducer.request_acquire(inference, RouteV3.INFERENCE)
        asr_result = reducer.request_acquire(asr, RouteV3.ASR)
        assert isinstance(inference_result, tuple) and isinstance(asr_result, tuple)
        self.assertEqual(inference_result[3], 2097152)
        self.assertEqual(asr_result[3], 2097152)
        self.assertEqual(len(reducer.route_slot_holders), 2)

    def test_work_and_request_release_ordering(self) -> None:
        reducer = ServingResourceReducerV3()
        session = _completed_session(reducer)
        request, work, _buffer, _capacity = reducer.request_acquire(session, RouteV3.INFERENCE)
        with self.assertRaises(ApplianceErrorV3):
            reducer.work_begin(session, b"x" * 32)
        reducer.work_begin(session, work)
        with self.assertRaises(ApplianceErrorV3):
            reducer.work_finish(session, b"x" * 32)
        reducer.work_finish(session, work)
        reducer.request_release(session, request)

        request, work, _buffer, _capacity = reducer.request_acquire(session, RouteV3.ASR)
        reducer.request_release(session, request)
        self.assertNotIn(RouteV3.ASR, reducer.route_slot_holders)
        with self.assertRaises(ApplianceErrorV3):
            reducer.work_finish(session, work)

    def test_session_release_and_global_revoke(self) -> None:
        reducer = ServingResourceReducerV3()
        held_collector = reducer.session_acquire()
        assert held_collector is not None
        collector = reducer.collector_acquire(held_collector, CollectorGenerationV3.CERTIFICATE)
        assert collector is not None
        with self.assertRaises(ApplianceErrorV3):
            reducer.session_release(held_collector)
        reducer.collector_abort(held_collector, CollectorGenerationV3.CERTIFICATE, collector)
        self.assertEqual(reducer.session_release(held_collector), (0, None, None, None))

        session = _completed_session(reducer)
        request, work, buffer, _capacity = reducer.request_acquire(session, RouteV3.INFERENCE)
        bitmap, request_slot, work_slot, buffer_slot = reducer.session_release(session)
        self.assertEqual(bitmap, 7)
        self.assertEqual((request_slot, work_slot, buffer_slot), (request, work, buffer))
        self.assertNotIn(RouteV3.INFERENCE, reducer.route_slot_holders)

        survivor = reducer.session_acquire()
        assert survivor is not None
        reducer.global_revoke()
        reducer.global_revoke()
        with self.assertRaises(ApplianceErrorV3):
            reducer.session_acquire()
        with self.assertRaises(ApplianceErrorV3):
            reducer.session_release(survivor)

    def test_wrapper_drives_resource_and_session_in_lockstep(self) -> None:
        wrapper = ServingAuthorityWrapperV3()
        handle = object()
        closed: list[bool] = []
        transport = _SessionTransport(handle)
        session = wrapper.open_session(transport, lambda: closed.append(True))
        assert session is not None
        for generation in (CollectorGenerationV3.CERTIFICATE, CollectorGenerationV3.EXPORTER):
            permit = wrapper.collector_acquire(session, generation)
            assert permit is not None
            wrapper.collector_finish(session, generation, permit)

        result = wrapper.begin_request(
            session, path="/v1/chat/completions", body_length=1, opaque_handle=handle
        )
        assert isinstance(result, tuple)
        request_permit, route_work_permit, _buffer_permit, capacity = result
        self.assertEqual(capacity, 2097152)
        while True:
            effect = wrapper.next_effect(session)
            assert type(effect) is boot.ServingSessionEffect
            if effect.action == "upstream_open":
                wrapper.work_begin(session, route_work_permit)
                self.assertTrue(wrapper._resource.sessions[session.session_token].route_work[2])
                wrapper.advance(session, transport)
                break
            wrapper.advance(session, transport)
        self.assertEqual(session.session_reducer.state, boot.ServingSessionState.UPSTREAM_OPENED)
        wrapper.work_finish(session, route_work_permit, WorkFinishOutcomeV3.ORDINARY)
        wrapper.advance(session, transport)
        self.assertEqual(session.session_reducer.state, boot.ServingSessionState.REQUEST_CLOSED)
        wrapper.request_release(session, request_permit)
        self.assertIsNone(wrapper._resource.sessions[session.session_token].request_permit)
        self.assertEqual(wrapper.session_release(session), (0, None, None, None))
        self.assertEqual(closed, [True])


if __name__ == "__main__":
    unittest.main()
