#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""PID1 resource authority and session composition for SPP boot v3."""

from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import Callable

from conf_proc_spp_boot import (
    BootEffect,
    BootObservation,
    BootTransport,
    ServingSessionEffect,
    ServingSessionReducer,
    ServingSessionState,
)
from conf_proc_spp_boot_v3_tables import (
    COLLECTOR_OPERATION_PERMITS_V3,
    MAX_LIVE_SESSIONS_V3,
    ROUTE_WORK_PERMITS_TOTAL_V3,
    STREAM_BUFFER_BYTES_V3,
)
from conf_proc_spp_boot_v3_wire import (
    CollectorGenerationV3,
    RequestRejectReasonV3,
    RouteV3,
    WorkFinishOutcomeV3,
)
from conf_proc_spp_reasons_v3 import ApplianceErrorV3, CP_BOOT_V3_RESOURCE_REDUCER


def _reject(message: str) -> None:
    raise ApplianceErrorV3(CP_BOOT_V3_RESOURCE_REDUCER, message)


def _opaque_token(value: object, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32 or not any(value):
        _reject(f"{label} is invalid")
    return value


def _mint_token() -> bytes:
    token = secrets.token_bytes(32)
    while not any(token):
        token = secrets.token_bytes(32)
    return token


@dataclass
class _SessionRecordV3:
    collector_generation: int = 0
    must_release_only: bool = False
    request_permit: bytes | None = None
    route_work: tuple[RouteV3, bytes, bool] | None = None
    buffer_permit: bytes | None = None


class ServingResourceReducerV3:
    """PID1's local ledger for serving permits and their required ordering."""

    def __init__(self) -> None:
        self.revoked = False
        self.sessions: dict[bytes, _SessionRecordV3] = {}
        self.collector_permit_holder: tuple[bytes, CollectorGenerationV3] | None = None
        self._collector_permit_token: bytes | None = None
        self.route_slot_holders: dict[RouteV3, bytes] = {}

    def _check_active(self) -> None:
        if self.revoked:
            _reject("revoked")

    def _session(self, session_token: object) -> _SessionRecordV3:
        token = _opaque_token(session_token, "session token")
        record = self.sessions.get(token)
        if record is None:
            _reject("session token is unknown")
        return record

    @staticmethod
    def _generation(generation: object) -> CollectorGenerationV3:
        if type(generation) is not CollectorGenerationV3:
            _reject("collector generation is invalid")
        return generation

    @staticmethod
    def _route(route: object) -> RouteV3:
        if type(route) is not RouteV3:
            _reject("route is invalid")
        return route

    @staticmethod
    def _release_route_slot(
        holders: dict[RouteV3, bytes], session_token: bytes, route_work: tuple[RouteV3, bytes, bool] | None
    ) -> None:
        if route_work is not None and holders.get(route_work[0]) == session_token:
            del holders[route_work[0]]

    def session_acquire(self) -> bytes | None:
        self._check_active()
        if len(self.sessions) >= MAX_LIVE_SESSIONS_V3:
            return None
        token = _mint_token()
        while token in self.sessions:
            token = _mint_token()
        self.sessions[token] = _SessionRecordV3()
        return token

    def collector_acquire(
        self, session_token: bytes, generation: CollectorGenerationV3
    ) -> bytes | None:
        self._check_active()
        record = self._session(session_token)
        generation = self._generation(generation)
        if record.must_release_only:
            _reject("session must be released")
        if generation.value != record.collector_generation + 1:
            _reject("collector generation is out of order")
        if self.collector_permit_holder is not None:
            # A saturated collector acquisition must be followed by release only.
            record.must_release_only = True
            return None
        token = _mint_token()
        self.collector_permit_holder = (session_token, generation)
        self._collector_permit_token = token
        return token

    def _consume_collector_permit(
        self, session_token: bytes, generation: CollectorGenerationV3, permit_token: bytes
    ) -> _SessionRecordV3:
        record = self._session(session_token)
        generation = self._generation(generation)
        token = _opaque_token(permit_token, "collector permit token")
        if (
            self.collector_permit_holder != (session_token, generation)
            or self._collector_permit_token != token
        ):
            _reject("collector permit does not match its holder")
        self.collector_permit_holder = None
        self._collector_permit_token = None
        return record

    def collector_finish(
        self, session_token: bytes, generation: CollectorGenerationV3, permit_token: bytes
    ) -> None:
        self._check_active()
        record = self._consume_collector_permit(session_token, generation, permit_token)
        record.collector_generation = generation.value

    def collector_abort(
        self, session_token: bytes, generation: CollectorGenerationV3, permit_token: bytes
    ) -> None:
        self._check_active()
        record = self._consume_collector_permit(session_token, generation, permit_token)
        record.must_release_only = True

    def request_acquire(
        self, session_token: bytes, route: RouteV3
    ) -> tuple[bytes, bytes, bytes, int] | RequestRejectReasonV3:
        self._check_active()
        record = self._session(session_token)
        route = self._route(route)
        if record.must_release_only:
            _reject("session must be released")
        if record.collector_generation != CollectorGenerationV3.EXPORTER.value:
            _reject("collector generations are incomplete")
        if record.request_permit is not None:
            record.must_release_only = True
            return RequestRejectReasonV3.DUPLICATE_REQUEST
        if self.route_slot_holders.get(route) is not None:
            # A saturated request acquisition must be followed by release only.
            record.must_release_only = True
            return RequestRejectReasonV3.ROUTE_SLOT_SATURATED
        request_permit = _mint_token()
        route_work_permit = _mint_token()
        buffer_permit = _mint_token()
        record.request_permit = request_permit
        record.route_work = (route, route_work_permit, False)
        record.buffer_permit = buffer_permit
        self.route_slot_holders[route] = session_token
        return request_permit, route_work_permit, buffer_permit, STREAM_BUFFER_BYTES_V3

    def work_begin(self, session_token: bytes, route_work_permit: bytes) -> None:
        self._check_active()
        record = self._session(session_token)
        token = _opaque_token(route_work_permit, "route work permit token")
        if record.must_release_only:
            _reject("session must be released")
        if record.route_work is None or record.route_work[1] != token or record.route_work[2]:
            _reject("route work permit is unavailable")
        record.route_work = (record.route_work[0], token, True)

    def work_finish(self, session_token: bytes, route_work_permit: bytes) -> None:
        self._check_active()
        record = self._session(session_token)
        token = _opaque_token(route_work_permit, "route work permit token")
        if record.must_release_only:
            _reject("session must be released")
        if record.route_work is None or record.route_work[1] != token:
            _reject("route work permit is unavailable")
        self._release_route_slot(self.route_slot_holders, session_token, record.route_work)
        record.route_work = None

    def request_release(self, session_token: bytes, request_permit: bytes) -> None:
        self._check_active()
        record = self._session(session_token)
        token = _opaque_token(request_permit, "request permit token")
        if record.must_release_only:
            _reject("session must be released")
        if record.request_permit != token:
            _reject("request permit is unavailable")
        self._release_route_slot(self.route_slot_holders, session_token, record.route_work)
        record.request_permit = None
        record.route_work = None
        record.buffer_permit = None

    def session_release(self, session_token: bytes) -> tuple[int, bytes | None, bytes | None, bytes | None]:
        self._check_active()
        record = self._session(session_token)
        if self.collector_permit_holder is not None and self.collector_permit_holder[0] == session_token:
            _reject("collector permit must be consumed before session release")
        bitmap = 0
        if record.request_permit is not None:
            bitmap |= 1
        if record.route_work is not None:
            bitmap |= 2
        if record.buffer_permit is not None:
            bitmap |= 4
        self._release_route_slot(self.route_slot_holders, session_token, record.route_work)
        del self.sessions[session_token]
        return bitmap, record.request_permit, record.route_work[1] if record.route_work else None, record.buffer_permit

    def global_revoke(self) -> None:
        self.revoked = True
        self.sessions.clear()
        self.collector_permit_holder = None
        self._collector_permit_token = None
        self.route_slot_holders.clear()


@dataclass(frozen=True)
class ServingGatewaySessionV3:
    session_token: bytes
    session_reducer: object


class ServingAuthorityWrapperV3:
    """Thin PID1-side composition of resource and gateway session authorities."""

    def __init__(self, on_global_fault: Callable[[], None] | None = None) -> None:
        self._resource = ServingResourceReducerV3()
        self._sessions: dict[bytes, ServingGatewaySessionV3] = {}
        self._on_global_fault = on_global_fault

    def _session(self, session: object) -> ServingGatewaySessionV3:
        if type(session) is not ServingGatewaySessionV3:
            _reject("gateway session is invalid")
        if self._sessions.get(session.session_token) is not session:
            _reject("gateway session is unknown")
        return session

    def open_session(
        self, session_transport: BootTransport, close_callback: object
    ) -> ServingGatewaySessionV3 | None:
        token = self._resource.session_acquire()
        if token is None:
            return None
        try:
            session = ServingGatewaySessionV3(token, ServingSessionReducer(session_transport, close_callback))
        except Exception:
            self._resource.session_release(token)
            raise
        self._sessions[token] = session
        return session

    def begin_request(
        self,
        session: ServingGatewaySessionV3,
        *,
        path: str,
        body_length: int,
        opaque_handle: object,
    ) -> tuple[bytes, bytes, bytes, int] | RequestRejectReasonV3:
        claimed = self._session(session)
        result = self._resource.request_acquire(claimed.session_token, self._route_for_path(path))
        if isinstance(result, RequestRejectReasonV3):
            return result
        reducer = self._reducer(claimed)
        reducer.begin_request(path=path, body_length=body_length, opaque_handle=opaque_handle)
        return result

    @staticmethod
    def _route_for_path(path: object) -> RouteV3:
        if type(path) is not str or not path.startswith("/"):
            _reject("request path is invalid")
        return RouteV3.ASR if path.startswith("/v1/audio/") else RouteV3.INFERENCE

    @staticmethod
    def _reducer(session: ServingGatewaySessionV3) -> ServingSessionReducer:
        if type(session.session_reducer) is not ServingSessionReducer:
            _reject("session reducer is invalid")
        return session.session_reducer

    def work_begin(self, session: ServingGatewaySessionV3, route_work_permit: bytes) -> None:
        claimed = self._session(session)
        effect = self._reducer(claimed).next_effect()
        if type(effect) is not ServingSessionEffect or effect.action != "upstream_open":
            _reject("upstream open effect is not pending")
        self._resource.work_begin(claimed.session_token, route_work_permit)

    def work_finish(
        self,
        session: ServingGatewaySessionV3,
        route_work_permit: bytes,
        outcome: WorkFinishOutcomeV3,
    ) -> None:
        claimed = self._session(session)
        if type(outcome) is not WorkFinishOutcomeV3:
            _reject("work finish outcome is invalid")
        self._resource.work_finish(claimed.session_token, route_work_permit)

    def request_release(self, session: ServingGatewaySessionV3, request_permit: bytes) -> None:
        claimed = self._session(session)
        state = self._reducer(claimed).state
        if state not in (ServingSessionState.REQUEST_CLOSED, ServingSessionState.SESSION_CLOSED):
            _reject("session request is not closed")
        self._resource.request_release(claimed.session_token, request_permit)

    def session_release(self, session: ServingGatewaySessionV3) -> tuple[int, bytes | None, bytes | None, bytes | None]:
        claimed = self._session(session)
        result = self._resource.session_release(claimed.session_token)
        del self._sessions[claimed.session_token]
        self._reducer(claimed).close()
        return result

    def global_revoke(self) -> None:
        try:
            if self._on_global_fault is not None:
                self._on_global_fault()
        finally:
            self._resource.global_revoke()
            for session in self._sessions.values():
                self._reducer(session).close()
            self._sessions.clear()

    def next_effect(self, session: ServingGatewaySessionV3) -> BootEffect | None:
        return self._reducer(self._session(session)).next_effect()

    def advance(self, session: ServingGatewaySessionV3, transport: BootTransport) -> ServingSessionState:
        return self._reducer(self._session(session)).advance(transport)

    def accept(self, session: ServingGatewaySessionV3, observation: BootObservation) -> ServingSessionState:
        return self._reducer(self._session(session)).accept(observation)

    def collector_acquire(
        self, session: ServingGatewaySessionV3, generation: CollectorGenerationV3
    ) -> bytes | None:
        claimed = self._session(session)
        return self._resource.collector_acquire(claimed.session_token, generation)

    def collector_finish(
        self, session: ServingGatewaySessionV3, generation: CollectorGenerationV3, permit_token: bytes
    ) -> None:
        claimed = self._session(session)
        self._resource.collector_finish(claimed.session_token, generation, permit_token)

    def collector_abort(
        self, session: ServingGatewaySessionV3, generation: CollectorGenerationV3, permit_token: bytes
    ) -> None:
        claimed = self._session(session)
        self._resource.collector_abort(claimed.session_token, generation, permit_token)
