#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""PID1 resource authority and session composition for SPP boot v3."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import secrets
import threading
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
from conf_proc_spp_reasons_v3 import ApplianceErrorV3, CP_BOOT_V3_BINDING, CP_BOOT_V3_RESOURCE_REDUCER


def _reject(message: str) -> None:
    raise ApplianceErrorV3(CP_BOOT_V3_RESOURCE_REDUCER, message)


def _binding_reject(message: str) -> None:
    raise ApplianceErrorV3(CP_BOOT_V3_BINDING, message)


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


class ServingAuthorityWrapperV3:
    """Thin PID1-side composition of resource and gateway session authorities."""

    def __init__(
        self,
        *,
        admission_capability: object = None,
        on_global_fault: Callable[[], None] | None = None,
    ) -> None:
        from conf_proc_spp_boot_v3 import _claim_serving_wrapper_construction_v3

        _claim_serving_wrapper_construction_v3(admission_capability, self)
        self._admission_capability = admission_capability
        try:
            self._resource = ServingResourceReducerV3()
            self._sessions: dict[bytes, ServingGatewaySessionV3] = {}
            self._reducers: dict[bytes, ServingSessionReducer] = {}
            self._on_global_fault = on_global_fault
            self._operation_lock = threading.RLock()
            self._cleanup_condition = threading.Condition(threading.RLock())
            self._cleanup_phase = "active"
            self._cleanup_owner_thread_id: int | None = None
            self._cleanup_error: BaseException | None = None
            self._revoke_count = 0
        except BaseException:
            from conf_proc_spp_boot_v3 import _abandon_serving_wrapper_construction_v3

            _abandon_serving_wrapper_construction_v3(admission_capability, self)
            raise

    def _verify_admission_v3(self, *, allow_complete: bool = False) -> None:
        from conf_proc_spp_boot_v3 import _verify_serving_wrapper_v3

        _verify_serving_wrapper_v3(
            getattr(self, "_admission_capability", None),
            self,
            allow_complete=allow_complete,
        )

    def __copy__(self) -> "ServingAuthorityWrapperV3":
        clone = object.__new__(ServingAuthorityWrapperV3)
        clone.__dict__.update(self.__dict__)
        return clone

    def __deepcopy__(self, memo: dict[int, object]) -> "ServingAuthorityWrapperV3":
        del memo
        return self.__copy__()

    def _guard_active_v3(self) -> None:
        self._verify_admission_v3()
        thread_id = threading.get_ident()
        with self._cleanup_condition:
            while self._cleanup_phase == "cleaning":
                if self._cleanup_owner_thread_id == thread_id:
                    _binding_reject("serving authority is cleaning")
                self._cleanup_condition.wait()
            if self._cleanup_phase != "active":
                _binding_reject("serving authority is revoked")

    @contextmanager
    def _active_operation_v3(self):
        self._guard_active_v3()
        with self._operation_lock:
            self._guard_active_v3()
            yield

    def _session(self, session: object) -> ServingGatewaySessionV3:
        if type(session) is not ServingGatewaySessionV3:
            _reject("gateway session is invalid")
        if self._sessions.get(session.session_token) is not session:
            _reject("gateway session is unknown")
        return session

    def open_session(
        self, session_transport: BootTransport, close_callback: object
    ) -> ServingGatewaySessionV3 | None:
        with self._active_operation_v3():
            token = self._resource.session_acquire()
            if token is None:
                return None
            try:
                reducer = ServingSessionReducer(session_transport, close_callback)
                session = ServingGatewaySessionV3(token)
            except BaseException:
                self._resource.session_release(token)
                raise
            self._sessions[token] = session
            self._reducers[token] = reducer
            return session

    def begin_request(
        self,
        session: ServingGatewaySessionV3,
        *,
        path: str,
        body_length: int,
        opaque_handle: object,
    ) -> tuple[bytes, bytes, bytes, int] | RequestRejectReasonV3:
        with self._active_operation_v3():
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

    def _reducer(self, session: ServingGatewaySessionV3) -> ServingSessionReducer:
        reducer = self._reducers.get(session.session_token)
        if type(reducer) is not ServingSessionReducer:
            _reject("session reducer is invalid")
        return reducer

    def work_begin(self, session: ServingGatewaySessionV3, route_work_permit: bytes) -> None:
        with self._active_operation_v3():
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
        with self._active_operation_v3():
            claimed = self._session(session)
            if type(outcome) is not WorkFinishOutcomeV3:
                _reject("work finish outcome is invalid")
            self._resource.work_finish(claimed.session_token, route_work_permit)

    def request_release(self, session: ServingGatewaySessionV3, request_permit: bytes) -> None:
        with self._active_operation_v3():
            claimed = self._session(session)
            state = self._reducer(claimed).state
            if state not in (ServingSessionState.REQUEST_CLOSED, ServingSessionState.SESSION_CLOSED):
                _reject("session request is not closed")
            self._resource.request_release(claimed.session_token, request_permit)

    def session_release(self, session: ServingGatewaySessionV3) -> tuple[int, bytes | None, bytes | None, bytes | None]:
        with self._active_operation_v3():
            claimed = self._session(session)
            result = self._resource.session_release(claimed.session_token)
            reducer = self._reducer(claimed)
            del self._sessions[claimed.session_token]
            del self._reducers[claimed.session_token]
            reducer.close()
            return result

    def global_revoke(self) -> None:
        self._verify_admission_v3(allow_complete=True)
        thread_id = threading.get_ident()
        reducers: tuple[ServingSessionReducer, ...] = ()
        error: BaseException | None = None
        cleanup_owner = False
        with self._operation_lock:
            with self._cleanup_condition:
                if self._cleanup_phase == "complete":
                    error = self._cleanup_error
                elif self._cleanup_phase == "cleaning":
                    if self._cleanup_owner_thread_id == thread_id:
                        return
                    while self._cleanup_phase == "cleaning":
                        self._cleanup_condition.wait()
                    error = self._cleanup_error
                else:
                    cleanup_owner = True
                    self._cleanup_phase = "cleaning"
                    self._cleanup_owner_thread_id = thread_id
                    self._revoke_count += 1
                    reducers = tuple(self._reducers.values())
                    self._sessions.clear()
                    self._reducers.clear()
                    try:
                        self._resource.global_revoke()
                    except BaseException as caught:
                        error = caught
            if not cleanup_owner:
                if error is not None:
                    raise error
                return
        # No wrapper or registry lock is held while invoking user callbacks.
        try:
            if self._on_global_fault is not None:
                self._on_global_fault()
        except BaseException as caught:
            error = caught
        for reducer in reducers:
            try:
                reducer.close()
            except BaseException as caught:
                if error is None:
                    error = caught
        with self._cleanup_condition:
            self._cleanup_error = error
            self._cleanup_phase = "complete"
            self._cleanup_owner_thread_id = None
            self._cleanup_condition.notify_all()
        from conf_proc_spp_boot_v3 import _retire_serving_admission_v3

        _retire_serving_admission_v3(self._admission_capability, self)
        if error is not None:
            raise error

    def next_effect(self, session: ServingGatewaySessionV3) -> BootEffect | None:
        with self._active_operation_v3():
            return self._reducer(self._session(session)).next_effect()

    def advance(self, session: ServingGatewaySessionV3, transport: BootTransport) -> ServingSessionState:
        with self._active_operation_v3():
            return self._reducer(self._session(session)).advance(transport)

    def accept(self, session: ServingGatewaySessionV3, observation: BootObservation) -> ServingSessionState:
        with self._active_operation_v3():
            return self._reducer(self._session(session)).accept(observation)

    def collector_acquire(
        self, session: ServingGatewaySessionV3, generation: CollectorGenerationV3
    ) -> bytes | None:
        with self._active_operation_v3():
            claimed = self._session(session)
            return self._resource.collector_acquire(claimed.session_token, generation)

    def collector_finish(
        self, session: ServingGatewaySessionV3, generation: CollectorGenerationV3, permit_token: bytes
    ) -> None:
        with self._active_operation_v3():
            claimed = self._session(session)
            self._resource.collector_finish(claimed.session_token, generation, permit_token)

    def collector_abort(
        self, session: ServingGatewaySessionV3, generation: CollectorGenerationV3, permit_token: bytes
    ) -> None:
        with self._active_operation_v3():
            claimed = self._session(session)
            self._resource.collector_abort(claimed.session_token, generation, permit_token)
