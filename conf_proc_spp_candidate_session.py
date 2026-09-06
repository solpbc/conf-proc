#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Physical socket ownership for the isolated candidate's bounded sessions.

The PID1 event loop calls wait() instead of an unbounded epoll wait. The gateway
receives duplicates of connected sockets; shutdown on the retained description
interrupts its idle, receiving and sending operations. This module consumes a
previously appraised lease deadline; it does not appraise or mint leases.
"""
from __future__ import annotations

import errno
import os
import selectors
import socket
import threading
import time
from dataclasses import dataclass, field

from conf_proc_spp_boot_v3_resource import ServingResourceReducerV3

MAX_LEASE_NS = 60_000_000_000
MAX_SESSION_SOCKETS = 3  # client, one upstream, one private verifier channel


@dataclass
class _OwnedSession:
    deadline_ns: int
    sockets: dict[tuple[int, int], socket.socket] = field(default_factory=dict)


class CandidateSessionOwner:
    """One controller thread owns both the existing permit ledger and sockets."""

    def __init__(self, ledger: ServingResourceReducerV3) -> None:
        self.ledger = ledger
        self._thread = threading.get_ident()
        self._sessions: dict[bytes, _OwnedSession] = {}
        self._selector = selectors.DefaultSelector()
        self._closed = False

    def _check_owner(self) -> None:
        if self._thread != threading.get_ident() or self._closed:
            raise RuntimeError("candidate session owner unavailable")

    def adopt(self, token: bytes, client: socket.socket, deadline_ns: int) -> None:
        """Retain a duplicate only after the controller has appraised this lease."""
        self._check_owner()
        now = time.monotonic_ns()
        if (type(deadline_ns) is not int or not now < deadline_ns <= now + MAX_LEASE_NS
                or token not in self.ledger.sessions or token in self._sessions):
            raise ValueError("invalid candidate lease or session")
        self._sessions[token] = _OwnedSession(deadline_ns)
        try:
            self.attach(token, client)
        except BaseException:
            self._sessions.pop(token, None)
            raise

    def attach(self, token: bytes, connected: socket.socket) -> None:
        """Pin a connected socket before passing its descriptor to the gateway."""
        self._check_owner()
        session = self._sessions[token]
        if time.monotonic_ns() >= session.deadline_ns:
            self.release(token)
            raise TimeoutError("candidate lease expired")
        if len(session.sockets) >= MAX_SESSION_SOCKETS:
            raise ValueError("candidate socket limit")
        if (connected.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or connected.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            raise ValueError("candidate requires a connected stream")
        connected.getpeername()  # Reject unconnected sockets before duplicating.
        pinned = connected.dup()
        try:
            info = os.fstat(pinned.fileno())
            identity = (info.st_dev, info.st_ino)
            if any(identity in item.sockets for item in self._sessions.values()):
                raise ValueError("socket already owned")
            session.sockets[identity] = pinned
        except BaseException:
            pinned.close()
            raise

    def detach(self, token: bytes, connected: socket.socket) -> None:
        """Close a completed upstream before granting the next request's FD."""
        self._check_owner()
        info = os.fstat(connected.fileno())
        identity = (info.st_dev, info.st_ino)
        pinned = self._sessions[token].sockets.pop(identity)
        try:
            pinned.shutdown(socket.SHUT_RDWR)
        except OSError as exc:
            if exc.errno not in (errno.ENOTCONN, errno.EINVAL):
                self.revoke_all()
                raise
        finally:
            pinned.close()

    def release(self, token: bytes) -> None:
        self._check_owner()
        session = self._sessions.pop(token)
        error = None
        for pinned in session.sockets.values():
            try:
                pinned.shutdown(socket.SHUT_RDWR)
            except OSError as exc:
                if exc.errno not in (errno.ENOTCONN, errno.EINVAL):
                    error = exc
            finally:
                pinned.close()
        # A live collector permit cannot be silently abandoned. An inconsistent
        # release revokes every session and all grants through the existing ledger.
        try:
            self.ledger.session_release(token)
        except BaseException:
            self.revoke_all()
            raise
        if error is not None:
            self.revoke_all()
            raise error

    def expire(self) -> None:
        self._check_owner()
        now = time.monotonic_ns()
        for token, session in tuple(self._sessions.items()):
            if now >= session.deadline_ns:
                self.release(token)

    def register(self, fd: int, events: int, data: object) -> None:
        self._check_owner()
        self._selector.register(fd, events, data)

    def unregister(self, fd: int) -> None:
        self._check_owner()
        self._selector.unregister(fd)

    def wait(self, maximum_seconds: float = 1.0) -> list:
        """Expire before and after IO readiness, including continuously ready IO."""
        self._check_owner()
        if not 0 <= maximum_seconds <= 1.0:
            raise ValueError("unbounded candidate controller wait")
        self.expire()
        timeout = maximum_seconds
        if self._sessions:
            next_ns = min(s.deadline_ns for s in self._sessions.values())
            timeout = min(timeout, max(0, next_ns - time.monotonic_ns()) / 1e9)
        events = self._selector.select(timeout)
        self.expire()
        return events

    def revoke_all(self) -> None:
        self._check_owner()
        errors = []
        sessions, self._sessions = self._sessions, {}
        for session in sessions.values():
            for pinned in session.sockets.values():
                try:
                    pinned.shutdown(socket.SHUT_RDWR)
                except OSError as exc:
                    if exc.errno not in (errno.ENOTCONN, errno.EINVAL):
                        errors.append(exc)
                finally:
                    pinned.close()
        self.ledger.global_revoke()
        if errors:
            raise errors[0]

    def close(self) -> None:
        self._check_owner()
        try:
            self.revoke_all()
        finally:
            self._selector.close()
            self._closed = True
