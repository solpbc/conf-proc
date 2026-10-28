# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Ephemeral daily allowance and a bounded post-allowance cooldown."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import re
import threading
import time

JOURNAL_HEADER = "X-Sol-SPP-Journal"
POLICY_HEADER = "X-Sol-SPP-Allowance"
POLICY_LIMITS = {"v": (1, 1), "daily": (1, 10**12), "cooldown_ms": (1, 30_000),
                 "audio_per_second": (1, 10**6), "max_inflight": (1, 32)}


@dataclass(frozen=True)
class Policy:
    daily: int
    cooldown_ms: int
    audio_per_second: int
    max_inflight: int


@dataclass(frozen=True)
class Authorization:
    journal: str
    policy: Policy | None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate policy field")
        result[key] = value
    return result


def parse_authorization(headers) -> Authorization:
    journals = headers.get_all(JOURNAL_HEADER, [])
    policies = headers.get_all(POLICY_HEADER, [])
    if len(journals) != 1 or re.fullmatch(r"[A-Za-z0-9_-]{43}", journals[0]) is None:
        raise ValueError("invalid journal scope")
    if not policies:
        return Authorization(journals[0], None)
    if len(policies) != 1 or len(policies[0]) > 512:
        raise ValueError("invalid allowance policy")
    value = json.loads(policies[0], object_pairs_hook=_unique_object)
    if type(value) is not dict or value.keys() != POLICY_LIMITS.keys():
        raise ValueError("invalid allowance policy")
    for key, (low, high) in POLICY_LIMITS.items():
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValueError("invalid allowance policy")
    return Authorization(journals[0], Policy(**{k: value[k] for k in value if k != "v"}))


class OccupancyExceeded(Exception):
    pass


@dataclass
class _State:
    day: int
    used: int = 0
    active: int = 0
    completed_at: float | None = None


@dataclass
class Lease:
    key: bytes
    state: _State
    delay: float
    policy: Policy
    finished: bool = False


class Allowance:
    def __init__(self, clock=time.time, monotonic=time.monotonic):
        self._clock, self._monotonic = clock, monotonic
        self._day = int(clock() // 86400)
        self._key = os.urandom(32)
        self._states: dict[bytes, _State] = {}
        self._lock = threading.Lock()

    def _expire(self):
        day = int(self._clock() // 86400)
        if day <= self._day:
            return
        self._day = day
        for key, state in list(self._states.items()):
            if state.active:
                state.day, state.used, state.completed_at = day, 0, None
            else:
                del self._states[key]

    def expire(self):
        with self._lock:
            self._expire()

    def begin(self, authorization: Authorization) -> Lease | None:
        policy = authorization.policy
        if policy is None:
            return None
        key = hmac.new(self._key, authorization.journal.encode("ascii"), hashlib.sha256).digest()
        with self._lock:
            self._expire()
            state = self._states.setdefault(key, _State(self._day))
            slower = state.used >= policy.daily
            if state.active >= (1 if slower else policy.max_inflight):
                raise OccupancyExceeded("simultaneous occupancy exceeded")
            state.active += 1
            delay = 0.0
            if slower and state.completed_at is not None:
                delay = max(0.0, state.completed_at + policy.cooldown_ms / 1000 - self._monotonic())
            return Lease(key, state, delay, policy)

    def finish(self, lease: Lease | None, units: int, worked: bool):
        if lease is None:
            return
        with self._lock:
            if lease.finished:
                return
            self._expire()
            state = lease.state
            state.active -= 1
            if worked:
                state.used = min(10**15, state.used + max(0, units))
                state.completed_at = self._monotonic()
            lease.finished = True


def audio_units(milliseconds: int, policy: Policy) -> int:
    return (milliseconds * policy.audio_per_second + 999) // 1000
