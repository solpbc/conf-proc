# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fleet cache measurements and a suppressed, closed-month distribution."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import threading
import time
from typing import Callable

BAND_EDGES = (2_000_000, 6_000_000)
DAY_SECONDS = 86400


def _month(day: int) -> int:
    date = datetime.fromtimestamp(day * DAY_SECONDS, timezone.utc)
    return date.year * 100 + date.month


def _previous_month(day: int) -> int:
    date = datetime.fromtimestamp(day * DAY_SECONDS, timezone.utc)
    previous = date.replace(day=1) - timedelta(days=1)
    return previous.year * 100 + previous.month


class FleetUsage:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._day = int(clock() // DAY_SECONDS)
        self._whole_day = False
        self._clock_invalid = False
        self._salt = os.urandom(32)
        self._daily: dict[bytes, int] = {}
        self._bands = [0, 0, 0]
        self._counted_days = 0
        self._released = {"month": 0, "released": False, "bands": [0, 0, 0], "counted_days": 0}
        self._prompt = 0
        self._cached = 0
        self._measured_prompt = 0
        self._unavailable = 0
        self._accounting_boot = os.urandom(16).hex()
        self._frozen_counters = {"prompt_tokens_total": 0, "prompt_tokens_cached": 0,
                                 "prompt_tokens_cache_measured": 0, "cache_unavailable_responses": 0,
                                 "as_of_day": 0}

    def _roll(self) -> None:
        day = int(self._clock() // DAY_SECONDS)
        if self._clock_invalid or day == self._day:
            return
        if day < self._day:
            # A repeated calendar interval cannot contribute a second release.
            # Keep fleet counters, but stop this process's histogram series.
            self._clock_invalid = True
            self._daily.clear()
            self._salt = os.urandom(32)
            self._bands = [0, 0, 0]
            self._counted_days = 0
            self._released = {"month": 0, "released": False, "bands": [0, 0, 0], "counted_days": 0}
            return
        self._frozen_counters = {
            "prompt_tokens_total": self._prompt,
            "prompt_tokens_cached": self._cached,
            "prompt_tokens_cache_measured": self._measured_prompt,
            "cache_unavailable_responses": self._unavailable,
            "as_of_day": int(datetime.fromtimestamp(day * DAY_SECONDS, timezone.utc).strftime("%Y%m%d")),
        }
        adjacent = day == self._day + 1
        if adjacent and self._whole_day and len(self._daily) >= 10:
            counts = [0, 0, 0]
            for value in self._daily.values():
                band = sum(value >= edge for edge in BAND_EDGES)
                counts[band] += 1
            for index, count in enumerate(counts):
                if count >= 5:
                    self._bands[index] += count
            self._counted_days += 1
        if _month(day) != _month(self._day):
            previous = _previous_month(day)
            covered = _month(self._day) == previous
            counted = self._counted_days if covered else 0
            self._released = {
                "month": previous,
                "released": counted > 0,
                "bands": self._bands[:] if covered else [0, 0, 0],
                "counted_days": counted,
            }
            self._bands = [0, 0, 0]
            self._counted_days = 0
        self._daily.clear()
        self._salt = os.urandom(32)
        self._whole_day = adjacent
        self._day = day

    def record(self, label: str, prompt: int, completion: int, cached: int | None) -> None:
        with self._lock:
            self._roll()
            self._prompt += prompt
            if type(cached) is int and 0 <= cached <= prompt:
                self._cached += cached
                self._measured_prompt += prompt
            else:
                self._unavailable += 1
            total = prompt + completion
            if total > 0 and not self._clock_invalid:
                daily_label = hmac.new(self._salt, label.encode("ascii"), hashlib.sha256).digest()
                self._daily[daily_label] = self._daily.get(daily_label, 0) + total

    def snapshot(self) -> dict:
        # The independent reporter calls this even when there is no traffic.
        with self._lock:
            self._roll()
            return {
                "accounting_boot": self._accounting_boot,
                "counters": self._frozen_counters.copy(),
                "histogram": {**self._released, "bands": self._released["bands"][:]},
            }
