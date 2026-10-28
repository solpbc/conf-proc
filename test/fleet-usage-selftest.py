#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fleet_usage import BAND_EDGES, FleetUsage
from allowance import parse_authorization
from email.message import Message
from usage_tally import ChatTally, UsageWalker


def stamp(value):
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp()


class FleetTests(unittest.TestCase):
    def setUp(self):
        self.now = stamp("2028-01-01T12:00:00")
        self.fleet = FleetUsage(clock=lambda: self.now)

    def advance(self, value):
        self.now = stamp(value)
        return self.fleet.snapshot()

    def day(self, counts):
        for band, count in enumerate(counts):
            for index in range(count):
                total = (1, BAND_EDGES[0], BAND_EDGES[1])[band]
                self.fleet.record(f"label-{band}-{index}", total, 0, 0)

    def test_partial_start_day_is_discarded(self):
        self.day((5, 5, 0))
        self.advance("2028-01-02T00:00:00")
        self.assertEqual(self.advance("2028-02-01T00:00:00")["histogram"],
                         {"month": 202801, "released": False, "bands": [0, 0, 0], "counted_days": 0})

    def test_floors_positive_twins_and_exact_edges(self):
        self.advance("2028-01-02T00:00:00")
        self.day((5, 4, 0))  # Nine never releases.
        self.advance("2028-01-03T00:00:00")
        self.day((5, 5, 0))
        self.advance("2028-01-04T00:00:00")
        self.day((4, 0, 6))
        self.advance("2028-01-05T00:00:00")
        self.assertEqual(self.fleet.snapshot()["histogram"]["month"], 0)
        released = self.advance("2028-02-01T00:00:00")["histogram"]
        self.assertEqual(released, {"month": 202801, "released": True,
                                    "bands": [5, 5, 6], "counted_days": 2})
        self.day((10, 0, 0))
        self.assertEqual(self.advance("2028-02-02T00:00:00")["histogram"], released)

    def test_idle_rollover_erases_daily_link(self):
        self.advance("2028-01-02T00:00:00")
        self.fleet.record("journal", 1, 0, 0)
        previous = set(self.fleet._daily)
        self.advance("2028-01-03T00:00:00")
        self.assertEqual(self.fleet._daily, {})
        self.fleet.record("journal", 1, 0, 0)
        self.assertFalse(previous.intersection(self.fleet._daily))
        self.assertNotIn("journal", json.dumps(self.fleet.snapshot()))

    def test_leap_day_and_skipped_month(self):
        self.advance("2028-02-28T00:00:00")
        self.advance("2028-02-29T00:00:00")
        self.day((5, 0, 5))
        self.assertEqual(self.advance("2028-03-01T00:00:00")["histogram"]["bands"], [5, 0, 5])
        self.assertEqual(self.advance("2028-05-01T00:00:00")["histogram"],
                         {"month": 202804, "released": False, "bands": [0, 0, 0], "counted_days": 0})

    def test_backwards_day_stops_series(self):
        self.advance("2028-01-02T00:00:00")
        self.day((5, 5, 0))
        self.advance("2028-01-03T00:00:00")
        self.advance("2028-01-02T00:00:00")
        self.day((5, 5, 0))
        self.assertFalse(self.advance("2028-02-01T00:00:00")["histogram"]["released"])
        self.assertEqual(self.fleet._daily, {})

    def test_restart_cannot_release_prior_process(self):
        self.advance("2028-01-02T00:00:00")
        self.day((5, 5, 0))
        self.advance("2028-01-03T00:00:00")
        self.fleet = FleetUsage(clock=lambda: self.now)
        self.assertFalse(self.advance("2028-02-01T00:00:00")["histogram"]["released"])

    def test_missing_cache_preserves_ledger_with_matched_denominator(self):
        tally = ChatTally(fleet=self.fleet)
        for cached in (2, None, -1, True, 11):
            walker = UsageWalker()
            walker.feed(json.dumps({"usage": {"prompt_tokens": 10, "completion_tokens": 3,
                                                "prompt_tokens_details": {"cached_tokens": cached}}}).encode())
            tally.commit_response("label", walker, False)
        self.assertEqual(self.fleet.snapshot()["counters"]["as_of_day"], 0)
        self.assertEqual(self.advance("2028-01-02T00:00:00")["counters"], {
            "prompt_tokens_total": 50, "prompt_tokens_cached": 2,
            "prompt_tokens_cache_measured": 10, "cache_unavailable_responses": 4, "as_of_day": 20280102})
        self.assertIn(' 50\n', tally.render())

    def test_counters_frozen_until_midnight_and_epoch_changes_on_restart(self):
        self.fleet.record("journal", 10, 3, 4)
        frozen = self.advance("2028-01-02T00:00:00")
        for index in range(10):
            self.now += 60
            self.fleet.record("journal", 10, 3, 4)
            self.assertEqual(self.fleet.snapshot()["counters"], frozen["counters"])
        self.assertEqual(self.advance("2028-01-03T00:00:00")["counters"]["prompt_tokens_total"], 110)
        restarted = FleetUsage(clock=lambda: self.now).snapshot()
        self.assertNotEqual(restarted["accounting_boot"], frozen["accounting_boot"])
        self.assertEqual(restarted["counters"]["as_of_day"], 0)
        self.assertEqual(restarted["counters"]["prompt_tokens_total"], 0)

    def test_only_top_level_usage_and_last_stream_sample_count(self):
        usage = {"prompt_tokens": 10, "completion_tokens": 3,
                 "prompt_tokens_details": {"cached_tokens": 4}}
        for width in (1, 7, 1024):
            walker = UsageWalker()
            body = ("data: " + json.dumps({"choices": [{"usage": usage, "content": json.dumps({"usage": usage})}]}) +
                    "\n\ndata: " + json.dumps({"usage": usage}) + "\n\ndata: " + json.dumps({"usage": usage})).encode()
            for start in range(0, len(body), width):
                walker.feed(body[start:start+width])
            self.assertEqual(walker.last, (10, 3))
            self.assertEqual(walker.last_cached, 4)
            self.fleet = FleetUsage(clock=lambda: self.now)
            tally = ChatTally(fleet=self.fleet)
            tally.commit_response("label", walker, False)
            self.now += 86400
            self.assertEqual(tally.fleet.snapshot()["counters"]["prompt_tokens_total"], 10)
            negative = UsageWalker()
            negative.feed(json.dumps({"choices": [{"usage": usage}]}).encode())
            self.assertIsNone(negative.last)

    def test_first_record_after_midnight_excluded_and_rollback_never_republishes(self):
        self.fleet.record("journal", 10, 0, 3)
        self.now = stamp("2028-01-02T00:00:01")
        self.fleet.record("journal", 200, 0, 100)
        frozen = self.fleet.snapshot()["counters"]
        self.assertEqual(frozen["prompt_tokens_total"], 10)
        self.assertEqual(frozen["as_of_day"], 20280102)
        self.now = stamp("2028-01-01T23:59:00")
        self.fleet.record("journal", 1000, 0, 500)
        self.assertEqual(self.advance("2028-01-02T00:00:01")["counters"], frozen)
        self.assertEqual(self.advance("2028-01-03T00:00:01")["counters"], frozen)

    def test_credential_remints_cannot_inflate_journal_privacy_floor(self):
        self.advance("2028-01-02T00:00:00")
        tally = ChatTally(fleet=self.fleet)
        for journal in range(5):
            for _remint in range(2):
                headers = Message()
                headers["X-Sol-SPP-Journal"] = str(journal) * 43
                authorization = parse_authorization(headers)
                walker = UsageWalker()
                walker.feed(b'{"usage":{"prompt_tokens":1,"completion_tokens":1}}')
                tally.commit_response(tally.label_for(authorization.journal), walker, False)
        self.assertEqual(len(self.fleet._daily), 5)
        self.advance("2028-01-03T00:00:00")
        self.assertFalse(self.advance("2028-02-01T00:00:00")["histogram"]["released"])


if __name__ == "__main__":
    unittest.main()
