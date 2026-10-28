#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Deterministic allowance clock, scope, policy and privacy invariants."""
from email.message import Message
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from allowance import Allowance, Authorization, OccupancyExceeded, Policy, audio_units, parse_authorization
from fleet_usage import FleetUsage
from usage_tally import ChatTally, UsageWalker

POLICY = {"v": 1, "daily": 100, "cooldown_ms": 5000, "audio_per_second": 10, "max_inflight": 2}
SCOPE = "J" * 43


def headers(policy=POLICY, journal=SCOPE):
    result = Message()
    if journal is not None:
        result["X-Sol-SPP-Journal"] = journal
    if policy is not None:
        result["X-Sol-SPP-Allowance"] = json.dumps(policy)
    return result


class AllowanceTests(unittest.TestCase):
    def setUp(self):
        self.wall, self.mono = 100 * 86400, 1000.0
        self.manager = Allowance(clock=lambda: self.wall, monotonic=lambda: self.mono)
        self.auth = parse_authorization(headers())

    def test_off_has_no_enforcement_state(self):
        auth = parse_authorization(headers(None))
        self.assertIsNone(self.manager.begin(auth))
        self.assertEqual(self.manager._states, {})

    def test_policy_and_scope_are_exact_and_bounded(self):
        for bad in (None, "short", "!" * 43, "A" * 44):
            with self.assertRaises(ValueError):
                parse_authorization(headers(journal=bad))
        for key in POLICY:
            for bad in (-1, 0, True, 1.5, "1", 10**20):
                value = {**POLICY, key: bad}
                with self.assertRaises(ValueError):
                    parse_authorization(headers(value))
        for policy in ({**POLICY, "owner": "secret"}, [], None):
            if policy is None:
                continue
            with self.assertRaises(ValueError):
                parse_authorization(headers(policy))
        for name in ("X-Sol-SPP-Journal", "X-Sol-SPP-Allowance"):
            value = headers()
            value[name] = value[name]
            with self.assertRaises(ValueError):
                parse_authorization(value)
        value = headers(None)
        for raw in ('{"v":1,"v":1}', 'a' * 513, '{'):
            value.replace_header("X-Sol-SPP-Journal", SCOPE)
            if "X-Sol-SPP-Allowance" in value:
                del value["X-Sol-SPP-Allowance"]
            value["X-Sol-SPP-Allowance"] = raw
            with self.assertRaises(ValueError):
                parse_authorization(value)

    def test_full_speed_then_repeated_bounded_floor_without_cutoff(self):
        lease = self.manager.begin(self.auth)
        self.assertEqual(lease.delay, 0)
        self.manager.finish(lease, 99, True)
        lease = self.manager.begin(self.auth)
        self.assertEqual(lease.delay, 0)
        self.manager.finish(lease, 1, True)
        for _ in range(5):
            lease = self.manager.begin(self.auth)
            self.assertEqual(lease.delay, 5)
            self.mono += lease.delay
            self.manager.finish(lease, 1_000_000, True)

    def test_channels_share_scope_but_other_journal_does_not(self):
        first = self.manager.begin(self.auth)
        second = self.manager.begin(parse_authorization(headers()))
        with self.assertRaises(OccupancyExceeded):
            self.manager.begin(self.auth)
        other = self.manager.begin(parse_authorization(headers(journal="K" * 43)))
        self.assertEqual(other.delay, 0)
        self.manager.finish(first, 100, True)
        with self.assertRaises(OccupancyExceeded):
            self.manager.begin(self.auth)
        self.manager.finish(second, 100, True)
        slower = self.manager.begin(self.auth)
        with self.assertRaises(OccupancyExceeded):
            self.manager.begin(self.auth)
        self.manager.finish(slower, 0, False)
        self.assertEqual(self.manager.begin(self.auth).delay, 5)

    def test_same_day_idle_retains_usage_prior_day_expires(self):
        lease = self.manager.begin(self.auth)
        self.manager.finish(lease, 100, True)
        self.wall += 3600
        self.manager.expire()
        self.assertEqual(len(self.manager._states), 1)
        lease = self.manager.begin(self.auth)
        self.assertEqual(lease.delay, 5)
        self.manager.finish(lease, 0, False)
        self.wall += 86400
        self.manager.expire()
        self.assertEqual(self.manager._states, {})
        self.assertEqual(self.manager.begin(self.auth).delay, 0)

    def test_midnight_keeps_active_occupancy_and_charges_completion_day(self):
        lease = self.manager.begin(self.auth)
        self.wall += 86400
        self.manager.expire()
        self.assertEqual(lease.state.active, 1)
        self.manager.finish(lease, 100, True)
        self.assertEqual(lease.state.used, 100)
        self.assertEqual(self.manager.begin(self.auth).delay, 5)

    def test_wall_clock_rollback_cannot_reset_or_extend_monotonic_pace(self):
        lease = self.manager.begin(self.auth)
        self.manager.finish(lease, 100, True)
        self.wall -= 86400
        self.mono += 3
        lease = self.manager.begin(self.auth)
        self.assertEqual(lease.delay, 2)
        self.manager.finish(lease, 0, False)
        self.wall += 86400
        self.mono += 3
        lease = self.manager.begin(self.auth)
        self.assertEqual(lease.delay, 0)
        self.assertEqual(lease.state.used, 100)

    def test_finish_is_once_and_cancel_does_not_charge_or_move_cooldown(self):
        lease = self.manager.begin(self.auth)
        self.manager.finish(lease, 100, True)
        self.manager.finish(lease, 100, True)
        self.assertEqual(lease.state.active, 0)
        self.assertEqual(lease.state.used, 100)
        cancelled = self.manager.begin(self.auth)
        self.mono += 1
        self.manager.finish(cancelled, 1000, False)
        self.assertEqual(self.manager.begin(self.auth).delay, 4)

    def test_audio_rounding_and_shared_budget(self):
        self.assertEqual(audio_units(1, self.auth.policy), 1)
        self.assertEqual(audio_units(1001, self.auth.policy), 11)
        lease = self.manager.begin(self.auth)
        self.manager.finish(lease, 90, True)
        lease = self.manager.begin(self.auth)
        self.manager.finish(lease, audio_units(1000, lease.policy), True)
        self.assertEqual(self.manager.begin(self.auth).delay, 5)

    def test_restart_unlinks_and_enforcement_never_enters_observations(self):
        lease = self.manager.begin(self.auth)
        self.manager.finish(lease, 262144, True)
        fleet = FleetUsage(clock=lambda: self.wall)
        tally = ChatTally(fleet=fleet)
        walker = UsageWalker()
        walker.feed(b'{"usage":{"prompt_tokens":10,"completion_tokens":1}}')
        tally.commit_response(tally.label_for(self.auth.journal), walker, False)
        observations = tally.render() + json.dumps(fleet.snapshot())
        self.assertNotIn(self.auth.journal, observations)
        self.assertNotIn(lease.key.hex(), observations)
        for key in ("cooldown", "remaining", "allowance", "max_inflight", "262144"):
            self.assertNotIn(key, observations)
        restarted = Allowance(clock=lambda: self.wall, monotonic=lambda: self.mono)
        fresh = restarted.begin(self.auth)
        self.assertNotEqual(fresh.key, lease.key)
        self.assertEqual(fresh.delay, 0)
        self.assertEqual(fresh.state.used, 0)


if __name__ == "__main__":
    unittest.main()
