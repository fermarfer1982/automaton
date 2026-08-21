from __future__ import annotations

import unittest
from datetime import UTC, datetime

from trading_lab.market_experience_collector import (
    CollectorResult,
)
from trading_lab.market_experience_loop import (
    MarketExperienceLoop,
)


NOW = datetime(2026, 8, 20, 14, 31, tzinfo=UTC)


class FakeCollector:
    def __init__(self, results):
        self.results = list(results)
        self.calls = 0

    def collect_once(self, *, now=None):
        self.calls += 1
        item = self.results.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class MarketExperienceLoopTests(unittest.TestCase):
    def test_accumulates_persisted_evidence(self):
        collector = FakeCollector([
            CollectorResult(
                experience_id="e1",
                bar_time_utc="2026-08-20T14:30:00+00:00",
                experience_created=True,
                outcomes_created=0,
                backfill_experiences_created=2,
            ),
            CollectorResult(
                experience_id="e1",
                bar_time_utc="2026-08-20T14:30:00+00:00",
                experience_created=False,
                outcomes_created=1,
            ),
        ])
        loop = MarketExperienceLoop(
            collector,
            now_provider=lambda: NOW,
        )

        loop.run_cycle()
        loop.run_cycle()

        state = loop.snapshot()
        self.assertEqual(2, state.cycles)
        self.assertEqual(3, state.experiences_created)
        self.assertEqual(1, state.outcomes_created)
        self.assertEqual(0, state.consecutive_errors)
        self.assertIsNone(state.last_error)

    def test_cycle_error_is_recorded_and_does_not_escape(self):
        collector = FakeCollector([
            RuntimeError("temporary read-only failure"),
            CollectorResult(
                experience_id="e2",
                bar_time_utc="2026-08-20T14:31:00+00:00",
                experience_created=True,
                outcomes_created=0,
            ),
        ])
        loop = MarketExperienceLoop(
            collector,
            now_provider=lambda: NOW,
        )

        self.assertIsNone(loop.run_cycle())
        failed = loop.snapshot()
        self.assertEqual(1, failed.consecutive_errors)
        self.assertIn(
            "temporary read-only failure",
            failed.last_error,
        )

        self.assertIsNotNone(loop.run_cycle())
        recovered = loop.snapshot()
        self.assertEqual(0, recovered.consecutive_errors)
        self.assertIsNone(recovered.last_error)
        self.assertEqual(1, recovered.experiences_created)

    def test_health_reports_loop_state(self):
        collector = FakeCollector([
            CollectorResult(
                experience_id="e-health",
                bar_time_utc=(
                    "2026-08-20T14:30:00+00:00"
                ),
                experience_created=True,
                outcomes_created=2,
                backfill_experiences_created=1,
            ),
        ])

        loop = MarketExperienceLoop(
            collector,
            now_provider=lambda: NOW,
        )

        initial = loop.health()
        self.assertTrue(initial["running"])
        self.assertEqual(0, initial["cycles"])
        self.assertEqual(
            0,
            initial["consecutive_errors"],
        )

        loop.run_cycle()

        healthy = loop.health()
        self.assertTrue(healthy["running"])
        self.assertEqual(1, healthy["cycles"])
        self.assertEqual(
            2,
            healthy["experiences_created"],
        )
        self.assertEqual(
            2,
            healthy["outcomes_created"],
        )
        self.assertEqual(
            "2026-08-20T14:30:00+00:00",
            healthy["last_bar_time_utc"],
        )
        self.assertEqual(
            NOW.isoformat(),
            healthy["last_success_at_utc"],
        )

        loop.stop()
        stopped = loop.health()
        self.assertFalse(stopped["running"])

    def test_interval_is_bounded(self):
        collector = FakeCollector([])

        for value in (0.5, 61.0):
            with self.assertRaises(ValueError):
                MarketExperienceLoop(
                    collector,
                    interval_seconds=value,
                )


if __name__ == "__main__":
    unittest.main()
