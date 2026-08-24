from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from trading_lab.market_experience_collector import MarketExperienceCollector
from trading_lab.research_store import MarketExperienceRecord, ResearchStore


class PendingSpyStore:
    def __init__(self) -> None:
        self.pending_kwargs = None

    def pending_market_experiences(self, **kwargs):
        self.pending_kwargs = kwargs
        return []


class MarketOutcomePendingWindowTests(unittest.TestCase):
    def test_store_can_bound_pending_rows_and_order_newest_first(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(Path(directory) / "research.db")
            base = datetime(2026, 8, 24, 6, 0, tzinfo=UTC)

            for index in range(4):
                at = base + timedelta(minutes=index)
                store.record_market_experience(
                    MarketExperienceRecord(
                        experience_id=f"exp-{index}",
                        symbol="XAUUSD",
                        timeframe="M1",
                        bar_time_utc=at,
                        reference_price=4500.0 + index,
                        point=0.01,
                        spread_points=10.0,
                        session="LONDON",
                        features={"feature_version": 2},
                        feature_version=2,
                    )
                )

            default_rows = store.pending_market_experiences(
                feature_version=2,
            )
            self.assertEqual(
                ["exp-0", "exp-1", "exp-2", "exp-3"],
                [row["experience_id"] for row in default_rows],
            )

            bounded = store.pending_market_experiences(
                feature_version=2,
                start_utc=base + timedelta(minutes=1),
                end_utc=base + timedelta(minutes=3),
                newest_first=True,
            )
            self.assertEqual(
                ["exp-3", "exp-2", "exp-1"],
                [row["experience_id"] for row in bounded],
            )

            with self.assertRaises(ValueError):
                store.pending_market_experiences(
                    feature_version=2,
                    start_utc=base + timedelta(minutes=3),
                    end_utc=base + timedelta(minutes=1),
                )

    def test_collector_requests_available_window_newest_first(self):
        store = PendingSpyStore()
        collector = MarketExperienceCollector(None, store)
        start = datetime(2026, 8, 24, 6, 0, tzinfo=UTC)
        rows = []
        for minute in range(3):
            at = start + timedelta(minutes=minute)
            rows.append({
                "time_msc": int(at.timestamp() * 1000),
                "open": 4500.0,
                "high": 4501.0,
                "low": 4499.0,
                "close": 4500.5,
            })

        created = collector._complete_outcomes(rows)

        self.assertEqual(0, created)
        self.assertEqual(1000, store.pending_kwargs["limit"])
        self.assertEqual(2, store.pending_kwargs["feature_version"])
        self.assertEqual(start, store.pending_kwargs["start_utc"])
        self.assertEqual(
            start + timedelta(minutes=2),
            store.pending_kwargs["end_utc"],
        )
        self.assertIs(True, store.pending_kwargs["newest_first"])


if __name__ == "__main__":
    unittest.main()
