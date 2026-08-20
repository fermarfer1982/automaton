from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from trading_lab.market_experience_collector import (
    MarketExperienceCollector,
)
from trading_lab.research_store import (
    MarketExperienceRecord,
    ResearchStore,
)


def candle(time: datetime, price: float, *, spread: int = 12):
    return {
        "symbol": "XAUUSD",
        "timeframe": "M1",
        "time_msc": int(time.timestamp() * 1000),
        "open": price - 0.02,
        "high": price + 0.05,
        "low": price - 0.05,
        "close": price,
        "spread": spread,
    }


def series(
    *,
    start: datetime,
    count: int,
    step_minutes: int,
    start_price: float,
    increment: float,
    timeframe: str,
):
    output = []
    for index in range(count):
        price = start_price + increment * index
        item = candle(
            start + timedelta(minutes=step_minutes * index),
            price,
        )
        item["timeframe"] = timeframe
        output.append(item)
    return output


class FakeObservation:
    def __init__(self, rows_by_timeframe):
        self.rows = rows_by_timeframe
        self.candle_requests = []

    def symbol_state(self, symbol):
        return {
            "symbol": symbol,
            "bid": 4500.00,
            "ask": 4500.12,
            "point": 0.01,
        }

    def candles(self, symbol, timeframe, count):
        self.candle_requests.append(timeframe)
        rows = self.rows[timeframe][-count:]
        return {
            "symbol": symbol,
            "timeframe": timeframe,
            "count": len(rows),
            "candles": rows,
            "execution_capable": False,
        }


class MarketExperienceCollectorTests(unittest.TestCase):
    def build_rows(self):
        start = datetime(2026, 8, 20, 8, 0, tzinfo=UTC)
        return {
            "M1": series(
                start=start,
                count=181,
                step_minutes=1,
                start_price=4480.0,
                increment=0.10,
                timeframe="M1",
            ),
            "M5": series(
                start=start - timedelta(hours=12),
                count=200,
                step_minutes=5,
                start_price=4460.0,
                increment=0.05,
                timeframe="M5",
            ),
            "M15": series(
                start=start - timedelta(days=2),
                count=200,
                step_minutes=15,
                start_price=4440.0,
                increment=0.08,
                timeframe="M15",
            ),
            "H1": series(
                start=start - timedelta(days=8),
                count=200,
                step_minutes=60,
                start_price=4400.0,
                increment=0.20,
                timeframe="H1",
            ),
        }

    def test_collects_latest_closed_m1_idempotently(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(Path(directory) / "research.db")
            rows = self.build_rows()
            observation = FakeObservation(rows)
            collector = MarketExperienceCollector(
                observation,
                store,
            )
            now = datetime(2026, 8, 20, 11, 1, tzinfo=UTC)

            first = collector.collect_once(now=now)
            observation.candle_requests.clear()
            second = collector.collect_once(now=now)

            self.assertEqual(
                ["M1"],
                observation.candle_requests,
            )
            self.assertTrue(first.experience_created)
            self.assertFalse(second.experience_created)
            self.assertEqual(
                first.experience_id,
                second.experience_id,
            )

            saved = store.get_market_experience(
                first.experience_id
            )
            self.assertIsNotNone(saved)
            self.assertEqual("XAUUSD", saved["symbol"])
            self.assertEqual("M1", saved["timeframe"])
            self.assertEqual(
                12.0,
                saved["spread_points"],
            )
            features = saved["features"]
            self.assertTrue(features["closed_bar_only"])
            self.assertTrue(features["no_lookahead"])
            self.assertEqual(
                "CLOSED_M1",
                features["spread_source"],
            )
            self.assertIn(
                "H1",
                features["timeframes"],
            )
            self.assertIsNotNone(
                features["timeframes"]["M1"]["ema20"]
            )
            self.assertIsNotNone(
                features["timeframes"]["M1"]["rsi14"]
            )

    def test_completes_5_15_60_minute_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(Path(directory) / "research.db")
            rows = self.build_rows()
            base_index = 120
            base_row = rows["M1"][base_index]
            base_time = datetime.fromtimestamp(
                base_row["time_msc"] / 1000,
                UTC,
            )
            store.record_market_experience(
                MarketExperienceRecord(
                    experience_id="old-experience",
                    symbol="XAUUSD",
                    timeframe="M1",
                    bar_time_utc=base_time,
                    reference_price=float(base_row["close"]),
                    point=0.01,
                    spread_points=12.0,
                    session="LONDON",
                    features={"seed": True},
                )
            )

            collector = MarketExperienceCollector(
                FakeObservation(rows),
                store,
            )
            result = collector.collect_once(
                now=datetime(2026, 8, 20, 11, 1, tzinfo=UTC)
            )

            self.assertGreaterEqual(
                result.outcomes_created,
                3,
            )
            self.assertGreater(
                result.backfill_experiences_created,
                0,
            )
            outcomes = store.experience_outcomes(
                "old-experience"
            )
            self.assertEqual(
                [5, 15, 60],
                [
                    row["horizon_minutes"]
                    for row in outcomes
                ],
            )
            by_horizon = {
                row["horizon_minutes"]: row
                for row in outcomes
            }
            self.assertAlmostEqual(
                50.0,
                by_horizon[5]["return_points"],
                places=6,
            )
            self.assertAlmostEqual(
                55.0,
                by_horizon[5]["mfe_long_points"],
                places=6,
            )

    def test_backfills_internal_gap_without_m1_lookahead(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(Path(directory) / "research.db")
            rows = self.build_rows()
            observation = FakeObservation(rows)
            collector = MarketExperienceCollector(
                observation,
                store,
            )

            base = datetime(
                2026, 8, 20, 10, 55, tzinfo=UTC
            )
            for minute in (0, 4):
                bar_time = base + timedelta(minutes=minute)
                row = next(
                    item for item in rows["M1"]
                    if int(item["time_msc"])
                    == int(bar_time.timestamp() * 1000)
                )
                store.record_market_experience(
                    MarketExperienceRecord(
                        experience_id=collector._experience_id(
                            int(row["time_msc"])
                        ),
                        symbol="XAUUSD",
                        timeframe="M1",
                        bar_time_utc=bar_time,
                        reference_price=float(row["close"]),
                        point=0.01,
                        spread_points=float(row["spread"]),
                        session="LONDON",
                        features={"seed": True},
                    )
                )

            future_spike_time = int(
                datetime(
                    2026, 8, 20, 10, 57, tzinfo=UTC
                ).timestamp() * 1000
            )
            for row in rows["M1"]:
                if int(row["time_msc"]) == future_spike_time:
                    row["high"] = 9000.0

            result = collector.collect_once(
                now=datetime(
                    2026, 8, 20, 11, 1, tzinfo=UTC
                )
            )

            self.assertTrue(result.experience_created)
            self.assertEqual(
                3,
                result.backfill_experiences_created,
            )

            expected_times = {
                (
                    base + timedelta(minutes=minute)
                ).isoformat()
                for minute in range(6)
            }
            actual_times = store.market_experience_bar_times(
                base,
                base + timedelta(minutes=5),
            )
            self.assertEqual(
                expected_times,
                actual_times,
            )

            target = datetime(
                2026, 8, 20, 10, 56, tzinfo=UTC
            )
            target_id = collector._experience_id(
                int(target.timestamp() * 1000)
            )
            saved = store.get_market_experience(
                target_id
            )
            self.assertIsNotNone(saved)
            m1_features = saved["features"]["timeframes"]["M1"]
            self.assertEqual(
                target.isoformat(),
                m1_features["bar_time_utc"],
            )
            self.assertLess(
                m1_features["rolling_high_20"],
                9000.0,
            )

    def test_does_not_create_outcome_across_missing_m1_bar(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(Path(directory) / "research.db")
            rows = self.build_rows()
            base_index = 120
            base_row = rows["M1"][base_index]
            base_time = datetime.fromtimestamp(
                base_row["time_msc"] / 1000,
                UTC,
            )
            store.record_market_experience(
                MarketExperienceRecord(
                    experience_id="gap-experience",
                    symbol="XAUUSD",
                    timeframe="M1",
                    bar_time_utc=base_time,
                    reference_price=float(base_row["close"]),
                    point=0.01,
                    spread_points=12.0,
                    session="LONDON",
                    features={},
                )
            )

            missing_time = (
                int(base_row["time_msc"]) + 3 * 60_000
            )
            rows["M1"] = [
                row for row in rows["M1"]
                if int(row["time_msc"]) != missing_time
            ]

            collector = MarketExperienceCollector(
                FakeObservation(rows),
                store,
            )
            collector.collect_once(
                now=datetime(2026, 8, 20, 11, 1, tzinfo=UTC)
            )

            outcomes = store.experience_outcomes(
                "gap-experience"
            )
            self.assertEqual([], outcomes)


if __name__ == "__main__":
    unittest.main()
