from __future__ import annotations

import tempfile
import unittest
import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from trading_lab.domain import Side, TradingMode
from trading_lab.research_store import (
    ExperienceOutcomeRecord,
    MarketExperienceRecord,
    ResearchStore,
    TradeResultRecord,
)
from tests.test_risk_engine import proposal


class ResearchStoreTests(unittest.TestCase):
    def test_records_structured_proposal_and_hypothesis_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(Path(directory) / "research.db")
            item = replace(
                proposal(), confidence=0.72, timeframe="M1",
                atr_at_entry=2.5, entry_spread_points=20.0,
                point_at_entry=0.01, stop_distance_points=220.0,
                initial_reward_risk=1.8, volatility_regime="NORMAL",
                data_quality="LIVE_TICK_AND_CLOSED_CANDLES",
            )
            store.record_proposal(
                item,
                mode=TradingMode.OBSERVE_ONLY,
                status="OBSERVED",
                fingerprint="abc",
                estimated_risk_amount=1.1,
            )
            row = store.get_proposal(item.proposal_id)
            self.assertEqual("emergent-research", row["strategy_id"])
            self.assertEqual("breakout-observation", row["setup_id"])
            self.assertEqual("0.1.0", row["strategy_version"])
            self.assertEqual("LONDON", row["session"])
            self.assertEqual("UNKNOWN", row["market_regime"])
            self.assertEqual(0.72, row["confidence"])
            self.assertEqual("M1", row["timeframe"])
            self.assertEqual(2.5, row["atr_at_entry"])
            self.assertEqual(220.0, row["stop_distance_points"])

    def test_computes_evidence_metrics_from_closed_trades(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(Path(directory) / "research.db")
            base = datetime(2026, 8, 1, tzinfo=UTC)
            outcomes = [
                ("t1", 100.0, 2.0, 2.5, -0.3),
                ("t2", -50.0, -1.0, 0.4, -1.2),
                ("t3", 50.0, 1.0, 1.4, -0.2),
                ("t4", -25.0, -0.5, 0.2, -0.8),
            ]
            for index, (trade_id, pnl, r_multiple, mfe_r, mae_r) in enumerate(outcomes):
                store.record_trade_result(
                    TradeResultRecord(
                        trade_id=trade_id,
                        proposal_id=f"p{index}",
                        hypothesis_id="h1",
                        strategy_id="adaptive",
                        setup_id="setup-a",
                        strategy_version="1.0.0",
                        session="LONDON",
                        market_regime="TREND",
                        symbol="XAUUSD",
                        side=Side.BUY,
                        volume=0.01,
                        entry_price=2400.0,
                        exit_price=2401.0,
                        initial_stop_loss=2399.0,
                        opened_at=base + timedelta(hours=index),
                        closed_at=base + timedelta(hours=index, minutes=30),
                        pnl=pnl,
                        r_multiple=r_multiple,
                        mfe_r=mfe_r,
                        mae_r=mae_r,
                        volatility_regime="NORMAL",
                    )
                )
            metrics = store.strategy_metrics("adaptive", "1.0.0")
            self.assertEqual(4, metrics.sample_size)
            self.assertAlmostEqual(75.0, metrics.total_pnl)
            self.assertAlmostEqual(0.375, metrics.expectancy_r)
            self.assertAlmostEqual(2.0, metrics.profit_factor)
            self.assertAlmostEqual(0.5, metrics.win_rate)
            self.assertAlmostEqual(50.0, metrics.max_drawdown)
            self.assertAlmostEqual(1.125, metrics.average_mfe_r)
            self.assertAlmostEqual(-0.625, metrics.average_mae_r)
            self.assertEqual(2, metrics.wins)
            self.assertEqual(2, metrics.losses)
            self.assertIsNotNone(metrics.expectancy_r_ci95_low)
            self.assertIsNotNone(metrics.expectancy_r_ci95_high)
            repeated = ResearchStore(Path(directory) / "research.db").strategy_metrics(
                "adaptive", "1.0.0"
            )
            self.assertEqual(
                (metrics.expectancy_r_ci95_low, metrics.expectancy_r_ci95_high),
                (repeated.expectancy_r_ci95_low, repeated.expectancy_r_ci95_high),
            )
            groups = store.grouped_metrics()
            london = next(
                item for item in groups
                if item["dimension"] == "session" and item["value"] == "LONDON"
            )
            self.assertEqual(4, london["sample_size"])
            self.assertIn("max_drawdown", london)
            volatility = next(
                item for item in groups
                if item["dimension"] == "volatility_regime"
                and item["value"] == "NORMAL"
            )
            self.assertEqual(4, volatility["sample_size"])

    def test_empty_sample_reports_no_statistical_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metrics = ResearchStore(Path(directory) / "research.db").strategy_metrics("missing", "1")
            self.assertEqual(0, metrics.sample_size)
            self.assertIsNone(metrics.expectancy_r)
            self.assertIsNone(metrics.profit_factor)
            self.assertFalse(metrics.evidence_sufficient)

    def test_daily_equity_start_and_peak_are_durable_in_utc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "research.db"
            store = ResearchStore(path)
            at = datetime(2026, 8, 11, 0, 5, tzinfo=UTC)
            first = store.update_daily_risk_state(
                currency="EUR", equity=10_000.0, balance=10_000.0, at=at,
            )
            store.update_daily_risk_state(
                currency="EUR", equity=10_050.0, balance=10_000.0,
                at=at + timedelta(hours=1),
            )
            restarted = ResearchStore(path)
            drawdown = restarted.update_daily_risk_state(
                currency="EUR", equity=9_990.0, balance=10_000.0,
                at=at + timedelta(hours=2),
            )
            self.assertEqual(10_000.0, first["start_equity"])
            self.assertEqual(10_000.0, drawdown["start_equity"])
            self.assertEqual(10_050.0, drawdown["peak_equity"])
            self.assertEqual(60.0, drawdown["drawdown"])

    def test_market_experiences_and_outcomes_are_append_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "research.db"
            store = ResearchStore(path)
            bar_time = datetime(2026, 8, 20, 11, 5, tzinfo=UTC)
            experience = MarketExperienceRecord(
                experience_id="experience-1",
                symbol="XAUUSD",
                timeframe="M1",
                bar_time_utc=bar_time,
                reference_price=4487.47,
                point=0.01,
                spread_points=28.0,
                session="LONDON",
                features={
                    "h1_bias": "BULLISH",
                    "m15_state": "PULLBACK",
                    "m5_state": "REBOUND",
                    "atr_m1": 2.03,
                },
            )
            store.record_market_experience(experience)

            stored = store.get_market_experience(
                experience.experience_id
            )
            self.assertIsNotNone(stored)
            self.assertEqual("XAUUSD", stored["symbol"])
            self.assertTrue(store.health())
            self.assertEqual(
                "BULLISH",
                stored["features"]["h1_bias"],
            )

            store.record_experience_outcome(
                ExperienceOutcomeRecord(
                    experience_id=experience.experience_id,
                    horizon_minutes=5,
                    future_bar_time_utc=(
                        bar_time + timedelta(minutes=5)
                    ),
                    future_close=4489.47,
                    window_high=4490.47,
                    window_low=4486.47,
                )
            )
            rows = store.experience_outcomes(
                experience.experience_id
            )
            self.assertEqual(1, len(rows))
            self.assertAlmostEqual(
                200.0,
                rows[0]["return_points"],
            )
            self.assertAlmostEqual(
                300.0,
                rows[0]["mfe_long_points"],
            )
            self.assertAlmostEqual(
                -100.0,
                rows[0]["mae_long_points"],
            )

            with self.assertRaises(FileExistsError):
                store.record_market_experience(experience)
            with self.assertRaises(FileExistsError):
                store.record_experience_outcome(
                    ExperienceOutcomeRecord(
                        experience_id=experience.experience_id,
                        horizon_minutes=5,
                        future_bar_time_utc=(
                            bar_time + timedelta(minutes=5)
                        ),
                        future_close=4489.47,
                        window_high=4490.47,
                        window_low=4486.47,
                    )
                )

            with closing(sqlite3.connect(path)) as connection:
                versions = {
                    int(row[0])
                    for row in connection.execute(
                        "SELECT version FROM research_schema"
                    )
                }
                self.assertIn(9, versions)
                self.assertIn(10, versions)
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute(
                        """
                        UPDATE market_experiences
                        SET reference_price = 1
                        """
                    )
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute(
                        "DELETE FROM experience_outcomes"
                    )

    def test_market_experience_versions_can_share_bar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(
                Path(directory) / "research.db"
            )
            bar_time = datetime(
                2026, 8, 20, 11, 5, tzinfo=UTC
            )

            for version in (1, 2):
                store.record_market_experience(
                    MarketExperienceRecord(
                        experience_id=f"same-bar-v{version}",
                        symbol="XAUUSD",
                        timeframe="M1",
                        bar_time_utc=bar_time,
                        reference_price=4487.47,
                        point=0.01,
                        spread_points=10.0,
                        session="LONDON",
                        features={
                            "feature_version": version
                        },
                        feature_version=version,
                    )
                )

            self.assertEqual(
                (bar_time, bar_time),
                store.market_experience_bounds(
                    feature_version=1
                ),
            )
            self.assertEqual(
                (bar_time, bar_time),
                store.market_experience_bounds(
                    feature_version=2
                ),
            )
            self.assertEqual(
                {bar_time.isoformat()},
                store.market_experience_bar_times(
                    bar_time,
                    bar_time,
                    feature_version=1,
                ),
            )
            self.assertEqual(
                {bar_time.isoformat()},
                store.market_experience_bar_times(
                    bar_time,
                    bar_time,
                    feature_version=2,
                ),
            )

            with self.assertRaises(FileExistsError):
                store.record_market_experience(
                    MarketExperienceRecord(
                        experience_id="duplicate-v2",
                        symbol="XAUUSD",
                        timeframe="M1",
                        bar_time_utc=bar_time,
                        reference_price=4487.47,
                        point=0.01,
                        spread_points=10.0,
                        session="LONDON",
                        features={
                            "feature_version": 2
                        },
                        feature_version=2,
                    )
                )

    def test_migrates_v9_market_feature_versions_to_v10(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "research.db"

            with closing(sqlite3.connect(path)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE research_schema (
                      version INTEGER PRIMARY KEY,
                      applied_at TEXT NOT NULL
                        DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO research_schema(version)
                    VALUES (9);

                    CREATE TABLE market_experiences (
                      experience_id TEXT PRIMARY KEY,
                      symbol TEXT NOT NULL
                        CHECK(symbol = 'XAUUSD'),
                      timeframe TEXT NOT NULL
                        CHECK(timeframe = 'M1'),
                      bar_time_utc TEXT NOT NULL,
                      reference_price REAL NOT NULL,
                      point REAL NOT NULL,
                      spread_points REAL NOT NULL,
                      session TEXT NOT NULL,
                      features_json TEXT NOT NULL,
                      created_at_utc TEXT NOT NULL,
                      UNIQUE(
                        symbol,
                        timeframe,
                        bar_time_utc
                      )
                    );

                    CREATE TABLE experience_outcomes (
                      experience_id TEXT NOT NULL,
                      horizon_minutes INTEGER NOT NULL,
                      future_bar_time_utc TEXT NOT NULL,
                      future_close REAL NOT NULL,
                      window_high REAL NOT NULL,
                      window_low REAL NOT NULL,
                      return_points REAL NOT NULL,
                      mfe_long_points REAL NOT NULL,
                      mae_long_points REAL NOT NULL,
                      created_at_utc TEXT NOT NULL,
                      PRIMARY KEY(
                        experience_id,
                        horizon_minutes
                      ),
                      FOREIGN KEY(experience_id)
                        REFERENCES market_experiences(
                          experience_id
                        )
                    );
                    """
                )

                base = datetime(
                    2026, 8, 20, 11, 5, tzinfo=UTC
                )
                for index, version in enumerate((1, 2)):
                    at = base + timedelta(minutes=index)
                    connection.execute(
                        """
                        INSERT INTO market_experiences(
                          experience_id,
                          symbol,
                          timeframe,
                          bar_time_utc,
                          reference_price,
                          point,
                          spread_points,
                          session,
                          features_json,
                          created_at_utc
                        ) VALUES (
                          ?, 'XAUUSD', 'M1', ?,
                          4487.47, 0.01, 10.0,
                          'LONDON', ?, ?
                        )
                        """,
                        (
                            f"legacy-v{version}",
                            at.isoformat(),
                            (
                                '{"feature_version":'
                                f'{version}'
                                '}'
                            ),
                            at.isoformat(),
                        ),
                    )
                connection.commit()

            store = ResearchStore(path)

            v1 = store.get_market_experience(
                "legacy-v1"
            )
            v2 = store.get_market_experience(
                "legacy-v2"
            )
            self.assertEqual(1, v1["feature_version"])
            self.assertEqual(2, v2["feature_version"])

            with closing(sqlite3.connect(path)) as connection:
                versions = {
                    int(row[0])
                    for row in connection.execute(
                        "SELECT version FROM research_schema"
                    )
                }
                self.assertIn(10, versions)

                columns = {
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(market_experiences)"
                    )
                }
                self.assertIn(
                    "feature_version",
                    columns,
                )

    def test_market_experience_coverage_queries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(
                Path(directory) / "research.db"
            )
            self.assertEqual(
                (None, None),
                store.market_experience_bounds(),
            )

            first = datetime(
                2026, 8, 20, 11, 5, tzinfo=UTC
            )
            last = first + timedelta(minutes=2)

            for index, bar_time in enumerate(
                (first, last),
                start=1,
            ):
                store.record_market_experience(
                    MarketExperienceRecord(
                        experience_id=f"coverage-{index}",
                        symbol="XAUUSD",
                        timeframe="M1",
                        bar_time_utc=bar_time,
                        reference_price=4487.0 + index,
                        point=0.01,
                        spread_points=10.0,
                        session="LONDON",
                        features={},
                    )
                )

            self.assertEqual(
                (first, last),
                store.market_experience_bounds(),
            )
            self.assertEqual(
                {
                    first.isoformat(),
                    last.isoformat(),
                },
                store.market_experience_bar_times(
                    first,
                    last,
                ),
            )

            with self.assertRaises(ValueError):
                store.market_experience_bar_times(
                    last,
                    first,
                )

    def test_market_experience_requires_m1_aligned_utc_bar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(
                Path(directory) / "research.db"
            )
            with self.assertRaisesRegex(
                ValueError,
                "align to a closed M1 bar",
            ):
                store.record_market_experience(
                    MarketExperienceRecord(
                        experience_id="experience-unaligned",
                        symbol="XAUUSD",
                        timeframe="M1",
                        bar_time_utc=datetime(
                            2026, 8, 20, 11, 5, 1, tzinfo=UTC
                        ),
                        reference_price=4487.47,
                        point=0.01,
                        spread_points=10.0,
                        session="LONDON",
                        features={},
                    )
                )

    def test_experience_outcome_requires_exact_horizon_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(
                Path(directory) / "research.db"
            )
            bar_time = datetime(
                2026, 8, 20, 11, 5, tzinfo=UTC
            )
            store.record_market_experience(
                MarketExperienceRecord(
                    experience_id="experience-2",
                    symbol="XAUUSD",
                    timeframe="M1",
                    bar_time_utc=bar_time,
                    reference_price=4487.47,
                    point=0.01,
                    spread_points=10.0,
                    session="LONDON",
                    features={},
                )
            )
            with self.assertRaisesRegex(
                ValueError,
                "does not match its horizon",
            ):
                store.record_experience_outcome(
                    ExperienceOutcomeRecord(
                        experience_id="experience-2",
                        horizon_minutes=15,
                        future_bar_time_utc=(
                            bar_time + timedelta(minutes=14)
                        ),
                        future_close=4488.0,
                        window_high=4489.0,
                        window_low=4486.0,
                    )
                )

    def test_hypotheses_and_closed_trade_evidence_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "research.db"
            store = ResearchStore(path)
            item = proposal()
            store.record_proposal(
                item, mode=TradingMode.OBSERVE_ONLY, status="OBSERVED",
                fingerprint="immutable", estimated_risk_amount=1.0,
            )
            with self.assertRaises(ValueError):
                store.record_proposal(
                    replace(item, thesis="changed thesis"),
                    mode=TradingMode.OBSERVE_ONLY, status="OBSERVED",
                    fingerprint="changed", estimated_risk_amount=1.0,
                )
            base = datetime(2026, 8, 1, tzinfo=UTC)
            store.record_trade_result(TradeResultRecord(
                trade_id="immutable-trade", proposal_id="p-immutable",
                hypothesis_id="h-immutable", strategy_id="s", setup_id="setup",
                strategy_version="1", session="ASIA", market_regime="RANGE",
                symbol="XAUUSD", side=Side.BUY, volume=0.01,
                entry_price=2400.0, exit_price=2401.0, initial_stop_loss=2399.0,
                opened_at=base, closed_at=base + timedelta(minutes=5),
                pnl=1.0, r_multiple=1.0, mfe_r=1.0, mae_r=-0.1,
            ))
            with closing(sqlite3.connect(path)) as connection:
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute("UPDATE trade_results SET pnl = 999")
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute("DELETE FROM hypotheses")


if __name__ == "__main__":
    unittest.main()
