from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from trading_lab.domain import Side, TradingMode
from trading_lab.research_store import ResearchStore, TradeResultRecord
from tests.test_risk_engine import proposal


class ResearchStoreTests(unittest.TestCase):
    def test_records_structured_proposal_and_hypothesis_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(Path(directory) / "research.db")
            item = proposal()
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


if __name__ == "__main__":
    unittest.main()
