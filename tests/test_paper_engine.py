from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from trading_lab.audit import HashChainAuditLog
from trading_lab.paper_engine import PaperEngine
from trading_lab.research_store import ResearchStore
from tests.fakes import FakeMT5Adapter
from tests.test_risk_engine import proposal


class PaperEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        directory = Path(self.temp.name)
        self.store = ResearchStore(directory / "research.db")
        self.audit = HashChainAuditLog(directory / "audit.jsonl")
        self.engine = PaperEngine(self.store, self.audit)
        self.adapter = FakeMT5Adapter()
        self.opened_at = datetime(2026, 8, 11, 10, 0, tzinfo=UTC)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_opens_persistent_virtual_position(self) -> None:
        item = proposal()
        self.engine.open(item, self.adapter.symbol, opened_at=self.opened_at)
        positions = self.engine.position_snapshots()
        self.assertEqual(1, len(positions))
        self.assertEqual("XAUUSD", positions[0].symbol)
        self.assertEqual(0.05, positions[0].volume)
        self.assertEqual(1, len(self.store.list_open_paper_positions()))

    def test_updates_excursions_and_closes_take_profit(self) -> None:
        item = proposal(take_profit=2404.0)
        self.engine.open(item, self.adapter.symbol, opened_at=self.opened_at)
        mid_market = replace(
            self.adapter.symbol, bid=2401.30, ask=2401.50,
            tick_time_msc=int((self.opened_at + timedelta(minutes=1)).timestamp() * 1000),
        )
        self.assertEqual([], self.engine.reconcile(mid_market, at=self.opened_at + timedelta(minutes=1)))
        open_row = self.store.list_open_paper_positions()[0]
        self.assertAlmostEqual(0.5, open_row["mfe_r"])
        self.assertAlmostEqual(0.0, open_row["mae_r"])

        take_profit_market = replace(
            self.adapter.symbol, bid=2404.20, ask=2404.40,
            tick_time_msc=int((self.opened_at + timedelta(minutes=2)).timestamp() * 1000),
        )
        closed = self.engine.reconcile(take_profit_market, at=self.opened_at + timedelta(minutes=2))
        self.assertEqual(1, len(closed))
        self.assertAlmostEqual(2.0, closed[0].pnl)
        self.assertAlmostEqual(4.0 / 2.2, closed[0].r_multiple)
        self.assertEqual([], self.store.list_open_paper_positions())
        metrics = self.store.strategy_metrics("emergent-research", "0.1.0")
        self.assertEqual(1, metrics.sample_size)
        self.assertFalse(metrics.evidence_sufficient)

    def test_closes_stop_with_negative_r_and_survives_engine_restart(self) -> None:
        item = proposal()
        self.engine.open(item, self.adapter.symbol, opened_at=self.opened_at)
        restarted = PaperEngine(self.store, self.audit)
        stop_market = replace(
            self.adapter.symbol, bid=2397.80, ask=2398.00,
            tick_time_msc=int((self.opened_at + timedelta(minutes=3)).timestamp() * 1000),
        )
        closed = restarted.reconcile(stop_market, at=self.opened_at + timedelta(minutes=3))
        self.assertEqual(1, len(closed))
        self.assertLess(closed[0].pnl, 0)
        self.assertLess(closed[0].r_multiple, -1.0)
        self.assertLessEqual(closed[0].mae_r, closed[0].r_multiple)
        self.assertAlmostEqual(closed[0].pnl, self.store.paper_daily_realized_pnl())


if __name__ == "__main__":
    unittest.main()
