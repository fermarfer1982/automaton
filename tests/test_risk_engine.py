from __future__ import annotations

import unittest
from dataclasses import replace

from trading_lab.config import RiskLimits
from trading_lab.domain import ActiveOrderSnapshot, PositionSnapshot, Side, TradeProposal
from trading_lab.risk_engine import RiskEngine
from tests.fakes import FakeMT5Adapter


def proposal(**overrides: object) -> TradeProposal:
    values: dict[str, object] = {
        "proposal_id": "proposal-001",
        "hypothesis_id": "hypothesis-001",
        "strategy_id": "emergent-research",
        "setup_id": "breakout-observation",
        "strategy_version": "0.1.0",
        "symbol": "XAUUSD",
        "side": Side.BUY,
        "volume": 0.05,
        "stop_loss": 2398.00,
        "take_profit": 2404.00,
        "magic_number": 26081101,
        "position_management": "SINGLE_ENTRY",
        "thesis": "Testable hypothesis with invalidation at the stop.",
        "session": "LONDON",
        "market_regime": "UNKNOWN",
    }
    values.update(overrides)
    return TradeProposal(**values)


class RiskEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = FakeMT5Adapter()
        self.limits = RiskLimits(
            max_risk_per_trade_fraction=0.0025,
            max_volume=0.10,
            max_spread_points=30.0,
            max_open_positions=1,
            max_symbol_exposure_lots=0.10,
            max_daily_loss_fraction=0.01,
            min_stop_distance_points=20,
            duplicate_window_seconds=300,
        )
        self.engine = RiskEngine(
            allowed_symbol="XAUUSD",
            required_magic_number=26081101,
            limits=self.limits,
        )

    def evaluate(self, item: TradeProposal, **kwargs: object):
        return self.engine.evaluate(
            proposal=item,
            account=self.adapter.account,
            market=self.adapter.symbol,
            positions=kwargs.get("positions", []),
            daily_realized_pnl=float(kwargs.get("daily_realized_pnl", 0.0)),
            duplicate=bool(kwargs.get("duplicate", False)),
            active_orders=kwargs.get("active_orders", []),
        )

    def test_accepts_bounded_single_entry_proposal(self) -> None:
        result = self.evaluate(proposal())
        self.assertTrue(result.allowed, result.failed_codes)
        self.assertAlmostEqual(result.estimated_risk_amount, 1.10)

    def test_rejects_symbol_or_magic_mismatch(self) -> None:
        wrong_symbol = self.evaluate(proposal(symbol="EURUSD"))
        wrong_magic = self.evaluate(proposal(magic_number=1))
        self.assertIn("SYMBOL_NOT_ALLOWED", wrong_symbol.failed_codes)
        self.assertIn("MAGIC_NUMBER_MISMATCH", wrong_magic.failed_codes)

    def test_rejects_missing_wrong_side_or_too_close_stop(self) -> None:
        missing = self.evaluate(proposal(stop_loss=None))
        wrong_side = self.evaluate(proposal(stop_loss=2401.0))
        too_close = self.evaluate(proposal(stop_loss=2400.10))
        self.assertIn("STOP_LOSS_REQUIRED", missing.failed_codes)
        self.assertIn("STOP_LOSS_WRONG_SIDE", wrong_side.failed_codes)
        self.assertIn("STOP_DISTANCE_TOO_SMALL", too_close.failed_codes)

    def test_rejects_excessive_spread_volume_and_risk(self) -> None:
        wide_market = replace(self.adapter.symbol, ask=2400.50)
        wide = self.engine.evaluate(
            proposal=proposal(), account=self.adapter.account, market=wide_market,
            positions=[], daily_realized_pnl=0.0, duplicate=False,
        )
        excessive_volume = self.evaluate(proposal(volume=0.11))
        excessive_risk = self.evaluate(proposal(volume=0.10, stop_loss=2350.0))
        self.assertIn("SPREAD_TOO_WIDE", wide.failed_codes)
        self.assertIn("VOLUME_LIMIT_EXCEEDED", excessive_volume.failed_codes)
        self.assertIn("RISK_PER_TRADE_EXCEEDED", excessive_risk.failed_codes)

    def test_rejects_non_aligned_broker_volume(self) -> None:
        result = self.evaluate(proposal(volume=0.015))
        self.assertIn("VOLUME_STEP_MISMATCH", result.failed_codes)

    def test_rejects_duplicate_daily_loss_and_existing_position(self) -> None:
        existing = PositionSnapshot(
            ticket=1, symbol="XAUUSD", side=Side.BUY, volume=0.02,
            price_open=2399.0, stop_loss=2397.0, profit=-5.0,
            magic_number=26081101,
        )
        duplicate = self.evaluate(proposal(), duplicate=True)
        daily_loss = self.evaluate(proposal(), daily_realized_pnl=-101.0)
        occupied = self.evaluate(proposal(), positions=[existing])
        self.assertIn("DUPLICATE_PROPOSAL", duplicate.failed_codes)
        self.assertIn("DAILY_LOSS_LIMIT_REACHED", daily_loss.failed_codes)
        self.assertIn("EXISTING_SYMBOL_POSITION", occupied.failed_codes)

    def test_rejects_martingale_grid_and_averaging_down_structurally(self) -> None:
        for management in ("MARTINGALE", "GRID", "AVERAGING_DOWN"):
            with self.subTest(management=management):
                result = self.evaluate(proposal(position_management=management))
                self.assertIn("POSITION_MANAGEMENT_FORBIDDEN", result.failed_codes)

    def test_rejects_stale_tick_and_any_pending_order(self) -> None:
        stale_market = replace(self.adapter.symbol, tick_time_msc=1)
        stale = self.engine.evaluate(
            proposal=proposal(), account=self.adapter.account, market=stale_market,
            positions=[], active_orders=[], daily_realized_pnl=0.0, duplicate=False,
        )
        pending = ActiveOrderSnapshot(ticket=99, symbol="XAUUSD", volume=0.01, magic_number=26081101)
        with_order = self.evaluate(proposal(), active_orders=[pending])
        self.assertIn("MARKET_TICK_STALE", stale.failed_codes)
        self.assertIn("ACTIVE_ORDERS_PRESENT", with_order.failed_codes)


if __name__ == "__main__":
    unittest.main()
