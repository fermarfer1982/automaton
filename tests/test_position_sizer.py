from __future__ import annotations

import unittest
from dataclasses import replace

from trading_lab.config import RiskLimits
from trading_lab.domain import Side
from trading_lab.position_sizer import PositionSizer
from tests.fakes import FakeMT5Adapter


class PositionSizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = FakeMT5Adapter()
        self.limits = RiskLimits(
            max_risk_per_trade_fraction=0.0025,
            max_volume=0.01,
            max_spread_points=30.0,
            max_open_positions=1,
            max_symbol_exposure_lots=0.01,
            max_daily_loss_fraction=0.01,
            min_stop_distance_points=20,
            duplicate_window_seconds=300,
            max_risk_per_trade_amount=10.0,
        )
        self.sizer = PositionSizer(self.adapter, self.limits)

    def test_gateway_calculates_and_caps_volume(self) -> None:
        result = self.sizer.size(
            side=Side.BUY,
            requested_risk_amount=10.0,
            stop_loss=2398.0,
            account=self.adapter.account,
            market=self.adapter.symbol,
        )
        self.assertTrue(result.ok, result)
        self.assertEqual(0.01, result.volume)
        self.assertAlmostEqual(0.22, result.estimated_risk_amount)

    def test_rejects_requested_risk_above_dual_cap(self) -> None:
        account = replace(self.adapter.account, equity=1_000.0)
        result = self.sizer.size(
            side=Side.BUY,
            requested_risk_amount=3.0,
            stop_loss=2398.0,
            account=account,
            market=self.adapter.symbol,
        )
        self.assertFalse(result.ok)
        self.assertEqual("DENIED_RISK_LIMIT", result.failed_code)
        self.assertEqual(2.5, result.allowed_risk_amount)

    def test_rejects_when_safe_volume_is_below_broker_minimum(self) -> None:
        market = replace(self.adapter.symbol, volume_min=0.1, volume_step=0.1)
        result = self.sizer.size(
            side=Side.SELL,
            requested_risk_amount=1.0,
            stop_loss=2500.0,
            account=self.adapter.account,
            market=market,
        )
        self.assertFalse(result.ok)
        self.assertEqual("DENIED_VOLUME_BELOW_MINIMUM", result.failed_code)

    def test_fails_closed_when_mt5_profit_calculation_fails(self) -> None:
        self.adapter.order_calc_profit = lambda *args: float("nan")  # type: ignore[method-assign]
        result = self.sizer.size(
            side=Side.BUY,
            requested_risk_amount=1.0,
            stop_loss=2398.0,
            account=self.adapter.account,
            market=self.adapter.symbol,
        )
        self.assertFalse(result.ok)
        self.assertEqual("DENIED_PROFIT_CALCULATION", result.failed_code)


if __name__ == "__main__":
    unittest.main()
