from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from trading_lab.domain import DealSnapshot, OrderCheckResult, OrderSendResult, Side
from trading_lab.providers import (
    LiveMT5MarketDataProvider,
    ReplayMarketDataProvider,
    SimulatedExecutionProvider,
)

from tests.fakes import FakeMT5Adapter


class ProviderBoundaryTests(unittest.TestCase):
    def test_live_market_facade_exposes_no_execution_methods(self) -> None:
        provider = LiveMT5MarketDataProvider(FakeMT5Adapter())
        self.assertFalse(hasattr(provider, "order_check"))
        self.assertFalse(hasattr(provider, "order_send"))
        self.assertEqual("XAUUSD", provider.symbol_snapshot("XAUUSD").symbol)

    def test_replay_filters_history_and_never_executes(self) -> None:
        fake = FakeMT5Adapter()
        now = datetime.now(UTC)
        deal = DealSnapshot(
            ticket=1, order_id=2, position_id=3, symbol="XAUUSD", side=Side.BUY,
            entry="OUT", volume=0.01, price=2400.0, profit=2.0,
            commission=-0.1, swap=0.0, fee=0.0,
            time_msc=int(now.timestamp() * 1000), magic_number=23400001,
        )
        replay = ReplayMarketDataProvider(
            account=fake.account, symbols=[fake.symbol], deals=[deal]
        )
        result = replay.history(now - timedelta(minutes=1), now + timedelta(minutes=1))
        self.assertEqual([deal], result)
        self.assertAlmostEqual(1.9, replay.daily_realized_pnl())
        self.assertFalse(hasattr(replay, "order_send"))

    def test_simulated_execution_records_contract_calls(self) -> None:
        provider = SimulatedExecutionProvider(
            check_result=OrderCheckResult(True, 0, "ok"),
            send_result=OrderSendResult(True, 10009, "done", 1, 2),
        )
        request = {"action": "DEAL"}
        provider.order_check(request)
        provider.order_send(request)
        self.assertEqual([request], provider.checked_requests)
        self.assertEqual([request], provider.sent_requests)


if __name__ == "__main__":
    unittest.main()
