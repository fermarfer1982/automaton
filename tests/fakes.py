from __future__ import annotations

from dataclasses import replace
from time import time

from trading_lab.domain import (
    AccountKind,
    AccountSnapshot,
    CandleSnapshot,
    OrderCheckResult,
    OrderSendResult,
    PositionSnapshot,
    SymbolSnapshot,
)


class FakeMT5Adapter:
    def __init__(self) -> None:
        self.initialized = True
        self.account = AccountSnapshot(
            login=12345678,
            server="Broker-Demo",
            kind=AccountKind.DEMO,
            equity=10_000.0,
            balance=10_000.0,
            connected=True,
            trade_allowed=True,
            terminal_trade_allowed=True,
            currency="EUR",
            account_name="Authorized Demo",
        )
        self.symbol = SymbolSnapshot(
            symbol="XAUUSD",
            bid=2400.00,
            ask=2400.20,
            point=0.01,
            tick_size=0.01,
            tick_value=0.10,
            volume_min=0.01,
            volume_max=100.0,
            volume_step=0.01,
            trade_stops_level=10,
            visible=True,
            tick_time_msc=int(time() * 1000),
            trade_freeze_level=5,
            market_open=True,
        )
        self.open_positions: list[PositionSnapshot] = []
        self.open_orders = []
        self.realized_pnl_today = 0.0
        self.deals = []
        self.order_check_result = OrderCheckResult(ok=True, retcode=0, comment="ok")
        self.order_send_result = OrderSendResult(
            ok=True, retcode=10009, comment="done", order_id=42, deal_id=43
        )
        self.calls: list[str] = []

    def initialize(self) -> bool:
        self.calls.append("initialize")
        return self.initialized

    def shutdown(self) -> None:
        self.calls.append("shutdown")

    def account_snapshot(self) -> AccountSnapshot:
        self.calls.append("account_snapshot")
        return self.account

    def symbol_snapshot(self, symbol: str) -> SymbolSnapshot:
        self.calls.append("symbol_snapshot")
        if symbol != self.symbol.symbol:
            return replace(self.symbol, symbol=symbol, visible=False)
        return self.symbol

    def candles(self, symbol: str, timeframe: str, count: int):
        self.calls.append("candles")
        now = int(time() // 60 * 60 * 1000) - 60_000
        return [
            CandleSnapshot(
                symbol=symbol, timeframe=timeframe, time_msc=now - (count - index) * 60_000,
                open=2400.0, high=2401.0, low=2399.0, close=2400.5,
                tick_volume=100, spread=20,
            )
            for index in range(count)
        ]

    def positions(self) -> list[PositionSnapshot]:
        self.calls.append("positions")
        return list(self.open_positions)

    def active_orders(self):
        self.calls.append("active_orders")
        return list(self.open_orders)

    def daily_realized_pnl(self) -> float:
        self.calls.append("daily_realized_pnl")
        return self.realized_pnl_today

    def history(self, start, end, *, symbol=None, limit=1000):
        self.calls.append("history")
        values = [item for item in self.deals if symbol is None or item.symbol == symbol]
        return values[:limit]

    def order_calc_profit(
        self,
        side,
        symbol: str,
        volume: float,
        price_open: float,
        price_close: float,
    ) -> float:
        self.calls.append("order_calc_profit")
        if symbol != "XAUUSD":
            raise ValueError("unsupported symbol")
        return -abs(price_open - price_close) / self.symbol.tick_size * self.symbol.tick_value * volume

    def order_check(self, request: dict[str, object]) -> OrderCheckResult:
        self.calls.append("order_check")
        return self.order_check_result

    def order_send(self, request: dict[str, object]) -> OrderSendResult:
        self.calls.append("order_send")
        return self.order_send_result
