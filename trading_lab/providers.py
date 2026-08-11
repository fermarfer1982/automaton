from __future__ import annotations

from typing import Protocol

class MarketDataProvider(Protocol):
    def account_snapshot(self): ...
    def symbol_snapshot(self, symbol: str): ...
    def candles(self, symbol: str, timeframe: str, count: int): ...
    def positions(self): ...
    def active_orders(self): ...
    def daily_realized_pnl(self) -> float: ...
class LiveMT5MarketDataProvider:
    """Read-only provider facade used by live mode and future replay substitution."""

    def __init__(self, adapter) -> None:
        self._adapter = adapter

    def account_snapshot(self):
        return self._adapter.account_snapshot()

    def symbol_snapshot(self, symbol: str):
        return self._adapter.symbol_snapshot(symbol)

    def candles(self, symbol: str, timeframe: str, count: int):
        return self._adapter.candles(symbol, timeframe, count)

    def positions(self):
        return self._adapter.positions()

    def active_orders(self):
        return self._adapter.active_orders()

    def daily_realized_pnl(self) -> float:
        return self._adapter.daily_realized_pnl()
