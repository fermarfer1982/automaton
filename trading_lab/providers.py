from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Protocol

from .domain import (
    AccountSnapshot,
    ActiveOrderSnapshot,
    CandleSnapshot,
    DealSnapshot,
    OrderCheckResult,
    OrderSendResult,
    PositionSnapshot,
    SymbolSnapshot,
)
from .mt5_adapter import MT5Adapter


class MarketDataProvider(Protocol):
    """Read-only broker observations consumed by guards and the application."""

    def account_snapshot(self) -> AccountSnapshot: ...
    def symbol_snapshot(self, symbol: str) -> SymbolSnapshot: ...
    def candles(self, symbol: str, timeframe: str, count: int) -> list[CandleSnapshot]: ...
    def positions(self) -> list[PositionSnapshot]: ...
    def active_orders(self) -> list[ActiveOrderSnapshot]: ...
    def daily_realized_pnl(self) -> float: ...
    def history(
        self,
        start: datetime,
        end: datetime,
        *,
        symbol: str | None = None,
        limit: int = 1000,
    ) -> list[DealSnapshot]: ...


class LiveMT5MarketDataProvider:
    """Read-only facade: consumers cannot reach MT5 execution methods through it."""

    def __init__(self, adapter: MT5Adapter) -> None:
        self._adapter = adapter

    def account_snapshot(self) -> AccountSnapshot:
        return self._adapter.account_snapshot()

    def symbol_snapshot(self, symbol: str) -> SymbolSnapshot:
        return self._adapter.symbol_snapshot(symbol)

    def candles(self, symbol: str, timeframe: str, count: int) -> list[CandleSnapshot]:
        return self._adapter.candles(symbol, timeframe, count)

    def positions(self) -> list[PositionSnapshot]:
        return self._adapter.positions()

    def active_orders(self) -> list[ActiveOrderSnapshot]:
        return self._adapter.active_orders()

    def daily_realized_pnl(self) -> float:
        return self._adapter.daily_realized_pnl()

    def history(
        self,
        start: datetime,
        end: datetime,
        *,
        symbol: str | None = None,
        limit: int = 1000,
    ) -> list[DealSnapshot]:
        return self._adapter.history(start, end, symbol=symbol, limit=limit)


class MT5ExecutionProvider(MT5Adapter):
    """Named protected live provider; raw sends remain implemented only by MT5Adapter."""


class ReplayMarketDataProvider:
    """Immutable deterministic provider for PAPER/replay research and tests."""

    def __init__(
        self,
        *,
        account: AccountSnapshot,
        symbols: Iterable[SymbolSnapshot],
        candles: Iterable[CandleSnapshot] = (),
        positions: Iterable[PositionSnapshot] = (),
        active_orders: Iterable[ActiveOrderSnapshot] = (),
        deals: Iterable[DealSnapshot] = (),
    ) -> None:
        self._account = account
        self._symbols = {item.symbol: item for item in symbols}
        self._candles = tuple(candles)
        self._positions = tuple(positions)
        self._active_orders = tuple(active_orders)
        self._deals = tuple(deals)

    def account_snapshot(self) -> AccountSnapshot:
        return self._account

    def symbol_snapshot(self, symbol: str) -> SymbolSnapshot:
        if symbol not in self._symbols:
            raise LookupError("Replay symbol is unavailable")
        return self._symbols[symbol]

    def candles(self, symbol: str, timeframe: str, count: int) -> list[CandleSnapshot]:
        selected = [
            item for item in self._candles
            if item.symbol == symbol and item.timeframe == timeframe
        ]
        return sorted(selected, key=lambda item: item.time_msc)[-count:]

    def positions(self) -> list[PositionSnapshot]:
        return list(self._positions)

    def active_orders(self) -> list[ActiveOrderSnapshot]:
        return list(self._active_orders)

    def daily_realized_pnl(self) -> float:
        return sum(item.net_pnl for item in self._deals)

    def history(
        self,
        start: datetime,
        end: datetime,
        *,
        symbol: str | None = None,
        limit: int = 1000,
    ) -> list[DealSnapshot]:
        start_msc = int(start.timestamp() * 1000)
        end_msc = int(end.timestamp() * 1000)
        return [
            item for item in self._deals
            if start_msc <= item.time_msc <= end_msc
            and (symbol is None or item.symbol == symbol)
        ][:limit]


class SimulatedExecutionProvider:
    """Deterministic non-MT5 provider for execution-engine contract tests."""

    def __init__(
        self,
        *,
        check_result: OrderCheckResult,
        send_result: OrderSendResult,
    ) -> None:
        self.check_result = check_result
        self.send_result = send_result
        self.checked_requests: list[dict[str, object]] = []
        self.sent_requests: list[dict[str, object]] = []

    def order_check(self, request: dict[str, object]) -> OrderCheckResult:
        self.checked_requests.append(dict(request))
        return self.check_result

    def order_send(self, request: dict[str, object]) -> OrderSendResult:
        self.sent_requests.append(dict(request))
        return self.send_result
