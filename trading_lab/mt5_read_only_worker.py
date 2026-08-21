from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from .domain import (
    AccountSnapshot,
    ActiveOrderSnapshot,
    CandleSnapshot,
    DealSnapshot,
    PositionSnapshot,
    SymbolSnapshot,
)
from .mt5_read_only_data import MT5ReadOnlyDataError
from .mt5_read_only_protocol import (
    ReadOnlyRequest,
    ReadOnlyResponse,
)


class MT5ReadOnlyWorkerAdapter(Protocol):
    def account_snapshot(self) -> AccountSnapshot:
        ...

    def symbol_snapshot(
        self,
        symbol: str,
    ) -> SymbolSnapshot:
        ...

    def candles(
        self,
        symbol: str,
        timeframe: str,
        count: int,
        *,
        start_pos: int = 1,
    ) -> list[CandleSnapshot]:
        ...

    def positions(
        self,
    ) -> list[PositionSnapshot]:
        ...

    def active_orders(
        self,
    ) -> list[ActiveOrderSnapshot]:
        ...

    def history(
        self,
        start: datetime,
        end: datetime,
        *,
        symbol: str | None,
        limit: int,
    ) -> list[DealSnapshot]:
        ...

    def daily_realized_pnl(
        self,
    ) -> float:
        ...


def _account_result(
    snapshot: AccountSnapshot,
) -> dict[str, Any]:
    return {
        "login": snapshot.login,
        "server": snapshot.server,
        "kind": snapshot.kind.value,
        "equity": snapshot.equity,
        "balance": snapshot.balance,
        "connected": snapshot.connected,
        "trade_allowed": snapshot.trade_allowed,
        "terminal_trade_allowed": (
            snapshot.terminal_trade_allowed
        ),
        "currency": snapshot.currency,
        "account_name": snapshot.account_name,
    }


def _symbol_result(
    snapshot: SymbolSnapshot,
) -> dict[str, Any]:
    return {
        "symbol": snapshot.symbol,
        "bid": snapshot.bid,
        "ask": snapshot.ask,
        "point": snapshot.point,
        "tick_size": snapshot.tick_size,
        "tick_value": snapshot.tick_value,
        "volume_min": snapshot.volume_min,
        "volume_max": snapshot.volume_max,
        "volume_step": snapshot.volume_step,
        "trade_stops_level": snapshot.trade_stops_level,
        "trade_freeze_level": snapshot.trade_freeze_level,
        "visible": snapshot.visible,
        "tick_time_msc": snapshot.tick_time_msc,
        "market_open": snapshot.market_open,
        "trade_mode": snapshot.trade_mode,
    }


def _candle_result(
    snapshot: CandleSnapshot,
) -> dict[str, Any]:
    return {
        "symbol": snapshot.symbol,
        "timeframe": snapshot.timeframe,
        "time_msc": snapshot.time_msc,
        "open": snapshot.open,
        "high": snapshot.high,
        "low": snapshot.low,
        "close": snapshot.close,
        "tick_volume": snapshot.tick_volume,
        "spread": snapshot.spread,
    }


def _position_result(
    snapshot: PositionSnapshot,
) -> dict[str, Any]:
    return {
        "ticket": snapshot.ticket,
        "symbol": snapshot.symbol,
        "side": snapshot.side.value,
        "volume": snapshot.volume,
        "price_open": snapshot.price_open,
        "stop_loss": snapshot.stop_loss,
        "profit": snapshot.profit,
        "magic_number": snapshot.magic_number,
    }


def _active_order_result(
    snapshot: ActiveOrderSnapshot,
) -> dict[str, Any]:
    return {
        "ticket": snapshot.ticket,
        "symbol": snapshot.symbol,
        "volume": snapshot.volume,
        "magic_number": snapshot.magic_number,
    }


def _deal_result(
    snapshot: DealSnapshot,
) -> dict[str, Any]:
    return {
        "ticket": snapshot.ticket,
        "order_id": snapshot.order_id,
        "position_id": snapshot.position_id,
        "symbol": snapshot.symbol,
        "side": (
            snapshot.side.value
            if snapshot.side is not None
            else None
        ),
        "entry": snapshot.entry,
        "volume": snapshot.volume,
        "price": snapshot.price,
        "profit": snapshot.profit,
        "commission": snapshot.commission,
        "swap": snapshot.swap,
        "fee": snapshot.fee,
        "net_pnl": snapshot.net_pnl,
        "time_msc": snapshot.time_msc,
        "magic_number": snapshot.magic_number,
    }


def _success(
    request_id: str,
    result: Any,
) -> ReadOnlyResponse:
    return ReadOnlyResponse(
        request_id=request_id,
        ok=True,
        result=result,
    )


def _failure(
    request_id: str,
    *,
    code: str,
    message: str,
) -> ReadOnlyResponse:
    return ReadOnlyResponse(
        request_id=request_id,
        ok=False,
        error={
            "code": code,
            "message": message,
        },
    )


def dispatch_request(
    adapter: MT5ReadOnlyWorkerAdapter,
    request: ReadOnlyRequest,
) -> tuple[ReadOnlyResponse, bool]:
    operation = request.operation
    params = request.params

    try:
        if operation == "PING":
            return (
                _success(
                    request.request_id,
                    {
                        "service": "mt5-read-only-worker",
                        "execution_capable": False,
                    },
                ),
                False,
            )

        if operation == "ACCOUNT":
            snapshot = adapter.account_snapshot()

            return (
                _success(
                    request.request_id,
                    _account_result(snapshot),
                ),
                False,
            )

        if operation == "SYMBOL":
            snapshot = adapter.symbol_snapshot(
                params["symbol"]
            )

            return (
                _success(
                    request.request_id,
                    _symbol_result(snapshot),
                ),
                False,
            )

        if operation == "CANDLES":
            start_pos = int(
                params.get("start_pos", 1)
            )

            if start_pos == 1:
                snapshots = adapter.candles(
                    params["symbol"],
                    params["timeframe"],
                    params["count"],
                )
            else:
                snapshots = adapter.candles(
                    params["symbol"],
                    params["timeframe"],
                    params["count"],
                    start_pos=start_pos,
                )

            return (
                _success(
                    request.request_id,
                    [
                        _candle_result(snapshot)
                        for snapshot in snapshots
                    ],
                ),
                False,
            )

        if operation == "POSITIONS":
            snapshots = adapter.positions()

            return (
                _success(
                    request.request_id,
                    {
                        "scope": "ACCOUNT",
                        "positions": [
                            _position_result(snapshot)
                            for snapshot in snapshots
                        ],
                    },
                ),
                False,
            )

        if operation == "ACTIVE_ORDERS":
            snapshots = adapter.active_orders()

            return (
                _success(
                    request.request_id,
                    {
                        "scope": "ACCOUNT",
                        "orders": [
                            _active_order_result(snapshot)
                            for snapshot in snapshots
                        ],
                    },
                ),
                False,
            )

        if operation == "HISTORY":
            start = datetime.fromisoformat(
                params["from_utc"]
            )
            end = datetime.fromisoformat(
                params["to_utc"]
            )

            snapshots = adapter.history(
                start,
                end,
                symbol=params["symbol"],
                limit=params["limit"],
            )

            return (
                _success(
                    request.request_id,
                    [
                        _deal_result(snapshot)
                        for snapshot in snapshots
                    ],
                ),
                False,
            )

        if operation == "DAILY_PNL":
            pnl = adapter.daily_realized_pnl()

            return (
                _success(
                    request.request_id,
                    {
                        "scope": "ACCOUNT",
                        "realized_pnl": pnl,
                    },
                ),
                False,
            )

        if operation == "SHUTDOWN":
            return (
                _success(
                    request.request_id,
                    {
                        "shutdown": True,
                    },
                ),
                True,
            )

        return (
            _failure(
                request.request_id,
                code="INTERNAL_ERROR",
                message="Read-only worker rejected operation",
            ),
            False,
        )

    except MT5ReadOnlyDataError:
        return (
            _failure(
                request.request_id,
                code="MT5_ERROR",
                message="Read-only MT5 operation failed",
            ),
            False,
        )

    except Exception:
        return (
            _failure(
                request.request_id,
                code="INTERNAL_ERROR",
                message="Read-only worker internal failure",
            ),
            False,
        )