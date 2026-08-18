from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from trading_lab.domain import (
    AccountKind,
    AccountSnapshot,
    ActiveOrderSnapshot,
    CandleSnapshot,
    DealSnapshot,
    PositionSnapshot,
    Side,
    SymbolSnapshot,
)
from trading_lab.mt5_read_only_data import (
    MT5ReadOnlyDataError,
)
from trading_lab.mt5_read_only_protocol import (
    ReadOnlyRequest,
    encode_response,
)
from trading_lab.mt5_read_only_worker import (
    dispatch_request,
)


class FakeWorkerAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.fail = False

    def _maybe_fail(self) -> None:
        if self.fail:
            raise MT5ReadOnlyDataError(
                "fake MT5 failure with internal details"
            )

    def account_snapshot(self) -> AccountSnapshot:
        self.calls.append(("account_snapshot",))
        self._maybe_fail()

        return AccountSnapshot(
            login=10012236003,
            server="MetaQuotes-Demo",
            kind=AccountKind.DEMO,
            equity=10000.0,
            balance=9990.0,
            connected=True,
            trade_allowed=True,
            terminal_trade_allowed=True,
            currency="EUR",
            account_name="Demo",
        )

    def symbol_snapshot(
        self,
        symbol: str,
    ) -> SymbolSnapshot:
        self.calls.append(
            ("symbol_snapshot", symbol)
        )
        self._maybe_fail()

        return SymbolSnapshot(
            symbol=symbol,
            bid=3333.10,
            ask=3333.50,
            point=0.01,
            tick_size=0.01,
            tick_value=1.0,
            volume_min=0.01,
            volume_max=100.0,
            volume_step=0.01,
            trade_stops_level=0,
            visible=True,
            tick_time_msc=123456789,
            trade_freeze_level=0,
            market_open=True,
            trade_mode="FULL",
        )

    def candles(
        self,
        symbol: str,
        timeframe: str,
        count: int,
    ) -> list[CandleSnapshot]:
        self.calls.append(
            (
                "candles",
                symbol,
                timeframe,
                count,
            )
        )
        self._maybe_fail()

        return [
            CandleSnapshot(
                symbol=symbol,
                timeframe=timeframe,
                time_msc=1000,
                open=3330.0,
                high=3335.0,
                low=3329.0,
                close=3334.0,
                tick_volume=100,
                spread=40,
            )
        ]

    def positions(
        self,
    ) -> list[PositionSnapshot]:
        self.calls.append(("positions",))
        self._maybe_fail()

        return [
            PositionSnapshot(
                ticket=101,
                symbol="XAUUSD",
                side=Side.BUY,
                volume=0.01,
                price_open=3330.0,
                stop_loss=3325.0,
                profit=5.0,
                magic_number=26081101,
            )
        ]

    def active_orders(
        self,
    ) -> list[ActiveOrderSnapshot]:
        self.calls.append(("active_orders",))
        self._maybe_fail()

        return [
            ActiveOrderSnapshot(
                ticket=202,
                symbol="EURUSD",
                volume=0.10,
                magic_number=0,
            )
        ]

    def history(
        self,
        start: datetime,
        end: datetime,
        *,
        symbol: str | None,
        limit: int,
    ) -> list[DealSnapshot]:
        self.calls.append(
            (
                "history",
                start,
                end,
                symbol,
                limit,
            )
        )
        self._maybe_fail()

        return [
            DealSnapshot(
                ticket=301,
                order_id=302,
                position_id=303,
                symbol="XAUUSD",
                side=Side.SELL,
                entry="OUT",
                volume=0.01,
                price=3333.0,
                profit=10.0,
                commission=-1.0,
                swap=-0.5,
                fee=-0.25,
                time_msc=987654321,
                magic_number=26081101,
            )
        ]

    def daily_realized_pnl(self) -> float:
        self.calls.append(
            ("daily_realized_pnl",)
        )
        self._maybe_fail()

        return 8.25


def request(
    operation: str,
    params: dict | None = None,
) -> ReadOnlyRequest:
    return ReadOnlyRequest(
        request_id=f"id-{operation}",
        operation=operation,
        params=params or {},
    )


def test_ping_never_calls_adapter():
    adapter = FakeWorkerAdapter()

    response, shutdown = dispatch_request(
        adapter,
        request("PING"),
    )

    assert response.ok is True
    assert response.result == {
        "service": "mt5-read-only-worker",
        "execution_capable": False,
    }
    assert shutdown is False
    assert adapter.calls == []


def test_account_is_explicitly_normalized():
    adapter = FakeWorkerAdapter()

    response, shutdown = dispatch_request(
        adapter,
        request("ACCOUNT"),
    )

    assert shutdown is False
    assert response.ok is True

    assert response.result == {
        "login": 10012236003,
        "server": "MetaQuotes-Demo",
        "kind": "DEMO",
        "equity": 10000.0,
        "balance": 9990.0,
        "connected": True,
        "trade_allowed": True,
        "terminal_trade_allowed": True,
        "currency": "EUR",
        "account_name": "Demo",
    }


def test_symbol_dispatch_is_exact():
    adapter = FakeWorkerAdapter()

    response, _ = dispatch_request(
        adapter,
        request(
            "SYMBOL",
            {"symbol": "XAUUSD"},
        ),
    )

    assert response.ok is True
    assert response.result["symbol"] == "XAUUSD"
    assert response.result["trade_mode"] == "FULL"

    assert adapter.calls == [
        ("symbol_snapshot", "XAUUSD")
    ]


def test_candles_dispatch_uses_exact_parameters():
    adapter = FakeWorkerAdapter()

    response, _ = dispatch_request(
        adapter,
        request(
            "CANDLES",
            {
                "symbol": "XAUUSD",
                "timeframe": "M5",
                "count": 25,
            },
        ),
    )

    assert response.ok is True
    assert len(response.result) == 1
    assert response.result[0]["timeframe"] == "M5"

    assert adapter.calls == [
        (
            "candles",
            "XAUUSD",
            "M5",
            25,
        )
    ]


def test_positions_remain_account_wide():
    adapter = FakeWorkerAdapter()

    response, _ = dispatch_request(
        adapter,
        request("POSITIONS"),
    )

    assert response.ok is True
    assert response.result["scope"] == "ACCOUNT"

    assert response.result["positions"] == [
        {
            "ticket": 101,
            "symbol": "XAUUSD",
            "side": "BUY",
            "volume": 0.01,
            "price_open": 3330.0,
            "stop_loss": 3325.0,
            "profit": 5.0,
            "magic_number": 26081101,
        }
    ]


def test_active_orders_remain_account_wide():
    adapter = FakeWorkerAdapter()

    response, _ = dispatch_request(
        adapter,
        request("ACTIVE_ORDERS"),
    )

    assert response.ok is True
    assert response.result == {
        "scope": "ACCOUNT",
        "orders": [
            {
                "ticket": 202,
                "symbol": "EURUSD",
                "volume": 0.10,
                "magic_number": 0,
            }
        ],
    }


def test_history_dispatch_parses_reviewed_utc_values():
    adapter = FakeWorkerAdapter()

    response, _ = dispatch_request(
        adapter,
        request(
            "HISTORY",
            {
                "symbol": "XAUUSD",
                "from_utc": (
                    "2026-08-17T00:00:00+00:00"
                ),
                "to_utc": (
                    "2026-08-18T00:00:00+00:00"
                ),
                "limit": 100,
            },
        ),
    )

    assert response.ok is True

    assert response.result == [
        {
            "ticket": 301,
            "order_id": 302,
            "position_id": 303,
            "symbol": "XAUUSD",
            "side": "SELL",
            "entry": "OUT",
            "volume": 0.01,
            "price": 3333.0,
            "profit": 10.0,
            "commission": -1.0,
            "swap": -0.5,
            "fee": -0.25,
            "net_pnl": 8.25,
            "time_msc": 987654321,
            "magic_number": 26081101,
        }
    ]

    call = adapter.calls[0]

    assert call[0] == "history"
    assert call[1] == datetime(
        2026,
        8,
        17,
        tzinfo=UTC,
    )
    assert call[2] == datetime(
        2026,
        8,
        18,
        tzinfo=UTC,
    )
    assert call[3] == "XAUUSD"
    assert call[4] == 100


def test_daily_pnl_is_explicitly_account_scope():
    adapter = FakeWorkerAdapter()

    response, _ = dispatch_request(
        adapter,
        request("DAILY_PNL"),
    )

    assert response.ok is True
    assert response.result == {
        "scope": "ACCOUNT",
        "realized_pnl": 8.25,
    }


def test_shutdown_never_calls_adapter():
    adapter = FakeWorkerAdapter()

    response, shutdown = dispatch_request(
        adapter,
        request("SHUTDOWN"),
    )

    assert response.ok is True
    assert response.result == {
        "shutdown": True,
    }
    assert shutdown is True
    assert adapter.calls == []


def test_mt5_error_is_sanitized():
    adapter = FakeWorkerAdapter()
    adapter.fail = True

    response, shutdown = dispatch_request(
        adapter,
        request("ACCOUNT"),
    )

    assert shutdown is False
    assert response.ok is False

    assert response.error == {
        "code": "MT5_ERROR",
        "message": "Read-only MT5 operation failed",
    }

    encoded = encode_response(response)

    assert (
        b"fake MT5 failure with internal details"
        not in encoded
    )


def test_unknown_operation_fails_without_adapter_call():
    adapter = FakeWorkerAdapter()

    response, shutdown = dispatch_request(
        adapter,
        request("ORDER_SEND"),
    )

    assert shutdown is False
    assert response.ok is False
    assert response.error == {
        "code": "INTERNAL_ERROR",
        "message": "Read-only worker rejected operation",
    }

    assert adapter.calls == []


def test_worker_source_has_no_dynamic_dispatch():
    source = Path(
        r"C:\automaton\trading_lab\mt5_read_only_worker.py"
    ).read_text(
        encoding="utf-8"
    )

    forbidden = (
        "getattr(",
        "setattr(",
        "eval(",
        "exec(",
        "__import__",
        "import_module",
        "MetaTrader5",
        ".order_check(",
        ".order_send(",
        ".login(",
        "TRADE_ACTION_",
    )

    for marker in forbidden:
        assert marker not in source


@pytest.mark.parametrize(
    "operation",
    [
        "PING",
        "ACCOUNT",
        "SYMBOL",
        "CANDLES",
        "POSITIONS",
        "ACTIVE_ORDERS",
        "HISTORY",
        "DAILY_PNL",
        "SHUTDOWN",
    ],
)
def test_worker_contains_explicit_operation_branch(
    operation: str,
):
    source = Path(
        r"C:\automaton\trading_lab\mt5_read_only_worker.py"
    ).read_text(
        encoding="utf-8"
    )

    assert (
        f'operation == "{operation}"'
        in source
    )