from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

from trading_lab.domain import AccountKind, Side
from trading_lab.mt5_adapter import MT5Adapter, MT5AdapterError


class FakeMT5Module:
    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_CONTEST = 1
    ACCOUNT_TRADE_MODE_REAL = 2
    ORDER_TYPE_BUY = 0
    ORDER_TYPE_SELL = 1
    DEAL_ENTRY_OUT = 1
    DEAL_ENTRY_INOUT = 2
    DEAL_ENTRY_OUT_BY = 3
    DEAL_ENTRY_IN = 0
    TRADE_ACTION_DEAL = 1
    ORDER_TIME_GTC = 0
    ORDER_FILLING_IOC = 1
    TRADE_RETCODE_PLACED = 10008
    TRADE_RETCODE_DONE = 10009
    TRADE_RETCODE_DONE_PARTIAL = 10010
    SYMBOL_TRADE_MODE_DISABLED = 0
    TIMEFRAME_M1 = 1
    TIMEFRAME_M5 = 5
    TIMEFRAME_M15 = 15
    TIMEFRAME_H1 = 60

    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def initialize(self, path: str, timeout: int, portable: bool) -> bool:
        self.calls.append(("initialize", {"path": path, "timeout": timeout, "portable": portable}))
        return True

    def shutdown(self) -> None:
        self.calls.append(("shutdown", None))

    def terminal_info(self):
        return SimpleNamespace(connected=True, trade_allowed=True)

    def account_info(self):
        return SimpleNamespace(
            login=12345678, server="Broker-Demo", trade_mode=0,
            equity=10000.0, balance=10000.0, trade_allowed=True,
            currency="EUR", name="Authorized Demo",
        )

    def symbol_info(self, symbol: str):
        return SimpleNamespace(
            name=symbol, visible=True, point=0.01, trade_tick_size=0.01,
            trade_tick_value=0.1, trade_tick_value_profit=0.1,
            trade_tick_value_loss=0.1, volume_min=0.01, volume_max=100.0,
            volume_step=0.01, trade_stops_level=10,
            trade_freeze_level=5, trade_mode=4,
        )

    def symbol_info_tick(self, symbol: str):
        return SimpleNamespace(bid=2400.0, ask=2400.2, time_msc=2_000_000_000_000)

    def copy_rates_from_pos(self, symbol, timeframe, start_pos, count):
        self.calls.append(("copy_rates_from_pos", {
            "symbol": symbol, "timeframe": timeframe,
            "start_pos": start_pos, "count": count,
        }))
        return [
            {
                "time": 2_000_000_000,
                "open": 2400.0,
                "high": 2401.0,
                "low": 2399.0,
                "close": 2400.5,
                "tick_volume": 100,
                "spread": 20,
            }
        ]

    def positions_get(self):
        return (
            SimpleNamespace(
                ticket=5, symbol="XAUUSD", type=0, volume=0.01,
                price_open=2390.0, sl=2380.0, profit=10.0, magic=26081101,
            ),
        )

    def orders_get(self):
        return (
            SimpleNamespace(ticket=8, symbol="XAUUSD", volume_current=0.02, magic=26081101),
        )

    def history_deals_get(self, start, end):
        return (
            SimpleNamespace(
                ticket=21, order=20, position_id=19, symbol="XAUUSD", type=1,
                entry=1, volume=0.01, price=2401.0, profit=-4.0,
                commission=-0.5, swap=-0.1, fee=0.0,
                time_msc=2_000_000_000_000, magic=26081101,
            ),
            SimpleNamespace(
                ticket=22, order=20, position_id=19, symbol="XAUUSD", type=0,
                entry=0, volume=0.01, price=2400.0, profit=0.0,
                commission=-0.5, swap=0.0, fee=0.0,
                time_msc=1_999_999_000_000, magic=26081101,
            ),
        )

    def order_check(self, request):
        self.calls.append(("order_check", request))
        return SimpleNamespace(retcode=0, comment="ok")

    def order_calc_profit(self, order_type, symbol, volume, price_open, price_close):
        self.calls.append(("order_calc_profit", {
            "order_type": order_type, "symbol": symbol, "volume": volume,
            "price_open": price_open, "price_close": price_close,
        }))
        return -20.0

    def order_send(self, request):
        self.calls.append(("order_send", request))
        return SimpleNamespace(retcode=10009, comment="done", order=42, deal=43)

    def last_error(self):
        return (0, "ok")


class MT5AdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = FakeMT5Module()
        self.adapter = MT5Adapter(
            Path("C:/Program Files/MetaTrader 5/terminal64.exe"),
            module=self.module,
            terminal_running_probe=lambda _path: True,
        )

    def test_initialize_passes_only_path_and_noncredential_options(self) -> None:
        self.assertTrue(self.adapter.initialize())
        name, kwargs = self.module.calls[0]
        self.assertEqual("initialize", name)
        self.assertEqual(
            {"path": "C:\\Program Files\\MetaTrader 5\\terminal64.exe", "timeout": 10_000, "portable": False},
            kwargs,
        )
        self.assertNotIn("login", kwargs)
        self.assertNotIn("password", kwargs)
        self.assertNotIn("server", kwargs)

    def test_initialize_never_launches_an_absent_or_headless_terminal(self) -> None:
        adapter = MT5Adapter(
            Path("C:/Program Files/MetaTrader 5/terminal64.exe"),
            module=self.module,
            terminal_running_probe=lambda _path: False,
        )
        with self.assertRaises(MT5AdapterError):
            adapter.initialize()
        self.assertEqual([], self.module.calls)

    def test_maps_account_symbol_positions_and_daily_pnl(self) -> None:
        account = self.adapter.account_snapshot()
        symbol = self.adapter.symbol_snapshot("XAUUSD")
        positions = self.adapter.positions()
        orders = self.adapter.active_orders()
        self.assertEqual(AccountKind.DEMO, account.kind)
        self.assertEqual("EUR", account.currency)
        self.assertEqual("Authorized Demo", account.account_name)
        self.assertEqual("XAUUSD", symbol.symbol)
        self.assertEqual(Side.BUY, positions[0].side)
        self.assertEqual(8, orders[0].ticket)
        self.assertAlmostEqual(-5.1, self.adapter.daily_realized_pnl())
        self.assertAlmostEqual(
            -20.0,
            self.adapter.order_calc_profit(Side.BUY, "XAUUSD", 1.0, 2400.2, 2398.2),
        )

    def test_maps_order_constants_inside_adapter(self) -> None:
        request = {
            "action": "DEAL", "symbol": "XAUUSD", "volume": 0.01,
            "type": "BUY", "price": 2400.2, "sl": 2398.0, "tp": 2404.0,
            "deviation": 10, "magic": 26081101, "comment": "automaton:p1",
            "type_time": "GTC", "type_filling": "IOC",
        }
        checked = self.adapter.order_check(request)
        sent = self.adapter.order_send(request)
        self.assertTrue(checked.ok)
        self.assertTrue(sent.ok)
        raw = next(payload for name, payload in self.module.calls if name == "order_send")
        self.assertEqual(self.module.TRADE_ACTION_DEAL, raw["action"])
        self.assertEqual(self.module.ORDER_TYPE_BUY, raw["type"])

    def test_reads_only_closed_candles_for_allowed_timeframes(self) -> None:
        candles = self.adapter.candles("XAUUSD", "M1", 1)
        self.assertEqual(1, len(candles))
        self.assertEqual(2_000_000_000_000, candles[0].time_msc)
        _, request = next(item for item in self.module.calls if item[0] == "copy_rates_from_pos")
        self.assertEqual(1, request["start_pos"])
        with self.assertRaises(MT5AdapterError):
            self.adapter.candles("XAUUSD", "D1", 1)
        with self.assertRaises(MT5AdapterError):
            self.adapter.candles("XAUUSD", "M1", 501)

    def test_reads_bounded_timezone_aware_history(self) -> None:
        from datetime import UTC, datetime, timedelta

        end = datetime.now(UTC)
        deals = self.adapter.history(end - timedelta(days=1), end, symbol="XAUUSD")
        self.assertEqual(2, len(deals))
        self.assertAlmostEqual(-4.6, deals[0].net_pnl)
        with self.assertRaises(MT5AdapterError):
            self.adapter.history(end.replace(tzinfo=None), end)

    def test_rejects_unknown_request_values_fail_closed(self) -> None:
        with self.assertRaises(MT5AdapterError):
            self.adapter.order_check({"action": "PENDING"})


if __name__ == "__main__":
    unittest.main()
