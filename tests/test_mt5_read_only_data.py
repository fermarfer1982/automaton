from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import trading_lab.mt5_read_only_data as readonly_module
from trading_lab.mt5_read_only_data import (
    MT5ReadOnlyDataAdapter,
    MT5ReadOnlyDataCapabilityViolation,
    MT5ReadOnlyDataError,
    PROHIBITED_DATA_CAPABILITIES,
    READ_ONLY_DATA_CAPABILITIES,
    _bindings_from_module,
    load_mt5_read_only_data_adapter,
)


class FakeMT5:
    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_CONTEST = 1
    ACCOUNT_TRADE_MODE_REAL = 2

    TIMEFRAME_M1 = 1
    TIMEFRAME_M5 = 5
    TIMEFRAME_M15 = 15
    TIMEFRAME_H1 = 60

    ORDER_TYPE_BUY = 0
    ORDER_TYPE_SELL = 1

    DEAL_ENTRY_IN = 0
    DEAL_ENTRY_OUT = 1
    DEAL_ENTRY_INOUT = 2
    DEAL_ENTRY_OUT_BY = 3

    SYMBOL_TRADE_MODE_DISABLED = 0
    SYMBOL_TRADE_MODE_LONGONLY = 1
    SYMBOL_TRADE_MODE_SHORTONLY = 2
    SYMBOL_TRADE_MODE_CLOSEONLY = 3
    SYMBOL_TRADE_MODE_FULL = 4

    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.shutdown_count = 0

    def initialize(self, **kwargs):
        self.calls.append(("initialize", kwargs))
        return True

    def version(self):
        self.calls.append(("version", None))
        return (500, 6116, "test")

    def terminal_info(self):
        self.calls.append(("terminal_info", None))
        return SimpleNamespace(
            connected=True,
            trade_allowed=False,
        )

    def account_info(self):
        self.calls.append(("account_info", None))
        return SimpleNamespace(
            login=10012236003,
            server="MetaQuotes-Demo",
            trade_mode=self.ACCOUNT_TRADE_MODE_DEMO,
            equity=10000.0,
            balance=9950.0,
            trade_allowed=False,
            currency="EUR",
            name="ReadOnly Demo",
        )

    def symbol_info(self, symbol: str):
        self.calls.append(("symbol_info", symbol))
        return SimpleNamespace(
            name=symbol,
            point=0.01,
            trade_tick_size=0.01,
            trade_tick_value=1.0,
            trade_tick_value_profit=1.0,
            trade_tick_value_loss=1.0,
            volume_min=0.01,
            volume_max=100.0,
            volume_step=0.01,
            trade_stops_level=0,
            visible=True,
            trade_freeze_level=0,
            trade_mode=self.SYMBOL_TRADE_MODE_FULL,
        )

    def symbol_info_tick(self, symbol: str):
        self.calls.append(("symbol_info_tick", symbol))
        return SimpleNamespace(
            bid=4392.96,
            ask=4393.23,
            time_msc=1_800_000_000_000,
        )

    def copy_rates_from_pos(
        self,
        symbol: str,
        timeframe: int,
        start_pos: int,
        count: int,
    ):
        self.calls.append((
            "copy_rates_from_pos",
            (symbol, timeframe, start_pos, count),
        ))

        base = 1_800_000_000

        return [
            {
                "time": base + index * 60,
                "open": 4390.0 + index,
                "high": 4392.0 + index,
                "low": 4389.0 + index,
                "close": 4391.0 + index,
                "tick_volume": 100 + index,
                "spread": 25,
            }
            for index in range(count)
        ]

    def positions_get(self):
        self.calls.append(("positions_get", None))
        return [
            SimpleNamespace(
                ticket=12345,
                symbol="XAUUSD",
                type=self.ORDER_TYPE_BUY,
                volume=0.01,
                price_open=4380.0,
                sl=4370.0,
                profit=12.5,
                magic=26081101,
            )
        ]

    def orders_get(self):
        self.calls.append(("orders_get", None))
        return [
            SimpleNamespace(
                ticket=54321,
                symbol="XAUUSD",
                volume_current=0.02,
                magic=26081101,
            )
        ]

    def history_deals_get(self, start: datetime, end: datetime):
        self.calls.append(("history_deals_get", (start, end)))
        return [
            SimpleNamespace(
                ticket=1,
                order=11,
                position_id=111,
                symbol="XAUUSD",
                type=self.ORDER_TYPE_BUY,
                entry=self.DEAL_ENTRY_IN,
                volume=0.01,
                price=4380.0,
                profit=99.0,
                commission=-1.0,
                swap=0.0,
                fee=0.0,
                time_msc=1_800_000_000_000,
                magic=26081101,
            ),
            SimpleNamespace(
                ticket=2,
                order=12,
                position_id=111,
                symbol="XAUUSD",
                type=self.ORDER_TYPE_SELL,
                entry=self.DEAL_ENTRY_OUT,
                volume=0.01,
                price=4390.0,
                profit=10.0,
                commission=-0.5,
                swap=-0.2,
                fee=-0.1,
                time_msc=1_800_000_100_000,
                magic=26081101,
            ),
        ]

    def shutdown(self):
        self.calls.append(("shutdown", None))
        self.shutdown_count += 1

    def last_error(self):
        self.calls.append(("last_error", None))
        return (0, "OK")

    # Poison methods. If the read-only binding layer ever tries to use
    # one of them, the test must fail immediately.
    def login(self, *args, **kwargs):
        raise AssertionError("login must never be called")

    def symbol_select(self, *args, **kwargs):
        raise AssertionError("symbol_select must never be called")

    def order_calc_profit(self, *args, **kwargs):
        raise AssertionError("order_calc_profit must never be called")

    def order_check(self, *args, **kwargs):
        raise AssertionError("order_check must never be called")

    def order_send(self, *args, **kwargs):
        raise AssertionError("order_send must never be called")


_TEST_SERVER_RAW_MSC = 1_800_000_000_000
_TEST_SERVER_OFFSET_MSC = 3 * 60 * 60 * 1000
_TEST_NOW_UTC = datetime.fromtimestamp(
    (
        _TEST_SERVER_RAW_MSC
        - _TEST_SERVER_OFFSET_MSC
    ) / 1000,
    UTC,
)


def make_adapter():
    fake = FakeMT5()
    bindings = _bindings_from_module(fake)
    adapter = MT5ReadOnlyDataAdapter(
        Path(r"C:\Program Files\MetaTrader 5\terminal64.exe"),
        bindings,
        terminal_running_probe=lambda _path: True,
        now_provider=lambda: _TEST_NOW_UTC,
    )
    return fake, bindings, adapter


def test_capability_surface_is_exact_and_execution_methods_are_absent():
    _, bindings, adapter = make_adapter()

    assert adapter.allowed_capabilities == READ_ONLY_DATA_CAPABILITIES

    for capability in PROHIBITED_DATA_CAPABILITIES:
        assert not hasattr(adapter, capability)
        assert not hasattr(bindings, capability)

    assert not hasattr(adapter, "_mt5")
    assert not hasattr(adapter, "_module")

    assert set(MT5ReadOnlyDataAdapter.__slots__) == {
        "_terminal_path",
        "_bindings",
        "_ledger",
        "_lock",
        "_terminal_running_probe",
        "_now_provider",
    }

    adapter.assert_read_only_boundary()


def test_binding_factory_never_requests_forbidden_module_attributes():
    class TrapFakeMT5(FakeMT5):
        def __getattribute__(self, name: str):
            if name in PROHIBITED_DATA_CAPABILITIES:
                raise AssertionError(
                    f"binding factory touched forbidden capability: {name}"
                )
            return super().__getattribute__(name)

    fake = TrapFakeMT5()

    bindings = _bindings_from_module(fake)

    assert callable(bindings.account_info)
    assert callable(bindings.copy_rates_from_pos)
    assert callable(bindings.positions_get)
    assert callable(bindings.orders_get)
    assert callable(bindings.history_deals_get)


def test_initialize_uses_exact_terminal_path_and_parameters():
    fake, _, adapter = make_adapter()

    assert adapter.initialize() is True

    calls = [
        payload
        for name, payload in fake.calls
        if name == "initialize"
    ]

    assert len(calls) == 1
    assert calls[0] == {
        "path": r"C:\Program Files\MetaTrader 5\terminal64.exe",
        "timeout": 10_000,
        "portable": False,
    }

    evidence = adapter.capability_evidence()

    assert evidence["allowed"]["initialize"] == 1
    assert evidence["unexpected"] == {}


def test_observation_methods_only_use_read_capabilities():
    fake, _, adapter = make_adapter()

    account = adapter.account_snapshot()
    market = adapter.symbol_snapshot("XAUUSD")
    candles = adapter.candles("XAUUSD", "M5", 2)
    positions = adapter.positions()
    orders = adapter.active_orders()

    start = datetime.now(UTC) - timedelta(days=1)
    end = datetime.now(UTC)

    history = adapter.history(
        start,
        end,
        symbol="XAUUSD",
        limit=100,
    )

    daily = adapter.daily_realized_pnl()

    assert account.login == 10012236003
    assert account.server == "MetaQuotes-Demo"
    assert account.kind.value == "DEMO"
    assert account.connected is True
    assert account.terminal_trade_allowed is False

    assert market.symbol == "XAUUSD"
    assert market.bid == pytest.approx(4392.96)
    assert market.ask == pytest.approx(4393.23)
    assert market.trade_mode == "FULL"
    assert market.tick_time_msc == (
        _TEST_SERVER_RAW_MSC
        - _TEST_SERVER_OFFSET_MSC
    )

    assert len(candles) == 2
    assert candles[0].timeframe == "M5"
    assert candles[0].symbol == "XAUUSD"
    assert candles[0].time_msc == (
        _TEST_SERVER_RAW_MSC
        - _TEST_SERVER_OFFSET_MSC
    )

    assert len(positions) == 1
    assert positions[0].ticket == 12345
    assert positions[0].magic_number == 26081101

    assert len(orders) == 1
    assert orders[0].ticket == 54321

    assert len(history) == 2
    assert history[0].symbol == "XAUUSD"
    assert history[0].time_msc == (
        _TEST_SERVER_RAW_MSC
        - _TEST_SERVER_OFFSET_MSC
    )
    assert history[1].entry == "OUT"
    assert history[1].time_msc == (
        _TEST_SERVER_RAW_MSC
        + 100_000
        - _TEST_SERVER_OFFSET_MSC
    )

    # Entry-deal profit is ignored for realized PnL.
    # -1.0 entry commission
    # +10.0 -0.5 -0.2 -0.1 closing deal = +9.2
    # Total = 8.2
    assert daily == pytest.approx(8.2)

    forbidden_names = {
        "login",
        "symbol_select",
        "order_calc_profit",
        "order_check",
        "order_send",
    }

    observed_calls = {
        name
        for name, _payload in fake.calls
    }

    assert observed_calls.isdisjoint(forbidden_names)

    evidence = adapter.capability_evidence()

    assert evidence["allowed"]["terminal_info"] == 1
    assert evidence["allowed"]["account_info"] == 1
    assert evidence["allowed"]["symbol_info"] == 1
    assert evidence["allowed"]["symbol_info_tick"] == 3
    assert evidence["allowed"]["copy_rates_from_pos"] == 1
    assert evidence["allowed"]["positions_get"] == 1
    assert evidence["allowed"]["orders_get"] == 1
    assert evidence["allowed"]["history_deals_get"] == 2
    assert evidence["unexpected"] == {}


def test_server_time_calibration_fails_closed_on_non_hour_drift():
    class DriftedFakeMT5(FakeMT5):
        def symbol_info_tick(self, symbol: str):
            tick = super().symbol_info_tick(symbol)
            tick.time_msc += 20 * 60 * 1000
            return tick

    fake = DriftedFakeMT5()
    bindings = _bindings_from_module(fake)
    adapter = MT5ReadOnlyDataAdapter(
        Path(r"C:\Program Files\MetaTrader 5\terminal64.exe"),
        bindings,
        terminal_running_probe=lambda _path: True,
        now_provider=lambda: _TEST_NOW_UTC,
    )

    with pytest.raises(
        MT5ReadOnlyDataError,
        match="integral-hour offset",
    ):
        adapter.symbol_snapshot("XAUUSD")


def test_unexpected_capability_fails_closed_and_remains_poisoned():
    _, _, adapter = make_adapter()

    with pytest.raises(
        MT5ReadOnlyDataCapabilityViolation,
        match="order_send",
    ):
        adapter._ledger.invoke(
            "order_send",
            lambda: None,
        )

    evidence = adapter.capability_evidence()

    assert evidence["unexpected"]["order_send"] == 1

    with pytest.raises(
        MT5ReadOnlyDataCapabilityViolation,
        match="Unexpected MT5 capability",
    ):
        adapter.assert_read_only_boundary()


@pytest.mark.parametrize(
    ("timeframe", "count"),
    [
        ("M2", 10),
        ("M1", 0),
        ("M1", 501),
    ],
)
def test_candle_bounds_fail_closed(timeframe: str, count: int):
    _, _, adapter = make_adapter()

    with pytest.raises(MT5ReadOnlyDataError):
        adapter.candles(
            "XAUUSD",
            timeframe,
            count,
        )


def test_history_bounds_fail_closed():
    _, _, adapter = make_adapter()

    aware = datetime.now(UTC)
    naive = datetime.now()

    with pytest.raises(MT5ReadOnlyDataError):
        adapter.history(
            naive,
            aware,
        )

    with pytest.raises(MT5ReadOnlyDataError):
        adapter.history(
            aware,
            aware,
        )

    with pytest.raises(MT5ReadOnlyDataError):
        adapter.history(
            aware - timedelta(days=1),
            aware,
            limit=0,
        )

    with pytest.raises(MT5ReadOnlyDataError):
        adapter.history(
            aware - timedelta(days=1),
            aware,
            limit=1001,
        )


def test_source_has_no_execution_call_sites_or_full_module_storage():
    source = inspect.getsource(readonly_module)

    forbidden_call_sites = (
        ".login(",
        ".symbol_select(",
        ".market_book_add(",
        ".market_book_release(",
        ".copy_ticks_from(",
        ".order_calc_profit(",
        ".order_check(",
        ".order_send(",
        "TRADE_ACTION_",
    )

    for forbidden in forbidden_call_sites:
        assert forbidden not in source

    assert "self._mt5" not in source
    assert "self._module(" not in source


def test_loader_copies_reviewed_bindings_without_exposing_module(
    monkeypatch: pytest.MonkeyPatch,
):
    fake = FakeMT5()

    imported: list[str] = []

    def fake_import(name: str):
        imported.append(name)
        assert name == "MetaTrader5"
        return fake

    monkeypatch.setattr(
        readonly_module.importlib,
        "import_module",
        fake_import,
    )

    adapter = load_mt5_read_only_data_adapter(
        Path(r"C:\Program Files\MetaTrader 5\terminal64.exe"),
        terminal_running_probe=lambda _path: True,
    )

    assert imported == ["MetaTrader5"]

    assert not hasattr(adapter, "_mt5")
    assert not hasattr(adapter, "_module")
    assert not hasattr(adapter, "order_check")
    assert not hasattr(adapter, "order_send")

    adapter.assert_read_only_boundary()

def test_initialize_fails_before_mt5_initialize_when_terminal_not_visible():
    fake = FakeMT5()
    bindings = _bindings_from_module(fake)

    adapter = MT5ReadOnlyDataAdapter(
        Path(r"C:\Program Files\MetaTrader 5\terminal64.exe"),
        bindings,
        terminal_running_probe=lambda _path: False,
    )

    with pytest.raises(
        MT5ReadOnlyDataError,
        match="already be visible",
    ):
        adapter.initialize()

    initialize_calls = [
        item
        for item in fake.calls
        if item[0] == "initialize"
    ]

    assert initialize_calls == []
    assert (
        adapter.capability_evidence()
        ["allowed"]["initialize"]
        == 0
    )


def test_loader_fails_before_import_when_terminal_not_visible(
    monkeypatch: pytest.MonkeyPatch,
):
    imported: list[str] = []

    def forbidden_import(name: str):
        imported.append(name)
        raise AssertionError(
            "MetaTrader5 must not be imported "
            "when terminal probe fails"
        )

    monkeypatch.setattr(
        readonly_module.importlib,
        "import_module",
        forbidden_import,
    )

    with pytest.raises(
        MT5ReadOnlyDataError,
        match="already be visible",
    ):
        load_mt5_read_only_data_adapter(
            Path(r"C:\Program Files\MetaTrader 5\terminal64.exe"),
            terminal_running_probe=lambda _path: False,
        )

    assert imported == []

