from __future__ import annotations

import importlib
import json
import math
import shutil
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

from .domain import (
    AccountKind,
    AccountSnapshot,
    ActiveOrderSnapshot,
    CandleSnapshot,
    DealSnapshot,
    PositionSnapshot,
    Side,
    SymbolSnapshot,
)


READ_ONLY_DATA_CAPABILITIES = frozenset({
    "initialize",
    "version",
    "terminal_info",
    "account_info",
    "symbol_info",
    "symbol_info_tick",
    "copy_rates_from_pos",
    "positions_get",
    "orders_get",
    "history_deals_get",
    "shutdown",
    "last_error",
})

PROHIBITED_DATA_CAPABILITIES = frozenset({
    "login",
    "symbol_select",
    "market_book_add",
    "market_book_release",
    "copy_ticks_from",
    "order_calc_profit",
    "order_check",
    "order_send",
})


class MT5ReadOnlyDataError(RuntimeError):
    pass


class MT5ReadOnlyDataCapabilityViolation(MT5ReadOnlyDataError):
    pass


def _terminal_is_visible_in_session(
    terminal_path: Path,
) -> bool:
    powershell = (
        shutil.which("powershell.exe")
        or shutil.which("powershell")
    )

    if powershell is None:
        return False

    script = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$requested = [System.IO.Path]::GetFullPath(
    [Console]::In.ReadToEnd().Trim()
)

$sessionId = (Get-Process -Id $PID).SessionId
$name = [System.IO.Path]::GetFileNameWithoutExtension($requested)
$matched = $false

foreach (
    $process in @(
        Get-Process -Name $name -ErrorAction SilentlyContinue
    )
) {
    try {
        if (
            $process.SessionId -eq $sessionId -and
            $process.MainWindowHandle -ne 0 -and
            [string]::Equals(
                [System.IO.Path]::GetFullPath($process.Path),
                $requested,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            $matched = $true
        }
    }
    catch {
    }
}

$matched | ConvertTo-Json -Compress
'''

    try:
        completed = subprocess.run(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            input=str(terminal_path.resolve()),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )

        return (
            completed.returncode == 0
            and json.loads(completed.stdout) is True
        )

    except (
        OSError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ):
        return False


@dataclass(frozen=True)
class MT5ReadOnlyDataBindings:
    initialize: Callable[..., object]
    version: Callable[[], object]
    terminal_info: Callable[[], object]
    account_info: Callable[[], object]
    symbol_info: Callable[[str], object]
    symbol_info_tick: Callable[[str], object]
    copy_rates_from_pos: Callable[..., object]
    positions_get: Callable[..., object]
    orders_get: Callable[..., object]
    history_deals_get: Callable[..., object]
    shutdown: Callable[[], object]
    last_error: Callable[[], object]

    account_trade_mode_demo: int
    account_trade_mode_contest: int
    account_trade_mode_real: int

    timeframe_m1: int
    timeframe_m5: int
    timeframe_m15: int
    timeframe_h1: int

    order_type_buy: int
    order_type_sell: int

    deal_entry_in: int
    deal_entry_out: int
    deal_entry_inout: int
    deal_entry_out_by: int

    symbol_trade_mode_disabled: int
    symbol_trade_mode_longonly: int
    symbol_trade_mode_shortonly: int
    symbol_trade_mode_closeonly: int
    symbol_trade_mode_full: int


class MT5ReadOnlyDataCapabilityLedger:
    def __init__(self) -> None:
        self._counts = {
            name: 0
            for name in READ_ONLY_DATA_CAPABILITIES
        }
        self._unexpected: dict[str, int] = {}

    def invoke(
        self,
        capability: str,
        operation: Callable[..., object],
        *args: object,
        **kwargs: object,
    ) -> object:
        if capability not in READ_ONLY_DATA_CAPABILITIES:
            self._unexpected[capability] = (
                self._unexpected.get(capability, 0) + 1
            )
            raise MT5ReadOnlyDataCapabilityViolation(
                f"MT5 capability is not authorized in read-only data plane: "
                f"{capability}"
            )

        self._counts[capability] += 1
        return operation(*args, **kwargs)

    def evidence(self) -> dict[str, dict[str, int]]:
        return {
            "allowed": dict(self._counts),
            "unexpected": dict(self._unexpected),
        }


def _bindings_from_module(
    module: ModuleType | Any,
) -> MT5ReadOnlyDataBindings:
    return MT5ReadOnlyDataBindings(
        initialize=module.initialize,
        version=module.version,
        terminal_info=module.terminal_info,
        account_info=module.account_info,
        symbol_info=module.symbol_info,
        symbol_info_tick=module.symbol_info_tick,
        copy_rates_from_pos=module.copy_rates_from_pos,
        positions_get=module.positions_get,
        orders_get=module.orders_get,
        history_deals_get=module.history_deals_get,
        shutdown=module.shutdown,
        last_error=module.last_error,

        account_trade_mode_demo=int(module.ACCOUNT_TRADE_MODE_DEMO),
        account_trade_mode_contest=int(module.ACCOUNT_TRADE_MODE_CONTEST),
        account_trade_mode_real=int(module.ACCOUNT_TRADE_MODE_REAL),

        timeframe_m1=int(module.TIMEFRAME_M1),
        timeframe_m5=int(module.TIMEFRAME_M5),
        timeframe_m15=int(module.TIMEFRAME_M15),
        timeframe_h1=int(module.TIMEFRAME_H1),

        order_type_buy=int(module.ORDER_TYPE_BUY),
        order_type_sell=int(module.ORDER_TYPE_SELL),

        deal_entry_in=int(getattr(module, "DEAL_ENTRY_IN", 0)),
        deal_entry_out=int(module.DEAL_ENTRY_OUT),
        deal_entry_inout=int(module.DEAL_ENTRY_INOUT),
        deal_entry_out_by=int(module.DEAL_ENTRY_OUT_BY),

        symbol_trade_mode_disabled=int(
            getattr(module, "SYMBOL_TRADE_MODE_DISABLED", 0)
        ),
        symbol_trade_mode_longonly=int(
            getattr(module, "SYMBOL_TRADE_MODE_LONGONLY", 1)
        ),
        symbol_trade_mode_shortonly=int(
            getattr(module, "SYMBOL_TRADE_MODE_SHORTONLY", 2)
        ),
        symbol_trade_mode_closeonly=int(
            getattr(module, "SYMBOL_TRADE_MODE_CLOSEONLY", 3)
        ),
        symbol_trade_mode_full=int(
            getattr(module, "SYMBOL_TRADE_MODE_FULL", 4)
        ),
    )


class MT5ReadOnlyDataAdapter:
    __slots__ = (
        "_terminal_path",
        "_bindings",
        "_ledger",
        "_lock",
        "_terminal_running_probe",
    )

    def __init__(
        self,
        terminal_path: Path,
        bindings: MT5ReadOnlyDataBindings,
        *,
        terminal_running_probe: Callable[[Path], bool] | None = None,
    ) -> None:
        self._terminal_path = terminal_path
        self._bindings = bindings
        self._ledger = MT5ReadOnlyDataCapabilityLedger()
        self._lock = threading.RLock()
        self._terminal_running_probe = (
            terminal_running_probe
            or _terminal_is_visible_in_session
        )
        self.assert_read_only_boundary()

    @property
    def allowed_capabilities(self) -> frozenset[str]:
        return READ_ONLY_DATA_CAPABILITIES

    def capability_evidence(self) -> dict[str, dict[str, int]]:
        return self._ledger.evidence()

    def assert_read_only_boundary(self) -> None:
        if self.allowed_capabilities != READ_ONLY_DATA_CAPABILITIES:
            raise MT5ReadOnlyDataCapabilityViolation(
                "Read-only MT5 capability surface is not exact"
            )

        for capability in PROHIBITED_DATA_CAPABILITIES:
            if hasattr(self, capability):
                raise MT5ReadOnlyDataCapabilityViolation(
                    f"Forbidden MT5 method is exposed: {capability}"
                )

        unexpected = self._ledger.evidence()["unexpected"]
        if unexpected:
            raise MT5ReadOnlyDataCapabilityViolation(
                "Unexpected MT5 capability was previously requested"
            )

    def _invoke(
        self,
        capability: str,
        operation: Callable[..., object],
        *args: object,
        **kwargs: object,
    ) -> object:
        with self._lock:
            return self._ledger.invoke(
                capability,
                operation,
                *args,
                **kwargs,
            )

    def _error(self, operation: str) -> MT5ReadOnlyDataError:
        try:
            raw = self._invoke(
                "last_error",
                self._bindings.last_error,
            )
            code, message = raw
            return MT5ReadOnlyDataError(
                f"{operation} failed with MT5 error {code}: {message}"
            )
        except Exception:
            return MT5ReadOnlyDataError(f"{operation} failed")

    def initialize(self) -> bool:
        if not self._terminal_running_probe(
            self._terminal_path
        ):
            raise MT5ReadOnlyDataError(
                "Configured MT5 terminal must already be visible "
                "in the current Windows session"
            )

        return bool(
            self._invoke(
                "initialize",
                self._bindings.initialize,
                path=str(self._terminal_path),
                timeout=10_000,
                portable=False,
            )
        )

    def version(self) -> object:
        return self._invoke(
            "version",
            self._bindings.version,
        )

    def shutdown(self) -> None:
        self._invoke(
            "shutdown",
            self._bindings.shutdown,
        )

    def account_snapshot(self) -> AccountSnapshot:
        terminal = self._invoke(
            "terminal_info",
            self._bindings.terminal_info,
        )
        account = self._invoke(
            "account_info",
            self._bindings.account_info,
        )

        if terminal is None or account is None:
            raise self._error("account_info")

        trade_mode = int(account.trade_mode)
        kinds = {
            self._bindings.account_trade_mode_demo: AccountKind.DEMO,
            self._bindings.account_trade_mode_contest: AccountKind.CONTEST,
            self._bindings.account_trade_mode_real: AccountKind.REAL,
        }

        return AccountSnapshot(
            login=int(account.login),
            server=str(account.server),
            kind=kinds.get(trade_mode, AccountKind.UNKNOWN),
            equity=float(account.equity),
            balance=float(account.balance),
            connected=bool(terminal.connected),
            trade_allowed=bool(account.trade_allowed),
            terminal_trade_allowed=bool(
                getattr(terminal, "trade_allowed", False)
            ),
            currency=str(getattr(account, "currency", "UNKNOWN")),
            account_name=str(getattr(account, "name", "")) or None,
        )

    def symbol_snapshot(self, symbol: str) -> SymbolSnapshot:
        info = self._invoke(
            "symbol_info",
            self._bindings.symbol_info,
            symbol,
        )
        tick = self._invoke(
            "symbol_info_tick",
            self._bindings.symbol_info_tick,
            symbol,
        )

        if info is None or tick is None:
            raise self._error("symbol_info")

        tick_values = [
            abs(float(getattr(info, field, 0.0) or 0.0))
            for field in (
                "trade_tick_value",
                "trade_tick_value_profit",
                "trade_tick_value_loss",
            )
        ]
        tick_value = max(tick_values)

        raw_trade_mode = int(getattr(info, "trade_mode", -1))
        trade_modes = {
            self._bindings.symbol_trade_mode_disabled: "DISABLED",
            self._bindings.symbol_trade_mode_longonly: "LONG_ONLY",
            self._bindings.symbol_trade_mode_shortonly: "SHORT_ONLY",
            self._bindings.symbol_trade_mode_closeonly: "CLOSE_ONLY",
            self._bindings.symbol_trade_mode_full: "FULL",
        }

        return SymbolSnapshot(
            symbol=str(getattr(info, "name", symbol)),
            bid=float(tick.bid),
            ask=float(tick.ask),
            point=float(info.point),
            tick_size=float(info.trade_tick_size),
            tick_value=tick_value,
            volume_min=float(info.volume_min),
            volume_max=float(info.volume_max),
            volume_step=float(info.volume_step),
            trade_stops_level=int(info.trade_stops_level),
            visible=bool(info.visible),
            tick_time_msc=int(tick.time_msc),
            trade_freeze_level=int(
                getattr(info, "trade_freeze_level", 0)
            ),
            market_open=(
                raw_trade_mode
                != self._bindings.symbol_trade_mode_disabled
            ),
            trade_mode=trade_modes.get(
                raw_trade_mode,
                "UNKNOWN",
            ),
        )

    def candles(
        self,
        symbol: str,
        timeframe: str,
        count: int,
    ) -> list[CandleSnapshot]:
        if count < 1 or count > 500:
            raise MT5ReadOnlyDataError(
                "Candle count must be between 1 and 500"
            )

        timeframes = {
            "M1": self._bindings.timeframe_m1,
            "M5": self._bindings.timeframe_m5,
            "M15": self._bindings.timeframe_m15,
            "H1": self._bindings.timeframe_h1,
        }

        if timeframe not in timeframes:
            raise MT5ReadOnlyDataError(
                "Unsupported candle timeframe"
            )

        rates = self._invoke(
            "copy_rates_from_pos",
            self._bindings.copy_rates_from_pos,
            symbol,
            timeframes[timeframe],
            1,
            count,
        )

        if rates is None:
            raise self._error("copy_rates_from_pos")

        candles: list[CandleSnapshot] = []

        for rate in rates:
            def field(name: str):
                try:
                    return rate[name]
                except (KeyError, TypeError, IndexError):
                    return getattr(rate, name)

            values = [
                float(field(name))
                for name in ("open", "high", "low", "close")
            ]

            if not all(
                math.isfinite(value) and value > 0
                for value in values
            ):
                raise MT5ReadOnlyDataError(
                    "MT5 returned invalid candle values"
                )

            if (
                values[1] < max(values[0], values[3])
                or values[2] > min(values[0], values[3])
            ):
                raise MT5ReadOnlyDataError(
                    "MT5 returned inconsistent candle bounds"
                )

            candles.append(
                CandleSnapshot(
                    symbol=symbol,
                    timeframe=timeframe,
                    time_msc=int(field("time")) * 1000,
                    open=values[0],
                    high=values[1],
                    low=values[2],
                    close=values[3],
                    tick_volume=int(field("tick_volume")),
                    spread=int(field("spread")),
                )
            )

        return candles

    def positions(self) -> list[PositionSnapshot]:
        raw_positions = self._invoke(
            "positions_get",
            self._bindings.positions_get,
        )

        if raw_positions is None:
            raise self._error("positions_get")

        result: list[PositionSnapshot] = []

        for item in raw_positions:
            raw_type = int(item.type)

            if raw_type == self._bindings.order_type_buy:
                side = Side.BUY
            elif raw_type == self._bindings.order_type_sell:
                side = Side.SELL
            else:
                raise MT5ReadOnlyDataError(
                    f"Unknown MT5 position type: {item.type}"
                )

            raw_stop = float(item.sl)

            result.append(
                PositionSnapshot(
                    ticket=int(item.ticket),
                    symbol=str(item.symbol),
                    side=side,
                    volume=float(item.volume),
                    price_open=float(item.price_open),
                    stop_loss=raw_stop if raw_stop > 0 else None,
                    profit=float(item.profit),
                    magic_number=int(item.magic),
                )
            )

        return result

    def active_orders(self) -> list[ActiveOrderSnapshot]:
        raw_orders = self._invoke(
            "orders_get",
            self._bindings.orders_get,
        )

        if raw_orders is None:
            raise self._error("orders_get")

        return [
            ActiveOrderSnapshot(
                ticket=int(item.ticket),
                symbol=str(item.symbol),
                volume=float(item.volume_current),
                magic_number=int(item.magic),
            )
            for item in raw_orders
        ]

    def history(
        self,
        start: datetime,
        end: datetime,
        *,
        symbol: str | None = None,
        limit: int = 1000,
    ) -> list[DealSnapshot]:
        if (
            start.tzinfo is None
            or end.tzinfo is None
            or end <= start
        ):
            raise MT5ReadOnlyDataError(
                "History bounds must be ordered timezone-aware datetimes"
            )

        if limit < 1 or limit > 1000:
            raise MT5ReadOnlyDataError(
                "History limit must be between 1 and 1000"
            )

        deals = self._invoke(
            "history_deals_get",
            self._bindings.history_deals_get,
            start,
            end,
        )

        if deals is None:
            raise self._error("history_deals_get")

        entry_names = {
            self._bindings.deal_entry_in: "IN",
            self._bindings.deal_entry_out: "OUT",
            self._bindings.deal_entry_inout: "INOUT",
            self._bindings.deal_entry_out_by: "OUT_BY",
        }

        result: list[DealSnapshot] = []

        for deal in deals:
            deal_symbol = str(
                getattr(deal, "symbol", "")
            )

            if (
                symbol is not None
                and deal_symbol != symbol
            ):
                continue

            raw_type = int(
                getattr(deal, "type", -1)
            )

            side = (
                Side.BUY
                if raw_type == self._bindings.order_type_buy
                else Side.SELL
                if raw_type == self._bindings.order_type_sell
                else None
            )

            result.append(
                DealSnapshot(
                    ticket=int(
                        getattr(deal, "ticket", 0)
                    ),
                    order_id=int(
                        getattr(deal, "order", 0)
                    ),
                    position_id=int(
                        getattr(deal, "position_id", 0)
                    ),
                    symbol=deal_symbol,
                    side=side,
                    entry=entry_names.get(
                        int(getattr(deal, "entry", -1)),
                        "UNKNOWN",
                    ),
                    volume=float(
                        getattr(deal, "volume", 0.0)
                    ),
                    price=float(
                        getattr(deal, "price", 0.0)
                    ),
                    profit=float(
                        getattr(deal, "profit", 0.0)
                    ),
                    commission=float(
                        getattr(deal, "commission", 0.0)
                    ),
                    swap=float(
                        getattr(deal, "swap", 0.0)
                    ),
                    fee=float(
                        getattr(deal, "fee", 0.0)
                    ),
                    time_msc=int(
                        getattr(deal, "time_msc", 0)
                    ),
                    magic_number=int(
                        getattr(deal, "magic", 0)
                    ),
                )
            )

            if len(result) >= limit:
                break

        return result

    def daily_realized_pnl(self) -> float:
        now = datetime.now(UTC)
        start = now.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )

        deals = self._invoke(
            "history_deals_get",
            self._bindings.history_deals_get,
            start,
            now,
        )

        if deals is None:
            raise self._error("history_deals_get")

        closing_entries = {
            self._bindings.deal_entry_out,
            self._bindings.deal_entry_inout,
            self._bindings.deal_entry_out_by,
        }

        total = 0.0

        for deal in deals:
            profit = (
                float(deal.profit)
                if int(deal.entry) in closing_entries
                else 0.0
            )

            total += (
                profit
                + float(deal.commission)
                + float(deal.swap)
                + float(deal.fee)
            )

        if not math.isfinite(total):
            raise MT5ReadOnlyDataError(
                "Daily realized PnL is not finite"
            )

        return total


def load_mt5_read_only_data_adapter(
    terminal_path: Path,
    *,
    terminal_running_probe: Callable[[Path], bool] | None = None,
) -> MT5ReadOnlyDataAdapter:
    terminal_path = Path(terminal_path)

    probe = (
        terminal_running_probe
        or _terminal_is_visible_in_session
    )

    # Fail closed before MetaTrader5 is imported. This prevents
    # initialize() from implicitly starting an absent terminal.
    if not probe(terminal_path):
        raise MT5ReadOnlyDataError(
            "Configured MT5 terminal must already be visible "
            "in the current Windows session"
        )

    try:
        module = importlib.import_module("MetaTrader5")
    except ImportError as exc:
        raise MT5ReadOnlyDataError(
            "MetaTrader5 Python package is unavailable"
        ) from exc

    bindings = _bindings_from_module(module)

    adapter = MT5ReadOnlyDataAdapter(
        terminal_path,
        bindings,
        terminal_running_probe=probe,
    )
    adapter.assert_read_only_boundary()
    return adapter
