from __future__ import annotations

import importlib
import json
import math
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from types import ModuleType
from collections.abc import Callable
from typing import Any

from .domain import (
    AccountKind,
    AccountSnapshot,
    ActiveOrderSnapshot,
    CandleSnapshot,
    DealSnapshot,
    OrderCheckResult,
    OrderSendResult,
    PositionSnapshot,
    Side,
    SymbolSnapshot,
)


class MT5AdapterError(RuntimeError):
    pass


class MT5Adapter:
    """Narrow adapter over MetaTrader5; deliberately has no account-login operation."""

    def __init__(
        self,
        terminal_path: str | Path,
        *,
        module: ModuleType | Any | None = None,
        terminal_running_probe: Callable[[Path], bool] | None = None,
    ) -> None:
        self._terminal_path = Path(terminal_path)
        self._mt5 = module
        self._terminal_running_probe = terminal_running_probe or self._terminal_is_visible_in_session

    @staticmethod
    def _terminal_is_visible_in_session(terminal_path: Path) -> bool:
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if powershell is None:
            return False
        script = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$requested = [System.IO.Path]::GetFullPath([Console]::In.ReadToEnd().Trim())
$sessionId = (Get-Process -Id $PID).SessionId
$name = [System.IO.Path]::GetFileNameWithoutExtension($requested)
$matched = $false
foreach ($process in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
  try {
    if ($process.SessionId -eq $sessionId -and $process.MainWindowHandle -ne 0 -and
        [string]::Equals([System.IO.Path]::GetFullPath($process.Path), $requested,
          [System.StringComparison]::OrdinalIgnoreCase)) {
      $matched = $true
    }
  } catch { }
}
$matched | ConvertTo-Json -Compress
"""
        try:
            completed = subprocess.run(
                [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                input=str(terminal_path.resolve()),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
            return completed.returncode == 0 and json.loads(completed.stdout) is True
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return False

    def _module(self):
        if self._mt5 is None:
            try:
                self._mt5 = importlib.import_module("MetaTrader5")
            except ImportError as exc:
                raise MT5AdapterError("MetaTrader5 Python package is unavailable") from exc
        return self._mt5

    def _error(self, operation: str) -> MT5AdapterError:
        try:
            code, message = self._module().last_error()
            return MT5AdapterError(f"{operation} failed with MT5 error {code}: {message}")
        except Exception:
            return MT5AdapterError(f"{operation} failed")

    def initialize(self) -> bool:
        if not self._terminal_running_probe(self._terminal_path):
            raise MT5AdapterError(
                "Configured MT5 terminal must already be visible in the current Windows session"
            )
        mt5 = self._module()
        # Supplying only the exact terminal path cannot select a different account.
        return bool(mt5.initialize(path=str(self._terminal_path), timeout=10_000, portable=False))

    def shutdown(self) -> None:
        self._module().shutdown()

    def account_snapshot(self) -> AccountSnapshot:
        mt5 = self._module()
        terminal = mt5.terminal_info()
        account = mt5.account_info()
        if terminal is None or account is None:
            raise self._error("account_info")
        trade_mode = int(account.trade_mode)
        kinds = {
            int(mt5.ACCOUNT_TRADE_MODE_DEMO): AccountKind.DEMO,
            int(mt5.ACCOUNT_TRADE_MODE_CONTEST): AccountKind.CONTEST,
            int(mt5.ACCOUNT_TRADE_MODE_REAL): AccountKind.REAL,
        }
        return AccountSnapshot(
            login=int(account.login),
            server=str(account.server),
            kind=kinds.get(trade_mode, AccountKind.UNKNOWN),
            equity=float(account.equity),
            balance=float(account.balance),
            connected=bool(terminal.connected),
            trade_allowed=bool(account.trade_allowed),
            terminal_trade_allowed=bool(getattr(terminal, "trade_allowed", False)),
            currency=str(getattr(account, "currency", "UNKNOWN")),
            account_name=str(getattr(account, "name", "")) or None,
        )

    def symbol_snapshot(self, symbol: str) -> SymbolSnapshot:
        mt5 = self._module()
        info = mt5.symbol_info(symbol)
        tick = mt5.symbol_info_tick(symbol)
        if info is None or tick is None:
            raise self._error("symbol_info")
        tick_values = [
            abs(float(getattr(info, field, 0.0) or 0.0))
            for field in ("trade_tick_value", "trade_tick_value_profit", "trade_tick_value_loss")
        ]
        tick_value = max(tick_values)
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
            trade_freeze_level=int(getattr(info, "trade_freeze_level", 0)),
            market_open=int(getattr(info, "trade_mode", 0))
            != int(getattr(mt5, "SYMBOL_TRADE_MODE_DISABLED", -1)),
        )

    def candles(self, symbol: str, timeframe: str, count: int) -> list[CandleSnapshot]:
        if count < 1 or count > 500:
            raise MT5AdapterError("Candle count must be between 1 and 500")
        mt5 = self._module()
        timeframes = {
            "M1": mt5.TIMEFRAME_M1,
            "M5": mt5.TIMEFRAME_M5,
            "M15": mt5.TIMEFRAME_M15,
            "H1": mt5.TIMEFRAME_H1,
        }
        if timeframe not in timeframes:
            raise MT5AdapterError("Unsupported candle timeframe")
        # Position zero is the still-forming bar; the laboratory consumes only closed bars.
        rates = mt5.copy_rates_from_pos(symbol, timeframes[timeframe], 1, count)
        if rates is None:
            raise self._error("copy_rates_from_pos")
        candles: list[CandleSnapshot] = []
        for rate in rates:
            def field(name: str):
                try:
                    return rate[name]
                except (KeyError, TypeError, IndexError):
                    return getattr(rate, name)

            values = [float(field(name)) for name in ("open", "high", "low", "close")]
            if not all(math.isfinite(value) and value > 0 for value in values):
                raise MT5AdapterError("MT5 returned invalid candle values")
            if values[1] < max(values[0], values[3]) or values[2] > min(values[0], values[3]):
                raise MT5AdapterError("MT5 returned inconsistent candle bounds")
            candles.append(CandleSnapshot(
                symbol=symbol,
                timeframe=timeframe,
                time_msc=int(field("time")) * 1000,
                open=values[0],
                high=values[1],
                low=values[2],
                close=values[3],
                tick_volume=int(field("tick_volume")),
                spread=int(field("spread")),
            ))
        return candles

    def order_calc_profit(
        self,
        side: Side,
        symbol: str,
        volume: float,
        price_open: float,
        price_close: float,
    ) -> float:
        mt5 = self._module()
        order_type = mt5.ORDER_TYPE_BUY if side is Side.BUY else mt5.ORDER_TYPE_SELL
        result = mt5.order_calc_profit(order_type, symbol, volume, price_open, price_close)
        if result is None:
            raise self._error("order_calc_profit")
        profit = float(result)
        if not math.isfinite(profit):
            raise MT5AdapterError("order_calc_profit returned a non-finite value")
        return profit

    def positions(self) -> list[PositionSnapshot]:
        mt5 = self._module()
        raw_positions = mt5.positions_get()
        if raw_positions is None:
            raise self._error("positions_get")
        positions: list[PositionSnapshot] = []
        for item in raw_positions:
            if int(item.type) == int(mt5.ORDER_TYPE_BUY):
                side = Side.BUY
            elif int(item.type) == int(mt5.ORDER_TYPE_SELL):
                side = Side.SELL
            else:
                raise MT5AdapterError(f"Unknown MT5 position type: {item.type}")
            raw_stop = float(item.sl)
            positions.append(
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
        return positions

    def active_orders(self) -> list[ActiveOrderSnapshot]:
        raw_orders = self._module().orders_get()
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
        if start.tzinfo is None or end.tzinfo is None or end <= start:
            raise MT5AdapterError("History bounds must be ordered timezone-aware datetimes")
        if limit < 1 or limit > 1000:
            raise MT5AdapterError("History limit must be between 1 and 1000")
        mt5 = self._module()
        deals = mt5.history_deals_get(start, end)
        if deals is None:
            raise self._error("history_deals_get")
        result: list[DealSnapshot] = []
        entry_names = {
            int(getattr(mt5, "DEAL_ENTRY_IN", 0)): "IN",
            int(mt5.DEAL_ENTRY_OUT): "OUT",
            int(mt5.DEAL_ENTRY_INOUT): "INOUT",
            int(mt5.DEAL_ENTRY_OUT_BY): "OUT_BY",
        }
        for deal in deals:
            deal_symbol = str(getattr(deal, "symbol", ""))
            if symbol is not None and deal_symbol != symbol:
                continue
            raw_type = int(getattr(deal, "type", -1))
            side = (
                Side.BUY if raw_type == int(mt5.ORDER_TYPE_BUY)
                else Side.SELL if raw_type == int(mt5.ORDER_TYPE_SELL)
                else None
            )
            result.append(DealSnapshot(
                ticket=int(getattr(deal, "ticket", 0)),
                order_id=int(getattr(deal, "order", 0)),
                position_id=int(getattr(deal, "position_id", 0)),
                symbol=deal_symbol,
                side=side,
                entry=entry_names.get(int(getattr(deal, "entry", -1)), "UNKNOWN"),
                volume=float(getattr(deal, "volume", 0.0)),
                price=float(getattr(deal, "price", 0.0)),
                profit=float(getattr(deal, "profit", 0.0)),
                commission=float(getattr(deal, "commission", 0.0)),
                swap=float(getattr(deal, "swap", 0.0)),
                fee=float(getattr(deal, "fee", 0.0)),
                time_msc=int(getattr(deal, "time_msc", 0)),
                magic_number=int(getattr(deal, "magic", 0)),
            ))
            if len(result) >= limit:
                break
        return result

    def daily_realized_pnl(self) -> float:
        mt5 = self._module()
        now = datetime.now().astimezone()
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        deals = mt5.history_deals_get(start, now)
        if deals is None:
            raise self._error("history_deals_get")
        closing_entries = {
            int(mt5.DEAL_ENTRY_OUT),
            int(mt5.DEAL_ENTRY_INOUT),
            int(mt5.DEAL_ENTRY_OUT_BY),
        }
        total = 0.0
        for deal in deals:
            # Commissions/fees on entry deals also count toward the account-wide daily limit.
            profit = float(deal.profit) if int(deal.entry) in closing_entries else 0.0
            total += profit + float(deal.commission) + float(deal.swap) + float(deal.fee)
        if not math.isfinite(total):
            raise MT5AdapterError("Daily realized PnL is not finite")
        return total

    def _raw_request(self, request: dict[str, object]) -> dict[str, object]:
        mt5 = self._module()
        required = {
            "action", "symbol", "volume", "type", "price", "sl", "tp",
            "deviation", "magic", "comment", "type_time", "type_filling",
        }
        if set(request) != required:
            raise MT5AdapterError("Execution request fields do not match the protected schema")
        if request["action"] != "DEAL" or request["type_time"] != "GTC" or request["type_filling"] != "IOC":
            raise MT5AdapterError("Unsupported protected execution request mode")
        side = request["type"]
        if side == Side.BUY.value:
            order_type = mt5.ORDER_TYPE_BUY
        elif side == Side.SELL.value:
            order_type = mt5.ORDER_TYPE_SELL
        else:
            raise MT5AdapterError("Unsupported order side")
        return {
            **request,
            "action": mt5.TRADE_ACTION_DEAL,
            "type": order_type,
            "type_time": mt5.ORDER_TIME_GTC,
            "type_filling": mt5.ORDER_FILLING_IOC,
        }

    def order_check(self, request: dict[str, object]) -> OrderCheckResult:
        result = self._module().order_check(self._raw_request(request))
        if result is None:
            raise self._error("order_check")
        return OrderCheckResult(
            ok=int(result.retcode) == 0,
            retcode=int(result.retcode),
            comment=str(result.comment),
        )

    def order_send(self, request: dict[str, object]) -> OrderSendResult:
        mt5 = self._module()
        result = mt5.order_send(self._raw_request(request))
        if result is None:
            raise self._error("order_send")
        successful = {
            int(mt5.TRADE_RETCODE_PLACED),
            int(mt5.TRADE_RETCODE_DONE),
            int(mt5.TRADE_RETCODE_DONE_PARTIAL),
        }
        return OrderSendResult(
            ok=int(result.retcode) in successful,
            retcode=int(result.retcode),
            comment=str(result.comment),
            order_id=int(result.order) if getattr(result, "order", 0) else None,
            deal_id=int(result.deal) if getattr(result, "deal", 0) else None,
        )
