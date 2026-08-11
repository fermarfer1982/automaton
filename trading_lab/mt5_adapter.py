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
        )

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
