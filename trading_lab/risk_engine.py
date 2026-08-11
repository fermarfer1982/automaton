from __future__ import annotations

import hashlib
import json
import math
import time
from decimal import Decimal, InvalidOperation
from collections.abc import Sequence

from .config import RiskLimits
from .domain import (
    AccountSnapshot,
    ActiveOrderSnapshot,
    CheckResult,
    GuardDecision,
    PositionSnapshot,
    Side,
    SymbolSnapshot,
    TradeProposal,
)


class RiskEngine:
    """Pure deterministic risk policy with no model or network dependency."""

    def __init__(self, allowed_symbol: str, required_magic_number: int, limits: RiskLimits) -> None:
        self._allowed_symbol = allowed_symbol
        self._required_magic_number = required_magic_number
        self._limits = limits

    @property
    def duplicate_window_seconds(self) -> int:
        return self._limits.duplicate_window_seconds

    @staticmethod
    def fingerprint(proposal: TradeProposal) -> str:
        material = {
            "strategy_id": proposal.strategy_id,
            "setup_id": proposal.setup_id,
            "strategy_version": proposal.strategy_version,
            "symbol": proposal.symbol,
            "side": proposal.side.value,
            "volume": proposal.volume,
            "stop_loss": proposal.stop_loss,
            "take_profit": proposal.take_profit,
            "position_management": proposal.position_management,
        }
        canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _aligned_to_step(volume: float, minimum: float, step: float) -> bool:
        try:
            units = (Decimal(str(volume)) - Decimal(str(minimum))) / Decimal(str(step))
        except (InvalidOperation, ZeroDivisionError):
            return False
        return units == units.to_integral_value()

    def evaluate(
        self,
        *,
        proposal: TradeProposal,
        account: AccountSnapshot,
        market: SymbolSnapshot,
        positions: list[PositionSnapshot],
        daily_realized_pnl: float,
        duplicate: bool,
        active_orders: Sequence[ActiveOrderSnapshot] = (),
        now_msc: int | None = None,
    ) -> GuardDecision:
        checks: list[CheckResult] = []

        def add(code: str, passed: bool, detail: str) -> None:
            checks.append(CheckResult(code, bool(passed), detail))

        add("SYMBOL_NOT_ALLOWED", proposal.symbol == self._allowed_symbol, "Only XAUUSD is allowed")
        add("MARKET_SYMBOL_MISMATCH", market.symbol == proposal.symbol, "Market data must match proposal symbol")
        add("SYMBOL_NOT_VISIBLE", market.visible, "Symbol must already be visible in MT5")
        add(
            "MAGIC_NUMBER_MISMATCH",
            proposal.magic_number == self._required_magic_number,
            "Magic number must match protected configuration",
        )
        add(
            "POSITION_MANAGEMENT_FORBIDDEN",
            proposal.position_management == "SINGLE_ENTRY",
            "Martingale, grid, averaging down, and multi-entry management are forbidden",
        )
        add("DUPLICATE_PROPOSAL", not duplicate, "Equivalent recent proposal must not be repeated")
        add(
            "ACTIVE_ORDERS_PRESENT",
            len(active_orders) == 0,
            "Pending/active orders must be absent before a new market proposal",
        )

        finite_volume = math.isfinite(proposal.volume) and proposal.volume > 0
        add("VOLUME_INVALID", finite_volume, "Volume must be finite and positive")
        add(
            "VOLUME_LIMIT_EXCEEDED",
            finite_volume and proposal.volume <= min(self._limits.max_volume, market.volume_max),
            "Volume exceeds configured or broker maximum",
        )
        add(
            "VOLUME_BELOW_MINIMUM",
            finite_volume and proposal.volume >= market.volume_min,
            "Volume is below broker minimum",
        )
        add(
            "VOLUME_STEP_MISMATCH",
            finite_volume and self._aligned_to_step(proposal.volume, market.volume_min, market.volume_step),
            "Volume must align to broker step",
        )

        valid_market = all(
            math.isfinite(value) and value > 0
            for value in (market.bid, market.ask, market.point, market.tick_size, market.tick_value)
        ) and market.ask >= market.bid
        add("MARKET_DATA_INVALID", valid_market, "Bid, ask, point and tick economics must be valid")
        current_msc = int(time.time() * 1000) if now_msc is None else now_msc
        tick_age_msc = current_msc - market.tick_time_msc
        add(
            "MARKET_TICK_STALE",
            -2_000 <= tick_age_msc <= int(self._limits.max_tick_age_seconds * 1000),
            "Latest MT5 tick is stale or implausibly in the future",
        )
        spread_points = (market.ask - market.bid) / market.point if valid_market else math.inf
        add(
            "SPREAD_TOO_WIDE",
            valid_market and spread_points <= self._limits.max_spread_points,
            "Current spread exceeds deterministic limit",
        )

        entry = market.ask if proposal.side is Side.BUY else market.bid
        stop = proposal.stop_loss
        valid_stop = stop is not None and math.isfinite(stop) and stop > 0
        add("STOP_LOSS_REQUIRED", valid_stop, "A finite positive stop loss is mandatory")
        stop_correct_side = valid_stop and (
            (proposal.side is Side.BUY and stop < entry)
            or (proposal.side is Side.SELL and stop > entry)
        )
        add("STOP_LOSS_WRONG_SIDE", stop_correct_side, "Stop loss must be beyond entry on the loss side")
        stop_distance_points = abs(entry - stop) / market.point if valid_market and valid_stop else 0.0
        minimum_stop_points = max(self._limits.min_stop_distance_points, market.trade_stops_level)
        add(
            "STOP_DISTANCE_TOO_SMALL",
            stop_correct_side and stop_distance_points >= minimum_stop_points,
            "Stop distance is below configured or broker minimum",
        )

        take_profit = proposal.take_profit
        valid_tp = take_profit is None or (math.isfinite(take_profit) and take_profit > 0)
        tp_correct_side = valid_tp and (
            take_profit is None
            or (proposal.side is Side.BUY and take_profit > entry)
            or (proposal.side is Side.SELL and take_profit < entry)
        )
        add("TAKE_PROFIT_INVALID", tp_correct_side, "Take profit, if present, must be on the profit side")

        estimated_risk = 0.0
        if valid_market and valid_stop and finite_volume:
            estimated_risk = abs(entry - stop) / market.tick_size * market.tick_value * proposal.volume
        risk_cap = account.equity * self._limits.max_risk_per_trade_fraction
        add(
            "RISK_PER_TRADE_EXCEEDED",
            math.isfinite(estimated_risk) and 0 < estimated_risk <= risk_cap,
            "Estimated stop risk exceeds configured equity fraction",
        )

        add(
            "OPEN_POSITION_LIMIT_REACHED",
            len(positions) < self._limits.max_open_positions,
            "Maximum open position count reached",
        )
        same_symbol = [position for position in positions if position.symbol == proposal.symbol]
        add(
            "EXISTING_SYMBOL_POSITION",
            not same_symbol,
            "Only one entry per symbol is allowed; prevents grid and averaging down",
        )
        exposure = sum(position.volume for position in same_symbol) + (proposal.volume if finite_volume else 0.0)
        add(
            "SYMBOL_EXPOSURE_EXCEEDED",
            exposure <= self._limits.max_symbol_exposure_lots,
            "Symbol lot exposure exceeds configured cap",
        )
        daily_loss_cap = account.balance * self._limits.max_daily_loss_fraction
        add(
            "DAILY_LOSS_LIMIT_REACHED",
            math.isfinite(daily_realized_pnl) and daily_realized_pnl > -daily_loss_cap,
            "Realized daily loss is at or beyond the configured cap",
        )
        return GuardDecision(checks=tuple(checks), estimated_risk_amount=estimated_risk)
