from __future__ import annotations

import math
from decimal import Decimal, ROUND_FLOOR
from typing import Protocol

from .config import RiskLimits
from .domain import AccountSnapshot, PositionSizeResult, Side, SymbolSnapshot


class ProfitCalculator(Protocol):
    def order_calc_profit(
        self,
        side: Side,
        symbol: str,
        volume: float,
        price_open: float,
        price_close: float,
    ) -> float: ...


class PositionSizer:
    """Deterministically turns monetary risk into broker-aligned volume."""

    def __init__(self, calculator: ProfitCalculator, limits: RiskLimits) -> None:
        self._calculator = calculator
        self._limits = limits

    @staticmethod
    def _floor_volume(cap: float, minimum: float, step: float) -> float | None:
        if not all(math.isfinite(value) and value > 0 for value in (cap, minimum, step)):
            return None
        if cap < minimum:
            return None
        cap_d = Decimal(str(cap))
        minimum_d = Decimal(str(minimum))
        step_d = Decimal(str(step))
        units = ((cap_d - minimum_d) / step_d).to_integral_value(rounding=ROUND_FLOOR)
        return float(minimum_d + units * step_d)

    def size(
        self,
        *,
        side: Side,
        requested_risk_amount: float,
        stop_loss: float,
        account: AccountSnapshot,
        market: SymbolSnapshot,
    ) -> PositionSizeResult:
        allowed_risk = min(
            account.equity * self._limits.max_risk_per_trade_fraction,
            self._limits.max_risk_per_trade_amount,
        )
        if (
            not math.isfinite(requested_risk_amount)
            or requested_risk_amount <= 0
            or requested_risk_amount > allowed_risk
        ):
            return PositionSizeResult(
                False,
                requested_risk_amount,
                allowed_risk,
                None,
                0.0,
                "DENIED_RISK_LIMIT",
                "Requested risk exceeds the deterministic dual cap",
            )
        entry = market.ask if side is Side.BUY else market.bid
        try:
            one_lot_loss = abs(float(self._calculator.order_calc_profit(
                side, market.symbol, 1.0, entry, stop_loss
            )))
        except Exception:
            one_lot_loss = math.nan
        if not math.isfinite(one_lot_loss) or one_lot_loss <= 0:
            return PositionSizeResult(
                False,
                requested_risk_amount,
                allowed_risk,
                None,
                0.0,
                "DENIED_PROFIT_CALCULATION",
                "MT5 could not calculate a finite one-lot stop loss",
            )
        raw_volume = requested_risk_amount / one_lot_loss
        volume_cap = min(
            raw_volume,
            self._limits.max_volume,
            self._limits.max_symbol_exposure_lots,
            market.volume_max,
        )
        volume = self._floor_volume(volume_cap, market.volume_min, market.volume_step)
        if volume is None:
            return PositionSizeResult(
                False,
                requested_risk_amount,
                allowed_risk,
                None,
                0.0,
                "DENIED_VOLUME_BELOW_MINIMUM",
                "Safe calculated volume is below the broker minimum",
            )
        estimated_risk = one_lot_loss * volume
        return PositionSizeResult(
            True,
            requested_risk_amount,
            allowed_risk,
            volume,
            estimated_risk,
            detail="Volume calculated and rounded down by the gateway",
        )
