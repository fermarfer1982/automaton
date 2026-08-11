from __future__ import annotations

import math

from .domain import CheckResult, GuardDecision, PositionSnapshot, Side, SymbolSnapshot


class PositionManagementRiskEngine:
    """Pure rules for full exits and risk-reducing protective-order changes."""

    def __init__(self, allowed_symbol: str, required_magic_number: int) -> None:
        self._allowed_symbol = allowed_symbol
        self._required_magic_number = required_magic_number

    def evaluate_position(
        self,
        action: str,
        position: PositionSnapshot,
        market: SymbolSnapshot,
        *,
        stop_loss: float | None = None,
        take_profit: float | None = None,
        paper: bool = False,
    ) -> GuardDecision:
        checks: list[CheckResult] = []

        def add(code: str, passed: bool, detail: str) -> None:
            checks.append(CheckResult(code, bool(passed), detail))

        add(
            "POSITION_NOT_OWNED",
            position.symbol == self._allowed_symbol
            and (paper or position.magic_number == self._required_magic_number),
            "Only the laboratory's XAUUSD position may be managed",
        )
        add(
            "MARKET_SYMBOL_MISMATCH",
            market.symbol == position.symbol,
            "Current market data must match the position symbol",
        )
        valid_market = (
            market.visible
            and market.market_open
            and all(math.isfinite(value) and value > 0 for value in (
                market.bid, market.ask, market.point,
            ))
            and market.ask >= market.bid
        )
        add("MARKET_DATA_INVALID", valid_market, "Fresh visible open-market data is required")
        if action == "CLOSE":
            return GuardDecision(tuple(checks))
        if action != "MODIFY":
            add("MANAGEMENT_ACTION_INVALID", False, "Unsupported position management action")
            return GuardDecision(tuple(checks))

        valid_stop = stop_loss is not None and math.isfinite(stop_loss) and stop_loss > 0
        add("STOP_LOSS_REQUIRED", valid_stop, "Modification requires a finite positive stop loss")
        if position.stop_loss is None:
            risk_reducing = valid_stop
        elif position.side is Side.BUY:
            risk_reducing = valid_stop and stop_loss >= position.stop_loss
        else:
            risk_reducing = valid_stop and stop_loss <= position.stop_loss
        add(
            "STOP_LOSS_WIDENING_FORBIDDEN",
            risk_reducing,
            "A stop may only be added or moved toward reduced risk",
        )
        correct_side = valid_market and valid_stop and (
            (position.side is Side.BUY and stop_loss < market.bid)
            or (position.side is Side.SELL and stop_loss > market.ask)
        )
        add("STOP_LOSS_WRONG_SIDE", correct_side, "Stop must remain beyond the current loss-side quote")
        distance = (
            abs((market.bid if position.side is Side.BUY else market.ask) - stop_loss) / market.point
            if correct_side else 0.0
        )
        minimum = max(market.trade_stops_level, market.trade_freeze_level)
        add(
            "STOP_OR_FREEZE_LEVEL",
            correct_side and distance >= minimum,
            "Stop modification violates the broker stop/freeze level",
        )
        valid_tp = take_profit is None or (
            math.isfinite(take_profit)
            and take_profit > 0
            and (
                (position.side is Side.BUY and take_profit > market.ask)
                or (position.side is Side.SELL and take_profit < market.bid)
            )
        )
        add("TAKE_PROFIT_INVALID", valid_tp, "Take profit must remain on the profit side")
        return GuardDecision(tuple(checks))

    def evaluate_order(self, order, *, paper: bool = False) -> GuardDecision:
        return GuardDecision((CheckResult(
            "ORDER_NOT_OWNED",
            order.symbol == self._allowed_symbol
            and (paper or order.magic_number == self._required_magic_number),
            "Only the laboratory's XAUUSD pending order may be cancelled",
        ),))
