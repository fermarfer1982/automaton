from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .domain import OpenAction


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ProposeTradeBody(StrictModel):
    action: OpenAction
    symbol: Literal["XAUUSD"]
    entry_type: Literal["MARKET"]
    stop_loss: float = Field(gt=0)
    take_profit: float | None = Field(default=None, gt=0)
    requested_risk_amount: float = Field(gt=0)
    hypothesis_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    strategy_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    setup_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    strategy_version: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    confidence: float = Field(ge=0, le=1)
    reason: str = Field(min_length=1, max_length=4000)
    timeframe: Literal["M1", "M5", "M15", "H1"]
    market_regime: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


class ClosePositionBody(StrictModel):
    ticket: int = Field(gt=0)
    reason: str = Field(min_length=1, max_length=1000)


class ModifyPositionBody(StrictModel):
    ticket: int = Field(gt=0)
    stop_loss: float = Field(gt=0)
    take_profit: float | None = Field(default=None, gt=0)
    reason: str = Field(min_length=1, max_length=1000)


class CancelPendingBody(StrictModel):
    ticket: int = Field(gt=0)
    reason: str = Field(min_length=1, max_length=1000)


class DecisionBody(StrictModel):
    decision_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    action: Literal["HOLD", "PROPOSE"]
    symbol: Literal["XAUUSD"]
    timeframe: Literal["M1"]
    bar_time_utc: datetime
    reason: str = Field(min_length=1, max_length=4000)
    hypothesis_id: str | None = Field(default=None, max_length=128)

    @field_validator("bar_time_utc")
    @classmethod
    def timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("bar_time_utc must be timezone-aware")
        return value


class HypothesisBody(StrictModel):
    hypothesis_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    thesis: str = Field(min_length=1, max_length=4000)


class ReviewBody(StrictModel):
    review_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    trade_id: str = Field(min_length=1, max_length=128)
    expected: str = Field(min_length=1, max_length=4000)
    observed: str = Field(min_length=1, max_length=4000)
    errors: str = Field(max_length=4000)
    strengths: str = Field(max_length=4000)
    learning: str = Field(min_length=1, max_length=4000)
    hypothesis_effect: str = Field(min_length=1, max_length=1000)
