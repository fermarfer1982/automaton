from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .market_analysis import session_context
from .research_store import (
    ExperienceOutcomeRecord,
    MarketExperienceRecord,
    ResearchStore,
)


class MarketObservationSource(Protocol):
    def symbol_state(self, symbol: str) -> dict[str, Any]: ...

    def candles(
        self,
        symbol: str,
        timeframe: str,
        count: int,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class CollectorResult:
    experience_id: str
    bar_time_utc: str
    experience_created: bool
    outcomes_created: int


def _finite(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be numeric")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{field} must be finite")
    return number


def _sorted_candles(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or not rows:
        raise ValueError("Closed candle series is empty")
    ordered = sorted(rows, key=lambda item: int(item["time_msc"]))
    previous = None
    for row in ordered:
        timestamp = int(row["time_msc"])
        if timestamp <= 0 or timestamp == previous:
            raise ValueError("Closed candle timestamps are invalid")
        for field in ("open", "high", "low", "close"):
            _finite(row[field], field=field)
        if float(row["high"]) < float(row["low"]):
            raise ValueError("Closed candle high/low are invalid")
        previous = timestamp
    return ordered


def _ema(values: list[float], period: int) -> float | None:
    if period < 1 or len(values) < period:
        return None
    alpha = 2.0 / (period + 1.0)
    result = sum(values[:period]) / period
    for value in values[period:]:
        result = alpha * value + (1.0 - alpha) * result
    return result


def _rsi(values: list[float], period: int = 14) -> float | None:
    if len(values) < period + 1:
        return None
    changes = [
        current - previous
        for previous, current in zip(values, values[1:])
    ]
    seed = changes[:period]
    average_gain = sum(max(change, 0.0) for change in seed) / period
    average_loss = sum(max(-change, 0.0) for change in seed) / period
    for change in changes[period:]:
        gain = max(change, 0.0)
        loss = max(-change, 0.0)
        average_gain = (
            average_gain * (period - 1) + gain
        ) / period
        average_loss = (
            average_loss * (period - 1) + loss
        ) / period
    if average_loss == 0:
        return 100.0 if average_gain > 0 else 50.0
    relative_strength = average_gain / average_loss
    return 100.0 - (100.0 / (1.0 + relative_strength))


def _atr(rows: list[dict[str, Any]], period: int = 14) -> float | None:
    if len(rows) < period + 1:
        return None
    selected = rows[-period - 1:]
    true_ranges: list[float] = []
    for previous, current in zip(selected, selected[1:]):
        previous_close = float(previous["close"])
        high = float(current["high"])
        low = float(current["low"])
        true_ranges.append(
            max(
                high - low,
                abs(high - previous_close),
                abs(low - previous_close),
            )
        )
    return sum(true_ranges) / period


def _timeframe_features(
    rows: list[dict[str, Any]],
    *,
    point: float,
) -> dict[str, Any]:
    ordered = _sorted_candles(rows)
    closes = [float(row["close"]) for row in ordered]
    last = ordered[-1]
    last_close = closes[-1]
    window20 = ordered[-20:]
    high20 = max(float(row["high"]) for row in window20)
    low20 = min(float(row["low"]) for row in window20)
    atr14 = _atr(ordered, 14)

    def points(delta: float) -> float:
        return delta / point

    return {
        "bar_time_utc": datetime.fromtimestamp(
            int(last["time_msc"]) / 1000,
            UTC,
        ).isoformat(),
        "open": float(last["open"]),
        "high": float(last["high"]),
        "low": float(last["low"]),
        "close": last_close,
        "range_points": points(
            float(last["high"]) - float(last["low"])
        ),
        "return_1_points": (
            points(last_close - closes[-2])
            if len(closes) >= 2
            else None
        ),
        "return_3_points": (
            points(last_close - closes[-4])
            if len(closes) >= 4
            else None
        ),
        "return_12_points": (
            points(last_close - closes[-13])
            if len(closes) >= 13
            else None
        ),
        "ema9": _ema(closes, 9),
        "ema20": _ema(closes, 20),
        "ema50": _ema(closes, 50),
        "rsi14": _rsi(closes, 14),
        "atr14": atr14,
        "atr14_points": (
            points(atr14) if atr14 is not None else None
        ),
        "rolling_high_20": high20,
        "rolling_low_20": low20,
        "distance_to_high_20_points": points(high20 - last_close),
        "distance_to_low_20_points": points(last_close - low20),
    }


class MarketExperienceCollector:
    """Closed-bar evidence collector with no MT5 execution capability."""

    HORIZONS = (5, 15, 60)

    def __init__(
        self,
        observation: MarketObservationSource,
        store: ResearchStore,
        *,
        symbol: str = "XAUUSD",
    ) -> None:
        if symbol != "XAUUSD":
            raise ValueError("Collector permits only XAUUSD")
        self._observation = observation
        self._store = store
        self._symbol = symbol

    @staticmethod
    def _experience_id(time_msc: int) -> str:
        material = f"XAUUSD|M1|{time_msc}".encode("utf-8")
        return "exp:" + hashlib.sha256(material).hexdigest()

    def _closed_candles(
        self,
        timeframe: str,
        count: int,
    ) -> list[dict[str, Any]]:
        payload = self._observation.candles(
            self._symbol,
            timeframe,
            count,
        )
        if (
            not isinstance(payload, dict)
            or payload.get("symbol") != self._symbol
            or payload.get("timeframe") != timeframe
            or payload.get("execution_capable") is not False
            or not isinstance(payload.get("candles"), list)
        ):
            raise RuntimeError("Observation candle boundary is invalid")
        return _sorted_candles(payload["candles"])

    def _complete_outcomes(
        self,
        m1: list[dict[str, Any]],
    ) -> int:
        by_time = {
            int(row["time_msc"]): row
            for row in m1
        }
        created = 0

        for experience in self._store.pending_market_experiences(
            limit=1000
        ):
            base = datetime.fromisoformat(
                str(experience["bar_time_utc"])
            ).astimezone(UTC)
            base_msc = int(base.timestamp() * 1000)
            existing = {
                int(row["horizon_minutes"])
                for row in self._store.experience_outcomes(
                    str(experience["experience_id"])
                )
            }

            for horizon in self.HORIZONS:
                if horizon in existing:
                    continue

                target_msc = base_msc + horizon * 60_000
                if target_msc not in by_time:
                    continue

                expected_times = [
                    base_msc + minute * 60_000
                    for minute in range(1, horizon + 1)
                ]
                if any(item not in by_time for item in expected_times):
                    continue

                window = [by_time[item] for item in expected_times]
                target = by_time[target_msc]

                try:
                    self._store.record_experience_outcome(
                        ExperienceOutcomeRecord(
                            experience_id=str(
                                experience["experience_id"]
                            ),
                            horizon_minutes=horizon,
                            future_bar_time_utc=datetime.fromtimestamp(
                                target_msc / 1000,
                                UTC,
                            ),
                            future_close=float(target["close"]),
                            window_high=max(
                                float(row["high"])
                                for row in window
                            ),
                            window_low=min(
                                float(row["low"])
                                for row in window
                            ),
                        )
                    )
                except FileExistsError:
                    continue
                created += 1

        return created

    def collect_once(
        self,
        *,
        now: datetime | None = None,
    ) -> CollectorResult:
        timestamp = (now or datetime.now(UTC)).astimezone(UTC)
        market = self._observation.symbol_state(self._symbol)
        if (
            not isinstance(market, dict)
            or market.get("symbol") != self._symbol
        ):
            raise RuntimeError("Observation symbol boundary is invalid")

        point = _finite(market.get("point"), field="point")
        bid = _finite(market.get("bid"), field="bid")
        ask = _finite(market.get("ask"), field="ask")
        if point <= 0 or bid <= 0 or ask < bid:
            raise RuntimeError("Observed market economics are invalid")

        m1 = self._closed_candles("M1", 500)
        m5 = self._closed_candles("M5", 200)
        m15 = self._closed_candles("M15", 200)
        h1 = self._closed_candles("H1", 200)

        latest = m1[-1]
        bar_msc = int(latest["time_msc"])
        bar_time = datetime.fromtimestamp(bar_msc / 1000, UTC)
        if bar_time >= timestamp:
            raise RuntimeError("Latest closed M1 bar is not in the past")

        closed_spread = latest.get("spread")
        if (
            isinstance(closed_spread, (int, float))
            and not isinstance(closed_spread, bool)
            and math.isfinite(float(closed_spread))
            and float(closed_spread) >= 0
        ):
            spread_points = float(closed_spread)
            spread_source = "CLOSED_M1"
        else:
            spread_points = (ask - bid) / point
            spread_source = "LIVE_TICK_FALLBACK"

        context = session_context(
            bar_time + timedelta(minutes=1)
        )
        def available_by_reference(
            rows: list[dict[str, Any]],
        ) -> list[dict[str, Any]]:
            selected = [
                row for row in rows
                if int(row["time_msc"]) <= bar_msc
            ]
            if not selected:
                raise RuntimeError(
                    "Higher-timeframe closed history is unavailable "
                    "at the M1 reference time"
                )
            return selected

        features = {
            "feature_version": 1,
            "closed_bar_only": True,
            "no_lookahead": True,
            "spread_source": spread_source,
            "weekday_utc": bar_time.weekday(),
            "hour_utc": bar_time.hour,
            "session": context,
            "timeframes": {
                "M1": _timeframe_features(m1, point=point),
                "M5": _timeframe_features(
                    available_by_reference(m5),
                    point=point,
                ),
                "M15": _timeframe_features(
                    available_by_reference(m15),
                    point=point,
                ),
                "H1": _timeframe_features(
                    available_by_reference(h1),
                    point=point,
                ),
            },
        }

        experience_id = self._experience_id(bar_msc)
        created = True
        try:
            self._store.record_market_experience(
                MarketExperienceRecord(
                    experience_id=experience_id,
                    symbol=self._symbol,
                    timeframe="M1",
                    bar_time_utc=bar_time,
                    reference_price=float(latest["close"]),
                    point=point,
                    spread_points=spread_points,
                    session=str(context["primary"]),
                    features=features,
                )
            )
        except FileExistsError:
            created = False

        outcomes_created = self._complete_outcomes(m1)

        return CollectorResult(
            experience_id=experience_id,
            bar_time_utc=bar_time.isoformat(),
            experience_created=created,
            outcomes_created=outcomes_created,
        )
