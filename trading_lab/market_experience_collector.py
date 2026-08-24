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
        *,
        start_pos: int = 1,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class CollectorResult:
    experience_id: str
    bar_time_utc: str
    experience_created: bool
    outcomes_created: int
    backfill_experiences_created: int = 0


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
    MAX_BACKFILL_PER_CYCLE = 120
    FEATURE_VERSION = 2
    CANDLE_PAGE_SIZE = 500
    HISTORICAL_TARGET_M1_BARS = 30_000
    HISTORICAL_WARMUP_BARS = 60
    TIMEFRAME_MINUTES = {
        "M1": 1,
        "M5": 5,
        "M15": 15,
        "H1": 60,
    }

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
        self._historical_cache: dict[
            str,
            list[dict[str, Any]],
        ] | None = None
        self._historical_backfill_complete = False

    @classmethod
    def _experience_id(cls, time_msc: int) -> str:
        material = (
            f"XAUUSD|M1|v{cls.FEATURE_VERSION}|{time_msc}"
        ).encode("utf-8")
        return "exp:" + hashlib.sha256(material).hexdigest()

    def _closed_candles(
        self,
        timeframe: str,
        count: int,
        *,
        start_pos: int = 1,
    ) -> list[dict[str, Any]]:
        if start_pos == 1:
            payload = self._observation.candles(
                self._symbol,
                timeframe,
                count,
            )
        else:
            payload = self._observation.candles(
                self._symbol,
                timeframe,
                count,
                start_pos=start_pos,
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

    def _closed_candles_paged(
        self,
        timeframe: str,
        total_count: int,
    ) -> list[dict[str, Any]]:
        if total_count < 1:
            raise ValueError(
                "Paged candle count must be positive"
            )

        collected: list[dict[str, Any]] = []
        start_pos = 1
        remaining = total_count

        while remaining > 0:
            request_count = min(
                self.CANDLE_PAGE_SIZE,
                remaining,
            )
            page = self._closed_candles(
                timeframe,
                request_count,
                start_pos=start_pos,
            )
            collected.extend(page)

            if len(page) < request_count:
                break

            start_pos += request_count
            remaining -= request_count

        by_time = {
            int(row["time_msc"]): row
            for row in collected
        }

        return _sorted_candles(
            list(by_time.values())
        )

    def _historical_counts(
        self,
    ) -> dict[str, int]:
        target = self.HISTORICAL_TARGET_M1_BARS
        warmup = self.HISTORICAL_WARMUP_BARS

        return {
            "M1": target + warmup,
            "M5": math.ceil(target / 5) + warmup,
            "M15": math.ceil(target / 15) + warmup,
            "H1": math.ceil(target / 60) + warmup,
        }

    def _ensure_historical_cache(
        self,
    ) -> dict[str, list[dict[str, Any]]]:
        if self._historical_cache is None:
            counts = self._historical_counts()
            self._historical_cache = {
                timeframe: self._closed_candles_paged(
                    timeframe,
                    count,
                )
                for timeframe, count in counts.items()
            }

        return self._historical_cache

    @staticmethod
    def _merge_histories(
        older: list[dict[str, Any]],
        recent: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        by_time = {
            int(row["time_msc"]): row
            for row in older
        }
        by_time.update({
            int(row["time_msc"]): row
            for row in recent
        })
        return _sorted_candles(
            list(by_time.values())
        )

    def _complete_outcomes(
        self,
        m1: list[dict[str, Any]],
    ) -> int:
        by_time = {
            int(row["time_msc"]): row
            for row in m1
        }
        if not by_time:
            return 0

        available_times = sorted(by_time)
        available_start = datetime.fromtimestamp(
            available_times[0] / 1000,
            UTC,
        )
        available_end = datetime.fromtimestamp(
            available_times[-1] / 1000,
            UTC,
        )
        created = 0

        for experience in self._store.pending_market_experiences(
            limit=1000,
            feature_version=self.FEATURE_VERSION,
            start_utc=available_start,
            end_utc=available_end,
            newest_first=True,
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

    def _record_experience_for_bar(
        self,
        *,
        row: dict[str, Any],
        m1: list[dict[str, Any]],
        m5: list[dict[str, Any]],
        m15: list[dict[str, Any]],
        h1: list[dict[str, Any]],
        point: float,
        bid: float,
        ask: float,
        allow_live_spread_fallback: bool,
    ) -> bool:
        bar_msc = int(row["time_msc"])
        bar_time = datetime.fromtimestamp(
            bar_msc / 1000,
            UTC,
        )
        experience_id = self._experience_id(bar_msc)
        reference_end_msc = bar_msc + 60_000

        closed_spread = row.get("spread")
        if (
            isinstance(closed_spread, (int, float))
            and not isinstance(closed_spread, bool)
            and math.isfinite(float(closed_spread))
            and float(closed_spread) >= 0
        ):
            spread_points = float(closed_spread)
            spread_source = "CLOSED_M1"
        elif allow_live_spread_fallback:
            spread_points = (ask - bid) / point
            spread_source = "LIVE_TICK_FALLBACK"
        else:
            return False

        context = session_context(
            bar_time + timedelta(minutes=1)
        )

        def available_by_reference(
            rows: list[dict[str, Any]],
            timeframe: str,
        ) -> list[dict[str, Any]]:
            duration_minutes = self.TIMEFRAME_MINUTES[
                timeframe
            ]
            duration_msc = duration_minutes * 60_000

            selected = [
                item
                for item in rows
                if (
                    int(item["time_msc"])
                    + duration_msc
                    <= reference_end_msc
                )
            ]
            if not selected:
                raise RuntimeError(
                    "Closed history is unavailable "
                    "at the M1 reference time"
                )
            return selected

        features = {
            "feature_version": self.FEATURE_VERSION,
            "reference_time_utc": (
                bar_time + timedelta(minutes=1)
            ).isoformat(),
            "closed_bar_only": True,
            "no_lookahead": True,
            "spread_source": spread_source,
            "weekday_utc": bar_time.weekday(),
            "hour_utc": bar_time.hour,
            "session": context,
            "timeframes": {
                "M1": _timeframe_features(
                    available_by_reference(m1, "M1"),
                    point=point,
                ),
                "M5": _timeframe_features(
                    available_by_reference(m5, "M5"),
                    point=point,
                ),
                "M15": _timeframe_features(
                    available_by_reference(m15, "M15"),
                    point=point,
                ),
                "H1": _timeframe_features(
                    available_by_reference(h1, "H1"),
                    point=point,
                ),
            },
        }

        try:
            self._store.record_market_experience(
                MarketExperienceRecord(
                    experience_id=experience_id,
                    symbol=self._symbol,
                    timeframe="M1",
                    bar_time_utc=bar_time,
                    reference_price=float(row["close"]),
                    point=point,
                    spread_points=spread_points,
                    session=str(context["primary"]),
                    features=features,
                    feature_version=self.FEATURE_VERSION,
                )
            )
        except FileExistsError:
            return False

        return True

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

        recent_m1 = self._closed_candles("M1", 500)

        latest = recent_m1[-1]
        bar_msc = int(latest["time_msc"])
        bar_time = datetime.fromtimestamp(bar_msc / 1000, UTC)
        if bar_time >= timestamp:
            raise RuntimeError("Latest closed M1 bar is not in the past")

        experience_id = self._experience_id(bar_msc)
        latest_exists = (
            self._store.get_market_experience(experience_id)
            is not None
        )

        backfill_rows: list[dict[str, Any]] = []
        first_m1_time = datetime.fromtimestamp(
            int(recent_m1[0]["time_msc"]) / 1000,
            UTC,
        )
        backfill_start = first_m1_time
        backfill_end = bar_time - timedelta(minutes=1)

        if backfill_start <= backfill_end:
            existing_times = (
                self._store.market_experience_bar_times(
                    backfill_start,
                    backfill_end,
                    feature_version=self.FEATURE_VERSION,
                )
            )
            earliest_v2, _ = (
                self._store.market_experience_bounds(
                    feature_version=self.FEATURE_VERSION,
                )
            )

            missing_rows = []
            for row in recent_m1[:-1]:
                row_time = datetime.fromtimestamp(
                    int(row["time_msc"]) / 1000,
                    UTC,
                )
                if (
                    backfill_start <= row_time <= backfill_end
                    and row_time.isoformat()
                    not in existing_times
                ):
                    missing_rows.append((row_time, row))

            internal_missing = []
            if earliest_v2 is not None:
                internal_missing = [
                    row
                    for row_time, row in missing_rows
                    if row_time >= earliest_v2
                ]

            if internal_missing:
                backfill_rows = internal_missing[
                    : self.MAX_BACKFILL_PER_CYCLE
                ]
            else:
                recent_historical_missing = [
                    row
                    for row_time, row in missing_rows
                    if (
                        earliest_v2 is None
                        or row_time < earliest_v2
                    )
                ]
                backfill_rows = list(
                    reversed(recent_historical_missing)
                )[: self.MAX_BACKFILL_PER_CYCLE]

        working_m1 = recent_m1
        historical_cache = self._historical_cache

        if (
            not backfill_rows
            and not self._historical_backfill_complete
            and len(recent_m1) == self.CANDLE_PAGE_SIZE
        ):
            historical_cache = self._ensure_historical_cache()
            working_m1 = self._merge_histories(
                historical_cache["M1"],
                recent_m1,
            )
            self._historical_cache["M1"] = working_m1

            eligible = working_m1[
                -(
                    self.HISTORICAL_TARGET_M1_BARS
                    + 1
                ):-1
            ]

            if eligible:
                historical_start = datetime.fromtimestamp(
                    int(eligible[0]["time_msc"]) / 1000,
                    UTC,
                )
                historical_end = datetime.fromtimestamp(
                    int(eligible[-1]["time_msc"]) / 1000,
                    UTC,
                )
                existing_historical = (
                    self._store.market_experience_bar_times(
                        historical_start,
                        historical_end,
                        feature_version=self.FEATURE_VERSION,
                    )
                )
                missing_historical = [
                    row
                    for row in eligible
                    if datetime.fromtimestamp(
                        int(row["time_msc"]) / 1000,
                        UTC,
                    ).isoformat()
                    not in existing_historical
                ]

                if missing_historical:
                    backfill_rows = list(
                        reversed(missing_historical)
                    )[: self.MAX_BACKFILL_PER_CYCLE]
                else:
                    self._historical_backfill_complete = True
            else:
                self._historical_backfill_complete = True

        if latest_exists and not backfill_rows:
            outcomes_created = self._complete_outcomes(
                working_m1
            )
            return CollectorResult(
                experience_id=experience_id,
                bar_time_utc=bar_time.isoformat(),
                experience_created=False,
                outcomes_created=outcomes_created,
            )

        recent_m5 = self._closed_candles("M5", 200)
        recent_m15 = self._closed_candles("M15", 200)
        recent_h1 = self._closed_candles("H1", 200)

        if historical_cache is not None:
            m1 = self._merge_histories(
                historical_cache["M1"],
                recent_m1,
            )
            m5 = self._merge_histories(
                historical_cache["M5"],
                recent_m5,
            )
            m15 = self._merge_histories(
                historical_cache["M15"],
                recent_m15,
            )
            h1 = self._merge_histories(
                historical_cache["H1"],
                recent_h1,
            )

            self._historical_cache.update({
                "M1": m1,
                "M5": m5,
                "M15": m15,
                "H1": h1,
            })
        else:
            m1 = recent_m1
            m5 = recent_m5
            m15 = recent_m15
            h1 = recent_h1

        latest_created = False
        if not latest_exists:
            latest_created = self._record_experience_for_bar(
                row=latest,
                m1=m1,
                m5=m5,
                m15=m15,
                h1=h1,
                point=point,
                bid=bid,
                ask=ask,
                allow_live_spread_fallback=True,
            )

        backfill_created = 0
        for row in backfill_rows:
            if self._record_experience_for_bar(
                row=row,
                m1=m1,
                m5=m5,
                m15=m15,
                h1=h1,
                point=point,
                bid=bid,
                ask=ask,
                allow_live_spread_fallback=False,
            ):
                backfill_created += 1

        outcomes_created = self._complete_outcomes(m1)

        return CollectorResult(
            experience_id=experience_id,
            bar_time_utc=bar_time.isoformat(),
            experience_created=latest_created,
            outcomes_created=outcomes_created,
            backfill_experiences_created=backfill_created,
        )
