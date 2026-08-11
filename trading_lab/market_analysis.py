from __future__ import annotations

import math
from collections.abc import Callable
from datetime import UTC, datetime, time, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .domain import CandleSnapshot


_SESSION_WINDOWS = {
    "ASIA": ("Asia/Singapore", time(8, 0), time(16, 0)),
    "LONDON": ("Europe/London", time(8, 0), time(16, 30)),
    "NEW_YORK": ("America/New_York", time(8, 0), time(17, 0)),
}
_PRIMARY_PRIORITY = ("NEW_YORK", "LONDON", "ASIA")


def session_context(
    timestamp: datetime,
    zone_loader: Callable[[str], tzinfo] = ZoneInfo,
) -> dict[str, object]:
    if timestamp.tzinfo is None:
        raise ValueError("Session timestamp must be timezone-aware")
    active: list[str] = []
    try:
        zones = {key: zone_loader(spec[0]) for key, spec in _SESSION_WINDOWS.items()}
    except ZoneInfoNotFoundError:
        return {"primary": "UNKNOWN", "active": [], "available": False}
    for name, (_, start, end) in _SESSION_WINDOWS.items():
        zone = zones[name]
        local_time = timestamp.astimezone(zone).time().replace(tzinfo=None)
        if start <= local_time < end:
            active.append(name)
    primary = next((name for name in _PRIMARY_PRIORITY if name in active), "OFF_SESSION")
    return {"primary": primary, "active": active, "available": True}


def atr(candles: list[CandleSnapshot], period: int = 14) -> float | None:
    if period < 1 or len(candles) < period + 1:
        return None
    ordered = sorted(candles, key=lambda item: item.time_msc)
    ranges: list[float] = []
    for previous, current in zip(ordered[-period - 1:-1], ordered[-period:]):
        value = max(
            current.high - current.low,
            abs(current.high - previous.close),
            abs(current.low - previous.close),
        )
        if not math.isfinite(value):
            return None
        ranges.append(value)
    return sum(ranges) / period


def summarize_candles(candles: list[CandleSnapshot]) -> dict[str, object]:
    if not candles:
        return {"available": False}
    ordered = sorted(candles, key=lambda item: item.time_msc)
    last = ordered[-1]
    return {
        "available": True,
        "last_closed_bar_time_utc": datetime.fromtimestamp(
            last.time_msc / 1000, UTC
        ).isoformat(),
        "open": last.open,
        "high": last.high,
        "low": last.low,
        "close": last.close,
        "atr14": atr(ordered),
    }


def utc_day_range(candles: list[CandleSnapshot], now: datetime) -> dict[str, float | None]:
    if now.tzinfo is None:
        raise ValueError("Range timestamp must be timezone-aware")
    today = now.astimezone(UTC).date()
    selected = [
        item for item in candles
        if datetime.fromtimestamp(item.time_msc / 1000, UTC).date() == today
    ]
    return {
        "high": max((item.high for item in selected), default=None),
        "low": min((item.low for item in selected), default=None),
    }
