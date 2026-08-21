from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from .frozen_candidate_evaluator import (
    FrozenCandidate,
    load_evaluable_rows,
    matches_rule,
    non_overlapping,
    summarize_episodes,
)


DEFAULT_REGIME_CANDIDATE = (
    Path(__file__).resolve().parents[1]
    / "research"
    / "frozen_candidates"
    / "xauusd_regime_v2.json"
)


@dataclass(frozen=True)
class FrozenRegimeCandidate:
    candidate_set_id: str
    symbol: str
    feature_version: int
    direction: str
    frozen_at_utc: datetime
    historical_holdout_before_utc: datetime
    prospective_oos_cutoff_utc: datetime
    evaluation_horizon_minutes: int
    diagnostic_horizons_minutes: tuple[int, ...]
    non_overlap_minutes: int
    minimum_oos_non_overlap_signals: int
    minimum_oos_utc_days: int
    base_episode_rule: dict[str, Any]
    regime_rules: dict[str, dict[str, Any]]


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
    ):
        raise ValueError("Frozen timestamp must be UTC")
    return parsed.astimezone(UTC)


def load_regime_candidate(
    path: Path = DEFAULT_REGIME_CANDIDATE,
) -> FrozenRegimeCandidate:
    payload = json.loads(
        Path(path).read_text(encoding="utf-8")
    )

    if payload.get("status") != "FROZEN":
        raise ValueError("Regime candidate must be FROZEN")
    if payload.get("candidate_set_id") != "xauusd_regime_v2":
        raise ValueError("Unexpected regime candidate id")
    if payload.get("symbol") != "XAUUSD":
        raise ValueError("Only XAUUSD is permitted")
    if payload.get("feature_version") != 2:
        raise ValueError("feature_version must remain 2")
    if payload.get("direction") != "LONG":
        raise ValueError("Only frozen LONG regime is expected")

    candidate = FrozenRegimeCandidate(
        candidate_set_id=str(payload["candidate_set_id"]),
        symbol=str(payload["symbol"]),
        feature_version=int(payload["feature_version"]),
        direction=str(payload["direction"]),
        frozen_at_utc=_utc(payload["frozen_at_utc"]),
        historical_holdout_before_utc=_utc(
            payload["historical_holdout_before_utc"]
        ),
        prospective_oos_cutoff_utc=_utc(
            payload["prospective_oos_cutoff_utc"]
        ),
        evaluation_horizon_minutes=int(
            payload["evaluation_horizon_minutes"]
        ),
        diagnostic_horizons_minutes=tuple(
            int(value)
            for value in payload[
                "diagnostic_horizons_minutes"
            ]
        ),
        non_overlap_minutes=int(
            payload["non_overlap_minutes"]
        ),
        minimum_oos_non_overlap_signals=int(
            payload["minimum_oos_non_overlap_signals"]
        ),
        minimum_oos_utc_days=int(
            payload["minimum_oos_utc_days"]
        ),
        base_episode_rule=dict(
            payload["base_episode_rule"]
        ),
        regime_rules=dict(payload["regime_rules"]),
    )

    if candidate.frozen_at_utc != datetime(
        2026, 8, 21, 13, 20, tzinfo=UTC
    ):
        raise ValueError("Frozen time changed")
    if candidate.historical_holdout_before_utc != datetime(
        2026, 8, 12, 0, 0, tzinfo=UTC
    ):
        raise ValueError("Historical holdout boundary changed")
    if candidate.prospective_oos_cutoff_utc != datetime(
        2026, 8, 21, 13, 20, tzinfo=UTC
    ):
        raise ValueError("Prospective OOS cutoff changed")
    if candidate.evaluation_horizon_minutes != 15:
        raise ValueError("Evaluation horizon changed")
    if candidate.diagnostic_horizons_minutes != (5, 15, 60):
        raise ValueError("Diagnostic horizons changed")
    if candidate.non_overlap_minutes != 15:
        raise ValueError("Non-overlap interval changed")
    if candidate.minimum_oos_non_overlap_signals != 30:
        raise ValueError("Minimum OOS signal count changed")
    if candidate.minimum_oos_utc_days != 3:
        raise ValueError("Minimum OOS day count changed")

    expected_base = {
        "all": [{
            "feature": "timeframes.M1.return_3_points",
            "op": "<=",
            "threshold": -125.0,
        }]
    }
    if candidate.base_episode_rule != expected_base:
        raise ValueError("Frozen base episode rule changed")

    expected_rules = {
        "F3_M5_RSI_BULLISH_PULLBACK_LONG": {
            "all": [{
                "feature": "timeframes.M5.rsi14",
                "op": ">=",
                "threshold": 60.5785,
            }]
        },
        "F4_LOW_H1_ATR_PULLBACK_LONG": {
            "all": [{
                "feature": "timeframes.H1.atr14_points",
                "op": "<=",
                "threshold": 1627.14,
            }]
        },
    }
    if candidate.regime_rules != expected_rules:
        raise ValueError("Frozen regime rules changed")

    return candidate


def _compatibility_candidate(
    candidate: FrozenRegimeCandidate,
) -> FrozenCandidate:
    return FrozenCandidate(
        candidate_set_id=candidate.candidate_set_id,
        symbol=candidate.symbol,
        feature_version=candidate.feature_version,
        direction=candidate.direction,
        discovery_window_start_utc=(
            candidate.historical_holdout_before_utc
        ),
        discovery_cutoff_utc=(
            candidate.prospective_oos_cutoff_utc
        ),
        evaluation_horizon_minutes=(
            candidate.evaluation_horizon_minutes
        ),
        diagnostic_horizons_minutes=(
            candidate.diagnostic_horizons_minutes
        ),
        non_overlap_minutes=candidate.non_overlap_minutes,
        minimum_oos_non_overlap_signals=(
            candidate.minimum_oos_non_overlap_signals
        ),
        minimum_oos_utc_days=(
            candidate.minimum_oos_utc_days
        ),
        rules=candidate.regime_rules,
    )


def load_regime_rows(
    db_path: Path,
    candidate: FrozenRegimeCandidate,
    *,
    scope: str,
) -> list[dict[str, Any]]:
    if scope not in {"historical", "oos"}:
        raise ValueError(
            "Frozen regime evaluator permits only "
            "historical or oos scope"
        )
    return load_evaluable_rows(
        db_path,
        _compatibility_candidate(candidate),
        scope=scope,
    )


def select_base_episodes(
    rows: Iterable[dict[str, Any]],
    candidate: FrozenRegimeCandidate,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    raw = [
        row
        for row in rows
        if matches_rule(
            row["features"],
            candidate.base_episode_rule,
        )
    ]
    episodes = non_overlapping(
        raw,
        candidate.non_overlap_minutes,
    )
    return raw, episodes


def select_regime_episodes(
    rows: Iterable[dict[str, Any]],
    candidate: FrozenRegimeCandidate,
    rule_name: str,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    if rule_name not in candidate.regime_rules:
        raise KeyError(rule_name)

    raw_base, base_episodes = select_base_episodes(
        rows,
        candidate,
    )
    regime_episodes = [
        row
        for row in base_episodes
        if matches_rule(
            row["features"],
            candidate.regime_rules[rule_name],
        )
    ]
    return raw_base, base_episodes, regime_episodes


def profit_factor(
    episodes: Iterable[dict[str, Any]],
    horizon: int = 15,
) -> float | None:
    values = [
        float(
            row["horizons"][horizon][
                "net_return_points"
            ]
        )
        for row in episodes
        if horizon in row["horizons"]
    ]
    if not values:
        return None
    gross_profit = sum(
        value for value in values if value > 0
    )
    gross_loss = -sum(
        value for value in values if value < 0
    )
    if gross_loss == 0:
        return math.inf if gross_profit > 0 else 0.0
    return gross_profit / gross_loss


def summarize_regime(
    episodes: Iterable[dict[str, Any]],
    horizon: int = 15,
) -> dict[str, Any]:
    rows = list(episodes)
    result = summarize_episodes(rows, horizon)
    result["profit_factor"] = profit_factor(
        rows,
        horizon,
    )
    return result


def evidence_status(
    summary: dict[str, Any],
    candidate: FrozenRegimeCandidate,
) -> str:
    if (
        summary["n"]
        < candidate.minimum_oos_non_overlap_signals
        or summary["days"]
        < candidate.minimum_oos_utc_days
    ):
        return "INSUFFICIENT"

    mean = summary["net_mean_points"]
    pf = summary["profit_factor"]
    if (
        mean is not None
        and mean > 0
        and pf is not None
        and pf > 1.0
    ):
        return "OOS_POSITIVE_DIAGNOSTIC"
    return "OOS_NOT_POSITIVE"
