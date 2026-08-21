from __future__ import annotations

import json
import math
import sqlite3
import statistics
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable


DEFAULT_DB = Path(
    r"C:\ProgramData\AutomatonMT5Lab\research\research.db"
)
DEFAULT_CANDIDATE = (
    Path(__file__).resolve().parents[1]
    / "research"
    / "frozen_candidates"
    / "xauusd_m1_pullback_v1.json"
)


@dataclass(frozen=True)
class FrozenCandidate:
    candidate_set_id: str
    symbol: str
    feature_version: int
    direction: str
    discovery_window_start_utc: datetime
    discovery_cutoff_utc: datetime
    evaluation_horizon_minutes: int
    diagnostic_horizons_minutes: tuple[int, ...]
    non_overlap_minutes: int
    minimum_oos_non_overlap_signals: int
    minimum_oos_utc_days: int
    rules: dict[str, dict[str, Any]]


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("Frozen timestamp must be UTC")
    return parsed.astimezone(UTC)


def load_candidate(path: Path = DEFAULT_CANDIDATE) -> FrozenCandidate:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))

    if payload.get("status") != "FROZEN":
        raise ValueError("Candidate must be FROZEN")
    if payload.get("symbol") != "XAUUSD":
        raise ValueError("Only XAUUSD candidate is permitted")
    if payload.get("direction") != "LONG":
        raise ValueError("Only frozen LONG candidate is expected")
    if payload.get("feature_version") != 2:
        raise ValueError("Frozen candidate requires feature_version=2")

    start = _utc(payload["discovery_window_start_utc"])
    cutoff = _utc(payload["discovery_cutoff_utc"])
    if cutoff <= start:
        raise ValueError("Discovery cutoff must follow discovery start")

    horizons = tuple(
        int(value)
        for value in payload["diagnostic_horizons_minutes"]
    )
    if horizons != (5, 15, 60):
        raise ValueError("Frozen diagnostic horizons changed")

    candidate = FrozenCandidate(
        candidate_set_id=str(payload["candidate_set_id"]),
        symbol=str(payload["symbol"]),
        feature_version=int(payload["feature_version"]),
        direction=str(payload["direction"]),
        discovery_window_start_utc=start,
        discovery_cutoff_utc=cutoff,
        evaluation_horizon_minutes=int(
            payload["evaluation_horizon_minutes"]
        ),
        diagnostic_horizons_minutes=horizons,
        non_overlap_minutes=int(payload["non_overlap_minutes"]),
        minimum_oos_non_overlap_signals=int(
            payload["minimum_oos_non_overlap_signals"]
        ),
        minimum_oos_utc_days=int(payload["minimum_oos_utc_days"]),
        rules=dict(payload["rules"]),
    )

    if candidate.evaluation_horizon_minutes != 15:
        raise ValueError("Frozen evaluation horizon changed")
    if candidate.non_overlap_minutes != 15:
        raise ValueError("Frozen non-overlap interval changed")
    if candidate.minimum_oos_non_overlap_signals != 30:
        raise ValueError("Frozen minimum OOS signal count changed")
    if candidate.minimum_oos_utc_days != 3:
        raise ValueError("Frozen minimum OOS day count changed")

    return candidate


def flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            result.update(flatten(item, name))
    else:
        result[prefix] = value
    return result


def _finite_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def matches_condition(
    features: dict[str, Any],
    condition: dict[str, Any],
) -> bool:
    value = features.get(str(condition["feature"]))
    if not _finite_number(value):
        return False

    threshold = float(condition["threshold"])
    numeric = float(value)
    operator = str(condition["op"])

    if operator == "<=":
        return numeric <= threshold
    if operator == ">=":
        return numeric >= threshold

    raise ValueError(f"Unsupported frozen operator: {operator}")


def matches_rule(
    features: dict[str, Any],
    rule: dict[str, Any],
) -> bool:
    conditions = rule.get("all")
    if not isinstance(conditions, list) or not conditions:
        raise ValueError("Frozen rule conditions are invalid")
    return all(
        matches_condition(features, condition)
        for condition in conditions
    )


def non_overlapping(
    rows: Iterable[dict[str, Any]],
    minutes: int,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    next_allowed: datetime | None = None

    for row in sorted(rows, key=lambda item: item["bar_time"]):
        bar_time = row["bar_time"]
        if next_allowed is None or bar_time >= next_allowed:
            selected.append(row)
            next_allowed = bar_time + timedelta(minutes=minutes)

    return selected


def _scope_clause(
    candidate: FrozenCandidate,
    scope: str,
) -> tuple[str, tuple[str, ...]]:
    start = candidate.discovery_window_start_utc.isoformat()
    cutoff = candidate.discovery_cutoff_utc.isoformat()

    if scope == "historical":
        return "me.bar_time_utc < ?", (start,)
    if scope == "discovery":
        return (
            "me.bar_time_utc >= ? AND me.bar_time_utc <= ?",
            (start, cutoff),
        )
    if scope == "oos":
        return "me.bar_time_utc > ?", (cutoff,)
    if scope == "all":
        return "1 = 1", ()

    raise ValueError(f"Unsupported scope: {scope}")


def load_evaluable_rows(
    db_path: Path,
    candidate: FrozenCandidate,
    *,
    scope: str,
) -> list[dict[str, Any]]:
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(path)

    clause, scope_params = _scope_clause(candidate, scope)
    uri = path.resolve().as_uri() + "?mode=ro"

    conn = sqlite3.connect(uri, uri=True, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA busy_timeout=10000")

    try:
        experiences = conn.execute(
            f"""
            SELECT
              me.experience_id,
              me.bar_time_utc,
              me.reference_price,
              me.point,
              me.spread_points,
              me.session,
              me.features_json
            FROM market_experiences me
            WHERE me.symbol = ?
              AND me.timeframe = 'M1'
              AND me.feature_version = ?
              AND {clause}
            ORDER BY me.bar_time_utc
            """,
            (
                candidate.symbol,
                candidate.feature_version,
                *scope_params,
            ),
        ).fetchall()

        outcomes = conn.execute(
            f"""
            SELECT
              eo.experience_id,
              eo.horizon_minutes,
              eo.future_bar_time_utc,
              eo.future_close,
              eo.window_high,
              eo.window_low,
              eo.return_points
            FROM experience_outcomes eo
            JOIN market_experiences me
              ON me.experience_id = eo.experience_id
            WHERE me.symbol = ?
              AND me.timeframe = 'M1'
              AND me.feature_version = ?
              AND eo.horizon_minutes IN (5, 15, 60)
              AND {clause}
            ORDER BY me.bar_time_utc, eo.horizon_minutes
            """,
            (
                candidate.symbol,
                candidate.feature_version,
                *scope_params,
            ),
        ).fetchall()
    finally:
        conn.close()

    by_experience: dict[str, dict[int, sqlite3.Row]] = {}
    for outcome in outcomes:
        by_experience.setdefault(
            str(outcome["experience_id"]),
            {},
        )[int(outcome["horizon_minutes"])] = outcome

    result: list[dict[str, Any]] = []
    for experience in experiences:
        experience_id = str(experience["experience_id"])
        horizons = by_experience.get(experience_id, {})
        if 15 not in horizons:
            continue

        bar_time = _utc(str(experience["bar_time_utc"]))
        reference = float(experience["reference_price"])
        point = float(experience["point"])
        spread_points = float(experience["spread_points"])
        if point <= 0:
            raise ValueError("Experience point must be positive")

        entry_ask = reference + spread_points * point
        features = flatten(
            json.loads(str(experience["features_json"]))
        )

        metrics: dict[int, dict[str, Any]] = {}
        for horizon, outcome in horizons.items():
            future_close = float(outcome["future_close"])
            window_high = float(outcome["window_high"])
            window_low = float(outcome["window_low"])

            metrics[horizon] = {
                "future_bar_time_utc": str(
                    outcome["future_bar_time_utc"]
                ),
                "gross_return_points": float(
                    outcome["return_points"]
                ),
                "net_return_points": (
                    future_close - entry_ask
                ) / point,
                "mfe_points": max(
                    0.0,
                    (window_high - entry_ask) / point,
                ),
                "mae_points": max(
                    0.0,
                    (entry_ask - window_low) / point,
                ),
            }

        result.append(
            {
                "experience_id": experience_id,
                "bar_time": bar_time,
                "session": str(experience["session"]),
                "reference_price": reference,
                "entry_ask": entry_ask,
                "point": point,
                "spread_points": spread_points,
                "features": features,
                "horizons": metrics,
            }
        )

    return result


def select_rule_episodes(
    rows: Iterable[dict[str, Any]],
    candidate: FrozenCandidate,
    rule_name: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if rule_name not in candidate.rules:
        raise KeyError(rule_name)

    raw = [
        row
        for row in rows
        if matches_rule(
            row["features"],
            candidate.rules[rule_name],
        )
    ]
    episodes = non_overlapping(
        raw,
        candidate.non_overlap_minutes,
    )
    return raw, episodes


def summarize_episodes(
    episodes: Iterable[dict[str, Any]],
    horizon: int = 15,
) -> dict[str, Any]:
    rows = [
        row for row in episodes if horizon in row["horizons"]
    ]

    if not rows:
        return {
            "n": 0,
            "days": 0,
            "wins": 0,
            "losses": 0,
            "win_rate": None,
            "net_total_points": None,
            "net_mean_points": None,
            "net_median_points": None,
            "mfe_mean_points": None,
            "mfe_median_points": None,
            "mae_mean_points": None,
            "mae_median_points": None,
        }

    net = [
        float(row["horizons"][horizon]["net_return_points"])
        for row in rows
    ]
    mfe = [
        float(row["horizons"][horizon]["mfe_points"])
        for row in rows
    ]
    mae = [
        float(row["horizons"][horizon]["mae_points"])
        for row in rows
    ]

    wins = sum(value > 0 for value in net)
    losses = sum(value < 0 for value in net)

    return {
        "n": len(rows),
        "days": len({row["bar_time"].date() for row in rows}),
        "wins": wins,
        "losses": losses,
        "win_rate": wins / len(rows),
        "net_total_points": sum(net),
        "net_mean_points": statistics.fmean(net),
        "net_median_points": statistics.median(net),
        "mfe_mean_points": statistics.fmean(mfe),
        "mfe_median_points": statistics.median(mfe),
        "mae_mean_points": statistics.fmean(mae),
        "mae_median_points": statistics.median(mae),
    }
