from __future__ import annotations

import argparse
import sys
from pathlib import Path

_WORKSPACE = Path(__file__).resolve().parents[1]
if str(_WORKSPACE) not in sys.path:
    sys.path.insert(0, str(_WORKSPACE))

from trading_lab.frozen_candidate_evaluator import (
    DEFAULT_CANDIDATE,
    DEFAULT_DB,
    load_candidate,
    load_evaluable_rows,
    select_rule_episodes,
    summarize_episodes,
)


def _fmt(value):
    if value is None:
        return "n/a"
    return f"{float(value):.2f}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only per-episode diagnostics for the frozen "
            "XAUUSD feature-v2 pullback candidate set."
        )
    )
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument(
        "--candidate", type=Path, default=DEFAULT_CANDIDATE
    )
    parser.add_argument(
        "--scope",
        choices=("historical", "discovery", "oos", "all"),
        default="oos",
    )
    parser.add_argument("--rule", default=None)
    parser.add_argument("--show", type=int, default=50)
    args = parser.parse_args()

    candidate = load_candidate(args.candidate)
    rows = load_evaluable_rows(
        args.db, candidate, scope=args.scope
    )

    rule_names = (
        [args.rule]
        if args.rule is not None
        else list(candidate.rules)
    )

    print("FROZEN_PULLBACK_EPISODE_EVALUATOR=PASS")
    print(f"CANDIDATE_SET={candidate.candidate_set_id}")
    print("STATUS=FROZEN")
    print(f"FEATURE_VERSION={candidate.feature_version}")
    print(f"SCOPE={args.scope.upper()}")
    print(
        "DISCOVERY_WINDOW_START_UTC="
        f"{candidate.discovery_window_start_utc.isoformat()}"
    )
    print(
        "DISCOVERY_CUTOFF_UTC="
        f"{candidate.discovery_cutoff_utc.isoformat()}"
    )
    print(f"EVALUABLE_EXPERIENCES={len(rows)}")

    for rule_name in rule_names:
        raw, episodes = select_rule_episodes(
            rows, candidate, rule_name
        )
        summary = summarize_episodes(episodes, 15)

        print(f"\nRULE={rule_name}")
        print(f"RAW_SIGNALS={len(raw)}")
        print(f"NON_OVERLAP_EPISODES={len(episodes)}")
        print(f"UTC_DAYS={summary['days']}")
        print(f"WINS={summary['wins']}")
        print(f"LOSSES={summary['losses']}")
        print(
            "WIN_RATE="
            + (
                "n/a"
                if summary["win_rate"] is None
                else f"{100*summary['win_rate']:.1f}%"
            )
        )
        print(
            "NET_TOTAL_15M_POINTS="
            f"{_fmt(summary['net_total_points'])}"
        )
        print(
            "NET_MEAN_15M_POINTS="
            f"{_fmt(summary['net_mean_points'])}"
        )
        print(
            "NET_MEDIAN_15M_POINTS="
            f"{_fmt(summary['net_median_points'])}"
        )
        print(
            "MFE_MEAN_15M_POINTS="
            f"{_fmt(summary['mfe_mean_points'])}"
        )
        print(
            "MFE_MEDIAN_15M_POINTS="
            f"{_fmt(summary['mfe_median_points'])}"
        )
        print(
            "MAE_MEAN_15M_POINTS="
            f"{_fmt(summary['mae_mean_points'])}"
        )
        print(
            "MAE_MEDIAN_15M_POINTS="
            f"{_fmt(summary['mae_median_points'])}"
        )

        print("EPISODES")
        for index, row in enumerate(
            episodes[: max(args.show, 0)],
            start=1,
        ):
            features = row["features"]
            m1_3 = features.get(
                "timeframes.M1.return_3_points"
            )
            h1_1 = features.get(
                "timeframes.H1.return_1_points"
            )

            horizon_values = {}
            for horizon in (5, 15, 60):
                metric = row["horizons"].get(horizon)
                horizon_values[horizon] = (
                    "n/a"
                    if metric is None
                    else _fmt(metric["net_return_points"])
                )

            primary = row["horizons"][15]
            print(
                f"{index:03d} | "
                f"time={row['bar_time'].isoformat()} | "
                f"session={row['session']} | "
                f"spread={_fmt(row['spread_points'])} | "
                f"M1ret3={_fmt(m1_3)} | "
                f"H1ret1={_fmt(h1_1)} | "
                f"net5={horizon_values[5]} | "
                f"net15={horizon_values[15]} | "
                f"net60={horizon_values[60]} | "
                f"MFE15={_fmt(primary['mfe_points'])} | "
                f"MAE15={_fmt(primary['mae_points'])}"
            )

    print("\nGUARDRAILS")
    print(
        "Candidate thresholds are loaded from the committed "
        "FROZEN artifact and are not optimized here."
    )
    print(
        "HISTORICAL scope is strictly before discovery start; "
        "OOS scope is strictly after discovery cutoff."
    )
    print(
        "MFE/MAE are long-side Bid-path diagnostics measured "
        "from effective Ask entry (reference + entry spread)."
    )
    print(
        "No stop-loss, take-profit, slippage, latency or "
        "position sizing is simulated."
    )


if __name__ == "__main__":
    main()
