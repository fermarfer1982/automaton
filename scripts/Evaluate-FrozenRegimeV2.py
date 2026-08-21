from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[1]
if str(WORKSPACE) not in sys.path:
    sys.path.insert(0, str(WORKSPACE))

from trading_lab.frozen_candidate_evaluator import DEFAULT_DB
from trading_lab.frozen_regime_evaluator import (
    DEFAULT_REGIME_CANDIDATE,
    evidence_status,
    load_regime_candidate,
    load_regime_rows,
    select_regime_episodes,
    summarize_regime,
)


def fmt(value):
    if value is None:
        return "n/a"
    if isinstance(value, float) and math.isinf(value):
        return "inf"
    return f"{float(value):.2f}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only evaluator for frozen XAUUSD "
            "regime-v2 candidates F3/F4."
        )
    )
    parser.add_argument(
        "--scope",
        choices=("historical", "oos"),
        required=True,
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB,
    )
    parser.add_argument(
        "--candidate",
        type=Path,
        default=DEFAULT_REGIME_CANDIDATE,
    )
    parser.add_argument(
        "--show",
        type=int,
        default=20,
    )
    args = parser.parse_args()

    candidate = load_regime_candidate(args.candidate)
    rows = load_regime_rows(
        args.db,
        candidate,
        scope=args.scope,
    )

    print("FROZEN_REGIME_V2_EVALUATOR=PASS")
    print(f"CANDIDATE_SET={candidate.candidate_set_id}")
    print(f"FEATURE_VERSION={candidate.feature_version}")
    print(f"SCOPE={args.scope.upper()}")
    print(
        "HISTORICAL_HOLDOUT_BEFORE_UTC="
        f"{candidate.historical_holdout_before_utc.isoformat()}"
    )
    print(
        "PROSPECTIVE_OOS_CUTOFF_UTC="
        f"{candidate.prospective_oos_cutoff_utc.isoformat()}"
    )
    print(f"EVALUABLE_EXPERIENCES={len(rows)}")
    print(
        "EPISODE_SEMANTICS="
        "F1_BASE_NON_OVERLAP_FIRST_THEN_REGIME_FILTER"
    )

    for rule_name in candidate.regime_rules:
        raw_base, base_episodes, episodes = (
            select_regime_episodes(
                rows,
                candidate,
                rule_name,
            )
        )
        summary = summarize_regime(episodes, 15)

        print(f"\nRULE={rule_name}")
        print(f"F1_RAW_SIGNALS={len(raw_base)}")
        print(
            f"F1_NON_OVERLAP_EPISODES={len(base_episodes)}"
        )
        print(f"REGIME_EPISODES={len(episodes)}")
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
            f"{fmt(summary['net_total_points'])}"
        )
        print(
            "NET_MEAN_15M_POINTS="
            f"{fmt(summary['net_mean_points'])}"
        )
        print(
            "NET_MEDIAN_15M_POINTS="
            f"{fmt(summary['net_median_points'])}"
        )
        print(
            "PROFIT_FACTOR="
            f"{fmt(summary['profit_factor'])}"
        )
        print(
            "MFE_MEAN_15M_POINTS="
            f"{fmt(summary['mfe_mean_points'])}"
        )
        print(
            "MAE_MEAN_15M_POINTS="
            f"{fmt(summary['mae_mean_points'])}"
        )

        if args.scope == "oos":
            print(
                "EVIDENCE_STATUS="
                f"{evidence_status(summary, candidate)}"
            )
        else:
            print(
                "EVIDENCE_STATUS="
                "UNTOUCHED_HISTORICAL_HOLDOUT_DIAGNOSTIC"
            )

        print("EPISODES")
        for index, row in enumerate(
            episodes[:max(args.show, 0)],
            start=1,
        ):
            metric = row["horizons"][15]
            print(
                f"{index:03d} | "
                f"time={row['bar_time'].isoformat()} | "
                f"session={row['session']} | "
                f"spread={fmt(row['spread_points'])} | "
                f"M1ret3={fmt(row['features'].get('timeframes.M1.return_3_points'))} | "
                f"M5rsi={fmt(row['features'].get('timeframes.M5.rsi14'))} | "
                f"H1atr={fmt(row['features'].get('timeframes.H1.atr14_points'))} | "
                f"net15={fmt(metric['net_return_points'])} | "
                f"MFE15={fmt(metric['mfe_points'])} | "
                f"MAE15={fmt(metric['mae_points'])}"
            )

    print("\nGUARDRAILS")
    print(
        "F3/F4 thresholds are frozen from TRAIN+VALIDATION "
        "and are not optimized by this evaluator."
    )
    print(
        "F3 and F4 are not combined; a combined rule would "
        "be a new experiment with a new future cutoff."
    )
    print(
        "Historical scope uses only bars strictly before "
        "2026-08-12T00:00:00Z."
    )
    print(
        "OOS scope uses only bars strictly after "
        "2026-08-21T13:20:00Z."
    )


if __name__ == "__main__":
    main()
