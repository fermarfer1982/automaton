from __future__ import annotations

import unittest
from datetime import UTC, datetime

from trading_lab.frozen_regime_evaluator import (
    DEFAULT_REGIME_CANDIDATE,
    load_regime_candidate,
    select_regime_episodes,
)
from trading_lab.market_experience_collector import (
    MarketExperienceCollector,
)


class FrozenRegimeEvaluatorTests(unittest.TestCase):
    def test_frozen_regime_contract_is_exact(self):
        candidate = load_regime_candidate(
            DEFAULT_REGIME_CANDIDATE
        )

        self.assertEqual(
            "xauusd_regime_v2",
            candidate.candidate_set_id,
        )
        self.assertEqual(2, candidate.feature_version)
        self.assertEqual(
            datetime(2026, 8, 12, 0, 0, tzinfo=UTC),
            candidate.historical_holdout_before_utc,
        )
        self.assertEqual(
            datetime(2026, 8, 21, 13, 20, tzinfo=UTC),
            candidate.prospective_oos_cutoff_utc,
        )
        self.assertEqual(
            {
                "all": [{
                    "feature": "timeframes.M1.return_3_points",
                    "op": "<=",
                    "threshold": -125.0,
                }]
            },
            candidate.base_episode_rule,
        )
        self.assertEqual(
            60.5785,
            candidate.regime_rules[
                "F3_M5_RSI_BULLISH_PULLBACK_LONG"
            ]["all"][0]["threshold"],
        )
        self.assertEqual(
            1627.14,
            candidate.regime_rules[
                "F4_LOW_H1_ATR_PULLBACK_LONG"
            ]["all"][0]["threshold"],
        )

    def test_base_f1_non_overlap_happens_before_regime_filter(self):
        candidate = load_regime_candidate(
            DEFAULT_REGIME_CANDIDATE
        )

        def row(minute, m5_rsi):
            return {
                "bar_time": datetime(
                    2026, 8, 21, 14, minute, tzinfo=UTC
                ),
                "features": {
                    "timeframes.M1.return_3_points": -200.0,
                    "timeframes.M5.rsi14": m5_rsi,
                    "timeframes.H1.atr14_points": 1000.0,
                },
                "horizons": {
                    15: {
                        "net_return_points": 100.0,
                        "mfe_points": 200.0,
                        "mae_points": 50.0,
                    }
                },
            }

        rows = [
            row(0, 50.0),
            row(5, 70.0),
            row(15, 70.0),
        ]

        raw, base, f3 = select_regime_episodes(
            rows,
            candidate,
            "F3_M5_RSI_BULLISH_PULLBACK_LONG",
        )

        self.assertEqual(3, len(raw))
        self.assertEqual(
            [0, 15],
            [item["bar_time"].minute for item in base],
        )
        self.assertEqual(
            [15],
            [item["bar_time"].minute for item in f3],
        )

    def test_historical_target_expands_to_30000_m1(self):
        self.assertEqual(
            30_000,
            MarketExperienceCollector.HISTORICAL_TARGET_M1_BARS,
        )


if __name__ == "__main__":
    unittest.main()
