from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from trading_lab.frozen_candidate_evaluator import (
    DEFAULT_CANDIDATE,
    load_candidate,
    matches_rule,
    non_overlapping,
)


class FrozenCandidateEvaluatorTests(unittest.TestCase):
    def test_candidate_contract_is_exactly_frozen(self):
        candidate = load_candidate(DEFAULT_CANDIDATE)

        self.assertEqual(
            candidate.candidate_set_id,
            "xauusd_m1_pullback_v1",
        )
        self.assertEqual(candidate.symbol, "XAUUSD")
        self.assertEqual(candidate.feature_version, 2)
        self.assertEqual(candidate.direction, "LONG")
        self.assertEqual(
            candidate.discovery_window_start_utc,
            datetime(2026, 8, 20, 23, 10, tzinfo=UTC),
        )
        self.assertEqual(
            candidate.discovery_cutoff_utc,
            datetime(2026, 8, 21, 7, 38, tzinfo=UTC),
        )
        self.assertEqual(candidate.evaluation_horizon_minutes, 15)
        self.assertEqual(candidate.non_overlap_minutes, 15)
        self.assertEqual(
            candidate.minimum_oos_non_overlap_signals, 30
        )
        self.assertEqual(candidate.minimum_oos_utc_days, 3)

        self.assertEqual(
            candidate.rules["F1_M1_3BAR_PULLBACK_LONG"],
            {
                "all": [
                    {
                        "feature": (
                            "timeframes.M1.return_3_points"
                        ),
                        "op": "<=",
                        "threshold": -125.0,
                    }
                ]
            },
        )
        self.assertEqual(
            candidate.rules[
                "F2_M1_PULLBACK_WITH_H1_CONFIRM_LONG"
            ],
            {
                "all": [
                    {
                        "feature": (
                            "timeframes.M1.return_3_points"
                        ),
                        "op": "<=",
                        "threshold": -125.0,
                    },
                    {
                        "feature": (
                            "timeframes.H1.return_1_points"
                        ),
                        "op": ">=",
                        "threshold": 525.0,
                    },
                ]
            },
        )

    def test_rule_matching_is_frozen(self):
        candidate = load_candidate(DEFAULT_CANDIDATE)
        f1 = candidate.rules["F1_M1_3BAR_PULLBACK_LONG"]
        f2 = candidate.rules[
            "F2_M1_PULLBACK_WITH_H1_CONFIRM_LONG"
        ]

        features = {
            "timeframes.M1.return_3_points": -125.0,
            "timeframes.H1.return_1_points": 524.0,
        }
        self.assertTrue(matches_rule(features, f1))
        self.assertFalse(matches_rule(features, f2))

        features["timeframes.H1.return_1_points"] = 525.0
        self.assertTrue(matches_rule(features, f2))

    def test_non_overlap_uses_first_signal_then_15_minutes(self):
        rows = [
            {
                "bar_time": datetime(
                    2026, 8, 21, 8, 0, tzinfo=UTC
                )
            },
            {
                "bar_time": datetime(
                    2026, 8, 21, 8, 1, tzinfo=UTC
                )
            },
            {
                "bar_time": datetime(
                    2026, 8, 21, 8, 14, tzinfo=UTC
                )
            },
            {
                "bar_time": datetime(
                    2026, 8, 21, 8, 15, tzinfo=UTC
                )
            },
        ]

        selected = non_overlapping(rows, 15)
        self.assertEqual(
            [row["bar_time"].minute for row in selected],
            [0, 15],
        )

    def test_modified_frozen_horizon_is_rejected(self):
        payload = json.loads(
            DEFAULT_CANDIDATE.read_text(encoding="utf-8")
        )
        payload["evaluation_horizon_minutes"] = 10

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "evaluation horizon",
            ):
                load_candidate(path)


if __name__ == "__main__":
    unittest.main()
