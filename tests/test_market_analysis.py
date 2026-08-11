from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta, timezone

from trading_lab.domain import CandleSnapshot
from trading_lab.market_analysis import asian_session_range, atr, session_context


class MarketAnalysisTests(unittest.TestCase):
    def test_session_classifier_uses_dst_aware_zones_and_priority(self) -> None:
        zones = {
            "Asia/Singapore": timezone(timedelta(hours=8)),
            "Europe/London": timezone(timedelta(hours=1)),
            "America/New_York": timezone(timedelta(hours=-4)),
        }
        summer_overlap = session_context(
            datetime(2026, 8, 11, 13, 0, tzinfo=UTC),
            zone_loader=zones.__getitem__,
        )
        self.assertIn("LONDON", summer_overlap["active"])
        self.assertIn("NEW_YORK", summer_overlap["active"])
        self.assertEqual("NEW_YORK", summer_overlap["primary"])
        self.assertTrue(summer_overlap["available"])

    def test_atr_uses_closed_candle_true_ranges(self) -> None:
        items = [
            CandleSnapshot(
                symbol="XAUUSD", timeframe="M1", time_msc=index * 60_000,
                open=100.0, high=102.0, low=99.0, close=101.0,
                tick_volume=1, spread=1,
            )
            for index in range(15)
        ]
        self.assertEqual(3.0, atr(items))

    def test_asian_range_uses_latest_iana_session(self) -> None:
        zone = timezone(timedelta(hours=8))
        now = datetime(2026, 8, 11, 9, 0, tzinfo=UTC)  # 17:00 Singapore.
        items = [
            CandleSnapshot(
                symbol="XAUUSD", timeframe="M5",
                time_msc=int(datetime(2026, 8, 11, hour, 0, tzinfo=UTC).timestamp() * 1000),
                open=100.0, high=100.0 + hour, low=99.0 - hour, close=100.0,
                tick_volume=1, spread=1,
            )
            for hour in range(0, 8)
        ]
        result = asian_session_range(items, now, zone_loader=lambda _name: zone)
        self.assertTrue(result["available"])
        self.assertTrue(result["complete"])
        self.assertEqual(107.0, result["high"])
        self.assertEqual(92.0, result["low"])
        self.assertEqual(15.0, result["range"])


if __name__ == "__main__":
    unittest.main()
