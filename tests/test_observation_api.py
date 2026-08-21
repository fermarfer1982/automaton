from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from trading_lab.api_auth import (
    ApiKeyVerifier,
)
from trading_lab.observation_api import (
    create_observation_api,
)


TEST_KEY = (
    "A" * 43
)


class FakeApplication:
    def status(self):
        return {
            "mode": "OBSERVE_ONLY",
            "execution_capable": False,
        }

    def account_state(self):
        return {
            "kind": "DEMO",
        }

    def market_snapshot(self, symbol):
        return {
            "symbol": symbol,
        }

    def candles(
        self,
        symbol,
        timeframe,
        count,
    ):
        return {
            "symbol": symbol,
            "timeframe": timeframe,
            "count": count,
            "candles": [],
        }

    def history_state(
        self,
        *,
        from_utc,
        to_utc,
        symbol,
        limit,
    ):
        return {
            "symbol": symbol,
            "from_utc": from_utc,
            "to_utc": to_utc,
            "count": 0,
            "deals": [],
        }

    def positions_state(self):
        return {
            "positions": [],
        }

    def active_orders_state(self):
        return {
            "active_orders": [],
        }

    def daily_stats(self):
        return {
            "daily_realized": 0.0,
        }


class ObservationApiTests(
    unittest.TestCase
):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()

        key_path = (
            Path(self.tempdir.name)
            / "observation.key"
        )

        key_path.write_text(
            TEST_KEY,
            encoding="ascii",
        )

        self.verifier = ApiKeyVerifier(
            key_path
        )

        self.client = TestClient(
            create_observation_api(
                FakeApplication(),
                self.verifier,
            )
        )

        self.headers = {
            "X-AUTOMATON-OBSERVATION-KEY":
            TEST_KEY,
        }

    def tearDown(self):
        self.tempdir.cleanup()

    def test_health_reports_worker_and_collector(self):
        class FakeCollectorLoop:
            def health(self):
                return {
                    "running": True,
                    "cycles": 7,
                    "experiences_created": 5,
                    "outcomes_created": 3,
                    "consecutive_errors": 0,
                    "last_bar_time_utc": (
                        "2026-08-20T14:30:00+00:00"
                    ),
                    "last_success_at_utc": (
                        "2026-08-20T14:31:00+00:00"
                    ),
                    "last_error_at_utc": None,
                    "last_error": None,
                }

        client = TestClient(
            create_observation_api(
                FakeApplication(),
                self.verifier,
                collector_loop=FakeCollectorLoop(),
            )
        )

        response = client.get("/health")

        self.assertEqual(
            response.status_code,
            200,
        )

        payload = response.json()

        self.assertEqual(
            "HEALTHY",
            payload["status"],
        )
        self.assertEqual(
            "OBSERVE_ONLY",
            payload["mode"],
        )
        self.assertFalse(
            payload["execution_capable"]
        )
        self.assertEqual(
            7,
            payload["collector"]["cycles"],
        )
        self.assertTrue(
            payload["collector"]["running"]
        )

    def test_health_is_degraded_after_collector_error(self):
        class FailedCollectorLoop:
            def health(self):
                return {
                    "running": True,
                    "consecutive_errors": 1,
                }

        client = TestClient(
            create_observation_api(
                FakeApplication(),
                self.verifier,
                collector_loop=FailedCollectorLoop(),
            )
        )

        response = client.get("/health")

        self.assertEqual(
            response.status_code,
            200,
        )
        self.assertEqual(
            "DEGRADED",
            response.json()["status"],
        )

    def test_missing_key_is_rejected(self):
        response = self.client.get(
            "/v1/status"
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_status_is_authenticated(self):
        response = self.client.get(
            "/v1/status",
            headers=self.headers,
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertFalse(
            response.json()[
                "execution_capable"
            ]
        )

    def test_non_get_is_rejected(self):
        response = self.client.post(
            "/v1/status",
            headers=self.headers,
            json={},
        )

        self.assertEqual(
            response.status_code,
            405,
        )

    def test_trade_routes_do_not_exist(self):
        paths = {
            route.path
            for route in self.client.app.routes
        }

        for forbidden in (
            "/v1/trade/propose",
            "/v1/trade/close",
            "/v1/trade/modify",
            "/v1/trade/cancel-pending",
        ):
            self.assertNotIn(
                forbidden,
                paths,
            )

    def test_history_route_is_get_only_and_present(self):
        response = self.client.get(
            "/v1/history"
            "?from=2026-08-18T10%3A00%3A00Z"
            "&to=2026-08-18T11%3A00%3A00Z"
            "&symbol=XAUUSD"
            "&limit=100",
            headers=self.headers,
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.json()["symbol"],
            "XAUUSD",
        )

    def test_history_post_is_rejected(self):
        response = self.client.post(
            "/v1/history",
            headers=self.headers,
            json={},
        )

        self.assertEqual(
            response.status_code,
            405,
        )

    def test_candle_bounds_are_enforced(self):
        response = self.client.get(
            "/v1/candles/XAUUSD"
            "?timeframe=M1&count=501",
            headers=self.headers,
        )

        self.assertEqual(
            response.status_code,
            422,
        )


if __name__ == "__main__":
    unittest.main()
