from __future__ import annotations

import unittest

from trading_lab.observation_application import (
    ObservationApplication,
)


ACCOUNT = 12345678
SERVER = "Broker-Demo"


class FakeClient:
    def __init__(self):
        self.account_payload = {
            "login": ACCOUNT,
            "server": SERVER,
            "account_name": "Hidden",
            "kind": "DEMO",
            "equity": 10000.0,
            "balance": 10000.0,
            "connected": True,
            "trade_allowed": True,
            "terminal_trade_allowed": False,
            "currency": "EUR",
        }

        self.history_request = None

    def ping(self):
        return {
            "service":
            "mt5-read-only-worker",
            "execution_capable": False,
        }

    def account(self):
        return dict(self.account_payload)

    def symbol(self, symbol="XAUUSD"):
        return {
            "symbol": symbol,
            "bid": 4400.0,
            "ask": 4400.2,
        }

    def candles(
        self,
        timeframe,
        count,
        *,
        symbol="XAUUSD",
    ):
        return [
            {
                "symbol": symbol,
                "timeframe": timeframe,
                "time_msc": index + 1,
                "open": 1.0,
                "high": 2.0,
                "low": 0.5,
                "close": 1.5,
            }
            for index in range(count)
        ]

    def positions(self):
        return {
            "scope": "ACCOUNT",
            "positions": [
                {
                    "ticket": 1,
                    "symbol": "XAUUSD",
                }
            ],
        }

    def active_orders(self):
        return {
            "scope": "ACCOUNT",
            "orders": [
                {
                    "ticket": 2,
                    "symbol": "XAUUSD",
                }
            ],
        }

    def history(
        self,
        *,
        from_utc,
        to_utc,
        limit=100,
        symbol="XAUUSD",
    ):
        self.history_request = {
            "from_utc": from_utc,
            "to_utc": to_utc,
            "limit": limit,
            "symbol": symbol,
        }

        return [
            {
                "ticket": 3,
                "symbol": "XAUUSD",
            }
        ]

    def daily_pnl(self):
        return {
            "scope": "ACCOUNT",
            "realized_pnl": 12.5,
        }


class ObservationApplicationTests(
    unittest.TestCase
):
    def setUp(self):
        self.client = FakeClient()

        self.app = ObservationApplication(
            self.client,
            authorized_account=ACCOUNT,
            authorized_server=SERVER,
        )

    def test_status_is_non_executable(self):
        result = self.app.status()

        self.assertEqual(
            result["mode"],
            "OBSERVE_ONLY",
        )

        self.assertFalse(
            result["execution_capable"]
        )

        self.assertFalse(
            result[
                "terminal_trade_allowed"
            ]
        )

    def test_account_hides_identifiers(self):
        result = self.app.account_state()

        self.assertNotIn("login", result)
        self.assertNotIn("server", result)
        self.assertNotIn(
            "account_name",
            result,
        )

    def test_account_mismatch_fails_closed(self):
        self.client.account_payload[
            "login"
        ] = ACCOUNT + 1

        with self.assertRaises(
            RuntimeError
        ):
            self.app.account_state()

    def test_server_mismatch_fails_closed(self):
        self.client.account_payload[
            "server"
        ] = "Other-Demo"

        with self.assertRaises(
            RuntimeError
        ):
            self.app.account_state()

    def test_non_demo_fails_closed(self):
        self.client.account_payload[
            "kind"
        ] = "REAL"

        with self.assertRaises(
            RuntimeError
        ):
            self.app.status()

    def test_terminal_trading_fails_closed(self):
        self.client.account_payload[
            "terminal_trade_allowed"
        ] = True

        with self.assertRaises(
            RuntimeError
        ):
            self.app.status()

    def test_market_contains_all_timeframes(self):
        result = self.app.market_snapshot(
            "XAUUSD"
        )

        self.assertEqual(
            set(result["timeframes"]),
            {
                "M1",
                "M5",
                "M15",
                "H1",
            },
        )

        for rows in (
            result["timeframes"].values()
        ):
            self.assertEqual(
                len(rows),
                20,
            )

    def test_positions_unwraps_real_protocol(self):
        result = self.app.positions_state()

        self.assertEqual(
            result["scope"],
            "account",
        )

        self.assertEqual(
            result["positions"][0]["ticket"],
            1,
        )

    def test_active_orders_unwraps_real_protocol(self):
        result = self.app.active_orders_state()

        self.assertEqual(
            result["active_orders"][0][
                "ticket"
            ],
            2,
        )

    def test_daily_pnl_unwraps_real_protocol(self):
        result = self.app.daily_stats()

        self.assertEqual(
            result["realized_pnl"],
            12.5,
        )

        self.assertEqual(
            result["currency"],
            "EUR",
        )

    def test_history_uses_real_client_signature(self):
        result = self.app.history_state(
            from_utc=(
                "2026-08-18T10:00:00Z"
            ),
            to_utc=(
                "2026-08-18T11:00:00Z"
            ),
            symbol="XAUUSD",
            limit=50,
        )

        self.assertEqual(
            result["count"],
            1,
        )

        self.assertEqual(
            self.client.history_request,
            {
                "from_utc":
                "2026-08-18T10:00:00+00:00",
                "to_utc":
                "2026-08-18T11:00:00+00:00",
                "limit": 50,
                "symbol": "XAUUSD",
            },
        )

    def test_history_rejects_non_utc(self):
        with self.assertRaises(
            ValueError
        ):
            self.app.history_state(
                from_utc=(
                    "2026-08-18T10:00:00+02:00"
                ),
                to_utc=(
                    "2026-08-18T11:00:00+02:00"
                ),
                symbol="XAUUSD",
                limit=50,
            )

    def test_history_rejects_over_31_days(self):
        with self.assertRaises(
            ValueError
        ):
            self.app.history_state(
                from_utc=(
                    "2026-07-01T00:00:00Z"
                ),
                to_utc=(
                    "2026-08-02T00:00:00Z"
                ),
                symbol="XAUUSD",
                limit=50,
            )

    def test_invalid_symbol_fails_closed(self):
        with self.assertRaises(
            ValueError
        ):
            self.app.market_snapshot(
                "EURUSD"
            )

    def test_invalid_timeframe_fails_closed(self):
        with self.assertRaises(
            ValueError
        ):
            self.app.candles(
                "XAUUSD",
                "D1",
                10,
            )


if __name__ == "__main__":
    unittest.main()
