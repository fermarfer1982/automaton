from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SERVICE = (
    ROOT
    / "trading_lab"
    / "observation_service.py"
)

API = (
    ROOT
    / "trading_lab"
    / "observation_api.py"
)


class ObservationServiceSourceTests(
    unittest.TestCase
):
    def test_source_compiles(self):
        ast.parse(
            SERVICE.read_text(
                encoding="utf-8"
            )
        )

        ast.parse(
            API.read_text(
                encoding="utf-8"
            )
        )

    def test_service_has_no_execution_primitives(self):
        source = SERVICE.read_text(
            encoding="utf-8"
        )

        for forbidden in (
            "MetaTrader5",
            "order_send",
            "order_check",
            "order_calc_profit",
            "TRADE_ACTION_",
            "symbol_select",
            ".login(",
        ):
            self.assertNotIn(
                forbidden,
                source,
            )

    def test_service_does_not_import_backend(self):
        source = SERVICE.read_text(
            encoding="utf-8"
        )

        self.assertNotIn(
            "mt5_read_only_data",
            source,
        )

        self.assertNotIn(
            "mt5_read_only_worker",
            source,
        )

        self.assertIn(
            "mt5_read_only_client",
            source,
        )

        self.assertIn(
            "MarketExperienceLoop",
            source,
        )

        self.assertIn(
            "ResearchStore",
            source,
        )

    def test_service_binds_protected_identity(self):
        source = SERVICE.read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "config.authorized_account",
            source,
        )

        self.assertIn(
            "config.authorized_server",
            source,
        )

        self.assertIn(
            "config.allowed_symbol",
            source,
        )

    def test_health_is_local_and_wired_to_collector(self):
        service_source = SERVICE.read_text(
            encoding="utf-8"
        )
        api_source = API.read_text(
            encoding="utf-8"
        )

        self.assertIn(
            'host="127.0.0.1"',
            service_source,
        )
        self.assertIn(
            "collector_loop=collector_loop",
            service_source,
        )
        self.assertIn(
            '"/health"',
            api_source,
        )
        self.assertIn(
            '"execution_capable": False',
            api_source,
        )

    def test_api_contains_no_mutating_routes(self):
        source = API.read_text(
            encoding="utf-8"
        )

        self.assertNotIn(
            "@app.post",
            source,
        )

        self.assertNotIn(
            "@app.put",
            source,
        )

        self.assertNotIn(
            "@app.patch",
            source,
        )

        self.assertNotIn(
            "@app.delete",
            source,
        )

        self.assertNotIn(
            "/v1/trade/",
            source,
        )


if __name__ == "__main__":
    unittest.main()
