from __future__ import annotations

from contextlib import closing
import sqlite3
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from trading_lab.audit import HashChainAuditLog
from trading_lab.domain import TradingMode
from trading_lab.health_only import (
    EXPECTED_MT5_PACKAGE_VERSION,
    HealthOnlyGatewayApplication,
)
from trading_lab.mt5_access import MT5AccessDisabled
from trading_lab.research_store import ResearchStore


class FakeLatestClosedM1Provider:
    def __init__(
        self,
        time_msc: int,
    ) -> None:
        self.time_msc = time_msc
        self.calls: list[str] = []

    def latest_closed_m1(
        self,
        symbol: str,
    ):
        self.calls.append(symbol)

        return {
            "symbol": symbol,
            "timeframe": "M1",
            "time_msc": self.time_msc,
            "open": 2400.0,
            "high": 2401.0,
            "low": 2399.0,
            "close": 2400.5,
            "tick_volume": 100,
            "spread": 20,
        }


class HealthOnlyResearchTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(
            self.temp.name
        )

        self.audit_path = (
            self.root
            / "audit.jsonl"
        )

        self.audit_path.write_text(
            "",
            encoding="utf-8",
        )

        self.research_path = (
            self.root
            / "research.db"
        )

        self.config = SimpleNamespace(
            mt5_access_enabled=False,
            trading_mode=(
                TradingMode.OBSERVE_ONLY
            ),
            allowed_symbol="XAUUSD",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def application(
        self,
        provider=None,
    ):
        return HealthOnlyGatewayApplication(
            config=self.config,
            audit=HashChainAuditLog(
                self.audit_path
            ),
            research_store=ResearchStore(
                self.research_path
            ),
            runtime_identity_verified=True,
            package_version=(
                EXPECTED_MT5_PACKAGE_VERSION
            ),
            latest_closed_m1_provider=provider,
        )

    @staticmethod
    def decision_payload(
        timestamp: datetime,
        decision_id: str = "d1",
    ):
        return {
            "decision_id": decision_id,
            "action": "HOLD",
            "symbol": "XAUUSD",
            "timeframe": "M1",
            "bar_time_utc":
                timestamp.isoformat(),
            "reason": "No valid setup",
            "hypothesis_id": None,
        }

    def decision_count(self) -> int:
        with closing(
            sqlite3.connect(
                self.research_path
            )
        ) as connection:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM agent_decisions
                """
            ).fetchone()

        assert row is not None

        return int(row[0])

    def test_matching_latest_closed_m1_records_decision(
        self,
    ) -> None:
        timestamp = datetime(
            2026,
            8,
            19,
            5,
            40,
            tzinfo=UTC,
        )

        provider = (
            FakeLatestClosedM1Provider(
                int(
                    timestamp.timestamp()
                    * 1000
                )
            )
        )

        result = self.application(
            provider
        ).record_decision(
            self.decision_payload(
                timestamp
            )
        )

        self.assertEqual(
            {
                "recorded": True,
                "decision_id": "d1",
            },
            result,
        )

        self.assertEqual(
            ["XAUUSD"],
            provider.calls,
        )

        self.assertEqual(
            1,
            self.decision_count(),
        )

        with closing(
            sqlite3.connect(
                self.research_path
            )
        ) as connection:
            row = connection.execute(
                """
                SELECT
                    decision_id,
                    bar_time_utc
                FROM agent_decisions
                """
            ).fetchone()

        self.assertEqual(
            "d1",
            row[0],
        )

        self.assertEqual(
            timestamp.isoformat(),
            row[1],
        )

    def test_stale_or_wrong_bar_is_rejected_without_persistence(
        self,
    ) -> None:
        requested = datetime(
            2026,
            8,
            19,
            5,
            40,
            tzinfo=UTC,
        )

        actual = datetime(
            2026,
            8,
            19,
            5,
            41,
            tzinfo=UTC,
        )

        provider = (
            FakeLatestClosedM1Provider(
                int(
                    actual.timestamp()
                    * 1000
                )
            )
        )

        with self.assertRaisesRegex(
            ValueError,
            "latest closed XAUUSD M1 bar",
        ):
            self.application(
                provider
            ).record_decision(
                self.decision_payload(
                    requested
                )
            )

        self.assertEqual(
            0,
            self.decision_count(),
        )

    def test_missing_observation_provider_fails_closed(
        self,
    ) -> None:
        timestamp = datetime(
            2026,
            8,
            19,
            5,
            40,
            tzinfo=UTC,
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "provider is unavailable",
        ):
            self.application().record_decision(
                self.decision_payload(
                    timestamp
                )
            )

        self.assertEqual(
            0,
            self.decision_count(),
        )

    def test_non_mt5_research_remains_available_but_trade_mutation_is_disabled(
        self,
    ) -> None:
        application = self.application()

        metrics = (
            application.research_metrics()
        )

        self.assertEqual(
            30,
            metrics[
                "minimum_evidence_sample"
            ],
        )

        hypothesis = (
            application.save_hypothesis(
                "h1",
                "Testable thesis",
            )
        )

        self.assertEqual(
            {
                "recorded": True,
                "hypothesis_id": "h1",
            },
            hypothesis,
        )

        memory = application.recent_memory(
            10
        )

        self.assertIsInstance(
            memory,
            dict,
        )

        self.assertIn(
            "items",
            memory,
        )

        with self.assertRaises(
            MT5AccessDisabled
        ):
            application.propose_semantic(
                {}
            )

        self.assertNotIn(
            "MetaTrader5",
            sys.modules,
        )


if __name__ == "__main__":
    unittest.main()