from __future__ import annotations

import tempfile
import unittest
import json
from dataclasses import replace
from pathlib import Path

from tests.audit_helpers import precreated_audit_path

from trading_lab.account_guard import AccountGuard
from trading_lab.application import GatewayApplication
from trading_lab.audit import HashChainAuditLog
from trading_lab.authorization import FileExecutionAuthorization
from trading_lab.config import RiskLimits
from trading_lab.domain import TradingMode
from trading_lab.execution_engine import ExecutionEngine
from trading_lab.gateway import MT5Gateway
from trading_lab.paper_engine import PaperEngine
from trading_lab.risk_engine import RiskEngine
from trading_lab.research_store import ResearchStore
from tests.fakes import FakeMT5Adapter
from tests.test_risk_engine import proposal


class GatewayApplicationTests(unittest.TestCase):
    def test_paper_market_observation_reconciles_without_mt5_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adapter = FakeMT5Adapter()
            audit = HashChainAuditLog(
                precreated_audit_path(Path(directory) / "audit.jsonl")
            )
            guard = AccountGuard(12345678, "Broker-Demo")
            research = ResearchStore(Path(directory) / "research.db")
            paper = PaperEngine(research, audit)
            gateway = MT5Gateway(
                mode=TradingMode.PAPER,
                adapter=adapter,
                account_guard=guard,
                risk_engine=RiskEngine(
                    "XAUUSD", 26081101,
                    RiskLimits(0.0025, 0.1, 30.0, 1, 0.1, 0.01, 20, 300),
                ),
                execution_engine=ExecutionEngine(adapter),
                audit=audit,
                execution_authorization=FileExecutionAuthorization(
                    Path(directory) / "demo.authorization", Path(directory) / "KILL_SWITCH"
                ),
                research_store=research,
                paper_engine=paper,
            )
            app = GatewayApplication(
                mode=TradingMode.PAPER,
                allowed_symbol="XAUUSD",
                adapter=adapter,
                account_guard=guard,
                gateway=gateway,
                audit=audit,
                research_store=research,
                paper_engine=paper,
                runtime_identity_verified=True,
            )
            self.assertEqual("PAPER_ACCEPTED", app.submit(proposal()).status.value)
            adapter.symbol = replace(adapter.symbol, bid=2404.20, ask=2404.40)
            app.market_snapshot("XAUUSD")
            self.assertEqual(1, research.strategy_metrics("emergent-research", "0.1.0").sample_size)
            self.assertNotIn("order_check", adapter.calls)
            self.assertNotIn("order_send", adapter.calls)

    def test_health_and_market_observation_never_execute(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adapter = FakeMT5Adapter()
            audit = HashChainAuditLog(
                precreated_audit_path(Path(directory) / "audit.jsonl")
            )
            guard = AccountGuard(12345678, "Broker-Demo")
            gateway = MT5Gateway(
                mode=TradingMode.OBSERVE_ONLY,
                adapter=adapter,
                account_guard=guard,
                risk_engine=RiskEngine(
                    "XAUUSD", 26081101,
                    RiskLimits(0.0025, 0.1, 30.0, 1, 0.1, 0.01, 20, 300),
                ),
                execution_engine=ExecutionEngine(adapter),
                audit=audit,
                execution_authorization=FileExecutionAuthorization(
                    Path(directory) / "demo.authorization", Path(directory) / "KILL_SWITCH"
                ),
            )
            app = GatewayApplication(
                mode=TradingMode.OBSERVE_ONLY,
                allowed_symbol="XAUUSD",
                adapter=adapter,
                account_guard=guard,
                gateway=gateway,
                audit=audit,
                research_store=ResearchStore(Path(directory) / "research.db"),
                runtime_identity_verified=True,
            )
            health = app.health()
            market = app.market_snapshot("XAUUSD")
            account = app.account_state()
            status = app.status()
            self.assertTrue(health["healthy"])
            self.assertEqual("XAUUSD", market["symbol"])
            self.assertTrue(health["exposure"]["clear"])
            self.assertNotIn("login", health)
            self.assertNotIn("server", health)
            sanitized = json.dumps({"account": account, "status": status}).lower()
            self.assertNotIn("12345678", sanitized)
            self.assertNotIn("broker-demo", sanitized)
            self.assertNotIn("terminal64", sanitized)
            self.assertIn("asia_range", market)
            self.assertEqual(0.0, status["daily_r"])
            self.assertIn("tick_time_utc", status["last_market_data"])
            self.assertIsNone(status["last_execution"])
            self.assertNotIn("order_check", adapter.calls)
            self.assertNotIn("order_send", adapter.calls)

    def test_market_endpoint_rejects_every_other_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adapter = FakeMT5Adapter()
            audit = HashChainAuditLog(
                precreated_audit_path(Path(directory) / "audit.jsonl")
            )
            guard = AccountGuard(12345678, "Broker-Demo")
            app = GatewayApplication(
                mode=TradingMode.OBSERVE_ONLY,
                allowed_symbol="XAUUSD",
                adapter=adapter,
                account_guard=guard,
                gateway=None,
                audit=audit,
            )
            with self.assertRaises(ValueError):
                app.market_snapshot("EURUSD")


if __name__ == "__main__":
    unittest.main()
