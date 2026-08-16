from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


FASTAPI_AVAILABLE = all(
    importlib.util.find_spec(module) is not None
    for module in ("fastapi", "pydantic", "httpx")
)

if FASTAPI_AVAILABLE:
    from fastapi.testclient import TestClient

    from trading_lab.account_guard import AccountGuard
    from trading_lab.api_auth import ApiKeyVerifier
    from trading_lab.application import GatewayApplication
    from trading_lab.audit import HashChainAuditLog
    from trading_lab.authorization import FileExecutionAuthorization
    from trading_lab.config import RiskLimits
    from trading_lab.domain import TradingMode
    from trading_lab.execution_engine import ExecutionEngine
    from trading_lab.fastapi_service import create_fastapi_app
    from trading_lab.gateway import MT5Gateway
    from trading_lab.position_sizer import PositionSizer
    from trading_lab.research_store import ResearchStore
    from trading_lab.risk_engine import RiskEngine
from tests.fakes import FakeMT5Adapter
from tests.audit_helpers import precreated_audit_path


@unittest.skipUnless(FASTAPI_AVAILABLE, "FastAPI hash-locked dependencies are not installed")
class FastApiServiceTests(unittest.TestCase):
    KEY = "A" * 43

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        directory = Path(self.temp.name)
        key_path = directory / "gateway.key"
        key_path.write_text(self.KEY, encoding="ascii")
        self.adapter = FakeMT5Adapter()
        audit = HashChainAuditLog(
            precreated_audit_path(directory / "audit.jsonl")
        )
        store = ResearchStore(directory / "research.db")
        guard = AccountGuard(12345678, "Broker-Demo")
        limits = RiskLimits(0.0025, 0.1, 30.0, 1, 0.1, 0.01, 20, 300)
        gateway = MT5Gateway(
            mode=TradingMode.OBSERVE_ONLY,
            adapter=self.adapter,
            account_guard=guard,
            risk_engine=RiskEngine("XAUUSD", 26081101, limits),
            execution_engine=ExecutionEngine(self.adapter),
            audit=audit,
            execution_authorization=FileExecutionAuthorization(
                directory / "demo.authorization", directory / "KILL_SWITCH",
            ),
            research_store=store,
        )
        application = GatewayApplication(
            mode=TradingMode.OBSERVE_ONLY,
            allowed_symbol="XAUUSD",
            adapter=self.adapter,
            account_guard=guard,
            gateway=gateway,
            audit=audit,
            research_store=store,
            runtime_identity_verified=True,
            magic_number=26081101,
            position_sizer=PositionSizer(self.adapter, limits),
            risk_limits=limits,
        )
        self.api = create_fastapi_app(application, ApiKeyVerifier(key_path))
        self.client = TestClient(self.api)
        self.headers = {"X-AUTOMATON-KEY": self.KEY}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_every_route_requires_the_external_api_key(self) -> None:
        protected_routes = [
            route for route in self.api.routes
            if getattr(route, "path", "").startswith("/v1")
        ]
        self.assertEqual(18, len(protected_routes))
        for route in protected_routes:
            path = route.path.replace("{symbol}", "XAUUSD").replace("{ticket}", "1")
            for method in route.methods:
                if method not in {"GET", "POST"}:
                    continue
                response = self.client.request(
                    method, path, json={} if method == "POST" else None
                )
                self.assertEqual(401, response.status_code, path)

    def test_schema_cannot_select_protected_execution_fields(self) -> None:
        body = {
            "action": "OPEN_LONG", "symbol": "XAUUSD", "entry_type": "MARKET",
            "stop_loss": 2398.0, "take_profit": 2404.0,
            "requested_risk_amount": 1.0, "hypothesis_id": "h1",
            "strategy_id": "s1", "setup_id": "setup1", "strategy_version": "1",
            "confidence": 0.5, "reason": "falsifiable test", "timeframe": "M1",
            "market_regime": "UNKNOWN", "volume": 1.0,
        }
        response = self.client.post(
            "/v1/trade/propose",
            headers={**self.headers, "Idempotency-Key": "e0db5b86-5e59-4f72-9234-7f7a8a34eb15"},
            json=body,
        )
        self.assertEqual(422, response.status_code)
        self.assertNotIn("order_check", self.adapter.calls)
        self.assertNotIn("order_send", self.adapter.calls)

    def test_observe_only_management_is_domain_rejected_without_mt5_execution(self) -> None:
        response = self.client.post(
            "/v1/trade/close", headers=self.headers,
            json={"ticket": 1, "reason": "protect capital"},
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("TRADING_MODE_OBSERVE_ONLY", response.json()["failed_codes"])
        self.assertNotIn("order_check", self.adapter.calls)
        self.assertNotIn("order_send", self.adapter.calls)


if __name__ == "__main__":
    unittest.main()
