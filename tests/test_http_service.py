from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from trading_lab.account_guard import AccountGuard
from trading_lab.application import GatewayApplication
from trading_lab.audit import HashChainAuditLog
from trading_lab.authorization import FileExecutionAuthorization
from trading_lab.config import RiskLimits
from trading_lab.domain import TradingMode
from trading_lab.execution_engine import ExecutionEngine
from trading_lab.gateway import MT5Gateway
from trading_lab.research_store import ResearchStore
from trading_lab.risk_engine import RiskEngine
from trading_lab.service import create_server
from tests.fakes import FakeMT5Adapter
from tests.test_service import valid_payload


class HttpServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        directory = Path(self.temp.name)
        adapter = FakeMT5Adapter()
        audit = HashChainAuditLog(directory / "audit.jsonl")
        research = ResearchStore(directory / "research.db")
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
                directory / "demo.authorization", directory / "KILL_SWITCH"
            ),
            research_store=research,
        )
        app = GatewayApplication(
            mode=TradingMode.OBSERVE_ONLY,
            allowed_symbol="XAUUSD",
            adapter=adapter,
            account_guard=guard,
            gateway=gateway,
            audit=audit,
            research_store=research,
            runtime_identity_verified=True,
        )
        self.server = create_server(app, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def get_json(self, path: str) -> tuple[int, dict[str, object]]:
        with urlopen(self.base + path, timeout=2) as response:
            return response.status, json.loads(response.read())

    def post_json(self, path: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
        request = Request(
            self.base + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=2) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def test_health_market_and_proposal_are_real_json(self) -> None:
        status, health = self.get_json("/v1/health")
        self.assertEqual(200, status)
        self.assertEqual("OBSERVE_ONLY", health["mode"])
        status, market = self.get_json("/v1/market/XAUUSD")
        self.assertEqual(200, status)
        self.assertEqual("XAUUSD", market["symbol"])
        status, result = self.post_json("/v1/proposals", valid_payload())
        self.assertEqual(200, status)
        self.assertEqual("OBSERVED", result["status"])
        self.assertEqual("OBSERVE_ONLY", result["mode"])

    def test_no_mode_or_execution_endpoint_exists(self) -> None:
        for path in ("/v1/mode", "/v1/execute", "/v1/account/login"):
            with self.subTest(path=path):
                status, payload = self.post_json(path, {})
                self.assertEqual(404, status)
                self.assertEqual("not_found", payload["error"])

    def test_request_cannot_add_account_or_mode(self) -> None:
        payload = valid_payload()
        payload["trading_mode"] = "DEMO_EXECUTION"
        status, result = self.post_json("/v1/proposals", payload)
        self.assertEqual(400, status)
        self.assertEqual("invalid_proposal", result["error"])


if __name__ == "__main__":
    unittest.main()
