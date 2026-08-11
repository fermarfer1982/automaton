from __future__ import annotations

import tempfile
import unittest
import json
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from trading_lab.config import security_config_hash
from trading_lab.domain import OpenAction, OrderCheckResult, SemanticTradeRequest, TradingMode
from trading_lab.factory import build_application
from trading_lab.research_store import ResearchStore
from tests.fakes import FakeMT5Adapter
from tests.test_readiness import security_config


def semantic_request(**overrides):
    values = {
        "idempotency_key": str(uuid4()),
        "action": OpenAction.OPEN_LONG,
        "symbol": "XAUUSD",
        "entry_type": "MARKET",
        "stop_loss": 2398.0,
        "take_profit": 2404.0,
        "requested_risk_amount": 1.0,
        "hypothesis_id": "hypothesis-001",
        "strategy_id": "emergent-research",
        "setup_id": "breakout-observation",
        "strategy_version": "0.1.0",
        "confidence": 0.6,
        "reason": "A falsifiable hypothesis with invalidation at the stop.",
        "timeframe": "M1",
        "market_regime": "UNKNOWN",
    }
    values.update(overrides)
    return SemanticTradeRequest(**values)


class SemanticProposalTests(unittest.TestCase):
    def test_agent_supplies_risk_and_gateway_generates_volume_magic_and_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adapter = FakeMT5Adapter()
            config = security_config(Path(directory))
            app = build_application(config, adapter, runtime_identity_verified=True)
            request = semantic_request()
            result = app.propose_semantic(request)
            self.assertEqual("OBSERVED", result["status"])
            self.assertEqual(0.01, result["calculated_volume"])
            self.assertNotEqual(request.idempotency_key, result["proposal_id"])
            self.assertNotIn("order_check", adapter.calls)
            self.assertNotIn("order_send", adapter.calls)

    def test_same_idempotency_key_replays_without_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adapter = FakeMT5Adapter()
            app = build_application(
                security_config(Path(directory)), adapter, runtime_identity_verified=True
            )
            request = semantic_request()
            first = app.propose_semantic(request)
            calls = list(adapter.calls)
            second = app.propose_semantic(request)
            self.assertEqual(first["proposal_id"], second["proposal_id"])
            self.assertTrue(second["idempotent_replay"])
            self.assertEqual(calls, adapter.calls)

    def test_reused_key_with_changed_payload_is_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = build_application(
                security_config(Path(directory)), FakeMT5Adapter(), runtime_identity_verified=True
            )
            request = semantic_request()
            app.propose_semantic(request)
            with self.assertRaises(FileExistsError):
                app.propose_semantic(semantic_request(
                    idempotency_key=request.idempotency_key,
                    requested_risk_amount=2.0,
                ))

    def test_excessive_requested_risk_is_rejected_before_gateway_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adapter = FakeMT5Adapter()
            app = build_application(
                security_config(Path(directory)), adapter, runtime_identity_verified=True
            )
            result = app.propose_semantic(semantic_request(requested_risk_amount=100.0))
            self.assertEqual("REJECTED_RISK", result["status"])
            self.assertIn("DENIED_RISK_LIMIT", result["failed_codes"])
            self.assertNotIn("order_check", adapter.calls)

    def test_execution_failure_has_distinct_durable_lifecycle_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = FakeMT5Adapter()
            adapter.order_check_result = OrderCheckResult(False, 10030, "invalid")
            config = replace(
                security_config(root), trading_mode=TradingMode.DEMO_EXECUTION
            )
            config.demo_authorization_path.parent.mkdir(parents=True, exist_ok=True)
            config.demo_authorization_path.write_text(
                json.dumps({
                    "schema_version": 1,
                    "authorization": "ALLOW_DEMO_EXECUTION",
                    "authorized_account": config.authorized_account,
                    "authorized_server": config.authorized_server,
                    "config_sha256": security_config_hash(config),
                    "readiness_sha256": "a" * 64,
                }),
                encoding="utf-8",
            )
            app = build_application(config, adapter, runtime_identity_verified=True)
            result = app.propose_semantic(semantic_request())
            self.assertEqual("REJECTED", result["status"])
            self.assertIn("ORDER_CHECK_FAILED", result["failed_codes"])
            lifecycle = ResearchStore(config.research_db_path).latest_lifecycle_event()
            self.assertEqual("EXECUTION_FAILED", lifecycle["state"])
            self.assertNotIn("order_send", adapter.calls)


if __name__ == "__main__":
    unittest.main()
