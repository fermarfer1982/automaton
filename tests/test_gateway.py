from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from trading_lab.account_guard import AccountGuard
from trading_lab.audit import HashChainAuditLog
from trading_lab.authorization import FileExecutionAuthorization
from trading_lab.config import RiskLimits
from trading_lab.domain import AccountKind, GatewayStatus, TradingMode
from trading_lab.execution_engine import ExecutionEngine
from trading_lab.gateway import MT5Gateway
from trading_lab.paper_engine import PaperEngine
from trading_lab.research_store import ResearchStore
from trading_lab.risk_engine import RiskEngine
from tests.fakes import FakeMT5Adapter
from tests.audit_helpers import precreated_audit_path
from tests.test_risk_engine import proposal


class GatewayTests(unittest.TestCase):
    def build_gateway(self, directory: str, mode: TradingMode, audit=None) -> tuple[MT5Gateway, FakeMT5Adapter, Path, Path]:
        adapter = FakeMT5Adapter()
        authorization_path = Path(directory) / "demo.authorization"
        kill_path = Path(directory) / "KILL_SWITCH"
        audit = audit or HashChainAuditLog(
            precreated_audit_path(Path(directory) / "audit.jsonl")
        )
        research = ResearchStore(Path(directory) / "research.db")
        paper = PaperEngine(research, audit)
        gateway = MT5Gateway(
            mode=mode,
            adapter=adapter,
            account_guard=AccountGuard(12345678, "Broker-Demo"),
            risk_engine=RiskEngine(
                "XAUUSD",
                26081101,
                RiskLimits(
                    max_risk_per_trade_fraction=0.0025,
                    max_volume=0.10,
                    max_spread_points=30.0,
                    max_open_positions=1,
                    max_symbol_exposure_lots=0.10,
                    max_daily_loss_fraction=0.01,
                    min_stop_distance_points=20,
                    duplicate_window_seconds=300,
                ),
            ),
            execution_engine=ExecutionEngine(adapter),
            audit=audit,
            execution_authorization=FileExecutionAuthorization(authorization_path, kill_path),
            research_store=research,
            paper_engine=paper,
        )
        return gateway, adapter, authorization_path, kill_path

    def test_audit_failure_before_send_prevents_order(self) -> None:
        class FailingAudit:
            def __init__(self, path: Path) -> None:
                self.delegate = HashChainAuditLog(path)

            def append(self, event, payload):
                if event == "order_send_authorized":
                    raise OSError("audit disk unavailable")
                return self.delegate.append(event, payload)

            def has_recent_fingerprint(self, fingerprint, window_seconds):
                return self.delegate.has_recent_fingerprint(fingerprint, window_seconds)

            def verify(self):
                return self.delegate.verify()

            def has_unreconciled_execution(self, fingerprint):
                return self.delegate.has_unreconciled_execution(fingerprint)

            def has_recent_entry(self, window_seconds):
                return self.delegate.has_recent_entry(window_seconds)

        with tempfile.TemporaryDirectory() as directory:
            audit = FailingAudit(
                precreated_audit_path(Path(directory) / "audit.jsonl")
            )
            gateway, adapter, authorization_path, _ = self.build_gateway(
                directory, TradingMode.DEMO_EXECUTION, audit=audit
            )
            authorization_path.write_text("ALLOW_DEMO_EXECUTION\n", encoding="utf-8")
            result = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.REJECTED, result.status)
            self.assertIn("GATEWAY_INTERNAL_ERROR", result.failed_codes)
            self.assertNotIn("order_send", adapter.calls)

    def test_observe_only_never_calls_order_check_or_send(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway, adapter, _, _ = self.build_gateway(directory, TradingMode.OBSERVE_ONLY)
            result = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.OBSERVED, result.status)
            self.assertNotIn("order_check", adapter.calls)
            self.assertNotIn("order_send", adapter.calls)

    def test_paper_never_calls_mt5_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway, adapter, _, _ = self.build_gateway(directory, TradingMode.PAPER)
            result = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.PAPER_ACCEPTED, result.status)
            self.assertNotIn("order_check", adapter.calls)
            self.assertNotIn("order_send", adapter.calls)
            self.assertEqual(1, len(gateway._paper_engine.position_snapshots()))

            second = gateway.submit(replace(proposal(), proposal_id="proposal-002"))
            self.assertEqual(GatewayStatus.REJECTED, second.status)
            self.assertIn("EXISTING_SYMBOL_POSITION", second.failed_codes)

    def test_paper_entry_cooldown_survives_position_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway, adapter, _, _ = self.build_gateway(directory, TradingMode.PAPER)
            first = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.PAPER_ACCEPTED, first.status)
            ticket = gateway._paper_engine.position_snapshots()[0].ticket
            gateway._paper_engine.close(ticket, adapter.symbol)
            second = gateway.submit(replace(proposal(), proposal_id="proposal-002"))
            self.assertEqual(GatewayStatus.REJECTED, second.status)
            self.assertIn("COOLDOWN_ACTIVE", second.failed_codes)

    def test_demo_execution_requires_external_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway, adapter, _, _ = self.build_gateway(directory, TradingMode.DEMO_EXECUTION)
            result = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.REJECTED, result.status)
            self.assertIn("DEMO_EXECUTION_NOT_AUTHORIZED", result.failed_codes)
            self.assertNotIn("order_send", adapter.calls)

    def test_kill_switch_overrides_valid_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway, adapter, authorization_path, kill_path = self.build_gateway(directory, TradingMode.DEMO_EXECUTION)
            authorization_path.write_text("ALLOW_DEMO_EXECUTION\n", encoding="utf-8")
            kill_path.write_text("HALT\n", encoding="utf-8")
            result = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.REJECTED, result.status)
            self.assertIn("KILL_SWITCH_ENGAGED", result.failed_codes)
            self.assertNotIn("order_send", adapter.calls)

    def test_demo_order_check_precedes_send(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway, adapter, authorization_path, _ = self.build_gateway(directory, TradingMode.DEMO_EXECUTION)
            authorization_path.write_text("ALLOW_DEMO_EXECUTION\n", encoding="utf-8")
            result = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.EXECUTED, result.status)
            self.assertLess(adapter.calls.index("order_check"), adapter.calls.index("order_send"))

    def test_failed_order_check_prevents_send(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway, adapter, authorization_path, _ = self.build_gateway(directory, TradingMode.DEMO_EXECUTION)
            authorization_path.write_text("ALLOW_DEMO_EXECUTION\n", encoding="utf-8")
            adapter.order_check_result = replace(
                adapter.order_check_result, ok=False, retcode=10013, comment="invalid"
            )
            result = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.REJECTED, result.status)
            self.assertIn("ORDER_CHECK_FAILED", result.failed_codes)
            self.assertNotIn("order_send", adapter.calls)

    def test_kill_switch_engaged_during_order_check_prevents_send(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway, adapter, authorization_path, kill_path = self.build_gateway(
                directory, TradingMode.DEMO_EXECUTION
            )
            authorization_path.write_text("ALLOW_DEMO_EXECUTION\n", encoding="utf-8")
            original_order_check = adapter.order_check

            def check_then_kill(request):
                result = original_order_check(request)
                kill_path.write_text("HALT\n", encoding="utf-8")
                return result

            adapter.order_check = check_then_kill  # type: ignore[method-assign]
            result = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.REJECTED, result.status)
            self.assertIn("EXECUTION_AUTHORIZATION_REVOKED", result.failed_codes)
            self.assertNotIn("order_send", adapter.calls)

    def test_real_account_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway, adapter, authorization_path, _ = self.build_gateway(directory, TradingMode.DEMO_EXECUTION)
            authorization_path.write_text("ALLOW_DEMO_EXECUTION\n", encoding="utf-8")
            adapter.account = replace(adapter.account, kind=AccountKind.REAL)
            result = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.REJECTED, result.status)
            self.assertIn("ACCOUNT_NOT_DEMO", result.failed_codes)
            self.assertNotIn("order_check", adapter.calls)
            self.assertNotIn("order_send", adapter.calls)

    def test_gateway_fails_closed_on_adapter_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway, adapter, _, _ = self.build_gateway(directory, TradingMode.OBSERVE_ONLY)
            def broken_account():
                raise RuntimeError("terminal unavailable")
            adapter.account_snapshot = broken_account  # type: ignore[method-assign]
            result = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.REJECTED, result.status)
            self.assertIn("GATEWAY_INTERNAL_ERROR", result.failed_codes)

    def test_tampered_audit_rejects_before_reading_mt5(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway, adapter, _, _ = self.build_gateway(directory, TradingMode.OBSERVE_ONLY)
            first = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.OBSERVED, first.status)
            audit_path = Path(directory) / "audit.jsonl"
            text = audit_path.read_text(encoding="utf-8")
            audit_path.write_text(text.replace("proposal_received", "proposal_changed", 1), encoding="utf-8")
            adapter.calls.clear()
            result = gateway.submit(replace(proposal(), proposal_id="proposal-002"))
            self.assertEqual(GatewayStatus.REJECTED, result.status)
            self.assertIn("AUDIT_CHAIN_INVALID", result.failed_codes)
            self.assertEqual([], adapter.calls)

    def test_order_send_exception_is_uncertain_and_cannot_be_retried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway, adapter, authorization_path, _ = self.build_gateway(
                directory, TradingMode.DEMO_EXECUTION
            )
            authorization_path.write_text("ALLOW_DEMO_EXECUTION\n", encoding="utf-8")

            def uncertain_send(_request):
                adapter.calls.append("order_send")
                raise TimeoutError("response lost")

            adapter.order_send = uncertain_send  # type: ignore[method-assign]
            first = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.EXECUTION_UNCERTAIN, first.status)
            self.assertIn("ORDER_SEND_UNCERTAIN", first.failed_codes)

            second = gateway.submit(replace(proposal(), proposal_id="proposal-002"))
            self.assertEqual(GatewayStatus.EXECUTION_UNCERTAIN, second.status)
            self.assertIn("EXECUTION_RECONCILIATION_REQUIRED", second.failed_codes)
            self.assertEqual(1, adapter.calls.count("order_send"))

    def test_post_send_audit_failure_is_reported_as_uncertain(self) -> None:
        class ResultFailingAudit:
            def __init__(self, path: Path) -> None:
                self.delegate = HashChainAuditLog(path)

            def append(self, event, payload):
                if event == "order_send_result":
                    raise OSError("audit result unavailable")
                return self.delegate.append(event, payload)

            def has_recent_fingerprint(self, fingerprint, window_seconds):
                return self.delegate.has_recent_fingerprint(fingerprint, window_seconds)

            def verify(self):
                return self.delegate.verify()

            def has_unreconciled_execution(self, fingerprint):
                return self.delegate.has_unreconciled_execution(fingerprint)

            def has_recent_entry(self, window_seconds):
                return self.delegate.has_recent_entry(window_seconds)

        with tempfile.TemporaryDirectory() as directory:
            audit = ResultFailingAudit(
                precreated_audit_path(Path(directory) / "audit.jsonl")
            )
            gateway, adapter, authorization_path, _ = self.build_gateway(
                directory, TradingMode.DEMO_EXECUTION, audit=audit
            )
            authorization_path.write_text("ALLOW_DEMO_EXECUTION\n", encoding="utf-8")
            result = gateway.submit(proposal())
            self.assertEqual(GatewayStatus.EXECUTION_UNCERTAIN, result.status)
            self.assertIn("POST_SEND_AUDIT_FAILED", result.failed_codes)
            self.assertEqual(1, adapter.calls.count("order_send"))


if __name__ == "__main__":
    unittest.main()
