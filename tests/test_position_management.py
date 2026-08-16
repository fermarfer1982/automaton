from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from time import time

from trading_lab.account_guard import AccountGuard
from trading_lab.audit import HashChainAuditLog
from trading_lab.authorization import FileExecutionAuthorization
from trading_lab.config import RiskLimits
from trading_lab.domain import ActiveOrderSnapshot, PositionSnapshot, Side, TradingMode
from trading_lab.execution_engine import ExecutionEngine
from trading_lab.gateway import MT5Gateway
from trading_lab.paper_engine import PaperEngine
from trading_lab.research_store import ResearchStore
from trading_lab.risk_engine import RiskEngine
from tests.fakes import FakeMT5Adapter
from tests.audit_helpers import precreated_audit_path
from tests.test_risk_engine import proposal


class PositionManagementTests(unittest.TestCase):
    def build(self, directory: Path, mode: TradingMode, *, authorize: bool = True):
        adapter = FakeMT5Adapter()
        audit = HashChainAuditLog(
            precreated_audit_path(directory / "audit.jsonl")
        )
        store = ResearchStore(directory / "research.db")
        paper = PaperEngine(store, audit)
        if mode is TradingMode.DEMO_EXECUTION and authorize:
            (directory / "demo.authorization").write_text(
                "ALLOW_DEMO_EXECUTION\n", encoding="utf-8"
            )
        gateway = MT5Gateway(
            mode=mode,
            adapter=adapter,
            account_guard=AccountGuard(12345678, "Broker-Demo"),
            risk_engine=RiskEngine(
                "XAUUSD", 26081101,
                RiskLimits(0.0025, 0.10, 30.0, 1, 0.10, 0.01, 20, 300),
            ),
            execution_engine=ExecutionEngine(adapter, 10),
            audit=audit,
            execution_authorization=FileExecutionAuthorization(
                directory / "demo.authorization", directory / "KILL_SWITCH",
            ),
            research_store=store,
            paper_engine=paper,
        )
        return gateway, adapter, paper, store

    @staticmethod
    def owned_position(magic: int = 26081101) -> PositionSnapshot:
        return PositionSnapshot(
            ticket=77, symbol="XAUUSD", side=Side.BUY, volume=0.01,
            price_open=2399.0, stop_loss=2398.0, profit=1.0,
            magic_number=magic,
        )

    def test_observe_only_records_and_denies_before_order_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            gateway, adapter, _, _ = self.build(Path(temporary), TradingMode.OBSERVE_ONLY)
            result = gateway.manage_position("CLOSE", {"ticket": 77, "reason": "risk exit"})
            self.assertEqual("REJECTED_SECURITY", result["status"])
            self.assertIn("TRADING_MODE_OBSERVE_ONLY", result["failed_codes"])
            self.assertNotIn("order_check", adapter.calls)
            self.assertNotIn("order_send", adapter.calls)

    def test_paper_modify_only_reduces_risk_then_closes_durably(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            gateway, adapter, paper, store = self.build(Path(temporary), TradingMode.PAPER)
            paper.open(proposal(), adapter.symbol)
            ticket = paper.position_snapshots()[0].ticket
            widened = gateway.manage_position("MODIFY", {
                "ticket": ticket, "stop_loss": 2397.0,
                "take_profit": 2404.0, "reason": "invalid widening",
            })
            self.assertEqual("REJECTED", widened["status"])
            self.assertIn("STOP_LOSS_WIDENING_FORBIDDEN", widened["failed_codes"])

            modified = gateway.manage_position("MODIFY", {
                "ticket": ticket, "stop_loss": 2399.0,
                "take_profit": 2404.0, "reason": "reduce risk",
            })
            self.assertEqual("PAPER_EXECUTED", modified["status"])
            self.assertEqual(2399.0, paper.position_snapshots()[0].stop_loss)
            closed = gateway.manage_position("CLOSE", {
                "ticket": ticket, "reason": "manual paper exit",
            })
            self.assertEqual("PAPER_EXECUTED", closed["status"])
            self.assertEqual([], paper.position_snapshots())
            self.assertEqual(1, store.strategy_metrics("emergent-research", "0.1.0").sample_size)
            self.assertNotIn("order_check", adapter.calls)
            self.assertNotIn("order_send", adapter.calls)

    def test_demo_rejects_foreign_magic_and_executes_full_owned_close(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            gateway, adapter, _, _ = self.build(Path(temporary), TradingMode.DEMO_EXECUTION)
            adapter.open_positions = [self.owned_position(magic=999)]
            self.assertEqual(
                {"trading_enabled": True, "kill_switch": "CLEAR"},
                gateway.execution_control_state(),
            )
            rejected = gateway.manage_position("CLOSE", {"ticket": 77, "reason": "exit"})
            self.assertIn("POSITION_NOT_OWNED", rejected["failed_codes"])
            self.assertNotIn("order_check", adapter.calls)

            adapter.calls.clear()
            adapter.open_positions = [self.owned_position()]
            executed = gateway.manage_position("CLOSE", {"ticket": 77, "reason": "exit"})
            self.assertEqual("EXECUTED", executed["status"])
            self.assertLess(adapter.calls.index("order_check"), adapter.calls.index("order_send"))

    def test_demo_cancel_requires_owned_xauusd_magic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            gateway, adapter, _, _ = self.build(Path(temporary), TradingMode.DEMO_EXECUTION)
            adapter.open_orders = [ActiveOrderSnapshot(91, "XAUUSD", 0.01, 26081101)]
            result = gateway.manage_position(
                "CANCEL_PENDING", {"ticket": 91, "reason": "remove risk"},
            )
            self.assertEqual("EXECUTED", result["status"])

    def test_demo_management_requires_authorization_but_kill_allows_risk_reduction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gateway, adapter, _, _ = self.build(
                root, TradingMode.DEMO_EXECUTION, authorize=False
            )
            adapter.open_positions = [self.owned_position()]
            rejected = gateway.manage_position("CLOSE", {"ticket": 77, "reason": "exit"})
            self.assertEqual("REJECTED_SECURITY", rejected["status"])
            self.assertIn("DEMO_EXECUTION_NOT_AUTHORIZED", rejected["failed_codes"])
            self.assertNotIn("order_check", adapter.calls)

            (root / "KILL_SWITCH").write_text("HALT\n", encoding="ascii")
            self.assertEqual("ENGAGED", gateway.execution_control_state()["kill_switch"])
            adapter.calls.clear()
            allowed = gateway.manage_position("CLOSE", {"ticket": 77, "reason": "exit"})
            self.assertEqual("EXECUTED", allowed["status"])
            self.assertIn("KILL_SWITCH_RISK_REDUCTION_ALLOWED", [
                item["code"] for item in allowed["checks"]
            ])
            self.assertIn("order_send", adapter.calls)

    def test_uncertain_management_is_durably_blocked_from_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            gateway, adapter, _, _ = self.build(Path(temporary), TradingMode.DEMO_EXECUTION)
            adapter.open_positions = [self.owned_position()]

            def uncertain(_request):
                adapter.calls.append("order_send")
                raise TimeoutError("response lost")

            adapter.order_send = uncertain  # type: ignore[method-assign]
            payload = {"ticket": 77, "reason": "exit"}
            first = gateway.manage_position("CLOSE", payload)
            second = gateway.manage_position("CLOSE", payload)
            self.assertEqual("EXECUTION_UNCERTAIN", first["status"])
            self.assertEqual("EXECUTION_UNCERTAIN", second["status"])
            self.assertIn("EXECUTION_RECONCILIATION_REQUIRED", second["failed_codes"])
            self.assertEqual(1, adapter.calls.count("order_send"))

    def test_management_authorization_is_rechecked_after_order_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gateway, adapter, _, _ = self.build(root, TradingMode.DEMO_EXECUTION)
            adapter.open_positions = [self.owned_position()]

            def revoke_after_check(request):
                adapter.calls.append("order_check")
                (root / "demo.authorization").unlink()
                return adapter.order_check_result

            adapter.order_check = revoke_after_check  # type: ignore[method-assign]
            result = gateway.manage_position("CLOSE", {"ticket": 77, "reason": "exit"})
            self.assertEqual("REJECTED", result["status"])
            self.assertNotIn("order_send", adapter.calls)

    def test_demo_close_rechecks_tick_and_spread_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            gateway, adapter, _, _ = self.build(
                Path(temporary), TradingMode.DEMO_EXECUTION
            )
            adapter.open_positions = [self.owned_position()]
            adapter.symbol = replace(
                adapter.symbol, tick_time_msc=int((time() - 10) * 1000)
            )
            stale = gateway.manage_position("CLOSE", {"ticket": 77, "reason": "exit"})
            self.assertIn("MARKET_TICK_STALE", stale["failed_codes"])
            self.assertNotIn("order_check", adapter.calls)

            adapter.calls.clear()
            adapter.symbol = replace(
                adapter.symbol, ask=2401.0, tick_time_msc=int(time() * 1000)
            )
            wide = gateway.manage_position("CLOSE", {"ticket": 77, "reason": "exit"})
            self.assertIn("SPREAD_TOO_WIDE", wide["failed_codes"])
            self.assertNotIn("order_check", adapter.calls)


if __name__ == "__main__":
    unittest.main()
