from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from trading_lab.config import RiskLimits, SecurityConfig
from trading_lab.domain import TradingMode
from trading_lab.readiness import _fresh_timestamp, _past_timestamp, run_readiness
from trading_lab.service import serve
from trading_lab.windows_acl import AclVerification


def security_config(directory: Path) -> SecurityConfig:
    return SecurityConfig(
        schema_version=1,
        trading_mode=TradingMode.OBSERVE_ONLY,
        authorized_account=12345678,
        authorized_server="Broker-Demo",
        allowed_symbol="XAUUSD",
        magic_number=26081101,
        mt5_terminal_path=directory / "terminal64.exe",
        audit_path=directory / "data" / "audit.jsonl",
        research_db_path=directory / "data" / "research.db",
        demo_authorization_path=directory / "control" / "demo.authorization",
        kill_switch_path=directory / "control" / "KILL_SWITCH",
        automaton_state_dir=directory / "agent",
        gateway_windows_identity="LAB\\Gateway",
        automaton_windows_identity="LAB\\Agent",
        risk=RiskLimits(0.0025, 0.01, 30.0, 1, 0.01, 0.01, 20, 300),
    )


class ReadinessAclGateTests(unittest.TestCase):
    def test_runtime_evidence_timestamp_must_be_recent_and_timezone_aware(self) -> None:
        self.assertTrue(_fresh_timestamp(datetime.now(UTC).isoformat()))
        self.assertFalse(_fresh_timestamp(datetime.now().replace(tzinfo=None).isoformat()))
        self.assertFalse(_fresh_timestamp((datetime.now(UTC) - timedelta(hours=1)).isoformat()))
        self.assertFalse(_fresh_timestamp((datetime.now(UTC) + timedelta(minutes=2)).isoformat()))
        self.assertTrue(_past_timestamp((datetime.now(UTC) - timedelta(days=2)).isoformat()))

    def test_readiness_does_not_touch_mt5_when_acl_is_unsafe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = security_config(Path(directory))
            with (
                patch("trading_lab.readiness.load_security_config", return_value=config),
                patch(
                    "trading_lab.readiness.verify_windows_acl",
                    return_value=AclVerification(False, "unsafe ACL"),
                ),
                patch("trading_lab.readiness._gateway_get") as gateway_get,
            ):
                report = run_readiness(Path(directory) / "security.json", run_tests=False)
            gateway_get.assert_not_called()
            checks = {item["name"]: item for item in report["checks"]}
            self.assertFalse(checks["least_privilege_windows_acl"]["passed"])
            self.assertFalse(report["AUTOMATON_MT5_LAB_READY"])
            self.assertEqual(report["TRADING_MODE"], "UNVERIFIED")
            for field in (
                "MT5_CONNECTED", "DEMO_VERIFIED", "ACCOUNT_ALLOWED",
                "SERVER_ALLOWED", "XAUUSD_AVAILABLE", "GATEWAY_HEALTH",
                "AUTOMATON_TOOLS_READY", "AUDIT_READY", "RISK_TESTS",
                "SECURITY_TESTS",
            ):
                self.assertIs(report[field], False)

    def test_gateway_service_refuses_unsafe_acl_before_mt5_initialize(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = security_config(Path(directory))
            with (
                patch("trading_lab.service.load_security_config", return_value=config),
                patch(
                    "trading_lab.service.verify_windows_acl",
                    return_value=AclVerification(False, "unsafe ACL"),
                ),
                patch("trading_lab.service.MT5Adapter") as adapter,
            ):
                with self.assertRaises(PermissionError):
                    serve(Path(directory) / "security.json")
            adapter.assert_not_called()


if __name__ == "__main__":
    unittest.main()
