from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from trading_lab.config import load_security_config, security_config_hash
from trading_lab.domain import TradingMode
from trading_lab.operator import enable_demo
from trading_lab.windows_acl import AclVerification
from tests import test_config as config_test_helpers


class HumanOperatorTests(unittest.TestCase):
    @staticmethod
    def ready_report() -> dict[str, object]:
        report = {
            field: True
            for field in (
                "AUTOMATON_MT5_LAB_READY", "MT5_CONNECTED", "DEMO_VERIFIED",
                "ACCOUNT_ALLOWED", "SERVER_ALLOWED", "XAUUSD_AVAILABLE",
                "GATEWAY_HEALTH", "AUTOMATON_TOOLS_READY", "AUDIT_READY",
                "RISK_TESTS", "SECURITY_TESTS",
            )
        }
        report["TRADING_MODE"] = "OBSERVE_ONLY"
        return report

    def test_enable_demo_is_dry_run_by_default_and_requires_ready_observe_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "security.json"
            original = config_test_helpers.SecurityConfigTests().valid_config()
            source_path.write_text(json.dumps(original), encoding="utf-8")
            config = load_security_config(source_path)
            config_path = root / "security.yaml"
            config_path.write_text(json.dumps(original), encoding="utf-8")
            readiness_path = root / "readiness.json"
            def write_readiness(report: dict[str, object]) -> None:
                raw = json.dumps(report).encode("utf-8")
                readiness_path.write_bytes(raw)
                digest = hashlib.sha256(raw).hexdigest()
                readiness_path.with_name("readiness.json.sha256").write_text(
                    f"{digest}  readiness.json\n", encoding="ascii"
                )
            ready = self.ready_report()
            ready["SECURITY_CONFIG_SHA256"] = security_config_hash(config)
            write_readiness(ready)
            with (
                patch("trading_lab.operator.load_security_config", return_value=config),
                patch(
                    "trading_lab.operator.verify_windows_acl",
                    return_value=AclVerification(True, "ok"),
                ),
            ):
                plan = enable_demo(
                    config_path, readiness_path, apply=False, clear_kill_switch=False,
                )
            self.assertFalse(plan["apply"])
            self.assertEqual(original, json.loads(config_path.read_text(encoding="utf-8")))
            unsafe = self.ready_report()
            unsafe["SECURITY_CONFIG_SHA256"] = security_config_hash(config)
            unsafe["AUTOMATON_MT5_LAB_READY"] = False
            write_readiness(unsafe)
            with (
                patch("trading_lab.operator.load_security_config", return_value=config),
                patch(
                    "trading_lab.operator.verify_windows_acl",
                    return_value=AclVerification(True, "ok"),
                ),
                self.assertRaises(PermissionError),
            ):
                enable_demo(config_path, readiness_path, apply=False, clear_kill_switch=False)

    def test_config_hash_changes_with_protected_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = config_test_helpers.SecurityConfigTests().write(
                directory, config_test_helpers.SecurityConfigTests().valid_config()
            )
            observe = load_security_config(path)
            demo = replace(observe, trading_mode=TradingMode.DEMO_EXECUTION)
            self.assertNotEqual(security_config_hash(observe), security_config_hash(demo))


if __name__ == "__main__":
    unittest.main()
