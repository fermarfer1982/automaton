from __future__ import annotations

import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tests.test_readiness import security_config
from trading_lab.audit import HashChainAuditLog
from trading_lab.domain import TradingMode
from trading_lab.mt5_read_only import (
    ALLOWED_MT5_CAPABILITIES,
    EXACT_SYMBOL,
    MODE,
    MT5ReadOnlyAdapter,
    MT5ReadOnlyBindings,
    execute_mt5_read_only_preflight,
    load_mt5_read_only_adapter,
)
from trading_lab.windows_acl import AclVerification


GATEWAY_SID = "S-1-5-21-1-2-3-1007"


class FakeMT5Module:
    ACCOUNT_TRADE_MODE_DEMO = 0

    def __init__(self, root: Path) -> None:
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []
        self.initialize_result = True
        self.terminal = SimpleNamespace(
            connected=True,
            trade_allowed=True,
            path=str(root),
        )
        self.account = SimpleNamespace(
            login=12345678,
            server="Broker-Demo",
            name="Authorized Demo",
            trade_mode=self.ACCOUNT_TRADE_MODE_DEMO,
        )
        self.symbol = SimpleNamespace(
            name=EXACT_SYMBOL,
            digits=2,
            trade_tick_size=0.01,
            trade_mode=4,
        )
        self.tick = SimpleNamespace(time=1_800_000_000, bid=2500.10, ask=2500.20)

    def _record(self, name: str, *args, **kwargs) -> None:
        self.calls.append((name, args, kwargs))

    def initialize(self, *args, **kwargs):
        self._record("initialize", *args, **kwargs)
        return self.initialize_result

    def version(self):
        self._record("version")
        return 500, 6090, "17 Aug 2026"

    def terminal_info(self):
        self._record("terminal_info")
        return self.terminal

    def account_info(self):
        self._record("account_info")
        return self.account

    def symbol_info(self, symbol: str):
        self._record("symbol_info", symbol)
        return self.symbol

    def symbol_info_tick(self, symbol: str):
        self._record("symbol_info_tick", symbol)
        return self.tick

    def shutdown(self):
        self._record("shutdown")

    def last_error(self):
        self._record("last_error")
        return 1, "unavailable"


def adapter_for(module: FakeMT5Module) -> MT5ReadOnlyAdapter:
    return MT5ReadOnlyAdapter(MT5ReadOnlyBindings(
        initialize=module.initialize,
        version=module.version,
        terminal_info=module.terminal_info,
        account_info=module.account_info,
        symbol_info=module.symbol_info,
        symbol_info_tick=module.symbol_info_tick,
        shutdown=module.shutdown,
        last_error=module.last_error,
        account_trade_mode_demo=module.ACCOUNT_TRADE_MODE_DEMO,
    ))


class MT5ReadOnlyPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "outside-workspace" / "trading.yaml"
        self.config_path.parent.mkdir(parents=True)
        self.config_path.write_text("test-only", encoding="utf-8")
        self.config = replace(
            security_config(self.root),
            authorized_account_name="Authorized Demo",
            mt5_access_enabled=False,
        )
        self.config.mt5_terminal_path.write_bytes(b"test terminal placeholder")
        self.module = FakeMT5Module(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_preflight(self, *, adapter: MT5ReadOnlyAdapter | None = None, config=None):
        selected_config = self.config if config is None else config
        selected_adapter = adapter_for(self.module) if adapter is None else adapter
        return execute_mt5_read_only_preflight(
            self.config_path,
            "11111111-2222-4333-8444-555555555555",
            config_loader=lambda _path: selected_config,
            acl_verifier=lambda *_args, **_kwargs: AclVerification(
                True,
                "strict",
                gateway_sid=GATEWAY_SID,
                current_sid=GATEWAY_SID,
            ),
            adapter_loader=lambda: selected_adapter,
            package_version_provider=lambda: "5.0.6090",
        )

    def test_exact_account_server_demo_terminal_and_xauusd_pass(self) -> None:
        report = self.run_preflight()
        self.assertEqual("PASS", report["status"])
        self.assertEqual(MODE, report["mode"])
        self.assertEqual("OBSERVE_ONLY", report["trading_mode"])
        self.assertEqual(GATEWAY_SID, report["effective_sid"])
        self.assertTrue(report["terminal_connected"])
        self.assertTrue(report["terminal_path_match"])
        self.assertTrue(report["account_login_match"])
        self.assertTrue(report["account_server_match"])
        self.assertTrue(report["account_demo_verified"])
        self.assertTrue(report["account_name_match"])
        self.assertEqual(EXACT_SYMBOL, report["symbol"])
        self.assertTrue(report["symbol_exists"])
        self.assertTrue(report["tick_read"])
        self.assertEqual(0.01, report["symbol_trade_tick_size"])
        self.assertAlmostEqual(0.10, report["spread"])
        self.assertTrue(report["mt5_shutdown_called"])
        self.assertTrue(report["process_stopped_cleanly"])
        self.assertTrue(report["audit_chain_valid"])
        self.assertFalse(report["order_check_called"])
        self.assertFalse(report["order_send_called"])
        self.assertFalse(report["login_called"])
        self.assertFalse(report["symbol_select_called"])
        self.assertEqual(
            [
                "mt5_read_only_preflight_started",
                "mt5_identity_verified",
                "mt5_read_only_preflight_stopped",
            ],
            report["audit_events_recorded"],
        )
        self.assertEqual(
            ["initialize", "version", "terminal_info", "account_info",
             "symbol_info", "symbol_info_tick", "shutdown"],
            [call[0] for call in self.module.calls],
        )
        initialize_call = self.module.calls[0]
        self.assertEqual((), initialize_call[1])
        self.assertEqual(
            {"path": str(self.config.mt5_terminal_path)}, initialize_call[2]
        )

    def test_identity_and_demo_mismatches_fail_closed(self) -> None:
        cases = (
            ("login", 999, "MT5_READ_ONLY_ACCOUNT_MISMATCH"),
            ("server", "Other-Demo", "MT5_READ_ONLY_SERVER_MISMATCH"),
            ("trade_mode", 2, "MT5_READ_ONLY_NOT_DEMO"),
            ("name", "Other Account", "MT5_READ_ONLY_ACCOUNT_NAME_MISMATCH"),
        )
        for field, value, expected_code in cases:
            with self.subTest(field=field):
                setattr(self.module.account, field, value)
                report = self.run_preflight()
                self.assertEqual("FAIL", report["status"])
                self.assertEqual(expected_code, report["failure_code"])
                self.assertEqual("shutdown", self.module.calls[-1][0])
                self.assertFalse(report["order_check_called"])
                self.assertFalse(report["order_send_called"])
                self.module = FakeMT5Module(self.root)

    def test_initialize_false_still_calls_last_error_and_shutdown(self) -> None:
        self.module.initialize_result = False
        report = self.run_preflight()
        self.assertEqual("FAIL", report["status"])
        self.assertEqual("MT5_READ_ONLY_INITIALIZE_FAILED", report["failure_code"])
        self.assertEqual(["initialize", "last_error", "shutdown"], [
            call[0] for call in self.module.calls
        ])
        self.assertTrue(report["mt5_shutdown_called"])

    def test_missing_read_payloads_fail_and_shutdown(self) -> None:
        cases = (
            ("terminal", None, "MT5_READ_ONLY_TERMINAL_INFO_MISSING"),
            ("account", None, "MT5_READ_ONLY_ACCOUNT_INFO_MISSING"),
            ("symbol", None, "MT5_READ_ONLY_SYMBOL_MISSING"),
            ("tick", None, "MT5_READ_ONLY_TICK_MISSING"),
        )
        for field, value, expected_code in cases:
            with self.subTest(field=field):
                setattr(self.module, field, value)
                report = self.run_preflight()
                self.assertEqual("FAIL", report["status"])
                self.assertEqual(expected_code, report["failure_code"])
                self.assertEqual("shutdown", self.module.calls[-1][0])
                self.module = FakeMT5Module(self.root)

    def test_terminal_path_and_exact_symbol_mismatch_fail(self) -> None:
        self.module.terminal.path = str(self.root / "other-terminal")
        report = self.run_preflight()
        self.assertEqual("MT5_READ_ONLY_TERMINAL_PATH_MISMATCH", report["failure_code"])
        self.module = FakeMT5Module(self.root)
        self.module.symbol.name = "XAUUSDm"
        report = self.run_preflight()
        self.assertEqual("MT5_READ_ONLY_SYMBOL_MISMATCH", report["failure_code"])
        self.assertEqual(EXACT_SYMBOL, self.module.calls[-2][1][0])

    def test_acl_failure_prevents_adapter_load(self) -> None:
        loader = Mock()
        report = execute_mt5_read_only_preflight(
            self.config_path,
            "11111111-2222-4333-8444-555555555555",
            config_loader=lambda _path: self.config,
            acl_verifier=lambda *_args, **_kwargs: AclVerification(False, "unsafe"),
            adapter_loader=loader,
            package_version_provider=lambda: "5.0.6090",
        )
        self.assertEqual("FAIL", report["status"])
        self.assertEqual("MT5_READ_ONLY_ACL_FAILED", report["failure_code"])
        loader.assert_not_called()

    def test_observe_only_is_mandatory(self) -> None:
        for mode in (TradingMode.PAPER, TradingMode.DEMO_EXECUTION):
            with self.subTest(mode=mode):
                report = self.run_preflight(config=replace(self.config, trading_mode=mode))
                self.assertEqual("MT5_READ_ONLY_OBSERVE_ONLY_REQUIRED", report["failure_code"])
                self.assertFalse(report["mt5_imported"])

    def test_adapter_surface_contains_only_reviewed_read_capabilities(self) -> None:
        adapter = adapter_for(self.module)
        self.assertEqual(
            {
                "initialize", "version", "terminal_info", "account_info",
                "symbol_info", "symbol_info_tick", "shutdown", "last_error",
            },
            set(ALLOWED_MT5_CAPABILITIES),
        )
        for prohibited in (
            "login", "symbol_select", "market_book_add", "market_book_release",
            "copy_ticks_from", "order_check", "order_send",
        ):
            self.assertFalse(hasattr(adapter, prohibited), prohibited)
        self.assertFalse(hasattr(adapter, "_mt5"))
        self.assertFalse(hasattr(adapter, "__dict__"))

    def test_unexpected_capability_is_recorded_and_fails(self) -> None:
        class ViolatingAdapter(MT5ReadOnlyAdapter):
            def initialize(self, terminal_path: Path) -> bool:
                self._ledger.invoke("login", lambda: True)
                return super().initialize(terminal_path)

        adapter = ViolatingAdapter(adapter_for(self.module)._bindings)
        report = self.run_preflight(adapter=adapter)
        self.assertEqual("FAIL", report["status"])
        self.assertEqual("MT5_READ_ONLY_UNEXPECTED_CAPABILITY", report["failure_code"])
        self.assertTrue(report["unexpected_capability_called"])
        self.assertTrue(report["login_called"])
        self.assertTrue(report["mt5_shutdown_called"])

    def test_runtime_error_redacts_credentials(self) -> None:
        secret_error = RuntimeError(
            "password=hunter2 api_key=abc login 12345678 on Broker-Demo for Authorized Demo"
        )
        self.module.initialize = Mock(side_effect=secret_error)
        report = self.run_preflight(adapter=adapter_for(self.module))
        serialized = json.dumps(report)
        for secret in ("hunter2", "abc", "12345678", "Broker-Demo"):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("Authorized Demo", serialized)
        self.assertIn("[REDACTED]", report["runtime_error"])

    def test_audit_failure_prevents_mt5_import(self) -> None:
        class BrokenAudit:
            def verify(self):
                return SimpleNamespace(valid=False)

            def append(self, _event, _payload):
                raise AssertionError("append must not be attempted after failed verification")

        loader = Mock()
        report = execute_mt5_read_only_preflight(
            self.config_path,
            "11111111-2222-4333-8444-555555555555",
            config_loader=lambda _path: self.config,
            acl_verifier=lambda *_args, **_kwargs: AclVerification(
                True, "strict", gateway_sid=GATEWAY_SID, current_sid=GATEWAY_SID
            ),
            adapter_loader=loader,
            package_version_provider=lambda: "5.0.6090",
            audit_factory=lambda _config: BrokenAudit(),
        )
        self.assertEqual("FAIL", report["status"])
        self.assertEqual("MT5_READ_ONLY_AUDIT_FAILED", report["failure_code"])
        loader.assert_not_called()

    def test_audit_chain_is_intact_and_contains_only_sanitized_identity_evidence(self) -> None:
        report = self.run_preflight()
        verification = HashChainAuditLog(self.config.audit_path).verify()
        self.assertTrue(verification.valid)
        self.assertEqual(3, verification.records)
        text = self.config.audit_path.read_text(encoding="utf-8")
        self.assertNotIn(str(self.config.authorized_account), text)
        self.assertNotIn(self.config.authorized_server, text)
        self.assertNotIn("password", text.casefold())
        self.assertTrue(report["audit_chain_valid"])

    def test_kill_switch_is_observed_without_blocking_diagnostic_reads(self) -> None:
        self.config.kill_switch_path.parent.mkdir(parents=True, exist_ok=True)
        self.config.kill_switch_path.write_text("STOP\n", encoding="ascii")
        report = self.run_preflight()
        self.assertEqual("PASS", report["status"])
        self.assertTrue(report["kill_switch_present"])

    def test_lazy_loader_copies_explicit_bindings_without_real_mt5_import(self) -> None:
        with patch(
            "trading_lab.mt5_read_only.importlib.import_module",
            return_value=self.module,
        ) as importer:
            adapter = load_mt5_read_only_adapter()
        importer.assert_called_once_with("MetaTrader5")
        self.assertIsInstance(adapter, MT5ReadOnlyAdapter)
        self.assertFalse(hasattr(adapter, "_mt5"))

    def test_preimported_mt5_fails_before_config_or_adapter_access(self) -> None:
        sentinel = object()
        loader = Mock()
        config_loader = Mock()
        with patch.dict(sys.modules, {"MetaTrader5": sentinel}):
            report = execute_mt5_read_only_preflight(
                self.config_path,
                "11111111-2222-4333-8444-555555555555",
                config_loader=config_loader,
                adapter_loader=loader,
            )
        self.assertEqual("FAIL", report["status"])
        self.assertEqual("MT5_READ_ONLY_PREIMPORTED", report["failure_code"])
        self.assertTrue(report["mt5_imported"])
        config_loader.assert_not_called()
        loader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
