from __future__ import annotations

import json
import hashlib
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
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
from trading_lab.mt5_read_only_controls import (
    KillSwitchState,
    MT5ReadOnlyControlError,
    ReadOnlyAuthorizationFile,
    authorization_path,
    probe_kill_switch,
    render_authorization,
)
from trading_lab.windows_acl import AclVerification


GATEWAY_SID = "S-1-5-21-1-2-3-1007"
MAINTENANCE_SID = "S-1-5-21-1-2-3-1008"
RUN_ID = "11111111-2222-4333-8444-555555555555"
AUTHORIZATION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
NOW = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
WORKSPACE = Path(__file__).resolve().parents[1]


class FakeMT5Module:
    ACCOUNT_TRADE_MODE_DEMO = 0

    def __init__(self, root: Path) -> None:
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []
        self.initialize_result = True
        self.last_error_result: object = (1, "unavailable")
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
        return self.last_error_result


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
            demo_authorization_path=(
                self.root / "control" / "demo-authorization" / "authorization.json"
            ),
            kill_switch_path=self.root / "control" / "STOP_TRADING",
        )
        self.config.mt5_terminal_path.write_bytes(b"test terminal placeholder")
        self.module = FakeMT5Module(self.root)
        self.authorization = render_authorization(
            config=self.config,
            config_path=self.config_path,
            workspace=WORKSPACE,
            run_id=RUN_ID,
            authorization_id=AUTHORIZATION_ID,
            issuer_sid=MAINTENANCE_SID,
            gateway_sid=GATEWAY_SID,
            issued_at=NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def authorization_reader(self, path: Path) -> ReadOnlyAuthorizationFile:
        content = json.dumps(
            self.authorization, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return ReadOnlyAuthorizationFile(
            path=path,
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
        )

    def run_preflight(
        self,
        *,
        adapter: MT5ReadOnlyAdapter | None = None,
        config=None,
        acl_verifier=None,
        authorization_reader=None,
        kill_switch_probe=None,
        audit_factory=None,
        now: datetime = NOW + timedelta(minutes=1),
    ):
        selected_config = self.config if config is None else config
        selected_adapter = adapter_for(self.module) if adapter is None else adapter
        kwargs = {
            "config_loader": lambda _path: selected_config,
            "acl_verifier": acl_verifier or (lambda *_args, **_kwargs: AclVerification(
                True,
                "strict",
                gateway_sid=GATEWAY_SID,
                current_sid=GATEWAY_SID,
                maintenance_sid=MAINTENANCE_SID,
            )),
            "adapter_loader": lambda: selected_adapter,
            "package_version_provider": lambda: "5.0.6090",
            "authorization_reader": authorization_reader or self.authorization_reader,
            "now_provider": lambda: now,
        }
        if kill_switch_probe is not None:
            kwargs["kill_switch_probe"] = kill_switch_probe
        if audit_factory is not None:
            kwargs["audit_factory"] = audit_factory
        return execute_mt5_read_only_preflight(
            self.config_path,
            RUN_ID,
            **kwargs,
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
        self.assertTrue(report["mt5_initialize_succeeded"])
        self.assertIsNone(report["mt5_last_error_code"])
        self.assertIsNone(report["mt5_last_error_message"])
        self.assertTrue(report["authorization_required"])
        self.assertTrue(report["authorization_present"])
        self.assertTrue(report["authorization_valid"])
        self.assertEqual(AUTHORIZATION_ID, report["authorization_id"])
        self.assertTrue(report["process_stopped_cleanly"])
        self.assertTrue(report["audit_chain_valid"])
        self.assertFalse(report["order_check_called"])
        self.assertFalse(report["order_send_called"])
        self.assertFalse(report["login_called"])
        self.assertFalse(report["symbol_select_called"])
        self.assertEqual(
            [
                "mt5_read_only_preflight_started",
                "mt5_read_only_authorization_accepted",
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

    def test_initialize_false_calls_last_error_but_not_shutdown(self) -> None:
        self.module.initialize_result = False
        self.module.last_error_result = (-10003, "example")
        report = self.run_preflight()
        self.assertEqual("FAIL", report["status"])
        self.assertEqual("MT5_READ_ONLY_INITIALIZE_FAILED", report["failure_code"])
        self.assertEqual("MT5_INITIALIZE", report["failure_stage"])
        self.assertEqual(["initialize", "last_error"], [
            call[0] for call in self.module.calls
        ])
        self.assertEqual(-10003, report["mt5_last_error_code"])
        self.assertEqual("example", report["mt5_last_error_message"])
        self.assertTrue(report["mt5_initialize_called"])
        self.assertFalse(report["mt5_initialize_succeeded"])
        self.assertFalse(report["mt5_shutdown_called"])
        for prohibited in (
            "login", "symbol_select", "market_book_add", "market_book_release",
            "copy_ticks_from", "order_check", "order_send",
        ):
            self.assertFalse(report[f"{prohibited}_called"], prohibited)

    def test_malformed_last_error_preserves_primary_initialize_failure(self) -> None:
        malformed_values = (
            None,
            (),
            (-10003,),
            (-10003, "example", "unexpected"),
            (True, "example"),
            ("-10003", "example"),
            (-10003, object()),
        )
        for malformed in malformed_values:
            with self.subTest(last_error=type(malformed).__name__):
                self.module.initialize_result = False
                self.module.last_error_result = malformed
                report = self.run_preflight()
                self.assertEqual("FAIL", report["status"])
                self.assertEqual(
                    "MT5_READ_ONLY_INITIALIZE_FAILED", report["failure_code"]
                )
                self.assertEqual("MT5_INITIALIZE", report["failure_stage"])
                self.assertIsNone(report["mt5_last_error_code"])
                self.assertIsNone(report["mt5_last_error_message"])
                self.assertEqual(
                    ["initialize", "last_error"],
                    [call[0] for call in self.module.calls],
                )
                self.assertFalse(report["mt5_shutdown_called"])
                self.module = FakeMT5Module(self.root)

    def test_last_error_exception_preserves_primary_initialize_failure(self) -> None:
        self.module.initialize_result = False
        self.module.last_error = Mock(side_effect=RuntimeError("secondary diagnostic"))
        report = self.run_preflight(adapter=adapter_for(self.module))
        self.assertEqual("FAIL", report["status"])
        self.assertEqual("MT5_READ_ONLY_INITIALIZE_FAILED", report["failure_code"])
        self.assertEqual("MT5_INITIALIZE", report["failure_stage"])
        self.assertEqual(
            "MetaTrader5 initialize returned false.", report["runtime_error"]
        )
        self.assertIsNone(report["mt5_last_error_code"])
        self.assertIsNone(report["mt5_last_error_message"])
        self.module.last_error.assert_called_once_with()
        self.assertFalse(report["mt5_shutdown_called"])

    def test_last_error_message_is_redacted_and_bounded(self) -> None:
        self.module.initialize_result = False
        self.module.last_error_result = (
            -10003,
            "password=hunter2 server=Broker-Demo C:\\Users\\Operator\\terminal "
            + ("x" * 700),
        )
        report = self.run_preflight()
        message = report["mt5_last_error_message"]
        self.assertIsInstance(message, str)
        self.assertLessEqual(len(message), 512)
        self.assertNotIn("hunter2", message)
        self.assertNotIn("Broker-Demo", message)
        self.assertNotIn("C:\\Users", message)
        self.assertIn("[REDACTED]", message)
        self.assertIn("[REDACTED_PATH]", message)

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
            authorization_reader=self.authorization_reader,
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
        self.assertFalse(report["mt5_initialize_succeeded"])
        self.assertFalse(report["mt5_shutdown_called"])

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
        self.assertTrue(report["mt5_initialize_called"])
        self.assertFalse(report["mt5_initialize_succeeded"])
        self.assertFalse(report["mt5_shutdown_called"])

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
                True,
                "strict",
                gateway_sid=GATEWAY_SID,
                current_sid=GATEWAY_SID,
                maintenance_sid=MAINTENANCE_SID,
            ),
            authorization_reader=self.authorization_reader,
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
        self.assertEqual(4, verification.records)
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
        self.assertTrue(report["kill_switch_readable"])

    def test_kill_switch_absence_is_explicit_and_acl_receives_authoritative_state(self) -> None:
        observed: dict[str, object] = {}

        def verifier(*_args, **kwargs):
            observed.update(kwargs)
            return AclVerification(
                True,
                "strict",
                gateway_sid=GATEWAY_SID,
                current_sid=GATEWAY_SID,
                maintenance_sid=MAINTENANCE_SID,
            )

        report = self.run_preflight(acl_verifier=verifier)
        self.assertEqual("PASS", report["status"])
        self.assertFalse(report["kill_switch_present"])
        self.assertIsNone(report["kill_switch_readable"])
        self.assertIs(observed["kill_switch_present"], False)
        self.assertEqual(
            authorization_path(self.config, RUN_ID),
            observed["read_only_authorization_path"],
        )

    def test_kill_switch_probe_distinguishes_absent_present_and_reparse(self) -> None:
        self.assertIs(KillSwitchState.ABSENT, probe_kill_switch(self.config.kill_switch_path))
        self.config.kill_switch_path.parent.mkdir(parents=True, exist_ok=True)
        self.config.kill_switch_path.write_bytes(b"")
        self.assertIs(
            KillSwitchState.PRESENT_READABLE,
            probe_kill_switch(self.config.kill_switch_path),
        )
        self.config.kill_switch_path.unlink()
        link_target = self.config.kill_switch_path.parent / "target"
        link_target.write_text("stop", encoding="ascii")
        try:
            self.config.kill_switch_path.symlink_to(link_target)
        except OSError:
            self.skipTest("symlink creation is unavailable")
        with self.assertRaises(MT5ReadOnlyControlError) as raised:
            probe_kill_switch(self.config.kill_switch_path)
        self.assertEqual("KILL_SWITCH_UNREADABLE", raised.exception.code)

    def test_kill_switch_access_or_io_error_never_becomes_absent(self) -> None:
        loader = Mock()
        for error in (PermissionError("denied"), OSError("device error")):
            with self.subTest(error=type(error).__name__):
                probe = Mock(side_effect=MT5ReadOnlyControlError(
                    "KILL_SWITCH_UNREADABLE", "KILL_SWITCH", str(error)
                ))
                report = execute_mt5_read_only_preflight(
                    self.config_path,
                    RUN_ID,
                    config_loader=lambda _path: self.config,
                    kill_switch_probe=probe,
                    adapter_loader=loader,
                )
                self.assertEqual("KILL_SWITCH_UNREADABLE", report["failure_code"])
                self.assertFalse(report["mt5_initialize_called"])
        loader.assert_not_called()

    def test_unknown_kill_switch_state_and_acl_failure_block_initialize(self) -> None:
        loader = Mock()
        report = execute_mt5_read_only_preflight(
            self.config_path,
            RUN_ID,
            config_loader=lambda _path: self.config,
            kill_switch_probe=lambda _path: "UNKNOWN",
            adapter_loader=loader,
        )
        self.assertEqual("KILL_SWITCH_UNREADABLE", report["failure_code"])
        loader.assert_not_called()
        report = self.run_preflight(
            acl_verifier=lambda *_args, **_kwargs: AclVerification(False, "unsafe")
        )
        self.assertEqual("MT5_READ_ONLY_ACL_FAILED", report["failure_code"])
        self.assertFalse(report["mt5_initialize_called"])

    def test_authorization_missing_even_with_environment_gate_blocks_initialize(self) -> None:
        loader = Mock()

        def missing(_path):
            raise MT5ReadOnlyControlError(
                "MT5_READ_ONLY_AUTHORIZATION_MISSING",
                "AUTHORIZATION_FILE",
                "missing",
            )

        with patch.dict("os.environ", {"MT5_READ_ONLY_PREFLIGHT": "true"}):
            report = execute_mt5_read_only_preflight(
                self.config_path,
                RUN_ID,
                config_loader=lambda _path: self.config,
                authorization_reader=missing,
                adapter_loader=loader,
            )
        self.assertEqual("MT5_READ_ONLY_AUTHORIZATION_MISSING", report["failure_code"])
        self.assertFalse(report["authorization_present"])
        self.assertFalse(report["mt5_initialize_called"])
        loader.assert_not_called()

    def test_authorization_exact_binding_mismatches_fail_before_initialize(self) -> None:
        cases = (
            ("purpose", "OTHER"),
            ("run_id", "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"),
            ("issuer_sid", "S-1-5-21-9-9-9-1000"),
            ("gateway_sid", "S-1-5-21-9-9-9-1001"),
            ("authorized_account", 98765432),
            ("authorized_server", "Other-Demo"),
            ("authorized_symbol", "XAUUSDm"),
            ("terminal_path", str(self.root / "other" / "terminal64.exe")),
            ("git_commit", "0" * 40),
            ("config_sha256", "0" * 64),
            ("runner_sha256", "0" * 64),
            ("harness_sha256", "0" * 64),
        )
        original = dict(self.authorization)
        for field, value in cases:
            with self.subTest(field=field):
                self.authorization = {**original, field: value}
                report = self.run_preflight()
                self.assertEqual("FAIL", report["status"])
                self.assertEqual(
                    "MT5_READ_ONLY_AUTHORIZATION_INVALID", report["failure_code"]
                )
                self.assertFalse(report["authorization_valid"])
                self.assertFalse(report["mt5_initialize_called"])
                self.assertEqual([], self.module.calls)
        self.authorization = original

    def test_authorization_expired_or_future_fails_before_initialize(self) -> None:
        expired = self.run_preflight(now=NOW + timedelta(minutes=16))
        self.assertEqual("MT5_READ_ONLY_AUTHORIZATION_INVALID", expired["failure_code"])
        self.assertFalse(expired["authorization_not_expired"])
        future = self.run_preflight(now=NOW - timedelta(seconds=1))
        self.assertEqual("MT5_READ_ONLY_AUTHORIZATION_INVALID", future["failure_code"])
        self.assertFalse(future["authorization_not_expired"])
        self.assertEqual([], self.module.calls)

    def test_authorization_reader_cannot_redirect_outside_protected_path(self) -> None:
        expected_reader = self.authorization_reader

        def redirected(path: Path):
            artifact = expected_reader(path)
            return replace(artifact, path=self.root / "outside.json")

        report = self.run_preflight(authorization_reader=redirected)
        self.assertEqual("MT5_READ_ONLY_AUTHORIZATION_PATH_INVALID", report["failure_code"])
        self.assertFalse(report["mt5_initialize_called"])

    def test_initialize_raise_and_false_never_shutdown(self) -> None:
        self.module.initialize = Mock(side_effect=RuntimeError("initialize failed"))
        report = self.run_preflight(adapter=adapter_for(self.module))
        self.assertTrue(report["mt5_initialize_called"])
        self.assertFalse(report["mt5_initialize_succeeded"])
        self.assertFalse(report["mt5_shutdown_called"])
        self.module = FakeMT5Module(self.root)
        self.module.initialize_result = False
        report = self.run_preflight()
        self.assertTrue(report["mt5_initialize_called"])
        self.assertFalse(report["mt5_initialize_succeeded"])
        self.assertFalse(report["mt5_shutdown_called"])

    def test_every_post_initialize_identity_and_market_failure_shutdowns(self) -> None:
        cases = (
            ("account", "login", 99, "MT5_READ_ONLY_ACCOUNT_MISMATCH"),
            ("account", "server", "Other", "MT5_READ_ONLY_SERVER_MISMATCH"),
            ("account", "trade_mode", 2, "MT5_READ_ONLY_NOT_DEMO"),
            ("symbol", "name", "OTHER", "MT5_READ_ONLY_SYMBOL_MISMATCH"),
            ("tick", "bid", -1.0, "MT5_READ_ONLY_TICK_INVALID"),
        )
        for object_name, field, value, code in cases:
            with self.subTest(code=code):
                setattr(getattr(self.module, object_name), field, value)
                report = self.run_preflight()
                self.assertEqual(code, report["failure_code"])
                self.assertTrue(report["mt5_initialize_succeeded"])
                self.assertTrue(report["mt5_shutdown_called"])
                self.assertEqual("shutdown", self.module.calls[-1][0])
                self.module = FakeMT5Module(self.root)

    def test_post_initialize_audit_failure_still_shutdowns(self) -> None:
        class FailsIdentityAudit:
            def __init__(self):
                self.events = 0

            def verify(self):
                return SimpleNamespace(valid=True)

            def append(self, event, _payload):
                self.events += 1
                if event == "mt5_identity_verified":
                    raise RuntimeError("identity audit unavailable")

        report = self.run_preflight(audit_factory=lambda _config: FailsIdentityAudit())
        self.assertEqual("FAIL", report["status"])
        self.assertTrue(report["mt5_initialize_succeeded"])
        self.assertTrue(report["mt5_shutdown_called"])
        self.assertEqual("shutdown", self.module.calls[-1][0])

    def test_shutdown_failure_is_fail_closed_and_preserves_primary_error(self) -> None:
        self.module.shutdown = Mock(side_effect=RuntimeError("shutdown unavailable"))
        report = self.run_preflight(adapter=adapter_for(self.module))
        self.assertEqual("MT5_READ_ONLY_SHUTDOWN_FAILED", report["failure_code"])
        self.assertFalse(report["process_stopped_cleanly"])

        self.module = FakeMT5Module(self.root)
        self.module.account.login = 999
        self.module.shutdown = Mock(side_effect=RuntimeError("shutdown unavailable"))
        report = self.run_preflight(adapter=adapter_for(self.module))
        self.assertEqual("MT5_READ_ONLY_ACCOUNT_MISMATCH", report["failure_code"])
        self.assertTrue(report["mt5_shutdown_called"])
        self.assertFalse(report["process_stopped_cleanly"])

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
