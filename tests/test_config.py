from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from trading_lab.config import (
    ConfigError,
    GatewayBootstrapConfig,
    load_gateway_bootstrap_config,
    load_mt5_security_config,
    load_security_config,
    resolve_mt5_access_enabled,
)
from trading_lab.domain import TradingMode


class SecurityConfigTests(unittest.TestCase):
    def valid_config(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "trading_mode": "OBSERVE_ONLY",
            "authorized_account": 12345678,
            "authorized_server": "Broker-Demo",
            "allowed_symbol": "XAUUSD",
            "magic_number": 26081101,
            "mt5_terminal_path": "C:\\Program Files\\MetaTrader 5\\terminal64.exe",
            "audit_path": "C:\\ProgramData\\AutomatonMT5Lab\\audit\\journal\\audit.jsonl",
            "audit_db_path": "C:\\ProgramData\\AutomatonMT5Lab\\audit\\sqlite\\audit.db",
            "research_db_path": "C:\\ProgramData\\AutomatonMT5Lab\\research\\research.db",
            "api_key_path": "C:\\ProgramData\\AutomatonMT5Lab\\ipc\\automaton.key",
            "gateway_lock_path": "C:\\ProgramData\\AutomatonMT5Lab\\operational\\gateway.lock",
            "log_dir": "C:\\ProgramData\\AutomatonMT5Lab\\logs\\gateway",
            "security_log_dir": "C:\\ProgramData\\AutomatonMT5Lab\\logs\\security",
            "demo_authorization_path": "C:\\ProgramData\\AutomatonMT5Lab\\control\\demo-authorization\\authorization.json",
            "kill_switch_path": "C:\\ProgramData\\AutomatonMT5Lab\\control\\STOP_TRADING",
            "automaton_state_dir": "C:\\Users\\AutomatonLabAgent\\.automaton",
            "gateway_windows_identity": "LAB\\Gateway",
            "automaton_windows_identity": "LAB\\Agent",
            "risk": {
                "max_risk_per_trade_fraction": 0.0025,
                "max_volume": 0.10,
                "max_spread_points": 30.0,
                "max_open_positions": 1,
                "max_symbol_exposure_lots": 0.10,
                "max_daily_loss_fraction": 0.01,
                "min_stop_distance_points": 20,
                "duplicate_window_seconds": 300,
            },
        }

    def write(self, directory: str, payload: dict[str, object]) -> Path:
        path = Path(directory) / "security.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_defaults_to_observe_only_when_mode_is_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = self.valid_config()
            payload.pop("trading_mode")
            config = load_security_config(self.write(directory, payload))
            self.assertEqual(TradingMode.OBSERVE_ONLY, config.trading_mode)

    def test_mt5_access_defaults_disabled_and_environment_cannot_escalate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = load_security_config(self.write(directory, self.valid_config()))
        self.assertFalse(config.mt5_access_enabled)
        self.assertFalse(resolve_mt5_access_enabled(config, {}))
        self.assertFalse(resolve_mt5_access_enabled(config, {"MT5_ACCESS_ENABLED": "false"}))
        with self.assertRaises(ConfigError):
            resolve_mt5_access_enabled(config, {"MT5_ACCESS_ENABLED": "true"})

    def test_mt5_access_requires_explicit_boolean_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = self.valid_config()
            payload["mt5_access_enabled"] = True
            config = load_security_config(self.write(directory, payload))
        self.assertTrue(config.mt5_access_enabled)
        self.assertTrue(resolve_mt5_access_enabled(config, {}))
        self.assertTrue(resolve_mt5_access_enabled(config, {"MT5_ACCESS_ENABLED": "true"}))
        self.assertFalse(resolve_mt5_access_enabled(config, {"MT5_ACCESS_ENABLED": "false"}))
        with tempfile.TemporaryDirectory() as directory:
            payload = self.valid_config()
            payload["mt5_access_enabled"] = "false"
            with self.assertRaises(ConfigError):
                load_security_config(self.write(directory, payload))

    def test_disabled_bootstrap_does_not_require_or_validate_mt5_account(self) -> None:
        cases = (None, 0, -1, "malformed", {"not": "an account"})
        for account in cases:
            with self.subTest(account=account), tempfile.TemporaryDirectory() as directory:
                payload = self.valid_config()
                payload["mt5_access_enabled"] = False
                if account is None:
                    payload.pop("authorized_account")
                else:
                    payload["authorized_account"] = account
                payload["authorized_server"] = 0
                payload["mt5_terminal_path"] = None
                payload["risk"] = "not-an-mt5-risk-object"
                config = load_gateway_bootstrap_config(self.write(directory, payload))
                self.assertIsInstance(config, GatewayBootstrapConfig)
                self.assertFalse(config.mt5_access_enabled)
                self.assertFalse(hasattr(config, "authorized_account"))
                self.assertFalse(hasattr(config, "authorized_server"))
                self.assertFalse(hasattr(config, "mt5_terminal_path"))
                self.assertFalse(hasattr(config, "risk"))

    def test_disabled_bootstrap_keeps_mt5_access_separate_and_non_escalating(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = self.valid_config()
            payload["mt5_access_enabled"] = False
            payload.pop("authorized_account")
            config = load_gateway_bootstrap_config(self.write(directory, payload))
        self.assertEqual(TradingMode.OBSERVE_ONLY, config.trading_mode)
        self.assertFalse(resolve_mt5_access_enabled(config, {}))
        self.assertFalse(resolve_mt5_access_enabled(config, {"MT5_ACCESS_ENABLED": "false"}))
        with self.assertRaises(ConfigError):
            resolve_mt5_access_enabled(config, {"MT5_ACCESS_ENABLED": "true"})

    def test_complete_mt5_loader_keeps_account_and_server_fail_closed(self) -> None:
        account_cases = (None, 0, -1, "invalid")
        for account in account_cases:
            with self.subTest(account=account), tempfile.TemporaryDirectory() as directory:
                payload = self.valid_config()
                payload["mt5_access_enabled"] = True
                if account is None:
                    payload.pop("authorized_account")
                else:
                    payload["authorized_account"] = account
                with self.assertRaisesRegex(ConfigError, "authorized_account"):
                    load_mt5_security_config(self.write(directory, payload))
        for server in (None, 0, "", "REPLACE_WITH_EXACT_DEMO_SERVER"):
            with self.subTest(server=server), tempfile.TemporaryDirectory() as directory:
                payload = self.valid_config()
                payload["mt5_access_enabled"] = True
                if server is None:
                    payload.pop("authorized_server")
                else:
                    payload["authorized_server"] = server
                with self.assertRaisesRegex(ConfigError, "authorized_server"):
                    load_mt5_security_config(self.write(directory, payload))

    def test_rejects_credentials_in_security_config(self) -> None:
        for key in ("password", "api_key", "token"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                payload = self.valid_config()
                payload[key] = "secret"
                with self.assertRaises(ConfigError):
                    load_security_config(self.write(directory, payload))

    def test_rejects_more_than_xauusd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = self.valid_config()
            payload["allowed_symbol"] = "EURUSD"
            with self.assertRaises(ConfigError):
                load_security_config(self.write(directory, payload))

    def test_rejects_unknown_fields_and_non_single_position_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = self.valid_config()
            payload["execution_override"] = True
            with self.assertRaises(ConfigError):
                load_security_config(self.write(directory, payload))
        with tempfile.TemporaryDirectory() as directory:
            payload = self.valid_config()
            payload["risk"]["max_open_positions"] = 2  # type: ignore[index]
            with self.assertRaises(ConfigError):
                load_security_config(self.write(directory, payload))

    def test_rejects_shared_identity_or_merged_control_and_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = self.valid_config()
            payload["automaton_windows_identity"] = payload["gateway_windows_identity"]
            with self.assertRaises(ConfigError):
                load_security_config(self.write(directory, payload))
        with tempfile.TemporaryDirectory() as directory:
            payload = self.valid_config()
            payload["audit_path"] = "C:\\ProgramData\\AutomatonMT5Lab\\data\\audit.jsonl"
            with self.assertRaises(ConfigError):
                load_security_config(self.write(directory, payload))

    def test_requires_separate_sqlite_research_operational_and_log_domains(self) -> None:
        for field, invalid in (
            ("audit_db_path", "C:\\ProgramData\\AutomatonMT5Lab\\data\\audit.db"),
            ("research_db_path", "C:\\ProgramData\\AutomatonMT5Lab\\data\\research.db"),
            ("gateway_lock_path", "C:\\ProgramData\\AutomatonMT5Lab\\data\\gateway.lock"),
            ("log_dir", "C:\\ProgramData\\AutomatonMT5Lab\\data\\logs"),
            ("security_log_dir", "C:\\ProgramData\\AutomatonMT5Lab\\logs\\gateway"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                payload = self.valid_config()
                payload[field] = invalid
                with self.assertRaises(ConfigError):
                    load_security_config(self.write(directory, payload))
    def test_rejects_protected_paths_inside_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = self.valid_config()
            payload["audit_path"] = str(Path(__file__).resolve().parents[1] / "audit.jsonl")
            with self.assertRaises(ConfigError):
                load_security_config(self.write(directory, payload))

    def test_rejects_placeholders_and_merged_ipc_domain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = self.valid_config()
            payload["authorized_server"] = "REPLACE_WITH_EXACT_DEMO_SERVER"
            with self.assertRaises(ConfigError):
                load_security_config(self.write(directory, payload))
        with tempfile.TemporaryDirectory() as directory:
            payload = self.valid_config()
            payload["api_key_path"] = "C:\\ProgramData\\AutomatonMT5Lab\\control\\automaton.key"
            with self.assertRaises(ConfigError):
                load_security_config(self.write(directory, payload))


if __name__ == "__main__":
    unittest.main()
