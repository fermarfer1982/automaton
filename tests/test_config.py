from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from trading_lab.config import ConfigError, load_security_config
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
            "audit_path": "C:\\ProgramData\\AutomatonMT5Lab\\data\\audit.jsonl",
            "research_db_path": "C:\\ProgramData\\AutomatonMT5Lab\\data\\research.db",
            "demo_authorization_path": "C:\\ProgramData\\AutomatonMT5Lab\\control\\demo.authorization",
            "kill_switch_path": "C:\\ProgramData\\AutomatonMT5Lab\\control\\KILL_SWITCH",
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
            payload["audit_path"] = "C:\\ProgramData\\AutomatonMT5Lab\\control\\audit.jsonl"
            payload["research_db_path"] = "C:\\ProgramData\\AutomatonMT5Lab\\control\\research.db"
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
