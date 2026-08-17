from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from trading_lab.config import ConfigError
from trading_lab.protected_identity_config import (
    TARGET_ACCOUNT,
    TARGET_MODE,
    TARGET_SERVER,
    TARGET_SYMBOL,
    TARGET_TERMINAL,
    parse_yaml_bytes,
    plan_identity_update,
    render_candidate,
    validate_canonical_config,
    validate_candidate,
)


def placeholder() -> dict[str, object]:
    return {
        "schema_version": 1,
        "trading_mode": TARGET_MODE,
        "authorized_account": 0,
        "authorized_server": "CHANGE_ME",
        "authorized_account_name": None,
        "allowed_symbol": TARGET_SYMBOL,
        "magic_number": 26081101,
        "mt5_terminal_path": TARGET_TERMINAL,
        "audit_path": r"C:\ProgramData\AutomatonMT5Lab\audit\journal\audit.jsonl",
        "audit_db_path": r"C:\ProgramData\AutomatonMT5Lab\audit\sqlite\audit.db",
        "research_db_path": r"C:\ProgramData\AutomatonMT5Lab\research\research.db",
        "api_key_path": r"C:\ProgramData\AutomatonMT5Lab\ipc\automaton.key",
        "gateway_lock_path": r"C:\ProgramData\AutomatonMT5Lab\operational\gateway.lock",
        "log_dir": r"C:\ProgramData\AutomatonMT5Lab\logs\gateway",
        "security_log_dir": r"C:\ProgramData\AutomatonMT5Lab\logs\security",
        "demo_authorization_path": r"C:\ProgramData\AutomatonMT5Lab\control\demo-authorization\authorization.json",
        "kill_switch_path": r"C:\ProgramData\AutomatonMT5Lab\control\STOP_TRADING",
        "automaton_state_dir": r"C:\Users\AutomatonAgent\.automaton",
        "gateway_windows_identity": r"DESKTOP-QPK9UQ5\AutomatonGateway",
        "automaton_windows_identity": r"DESKTOP-QPK9UQ5\AutomatonAgent",
        "risk": {
            "max_risk_per_trade_fraction": 0.0025,
            "max_volume": 0.01,
            "max_spread_points": 30.0,
            "max_open_positions": 1,
            "max_symbol_exposure_lots": 0.01,
            "max_daily_loss_fraction": 0.01,
            "min_stop_distance_points": 20,
            "duplicate_window_seconds": 300,
        },
    }


class ProtectedIdentityConfigTests(unittest.TestCase):
    def test_known_placeholder_becomes_only_exact_identity_target(self) -> None:
        raw = placeholder()
        state, candidate = plan_identity_update(raw)
        self.assertEqual("KNOWN_PLACEHOLDER", state)
        self.assertEqual(TARGET_ACCOUNT, candidate["authorized_account"])
        self.assertEqual(TARGET_SERVER, candidate["authorized_server"])
        self.assertIs(candidate["mt5_access_enabled"], False)
        for key in set(raw) - {"authorized_account", "authorized_server"}:
            self.assertEqual(raw[key], candidate[key])

    def test_exact_target_is_idempotent(self) -> None:
        _, exact = plan_identity_update(placeholder())
        state, second = plan_identity_update(exact)
        self.assertEqual("EXACT_TARGET", state)
        self.assertEqual(exact, second)

    def test_unexpected_account_or_server_fails_closed(self) -> None:
        cases = ((42, "CHANGE_ME"), (0, "Other-Demo"), (TARGET_ACCOUNT, "CHANGE_ME"))
        for account, server in cases:
            with self.subTest(account=account, server=server):
                raw = placeholder()
                raw["authorized_account"] = account
                raw["authorized_server"] = server
                with self.assertRaises(ConfigError):
                    plan_identity_update(raw)

    def test_access_true_or_wrong_fixed_boundary_fails_closed(self) -> None:
        for key, value in (
            ("mt5_access_enabled", True),
            ("allowed_symbol", "EURUSD"),
            ("mt5_terminal_path", r"C:\Other\terminal64.exe"),
            ("trading_mode", "PAPER"),
        ):
            with self.subTest(key=key):
                raw = placeholder()
                raw[key] = value
                with self.assertRaises(ConfigError):
                    plan_identity_update(raw)

    def test_render_is_structured_yaml_and_preserves_uncontrolled_values(self) -> None:
        raw = placeholder()
        rendered = render_candidate(raw)
        parsed = parse_yaml_bytes(rendered)
        self.assertEqual(TARGET_ACCOUNT, parsed["authorized_account"])
        self.assertEqual(TARGET_SERVER, parsed["authorized_server"])
        self.assertEqual(raw["risk"], parsed["risk"])
        self.assertNotIn("MetaTrader5", sys.modules)

    def test_unknown_fields_and_credentials_are_rejected(self) -> None:
        for key in ("password", "execution_override"):
            with self.subTest(key=key):
                raw = placeholder()
                raw[key] = "forbidden"
                import yaml

                with self.assertRaises(ConfigError):
                    parse_yaml_bytes(yaml.safe_dump(raw).encode("utf-8"))

    def test_candidate_does_not_mutate_input(self) -> None:
        raw = placeholder()
        before = copy.deepcopy(raw)
        plan_identity_update(raw)
        self.assertEqual(before, raw)

    def test_parse_builder_and_real_loader_failures_fail_closed(self) -> None:
        with self.assertRaises(ConfigError):
            parse_yaml_bytes(b"risk: [unterminated")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "trading.yaml"
            candidate = root / ".trading.identity-test.tmp"
            import yaml

            baseline.write_text(yaml.safe_dump(placeholder(), sort_keys=False), encoding="utf-8")
            candidate.write_bytes(render_candidate(placeholder()))
            with patch(
                "trading_lab.protected_identity_config._build_mt5_security_config",
                side_effect=ConfigError("builder rejected"),
            ), self.assertRaisesRegex(ConfigError, "builder rejected"):
                validate_candidate(baseline, candidate)

    def test_temp_candidate_uses_builder_while_public_loader_remains_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "trading.yaml"
            candidate = root / ".trading.identity-test.tmp"
            import yaml

            baseline.write_text(yaml.safe_dump(placeholder(), sort_keys=False), encoding="utf-8")
            original = baseline.read_bytes()
            candidate.write_bytes(render_candidate(placeholder()))
            result = validate_candidate(baseline, candidate)
            self.assertEqual("PASS", result["status"])
            self.assertEqual("_build_mt5_security_config", result["loader"])
            self.assertEqual(original, baseline.read_bytes())
            from trading_lab.config import load_mt5_security_config

            with self.assertRaisesRegex(ConfigError, "must use .yaml"):
                load_mt5_security_config(candidate)

    def test_post_replace_requires_canonical_path_and_public_loader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "original.backup"
            canonical = root / "trading.yaml"
            wrong = root / "other.yaml"
            import yaml

            baseline.write_text(yaml.safe_dump(placeholder(), sort_keys=False), encoding="utf-8")
            content = render_candidate(placeholder())
            canonical.write_bytes(content)
            wrong.write_bytes(content)
            with patch(
                "trading_lab.protected_identity_config.CANONICAL_CONFIG_PATH",
                canonical,
            ):
                result = validate_canonical_config(baseline, canonical)
                self.assertEqual("load_mt5_security_config", result["loader"])
                with self.assertRaisesRegex(ConfigError, "canonical trading.yaml"):
                    validate_canonical_config(baseline, wrong)

    def test_post_replace_public_loader_failure_is_propagated_for_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "original.backup"
            canonical = root / "trading.yaml"
            import yaml

            baseline.write_text(yaml.safe_dump(placeholder(), sort_keys=False), encoding="utf-8")
            canonical.write_bytes(render_candidate(placeholder()))
            with (
                patch("trading_lab.protected_identity_config.CANONICAL_CONFIG_PATH", canonical),
                patch(
                    "trading_lab.protected_identity_config.load_mt5_security_config",
                    side_effect=ConfigError("canonical reload rejected"),
                ),
                self.assertRaisesRegex(ConfigError, "canonical reload rejected"),
            ):
                validate_canonical_config(baseline, canonical)


if __name__ == "__main__":
    unittest.main()
