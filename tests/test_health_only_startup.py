from __future__ import annotations

import json
import logging
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from tests.test_readiness import security_config
from trading_lab.api_auth import ApiKeyVerifier
from trading_lab.fastapi_service import create_fastapi_app
from trading_lab.health_only import build_health_only_application
from trading_lab.mt5_access import MT5AccessDisabled
from trading_lab.service import acquire_mt5_adapter, serve
from trading_lab.windows_acl import AclVerification


class HealthOnlyStartupTests(unittest.TestCase):
    KEY = "H" * 43

    def _config(self, root: Path):
        return replace(security_config(root), mt5_access_enabled=False)

    def _application(self, root: Path):
        return build_health_only_application(
            self._config(root),
            runtime_identity_verified=True,
        )

    def test_health_only_application_never_imports_or_accesses_mt5(self) -> None:
        self.assertNotIn("MetaTrader5", sys.modules)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            application = self._application(root)
            application.record_gateway_started()
            health = application.health()
            application.record_gateway_stopped()
            records = [
                json.loads(line)
                for line in (root / "data" / "audit.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            startup = records[0]
            self.assertEqual("gateway_started", startup["event"])
            self.assertEqual(
                {
                    "GATEWAY_STARTED": True,
                    "TRADING_MODE": "OBSERVE_ONLY",
                    "MT5_ACCESS_ENABLED": False,
                    "MT5_IMPORTED": False,
                    "MT5_ACCESSED": False,
                    "ORDER_CHECK": False,
                    "ORDER_SEND": False,
                },
                startup["payload"],
            )
        self.assertEqual("UP", health["gateway_status"])
        self.assertTrue(health["healthy"])
        self.assertEqual("OBSERVE_ONLY", health["trading_mode"])
        self.assertFalse(health["mt5_access_enabled"])
        self.assertEqual("DISABLED_NOT_ACCESSED", health["mt5_status"])
        self.assertEqual("5.0.6090", health["mt5_package_metadata_version"])
        self.assertFalse(health["mt5_imported"])
        self.assertFalse(health["mt5_accessed"])
        self.assertFalse(health["order_check_called"])
        self.assertFalse(health["order_send_called"])
        self.assertNotIn("MetaTrader5", sys.modules)

    def test_health_route_works_and_mt5_dependent_routes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key_path = root / "gateway.key"
            key_path.write_text(self.KEY, encoding="ascii")
            api = create_fastapi_app(self._application(root), ApiKeyVerifier(key_path))
            client = TestClient(api)
            headers = {"X-AUTOMATON-KEY": self.KEY}
            self.assertEqual(401, client.get("/health").status_code)
            response = client.get("/health", headers=headers)
            self.assertEqual(200, response.status_code)
            self.assertEqual("DISABLED_NOT_ACCESSED", response.json()["mt5_status"])
            for method, path, body in (
                ("get", "/v1/status", None),
                ("get", "/v1/account", None),
                ("get", "/v1/market/XAUUSD", None),
                ("get", "/v1/positions", None),
                ("post", "/v1/trade/close", {"ticket": 1, "reason": "protect capital"}),
            ):
                result = (
                    getattr(client, method)(path, headers=headers)
                    if body is None
                    else getattr(client, method)(path, headers=headers, json=body)
                )
                self.assertEqual(503, result.status_code, path)
                self.assertEqual("MT5_ACCESS_DISABLED", result.json()["code"])
        self.assertNotIn("MetaTrader5", sys.modules)

    def test_adapter_acquisition_fails_before_any_import_when_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = replace(
                self._config(root),
                api_key_path=root / "gateway.key",
                gateway_lock_path=root / "gateway.lock",
            )
            with patch("builtins.__import__", wraps=__import__) as importer:
                with self.assertRaisesRegex(MT5AccessDisabled, "MT5_ACCESS_DISABLED"):
                    acquire_mt5_adapter(config, mt5_access_enabled=False)
            imported_names = [str(call.args[0]) for call in importer.call_args_list if call.args]
        self.assertNotIn("trading_lab.providers", imported_names)
        self.assertNotIn("MetaTrader5", imported_names)
        self.assertNotIn("MetaTrader5", sys.modules)

    def test_service_disabled_startup_never_acquires_or_shuts_down_mt5(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = replace(
                self._config(root),
                api_key_path=root / "gateway.key",
                gateway_lock_path=root / "gateway.lock",
            )
            application = Mock()
            application.health.return_value = {"gateway_status": "UP"}
            logger = Mock(spec=logging.Logger)
            with (
                patch("trading_lab.service.load_security_config", return_value=config),
                patch("trading_lab.service.resolve_mt5_access_enabled", return_value=False),
                patch(
                    "trading_lab.service.verify_windows_acl",
                    return_value=AclVerification(True, "safe"),
                ),
                patch("trading_lab.service.configure_gateway_logging"),
                patch("trading_lab.service.ApiKeyVerifier"),
                patch("trading_lab.service.GatewayProcessLock") as process_lock,
                patch(
                    "trading_lab.service.build_health_only_application",
                    return_value=application,
                ),
                patch("trading_lab.service.acquire_mt5_adapter") as acquire,
                patch("trading_lab.service._run_uvicorn") as run_uvicorn,
                patch("trading_lab.service.logging.getLogger", return_value=logger),
            ):
                process_lock.return_value.__enter__.return_value = process_lock.return_value
                serve(Path(directory) / "security.yaml", environment={"MT5_ACCESS_ENABLED": "false"})
            acquire.assert_not_called()
            application.record_gateway_started.assert_called_once_with()
            application.record_gateway_stopped.assert_called_once_with()
            run_uvicorn.assert_called_once()
            serialized_logs = json.dumps([
                {"args": call.args, "kwargs": call.kwargs}
                for call in logger.info.call_args_list
            ]).casefold()
            self.assertNotIn(str(config.authorized_account), serialized_logs)
            self.assertNotIn(config.authorized_server.casefold(), serialized_logs)
            self.assertNotIn("password", serialized_logs)
            self.assertNotIn(self.KEY.casefold(), serialized_logs)
        self.assertNotIn("MetaTrader5", sys.modules)

    def test_health_only_startup_uses_certified_final_python(self) -> None:
        self.assertEqual((3, 14, 5), sys.version_info[:3])
        self.assertEqual(
            Path(r"C:\automaton\.venv\Scripts\python.exe"),
            Path(sys.executable),
        )


if __name__ == "__main__":
    unittest.main()
