from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from trading_lab.authorization import FileExecutionAuthorization


class BoundExecutionAuthorizationTests(unittest.TestCase):
    def test_requires_exact_demo_account_server_config_and_readiness_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization_path = Path(directory) / "demo.authorization"
            kill_path = Path(directory) / "KILL_SWITCH"
            verifier = FileExecutionAuthorization(
                authorization_path,
                kill_path,
                expected_account=12345678,
                expected_server="Broker-Demo",
                expected_config_hash="a" * 64,
            )
            payload = {
                "schema_version": 1,
                "authorization": "ALLOW_DEMO_EXECUTION",
                "authorized_account": 12345678,
                "authorized_server": "Broker-Demo",
                "config_sha256": "a" * 64,
                "readiness_sha256": "b" * 64,
            }
            authorization_path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertTrue(verifier.evaluate().allowed)
            payload["authorized_server"] = "Other-Demo"
            authorization_path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertFalse(verifier.evaluate().allowed)

    def test_kill_switch_overrides_bound_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.authorization").write_text("{}", encoding="utf-8")
            (root / "KILL_SWITCH").write_text("HALT\n", encoding="utf-8")
            decision = FileExecutionAuthorization(
                root / "demo.authorization", root / "KILL_SWITCH",
                expected_account=1, expected_server="Demo", expected_config_hash="a" * 64,
            ).evaluate()
            self.assertFalse(decision.allowed)
            self.assertEqual("KILL_SWITCH_ENGAGED", decision.code)

    def test_kill_switch_permission_or_state_error_fails_closed(self) -> None:
        verifier = FileExecutionAuthorization("authorization.json", "STOP_TRADING")
        with mock.patch.object(Path, "lstat", side_effect=PermissionError("denied")):
            decision = verifier.evaluate()
        self.assertFalse(decision.allowed)
        self.assertEqual("KILL_SWITCH_UNREADABLE", decision.code)


if __name__ == "__main__":
    unittest.main()
