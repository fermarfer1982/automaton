from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tests.test_readiness import security_config
from trading_lab.domain import TradingMode
from trading_lab.mt5_read_only_authorization import _load_exact_config, render
from trading_lab.windows_acl import AclVerification


RUN_ID = "11111111-2222-4333-8444-555555555555"
AUTHORIZATION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
MAINTENANCE_SID = "S-1-5-21-1-2-3-1008"
GATEWAY_SID = "S-1-5-21-1-2-3-1007"


class MT5ReadOnlyAuthorizationHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "trading.yaml"
        self.config_path.write_text("trading_mode: OBSERVE_ONLY\n", encoding="utf-8")
        self.config = replace(
            security_config(self.root),
            mt5_access_enabled=False,
            demo_authorization_path=(
                self.root / "control" / "demo-authorization" / "authorization.json"
            ),
            kill_switch_path=self.root / "control" / "STOP_TRADING",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_render_requires_exact_canonical_maintenance_token(self) -> None:
        acl = AclVerification(
            True,
            "strict",
            current_sid=MAINTENANCE_SID,
            maintenance_sid=MAINTENANCE_SID,
            gateway_sid=GATEWAY_SID,
        )
        with (
            patch(
                "trading_lab.mt5_read_only_authorization._load_exact_config",
                return_value=self.config,
            ),
            patch("trading_lab.mt5_read_only_authorization._acl", return_value=acl),
        ):
            payload = render(
                self.config_path,
                RUN_ID,
                AUTHORIZATION_ID,
                MAINTENANCE_SID,
            )
            self.assertEqual(MAINTENANCE_SID, payload["issuer_sid"])
            with self.assertRaises(PermissionError):
                render(
                    self.config_path,
                    RUN_ID,
                    AUTHORIZATION_ID,
                    "S-1-5-21-9-9-9-9999",
                )

    def test_exact_config_rejects_non_observe_enabled_or_wrong_symbol(self) -> None:
        cases = (
            replace(self.config, trading_mode=TradingMode.PAPER),
            replace(self.config, mt5_access_enabled=True),
            replace(self.config, allowed_symbol="XAUUSDm"),
        )
        for config in cases:
            with self.subTest(config=config), patch(
                "trading_lab.mt5_read_only_authorization.load_mt5_security_config",
                return_value=config,
            ), self.assertRaises(RuntimeError):
                _load_exact_config(self.config_path)


if __name__ == "__main__":
    unittest.main()
