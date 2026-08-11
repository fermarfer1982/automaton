from __future__ import annotations

import unittest
from dataclasses import replace

from trading_lab.account_guard import AccountGuard
from trading_lab.domain import AccountKind
from tests.fakes import FakeMT5Adapter


class AccountGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = FakeMT5Adapter()
        self.guard = AccountGuard(
            authorized_login=12345678,
            authorized_server="Broker-Demo",
        )

    def test_accepts_only_exact_authorized_demo_account(self) -> None:
        decision = self.guard.evaluate(self.adapter.account)
        self.assertTrue(decision.allowed)
        self.assertTrue(all(check.passed for check in decision.checks))

    def test_rejects_wrong_account_without_trying_to_switch(self) -> None:
        account = replace(self.adapter.account, login=87654321)
        decision = self.guard.evaluate(account)
        self.assertFalse(decision.allowed)
        self.assertIn("ACCOUNT_LOGIN_MISMATCH", decision.failed_codes)

    def test_rejects_wrong_server(self) -> None:
        account = replace(self.adapter.account, server="Other-Demo")
        decision = self.guard.evaluate(account)
        self.assertFalse(decision.allowed)
        self.assertIn("ACCOUNT_SERVER_MISMATCH", decision.failed_codes)

    def test_rejects_real_account_even_when_login_and_server_match(self) -> None:
        account = replace(self.adapter.account, kind=AccountKind.REAL)
        decision = self.guard.evaluate(account)
        self.assertFalse(decision.allowed)
        self.assertIn("ACCOUNT_NOT_DEMO", decision.failed_codes)

    def test_rejects_disconnected_or_trade_disabled_terminal(self) -> None:
        disconnected = self.guard.evaluate(replace(self.adapter.account, connected=False))
        disabled = self.guard.evaluate(replace(self.adapter.account, trade_allowed=False))
        terminal_disabled = self.guard.evaluate(
            replace(self.adapter.account, terminal_trade_allowed=False)
        )
        self.assertFalse(disconnected.allowed)
        self.assertFalse(disabled.allowed)
        self.assertFalse(terminal_disabled.allowed)
        self.assertIn("TERMINAL_AUTOTRADING_DISABLED", terminal_disabled.failed_codes)


if __name__ == "__main__":
    unittest.main()
