from __future__ import annotations

import math

from .domain import AccountKind, AccountSnapshot, CheckResult, GuardDecision


class AccountGuard:
    """Validates the already-selected MT5 account; it never selects or logs into one."""

    def __init__(self, authorized_login: int, authorized_server: str) -> None:
        self._authorized_login = authorized_login
        self._authorized_server = authorized_server

    def evaluate(self, account: AccountSnapshot) -> GuardDecision:
        checks = (
            CheckResult("TERMINAL_CONNECTED", account.connected, "MT5 terminal must be connected"),
            CheckResult(
                "ACCOUNT_LOGIN_MISMATCH",
                account.login == self._authorized_login,
                "Current account must exactly match the externally authorized login",
            ),
            CheckResult(
                "ACCOUNT_SERVER_MISMATCH",
                account.server == self._authorized_server,
                "Current server must exactly match the externally authorized server",
            ),
            CheckResult(
                "ACCOUNT_NOT_DEMO",
                account.kind is AccountKind.DEMO,
                "Only an MT5 DEMO account is permitted",
            ),
            CheckResult(
                "ACCOUNT_TRADE_DISABLED",
                account.trade_allowed,
                "Trading must be enabled by the MT5 account",
            ),
            CheckResult(
                "TERMINAL_AUTOTRADING_DISABLED",
                account.terminal_trade_allowed,
                "MT5 terminal automated trading must be explicitly enabled",
            ),
            CheckResult(
                "ACCOUNT_EQUITY_INVALID",
                math.isfinite(account.equity) and account.equity > 0,
                "Account equity must be finite and positive",
            ),
        )
        return GuardDecision(checks=checks)
