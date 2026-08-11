from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    code: str
    detail: str


class FileExecutionAuthorization:
    """External two-part control: an allow file plus an overriding kill switch."""

    EXPECTED_AUTHORIZATION = "ALLOW_DEMO_EXECUTION"

    def __init__(self, authorization_path: str | Path, kill_switch_path: str | Path) -> None:
        self._authorization_path = Path(authorization_path)
        self._kill_switch_path = Path(kill_switch_path)

    def evaluate(self) -> AuthorizationDecision:
        if self._kill_switch_path.exists():
            return AuthorizationDecision(False, "KILL_SWITCH_ENGAGED", "Independent kill switch is engaged")
        try:
            content = self._authorization_path.read_text(encoding="utf-8").strip()
        except OSError:
            return AuthorizationDecision(
                False,
                "DEMO_EXECUTION_NOT_AUTHORIZED",
                "External human authorization file is absent or unreadable",
            )
        if content != self.EXPECTED_AUTHORIZATION:
            return AuthorizationDecision(
                False,
                "DEMO_EXECUTION_NOT_AUTHORIZED",
                "External human authorization content is invalid",
            )
        return AuthorizationDecision(True, "DEMO_EXECUTION_AUTHORIZED", "External authorization is valid")
