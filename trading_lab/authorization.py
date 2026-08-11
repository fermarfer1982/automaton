from __future__ import annotations

import json
import re
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

    def __init__(
        self,
        authorization_path: str | Path,
        kill_switch_path: str | Path,
        *,
        expected_account: int | None = None,
        expected_server: str | None = None,
        expected_config_hash: str | None = None,
    ) -> None:
        self._authorization_path = Path(authorization_path)
        self._kill_switch_path = Path(kill_switch_path)
        self._expected_account = expected_account
        self._expected_server = expected_server
        self._expected_config_hash = expected_config_hash

    def evaluate(self) -> AuthorizationDecision:
        try:
            self._kill_switch_path.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            return AuthorizationDecision(
                False,
                "KILL_SWITCH_UNREADABLE",
                "Independent kill switch state cannot be verified",
            )
        else:
            return AuthorizationDecision(False, "KILL_SWITCH_ENGAGED", "Independent kill switch is engaged")
        try:
            if self._authorization_path.is_symlink():
                raise OSError("authorization path is a symlink")
            content = self._authorization_path.read_text(encoding="utf-8")
        except OSError:
            return AuthorizationDecision(
                False,
                "DEMO_EXECUTION_NOT_AUTHORIZED",
                "External human authorization file is absent or unreadable",
            )
        binding_values = (
            self._expected_account, self._expected_server, self._expected_config_hash,
        )
        if any(value is not None for value in binding_values) and not all(
            value is not None for value in binding_values
        ):
            return AuthorizationDecision(
                False, "DEMO_EXECUTION_NOT_AUTHORIZED",
                "Execution authorization binding is incomplete",
            )
        strict_binding = all(value is not None for value in binding_values)
        if not strict_binding:
            if content.strip() == self.EXPECTED_AUTHORIZATION:
                return AuthorizationDecision(
                    True, "DEMO_EXECUTION_AUTHORIZED", "External authorization is valid"
                )
            return AuthorizationDecision(
                False,
                "DEMO_EXECUTION_NOT_AUTHORIZED",
                "External human authorization content is invalid",
            )
        try:
            payload = json.loads(content)
        except (ValueError, TypeError):
            payload = None
        expected_keys = {
            "schema_version", "authorization", "authorized_account",
            "authorized_server", "config_sha256", "readiness_sha256",
        }
        valid = (
            isinstance(payload, dict)
            and set(payload) == expected_keys
            and payload.get("schema_version") == 1
            and payload.get("authorization") == self.EXPECTED_AUTHORIZATION
            and payload.get("authorized_account") == self._expected_account
            and payload.get("authorized_server") == self._expected_server
            and payload.get("config_sha256") == self._expected_config_hash
            and isinstance(payload.get("readiness_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", payload["readiness_sha256"]) is not None
        )
        if not valid:
            return AuthorizationDecision(
                False,
                "DEMO_EXECUTION_NOT_AUTHORIZED",
                "External human authorization content is invalid",
            )
        return AuthorizationDecision(
            True,
            "DEMO_EXECUTION_AUTHORIZED",
            "External authorization is bound to the protected DEMO configuration",
        )
