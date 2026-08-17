from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from .config import SecurityConfig


AUTHORIZATION_PURPOSE = "MT5_READ_ONLY_PREFLIGHT"
AUTHORIZATION_SCHEMA_VERSION = 1
AUTHORIZATION_LIFETIME = timedelta(minutes=15)
MAX_CONTROL_FILE_BYTES = 64 * 1024
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class KillSwitchState(str, Enum):
    ABSENT = "ABSENT"
    PRESENT_READABLE = "PRESENT_READABLE"


class MT5ReadOnlyControlError(RuntimeError):
    def __init__(
        self,
        code: str,
        stage: str,
        message: str,
        *,
        evidence: dict[str, bool] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.evidence = {} if evidence is None else dict(evidence)


@dataclass(frozen=True, slots=True)
class ReadOnlyAuthorizationFile:
    path: Path
    content: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class ReadOnlyAuthorization:
    schema_version: int
    purpose: str
    run_id: str
    authorization_id: str
    issued_at_utc: str
    expires_at_utc: str
    issuer_sid: str
    gateway_sid: str
    trading_mode: str
    gateway_mt5_access_required: bool
    authorized_account: int
    authorized_server: str
    authorized_symbol: str
    terminal_path: str
    git_commit: str
    config_sha256: str
    entrypoint_sha256: str
    runner_sha256: str
    harness_sha256: str
    controls_sha256: str
    windows_acl_sha256: str
    authorization_script_sha256: str
    authorization_helper_sha256: str
    config_loader_sha256: str
    audit_sha256: str
    sqlite_audit_sha256: str
    package_guard_sha256: str


_AUTHORIZATION_FIELDS = frozenset(ReadOnlyAuthorization.__dataclass_fields__)


def _is_reparse_point(path: Path, file_stat: os.stat_result | None = None) -> bool:
    value = path.lstat() if file_stat is None else file_stat
    attributes = getattr(value, "st_file_attributes", 0)
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT) or stat.S_ISLNK(
        value.st_mode
    )


def _same_open_file(before: os.stat_result, opened: os.stat_result) -> bool:
    return (
        stat.S_ISREG(opened.st_mode)
        and before.st_dev == opened.st_dev
        and before.st_ino == opened.st_ino
        and before.st_size == opened.st_size
    )


def _regular_readonly_bytes(
    path: Path,
    *,
    missing_code: str,
    unreadable_code: str,
    stage: str,
    maximum_bytes: int,
) -> bytes:
    if not path.is_absolute():
        raise MT5ReadOnlyControlError(unreadable_code, stage, "Protected control path is not absolute.")
    try:
        file_stat = path.lstat()
    except FileNotFoundError as exc:
        raise MT5ReadOnlyControlError(missing_code, stage, "Protected control file is absent.") from exc
    except OSError as exc:
        raise MT5ReadOnlyControlError(unreadable_code, stage, "Protected control file status is unavailable.") from exc
    if _is_reparse_point(path, file_stat) or not stat.S_ISREG(file_stat.st_mode):
        raise MT5ReadOnlyControlError(unreadable_code, stage, "Protected control file is not a regular non-reparse file.")
    if file_stat.st_size < 0 or file_stat.st_size > maximum_bytes:
        raise MT5ReadOnlyControlError(unreadable_code, stage, "Protected control file size is invalid.")
    try:
        with path.open("rb") as handle:
            if not _same_open_file(file_stat, os.fstat(handle.fileno())):
                raise MT5ReadOnlyControlError(
                    unreadable_code,
                    stage,
                    "Protected control file changed during read-only open.",
                )
            content = handle.read(maximum_bytes + 1)
    except MT5ReadOnlyControlError:
        raise
    except OSError as exc:
        raise MT5ReadOnlyControlError(unreadable_code, stage, "Protected control file cannot be opened read-only.") from exc
    if len(content) > maximum_bytes:
        raise MT5ReadOnlyControlError(unreadable_code, stage, "Protected control file exceeds its size limit.")
    return content


def probe_kill_switch(path: str | Path) -> KillSwitchState:
    """Distinguish only a genuine absence from a readable regular file."""
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.name != "STOP_TRADING":
        raise MT5ReadOnlyControlError(
            "KILL_SWITCH_UNREADABLE", "KILL_SWITCH", "Kill-switch path is invalid."
        )
    try:
        file_stat = candidate.lstat()
    except FileNotFoundError:
        return KillSwitchState.ABSENT
    except OSError as exc:
        raise MT5ReadOnlyControlError(
            "KILL_SWITCH_UNREADABLE", "KILL_SWITCH", "Kill-switch state cannot be determined."
        ) from exc
    if _is_reparse_point(candidate, file_stat) or not stat.S_ISREG(file_stat.st_mode):
        raise MT5ReadOnlyControlError(
            "KILL_SWITCH_UNREADABLE", "KILL_SWITCH", "Kill switch is not a regular non-reparse file."
        )
    try:
        with candidate.open("rb") as handle:
            if not _same_open_file(file_stat, os.fstat(handle.fileno())):
                raise MT5ReadOnlyControlError(
                    "KILL_SWITCH_UNREADABLE",
                    "KILL_SWITCH",
                    "Kill switch changed during read-only open.",
                )
            handle.read(1)
    except MT5ReadOnlyControlError:
        raise
    except OSError as exc:
        raise MT5ReadOnlyControlError(
            "KILL_SWITCH_UNREADABLE", "KILL_SWITCH", "Kill switch cannot be opened read-only."
        ) from exc
    return KillSwitchState.PRESENT_READABLE


def authorization_path(config: SecurityConfig, run_id: str) -> Path:
    if not _UUID.fullmatch(run_id):
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_AUTHORIZATION_RUN_ID_INVALID",
            "AUTHORIZATION_PATH",
            "Authorization RunId is not a canonical UUID.",
        )
    root = Path(os.path.abspath(config.demo_authorization_path.parent))
    candidate = root / f"mt5-read-only-authorization-{run_id}.json"
    if Path(os.path.abspath(candidate.parent)) != root:
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_AUTHORIZATION_PATH_INVALID",
            "AUTHORIZATION_PATH",
            "Authorization path escapes the protected directory.",
        )
    return candidate


def read_authorization_file(path: Path) -> ReadOnlyAuthorizationFile:
    content = _regular_readonly_bytes(
        path,
        missing_code="MT5_READ_ONLY_AUTHORIZATION_MISSING",
        unreadable_code="MT5_READ_ONLY_AUTHORIZATION_UNREADABLE",
        stage="AUTHORIZATION_FILE",
        maximum_bytes=MAX_CONTROL_FILE_BYTES,
    )
    return ReadOnlyAuthorizationFile(
        path=path,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _parse_utc(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_AUTHORIZATION_INVALID", "AUTHORIZATION", f"{field} is invalid."
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_AUTHORIZATION_INVALID", "AUTHORIZATION", f"{field} must be UTC."
        )
    return parsed.astimezone(UTC)


def parse_authorization(content: bytes) -> ReadOnlyAuthorization:
    try:
        raw = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_AUTHORIZATION_INVALID", "AUTHORIZATION", "Authorization JSON is invalid."
        ) from exc
    if not isinstance(raw, dict) or frozenset(raw) != _AUTHORIZATION_FIELDS:
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_AUTHORIZATION_INVALID", "AUTHORIZATION", "Authorization schema is not exact."
        )
    try:
        authorization = ReadOnlyAuthorization(**raw)
    except TypeError as exc:
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_AUTHORIZATION_INVALID", "AUTHORIZATION", "Authorization field types are invalid."
        ) from exc
    string_fields = _AUTHORIZATION_FIELDS - {
        "schema_version", "gateway_mt5_access_required", "authorized_account"
    }
    if (
        type(authorization.schema_version) is not int
        or type(authorization.gateway_mt5_access_required) is not bool
        or type(authorization.authorized_account) is not int
        or any(
            not isinstance(getattr(authorization, field), str)
            or not getattr(authorization, field)
            for field in string_fields
        )
    ):
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_AUTHORIZATION_INVALID", "AUTHORIZATION", "Authorization field types are invalid."
        )
    return authorization


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(_regular_readonly_bytes(
        path,
        missing_code="MT5_READ_ONLY_BINDING_FILE_MISSING",
        unreadable_code="MT5_READ_ONLY_BINDING_FILE_UNREADABLE",
        stage="AUTHORIZATION_BINDING",
        maximum_bytes=2 * 1024 * 1024,
    )).hexdigest()


def read_git_head(workspace: Path) -> str:
    git_root = workspace / ".git"
    if not git_root.is_dir() or _is_reparse_point(git_root):
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_GIT_STATE_INVALID", "AUTHORIZATION_BINDING", "Git metadata root is invalid."
        )
    try:
        head = (git_root / "HEAD").read_text(encoding="ascii").strip()
    except OSError as exc:
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_GIT_STATE_INVALID", "AUTHORIZATION_BINDING", "Git HEAD is unavailable."
        ) from exc
    if _GIT_COMMIT.fullmatch(head):
        return head
    if not head.startswith("ref: refs/"):
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_GIT_STATE_INVALID", "AUTHORIZATION_BINDING", "Git HEAD format is invalid."
        )
    reference = head[5:]
    reference_path = git_root / Path(reference.replace("/", os.sep))
    if Path(os.path.abspath(reference_path)).is_relative_to(Path(os.path.abspath(git_root))):
        try:
            commit = reference_path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            commit = ""
        except OSError as exc:
            raise MT5ReadOnlyControlError(
                "MT5_READ_ONLY_GIT_STATE_INVALID", "AUTHORIZATION_BINDING", "Git reference is unavailable."
            ) from exc
        if _GIT_COMMIT.fullmatch(commit):
            return commit
    try:
        packed = (git_root / "packed-refs").read_text(encoding="ascii").splitlines()
    except FileNotFoundError:
        packed = []
    except OSError as exc:
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_GIT_STATE_INVALID", "AUTHORIZATION_BINDING", "Git packed references are unavailable."
        ) from exc
    for line in packed:
        if line.startswith("#") or line.startswith("^"):
            continue
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1] == reference and _GIT_COMMIT.fullmatch(parts[0]):
            return parts[0]
    raise MT5ReadOnlyControlError(
        "MT5_READ_ONLY_GIT_STATE_INVALID", "AUTHORIZATION_BINDING", "Git HEAD commit cannot be resolved."
    )


def expected_bindings(config_path: Path, workspace: Path) -> dict[str, str]:
    files = {
        "config_sha256": config_path,
        "entrypoint_sha256": workspace / "trading_lab" / "mt5_read_only_entrypoint.py",
        "runner_sha256": workspace / "trading_lab" / "mt5_read_only.py",
        "harness_sha256": workspace / "scripts" / "Test-MT5ReadOnlyPreflight.ps1",
        "controls_sha256": workspace / "trading_lab" / "mt5_read_only_controls.py",
        "windows_acl_sha256": workspace / "trading_lab" / "windows_acl.py",
        "authorization_script_sha256": workspace / "scripts" / "New-MT5ReadOnlyAuthorization.ps1",
        "authorization_helper_sha256": workspace / "trading_lab" / "mt5_read_only_authorization.py",
        "config_loader_sha256": workspace / "trading_lab" / "config.py",
        "audit_sha256": workspace / "trading_lab" / "audit.py",
        "sqlite_audit_sha256": workspace / "trading_lab" / "sqlite_audit.py",
        "package_guard_sha256": workspace / "trading_lab" / "health_only.py",
    }
    return {name: _sha256_file(path) for name, path in files.items()}


def render_authorization(
    *,
    config: SecurityConfig,
    config_path: Path,
    workspace: Path,
    run_id: str,
    authorization_id: str,
    issuer_sid: str,
    gateway_sid: str,
    issued_at: datetime,
) -> dict[str, Any]:
    if not _UUID.fullmatch(run_id) or not _UUID.fullmatch(authorization_id):
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_AUTHORIZATION_INVALID", "AUTHORIZATION_CREATE", "Authorization UUID is invalid."
        )
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    expires = issued + AUTHORIZATION_LIFETIME
    return {
        "schema_version": AUTHORIZATION_SCHEMA_VERSION,
        "purpose": AUTHORIZATION_PURPOSE,
        "run_id": run_id,
        "authorization_id": authorization_id,
        "issued_at_utc": issued.isoformat().replace("+00:00", "Z"),
        "expires_at_utc": expires.isoformat().replace("+00:00", "Z"),
        "issuer_sid": issuer_sid,
        "gateway_sid": gateway_sid,
        "trading_mode": "OBSERVE_ONLY",
        "gateway_mt5_access_required": False,
        "authorized_account": config.authorized_account,
        "authorized_server": config.authorized_server,
        "authorized_symbol": config.allowed_symbol,
        "terminal_path": str(config.mt5_terminal_path),
        "git_commit": read_git_head(workspace),
        **expected_bindings(config_path, workspace),
    }


def validate_authorization(
    authorization: ReadOnlyAuthorization,
    *,
    config: SecurityConfig,
    config_path: Path,
    workspace: Path,
    run_id: str,
    issuer_sid: str,
    gateway_sid: str,
    now: datetime,
) -> dict[str, bool]:
    issued = _parse_utc(authorization.issued_at_utc, "issued_at_utc")
    expires = _parse_utc(authorization.expires_at_utc, "expires_at_utc")
    current = now.astimezone(UTC)
    bindings = expected_bindings(config_path, workspace)
    run_match = authorization.run_id == run_id
    issuer_match = authorization.issuer_sid == issuer_sid
    gateway_match = authorization.gateway_sid == gateway_sid
    not_expired = issued <= current <= expires and expires - issued == AUTHORIZATION_LIFETIME
    config_hash_match = authorization.config_sha256 == bindings["config_sha256"]
    code_hash_match = all(
        getattr(authorization, field) == value
        for field, value in bindings.items()
        if field != "config_sha256"
    )
    exact = (
        authorization.schema_version == AUTHORIZATION_SCHEMA_VERSION
        and authorization.purpose == AUTHORIZATION_PURPOSE
        and _UUID.fullmatch(authorization.authorization_id) is not None
        and run_match
        and issuer_match
        and gateway_match
        and authorization.trading_mode == "OBSERVE_ONLY"
        and authorization.gateway_mt5_access_required is False
        and authorization.authorized_account == config.authorized_account
        and authorization.authorized_server == config.authorized_server
        and authorization.authorized_symbol == "XAUUSD" == config.allowed_symbol
        and os.path.normcase(os.path.abspath(authorization.terminal_path))
        == os.path.normcase(os.path.abspath(config.mt5_terminal_path))
        and authorization.git_commit == read_git_head(workspace)
        and config_hash_match
        and code_hash_match
        and not_expired
    )
    evidence = {
        "authorization_run_id_match": run_match,
        "authorization_not_expired": not_expired,
        "authorization_issuer_match": issuer_match,
        "authorization_gateway_sid_match": gateway_match,
        "authorization_config_hash_match": config_hash_match,
        "authorization_code_hash_match": code_hash_match,
    }
    if not exact:
        raise MT5ReadOnlyControlError(
            "MT5_READ_ONLY_AUTHORIZATION_INVALID",
            "AUTHORIZATION",
            "Protected MT5 read-only authorization does not match the exact runtime binding.",
            evidence=evidence,
        )
    return evidence
