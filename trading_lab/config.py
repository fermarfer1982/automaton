from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .domain import TradingMode


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class RiskLimits:
    max_risk_per_trade_fraction: float
    max_volume: float
    max_spread_points: float
    max_open_positions: int
    max_symbol_exposure_lots: float
    max_daily_loss_fraction: float
    min_stop_distance_points: int
    duplicate_window_seconds: int
    max_tick_age_seconds: float = 5.0


@dataclass(frozen=True)
class SecurityConfig:
    schema_version: int
    trading_mode: TradingMode
    authorized_account: int
    authorized_server: str
    allowed_symbol: str
    magic_number: int
    mt5_terminal_path: Path
    audit_path: Path
    research_db_path: Path
    demo_authorization_path: Path
    kill_switch_path: Path
    automaton_state_dir: Path
    gateway_windows_identity: str
    automaton_windows_identity: str
    risk: RiskLimits


_CREDENTIAL_KEYS = {
    "password",
    "passwd",
    "credential",
    "credentials",
    "api_key",
    "apikey",
    "token",
    "secret",
    "private_key",
}
_TOP_LEVEL_KEYS = {
    "schema_version", "trading_mode", "authorized_account", "authorized_server",
    "allowed_symbol", "magic_number", "mt5_terminal_path", "audit_path",
    "research_db_path", "demo_authorization_path", "kill_switch_path",
    "automaton_state_dir", "gateway_windows_identity",
    "automaton_windows_identity", "risk",
}
_RISK_KEYS = {
    "max_risk_per_trade_fraction", "max_volume", "max_spread_points",
    "max_open_positions", "max_symbol_exposure_lots", "max_daily_loss_fraction",
    "min_stop_distance_points", "duplicate_window_seconds", "max_tick_age_seconds",
}


def _reject_credentials(value: Any, prefix: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower()
            if normalized in _CREDENTIAL_KEYS:
                raise ConfigError(f"Credentials are forbidden in security config: {prefix}.{key}")
            _reject_credentials(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_credentials(child, f"{prefix}[{index}]")


def _positive_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise ConfigError(f"{name} must be finite and positive")
    return number


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{name} must be a positive integer")
    return value


def _required_string(payload: dict[str, Any], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{name} must be a non-empty string")
    return value.strip()


def _paths_overlap(first: Path, second: Path) -> bool:
    first_resolved = Path(os.path.abspath(first))
    second_resolved = Path(os.path.abspath(second))
    return (
        first_resolved == second_resolved
        or first_resolved.is_relative_to(second_resolved)
        or second_resolved.is_relative_to(first_resolved)
    )


def load_security_config(path: str | Path) -> SecurityConfig:
    config_path = Path(path)
    workspace = Path(__file__).resolve().parents[1]
    if not config_path.is_absolute():
        raise ConfigError("Security config path must be absolute")
    try:
        if config_path.resolve().is_relative_to(workspace):
            raise ConfigError("Security config must remain outside the workspace")
    except OSError as exc:
        raise ConfigError(f"Cannot resolve security config path: {exc}") from exc
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot load security config: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("Security config root must be an object")
    _reject_credentials(raw)
    unknown = set(raw) - _TOP_LEVEL_KEYS
    if unknown:
        raise ConfigError(f"Unknown security config fields: {', '.join(sorted(unknown))}")

    if raw.get("schema_version") != 1:
        raise ConfigError("schema_version must be exactly 1")
    try:
        mode = TradingMode(raw.get("trading_mode", TradingMode.OBSERVE_ONLY.value))
    except ValueError as exc:
        raise ConfigError("trading_mode is invalid") from exc

    account = _positive_int(raw.get("authorized_account"), "authorized_account")
    server = _required_string(raw, "authorized_server")
    symbol = _required_string(raw, "allowed_symbol")
    if symbol != "XAUUSD":
        raise ConfigError("Initial laboratory scope permits only exact symbol XAUUSD")
    magic = _positive_int(raw.get("magic_number"), "magic_number")

    risk_raw = raw.get("risk")
    if not isinstance(risk_raw, dict):
        raise ConfigError("risk must be an object")
    unknown_risk = set(risk_raw) - _RISK_KEYS
    if unknown_risk:
        raise ConfigError(f"Unknown risk fields: {', '.join(sorted(unknown_risk))}")
    risk = RiskLimits(
        max_risk_per_trade_fraction=_positive_number(
            risk_raw.get("max_risk_per_trade_fraction"), "risk.max_risk_per_trade_fraction"
        ),
        max_volume=_positive_number(risk_raw.get("max_volume"), "risk.max_volume"),
        max_spread_points=_positive_number(
            risk_raw.get("max_spread_points"), "risk.max_spread_points"
        ),
        max_open_positions=_positive_int(
            risk_raw.get("max_open_positions"), "risk.max_open_positions"
        ),
        max_symbol_exposure_lots=_positive_number(
            risk_raw.get("max_symbol_exposure_lots"), "risk.max_symbol_exposure_lots"
        ),
        max_daily_loss_fraction=_positive_number(
            risk_raw.get("max_daily_loss_fraction"), "risk.max_daily_loss_fraction"
        ),
        min_stop_distance_points=_positive_int(
            risk_raw.get("min_stop_distance_points"), "risk.min_stop_distance_points"
        ),
        duplicate_window_seconds=_positive_int(
            risk_raw.get("duplicate_window_seconds"), "risk.duplicate_window_seconds"
        ),
        max_tick_age_seconds=_positive_number(
            risk_raw.get("max_tick_age_seconds", 5.0), "risk.max_tick_age_seconds"
        ),
    )
    if risk.max_risk_per_trade_fraction >= 1 or risk.max_daily_loss_fraction >= 1:
        raise ConfigError("Risk fractions must be less than 1")
    if risk.max_open_positions != 1:
        raise ConfigError("Initial laboratory maximum open positions must be exactly 1")

    terminal_path = Path(_required_string(raw, "mt5_terminal_path"))
    audit_path = Path(_required_string(raw, "audit_path"))
    research_path = Path(_required_string(raw, "research_db_path"))
    authorization_path = Path(_required_string(raw, "demo_authorization_path"))
    kill_path = Path(_required_string(raw, "kill_switch_path"))
    automaton_state_dir = Path(_required_string(raw, "automaton_state_dir"))
    gateway_identity = _required_string(raw, "gateway_windows_identity")
    automaton_identity = _required_string(raw, "automaton_windows_identity")
    if gateway_identity.casefold() == automaton_identity.casefold():
        raise ConfigError("Gateway and Automaton Windows identities must be distinct")
    named_paths = {
        "mt5_terminal_path": terminal_path,
        "audit_path": audit_path,
        "research_db_path": research_path,
        "demo_authorization_path": authorization_path,
        "kill_switch_path": kill_path,
        "automaton_state_dir": automaton_state_dir,
    }
    for name, configured_path in named_paths.items():
        if not configured_path.is_absolute():
            raise ConfigError(f"{name} must be an absolute path")
    operational_paths = (
        audit_path, research_path, authorization_path, kill_path, automaton_state_dir,
    )
    if len({str(Path(os.path.abspath(item))).casefold() for item in operational_paths}) != len(operational_paths):
        raise ConfigError("Audit, research, authorization, and kill-switch paths must be distinct")
    for configured_path in operational_paths:
        try:
            if Path(os.path.abspath(configured_path)).is_relative_to(workspace):
                raise ConfigError("Protected operational paths must remain outside the workspace")
        except OSError as exc:
            raise ConfigError(f"Cannot resolve protected operational path: {exc}") from exc
    if Path(os.path.abspath(audit_path.parent)) != Path(os.path.abspath(research_path.parent)):
        raise ConfigError("Audit and research database must share the protected data directory")
    if Path(os.path.abspath(authorization_path.parent)) != Path(os.path.abspath(kill_path.parent)):
        raise ConfigError("Authorization and kill switch must share the protected control directory")
    if Path(os.path.abspath(audit_path.parent)) == Path(os.path.abspath(authorization_path.parent)):
        raise ConfigError("Writable gateway data and read-only control directories must be distinct")
    gateway_directories = (
        config_path.parent, audit_path.parent, authorization_path.parent,
    )
    if any(_paths_overlap(automaton_state_dir, item) for item in gateway_directories):
        raise ConfigError("Automaton state must be separate from gateway control and data")
    if _paths_overlap(audit_path.parent, authorization_path.parent):
        raise ConfigError("Gateway control and data directory trees must not overlap")

    return SecurityConfig(
        schema_version=1,
        trading_mode=mode,
        authorized_account=account,
        authorized_server=server,
        allowed_symbol=symbol,
        magic_number=magic,
        mt5_terminal_path=terminal_path,
        audit_path=audit_path,
        research_db_path=research_path,
        demo_authorization_path=authorization_path,
        kill_switch_path=kill_path,
        automaton_state_dir=automaton_state_dir,
        gateway_windows_identity=gateway_identity,
        automaton_windows_identity=automaton_identity,
        risk=risk,
    )
