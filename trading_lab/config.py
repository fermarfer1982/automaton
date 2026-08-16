from __future__ import annotations

import json
import hashlib
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
    max_risk_per_trade_amount: float = 10.0
    max_simultaneous_risk_fraction: float = 0.0025
    max_simultaneous_risk_amount: float = 10.0
    max_daily_loss_amount: float = 30.0
    max_daily_drawdown_fraction: float = 0.01
    max_daily_drawdown_amount: float = 30.0
    cooldown_seconds: int = 300
    max_deviation_points: int = 10


@dataclass(frozen=True)
class GatewayBootstrapConfig:
    """Minimum protected configuration required for local HTTP health startup."""

    schema_version: int
    trading_mode: TradingMode
    audit_path: Path
    research_db_path: Path
    demo_authorization_path: Path
    kill_switch_path: Path
    automaton_state_dir: Path
    gateway_windows_identity: str
    automaton_windows_identity: str
    mt5_access_enabled: bool = False
    audit_db_path: Path | None = None
    api_key_path: Path | None = None
    gateway_lock_path: Path | None = None
    log_dir: Path | None = None
    security_log_dir: Path | None = None


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
    mt5_access_enabled: bool = False
    authorized_account_name: str | None = None
    audit_db_path: Path | None = None
    api_key_path: Path | None = None
    gateway_lock_path: Path | None = None
    log_dir: Path | None = None
    security_log_dir: Path | None = None


def security_config_hash(config: SecurityConfig) -> str:
    """Canonical non-secret binding used by external DEMO authorization."""
    payload = {
        "schema_version": config.schema_version,
        "trading_mode": config.trading_mode.value,
        "mt5_access_enabled": config.mt5_access_enabled,
        "authorized_account": config.authorized_account,
        "authorized_server": config.authorized_server,
        "authorized_account_name": config.authorized_account_name,
        "allowed_symbol": config.allowed_symbol,
        "magic_number": config.magic_number,
        "mt5_terminal_path": str(config.mt5_terminal_path),
        "audit_path": str(config.audit_path),
        "audit_db_path": str(config.audit_db_path),
        "research_db_path": str(config.research_db_path),
        "api_key_path": str(config.api_key_path),
        "gateway_lock_path": str(config.gateway_lock_path),
        "log_dir": str(config.log_dir),
        "security_log_dir": str(config.security_log_dir),
        "demo_authorization_path": str(config.demo_authorization_path),
        "kill_switch_path": str(config.kill_switch_path),
        "automaton_state_dir": str(config.automaton_state_dir),
        "gateway_windows_identity": config.gateway_windows_identity,
        "automaton_windows_identity": config.automaton_windows_identity,
        "risk": {
            name: getattr(config.risk, name)
            for name in config.risk.__dataclass_fields__
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


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
    "schema_version", "trading_mode", "mt5_access_enabled", "authorized_account", "authorized_server",
    "allowed_symbol", "magic_number", "mt5_terminal_path", "audit_path",
    "research_db_path", "demo_authorization_path", "kill_switch_path",
    "automaton_state_dir", "gateway_windows_identity",
    "automaton_windows_identity", "risk",
    "authorized_account_name", "audit_db_path", "api_key_path",
    "gateway_lock_path", "log_dir", "security_log_dir",
}
_RISK_KEYS = {
    "max_risk_per_trade_fraction", "max_volume", "max_spread_points",
    "max_open_positions", "max_symbol_exposure_lots", "max_daily_loss_fraction",
    "min_stop_distance_points", "duplicate_window_seconds", "max_tick_age_seconds",
    "max_risk_per_trade_amount", "max_simultaneous_risk_fraction",
    "max_simultaneous_risk_amount", "max_daily_loss_amount",
    "max_daily_drawdown_fraction", "max_daily_drawdown_amount",
    "cooldown_seconds", "max_deviation_points",
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


def _load_raw_security_config(path: str | Path) -> tuple[dict[str, Any], Path]:
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
        text = config_path.read_text(encoding="utf-8")
        if len(text.encode("utf-8")) > 64 * 1024:
            raise ConfigError("Security config exceeds 64 KiB")
        if config_path.suffix.casefold() in {".yaml", ".yml"}:
            try:
                import yaml
            except ImportError as exc:
                raise ConfigError("PyYAML dependency is required for YAML configuration") from exc
            raw = yaml.safe_load(text)
        elif config_path.suffix.casefold() == ".json":
            raw = json.loads(text)
        else:
            raise ConfigError("Security config must use .yaml, .yml, or legacy .json")
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot load security config: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("Security config root must be an object")
    _reject_credentials(raw)
    unknown = set(raw) - _TOP_LEVEL_KEYS
    if unknown:
        raise ConfigError(f"Unknown security config fields: {', '.join(sorted(unknown))}")
    return raw, workspace


def _build_gateway_bootstrap_config(
    raw: dict[str, Any],
    workspace: Path,
) -> GatewayBootstrapConfig:
    if raw.get("schema_version") != 1:
        raise ConfigError("schema_version must be exactly 1")
    try:
        mode = TradingMode(raw.get("trading_mode", TradingMode.OBSERVE_ONLY.value))
    except ValueError as exc:
        raise ConfigError("trading_mode is invalid") from exc
    mt5_access_enabled = raw.get("mt5_access_enabled", False)
    if not isinstance(mt5_access_enabled, bool):
        raise ConfigError("mt5_access_enabled must be an explicit boolean")

    audit_path = Path(_required_string(raw, "audit_path"))
    research_path = Path(_required_string(raw, "research_db_path"))
    authorization_path = Path(_required_string(raw, "demo_authorization_path"))
    kill_path = Path(_required_string(raw, "kill_switch_path"))
    automaton_state_dir = Path(_required_string(raw, "automaton_state_dir"))
    lab_root = kill_path.parent.parent
    audit_db_path = Path(str(
        raw.get("audit_db_path") or lab_root / "audit" / "sqlite" / "audit.db"
    ))
    api_key_path = Path(str(
        raw.get("api_key_path") or lab_root / "ipc" / "automaton.key"
    ))
    gateway_lock_path = Path(str(
        raw.get("gateway_lock_path") or lab_root / "operational" / "gateway.lock"
    ))
    log_dir = Path(str(raw.get("log_dir") or lab_root / "logs" / "gateway"))
    security_log_dir = Path(str(
        raw.get("security_log_dir") or lab_root / "logs" / "security"
    ))
    gateway_identity = _required_string(raw, "gateway_windows_identity")
    automaton_identity = _required_string(raw, "automaton_windows_identity")
    if any("REPLACE_WITH" in value.upper() or value.upper() == "CHANGE_ME" for value in (
        gateway_identity, automaton_identity,
    )):
        raise ConfigError("Windows identity placeholders must be replaced explicitly")
    if gateway_identity.casefold() == automaton_identity.casefold():
        raise ConfigError("Gateway and Automaton Windows identities must be distinct")
    named_paths = {
        "audit_path": audit_path,
        "research_db_path": research_path,
        "demo_authorization_path": authorization_path,
        "kill_switch_path": kill_path,
        "automaton_state_dir": automaton_state_dir,
        "audit_db_path": audit_db_path,
        "api_key_path": api_key_path,
        "gateway_lock_path": gateway_lock_path,
        "log_dir": log_dir,
        "security_log_dir": security_log_dir,
    }
    for name, configured_path in named_paths.items():
        if not configured_path.is_absolute():
            raise ConfigError(f"{name} must be an absolute path")
    protected_paths = (
        audit_path, research_path, authorization_path, kill_path, automaton_state_dir,
        audit_db_path, api_key_path, gateway_lock_path, log_dir, security_log_dir,
    )
    if len({str(Path(os.path.abspath(item))).casefold() for item in protected_paths}) != len(protected_paths):
        raise ConfigError("Protected control, IPC, data, log, and state paths must be distinct")
    for configured_path in protected_paths:
        try:
            if Path(os.path.abspath(configured_path)).is_relative_to(workspace):
                raise ConfigError("Protected operational paths must remain outside the workspace")
        except OSError as exc:
            raise ConfigError(f"Cannot resolve protected operational path: {exc}") from exc
    normalized_root = Path(os.path.abspath(lab_root))
    expected_paths = {
        "audit_path": normalized_root / "audit" / "journal" / "audit.jsonl",
        "audit_db_path": normalized_root / "audit" / "sqlite" / "audit.db",
        "research_db_path": normalized_root / "research" / "research.db",
        "api_key_path": normalized_root / "ipc" / "automaton.key",
        "gateway_lock_path": normalized_root / "operational" / "gateway.lock",
        "log_dir": normalized_root / "logs" / "gateway",
        "security_log_dir": normalized_root / "logs" / "security",
        "demo_authorization_path": (
            normalized_root / "control" / "demo-authorization" / "authorization.json"
        ),
        "kill_switch_path": normalized_root / "control" / "STOP_TRADING",
    }
    actual_paths = {
        "audit_path": audit_path,
        "audit_db_path": audit_db_path,
        "research_db_path": research_path,
        "api_key_path": api_key_path,
        "gateway_lock_path": gateway_lock_path,
        "log_dir": log_dir,
        "security_log_dir": security_log_dir,
        "demo_authorization_path": authorization_path,
        "kill_switch_path": kill_path,
    }
    for name, expected in expected_paths.items():
        if Path(os.path.abspath(actual_paths[name])) != expected:
            raise ConfigError(f"{name} must use the separated protected domain: {expected}")

    gateway_directories = (normalized_root,)
    if any(_paths_overlap(automaton_state_dir, item) for item in gateway_directories):
        raise ConfigError("Automaton state must be separate from every Gateway domain")

    return GatewayBootstrapConfig(
        schema_version=1,
        trading_mode=mode,
        audit_path=audit_path,
        research_db_path=research_path,
        demo_authorization_path=authorization_path,
        kill_switch_path=kill_path,
        automaton_state_dir=automaton_state_dir,
        gateway_windows_identity=gateway_identity,
        automaton_windows_identity=automaton_identity,
        mt5_access_enabled=mt5_access_enabled,
        audit_db_path=audit_db_path,
        api_key_path=api_key_path,
        gateway_lock_path=gateway_lock_path,
        log_dir=log_dir,
        security_log_dir=security_log_dir,
    )


def load_gateway_bootstrap_config(path: str | Path) -> GatewayBootstrapConfig:
    """Load HTTP/ACL state without resolving any MT5-only material."""
    raw, workspace = _load_raw_security_config(path)
    return _build_gateway_bootstrap_config(raw, workspace)


def _build_risk_limits(raw: dict[str, Any]) -> RiskLimits:
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
        max_risk_per_trade_amount=_positive_number(
            risk_raw.get("max_risk_per_trade_amount", 10.0),
            "risk.max_risk_per_trade_amount",
        ),
        max_simultaneous_risk_fraction=_positive_number(
            risk_raw.get("max_simultaneous_risk_fraction", 0.0025),
            "risk.max_simultaneous_risk_fraction",
        ),
        max_simultaneous_risk_amount=_positive_number(
            risk_raw.get("max_simultaneous_risk_amount", 10.0),
            "risk.max_simultaneous_risk_amount",
        ),
        max_daily_loss_amount=_positive_number(
            risk_raw.get("max_daily_loss_amount", 30.0),
            "risk.max_daily_loss_amount",
        ),
        max_daily_drawdown_fraction=_positive_number(
            risk_raw.get("max_daily_drawdown_fraction", 0.01),
            "risk.max_daily_drawdown_fraction",
        ),
        max_daily_drawdown_amount=_positive_number(
            risk_raw.get("max_daily_drawdown_amount", 30.0),
            "risk.max_daily_drawdown_amount",
        ),
        cooldown_seconds=_positive_int(
            risk_raw.get("cooldown_seconds", 300), "risk.cooldown_seconds"
        ),
        max_deviation_points=_positive_int(
            risk_raw.get("max_deviation_points", 10), "risk.max_deviation_points"
        ),
    )
    if any(
        fraction >= 1
        for fraction in (
            risk.max_risk_per_trade_fraction,
            risk.max_simultaneous_risk_fraction,
            risk.max_daily_loss_fraction,
            risk.max_daily_drawdown_fraction,
        )
    ):
        raise ConfigError("Risk fractions must be less than 1")
    if risk.max_open_positions != 1:
        raise ConfigError("Initial laboratory maximum open positions must be exactly 1")
    return risk


def load_mt5_security_config(path: str | Path) -> SecurityConfig:
    """Load the complete fail-closed MT5 account, symbol, terminal, and risk domain."""
    raw, workspace = _load_raw_security_config(path)
    bootstrap = _build_gateway_bootstrap_config(raw, workspace)

    account = _positive_int(raw.get("authorized_account"), "authorized_account")
    server = _required_string(raw, "authorized_server")
    if server.upper() in {"CHANGE_ME", "REPLACE_WITH_EXACT_DEMO_SERVER"}:
        raise ConfigError("authorized_server placeholder must be replaced explicitly")
    raw_account_name = raw.get("authorized_account_name")
    if raw_account_name is not None and (
        not isinstance(raw_account_name, str) or not raw_account_name.strip()
    ):
        raise ConfigError("authorized_account_name must be null or a non-empty string")
    account_name = raw_account_name.strip() if isinstance(raw_account_name, str) else None
    symbol = _required_string(raw, "allowed_symbol")
    if symbol != "XAUUSD":
        raise ConfigError("Initial laboratory scope permits only exact symbol XAUUSD")
    magic = _positive_int(raw.get("magic_number"), "magic_number")
    terminal_path = Path(_required_string(raw, "mt5_terminal_path"))
    if not terminal_path.is_absolute():
        raise ConfigError("mt5_terminal_path must be an absolute path")
    risk = _build_risk_limits(raw)

    return SecurityConfig(
        schema_version=bootstrap.schema_version,
        trading_mode=bootstrap.trading_mode,
        authorized_account=account,
        authorized_server=server,
        allowed_symbol=symbol,
        magic_number=magic,
        mt5_terminal_path=terminal_path,
        audit_path=bootstrap.audit_path,
        research_db_path=bootstrap.research_db_path,
        demo_authorization_path=bootstrap.demo_authorization_path,
        kill_switch_path=bootstrap.kill_switch_path,
        automaton_state_dir=bootstrap.automaton_state_dir,
        gateway_windows_identity=bootstrap.gateway_windows_identity,
        automaton_windows_identity=bootstrap.automaton_windows_identity,
        risk=risk,
        mt5_access_enabled=bootstrap.mt5_access_enabled,
        authorized_account_name=account_name,
        audit_db_path=bootstrap.audit_db_path,
        api_key_path=bootstrap.api_key_path,
        gateway_lock_path=bootstrap.gateway_lock_path,
        log_dir=bootstrap.log_dir,
        security_log_dir=bootstrap.security_log_dir,
    )


def load_security_config(path: str | Path) -> SecurityConfig:
    """Backward-compatible name for the complete MT5 security loader."""
    return load_mt5_security_config(path)


def resolve_mt5_access_enabled(
    config: GatewayBootstrapConfig | SecurityConfig,
    environment: dict[str, str] | None = None,
) -> bool:
    """Resolve a process restriction without allowing environment escalation."""
    values = os.environ if environment is None else environment
    raw = values.get("MT5_ACCESS_ENABLED")
    if raw is None:
        return config.mt5_access_enabled
    normalized = raw.strip().casefold()
    if normalized == "false":
        return False
    if normalized == "true":
        if not config.mt5_access_enabled:
            raise ConfigError(
                "MT5_ACCESS_ENABLED=true requires mt5_access_enabled: true in protected config"
            )
        return True
    raise ConfigError("MT5_ACCESS_ENABLED must be exactly true or false when set")
