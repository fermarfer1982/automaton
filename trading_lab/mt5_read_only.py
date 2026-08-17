from __future__ import annotations

import importlib
import math
import os
import re
import stat
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

from .audit import HashChainAuditLog
from .config import SecurityConfig, load_mt5_security_config
from .domain import TradingMode
from .health_only import EXPECTED_MT5_PACKAGE_VERSION, mt5_package_metadata_version
from .sqlite_audit import DualAuditLog
from .windows_acl import AclVerification, verify_windows_acl


MODE = "MT5_READ_ONLY_PREFLIGHT"
SCHEMA_VERSION = 1
EXACT_SYMBOL = "XAUUSD"
ALLOWED_MT5_CAPABILITIES = frozenset({
    "initialize",
    "version",
    "terminal_info",
    "account_info",
    "symbol_info",
    "symbol_info_tick",
    "shutdown",
    "last_error",
})
PROHIBITED_MT5_CAPABILITIES = frozenset({
    "login",
    "symbol_select",
    "market_book_add",
    "market_book_release",
    "copy_ticks_from",
    "order_check",
    "order_send",
})


class MT5ReadOnlyPreflightFailure(RuntimeError):
    def __init__(self, code: str, stage: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage


class MT5ReadOnlyCapabilityViolation(MT5ReadOnlyPreflightFailure):
    def __init__(self, capability: str) -> None:
        super().__init__(
            "MT5_READ_ONLY_UNEXPECTED_CAPABILITY",
            "CAPABILITY_BOUNDARY",
            f"MT5 read-only capability boundary rejected {capability!r}.",
        )


@dataclass(frozen=True, slots=True)
class MT5ReadOnlyBindings:
    initialize: Callable[..., object]
    version: Callable[[], object]
    terminal_info: Callable[[], object]
    account_info: Callable[[], object]
    symbol_info: Callable[[str], object]
    symbol_info_tick: Callable[[str], object]
    shutdown: Callable[[], object]
    last_error: Callable[[], object]
    account_trade_mode_demo: int


class _CapabilityLedger:
    __slots__ = ("_counts", "_unexpected")

    def __init__(self) -> None:
        self._counts = {name: 0 for name in ALLOWED_MT5_CAPABILITIES}
        self._unexpected: dict[str, int] = {}

    def invoke(self, capability: str, operation: Callable[..., object], *args, **kwargs):
        if capability not in ALLOWED_MT5_CAPABILITIES:
            self._unexpected[capability] = self._unexpected.get(capability, 0) + 1
            raise MT5ReadOnlyCapabilityViolation(capability)
        self._counts[capability] += 1
        return operation(*args, **kwargs)

    def evidence(self) -> dict[str, object]:
        return {
            "allowed": dict(self._counts),
            "unexpected": dict(self._unexpected),
        }


class MT5ReadOnlyAdapter:
    """Capability-minimal MT5 facade for the one-shot diagnostic preflight.

    The adapter stores eight explicit callables, not the MetaTrader5 module.  It
    deliberately has no dynamic dispatch and no account, symbol-selection, or
    execution member.
    """

    __slots__ = ("_bindings", "_ledger")

    def __init__(self, bindings: MT5ReadOnlyBindings) -> None:
        self._bindings = bindings
        self._ledger = _CapabilityLedger()

    @property
    def demo_trade_mode(self) -> int:
        return self._bindings.account_trade_mode_demo

    @property
    def allowed_capabilities(self) -> frozenset[str]:
        return ALLOWED_MT5_CAPABILITIES

    def initialize(self, terminal_path: Path) -> bool:
        return bool(self._ledger.invoke(
            "initialize",
            self._bindings.initialize,
            path=str(terminal_path),
        ))

    def version(self) -> object:
        return self._ledger.invoke("version", self._bindings.version)

    def terminal_info(self) -> object:
        return self._ledger.invoke("terminal_info", self._bindings.terminal_info)

    def account_info(self) -> object:
        return self._ledger.invoke("account_info", self._bindings.account_info)

    def symbol_info(self, symbol: str) -> object:
        return self._ledger.invoke("symbol_info", self._bindings.symbol_info, symbol)

    def symbol_info_tick(self, symbol: str) -> object:
        return self._ledger.invoke(
            "symbol_info_tick", self._bindings.symbol_info_tick, symbol
        )

    def shutdown(self) -> None:
        self._ledger.invoke("shutdown", self._bindings.shutdown)

    def last_error(self) -> object:
        return self._ledger.invoke("last_error", self._bindings.last_error)

    def capability_evidence(self) -> dict[str, object]:
        return self._ledger.evidence()

    def assert_read_only_boundary(self) -> None:
        evidence = self._ledger.evidence()
        if evidence["unexpected"]:
            raise MT5ReadOnlyCapabilityViolation("unexpected")
        if frozenset(evidence["allowed"]) != ALLOWED_MT5_CAPABILITIES:
            raise MT5ReadOnlyCapabilityViolation("adapter_surface")


def _bindings_from_module(module: ModuleType | Any) -> MT5ReadOnlyBindings:
    """Copy only reviewed callables/constants; never retain the full module."""
    return MT5ReadOnlyBindings(
        initialize=module.initialize,
        version=module.version,
        terminal_info=module.terminal_info,
        account_info=module.account_info,
        symbol_info=module.symbol_info,
        symbol_info_tick=module.symbol_info_tick,
        shutdown=module.shutdown,
        last_error=module.last_error,
        account_trade_mode_demo=int(module.ACCOUNT_TRADE_MODE_DEMO),
    )


def load_mt5_read_only_adapter() -> MT5ReadOnlyAdapter:
    """Production-only lazy import boundary used by the dedicated entry point."""
    try:
        module = importlib.import_module("MetaTrader5")
        bindings = _bindings_from_module(module)
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        raise MT5ReadOnlyPreflightFailure(
            "MT5_READ_ONLY_IMPORT_FAILED",
            "MT5_IMPORT",
            "Reviewed MetaTrader5 read-only capabilities are unavailable.",
        ) from exc
    return MT5ReadOnlyAdapter(bindings)


def _build_audit(config: SecurityConfig):
    if config.audit_db_path is not None:
        return DualAuditLog(config.audit_path, config.audit_db_path)
    return HashChainAuditLog(config.audit_path)


def _new_report(run_id: str) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "run_id": run_id,
        "effective_sid": None,
        "status": "FAIL_INITIALIZING",
        "failure_code": None,
        "failure_stage": "INITIALIZING",
        "runtime_error": None,
        "python_executable": sys.executable,
        "trading_mode": None,
        "mt5_package_version": None,
        "mt5_terminal_version": None,
        "mt5_imported": False,
        "mt5_initialize_called": False,
        "mt5_initialize_result": False,
        "mt5_accessed": False,
        "mt5_shutdown_called": False,
        "terminal_connected": False,
        "terminal_trade_allowed": False,
        "terminal_path_match": False,
        "account_info_read": False,
        "account_login_match": False,
        "account_server_match": False,
        "account_name_match": None,
        "account_trade_mode": None,
        "account_demo_verified": False,
        "symbol": EXACT_SYMBOL,
        "symbol_info_read": False,
        "symbol_exists": False,
        "symbol_digits": None,
        "symbol_trade_tick_size": None,
        "symbol_trade_mode": None,
        "tick_read": False,
        "tick_time": None,
        "bid": None,
        "ask": None,
        "spread": None,
        "kill_switch_present": False,
        "audit_chain_valid": False,
        "audit_events_recorded": [],
        "unexpected_capability_called": False,
        "order_check_called": False,
        "order_send_called": False,
        "login_called": False,
        "symbol_select_called": False,
        "market_book_add_called": False,
        "market_book_release_called": False,
        "copy_ticks_from_called": False,
        "automaton_started": False,
        "gateway_started": False,
        "acl_verified": False,
        "acl_modified": False,
        "filesystem_runtime_modified": False,
        "process_stopped_cleanly": False,
        "orphan_processes": 0,
    }


_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|api[_ -]?key|ipc[_ -]?key|credential|credentials|"
    r"login|account|server|token|secret)\b\s*[:=]\s*[^\s,;]+"
)


def _sanitize_runtime_error(
    error: BaseException, sensitive_values: tuple[str, ...] = ()
) -> str:
    message = str(error).replace("\r", " ").replace("\n", " ").replace("\t", " ")
    for value in sensitive_values:
        if value:
            message = message.replace(value, "[REDACTED]")
    message = _SENSITIVE_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", message)
    message = " ".join(message.split()).strip() or type(error).__name__
    return message[:512]


def _fail(code: str, stage: str, message: str) -> None:
    raise MT5ReadOnlyPreflightFailure(code, stage, message)


def _canonical_windows_path(path: Path | str) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path))).rstrip("\\/")


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.lstat().st_file_attributes
    except AttributeError:
        return path.is_symlink()
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _validate_terminal_executable(path: Path) -> None:
    if not path.is_absolute() or not path.is_file() or _is_reparse_point(path):
        _fail(
            "MT5_READ_ONLY_TERMINAL_PATH_INVALID",
            "TERMINAL_PATH_PREFLIGHT",
            "Configured MT5 terminal executable is absent or unsafe.",
        )
    current = path.parent
    while current != current.parent:
        if _is_reparse_point(current):
            _fail(
                "MT5_READ_ONLY_TERMINAL_PATH_REPARSE",
                "TERMINAL_PATH_PREFLIGHT",
                "Configured MT5 terminal path traverses a reparse point.",
            )
        current = current.parent


def _terminal_path_matches(reported: object, configured_executable: Path) -> bool:
    if not isinstance(reported, str) or not reported.strip():
        return False
    return _canonical_windows_path(reported) == _canonical_windows_path(
        configured_executable.parent
    )


def _safe_terminal_version(value: object) -> list[object]:
    if not isinstance(value, (tuple, list)) or len(value) != 3:
        _fail(
            "MT5_READ_ONLY_VERSION_INVALID",
            "MT5_VERSION",
            "MT5 terminal version payload is invalid.",
        )
    result: list[object] = []
    for item in value:
        if not isinstance(item, (str, int)):
            _fail(
                "MT5_READ_ONLY_VERSION_INVALID",
                "MT5_VERSION",
                "MT5 terminal version payload is invalid.",
            )
        result.append(item)
    return result


def _update_capability_evidence(
    report: dict[str, object], adapter: MT5ReadOnlyAdapter | None
) -> None:
    if adapter is None:
        return
    evidence = adapter.capability_evidence()
    unexpected = evidence.get("unexpected", {})
    if not isinstance(unexpected, Mapping):
        report["unexpected_capability_called"] = True
        return
    report["unexpected_capability_called"] = bool(unexpected)
    for name in PROHIBITED_MT5_CAPABILITIES:
        report[f"{name}_called"] = bool(unexpected.get(name, 0))


def _audit_append(audit, event: str, payload: dict[str, object]) -> None:
    audit.append(event, payload)
    verification = audit.verify()
    if not verification.valid:
        _fail(
            "MT5_READ_ONLY_AUDIT_FAILED",
            "AUDIT",
            "Audit stores failed integrity verification.",
        )


def execute_mt5_read_only_preflight(
    config_path: str | Path,
    run_id: str,
    *,
    config_loader: Callable[[str | Path], SecurityConfig] = load_mt5_security_config,
    acl_verifier: Callable[..., AclVerification] = verify_windows_acl,
    adapter_loader: Callable[[], MT5ReadOnlyAdapter] = load_mt5_read_only_adapter,
    package_version_provider: Callable[[], str] = mt5_package_metadata_version,
    audit_factory: Callable[[SecurityConfig], object] = _build_audit,
) -> dict[str, object]:
    """Run one deterministic MT5 identity/market-data diagnostic and stop."""
    report = _new_report(run_id)
    config: SecurityConfig | None = None
    audit = None
    adapter: MT5ReadOnlyAdapter | None = None
    started_audit = False
    initialized_attempted = False
    primary_error: BaseException | None = None
    stage = "CONFIG"
    recorded_events: list[str] = []

    def sanitized(error: BaseException) -> str:
        sensitive_values: tuple[str, ...] = ()
        if config is not None:
            sensitive_values = (
                str(config.authorized_account),
                config.authorized_server,
                config.authorized_account_name or "",
            )
        return _sanitize_runtime_error(error, sensitive_values)

    try:
        if "MetaTrader5" in sys.modules:
            _fail(
                "MT5_READ_ONLY_PREIMPORTED",
                "CONFIG",
                "MetaTrader5 was imported before the dedicated preflight boundary.",
            )
        config = config_loader(config_path)
        report["trading_mode"] = config.trading_mode.value
        if config.trading_mode is not TradingMode.OBSERVE_ONLY:
            _fail(
                "MT5_READ_ONLY_OBSERVE_ONLY_REQUIRED",
                "CONFIG",
                "MT5 read-only preflight requires OBSERVE_ONLY.",
            )
        if config.allowed_symbol != EXACT_SYMBOL:
            _fail(
                "MT5_READ_ONLY_SYMBOL_CONFIG_INVALID",
                "CONFIG",
                "MT5 read-only preflight permits only exact XAUUSD.",
            )
        _validate_terminal_executable(config.mt5_terminal_path)
        report["kill_switch_present"] = config.kill_switch_path.exists()

        stage = "ACL"
        acl = acl_verifier(
            config_path,
            config,
            include_automaton_state=False,
            require_current_gateway=True,
        )
        if not acl.passed or not acl.current_sid:
            _fail(
                "MT5_READ_ONLY_ACL_FAILED",
                "ACL",
                "Gateway ACL or runtime identity verification failed closed.",
            )
        report["effective_sid"] = acl.current_sid
        report["acl_verified"] = True

        stage = "AUDIT_START"
        audit = audit_factory(config)
        if not audit.verify().valid:
            _fail(
                "MT5_READ_ONLY_AUDIT_FAILED",
                "AUDIT_START",
                "Audit stores failed integrity verification before preflight.",
            )
        _audit_append(audit, "mt5_read_only_preflight_started", {
            "run_id": run_id,
            "mode": MODE,
            "trading_mode": TradingMode.OBSERVE_ONLY.value,
            "kill_switch_present": report["kill_switch_present"],
            "read_only": True,
        })
        recorded_events.append("mt5_read_only_preflight_started")
        started_audit = True

        stage = "MT5_PACKAGE"
        package_version = package_version_provider()
        if package_version != EXPECTED_MT5_PACKAGE_VERSION:
            _fail(
                "MT5_READ_ONLY_PACKAGE_VERSION_FAILED",
                "MT5_PACKAGE",
                "MetaTrader5 package version is not the reviewed version.",
            )
        report["mt5_package_version"] = package_version

        stage = "MT5_IMPORT"
        adapter = adapter_loader()
        if adapter.allowed_capabilities != ALLOWED_MT5_CAPABILITIES:
            _fail(
                "MT5_READ_ONLY_ADAPTER_SURFACE_INVALID",
                "CAPABILITY_BOUNDARY",
                "MT5 read-only adapter capability surface is invalid.",
            )
        adapter.assert_read_only_boundary()
        report["mt5_imported"] = True

        stage = "MT5_INITIALIZE"
        report["mt5_initialize_called"] = True
        report["mt5_accessed"] = True
        initialized_attempted = True
        initialized = adapter.initialize(config.mt5_terminal_path)
        report["mt5_initialize_result"] = initialized
        if not initialized:
            try:
                adapter.last_error()
            except BaseException:
                pass
            _fail(
                "MT5_READ_ONLY_INITIALIZE_FAILED",
                "MT5_INITIALIZE",
                "MetaTrader5 initialize returned false.",
            )

        stage = "MT5_VERSION"
        report["mt5_terminal_version"] = _safe_terminal_version(adapter.version())

        stage = "TERMINAL_INFO"
        terminal = adapter.terminal_info()
        if terminal is None:
            _fail(
                "MT5_READ_ONLY_TERMINAL_INFO_MISSING",
                "TERMINAL_INFO",
                "MetaTrader5 terminal information is unavailable.",
            )
        report["terminal_connected"] = bool(terminal.connected)
        report["terminal_trade_allowed"] = bool(terminal.trade_allowed)
        report["terminal_path_match"] = _terminal_path_matches(
            terminal.path, config.mt5_terminal_path
        )
        if not report["terminal_connected"]:
            _fail(
                "MT5_READ_ONLY_TERMINAL_DISCONNECTED",
                "TERMINAL_INFO",
                "MetaTrader5 terminal is not connected.",
            )
        if not report["terminal_path_match"]:
            _fail(
                "MT5_READ_ONLY_TERMINAL_PATH_MISMATCH",
                "TERMINAL_INFO",
                "Connected MetaTrader5 terminal path is not authorized.",
            )

        stage = "ACCOUNT_INFO"
        account = adapter.account_info()
        if account is None:
            _fail(
                "MT5_READ_ONLY_ACCOUNT_INFO_MISSING",
                "ACCOUNT_INFO",
                "MetaTrader5 account information is unavailable.",
            )
        report["account_info_read"] = True
        report["account_login_match"] = int(account.login) == config.authorized_account
        report["account_server_match"] = str(account.server) == config.authorized_server
        report["account_trade_mode"] = int(account.trade_mode)
        report["account_demo_verified"] = (
            int(account.trade_mode) == adapter.demo_trade_mode
        )
        report["account_name_match"] = (
            None
            if config.authorized_account_name is None
            else str(account.name) == config.authorized_account_name
        )
        if not report["account_login_match"]:
            _fail(
                "MT5_READ_ONLY_ACCOUNT_MISMATCH",
                "ACCOUNT_INFO",
                "Connected MetaTrader5 account is not authorized.",
            )
        if not report["account_server_match"]:
            _fail(
                "MT5_READ_ONLY_SERVER_MISMATCH",
                "ACCOUNT_INFO",
                "Connected MetaTrader5 server is not authorized.",
            )
        if not report["account_demo_verified"]:
            _fail(
                "MT5_READ_ONLY_NOT_DEMO",
                "ACCOUNT_INFO",
                "Connected MetaTrader5 account is not DEMO.",
            )
        if report["account_name_match"] is False:
            _fail(
                "MT5_READ_ONLY_ACCOUNT_NAME_MISMATCH",
                "ACCOUNT_INFO",
                "Connected MetaTrader5 account name is not authorized.",
            )

        stage = "SYMBOL_INFO"
        symbol = adapter.symbol_info(EXACT_SYMBOL)
        if symbol is None:
            _fail(
                "MT5_READ_ONLY_SYMBOL_MISSING",
                "SYMBOL_INFO",
                "Exact XAUUSD symbol information is unavailable.",
            )
        report["symbol_info_read"] = True
        report["symbol_exists"] = str(symbol.name) == EXACT_SYMBOL
        report["symbol_digits"] = int(symbol.digits)
        report["symbol_trade_tick_size"] = float(symbol.trade_tick_size)
        report["symbol_trade_mode"] = int(symbol.trade_mode)
        if not report["symbol_exists"]:
            _fail(
                "MT5_READ_ONLY_SYMBOL_MISMATCH",
                "SYMBOL_INFO",
                "Broker returned a symbol other than exact XAUUSD.",
            )
        if (
            int(report["symbol_digits"]) < 0
            or not math.isfinite(float(report["symbol_trade_tick_size"]))
            or float(report["symbol_trade_tick_size"]) <= 0
        ):
            _fail(
                "MT5_READ_ONLY_SYMBOL_DATA_INVALID",
                "SYMBOL_INFO",
                "XAUUSD static symbol data is invalid.",
            )

        stage = "TICK"
        tick = adapter.symbol_info_tick(EXACT_SYMBOL)
        if tick is None:
            _fail(
                "MT5_READ_ONLY_TICK_MISSING",
                "TICK",
                "Exact XAUUSD tick is unavailable.",
            )
        bid = float(tick.bid)
        ask = float(tick.ask)
        tick_time = int(tick.time)
        if (
            not math.isfinite(bid)
            or not math.isfinite(ask)
            or bid <= 0
            or ask < bid
            or tick_time <= 0
        ):
            _fail(
                "MT5_READ_ONLY_TICK_INVALID",
                "TICK",
                "Exact XAUUSD tick data is invalid.",
            )
        report["tick_read"] = True
        report["tick_time"] = tick_time
        report["bid"] = bid
        report["ask"] = ask
        report["spread"] = ask - bid

        stage = "AUDIT_IDENTITY"
        adapter.assert_read_only_boundary()
        _audit_append(audit, "mt5_identity_verified", {
            "run_id": run_id,
            "mode": MODE,
            "trading_mode": TradingMode.OBSERVE_ONLY.value,
            "account_login_match": True,
            "account_server_match": True,
            "account_demo_verified": True,
            "terminal_path_match": True,
            "symbol": EXACT_SYMBOL,
            "symbol_exists": True,
            "tick_read": True,
            "read_only": True,
        })
        recorded_events.append("mt5_identity_verified")
        report["status"] = "PASS_PENDING_SHUTDOWN"
    except BaseException as exc:
        primary_error = exc
        report["mt5_imported"] = bool(
            report["mt5_imported"] or "MetaTrader5" in sys.modules
        )
        if isinstance(exc, MT5ReadOnlyPreflightFailure):
            report["failure_code"] = exc.code
            report["failure_stage"] = exc.stage
        else:
            report["failure_code"] = f"MT5_READ_ONLY_{stage}_FAILED"
            report["failure_stage"] = stage
        report["runtime_error"] = sanitized(exc)
    finally:
        shutdown_error: BaseException | None = None
        if adapter is not None and initialized_attempted:
            report["mt5_shutdown_called"] = True
            try:
                adapter.shutdown()
                report["process_stopped_cleanly"] = True
            except BaseException as exc:
                shutdown_error = exc
                report["process_stopped_cleanly"] = False

        _update_capability_evidence(report, adapter)
        if adapter is not None:
            try:
                adapter.assert_read_only_boundary()
            except BaseException as exc:
                if primary_error is None:
                    primary_error = exc
                    report["failure_code"] = "MT5_READ_ONLY_UNEXPECTED_CAPABILITY"
                    report["failure_stage"] = "CAPABILITY_BOUNDARY"
                    report["runtime_error"] = sanitized(exc)

        if shutdown_error is not None and primary_error is None:
            primary_error = shutdown_error
            report["failure_code"] = "MT5_READ_ONLY_SHUTDOWN_FAILED"
            report["failure_stage"] = "MT5_SHUTDOWN"
            report["runtime_error"] = sanitized(shutdown_error)

        if audit is not None and started_audit:
            try:
                _audit_append(audit, "mt5_read_only_preflight_stopped", {
                    "run_id": run_id,
                    "mode": MODE,
                    "status": "PASS" if primary_error is None else "FAIL",
                    "trading_mode": TradingMode.OBSERVE_ONLY.value,
                    "mt5_initialize_called": report["mt5_initialize_called"],
                    "mt5_shutdown_called": report["mt5_shutdown_called"],
                    "unexpected_capability_called": report[
                        "unexpected_capability_called"
                    ],
                    "read_only": True,
                })
                recorded_events.append("mt5_read_only_preflight_stopped")
                report["audit_chain_valid"] = audit.verify().valid
            except BaseException as exc:
                report["audit_chain_valid"] = False
                if primary_error is None:
                    primary_error = exc
                    report["failure_code"] = "MT5_READ_ONLY_AUDIT_STOP_FAILED"
                    report["failure_stage"] = "AUDIT_STOP"
                    report["runtime_error"] = sanitized(exc)

        report["audit_events_recorded"] = recorded_events
        if (
            primary_error is None
            and report["status"] == "PASS_PENDING_SHUTDOWN"
            and report["mt5_shutdown_called"]
            and report["process_stopped_cleanly"]
            and report["audit_chain_valid"]
            and not report["unexpected_capability_called"]
            and not any(report[f"{name}_called"] for name in PROHIBITED_MT5_CAPABILITIES)
        ):
            report["status"] = "PASS"
            report["failure_code"] = None
            report["failure_stage"] = None
            report["runtime_error"] = None
        else:
            report["status"] = "FAIL"
            if report["failure_code"] is None:
                report["failure_code"] = "MT5_READ_ONLY_BOUNDARY_FAILED"
                report["failure_stage"] = "BOUNDARY_VALIDATION"
                report["runtime_error"] = "Read-only preflight boundary validation failed."

    return report
