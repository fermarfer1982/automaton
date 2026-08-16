from __future__ import annotations

import sys
from importlib import metadata
from typing import Any

from .audit import HashChainAuditLog
from .config import SecurityConfig
from .mt5_access import MT5AccessDisabled
from .research_store import ResearchStore
from .sqlite_audit import DualAuditLog


EXPECTED_MT5_PACKAGE_VERSION = "5.0.6090"


def mt5_package_metadata_version() -> str:
    """Inspect distribution metadata without importing the MT5 extension module."""
    try:
        value = metadata.version("MetaTrader5")
    except metadata.PackageNotFoundError as exc:
        raise RuntimeError("Reviewed MetaTrader5 distribution metadata is unavailable") from exc
    if value != EXPECTED_MT5_PACKAGE_VERSION:
        raise RuntimeError("MetaTrader5 distribution metadata version is not reviewed")
    return value


def mt5_module_imported() -> bool:
    return "MetaTrader5" in sys.modules


class HealthOnlyGatewayApplication:
    """HTTP liveness surface that has no MT5 adapter or execution dependency."""

    def __init__(
        self,
        *,
        config: SecurityConfig,
        audit,
        research_store: ResearchStore,
        runtime_identity_verified: bool,
        package_version: str,
    ) -> None:
        if config.mt5_access_enabled:
            raise ValueError("Health-only application requires MT5 access disabled")
        if mt5_module_imported():
            raise RuntimeError("MetaTrader5 was imported before health-only startup")
        self._mode = config.trading_mode
        self._audit = audit
        self._research_store = research_store
        self._runtime_identity_verified = runtime_identity_verified
        self._package_version = package_version

    def _boundary_payload(self) -> dict[str, Any]:
        imported = mt5_module_imported()
        return {
            "gateway_status": "FAIL_CLOSED" if imported else "UP",
            "healthy": (
                self._runtime_identity_verified
                and not imported
                and self._audit.verify().valid
                and self._research_store.health()
            ),
            "mode": self._mode.value,
            "trading_mode": self._mode.value,
            "runtime_identity_verified": self._runtime_identity_verified,
            "mt5_access_enabled": False,
            "mt5_status": "IMPORTED_UNEXPECTEDLY" if imported else "DISABLED_NOT_ACCESSED",
            "mt5_package_metadata_version": self._package_version,
            "mt5_imported": imported,
            "mt5_accessed": False,
            "order_check_called": False,
            "order_send_called": False,
            "automaton_started": False,
        }

    def record_gateway_started(self) -> None:
        if mt5_module_imported():
            raise RuntimeError("MetaTrader5 was imported during health-only startup")
        self._audit.append("gateway_started", {
            "GATEWAY_STARTED": True,
            "TRADING_MODE": self._mode.value,
            "MT5_ACCESS_ENABLED": False,
            "MT5_IMPORTED": False,
            "MT5_ACCESSED": False,
            "ORDER_CHECK": False,
            "ORDER_SEND": False,
        })

    def record_gateway_stopped(self) -> None:
        self._audit.append("gateway_stopped", {
            "TRADING_MODE": self._mode.value,
            "MT5_ACCESS_ENABLED": False,
            "MT5_IMPORTED": mt5_module_imported(),
            "MT5_ACCESSED": False,
        })

    def health(self) -> dict[str, Any]:
        response = self._boundary_payload()
        if self._audit.verify().valid:
            self._audit.append("health_checked", response)
        return response

    @staticmethod
    def _mt5_disabled(*_args, **_kwargs):
        raise MT5AccessDisabled()

    status = _mt5_disabled
    account_state = _mt5_disabled
    market_snapshot = _mt5_disabled
    candles = _mt5_disabled
    positions_state = _mt5_disabled
    position_state = _mt5_disabled
    history = _mt5_disabled
    daily_stats = _mt5_disabled
    propose_semantic = _mt5_disabled
    manage_position = _mt5_disabled
    record_decision = _mt5_disabled
    save_hypothesis = _mt5_disabled
    save_trade_review = _mt5_disabled
    research_metrics = _mt5_disabled
    recent_memory = _mt5_disabled


def build_health_only_application(
    config: SecurityConfig,
    *,
    runtime_identity_verified: bool,
) -> HealthOnlyGatewayApplication:
    if config.mt5_access_enabled:
        raise ValueError("Protected config enables MT5; health-only builder refuses it")
    audit = (
        DualAuditLog(config.audit_path, config.audit_db_path)
        if config.audit_db_path is not None
        else HashChainAuditLog(config.audit_path)
    )
    research = ResearchStore(config.research_db_path)
    return HealthOnlyGatewayApplication(
        config=config,
        audit=audit,
        research_store=research,
        runtime_identity_verified=runtime_identity_verified,
        package_version=mt5_package_metadata_version(),
    )
