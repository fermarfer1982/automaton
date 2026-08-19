from __future__ import annotations

import sys
from datetime import UTC, datetime
from importlib import metadata
from typing import Any, Protocol
from uuid import uuid4

from .audit import HashChainAuditLog
from .config import GatewayBootstrapConfig, SecurityConfig
from .mt5_access import MT5AccessDisabled
from .research_store import ResearchStore
from .sqlite_audit import DualAuditLog


EXPECTED_MT5_PACKAGE_VERSION = "5.0.6090"


class LatestClosedM1Provider(Protocol):
    """Narrow read contract used only to validate research decisions."""

    def latest_closed_m1(
        self,
        symbol: str,
    ) -> dict[str, Any]:
        ...


def mt5_package_metadata_version() -> str:
    """Inspect distribution metadata without importing the MT5 extension module."""
    try:
        value = metadata.version("MetaTrader5")
    except metadata.PackageNotFoundError as exc:
        raise RuntimeError(
            "Reviewed MetaTrader5 distribution metadata is unavailable"
        ) from exc

    if value != EXPECTED_MT5_PACKAGE_VERSION:
        raise RuntimeError(
            "MetaTrader5 distribution metadata version is not reviewed"
        )

    return value


def mt5_module_imported() -> bool:
    return "MetaTrader5" in sys.modules


class HealthOnlyGatewayApplication:
    """Gateway surface that never owns an MT5 adapter or execution capability."""

    def __init__(
        self,
        *,
        config: GatewayBootstrapConfig | SecurityConfig,
        audit,
        research_store: ResearchStore,
        runtime_identity_verified: bool,
        package_version: str,
        latest_closed_m1_provider: LatestClosedM1Provider | None = None,
    ) -> None:
        if config.mt5_access_enabled:
            raise ValueError(
                "Health-only application requires MT5 access disabled"
            )

        if mt5_module_imported():
            raise RuntimeError(
                "MetaTrader5 was imported before health-only startup"
            )

        configured_symbol = getattr(
            config,
            "allowed_symbol",
            "XAUUSD",
        )

        if configured_symbol != "XAUUSD":
            raise ValueError(
                "Health-only research requires the configured XAUUSD symbol"
            )

        self._mode = config.trading_mode
        self._allowed_symbol = "XAUUSD"
        self._audit = audit
        self._research_store = research_store
        self._runtime_identity_verified = runtime_identity_verified
        self._package_version = package_version
        self._latest_closed_m1_provider = latest_closed_m1_provider

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

    def _require_research_ready(self) -> None:
        if mt5_module_imported():
            raise RuntimeError(
                "MetaTrader5 was imported into the health-only process"
            )

        if not self._runtime_identity_verified:
            raise RuntimeError(
                "Gateway runtime identity is not verified"
            )

        if not self._audit.verify().valid:
            raise RuntimeError(
                "Audit chain is invalid; research service is locked fail-closed"
            )

        if not self._research_store.health():
            raise RuntimeError(
                "Research store is unavailable"
            )

    def record_gateway_started(self) -> None:
        if mt5_module_imported():
            raise RuntimeError(
                "MetaTrader5 was imported during health-only startup"
            )

        self._audit.append(
            "gateway_started",
            {
                "GATEWAY_STARTED": True,
                "TRADING_MODE": self._mode.value,
                "MT5_ACCESS_ENABLED": False,
                "MT5_IMPORTED": False,
                "MT5_ACCESSED": False,
                "ORDER_CHECK": False,
                "ORDER_SEND": False,
            },
        )

    def record_gateway_stopped(self) -> None:
        self._audit.append(
            "gateway_stopped",
            {
                "TRADING_MODE": self._mode.value,
                "MT5_ACCESS_ENABLED": False,
                "MT5_IMPORTED": mt5_module_imported(),
                "MT5_ACCESSED": False,
            },
        )

    def health(self) -> dict[str, Any]:
        response = self._boundary_payload()

        if self._audit.verify().valid:
            self._audit.append(
                "health_checked",
                response,
            )

        return response

    def research_metrics(self) -> dict[str, Any]:
        self._require_research_ready()

        metrics = self._research_store.all_strategy_metrics()

        response = {
            "minimum_evidence_sample": 30,
            "strategies": [
                {
                    "strategy_id": item.strategy_id,
                    "strategy_version": item.strategy_version,
                    "sample_size": item.sample_size,
                    "total_pnl": item.total_pnl,
                    "expectancy_pnl": item.expectancy_pnl,
                    "expectancy_r": item.expectancy_r,
                    "profit_factor": item.profit_factor,
                    "win_rate": item.win_rate,
                    "average_mfe_r": item.average_mfe_r,
                    "average_mae_r": item.average_mae_r,
                    "max_drawdown": item.max_drawdown,
                    "wins": item.wins,
                    "losses": item.losses,
                    "median_duration_seconds": (
                        item.median_duration_seconds
                    ),
                    "expectancy_r_ci95_low": (
                        item.expectancy_r_ci95_low
                    ),
                    "expectancy_r_ci95_high": (
                        item.expectancy_r_ci95_high
                    ),
                    "evidence_sufficient": item.evidence_sufficient,
                }
                for item in metrics
            ],
            "groups": self._research_store.grouped_metrics(),
        }

        self._audit.append(
            "research_metrics_served",
            response,
        )

        return response

    def record_decision(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        self._require_research_ready()

        if self._latest_closed_m1_provider is None:
            raise RuntimeError(
                "Latest closed M1 observation provider is unavailable"
            )

        if (
            payload.get("symbol") != self._allowed_symbol
            or payload.get("timeframe") != "M1"
        ):
            raise ValueError(
                "Decisions must reference the configured XAUUSD M1 stream"
            )

        try:
            parsed = datetime.fromisoformat(
                str(payload["bar_time_utc"]).replace(
                    "Z",
                    "+00:00",
                )
            )
        except (KeyError, ValueError) as exc:
            raise ValueError(
                "Decision bar_time_utc is invalid"
            ) from exc

        if (
            parsed.tzinfo is None
            or parsed.utcoffset() is None
        ):
            raise ValueError(
                "Decision bar_time_utc must be timezone-aware"
            )

        bar_time = parsed.astimezone(UTC)

        latest = (
            self._latest_closed_m1_provider.latest_closed_m1(
                self._allowed_symbol
            )
        )

        if not isinstance(latest, dict):
            raise RuntimeError(
                "Latest closed M1 observation is invalid"
            )

        latest_time_msc = latest.get("time_msc")

        if (
            latest.get("symbol") != self._allowed_symbol
            or latest.get("timeframe") != "M1"
            or isinstance(latest_time_msc, bool)
            or not isinstance(latest_time_msc, int)
            or latest_time_msc <= 0
        ):
            raise RuntimeError(
                "Latest closed M1 observation identity is invalid"
            )

        requested_time_msc = int(
            bar_time.timestamp() * 1000
        )

        if latest_time_msc != requested_time_msc:
            raise ValueError(
                "Decision must reference the latest closed XAUUSD M1 bar"
            )

        canonical_payload = {
            **payload,
            "bar_time_utc": bar_time.isoformat(),
        }

        self._research_store.record_agent_decision(
            **canonical_payload
        )

        self._audit.append(
            "agent_decision_recorded",
            canonical_payload,
        )

        return {
            "recorded": True,
            "decision_id": canonical_payload["decision_id"],
        }

    def save_hypothesis(
        self,
        hypothesis_id: str,
        thesis: str,
    ) -> dict[str, Any]:
        self._require_research_ready()

        self._research_store.save_hypothesis(
            hypothesis_id,
            thesis,
        )

        self._audit.append(
            "hypothesis_saved",
            {
                "hypothesis_id": hypothesis_id,
                "thesis": thesis,
            },
        )

        return {
            "recorded": True,
            "hypothesis_id": hypothesis_id,
        }

    def save_trade_review(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        self._require_research_ready()

        self._research_store.save_trade_review(
            **payload
        )

        proposal_id = (
            self._research_store.proposal_id_for_trade(
                payload["trade_id"]
            )
        )

        if proposal_id is not None:
            self._research_store.append_lifecycle(
                str(uuid4()),
                proposal_id,
                "REVIEWED",
                {
                    "review_id": payload["review_id"],
                },
            )

        self._audit.append(
            "trade_review_saved",
            {
                "review_id": payload["review_id"],
                "trade_id": payload["trade_id"],
            },
        )

        return {
            "recorded": True,
            "review_id": payload["review_id"],
        }

    def recent_memory(
        self,
        limit: int = 50,
    ) -> dict[str, Any]:
        self._require_research_ready()

        items = self._research_store.recent_memory(
            limit
        )

        self._audit.append(
            "trading_memory_served",
            {
                "count": len(items),
            },
        )

        return {
            "count": len(items),
            "items": items,
        }

    @staticmethod
    def _mt5_disabled(
        *_args,
        **_kwargs,
    ):
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


def build_health_only_application(
    config: GatewayBootstrapConfig | SecurityConfig,
    *,
    runtime_identity_verified: bool,
    latest_closed_m1_provider: LatestClosedM1Provider | None = None,
) -> HealthOnlyGatewayApplication:
    if config.mt5_access_enabled:
        raise ValueError(
            "Protected config enables MT5; health-only builder refuses it"
        )

    audit = (
        DualAuditLog(
            config.audit_path,
            config.audit_db_path,
        )
        if config.audit_db_path is not None
        else HashChainAuditLog(
            config.audit_path
        )
    )

    research = ResearchStore(
        config.research_db_path
    )

    return HealthOnlyGatewayApplication(
        config=config,
        audit=audit,
        research_store=research,
        runtime_identity_verified=runtime_identity_verified,
        package_version=mt5_package_metadata_version(),
        latest_closed_m1_provider=latest_closed_m1_provider,
    )