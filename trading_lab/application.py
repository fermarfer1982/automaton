from __future__ import annotations

import time
from typing import Any

from .account_guard import AccountGuard
from .audit import HashChainAuditLog
from .domain import TradingMode, TradeProposal


class GatewayApplication:
    """Small application API shared by HTTP transport and readiness checks."""

    def __init__(
        self,
        *,
        mode: TradingMode,
        allowed_symbol: str,
        adapter,
        account_guard: AccountGuard,
        gateway,
        audit: HashChainAuditLog,
        research_store=None,
        paper_engine=None,
        runtime_identity_verified: bool = False,
    ) -> None:
        self._mode = mode
        self._allowed_symbol = allowed_symbol
        self._adapter = adapter
        self._account_guard = account_guard
        self._gateway = gateway
        self._audit = audit
        self._research_store = research_store
        self._paper_engine = paper_engine
        self._runtime_identity_verified = runtime_identity_verified

    def health(self) -> dict[str, Any]:
        account = self._adapter.account_snapshot()
        account_decision = self._account_guard.evaluate(account)
        market = self._adapter.symbol_snapshot(self._allowed_symbol)
        positions = self._adapter.positions()
        active_orders = self._adapter.active_orders()
        audit_verification = self._audit.verify()
        tick_fresh = -2_000 <= int(time.time() * 1000) - market.tick_time_msc <= 5_000
        exposure_clear = len(positions) == 0 and len(active_orders) == 0
        research_available = bool(self._research_store and self._research_store.health())
        healthy = (
            self._runtime_identity_verified
            and
            account_decision.allowed
            and market.visible
            and market.symbol == self._allowed_symbol
            and market.bid > 0
            and market.ask >= market.bid
            and tick_fresh
            and exposure_clear
            and research_available
            and audit_verification.valid
        )
        response = {
            "healthy": healthy,
            "mode": self._mode.value,
            "allowed_symbol": self._allowed_symbol,
            "runtime_identity_verified": self._runtime_identity_verified,
            "account_guard": {
                "allowed": account_decision.allowed,
                "failed_codes": account_decision.failed_codes,
            },
            "market_data": {
                "available": market.visible and market.bid > 0 and market.ask >= market.bid and tick_fresh,
                "symbol": market.symbol,
            },
            "exposure": {
                "clear": exposure_clear,
                "position_count": len(positions),
                "active_order_count": len(active_orders),
            },
            "audit": {
                "valid": audit_verification.valid,
                "records": audit_verification.records,
            },
            "research_store": {
                "available": research_available,
            },
        }
        if audit_verification.valid:
            self._audit.append("health_checked", response)
        return response

    def market_snapshot(self, symbol: str) -> dict[str, Any]:
        if symbol != self._allowed_symbol:
            raise ValueError("Only the configured XAUUSD symbol is permitted")
        if not self._audit.verify().valid:
            raise RuntimeError("Audit chain is invalid; market service is locked fail-closed")
        account_decision = self._account_guard.evaluate(self._adapter.account_snapshot())
        if not account_decision.allowed:
            self._audit.append(
                "market_snapshot_rejected",
                {"symbol": symbol, "failed_codes": account_decision.failed_codes},
            )
            raise RuntimeError("Account guard rejected market observation")
        market = self._adapter.symbol_snapshot(symbol)
        if not market.visible or market.bid <= 0 or market.ask < market.bid or market.point <= 0:
            raise RuntimeError("Market data is invalid")
        if self._mode is TradingMode.PAPER:
            if self._paper_engine is None:
                raise RuntimeError("PAPER mode requires a persistent paper engine")
            self._paper_engine.reconcile(market)
        response = {
            "symbol": market.symbol,
            "bid": market.bid,
            "ask": market.ask,
            "spread_points": (market.ask - market.bid) / market.point,
            "point": market.point,
            "trade_stops_level": market.trade_stops_level,
            "volume_min": market.volume_min,
            "volume_max": market.volume_max,
            "volume_step": market.volume_step,
            "tick_time_msc": market.tick_time_msc,
        }
        self._audit.append("market_snapshot_served", response)
        return response

    def submit(self, proposal: TradeProposal):
        if self._gateway is None:
            raise RuntimeError("Proposal gateway is unavailable")
        return self._gateway.submit(proposal)

    def research_metrics(self) -> dict[str, Any]:
        if not self._audit.verify().valid:
            raise RuntimeError("Audit chain is invalid; research service is locked fail-closed")
        if self._research_store is None or not self._research_store.health():
            raise RuntimeError("Research store is unavailable")
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
                    "evidence_sufficient": item.evidence_sufficient,
                }
                for item in metrics
            ],
        }
        self._audit.append("research_metrics_served", response)
        return response
