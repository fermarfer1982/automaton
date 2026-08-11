from __future__ import annotations

import time
import hashlib
import json
import math
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from .account_guard import AccountGuard
from .audit import HashChainAuditLog
from .domain import OpenAction, SemanticTradeRequest, Side, TradingMode, TradeProposal
from .market_analysis import asian_session_range, session_context, summarize_candles, utc_day_range


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
        magic_number: int = 0,
        position_sizer=None,
        risk_limits=None,
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
        self._magic_number = magic_number
        self._position_sizer = position_sizer
        self._risk_limits = risk_limits

    def health(self) -> dict[str, Any]:
        account = self._adapter.account_snapshot()
        account_decision = self._account_guard.evaluate(account)
        market = self._adapter.symbol_snapshot(self._allowed_symbol)
        positions = self._adapter.positions()
        if self._mode is TradingMode.PAPER and self._paper_engine is not None:
            positions = positions + self._paper_engine.position_snapshots()
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
        now = datetime.now(UTC)
        timeframe_data: dict[str, dict[str, object]] = {}
        range_candles = []
        if hasattr(self._adapter, "candles"):
            for timeframe in ("M1", "M5", "M15", "H1"):
                candles = self._adapter.candles(
                    symbol, timeframe, 500 if timeframe == "M5" else 100
                )
                timeframe_data[timeframe.lower()] = summarize_candles(candles)
                if timeframe == "M5":
                    range_candles = candles
        response = {
            "symbol": market.symbol,
            "timestamp_utc": now.isoformat(),
            "bid": market.bid,
            "ask": market.ask,
            "spread_points": (market.ask - market.bid) / market.point,
            "point": market.point,
            "trade_stops_level": market.trade_stops_level,
            "trade_freeze_level": market.trade_freeze_level,
            "trade_mode": market.trade_mode,
            "volume_min": market.volume_min,
            "volume_max": market.volume_max,
            "volume_step": market.volume_step,
            "tick_time_msc": market.tick_time_msc,
            "market_open": market.market_open,
            "session": session_context(now),
            "timeframes": timeframe_data,
            "day_range": utc_day_range(range_candles, now),
            "asia_range": asian_session_range(range_candles, now),
            "positions": self.positions_state(audit_event=False)["positions"],
            "daily": self.daily_stats(audit_event=False),
        }
        self._audit.append("market_snapshot_served", response)
        return response

    def _guarded_account(self):
        verification = self._audit.verify()
        if not verification.valid:
            raise RuntimeError("Audit is invalid; account data is locked fail-closed")
        account = self._adapter.account_snapshot()
        decision = self._account_guard.evaluate(account)
        if not decision.allowed:
            self._audit.append("account_read_rejected", {"failed_codes": decision.failed_codes})
            raise RuntimeError("Account guard rejected the current MT5 account")
        return account, decision

    def account_state(self) -> dict[str, Any]:
        account, decision = self._guarded_account()
        daily = self.daily_stats(audit_event=False)
        risk_headroom = None
        if self._risk_limits is not None:
            per_trade = min(
                account.equity * self._risk_limits.max_risk_per_trade_fraction,
                self._risk_limits.max_risk_per_trade_amount,
            )
            simultaneous = min(
                account.equity * self._risk_limits.max_simultaneous_risk_fraction,
                self._risk_limits.max_simultaneous_risk_amount,
            )
            daily_loss = min(
                account.balance * self._risk_limits.max_daily_loss_fraction,
                self._risk_limits.max_daily_loss_amount,
            )
            daily_drawdown = min(
                float(daily["start_equity"]) * self._risk_limits.max_daily_drawdown_fraction,
                self._risk_limits.max_daily_drawdown_amount,
            )
            risk_headroom = {
                "per_trade": per_trade,
                "simultaneous": simultaneous,
                "daily_loss_remaining": max(0.0, daily_loss + min(0.0, float(daily["realized_pnl"]))),
                "daily_drawdown_remaining": max(0.0, daily_drawdown - float(daily["drawdown"])),
            }
        response = {
            "connected": account.connected,
            "demo_verified": account.kind.value == "DEMO",
            "account_allowed": decision.allowed,
            "server_allowed": "ACCOUNT_SERVER_MISMATCH" not in decision.failed_codes,
            "trade_allowed": account.trade_allowed and account.terminal_trade_allowed,
            "currency": account.currency,
            "balance": account.balance,
            "equity": account.equity,
            "risk_headroom": risk_headroom,
        }
        self._audit.append("account_state_served", response)
        return response

    def candles(self, symbol: str, timeframe: str, count: int) -> dict[str, Any]:
        if symbol != self._allowed_symbol:
            raise ValueError("Only the configured XAUUSD symbol is permitted")
        self._guarded_account()
        items = self._adapter.candles(symbol, timeframe, count)
        response = {
            "symbol": symbol,
            "timeframe": timeframe,
            "closed_only": True,
            "count": len(items),
            "candles": [asdict(item) for item in items],
        }
        self._audit.append(
            "candles_served", {"symbol": symbol, "timeframe": timeframe, "count": len(items)}
        )
        return response

    def positions_state(self, *, audit_event: bool = True) -> dict[str, Any]:
        self._guarded_account()
        positions = self._adapter.positions()
        paper_tickets: set[int] = set()
        if self._mode is TradingMode.PAPER and self._paper_engine is not None:
            paper_positions = self._paper_engine.position_snapshots()
            paper_tickets = {item.ticket for item in paper_positions}
            positions = positions + paper_positions
        response = {
            "count": len(positions),
            "positions": [
                {
                    "ticket": item.ticket,
                    "symbol": item.symbol,
                    "side": item.side.value,
                    "volume": item.volume,
                    "price_open": item.price_open,
                    "stop_loss": item.stop_loss,
                    "profit": item.profit,
                    "owned_by_lab": item.symbol == self._allowed_symbol and (
                        item.ticket in paper_tickets
                        or item.magic_number == self._magic_number
                    ),
                }
                for item in positions
            ],
        }
        if audit_event:
            self._audit.append("positions_served", {"count": len(positions)})
        return response

    def position_state(self, ticket: int) -> dict[str, Any]:
        positions = self.positions_state(audit_event=False)["positions"]
        selected = next((item for item in positions if item["ticket"] == ticket), None)
        if selected is None:
            raise LookupError("Position was not found")
        self._audit.append("position_served", {"ticket": ticket})
        return selected

    def history(
        self,
        start: datetime,
        end: datetime,
        *,
        symbol: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        self._guarded_account()
        if start.tzinfo is None or end.tzinfo is None or end <= start:
            raise ValueError("History bounds must be ordered timezone-aware timestamps")
        if end - start > timedelta(days=31):
            raise ValueError("History window cannot exceed 31 days")
        if symbol is not None and symbol != self._allowed_symbol:
            raise ValueError("History symbol must be XAUUSD")
        deals = self._adapter.history(start, end, symbol=symbol, limit=limit)
        response = {
            "from_utc": start.astimezone(UTC).isoformat(),
            "to_utc": end.astimezone(UTC).isoformat(),
            "count": len(deals),
            "deals": [
                {
                    "ticket": item.ticket,
                    "order_id": item.order_id,
                    "position_id": item.position_id,
                    "symbol": item.symbol,
                    "side": item.side.value if item.side else None,
                    "entry": item.entry,
                    "volume": item.volume,
                    "price": item.price,
                    "profit": item.profit,
                    "commission": item.commission,
                    "swap": item.swap,
                    "fee": item.fee,
                    "time_msc": item.time_msc,
                    "net_pnl": item.net_pnl,
                    "owned_by_lab": (
                        item.symbol == self._allowed_symbol
                        and item.magic_number == self._magic_number
                    ),
                }
                for item in deals
            ],
        }
        self._audit.append("history_served", {"count": len(deals), "symbol": symbol})
        return response

    def daily_stats(self, *, audit_event: bool = True) -> dict[str, Any]:
        account, _ = self._guarded_account()
        realized = self._adapter.daily_realized_pnl()
        research_daily = (
            self._research_store.daily_research_summary()
            if self._research_store is not None else None
        )
        paper_positions = []
        if self._mode is TradingMode.PAPER and self._paper_engine is not None:
            paper_positions = self._paper_engine.position_snapshots()
            realized += self._research_store.paper_daily_realized_pnl()
        risk_state = (
            self._research_store.update_daily_risk_state(
                currency=account.currency,
                equity=account.equity,
                balance=account.balance,
            )
            if self._research_store is not None else None
        )
        response = {
            "date_utc": datetime.now(UTC).date().isoformat(),
            "currency": account.currency,
            "realized_pnl": realized,
            "equity": account.equity,
            "balance": account.balance,
            "open_positions": len(self._adapter.positions()) + len(paper_positions),
            "closed_trades": research_daily["sample_size"] if research_daily else 0,
            "daily_r": research_daily["total_r"] if research_daily else 0.0,
            "start_equity": risk_state["start_equity"] if risk_state else None,
            "peak_equity": risk_state["peak_equity"] if risk_state else None,
            "drawdown": risk_state["drawdown"] if risk_state else None,
        }
        if audit_event:
            self._audit.append("daily_stats_served", response)
        return response

    def status(self) -> dict[str, Any]:
        health = self.health()
        daily = self.daily_stats(audit_event=False)
        last_decision = (
            self._research_store.latest_agent_decision()
            if self._research_store is not None else None
        )
        last_execution = (
            self._research_store.latest_lifecycle_event()
            if self._research_store is not None else None
        )
        response = {
            "mode": self._mode.value,
            "connected": health["account_guard"]["allowed"],
            "account_allowed": health["account_guard"]["allowed"],
            "demo_verified": health["account_guard"]["allowed"],
            "trading_enabled": False,
            "kill_switch": "UNKNOWN" if self._mode is TradingMode.DEMO_EXECUTION else "NOT_APPLICABLE",
            "open_positions": health["exposure"]["position_count"],
            "daily_pnl": daily["realized_pnl"],
            "daily_r": daily["daily_r"],
            "last_agent_decision": last_decision,
            "last_execution": last_execution,
            "last_market_data": health["market_data"],
            "audit_valid": health["audit"]["valid"],
        }
        self._audit.append("status_served", response)
        return response

    def submit(self, proposal: TradeProposal):
        if self._gateway is None:
            raise RuntimeError("Proposal gateway is unavailable")
        return self._gateway.submit(proposal)

    @staticmethod
    def _request_hash(request: SemanticTradeRequest) -> str:
        payload = asdict(request)
        payload.pop("idempotency_key", None)
        payload["action"] = request.action.value
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _gateway_result_payload(result) -> dict[str, Any]:
        return {
            "status": result.status.value,
            "proposal_id": result.proposal_id,
            "mode": result.mode.value,
            "checks": [asdict(item) for item in result.checks],
            "failed_codes": list(result.failed_codes),
            "estimated_risk_amount": result.estimated_risk_amount,
            "execution": asdict(result.execution) if result.execution else None,
        }

    def propose_semantic(self, request: SemanticTradeRequest) -> dict[str, Any]:
        if self._research_store is None or self._position_sizer is None or self._magic_number <= 0:
            raise RuntimeError("Semantic proposal service is unavailable")
        try:
            UUID(request.idempotency_key)
        except (ValueError, TypeError) as exc:
            raise ValueError("idempotency_key must be a UUID") from exc
        if request.symbol != self._allowed_symbol or request.entry_type != "MARKET":
            raise ValueError("Only XAUUSD MARKET proposals are supported")
        if request.timeframe not in {"M1", "M5", "M15", "H1"}:
            raise ValueError("Unsupported decision timeframe")
        if not math.isfinite(request.confidence) or not 0 <= request.confidence <= 1:
            raise ValueError("confidence must be between zero and one")
        if not request.reason.strip() or len(request.reason) > 4000:
            raise ValueError("reason must contain 1..4000 characters")

        request_hash = self._request_hash(request)
        generated_id = str(uuid4())
        reservation, proposal_id, previous = self._research_store.reserve_idempotency(
            request.idempotency_key, request_hash, generated_id
        )
        if reservation == "CONFLICT":
            raise FileExistsError("Idempotency key was reused with a different proposal")
        if reservation == "EXISTING":
            if previous is not None:
                return {**previous, "idempotent_replay": True}
            return {
                "status": "EXECUTION_UNCERTAIN",
                "proposal_id": proposal_id,
                "mode": self._mode.value,
                "failed_codes": ["IDEMPOTENCY_RESULT_UNAVAILABLE"],
                "idempotent_replay": True,
            }

        self._research_store.append_lifecycle(str(uuid4()), proposal_id, "PROPOSED", {
            "strategy_id": request.strategy_id,
            "strategy_version": request.strategy_version,
            "confidence": request.confidence,
        })
        self._audit.append("semantic_proposal_received", {
            "proposal_id": proposal_id,
            "request_hash": request_hash,
            "symbol": request.symbol,
            "action": request.action.value,
            "requested_risk_amount": request.requested_risk_amount,
        })
        self._research_store.append_lifecycle(str(uuid4()), proposal_id, "VALIDATING")
        account, _ = self._guarded_account()
        market = self._adapter.symbol_snapshot(request.symbol)
        side = Side.BUY if request.action is OpenAction.OPEN_LONG else Side.SELL
        sizing = self._position_sizer.size(
            side=side,
            requested_risk_amount=request.requested_risk_amount,
            stop_loss=request.stop_loss,
            account=account,
            market=market,
        )
        if not sizing.ok or sizing.volume is None:
            response = {
                "status": "REJECTED_RISK",
                "proposal_id": proposal_id,
                "mode": self._mode.value,
                "failed_codes": [sizing.failed_code],
                "requested_risk_amount": request.requested_risk_amount,
                "allowed_risk_amount": sizing.allowed_risk_amount,
                "risk_currency": account.currency,
                "calculated_volume": None,
            }
            self._research_store.append_lifecycle(
                str(uuid4()), proposal_id, "REJECTED_RISK", {"code": sizing.failed_code}
            )
            self._audit.append("semantic_proposal_rejected", response)
            self._research_store.complete_idempotency(request.idempotency_key, response)
            return response

        session = session_context(datetime.now(UTC))["primary"]
        proposal = TradeProposal(
            proposal_id=proposal_id,
            hypothesis_id=request.hypothesis_id,
            strategy_id=request.strategy_id,
            setup_id=request.setup_id,
            strategy_version=request.strategy_version,
            symbol=request.symbol,
            side=side,
            volume=sizing.volume,
            stop_loss=request.stop_loss,
            take_profit=request.take_profit,
            magic_number=self._magic_number,
            position_management="SINGLE_ENTRY",
            thesis=request.reason.strip(),
            session=str(session),
            market_regime=request.market_regime,
        )
        result = self._gateway.submit(proposal)
        response = {
            **self._gateway_result_payload(result),
            "requested_risk_amount": request.requested_risk_amount,
            "allowed_risk_amount": sizing.allowed_risk_amount,
            "risk_currency": account.currency,
            "calculated_volume": sizing.volume,
            "idempotent_replay": False,
        }
        lifecycle_payload = {
            "gateway_status": result.status.value,
            "failed_codes": list(result.failed_codes),
        }
        if result.status.value == "OBSERVED":
            self._research_store.append_lifecycle(
                str(uuid4()), proposal_id, "OBSERVED", lifecycle_payload
            )
        elif result.status.value in {"PAPER_ACCEPTED", "EXECUTED"}:
            for state in ("APPROVED", "EXECUTING", "EXECUTED", "OPEN"):
                self._research_store.append_lifecycle(
                    str(uuid4()), proposal_id, state, lifecycle_payload
                )
        elif result.status.value == "EXECUTION_UNCERTAIN":
            self._research_store.append_lifecycle(
                str(uuid4()), proposal_id, "EXECUTION_UNCERTAIN", lifecycle_payload
            )
        else:
            failed = set(result.failed_codes)
            market_codes = {
                "MARKET_CLOSED", "MARKET_TICK_STALE", "SPREAD_TOO_WIDE",
                "MARKET_DATA_INVALID", "SYMBOL_TRADE_MODE_FORBIDDEN",
            }
            security_codes = {
                "ACCOUNT_NOT_DEMO", "ACCOUNT_LOGIN_MISMATCH", "ACCOUNT_SERVER_MISMATCH",
                "AUDIT_CHAIN_INVALID", "DEMO_EXECUTION_NOT_AUTHORIZED", "KILL_SWITCH_ENGAGED",
            }
            state = (
                "REJECTED_SECURITY" if failed & security_codes
                else "REJECTED_MARKET" if failed & market_codes
                else "REJECTED_RISK"
            )
            self._research_store.append_lifecycle(
                str(uuid4()), proposal_id, state, lifecycle_payload
            )
        self._research_store.complete_idempotency(request.idempotency_key, response)
        return response

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
                    "wins": item.wins,
                    "losses": item.losses,
                    "median_duration_seconds": item.median_duration_seconds,
                    "expectancy_r_ci95_low": item.expectancy_r_ci95_low,
                    "expectancy_r_ci95_high": item.expectancy_r_ci95_high,
                    "evidence_sufficient": item.evidence_sufficient,
                }
                for item in metrics
            ],
            "groups": self._research_store.grouped_metrics(),
        }
        self._audit.append("research_metrics_served", response)
        return response

    def record_decision(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._research_store is None:
            raise RuntimeError("Research store is unavailable")
        self._guarded_account()
        if not self._audit.verify().valid:
            raise RuntimeError("Audit chain is invalid")
        if payload.get("symbol") != self._allowed_symbol or payload.get("timeframe") != "M1":
            raise ValueError("Decisions must reference the configured XAUUSD M1 stream")
        bar_time = datetime.fromisoformat(str(payload["bar_time_utc"])).astimezone(UTC)
        candles = self._adapter.candles(self._allowed_symbol, "M1", 1)
        if len(candles) != 1 or candles[0].time_msc != int(bar_time.timestamp() * 1000):
            raise ValueError("Decision must reference the latest closed XAUUSD M1 bar")
        payload = {**payload, "bar_time_utc": bar_time.isoformat()}
        self._research_store.record_agent_decision(**payload)
        self._audit.append("agent_decision_recorded", payload)
        return {"recorded": True, "decision_id": payload["decision_id"]}

    def save_hypothesis(self, hypothesis_id: str, thesis: str) -> dict[str, Any]:
        if self._research_store is None:
            raise RuntimeError("Research store is unavailable")
        self._research_store.save_hypothesis(hypothesis_id, thesis)
        self._audit.append("hypothesis_saved", {
            "hypothesis_id": hypothesis_id, "thesis": thesis,
        })
        return {"recorded": True, "hypothesis_id": hypothesis_id}

    def save_trade_review(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._research_store is None:
            raise RuntimeError("Research store is unavailable")
        self._research_store.save_trade_review(**payload)
        proposal_id = self._research_store.proposal_id_for_trade(payload["trade_id"])
        if proposal_id is not None:
            self._research_store.append_lifecycle(
                str(uuid4()), proposal_id, "REVIEWED", {"review_id": payload["review_id"]}
            )
        self._audit.append("trade_review_saved", {
            "review_id": payload["review_id"], "trade_id": payload["trade_id"],
        })
        return {"recorded": True, "review_id": payload["review_id"]}

    def recent_memory(self, limit: int = 50) -> dict[str, Any]:
        if self._research_store is None:
            raise RuntimeError("Research store is unavailable")
        items = self._research_store.recent_memory(limit)
        self._audit.append("trading_memory_served", {"count": len(items)})
        return {"count": len(items), "items": items}

    def manage_position(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        if action not in {"CLOSE", "MODIFY", "CANCEL_PENDING"}:
            raise ValueError("Unsupported management action")
        if self._gateway is None:
            raise RuntimeError("Position management gateway is unavailable")
        return self._gateway.manage_position(action, payload)
