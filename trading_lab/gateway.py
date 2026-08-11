from __future__ import annotations

import threading
from typing import Any, Protocol

from .account_guard import AccountGuard
from .audit import HashChainAuditLog
from .authorization import FileExecutionAuthorization
from .domain import (
    CheckResult,
    GatewayResult,
    GatewayStatus,
    GuardDecision,
    TradingMode,
    TradeProposal,
    proposal_to_payload,
)
from .execution_engine import ExecutionEngine
from .paper_engine import PaperEngine
from .risk_engine import RiskEngine
from .research_store import ResearchStore


class GatewayAdapter(Protocol):
    def account_snapshot(self): ...
    def symbol_snapshot(self, symbol: str): ...
    def positions(self): ...
    def active_orders(self): ...
    def daily_realized_pnl(self) -> float: ...


class MT5Gateway:
    def __init__(
        self,
        *,
        mode: TradingMode,
        adapter: GatewayAdapter,
        account_guard: AccountGuard,
        risk_engine: RiskEngine,
        execution_engine: ExecutionEngine,
        audit: HashChainAuditLog,
        execution_authorization: FileExecutionAuthorization,
        research_store: ResearchStore | None = None,
        paper_engine: PaperEngine | None = None,
    ) -> None:
        self._mode = mode
        self._adapter = adapter
        self._account_guard = account_guard
        self._risk_engine = risk_engine
        self._execution_engine = execution_engine
        self._audit = audit
        self._execution_authorization = execution_authorization
        self._research_store = research_store
        self._paper_engine = paper_engine
        # Serializing the whole decision prevents duplicate races and interleaved MT5 calls.
        self._submit_lock = threading.Lock()

    def _outcome(
        self,
        proposal: TradeProposal,
        status: GatewayStatus,
        checks: tuple[CheckResult, ...],
        fingerprint: str,
        *,
        estimated_risk_amount: float = 0.0,
        execution=None,
    ) -> GatewayResult:
        result = GatewayResult(
            status=status,
            proposal_id=proposal.proposal_id,
            mode=self._mode,
            checks=checks,
            estimated_risk_amount=estimated_risk_amount,
            execution=execution,
        )
        self._audit.append(
            "proposal_outcome",
            {
                "proposal_id": proposal.proposal_id,
                "fingerprint": fingerprint,
                "mode": self._mode.value,
                "status": status.value,
                "failed_codes": result.failed_codes,
                "estimated_risk_amount": estimated_risk_amount,
            },
        )
        if self._research_store is not None:
            try:
                self._research_store.record_proposal(
                    proposal,
                    mode=self._mode,
                    status=status.value,
                    fingerprint=fingerprint,
                    estimated_risk_amount=estimated_risk_amount,
                )
            except Exception as exc:
                self._audit.append(
                    "research_store_error",
                    {"proposal_id": proposal.proposal_id, "error_type": type(exc).__name__},
                )
        return result

    def submit(self, proposal: TradeProposal) -> GatewayResult:
        with self._submit_lock:
            return self._submit_serialized(proposal)

    def _pre_send_decision(self, proposal: TradeProposal, fingerprint: str) -> GuardDecision:
        verification = self._audit.verify()
        if not verification.valid:
            return GuardDecision(checks=(CheckResult(
                "AUDIT_CHAIN_INVALID", False,
                "Audit chain changed before order send",
            ),))
        account = self._adapter.account_snapshot()
        account_decision = self._account_guard.evaluate(account)
        if not account_decision.allowed:
            return account_decision
        market = self._adapter.symbol_snapshot(proposal.symbol)
        risk = self._risk_engine.evaluate(
            proposal=proposal,
            account=account,
            market=market,
            positions=self._adapter.positions(),
            active_orders=self._adapter.active_orders(),
            daily_realized_pnl=self._adapter.daily_realized_pnl(),
            duplicate=self._audit.has_recent_fingerprint(
                fingerprint, self._risk_engine.duplicate_window_seconds
            ),
        )
        return GuardDecision(
            checks=account_decision.checks + risk.checks,
            estimated_risk_amount=risk.estimated_risk_amount,
        )

    def _submit_serialized(self, proposal: TradeProposal) -> GatewayResult:
        fingerprint = self._risk_engine.fingerprint(proposal)
        try:
            verification = self._audit.verify()
            if not verification.valid:
                return GatewayResult(
                    status=GatewayStatus.REJECTED,
                    proposal_id=proposal.proposal_id,
                    mode=self._mode,
                    checks=(CheckResult(
                        "AUDIT_CHAIN_INVALID", False,
                        "Audit chain verification failed; gateway is locked fail-closed",
                    ),),
                )
            # No subsequent action is permitted unless the proposal itself is durably audited.
            self._audit.append(
                "proposal_received",
                {"proposal": proposal_to_payload(proposal), "mode": self._mode.value, "fingerprint": fingerprint},
            )
            if self._research_store is not None:
                # Research memory must be writable before any possible execution path.
                self._research_store.record_proposal(
                    proposal,
                    mode=self._mode,
                    status="RECEIVED",
                    fingerprint=fingerprint,
                    estimated_risk_amount=0.0,
                )
            account = self._adapter.account_snapshot()
            account_decision = self._account_guard.evaluate(account)
            self._audit.append(
                "account_guard_decision",
                {"proposal_id": proposal.proposal_id, "checks": account_decision.checks},
            )
            if not account_decision.allowed:
                return self._outcome(proposal, GatewayStatus.REJECTED, account_decision.checks, fingerprint)

            market = self._adapter.symbol_snapshot(proposal.symbol)
            positions = self._adapter.positions()
            if self._mode is TradingMode.PAPER:
                if self._paper_engine is None:
                    raise RuntimeError("PAPER mode requires a persistent paper engine")
                positions = positions + self._paper_engine.position_snapshots()
            active_orders = self._adapter.active_orders()
            daily_pnl = self._adapter.daily_realized_pnl()
            if self._mode is TradingMode.PAPER and self._research_store is not None:
                # A profitable live/demo account must never mask PAPER losses (and
                # vice versa), so apply the more conservative daily result.
                daily_pnl = min(daily_pnl, self._research_store.paper_daily_realized_pnl())
            duplicate = self._audit.has_recent_fingerprint(
                fingerprint, self._risk_engine.duplicate_window_seconds
            )
            risk = self._risk_engine.evaluate(
                proposal=proposal,
                account=account,
                market=market,
                positions=positions,
                active_orders=active_orders,
                daily_realized_pnl=daily_pnl,
                duplicate=duplicate,
            )
            self._audit.append(
                "risk_engine_decision",
                {
                    "proposal_id": proposal.proposal_id,
                    "checks": risk.checks,
                    "estimated_risk_amount": risk.estimated_risk_amount,
                },
            )
            all_checks = account_decision.checks + risk.checks
            if not risk.allowed:
                return self._outcome(
                    proposal, GatewayStatus.REJECTED, all_checks, fingerprint,
                    estimated_risk_amount=risk.estimated_risk_amount,
                )

            if self._mode is TradingMode.OBSERVE_ONLY:
                return self._outcome(
                    proposal, GatewayStatus.OBSERVED, all_checks, fingerprint,
                    estimated_risk_amount=risk.estimated_risk_amount,
                )
            if self._mode is TradingMode.PAPER:
                self._paper_engine.open(proposal, market)
                return self._outcome(
                    proposal, GatewayStatus.PAPER_ACCEPTED, all_checks, fingerprint,
                    estimated_risk_amount=risk.estimated_risk_amount,
                )

            authorization = self._execution_authorization.evaluate()
            authorization_check = CheckResult(
                authorization.code, authorization.allowed, authorization.detail
            )
            all_checks = all_checks + (authorization_check,)
            self._audit.append(
                "execution_authorization_decision",
                {"proposal_id": proposal.proposal_id, "check": authorization_check},
            )
            if not authorization.allowed:
                return self._outcome(
                    proposal, GatewayStatus.REJECTED, all_checks, fingerprint,
                    estimated_risk_amount=risk.estimated_risk_amount,
                )

            execution = self._execution_engine.execute(
                proposal,
                market,
                self._audit.append,
                fingerprint=fingerprint,
                pre_send_guard=lambda: self._pre_send_decision(proposal, fingerprint),
                authorization_check=self._execution_authorization.evaluate,
            )
            status = (
                GatewayStatus.EXECUTION_UNCERTAIN
                if execution.execution_uncertain
                else GatewayStatus.EXECUTED if execution.ok
                else GatewayStatus.REJECTED
            )
            try:
                return self._outcome(
                    proposal, status, all_checks, fingerprint,
                    estimated_risk_amount=risk.estimated_risk_amount,
                    execution=execution,
                )
            except Exception:
                if execution.execution_uncertain or execution.ok:
                    return GatewayResult(
                        status=GatewayStatus.EXECUTION_UNCERTAIN,
                        proposal_id=proposal.proposal_id,
                        mode=self._mode,
                        checks=all_checks + (CheckResult(
                            "POST_EXECUTION_OUTCOME_AUDIT_FAILED",
                            False,
                            "Execution may have occurred; human reconciliation is required",
                        ),),
                        estimated_risk_amount=risk.estimated_risk_amount,
                        execution=execution,
                    )
                raise
        except Exception as exc:
            check = CheckResult(
                "GATEWAY_INTERNAL_ERROR",
                False,
                f"Fail-closed internal error: {type(exc).__name__}",
            )
            try:
                self._audit.append(
                    "gateway_internal_error",
                    {"proposal_id": proposal.proposal_id, "error_type": type(exc).__name__},
                )
            except Exception:
                pass
            return GatewayResult(
                status=GatewayStatus.REJECTED,
                proposal_id=proposal.proposal_id,
                mode=self._mode,
                checks=(check,),
            )
