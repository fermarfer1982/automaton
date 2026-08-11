from __future__ import annotations

import threading
import hashlib
import json
import logging
from typing import Any, Protocol
from uuid import uuid4

from .account_guard import AccountGuard
from .audit import HashChainAuditLog
from .authorization import FileExecutionAuthorization
from .domain import (
    CheckResult,
    GatewayResult,
    GatewayStatus,
    GuardDecision,
    RiskStage,
    TradingMode,
    TradeProposal,
    proposal_to_payload,
)
from .execution_engine import ExecutionEngine
from .management_risk import PositionManagementRiskEngine
from .paper_engine import PaperEngine
from .risk_engine import RiskEngine
from .research_store import ResearchStore


_SECURITY_LOG = logging.getLogger("automaton.security")
_TRADING_LOG = logging.getLogger("automaton.trading")


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
        self._management_risk = PositionManagementRiskEngine(
            risk_engine.allowed_symbol,
            risk_engine.required_magic_number,
        )
        # Serializing the whole decision prevents duplicate races and interleaved MT5 calls.
        self._submit_lock = threading.Lock()

    @staticmethod
    def _management_response(
        *,
        operation_id: str,
        action: str,
        mode: TradingMode,
        status: str,
        checks=(),
        execution=None,
    ) -> dict[str, Any]:
        failed_codes = [item.code for item in checks if not item.passed]
        if execution is not None and execution.failed_code:
            failed_codes.append(execution.failed_code)
        return {
            "operation_id": operation_id,
            "action": action,
            "mode": mode.value,
            "status": status,
            "failed_codes": failed_codes,
            "checks": [
                {"code": item.code, "passed": item.passed, "detail": item.detail}
                for item in checks
            ],
            "execution": (
                {
                    "ok": execution.ok,
                    "failed_code": execution.failed_code,
                    "detail": execution.detail,
                    "execution_uncertain": execution.execution_uncertain,
                }
                if execution is not None else None
            ),
        }

    def manage_position(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._submit_lock:
            return self._manage_position_serialized(action, payload)

    def _manage_position_serialized(
        self, action: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        if action not in {"CLOSE", "MODIFY", "CANCEL_PENDING"}:
            raise ValueError("Unsupported management action")
        operation_id = str(uuid4())
        if not self._audit.verify().valid:
            return self._management_response(
                operation_id=operation_id, action=action, mode=self._mode,
                status="REJECTED_SECURITY",
                checks=(CheckResult("AUDIT_CHAIN_INVALID", False, "Audit chain is invalid"),),
            )
        self._audit.append("position_management_received", {
            "operation_id": operation_id,
            "action": action,
            "ticket": payload.get("ticket"),
            "mode": self._mode.value,
        })
        account = self._adapter.account_snapshot()
        account_guard = self._account_guard.evaluate(account)
        self._audit.append("position_management_account_guard", {
            "stage": RiskStage.PRE_FLIGHT_CHECK.value,
            "operation_id": operation_id,
            "checks": account_guard.checks,
        })
        if not account_guard.allowed:
            return self._management_response(
                operation_id=operation_id, action=action, mode=self._mode,
                status="REJECTED_SECURITY", checks=account_guard.checks,
            )
        if self._mode is TradingMode.OBSERVE_ONLY:
            checks = account_guard.checks + (CheckResult(
                "TRADING_MODE_OBSERVE_ONLY", False,
                "OBSERVE_ONLY records but never executes mutations",
            ),)
            self._audit.append("position_management_rejected", {
                "operation_id": operation_id,
                "action": action,
                "ticket": payload.get("ticket"),
                "failed_codes": ["TRADING_MODE_OBSERVE_ONLY"],
            })
            return self._management_response(
                operation_id=operation_id, action=action, mode=self._mode,
                status="REJECTED_SECURITY", checks=checks,
            )

        ticket = int(payload["ticket"])
        if self._mode is TradingMode.PAPER:
            return self._manage_paper(
                operation_id, action, ticket, payload, account_guard.checks
            )
        return self._manage_demo(
            operation_id, action, ticket, payload, account_guard.checks
        )

    def _manage_paper(
        self,
        operation_id: str,
        action: str,
        ticket: int,
        payload: dict[str, Any],
        account_checks: tuple[CheckResult, ...],
    ) -> dict[str, Any]:
        if self._paper_engine is None:
            raise RuntimeError("PAPER mode requires a persistent paper engine")
        if action == "CANCEL_PENDING":
            checks = account_checks + (CheckResult(
                "PAPER_PENDING_ORDERS_UNSUPPORTED", False,
                "The PAPER engine does not create pending orders",
            ),)
            return self._management_response(
                operation_id=operation_id, action=action, mode=self._mode,
                status="REJECTED", checks=checks,
            )
        position = next(
            (item for item in self._paper_engine.position_snapshots() if item.ticket == ticket),
            None,
        )
        if position is None:
            checks = account_checks + (CheckResult(
                "POSITION_NOT_FOUND", False, "Paper position was not found",
            ),)
            return self._management_response(
                operation_id=operation_id, action=action, mode=self._mode,
                status="REJECTED", checks=checks,
            )
        market = self._adapter.symbol_snapshot(position.symbol)
        decision = self._management_risk.evaluate_position(
            action, position, market,
            stop_loss=float(payload["stop_loss"]) if action == "MODIFY" else None,
            take_profit=payload.get("take_profit"),
            paper=True,
        )
        checks = account_checks + decision.checks
        self._audit.append("position_management_risk_decision", {
            "stage": RiskStage.POST_LLM_CHECK.value,
            "operation_id": operation_id,
            "checks": decision.checks,
        })
        if not decision.allowed:
            return self._management_response(
                operation_id=operation_id, action=action, mode=self._mode,
                status="REJECTED", checks=checks,
            )
        if action == "CLOSE":
            self._paper_engine.close(ticket, market)
        else:
            self._paper_engine.modify(
                ticket,
                stop_loss=float(payload["stop_loss"]),
                take_profit=payload.get("take_profit"),
            )
        self._audit.append("position_management_outcome", {
            "operation_id": operation_id, "action": action, "status": "PAPER_EXECUTED",
        })
        return self._management_response(
            operation_id=operation_id, action=action, mode=self._mode,
            status="PAPER_EXECUTED", checks=checks,
        )

    def _management_pre_send(
        self,
        action: str,
        ticket: int,
        payload: dict[str, Any],
    ) -> GuardDecision:
        if not self._audit.verify().valid:
            return GuardDecision((CheckResult(
                "AUDIT_CHAIN_INVALID", False, "Audit changed before management send",
            ),))
        account_decision = self._account_guard.evaluate(self._adapter.account_snapshot())
        if not account_decision.allowed:
            return account_decision
        if action == "CANCEL_PENDING":
            order = next(
                (item for item in self._adapter.active_orders() if item.ticket == ticket), None
            )
            if order is None:
                return GuardDecision(account_decision.checks + (CheckResult(
                    "ORDER_NOT_FOUND", False, "Pending order changed before send",
                ),))
            risk = self._management_risk.evaluate_order(order)
        else:
            position = next(
                (item for item in self._adapter.positions() if item.ticket == ticket), None
            )
            if position is None:
                return GuardDecision(account_decision.checks + (CheckResult(
                    "POSITION_NOT_FOUND", False, "Position changed before send",
                ),))
            market = self._adapter.symbol_snapshot(position.symbol)
            risk = self._management_risk.evaluate_position(
                action, position, market,
                stop_loss=float(payload["stop_loss"]) if action == "MODIFY" else None,
                take_profit=payload.get("take_profit"),
            )
        return GuardDecision(account_decision.checks + risk.checks)

    def _manage_demo(
        self,
        operation_id: str,
        action: str,
        ticket: int,
        payload: dict[str, Any],
        account_checks: tuple[CheckResult, ...],
    ) -> dict[str, Any]:
        fingerprint = hashlib.sha256(json.dumps({
            "action": action,
            "ticket": ticket,
            "stop_loss": payload.get("stop_loss"),
            "take_profit": payload.get("take_profit"),
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        if self._audit.has_unreconciled_execution(fingerprint):
            checks = account_checks + (CheckResult(
                "EXECUTION_RECONCILIATION_REQUIRED", False,
                "A prior management send outcome is uncertain",
            ),)
            return self._management_response(
                operation_id=operation_id, action=action, mode=self._mode,
                status="EXECUTION_UNCERTAIN", checks=checks,
            )
        if action == "CANCEL_PENDING":
            order = next(
                (item for item in self._adapter.active_orders() if item.ticket == ticket), None
            )
            if order is None:
                decision = GuardDecision((CheckResult(
                    "ORDER_NOT_FOUND", False, "Pending order was not found",
                ),))
                request = None
            else:
                decision = self._management_risk.evaluate_order(order)
                request = self._execution_engine.build_cancel_request(
                    order, self._risk_engine.required_magic_number, operation_id
                )
        else:
            position = next(
                (item for item in self._adapter.positions() if item.ticket == ticket), None
            )
            if position is None:
                decision = GuardDecision((CheckResult(
                    "POSITION_NOT_FOUND", False, "Position was not found",
                ),))
                request = None
            else:
                market = self._adapter.symbol_snapshot(position.symbol)
                decision = self._management_risk.evaluate_position(
                    action, position, market,
                    stop_loss=float(payload["stop_loss"]) if action == "MODIFY" else None,
                    take_profit=payload.get("take_profit"),
                )
                request = (
                    self._execution_engine.build_close_request(
                        position, market, self._risk_engine.required_magic_number, operation_id
                    )
                    if action == "CLOSE"
                    else self._execution_engine.build_modify_request(
                        position, float(payload["stop_loss"]), payload.get("take_profit"),
                        self._risk_engine.required_magic_number, operation_id,
                    )
                )
        checks = account_checks + decision.checks
        self._audit.append("position_management_risk_decision", {
            "stage": RiskStage.POST_LLM_CHECK.value,
            "operation_id": operation_id,
            "checks": decision.checks,
        })
        if not decision.allowed or request is None:
            return self._management_response(
                operation_id=operation_id, action=action, mode=self._mode,
                status="REJECTED", checks=checks,
            )
        execution = self._execution_engine.execute_management(
            request,
            self._audit.append,
            operation_id=operation_id,
            fingerprint=fingerprint,
            pre_send_guard=lambda: self._management_pre_send(action, ticket, payload),
        )
        status = (
            "EXECUTION_UNCERTAIN" if execution.execution_uncertain
            else "EXECUTED" if execution.ok else "REJECTED"
        )
        return self._management_response(
            operation_id=operation_id, action=action, mode=self._mode,
            status=status, checks=checks, execution=execution,
        )

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
        if status in {GatewayStatus.REJECTED, GatewayStatus.EXECUTION_UNCERTAIN}:
            if _SECURITY_LOG.handlers:
                _SECURITY_LOG.warning(
                    "proposal_outcome status=%s failed_codes=%s",
                    status.value,
                    ",".join(result.failed_codes),
                )
        else:
            if _TRADING_LOG.handlers:
                _TRADING_LOG.info("proposal_outcome status=%s", status.value)
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
        daily_state = self._daily_risk_state(account)
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
            cooldown_active=self._audit.has_recent_entry(
                self._risk_engine.cooldown_seconds
            ),
            daily_start_equity=float(daily_state["start_equity"]),
            daily_peak_equity=float(daily_state["peak_equity"]),
        )
        return GuardDecision(
            checks=account_decision.checks + risk.checks,
            estimated_risk_amount=risk.estimated_risk_amount,
        )

    def _daily_risk_state(self, account) -> dict[str, Any]:
        if self._research_store is None:
            raise RuntimeError("Durable daily risk state is unavailable")
        return self._research_store.update_daily_risk_state(
            currency=account.currency,
            equity=account.equity,
            balance=account.balance,
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
            if self._audit.has_unreconciled_execution(fingerprint):
                return GatewayResult(
                    status=GatewayStatus.EXECUTION_UNCERTAIN,
                    proposal_id=proposal.proposal_id,
                    mode=self._mode,
                    checks=(CheckResult(
                        "EXECUTION_RECONCILIATION_REQUIRED", False,
                        "A prior send outcome is uncertain and requires human reconciliation",
                    ),),
                )
            # No subsequent action is permitted unless the proposal itself is durably audited.
            self._audit.append(
                "proposal_received",
                {
                    "stage": RiskStage.POST_LLM_CHECK.value,
                    "proposal": proposal_to_payload(proposal),
                    "mode": self._mode.value,
                    "fingerprint": fingerprint,
                },
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
                {
                    "stage": RiskStage.PRE_FLIGHT_CHECK.value,
                    "proposal_id": proposal.proposal_id,
                    "checks": account_decision.checks,
                },
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
            daily_state = self._daily_risk_state(account)
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
                cooldown_active=self._audit.has_recent_entry(
                    self._risk_engine.cooldown_seconds
                ),
                daily_start_equity=float(daily_state["start_equity"]),
                daily_peak_equity=float(daily_state["peak_equity"]),
            )
            self._audit.append(
                "risk_engine_decision",
                {
                    "stage": RiskStage.POST_LLM_CHECK.value,
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
