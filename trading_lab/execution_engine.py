from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from .authorization import AuthorizationDecision
from .domain import ExecutionResult, GuardDecision, Side, SymbolSnapshot, TradeProposal


class ExecutionAdapter(Protocol):
    def order_check(self, request: dict[str, object]): ...
    def order_send(self, request: dict[str, object]): ...


AuditHook = Callable[[str, dict[str, Any]], object]
PreSendGuard = Callable[[], GuardDecision]
AuthorizationCheck = Callable[[], AuthorizationDecision]


class ExecutionEngine:
    """The sole component allowed to sequence MT5 order_check and order_send."""

    def __init__(self, adapter: ExecutionAdapter) -> None:
        self._adapter = adapter

    @staticmethod
    def build_request(proposal: TradeProposal, market: SymbolSnapshot) -> dict[str, object]:
        return {
            "action": "DEAL",
            "symbol": proposal.symbol,
            "volume": proposal.volume,
            "type": proposal.side.value,
            "price": market.ask if proposal.side is Side.BUY else market.bid,
            "sl": proposal.stop_loss,
            "tp": proposal.take_profit or 0.0,
            "deviation": 10,
            "magic": proposal.magic_number,
            "comment": f"automaton:{proposal.proposal_id[:18]}",
            "type_time": "GTC",
            "type_filling": "IOC",
        }

    def execute(
        self,
        proposal: TradeProposal,
        market: SymbolSnapshot,
        audit_hook: AuditHook,
        *,
        fingerprint: str,
        pre_send_guard: PreSendGuard,
        authorization_check: AuthorizationCheck,
    ) -> ExecutionResult:
        request = self.build_request(proposal, market)
        audit_hook("order_check_requested", {"proposal_id": proposal.proposal_id, "request": request})
        checked = self._adapter.order_check(request)
        audit_hook(
            "order_check_result",
            {"proposal_id": proposal.proposal_id, "ok": checked.ok, "retcode": checked.retcode, "comment": checked.comment},
        )
        if not checked.ok:
            return ExecutionResult(False, "ORDER_CHECK_FAILED", checked.comment, order_check=checked)

        # Re-read protected state after order_check, as close as possible to the
        # irreversible call. This catches account switches, new exposure, market
        # deterioration, audit tampering, and a newly engaged kill switch.
        pre_send = pre_send_guard()
        audit_hook(
            "pre_send_guard_decision",
            {"proposal_id": proposal.proposal_id, "checks": pre_send.checks},
        )
        if not pre_send.allowed:
            return ExecutionResult(
                False,
                "PRE_SEND_GUARD_REJECTED",
                f"Pre-send revalidation failed: {', '.join(pre_send.failed_codes)}",
                order_check=checked,
            )

        authorization = authorization_check()
        audit_hook(
            "execution_authorization_revalidated",
            {
                "proposal_id": proposal.proposal_id,
                "allowed": authorization.allowed,
                "code": authorization.code,
            },
        )
        if not authorization.allowed:
            return ExecutionResult(
                False,
                "EXECUTION_AUTHORIZATION_REVOKED",
                authorization.detail,
                order_check=checked,
            )

        # This durable audit record must succeed before an order can be sent.
        audit_hook(
            "order_send_authorized",
            {
                "proposal_id": proposal.proposal_id,
                "fingerprint": fingerprint,
                "request": request,
            },
        )
        try:
            sent = self._adapter.order_send(request)
        except Exception as exc:
            try:
                audit_hook(
                    "order_send_uncertain",
                    {
                        "proposal_id": proposal.proposal_id,
                        "fingerprint": fingerprint,
                        "error_type": type(exc).__name__,
                    },
                )
            except Exception:
                pass
            return ExecutionResult(
                False,
                "ORDER_SEND_UNCERTAIN",
                "MT5 order_send outcome is unknown; human reconciliation is required",
                order_check=checked,
                execution_uncertain=True,
            )
        try:
            audit_hook(
                "order_send_result",
                {
                    "proposal_id": proposal.proposal_id,
                    "ok": sent.ok,
                    "retcode": sent.retcode,
                    "comment": sent.comment,
                    "order_id": sent.order_id,
                    "deal_id": sent.deal_id,
                },
            )
        except Exception:
            return ExecutionResult(
                False,
                "POST_SEND_AUDIT_FAILED",
                "MT5 responded but its result could not be durably audited; human reconciliation is required",
                order_check=checked,
                order_send=sent,
                execution_uncertain=True,
            )
        if not sent.ok:
            return ExecutionResult(False, "ORDER_SEND_FAILED", sent.comment, order_check=checked, order_send=sent)
        return ExecutionResult(True, None, "Order executed", order_check=checked, order_send=sent)
