from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TradingMode(str, Enum):
    OBSERVE_ONLY = "OBSERVE_ONLY"
    PAPER = "PAPER"
    DEMO_EXECUTION = "DEMO_EXECUTION"


class AccountKind(str, Enum):
    DEMO = "DEMO"
    CONTEST = "CONTEST"
    REAL = "REAL"
    UNKNOWN = "UNKNOWN"


class Side(str, Enum):
    BUY = "BUY"
    SELL = "SELL"


class OpenAction(str, Enum):
    OPEN_LONG = "OPEN_LONG"
    OPEN_SHORT = "OPEN_SHORT"


class GatewayStatus(str, Enum):
    OBSERVED = "OBSERVED"
    PAPER_ACCEPTED = "PAPER_ACCEPTED"
    EXECUTED = "EXECUTED"
    EXECUTION_UNCERTAIN = "EXECUTION_UNCERTAIN"
    REJECTED = "REJECTED"


class RiskStage(str, Enum):
    PRE_FLIGHT_CHECK = "PRE_FLIGHT_CHECK"
    POST_LLM_CHECK = "POST_LLM_CHECK"
    PRE_EXECUTION_CHECK = "PRE_EXECUTION_CHECK"


@dataclass(frozen=True)
class CheckResult:
    code: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class GuardDecision:
    checks: tuple[CheckResult, ...]
    estimated_risk_amount: float = 0.0

    @property
    def allowed(self) -> bool:
        return bool(self.checks) and all(check.passed for check in self.checks)

    @property
    def failed_codes(self) -> tuple[str, ...]:
        return tuple(check.code for check in self.checks if not check.passed)


@dataclass(frozen=True)
class AccountSnapshot:
    login: int
    server: str
    kind: AccountKind
    equity: float
    balance: float
    connected: bool
    trade_allowed: bool
    terminal_trade_allowed: bool
    currency: str = "UNKNOWN"
    account_name: str | None = None


@dataclass(frozen=True)
class SymbolSnapshot:
    symbol: str
    bid: float
    ask: float
    point: float
    tick_size: float
    tick_value: float
    volume_min: float
    volume_max: float
    volume_step: float
    trade_stops_level: int
    visible: bool
    tick_time_msc: int
    trade_freeze_level: int = 0
    market_open: bool = True


@dataclass(frozen=True)
class CandleSnapshot:
    symbol: str
    timeframe: str
    time_msc: int
    open: float
    high: float
    low: float
    close: float
    tick_volume: int
    spread: int


@dataclass(frozen=True)
class PositionSizeResult:
    ok: bool
    requested_risk_amount: float
    allowed_risk_amount: float
    volume: float | None
    estimated_risk_amount: float
    failed_code: str | None = None
    detail: str = ""


@dataclass(frozen=True)
class PositionSnapshot:
    ticket: int
    symbol: str
    side: Side
    volume: float
    price_open: float
    stop_loss: float | None
    profit: float
    magic_number: int


@dataclass(frozen=True)
class ActiveOrderSnapshot:
    ticket: int
    symbol: str
    volume: float
    magic_number: int


@dataclass(frozen=True)
class DealSnapshot:
    ticket: int
    order_id: int
    position_id: int
    symbol: str
    side: Side | None
    entry: str
    volume: float
    price: float
    profit: float
    commission: float
    swap: float
    fee: float
    time_msc: int
    magic_number: int

    @property
    def net_pnl(self) -> float:
        return self.profit + self.commission + self.swap + self.fee


@dataclass(frozen=True)
class TradeProposal:
    proposal_id: str
    hypothesis_id: str
    strategy_id: str
    setup_id: str
    strategy_version: str
    symbol: str
    side: Side
    volume: float
    stop_loss: float | None
    take_profit: float | None
    magic_number: int
    position_management: str
    thesis: str
    session: str
    market_regime: str


@dataclass(frozen=True)
class SemanticTradeRequest:
    idempotency_key: str
    action: OpenAction
    symbol: str
    entry_type: str
    stop_loss: float
    take_profit: float | None
    requested_risk_amount: float
    hypothesis_id: str
    strategy_id: str
    setup_id: str
    strategy_version: str
    confidence: float
    reason: str
    timeframe: str
    market_regime: str


@dataclass(frozen=True)
class OrderCheckResult:
    ok: bool
    retcode: int
    comment: str


@dataclass(frozen=True)
class OrderSendResult:
    ok: bool
    retcode: int
    comment: str
    order_id: int | None = None
    deal_id: int | None = None


@dataclass(frozen=True)
class ExecutionResult:
    ok: bool
    failed_code: str | None
    detail: str
    order_check: OrderCheckResult | None = None
    order_send: OrderSendResult | None = None
    execution_uncertain: bool = False


@dataclass(frozen=True)
class GatewayResult:
    status: GatewayStatus
    proposal_id: str
    mode: TradingMode
    checks: tuple[CheckResult, ...] = field(default_factory=tuple)
    estimated_risk_amount: float = 0.0
    execution: ExecutionResult | None = None

    @property
    def failed_codes(self) -> tuple[str, ...]:
        codes = [check.code for check in self.checks if not check.passed]
        if self.execution and self.execution.failed_code:
            codes.append(self.execution.failed_code)
        return tuple(codes)


def proposal_to_payload(proposal: TradeProposal) -> dict[str, Any]:
    return {
        "proposal_id": proposal.proposal_id,
        "hypothesis_id": proposal.hypothesis_id,
        "strategy_id": proposal.strategy_id,
        "setup_id": proposal.setup_id,
        "strategy_version": proposal.strategy_version,
        "symbol": proposal.symbol,
        "side": proposal.side.value,
        "volume": proposal.volume,
        "stop_loss": proposal.stop_loss,
        "take_profit": proposal.take_profit,
        "magic_number": proposal.magic_number,
        "position_management": proposal.position_management,
        "thesis": proposal.thesis,
        "session": proposal.session,
        "market_regime": proposal.market_regime,
    }
