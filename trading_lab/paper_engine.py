from __future__ import annotations

import hashlib
import threading
from datetime import datetime

from .audit import HashChainAuditLog
from .domain import PositionSnapshot, Side, SymbolSnapshot, TradingMode, TradeProposal
from .research_store import ResearchStore, TradeResultRecord


class PaperEngine:
    """Persistent deterministic paper fills; it has no MT5 execution methods."""

    def __init__(self, store: ResearchStore, audit: HashChainAuditLog) -> None:
        self._store = store
        self._audit = audit
        self._lock = threading.RLock()

    @staticmethod
    def _ticket(proposal_id: str) -> int:
        value = int.from_bytes(
            hashlib.sha256(proposal_id.encode("utf-8")).digest()[:7], "big"
        )
        return value or 1

    def open(
        self,
        proposal: TradeProposal,
        market: SymbolSnapshot,
        *,
        opened_at: datetime | None = None,
    ) -> None:
        with self._lock:
            self._open_serialized(proposal, market, opened_at=opened_at)

    def _open_serialized(
        self,
        proposal: TradeProposal,
        market: SymbolSnapshot,
        *,
        opened_at: datetime | None,
    ) -> None:
        opened_at = opened_at or datetime.now().astimezone()
        if proposal.symbol != market.symbol:
            raise ValueError("Proposal and market symbols must match")
        if proposal.stop_loss is None:
            raise ValueError("Paper position requires a stop loss")
        entry = market.ask if proposal.side is Side.BUY else market.bid
        risk_distance = abs(entry - proposal.stop_loss)
        if risk_distance <= 0 or market.tick_size <= 0 or market.tick_value <= 0:
            raise ValueError("Paper position risk economics are invalid")
        estimated_risk = (
            risk_distance / market.tick_size * market.tick_value * proposal.volume
        )
        fingerprint = hashlib.sha256(
            f"paper|{proposal.proposal_id}|{proposal.symbol}|{proposal.side.value}".encode("utf-8")
        ).hexdigest()
        opening_payload = {
            "proposal_id": proposal.proposal_id,
            "symbol": proposal.symbol,
            "side": proposal.side.value,
            "volume": proposal.volume,
            "entry_price": entry,
            "initial_stop_loss": proposal.stop_loss,
            "take_profit": proposal.take_profit,
            "opened_at": opened_at.isoformat(),
        }
        # The durable intent precedes mutation so an audit write failure leaves no
        # virtual position behind.
        self._audit.append("paper_position_open_authorized", opening_payload)
        self._store.record_proposal(
            proposal,
            mode=TradingMode.PAPER,
            status="PAPER_OPEN",
            fingerprint=fingerprint,
            estimated_risk_amount=estimated_risk,
        )
        self._store.open_paper_position(proposal, market, opened_at=opened_at)
        self._audit.append("paper_position_opened", opening_payload)

    def position_snapshots(self) -> list[PositionSnapshot]:
        with self._lock:
            return [
                PositionSnapshot(
                    ticket=self._ticket(str(row["proposal_id"])),
                    symbol=str(row["symbol"]),
                    side=Side(str(row["side"])),
                    volume=float(row["volume"]),
                    price_open=float(row["entry_price"]),
                    stop_loss=float(row["current_stop_loss"]),
                    profit=0.0,
                    # Virtual positions cannot carry an MT5 magic number. Presence on
                    # the symbol is sufficient for the independent risk engine to block
                    # grid and averaging behavior.
                    magic_number=0,
                )
                for row in self._store.list_open_paper_positions()
            ]

    def reconcile(
        self,
        market: SymbolSnapshot,
        *,
        at: datetime | None = None,
    ) -> list[TradeResultRecord]:
        with self._lock:
            return self._reconcile_serialized(market, at=at)

    def _reconcile_serialized(
        self,
        market: SymbolSnapshot,
        *,
        at: datetime | None,
    ) -> list[TradeResultRecord]:
        at = at or datetime.now().astimezone()
        closed: list[TradeResultRecord] = []
        for row in self._store.list_open_paper_positions():
            if str(row["symbol"]) != market.symbol:
                continue
            side = Side(str(row["side"]))
            direction = 1.0 if side is Side.BUY else -1.0
            exit_price = market.bid if side is Side.BUY else market.ask
            entry_price = float(row["entry_price"])
            initial_stop = float(row["initial_stop_loss"])
            current_stop = float(row["current_stop_loss"])
            risk_distance = abs(entry_price - initial_stop)
            if risk_distance <= 0:
                raise ValueError("Persisted paper risk distance is invalid")
            current_r = direction * (exit_price - entry_price) / risk_distance
            mfe_r = max(float(row["mfe_r"]), current_r, 0.0)
            mae_r = min(float(row["mae_r"]), current_r, 0.0)
            self._store.update_paper_excursions(
                str(row["proposal_id"]), mfe_r=mfe_r, mae_r=mae_r, updated_at=at
            )

            take_profit = row["take_profit"]
            hit_stop = (
                exit_price <= current_stop if side is Side.BUY else exit_price >= current_stop
            )
            hit_target = take_profit is not None and (
                exit_price >= float(take_profit)
                if side is Side.BUY
                else exit_price <= float(take_profit)
            )
            if not hit_stop and not hit_target:
                continue

            tick_size = float(row["tick_size"])
            tick_value = float(row["tick_value"])
            volume = float(row["volume"])
            if tick_size <= 0 or tick_value <= 0 or volume <= 0:
                raise ValueError("Persisted paper economics are invalid")
            pnl = direction * (exit_price - entry_price) / tick_size * tick_value * volume
            record = TradeResultRecord(
                trade_id=str(row["paper_trade_id"]),
                proposal_id=str(row["proposal_id"]),
                hypothesis_id=str(row["hypothesis_id"]),
                strategy_id=str(row["strategy_id"]),
                setup_id=str(row["setup_id"]),
                strategy_version=str(row["strategy_version"]),
                session=str(row["session"]),
                market_regime=str(row["market_regime"]),
                symbol=str(row["symbol"]),
                side=side,
                volume=volume,
                entry_price=entry_price,
                exit_price=exit_price,
                initial_stop_loss=initial_stop,
                opened_at=datetime.fromisoformat(str(row["opened_at"])),
                closed_at=at,
                pnl=pnl,
                r_multiple=current_r,
                mfe_r=mfe_r,
                mae_r=mae_r,
            )
            reason = "SL" if hit_stop else "TP"
            closing_payload = {
                "proposal_id": record.proposal_id,
                "trade_id": record.trade_id,
                "reason": reason,
                "exit_price": record.exit_price,
                "pnl": record.pnl,
                "r_multiple": record.r_multiple,
                "mfe_r": record.mfe_r,
                "mae_r": record.mae_r,
                "closed_at": at.isoformat(),
            }
            self._audit.append("paper_position_close_authorized", closing_payload)
            self._store.close_paper_position(record, reason=reason)
            self._audit.append(
                "paper_position_closed",
                closing_payload,
            )
            closed.append(record)
        return closed

    def modify(
        self,
        ticket: int,
        *,
        stop_loss: float,
        take_profit: float | None,
        at: datetime | None = None,
    ) -> None:
        with self._lock:
            row = next(
                (
                    item for item in self._store.list_open_paper_positions()
                    if self._ticket(str(item["proposal_id"])) == ticket
                ),
                None,
            )
            if row is None:
                raise LookupError("Paper position was not found")
            at = at or datetime.now().astimezone()
            payload = {
                "proposal_id": str(row["proposal_id"]),
                "ticket": ticket,
                "old_stop_loss": float(row["current_stop_loss"]),
                "new_stop_loss": stop_loss,
                "take_profit": take_profit,
                "updated_at": at.isoformat(),
            }
            self._audit.append("paper_position_modify_authorized", payload)
            self._store.update_paper_protection(
                str(row["proposal_id"]),
                stop_loss=stop_loss,
                take_profit=take_profit,
                updated_at=at,
            )
            self._audit.append("paper_position_modified", payload)

    def close(
        self,
        ticket: int,
        market: SymbolSnapshot,
        *,
        at: datetime | None = None,
    ) -> TradeResultRecord:
        with self._lock:
            row = next(
                (
                    item for item in self._store.list_open_paper_positions()
                    if self._ticket(str(item["proposal_id"])) == ticket
                ),
                None,
            )
            if row is None:
                raise LookupError("Paper position was not found")
            at = at or datetime.now().astimezone()
            side = Side(str(row["side"]))
            direction = 1.0 if side is Side.BUY else -1.0
            exit_price = market.bid if side is Side.BUY else market.ask
            entry_price = float(row["entry_price"])
            initial_stop = float(row["initial_stop_loss"])
            risk_distance = abs(entry_price - initial_stop)
            tick_size = float(row["tick_size"])
            tick_value = float(row["tick_value"])
            volume = float(row["volume"])
            if min(risk_distance, tick_size, tick_value, volume) <= 0:
                raise ValueError("Persisted paper economics are invalid")
            current_r = direction * (exit_price - entry_price) / risk_distance
            mfe_r = max(float(row["mfe_r"]), current_r, 0.0)
            mae_r = min(float(row["mae_r"]), current_r, 0.0)
            pnl = direction * (exit_price - entry_price) / tick_size * tick_value * volume
            record = TradeResultRecord(
                trade_id=str(row["paper_trade_id"]),
                proposal_id=str(row["proposal_id"]),
                hypothesis_id=str(row["hypothesis_id"]),
                strategy_id=str(row["strategy_id"]),
                setup_id=str(row["setup_id"]),
                strategy_version=str(row["strategy_version"]),
                session=str(row["session"]),
                market_regime=str(row["market_regime"]),
                symbol=str(row["symbol"]),
                side=side,
                volume=volume,
                entry_price=entry_price,
                exit_price=exit_price,
                initial_stop_loss=initial_stop,
                opened_at=datetime.fromisoformat(str(row["opened_at"])),
                closed_at=at,
                pnl=pnl,
                r_multiple=current_r,
                mfe_r=mfe_r,
                mae_r=mae_r,
            )
            payload = {
                "proposal_id": record.proposal_id,
                "trade_id": record.trade_id,
                "reason": "MANUAL",
                "exit_price": record.exit_price,
                "pnl": record.pnl,
                "r_multiple": record.r_multiple,
                "mfe_r": record.mfe_r,
                "mae_r": record.mae_r,
                "closed_at": at.isoformat(),
            }
            self._audit.append("paper_position_close_authorized", payload)
            self._store.close_paper_position(record, reason="MANUAL")
            self._audit.append("paper_position_closed", payload)
            return record
