from __future__ import annotations

import json
import math
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from .domain import Side, SymbolSnapshot, TradingMode, TradeProposal


MIN_EVIDENCE_SAMPLE = 30


@dataclass(frozen=True)
class TradeResultRecord:
    trade_id: str
    proposal_id: str
    hypothesis_id: str
    strategy_id: str
    setup_id: str
    strategy_version: str
    session: str
    market_regime: str
    symbol: str
    side: Side
    volume: float
    entry_price: float
    exit_price: float
    initial_stop_loss: float
    opened_at: datetime
    closed_at: datetime
    pnl: float
    r_multiple: float
    mfe_r: float
    mae_r: float


@dataclass(frozen=True)
class StrategyMetrics:
    strategy_id: str
    strategy_version: str
    sample_size: int
    total_pnl: float
    expectancy_pnl: float | None
    expectancy_r: float | None
    profit_factor: float | None
    win_rate: float | None
    average_mfe_r: float | None
    average_mae_r: float | None
    max_drawdown: float
    evidence_sufficient: bool
    minimum_evidence_sample: int = MIN_EVIDENCE_SAMPLE


_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS research_schema (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO research_schema(version) VALUES (1);
CREATE TABLE IF NOT EXISTS hypotheses (
  hypothesis_id TEXT PRIMARY KEY,
  thesis TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS proposals (
  proposal_id TEXT PRIMARY KEY,
  hypothesis_id TEXT NOT NULL,
  strategy_id TEXT NOT NULL,
  setup_id TEXT NOT NULL,
  strategy_version TEXT NOT NULL,
  session TEXT NOT NULL,
  market_regime TEXT NOT NULL,
  symbol TEXT NOT NULL CHECK(symbol = 'XAUUSD'),
  side TEXT NOT NULL CHECK(side IN ('BUY', 'SELL')),
  volume REAL NOT NULL,
  stop_loss REAL,
  take_profit REAL,
  mode TEXT NOT NULL,
  status TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  estimated_risk_amount REAL NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_proposals_strategy
  ON proposals(strategy_id, strategy_version, created_at);
CREATE TABLE IF NOT EXISTS trade_results (
  trade_id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL,
  hypothesis_id TEXT NOT NULL,
  strategy_id TEXT NOT NULL,
  setup_id TEXT NOT NULL,
  strategy_version TEXT NOT NULL,
  session TEXT NOT NULL,
  market_regime TEXT NOT NULL,
  symbol TEXT NOT NULL CHECK(symbol = 'XAUUSD'),
  side TEXT NOT NULL CHECK(side IN ('BUY', 'SELL')),
  volume REAL NOT NULL,
  entry_price REAL NOT NULL,
  exit_price REAL NOT NULL,
  initial_stop_loss REAL NOT NULL,
  opened_at TEXT NOT NULL,
  closed_at TEXT NOT NULL,
  pnl REAL NOT NULL,
  r_multiple REAL NOT NULL,
  mfe_r REAL NOT NULL,
  mae_r REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trade_results_strategy
  ON trade_results(strategy_id, strategy_version, closed_at);
CREATE TABLE IF NOT EXISTS paper_positions (
  proposal_id TEXT PRIMARY KEY,
  paper_trade_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK(status IN ('OPEN', 'CLOSED_TP', 'CLOSED_SL')),
  entry_price REAL NOT NULL,
  initial_stop_loss REAL NOT NULL,
  take_profit REAL,
  tick_size REAL NOT NULL,
  tick_value REAL NOT NULL,
  volume REAL NOT NULL,
  mfe_r REAL NOT NULL DEFAULT 0,
  mae_r REAL NOT NULL DEFAULT 0,
  opened_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_paper_positions_status
  ON paper_positions(status, updated_at);
INSERT OR IGNORE INTO research_schema(version) VALUES (2);
CREATE TABLE IF NOT EXISTS idempotency_requests (
  idempotency_key TEXT PRIMARY KEY,
  request_hash TEXT NOT NULL,
  proposal_id TEXT NOT NULL UNIQUE,
  response_json TEXT,
  created_at_utc TEXT NOT NULL,
  completed_at_utc TEXT
);
CREATE TABLE IF NOT EXISTS lifecycle_events (
  event_id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL,
  state TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_proposal
  ON lifecycle_events(proposal_id, created_at_utc, event_id);
CREATE TRIGGER IF NOT EXISTS lifecycle_events_no_update
BEFORE UPDATE ON lifecycle_events
BEGIN SELECT RAISE(ABORT, 'lifecycle events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS lifecycle_events_no_delete
BEFORE DELETE ON lifecycle_events
BEGIN SELECT RAISE(ABORT, 'lifecycle events are append-only'); END;
CREATE TABLE IF NOT EXISTS agent_decisions (
  decision_id TEXT PRIMARY KEY,
  action TEXT NOT NULL CHECK(action IN ('HOLD', 'PROPOSE')),
  symbol TEXT NOT NULL CHECK(symbol = 'XAUUSD'),
  timeframe TEXT NOT NULL,
  bar_time_utc TEXT NOT NULL,
  reason TEXT NOT NULL,
  hypothesis_id TEXT,
  created_at_utc TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS agent_decisions_no_update
BEFORE UPDATE ON agent_decisions
BEGIN SELECT RAISE(ABORT, 'agent decisions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS agent_decisions_no_delete
BEFORE DELETE ON agent_decisions
BEGIN SELECT RAISE(ABORT, 'agent decisions are append-only'); END;
CREATE TABLE IF NOT EXISTS trade_reviews (
  review_id TEXT PRIMARY KEY,
  trade_id TEXT NOT NULL,
  expected TEXT NOT NULL,
  observed TEXT NOT NULL,
  errors TEXT NOT NULL,
  strengths TEXT NOT NULL,
  learning TEXT NOT NULL,
  hypothesis_effect TEXT NOT NULL,
  created_at_utc TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS trade_reviews_no_update
BEFORE UPDATE ON trade_reviews
BEGIN SELECT RAISE(ABORT, 'trade reviews are append-only'); END;
CREATE TRIGGER IF NOT EXISTS trade_reviews_no_delete
BEFORE DELETE ON trade_reviews
BEGIN SELECT RAISE(ABORT, 'trade reviews are append-only'); END;
CREATE TABLE IF NOT EXISTS memory_items (
  memory_id TEXT PRIMARY KEY,
  category TEXT NOT NULL CHECK(category IN ('EPISODIC', 'SEMANTIC', 'PROCEDURAL', 'HYPOTHESIS')),
  subject_id TEXT NOT NULL,
  content TEXT NOT NULL,
  evidence_sample_size INTEGER NOT NULL DEFAULT 0,
  evidence_eligible INTEGER NOT NULL DEFAULT 0 CHECK(evidence_eligible IN (0, 1)),
  created_at_utc TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS memory_items_no_update
BEFORE UPDATE ON memory_items
BEGIN SELECT RAISE(ABORT, 'memory items are append-only'); END;
CREATE TRIGGER IF NOT EXISTS memory_items_no_delete
BEFORE DELETE ON memory_items
BEGIN SELECT RAISE(ABORT, 'memory items are append-only'); END;
INSERT OR IGNORE INTO research_schema(version) VALUES (3);
"""


class ResearchStore:
    """Gateway-owned SQLite memory for reproducible trading evidence."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with closing(self._connect()) as connection:
            connection.executescript(_SCHEMA)
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @staticmethod
    def _validate_finite(values: dict[str, float]) -> None:
        invalid = [name for name, value in values.items() if not math.isfinite(value)]
        if invalid:
            raise ValueError(f"Non-finite research values: {', '.join(invalid)}")

    def record_proposal(
        self,
        proposal: TradeProposal,
        *,
        mode: TradingMode,
        status: str,
        fingerprint: str,
        estimated_risk_amount: float,
    ) -> None:
        self._validate_finite({
            "volume": proposal.volume,
            "estimated_risk_amount": estimated_risk_amount,
        })
        now = datetime.now(UTC).isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO hypotheses(hypothesis_id, thesis, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(hypothesis_id) DO UPDATE SET
                  thesis=excluded.thesis,
                  updated_at=excluded.updated_at
                """,
                (proposal.hypothesis_id, proposal.thesis, now, now),
            )
            connection.execute(
                """
                INSERT INTO proposals(
                  proposal_id, hypothesis_id, strategy_id, setup_id, strategy_version,
                  session, market_regime, symbol, side, volume, stop_loss, take_profit,
                  mode, status, fingerprint, estimated_risk_amount, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(proposal_id) DO UPDATE SET
                  status=excluded.status,
                  estimated_risk_amount=excluded.estimated_risk_amount,
                  updated_at=excluded.updated_at
                """,
                (
                    proposal.proposal_id, proposal.hypothesis_id, proposal.strategy_id,
                    proposal.setup_id, proposal.strategy_version, proposal.session,
                    proposal.market_regime, proposal.symbol, proposal.side.value,
                    proposal.volume, proposal.stop_loss, proposal.take_profit,
                    mode.value, status, fingerprint, estimated_risk_amount, now, now,
                ),
            )
            connection.commit()

    def get_proposal(self, proposal_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
        return dict(row) if row else None

    def reserve_idempotency(
        self,
        idempotency_key: str,
        request_hash: str,
        proposal_id: str,
    ) -> tuple[str, str, dict[str, Any] | None]:
        """Return NEW, EXISTING, or CONFLICT without ever re-executing a request."""
        now = datetime.now(UTC).isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_hash, proposal_id, response_json FROM idempotency_requests WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO idempotency_requests(
                      idempotency_key, request_hash, proposal_id, created_at_utc
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (idempotency_key, request_hash, proposal_id, now),
                )
                connection.commit()
                return "NEW", proposal_id, None
            connection.commit()
            if str(row["request_hash"]) != request_hash:
                return "CONFLICT", str(row["proposal_id"]), None
            response = json.loads(str(row["response_json"])) if row["response_json"] else None
            return "EXISTING", str(row["proposal_id"]), response

    def complete_idempotency(self, idempotency_key: str, response: dict[str, Any]) -> None:
        encoded = json.dumps(response, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._lock, closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                UPDATE idempotency_requests
                SET response_json = ?, completed_at_utc = ?
                WHERE idempotency_key = ? AND response_json IS NULL
                """,
                (encoded, datetime.now(UTC).isoformat(), idempotency_key),
            )
            if cursor.rowcount != 1:
                raise ValueError("Idempotency request is absent or already completed")
            connection.commit()

    def append_lifecycle(
        self,
        event_id: str,
        proposal_id: str,
        state: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        encoded = json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO lifecycle_events(event_id, proposal_id, state, payload_json, created_at_utc)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_id, proposal_id, state, encoded, datetime.now(UTC).isoformat()),
            )
            connection.commit()

    def record_agent_decision(
        self,
        *,
        decision_id: str,
        action: str,
        symbol: str,
        timeframe: str,
        bar_time_utc: str,
        reason: str,
        hypothesis_id: str | None,
    ) -> None:
        if action not in {"HOLD", "PROPOSE"} or symbol != "XAUUSD":
            raise ValueError("Unsupported structured agent decision")
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO agent_decisions(
                  decision_id, action, symbol, timeframe, bar_time_utc,
                  reason, hypothesis_id, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id, action, symbol, timeframe, bar_time_utc,
                    reason, hypothesis_id, datetime.now(UTC).isoformat(),
                ),
            )
            connection.commit()

    def recent_memory(self, limit: int = 50) -> list[dict[str, Any]]:
        if limit < 1 or limit > 200:
            raise ValueError("Memory limit must be between 1 and 200")
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM memory_items ORDER BY created_at_utc DESC, memory_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def save_hypothesis(self, hypothesis_id: str, thesis: str) -> None:
        thesis = thesis.strip()
        if not thesis or len(thesis) > 4000:
            raise ValueError("Hypothesis thesis must contain 1..4000 characters")
        now = datetime.now(UTC).isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT thesis FROM hypotheses WHERE hypothesis_id = ?", (hypothesis_id,)
            ).fetchone()
            if existing is not None and str(existing["thesis"]) != thesis:
                raise ValueError("Hypothesis IDs are immutable; create a new version")
            connection.execute(
                """
                INSERT OR IGNORE INTO hypotheses(hypothesis_id, thesis, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (hypothesis_id, thesis, now, now),
            )
            connection.execute(
                """
                INSERT INTO memory_items(
                  memory_id, category, subject_id, content, created_at_utc
                ) VALUES (?, 'HYPOTHESIS', ?, ?, ?)
                """,
                (str(uuid4()), hypothesis_id, thesis, now),
            )
            connection.commit()

    def save_trade_review(
        self,
        *,
        review_id: str,
        trade_id: str,
        expected: str,
        observed: str,
        errors: str,
        strengths: str,
        learning: str,
        hypothesis_effect: str,
    ) -> None:
        values = (expected, observed, errors, strengths, learning, hypothesis_effect)
        if any(len(item) > 4000 for item in values):
            raise ValueError("Trade review field exceeds 4000 characters")
        now = datetime.now(UTC).isoformat()
        content = json.dumps({
            "expected": expected, "observed": observed, "errors": errors,
            "strengths": strengths, "learning": learning,
            "hypothesis_effect": hypothesis_effect,
        }, sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO trade_reviews(
                  review_id, trade_id, expected, observed, errors, strengths,
                  learning, hypothesis_effect, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    review_id, trade_id, expected, observed, errors, strengths,
                    learning, hypothesis_effect, now,
                ),
            )
            connection.execute(
                """
                INSERT INTO memory_items(
                  memory_id, category, subject_id, content, created_at_utc
                ) VALUES (?, 'EPISODIC', ?, ?, ?)
                """,
                (str(uuid4()), trade_id, content, now),
            )
            connection.commit()

    def record_trade_result(self, record: TradeResultRecord) -> None:
        self._validate_trade_result(record)
        with self._lock, closing(self._connect()) as connection:
            self._insert_trade_result(connection, record)
            connection.commit()

    def _validate_trade_result(self, record: TradeResultRecord) -> None:
        if record.symbol != "XAUUSD":
            raise ValueError("Research store currently accepts only XAUUSD")
        if record.closed_at < record.opened_at:
            raise ValueError("closed_at cannot precede opened_at")
        self._validate_finite({
            "volume": record.volume,
            "entry_price": record.entry_price,
            "exit_price": record.exit_price,
            "initial_stop_loss": record.initial_stop_loss,
            "pnl": record.pnl,
            "r_multiple": record.r_multiple,
            "mfe_r": record.mfe_r,
            "mae_r": record.mae_r,
        })

    @staticmethod
    def _insert_trade_result(connection: sqlite3.Connection, record: TradeResultRecord) -> None:
        connection.execute(
            """
            INSERT INTO trade_results(
              trade_id, proposal_id, hypothesis_id, strategy_id, setup_id,
              strategy_version, session, market_regime, symbol, side, volume,
              entry_price, exit_price, initial_stop_loss, opened_at, closed_at,
              pnl, r_multiple, mfe_r, mae_r
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.trade_id, record.proposal_id, record.hypothesis_id,
                record.strategy_id, record.setup_id, record.strategy_version,
                record.session, record.market_regime, record.symbol,
                record.side.value, record.volume, record.entry_price,
                record.exit_price, record.initial_stop_loss,
                record.opened_at.isoformat(), record.closed_at.isoformat(),
                record.pnl, record.r_multiple, record.mfe_r, record.mae_r,
            ),
        )

    def open_paper_position(
        self,
        proposal: TradeProposal,
        market: SymbolSnapshot,
        *,
        opened_at: datetime,
    ) -> None:
        if proposal.stop_loss is None:
            raise ValueError("Paper position requires a stop loss")
        entry_price = market.ask if proposal.side is Side.BUY else market.bid
        self._validate_finite({
            "entry_price": entry_price,
            "stop_loss": proposal.stop_loss,
            "tick_size": market.tick_size,
            "tick_value": market.tick_value,
            "volume": proposal.volume,
        })
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO paper_positions(
                  proposal_id, paper_trade_id, status, entry_price,
                  initial_stop_loss, take_profit, tick_size, tick_value, volume,
                  mfe_r, mae_r, opened_at, updated_at
                ) VALUES (?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
                """,
                (
                    proposal.proposal_id, f"paper:{proposal.proposal_id}", entry_price,
                    proposal.stop_loss, proposal.take_profit, market.tick_size,
                    market.tick_value, proposal.volume, opened_at.isoformat(),
                    opened_at.isoformat(),
                ),
            )
            connection.commit()

    def list_open_paper_positions(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT pp.*, p.hypothesis_id, p.strategy_id, p.setup_id,
                       p.strategy_version, p.session, p.market_regime,
                       p.symbol, p.side
                FROM paper_positions pp
                JOIN proposals p ON p.proposal_id = pp.proposal_id
                WHERE pp.status = 'OPEN'
                ORDER BY pp.opened_at, pp.proposal_id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def update_paper_excursions(
        self,
        proposal_id: str,
        *,
        mfe_r: float,
        mae_r: float,
        updated_at: datetime,
    ) -> None:
        self._validate_finite({"mfe_r": mfe_r, "mae_r": mae_r})
        with self._lock, closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                UPDATE paper_positions
                SET mfe_r = ?, mae_r = ?, updated_at = ?
                WHERE proposal_id = ? AND status = 'OPEN'
                """,
                (mfe_r, mae_r, updated_at.isoformat(), proposal_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Open paper position not found")
            connection.commit()

    def close_paper_position(
        self,
        record: TradeResultRecord,
        *,
        reason: str,
    ) -> None:
        if reason not in {"TP", "SL"}:
            raise ValueError("Paper close reason must be TP or SL")
        self._validate_trade_result(record)
        with self._lock, closing(self._connect()) as connection:
            self._insert_trade_result(connection, record)
            cursor = connection.execute(
                """
                UPDATE paper_positions
                SET status = ?, mfe_r = ?, mae_r = ?, updated_at = ?, closed_at = ?
                WHERE proposal_id = ? AND status = 'OPEN'
                """,
                (
                    f"CLOSED_{reason}", record.mfe_r, record.mae_r,
                    record.closed_at.isoformat(), record.closed_at.isoformat(),
                    record.proposal_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("Open paper position not found")
            connection.commit()

    def strategy_metrics(self, strategy_id: str, strategy_version: str) -> StrategyMetrics:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT pnl, r_multiple, mfe_r, mae_r
                FROM trade_results
                WHERE strategy_id = ? AND strategy_version = ?
                ORDER BY closed_at, trade_id
                """,
                (strategy_id, strategy_version),
            ).fetchall()
        if not rows:
            return StrategyMetrics(
                strategy_id=strategy_id,
                strategy_version=strategy_version,
                sample_size=0,
                total_pnl=0.0,
                expectancy_pnl=None,
                expectancy_r=None,
                profit_factor=None,
                win_rate=None,
                average_mfe_r=None,
                average_mae_r=None,
                max_drawdown=0.0,
                evidence_sufficient=False,
            )
        pnl = [float(row["pnl"]) for row in rows]
        r_values = [float(row["r_multiple"]) for row in rows]
        gross_profit = sum(value for value in pnl if value > 0)
        gross_loss = abs(sum(value for value in pnl if value < 0))
        cumulative = 0.0
        peak = 0.0
        max_drawdown = 0.0
        for value in pnl:
            cumulative += value
            peak = max(peak, cumulative)
            max_drawdown = max(max_drawdown, peak - cumulative)
        sample = len(rows)
        return StrategyMetrics(
            strategy_id=strategy_id,
            strategy_version=strategy_version,
            sample_size=sample,
            total_pnl=sum(pnl),
            expectancy_pnl=sum(pnl) / sample,
            expectancy_r=sum(r_values) / sample,
            profit_factor=gross_profit / gross_loss if gross_loss > 0 else None,
            win_rate=sum(1 for value in pnl if value > 0) / sample,
            average_mfe_r=sum(float(row["mfe_r"]) for row in rows) / sample,
            average_mae_r=sum(float(row["mae_r"]) for row in rows) / sample,
            max_drawdown=max_drawdown,
            evidence_sufficient=sample >= MIN_EVIDENCE_SAMPLE,
        )

    def all_strategy_metrics(self) -> list[StrategyMetrics]:
        with closing(self._connect()) as connection:
            groups = connection.execute(
                "SELECT DISTINCT strategy_id, strategy_version FROM trade_results ORDER BY strategy_id, strategy_version"
            ).fetchall()
        return [
            self.strategy_metrics(str(row["strategy_id"]), str(row["strategy_version"]))
            for row in groups
        ]

    def paper_daily_realized_pnl(self, day: date | None = None) -> float:
        """Return closed PAPER PnL for the local calendar day."""
        target_day = day or datetime.now(UTC).date()
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT pnl, closed_at FROM trade_results WHERE trade_id LIKE 'paper:%'"
            ).fetchall()
        total = 0.0
        for row in rows:
            closed_at = datetime.fromisoformat(str(row["closed_at"]))
            if closed_at.astimezone(UTC).date() == target_day:
                total += float(row["pnl"])
        return total

    def health(self) -> bool:
        try:
            with closing(self._connect()) as connection:
                version = connection.execute("SELECT MAX(version) FROM research_schema").fetchone()[0]
            return version == 3
        except sqlite3.Error:
            return False
