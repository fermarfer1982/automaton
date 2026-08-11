from __future__ import annotations

import math
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

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
        now = datetime.now().astimezone().isoformat()
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
        target_day = day or datetime.now().astimezone().date()
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT pnl, closed_at FROM trade_results WHERE trade_id LIKE 'paper:%'"
            ).fetchall()
        total = 0.0
        for row in rows:
            closed_at = datetime.fromisoformat(str(row["closed_at"]))
            if closed_at.astimezone().date() == target_day:
                total += float(row["pnl"])
        return total

    def health(self) -> bool:
        try:
            with closing(self._connect()) as connection:
                version = connection.execute("SELECT MAX(version) FROM research_schema").fetchone()[0]
            return version == 2
        except sqlite3.Error:
            return False
