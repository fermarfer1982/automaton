from __future__ import annotations

import json
import hashlib
import math
import random
import sqlite3
import statistics
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
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
    gross_pnl: float | None = None
    commission: float = 0.0
    swap: float = 0.0
    fee: float = 0.0
    entry_spread_points: float | None = None
    exit_spread_points: float | None = None
    timeframe: str = "UNKNOWN"
    atr_at_entry: float | None = None
    stop_distance_points: float | None = None
    initial_reward_risk: float | None = None
    primary_session: str | None = None
    active_sessions: str = "[]"
    data_quality: str = "UNKNOWN"
    confidence: float = 0.0
    exit_session: str = "UNKNOWN"
    exit_active_sessions: str = "[]"
    tp_distance_points: float | None = None
    volatility_regime: str = "UNCLASSIFIED"
    agent_version: str = "trading-profile-v1"


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
    wins: int
    losses: int
    median_duration_seconds: float | None
    expectancy_r_ci95_low: float | None
    expectancy_r_ci95_high: float | None
    evidence_sufficient: bool
    minimum_evidence_sample: int = MIN_EVIDENCE_SAMPLE


@dataclass(frozen=True)
class MarketExperienceRecord:
    experience_id: str
    symbol: str
    timeframe: str
    bar_time_utc: datetime
    reference_price: float
    point: float
    spread_points: float
    session: str
    features: dict[str, Any]
    feature_version: int = 1


@dataclass(frozen=True)
class ExperienceOutcomeRecord:
    experience_id: str
    horizon_minutes: int
    future_bar_time_utc: datetime
    future_close: float
    window_high: float
    window_low: float


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
CREATE TRIGGER IF NOT EXISTS trade_results_no_update
BEFORE UPDATE ON trade_results
BEGIN SELECT RAISE(ABORT, 'trade results are append-only'); END;
CREATE TRIGGER IF NOT EXISTS trade_results_no_delete
BEFORE DELETE ON trade_results
BEGIN SELECT RAISE(ABORT, 'trade results are append-only'); END;
CREATE TRIGGER IF NOT EXISTS hypotheses_no_update
BEFORE UPDATE ON hypotheses
BEGIN SELECT RAISE(ABORT, 'hypotheses are immutable; create a new version'); END;
CREATE TRIGGER IF NOT EXISTS hypotheses_no_delete
BEFORE DELETE ON hypotheses
BEGIN SELECT RAISE(ABORT, 'hypotheses are append-only'); END;
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
            self._migrate_schema(connection)
            connection.commit()

    @staticmethod
    def _migrate_schema(connection: sqlite3.Connection) -> None:
        version = int(connection.execute(
            "SELECT COALESCE(MAX(version), 0) FROM research_schema"
        ).fetchone()[0])
        if version < 4:
            connection.executescript(
            """
            BEGIN IMMEDIATE;
            DROP INDEX IF EXISTS idx_paper_positions_status;
            CREATE TABLE paper_positions_v4 (
              proposal_id TEXT PRIMARY KEY,
              paper_trade_id TEXT NOT NULL UNIQUE,
              status TEXT NOT NULL CHECK(status IN (
                'OPEN', 'CLOSED_TP', 'CLOSED_SL', 'CLOSED_MANUAL'
              )),
              entry_price REAL NOT NULL,
              initial_stop_loss REAL NOT NULL,
              current_stop_loss REAL NOT NULL,
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
            INSERT INTO paper_positions_v4(
              proposal_id, paper_trade_id, status, entry_price,
              initial_stop_loss, current_stop_loss, take_profit, tick_size,
              tick_value, volume, mfe_r, mae_r, opened_at, updated_at, closed_at
            )
            SELECT proposal_id, paper_trade_id, status, entry_price,
                   initial_stop_loss, initial_stop_loss, take_profit, tick_size,
                   tick_value, volume, mfe_r, mae_r, opened_at, updated_at, closed_at
            FROM paper_positions;
            DROP TABLE paper_positions;
            ALTER TABLE paper_positions_v4 RENAME TO paper_positions;
            CREATE INDEX idx_paper_positions_status
              ON paper_positions(status, updated_at);
            INSERT OR IGNORE INTO research_schema(version) VALUES (4);
            COMMIT;
            """
            )
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS daily_risk_state (
              date_utc TEXT PRIMARY KEY,
              currency TEXT NOT NULL,
              start_equity REAL NOT NULL,
              peak_equity REAL NOT NULL,
              last_equity REAL NOT NULL,
              balance REAL NOT NULL,
              updated_at_utc TEXT NOT NULL
            );
            INSERT OR IGNORE INTO research_schema(version) VALUES (5);
            """
        )
        trade_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(trade_results)")
        }
        additions = {
            "gross_pnl": "REAL",
            "commission": "REAL NOT NULL DEFAULT 0",
            "swap": "REAL NOT NULL DEFAULT 0",
            "fee": "REAL NOT NULL DEFAULT 0",
            "entry_spread_points": "REAL",
            "exit_spread_points": "REAL",
            "timeframe": "TEXT NOT NULL DEFAULT 'UNKNOWN'",
            "atr_at_entry": "REAL",
            "stop_distance_points": "REAL",
            "initial_reward_risk": "REAL",
            "primary_session": "TEXT",
            "active_sessions": "TEXT NOT NULL DEFAULT '[]'",
            "data_quality": "TEXT NOT NULL DEFAULT 'UNKNOWN'",
            "duration_seconds": "REAL NOT NULL DEFAULT 0",
            "weekday_utc": "INTEGER NOT NULL DEFAULT 0",
            "hour_utc": "INTEGER NOT NULL DEFAULT 0",
            "confidence": "REAL NOT NULL DEFAULT 0",
            "exit_session": "TEXT NOT NULL DEFAULT 'UNKNOWN'",
            "exit_active_sessions": "TEXT NOT NULL DEFAULT '[]'",
            "tp_distance_points": "REAL",
            "volatility_regime": "TEXT NOT NULL DEFAULT 'UNCLASSIFIED'",
            "agent_version": "TEXT NOT NULL DEFAULT 'trading-profile-v1'",
        }
        for name, declaration in additions.items():
            if name not in trade_columns:
                connection.execute(
                    f"ALTER TABLE trade_results ADD COLUMN {name} {declaration}"
                )
        connection.execute(
            "INSERT OR IGNORE INTO research_schema(version) VALUES (6)"
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_decision_closed_bar
            ON agent_decisions(symbol, timeframe, bar_time_utc)
            """
        )
        connection.execute(
            "INSERT OR IGNORE INTO research_schema(version) VALUES (7)"
        )
        proposal_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(proposals)")
        }
        proposal_additions = {
            "confidence": "REAL NOT NULL DEFAULT 0",
            "timeframe": "TEXT NOT NULL DEFAULT 'UNKNOWN'",
            "active_sessions": "TEXT NOT NULL DEFAULT '[]'",
            "atr_at_entry": "REAL",
            "entry_spread_points": "REAL",
            "point_at_entry": "REAL",
            "stop_distance_points": "REAL",
            "initial_reward_risk": "REAL",
            "volatility_regime": "TEXT NOT NULL DEFAULT 'UNCLASSIFIED'",
            "data_quality": "TEXT NOT NULL DEFAULT 'UNKNOWN'",
            "agent_version": "TEXT NOT NULL DEFAULT 'trading-profile-v1'",
        }
        for name, declaration in proposal_additions.items():
            if name not in proposal_columns:
                connection.execute(
                    f"ALTER TABLE proposals ADD COLUMN {name} {declaration}"
                )
        connection.execute(
            "INSERT OR IGNORE INTO research_schema(version) VALUES (8)"
        )
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS market_experiences (
              experience_id TEXT PRIMARY KEY,
              symbol TEXT NOT NULL CHECK(symbol = 'XAUUSD'),
              timeframe TEXT NOT NULL CHECK(timeframe = 'M1'),
              bar_time_utc TEXT NOT NULL,
              reference_price REAL NOT NULL CHECK(reference_price > 0),
              point REAL NOT NULL CHECK(point > 0),
              spread_points REAL NOT NULL CHECK(spread_points >= 0),
              session TEXT NOT NULL,
              features_json TEXT NOT NULL,
              created_at_utc TEXT NOT NULL,
              UNIQUE(symbol, timeframe, bar_time_utc)
            );
            CREATE INDEX IF NOT EXISTS idx_market_experiences_bar
              ON market_experiences(bar_time_utc, experience_id);
            CREATE TRIGGER IF NOT EXISTS market_experiences_no_update
            BEFORE UPDATE ON market_experiences
            BEGIN
              SELECT RAISE(ABORT, 'market experiences are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS market_experiences_no_delete
            BEFORE DELETE ON market_experiences
            BEGIN
              SELECT RAISE(ABORT, 'market experiences are append-only');
            END;

            CREATE TABLE IF NOT EXISTS experience_outcomes (
              experience_id TEXT NOT NULL,
              horizon_minutes INTEGER NOT NULL
                CHECK(horizon_minutes IN (5, 15, 60)),
              future_bar_time_utc TEXT NOT NULL,
              future_close REAL NOT NULL CHECK(future_close > 0),
              window_high REAL NOT NULL CHECK(window_high > 0),
              window_low REAL NOT NULL CHECK(window_low > 0),
              return_points REAL NOT NULL,
              mfe_long_points REAL NOT NULL CHECK(mfe_long_points >= 0),
              mae_long_points REAL NOT NULL CHECK(mae_long_points <= 0),
              created_at_utc TEXT NOT NULL,
              PRIMARY KEY(experience_id, horizon_minutes),
              FOREIGN KEY(experience_id)
                REFERENCES market_experiences(experience_id)
            );
            CREATE INDEX IF NOT EXISTS idx_experience_outcomes_horizon
              ON experience_outcomes(horizon_minutes, future_bar_time_utc);
            CREATE TRIGGER IF NOT EXISTS experience_outcomes_no_update
            BEFORE UPDATE ON experience_outcomes
            BEGIN
              SELECT RAISE(ABORT, 'experience outcomes are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS experience_outcomes_no_delete
            BEFORE DELETE ON experience_outcomes
            BEGIN
              SELECT RAISE(ABORT, 'experience outcomes are append-only');
            END;

            INSERT OR IGNORE INTO research_schema(version) VALUES (9);
            """
        )

        version = int(connection.execute(
            "SELECT COALESCE(MAX(version), 0) FROM research_schema"
        ).fetchone()[0])

        if version < 10:
            connection.commit()
            foreign_keys_enabled = bool(
                connection.execute(
                    "PRAGMA foreign_keys"
                ).fetchone()[0]
            )
            if foreign_keys_enabled:
                connection.execute(
                    "PRAGMA foreign_keys=OFF"
                )

            try:
                connection.execute("BEGIN IMMEDIATE")

                connection.execute(
                    """
                    CREATE TABLE market_experiences_v10 (
                      experience_id TEXT PRIMARY KEY,
                      symbol TEXT NOT NULL
                        CHECK(symbol = 'XAUUSD'),
                      timeframe TEXT NOT NULL
                        CHECK(timeframe = 'M1'),
                      bar_time_utc TEXT NOT NULL,
                      feature_version INTEGER NOT NULL
                        CHECK(feature_version >= 1),
                      reference_price REAL NOT NULL
                        CHECK(reference_price > 0),
                      point REAL NOT NULL CHECK(point > 0),
                      spread_points REAL NOT NULL
                        CHECK(spread_points >= 0),
                      session TEXT NOT NULL,
                      features_json TEXT NOT NULL,
                      created_at_utc TEXT NOT NULL,
                      UNIQUE(
                        symbol,
                        timeframe,
                        bar_time_utc,
                        feature_version
                      )
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE experience_outcomes_v10 (
                      experience_id TEXT NOT NULL,
                      horizon_minutes INTEGER NOT NULL
                        CHECK(
                          horizon_minutes IN (5, 15, 60)
                        ),
                      future_bar_time_utc TEXT NOT NULL,
                      future_close REAL NOT NULL
                        CHECK(future_close > 0),
                      window_high REAL NOT NULL
                        CHECK(window_high > 0),
                      window_low REAL NOT NULL
                        CHECK(window_low > 0),
                      return_points REAL NOT NULL,
                      mfe_long_points REAL NOT NULL
                        CHECK(mfe_long_points >= 0),
                      mae_long_points REAL NOT NULL
                        CHECK(mae_long_points <= 0),
                      created_at_utc TEXT NOT NULL,
                      PRIMARY KEY(
                        experience_id,
                        horizon_minutes
                      ),
                      FOREIGN KEY(experience_id)
                        REFERENCES
                          market_experiences_v10(
                            experience_id
                          )
                    )
                    """
                )

                rows = connection.execute(
                    """
                    SELECT *
                    FROM market_experiences
                    ORDER BY bar_time_utc, experience_id
                    """
                ).fetchall()

                for row in rows:
                    features = json.loads(
                        str(row["features_json"])
                    )
                    raw_feature_version = features.get(
                        "feature_version",
                        1,
                    )
                    if (
                        not isinstance(
                            raw_feature_version,
                            int,
                        )
                        or isinstance(
                            raw_feature_version,
                            bool,
                        )
                        or raw_feature_version < 1
                    ):
                        raise ValueError(
                            "Stored market experience has "
                            "invalid feature_version"
                        )

                    connection.execute(
                        """
                        INSERT INTO market_experiences_v10(
                          experience_id,
                          symbol,
                          timeframe,
                          bar_time_utc,
                          feature_version,
                          reference_price,
                          point,
                          spread_points,
                          session,
                          features_json,
                          created_at_utc
                        ) VALUES (
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                        )
                        """,
                        (
                            row["experience_id"],
                            row["symbol"],
                            row["timeframe"],
                            row["bar_time_utc"],
                            raw_feature_version,
                            row["reference_price"],
                            row["point"],
                            row["spread_points"],
                            row["session"],
                            row["features_json"],
                            row["created_at_utc"],
                        ),
                    )

                connection.execute(
                    """
                    INSERT INTO experience_outcomes_v10(
                      experience_id,
                      horizon_minutes,
                      future_bar_time_utc,
                      future_close,
                      window_high,
                      window_low,
                      return_points,
                      mfe_long_points,
                      mae_long_points,
                      created_at_utc
                    )
                    SELECT
                      experience_id,
                      horizon_minutes,
                      future_bar_time_utc,
                      future_close,
                      window_high,
                      window_low,
                      return_points,
                      mfe_long_points,
                      mae_long_points,
                      created_at_utc
                    FROM experience_outcomes
                    """
                )

                connection.execute(
                    "DROP TABLE experience_outcomes"
                )
                connection.execute(
                    "DROP TABLE market_experiences"
                )
                connection.execute(
                    """
                    ALTER TABLE market_experiences_v10
                    RENAME TO market_experiences
                    """
                )
                connection.execute(
                    """
                    ALTER TABLE experience_outcomes_v10
                    RENAME TO experience_outcomes
                    """
                )

                connection.execute(
                    """
                    CREATE INDEX idx_market_experiences_bar
                    ON market_experiences(
                      feature_version,
                      bar_time_utc,
                      experience_id
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX idx_experience_outcomes_horizon
                    ON experience_outcomes(
                      horizon_minutes,
                      future_bar_time_utc
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TRIGGER market_experiences_no_update
                    BEFORE UPDATE ON market_experiences
                    BEGIN
                      SELECT RAISE(
                        ABORT,
                        'market experiences are append-only'
                      );
                    END
                    """
                )
                connection.execute(
                    """
                    CREATE TRIGGER market_experiences_no_delete
                    BEFORE DELETE ON market_experiences
                    BEGIN
                      SELECT RAISE(
                        ABORT,
                        'market experiences are append-only'
                      );
                    END
                    """
                )
                connection.execute(
                    """
                    CREATE TRIGGER experience_outcomes_no_update
                    BEFORE UPDATE ON experience_outcomes
                    BEGIN
                      SELECT RAISE(
                        ABORT,
                        'experience outcomes are append-only'
                      );
                    END
                    """
                )
                connection.execute(
                    """
                    CREATE TRIGGER experience_outcomes_no_delete
                    BEFORE DELETE ON experience_outcomes
                    BEGIN
                      SELECT RAISE(
                        ABORT,
                        'experience outcomes are append-only'
                      );
                    END
                    """
                )

                violations = connection.execute(
                    "PRAGMA foreign_key_check"
                ).fetchall()
                if violations:
                    raise RuntimeError(
                        "Research schema v10 migration "
                        "failed foreign key validation"
                    )

                connection.execute(
                    """
                    INSERT OR IGNORE INTO research_schema(
                      version
                    ) VALUES (10)
                    """
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                if foreign_keys_enabled:
                    connection.execute(
                        "PRAGMA foreign_keys=ON"
                    )

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

    @staticmethod
    def _canonical_utc(value: datetime, *, field_name: str) -> datetime:
        if value.tzinfo is None:
            raise ValueError(f"{field_name} must be timezone-aware")
        return value.astimezone(UTC)

    @staticmethod
    def _validate_feature_version(
        value: int | None,
        *,
        allow_none: bool = False,
    ) -> int | None:
        if value is None and allow_none:
            return None
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
        ):
            raise ValueError(
                "Feature version must be a positive integer"
            )
        return value

    def record_market_experience(
        self,
        record: MarketExperienceRecord,
    ) -> None:
        if not record.experience_id.strip():
            raise ValueError("Experience ID must be non-empty")
        if record.symbol != "XAUUSD" or record.timeframe != "M1":
            raise ValueError("Market experiences support only XAUUSD M1")
        if not record.session.strip() or len(record.session) > 64:
            raise ValueError("Experience session must contain 1..64 characters")
        self._validate_finite({
            "reference_price": record.reference_price,
            "point": record.point,
            "spread_points": record.spread_points,
        })
        if (
            record.reference_price <= 0
            or record.point <= 0
            or record.spread_points < 0
        ):
            raise ValueError("Experience market economics are invalid")
        if not isinstance(record.features, dict):
            raise ValueError("Experience features must be an object")

        feature_version = self._validate_feature_version(
            record.feature_version
        )
        embedded_feature_version = record.features.get(
            "feature_version"
        )
        if (
            embedded_feature_version is not None
            and embedded_feature_version != feature_version
        ):
            raise ValueError(
                "Experience feature_version does not match "
                "its feature payload"
            )

        bar_time = self._canonical_utc(
            record.bar_time_utc,
            field_name="bar_time_utc",
        )
        if bar_time.second != 0 or bar_time.microsecond != 0:
            raise ValueError(
                "Experience bar_time_utc must align to a closed M1 bar"
            )
        features_json = json.dumps(
            record.features,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(features_json.encode("utf-8")) > 64 * 1024:
            raise ValueError("Experience features exceed 64 KiB")

        with self._lock, closing(self._connect()) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO market_experiences(
                      experience_id, symbol, timeframe, bar_time_utc,
                      feature_version, reference_price, point,
                      spread_points, session, features_json,
                      created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.experience_id,
                        record.symbol,
                        record.timeframe,
                        bar_time.isoformat(),
                        feature_version,
                        record.reference_price,
                        record.point,
                        record.spread_points,
                        record.session.strip(),
                        features_json,
                        datetime.now(UTC).isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise FileExistsError(
                    "A market experience already exists for this "
                    "closed M1 bar and feature version"
                ) from exc
            connection.commit()

    def get_market_experience(
        self,
        experience_id: str,
    ) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT * FROM market_experiences
                WHERE experience_id = ?
                """,
                (experience_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["features"] = json.loads(
            str(result.pop("features_json"))
        )
        return result

    def market_experience_bounds(
        self,
        *,
        feature_version: int | None = None,
    ) -> tuple[datetime | None, datetime | None]:
        version = self._validate_feature_version(
            feature_version,
            allow_none=True,
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT
                  MIN(bar_time_utc) AS first_bar_time_utc,
                  MAX(bar_time_utc) AS last_bar_time_utc
                FROM market_experiences
                WHERE (
                  ? IS NULL
                  OR feature_version = ?
                )
                """,
                (version, version),
            ).fetchone()

        first_raw = row["first_bar_time_utc"]
        last_raw = row["last_bar_time_utc"]

        first = (
            datetime.fromisoformat(
                str(first_raw)
            ).astimezone(UTC)
            if first_raw is not None
            else None
        )
        last = (
            datetime.fromisoformat(
                str(last_raw)
            ).astimezone(UTC)
            if last_raw is not None
            else None
        )
        return first, last

    def market_experience_bar_times(
        self,
        start_utc: datetime,
        end_utc: datetime,
        *,
        feature_version: int | None = None,
    ) -> set[str]:
        start = self._canonical_utc(
            start_utc,
            field_name="start_utc",
        )
        end = self._canonical_utc(
            end_utc,
            field_name="end_utc",
        )
        if end < start:
            raise ValueError(
                "Experience coverage end cannot precede start"
            )
        version = self._validate_feature_version(
            feature_version,
            allow_none=True,
        )

        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT bar_time_utc
                FROM market_experiences
                WHERE bar_time_utc >= ?
                  AND bar_time_utc <= ?
                  AND (
                    ? IS NULL
                    OR feature_version = ?
                  )
                ORDER BY bar_time_utc
                """,
                (
                    start.isoformat(),
                    end.isoformat(),
                    version,
                    version,
                ),
            ).fetchall()

        return {
            str(row["bar_time_utc"])
            for row in rows
        }

    def record_experience_outcome(
        self,
        record: ExperienceOutcomeRecord,
    ) -> None:
        if record.horizon_minutes not in {5, 15, 60}:
            raise ValueError(
                "Experience horizon must be 5, 15, or 60 minutes"
            )
        self._validate_finite({
            "future_close": record.future_close,
            "window_high": record.window_high,
            "window_low": record.window_low,
        })
        if min(
            record.future_close,
            record.window_high,
            record.window_low,
        ) <= 0:
            raise ValueError("Experience outcome prices must be positive")
        if not (
            record.window_low
            <= record.future_close
            <= record.window_high
        ):
            raise ValueError(
                "Future close must lie inside the outcome window"
            )

        future_time = self._canonical_utc(
            record.future_bar_time_utc,
            field_name="future_bar_time_utc",
        )

        with self._lock, closing(self._connect()) as connection:
            experience = connection.execute(
                """
                SELECT bar_time_utc, reference_price, point
                FROM market_experiences
                WHERE experience_id = ?
                """,
                (record.experience_id,),
            ).fetchone()
            if experience is None:
                raise LookupError("Market experience was not found")

            bar_time = datetime.fromisoformat(
                str(experience["bar_time_utc"])
            ).astimezone(UTC)
            expected_time = bar_time + timedelta(
                minutes=record.horizon_minutes
            )
            if future_time != expected_time:
                raise ValueError(
                    "Outcome timestamp does not match its horizon"
                )

            reference_price = float(experience["reference_price"])
            point = float(experience["point"])
            return_points = (
                record.future_close - reference_price
            ) / point
            mfe_long_points = max(
                0.0,
                (record.window_high - reference_price) / point,
            )
            mae_long_points = min(
                0.0,
                (record.window_low - reference_price) / point,
            )
            self._validate_finite({
                "return_points": return_points,
                "mfe_long_points": mfe_long_points,
                "mae_long_points": mae_long_points,
            })

            try:
                connection.execute(
                    """
                    INSERT INTO experience_outcomes(
                      experience_id, horizon_minutes,
                      future_bar_time_utc, future_close,
                      window_high, window_low,
                      return_points, mfe_long_points,
                      mae_long_points, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.experience_id,
                        record.horizon_minutes,
                        future_time.isoformat(),
                        record.future_close,
                        record.window_high,
                        record.window_low,
                        return_points,
                        mfe_long_points,
                        mae_long_points,
                        datetime.now(UTC).isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise FileExistsError(
                    "This experience horizon is already recorded"
                ) from exc
            connection.commit()

    def experience_outcomes(
        self,
        experience_id: str,
    ) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT * FROM experience_outcomes
                WHERE experience_id = ?
                ORDER BY horizon_minutes
                """,
                (experience_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def pending_market_experiences(
        self,
        *,
        limit: int = 1000,
        feature_version: int | None = None,
        start_utc: datetime | None = None,
        end_utc: datetime | None = None,
        newest_first: bool = False,
    ) -> list[dict[str, Any]]:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 5000
        ):
            raise ValueError(
                "Experience pending limit must be between 1 and 5000"
            )
        if not isinstance(newest_first, bool):
            raise ValueError(
                "Experience pending newest_first must be boolean"
            )

        version = self._validate_feature_version(
            feature_version,
            allow_none=True,
        )
        start = (
            self._canonical_utc(
                start_utc,
                field_name="start_utc",
            )
            if start_utc is not None
            else None
        )
        end = (
            self._canonical_utc(
                end_utc,
                field_name="end_utc",
            )
            if end_utc is not None
            else None
        )
        if (
            start is not None
            and end is not None
            and end < start
        ):
            raise ValueError(
                "Experience pending end cannot precede start"
            )

        start_iso = start.isoformat() if start is not None else None
        end_iso = end.isoformat() if end is not None else None
        direction = "DESC" if newest_first else "ASC"

        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT me.*
                FROM market_experiences me
                WHERE (
                  ? IS NULL
                  OR me.feature_version = ?
                )
                AND (
                  ? IS NULL
                  OR me.bar_time_utc >= ?
                )
                AND (
                  ? IS NULL
                  OR me.bar_time_utc <= ?
                )
                AND (
                  SELECT COUNT(*)
                  FROM experience_outcomes eo
                  WHERE eo.experience_id = me.experience_id
                ) < 3
                ORDER BY
                  me.bar_time_utc {direction},
                  me.experience_id {direction}
                LIMIT ?
                """,
                (
                    version,
                    version,
                    start_iso,
                    start_iso,
                    end_iso,
                    end_iso,
                    limit,
                ),
            ).fetchall()
        return [dict(row) for row in rows]

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
                INSERT OR IGNORE INTO hypotheses(
                  hypothesis_id, thesis, created_at, updated_at
                ) VALUES (?, ?, ?, ?)
                """,
                (proposal.hypothesis_id, proposal.thesis, now, now),
            )
            existing_hypothesis = connection.execute(
                "SELECT thesis FROM hypotheses WHERE hypothesis_id = ?",
                (proposal.hypothesis_id,),
            ).fetchone()
            if (
                existing_hypothesis is None
                or str(existing_hypothesis["thesis"]) != proposal.thesis
            ):
                raise ValueError(
                    "Hypothesis IDs are immutable; create a new hypothesis version"
                )
            connection.execute(
                """
                INSERT INTO proposals(
                  proposal_id, hypothesis_id, strategy_id, setup_id, strategy_version,
                  session, market_regime, symbol, side, volume, stop_loss, take_profit,
                  mode, status, fingerprint, estimated_risk_amount, created_at, updated_at,
                  confidence, timeframe, active_sessions, atr_at_entry,
                  entry_spread_points, point_at_entry, stop_distance_points,
                  initial_reward_risk, volatility_regime, data_quality, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    proposal.confidence, proposal.timeframe, proposal.active_sessions,
                    proposal.atr_at_entry, proposal.entry_spread_points,
                    proposal.point_at_entry, proposal.stop_distance_points,
                    proposal.initial_reward_risk, proposal.volatility_regime,
                    proposal.data_quality, proposal.agent_version,
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
        if action not in {"HOLD", "PROPOSE"} or symbol != "XAUUSD" or timeframe != "M1":
            raise ValueError("Unsupported structured agent decision")
        with self._lock, closing(self._connect()) as connection:
            try:
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
            except sqlite3.IntegrityError as exc:
                raise FileExistsError(
                    "A decision is already recorded for this closed M1 bar"
                ) from exc
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

    def latest_agent_decision(self) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT decision_id, action, symbol, timeframe, bar_time_utc,
                       reason, hypothesis_id, created_at_utc
                FROM agent_decisions
                ORDER BY created_at_utc DESC, decision_id DESC LIMIT 1
                """
            ).fetchone()
        return dict(row) if row else None

    def latest_lifecycle_event(self) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT event_id, proposal_id, state, created_at_utc
                FROM lifecycle_events
                ORDER BY created_at_utc DESC, event_id DESC LIMIT 1
                """
            ).fetchone()
        return dict(row) if row else None

    def latest_execution_event(self) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT event_id, proposal_id, state, created_at_utc
                FROM lifecycle_events
                WHERE state IN (
                  'EXECUTED', 'EXECUTION_FAILED', 'EXECUTION_UNCERTAIN', 'CLOSED'
                )
                ORDER BY created_at_utc DESC, event_id DESC LIMIT 1
                """
            ).fetchone()
        return dict(row) if row else None

    def daily_research_summary(self, day: date | None = None) -> dict[str, float | int]:
        target = (day or datetime.now(UTC).date()).isoformat()
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS sample_size,
                       COALESCE(SUM(pnl), 0) AS net_pnl,
                       COALESCE(SUM(r_multiple), 0) AS total_r
                FROM trade_results WHERE substr(closed_at, 1, 10) = ?
                """,
                (target,),
            ).fetchone()
        return {
            "sample_size": int(row["sample_size"]),
            "net_pnl": float(row["net_pnl"]),
            "total_r": float(row["total_r"]),
        }

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
            "gross_pnl": record.pnl if record.gross_pnl is None else record.gross_pnl,
            "commission": record.commission,
            "swap": record.swap,
            "fee": record.fee,
            "confidence": record.confidence,
        })
        optional = {
            "entry_spread_points": record.entry_spread_points,
            "exit_spread_points": record.exit_spread_points,
            "atr_at_entry": record.atr_at_entry,
            "stop_distance_points": record.stop_distance_points,
            "initial_reward_risk": record.initial_reward_risk,
            "tp_distance_points": record.tp_distance_points,
        }
        self._validate_finite({key: value for key, value in optional.items() if value is not None})

    @staticmethod
    def _insert_trade_result(connection: sqlite3.Connection, record: TradeResultRecord) -> None:
        connection.execute(
            """
            INSERT INTO trade_results(
              trade_id, proposal_id, hypothesis_id, strategy_id, setup_id,
              strategy_version, session, market_regime, symbol, side, volume,
              entry_price, exit_price, initial_stop_loss, opened_at, closed_at,
              pnl, r_multiple, mfe_r, mae_r
              , gross_pnl, commission, swap, fee, entry_spread_points,
              exit_spread_points, timeframe, atr_at_entry, stop_distance_points,
              initial_reward_risk, primary_session, active_sessions, data_quality,
              duration_seconds, weekday_utc, hour_utc
              , confidence, exit_session, exit_active_sessions,
              tp_distance_points, volatility_regime, agent_version
            ) VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?, ?
            )
            """,
            (
                record.trade_id, record.proposal_id, record.hypothesis_id,
                record.strategy_id, record.setup_id, record.strategy_version,
                record.session, record.market_regime, record.symbol,
                record.side.value, record.volume, record.entry_price,
                record.exit_price, record.initial_stop_loss,
                record.opened_at.isoformat(), record.closed_at.isoformat(),
                record.pnl, record.r_multiple, record.mfe_r, record.mae_r,
                record.pnl if record.gross_pnl is None else record.gross_pnl,
                record.commission, record.swap, record.fee,
                record.entry_spread_points, record.exit_spread_points,
                record.timeframe, record.atr_at_entry, record.stop_distance_points,
                record.initial_reward_risk, record.primary_session or record.session,
                record.active_sessions, record.data_quality,
                max(0.0, (record.closed_at - record.opened_at).total_seconds()),
                record.closed_at.astimezone(UTC).weekday(),
                record.closed_at.astimezone(UTC).hour,
                record.confidence, record.exit_session, record.exit_active_sessions,
                record.tp_distance_points, record.volatility_regime,
                record.agent_version,
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
                  initial_stop_loss, current_stop_loss, take_profit, tick_size, tick_value, volume,
                  mfe_r, mae_r, opened_at, updated_at
                ) VALUES (?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
                """,
                (
                    proposal.proposal_id, f"paper:{proposal.proposal_id}", entry_price,
                    proposal.stop_loss, proposal.stop_loss, proposal.take_profit, market.tick_size,
                    market.tick_value, proposal.volume, opened_at.isoformat(),
                    opened_at.isoformat(),
                ),
            )
            connection.commit()

    def update_paper_protection(
        self,
        proposal_id: str,
        *,
        stop_loss: float,
        take_profit: float | None,
        updated_at: datetime,
    ) -> None:
        self._validate_finite({"stop_loss": stop_loss})
        if take_profit is not None:
            self._validate_finite({"take_profit": take_profit})
        with self._lock, closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                UPDATE paper_positions
                SET current_stop_loss = ?, take_profit = ?, updated_at = ?
                WHERE proposal_id = ? AND status = 'OPEN'
                """,
                (stop_loss, take_profit, updated_at.isoformat(), proposal_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Open paper position not found")
            connection.commit()

    def list_open_paper_positions(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT pp.*, p.hypothesis_id, p.strategy_id, p.setup_id,
                       p.strategy_version, p.session, p.market_regime,
                       p.symbol, p.side, p.confidence, p.timeframe,
                       p.active_sessions, p.atr_at_entry, p.entry_spread_points,
                       p.point_at_entry, p.stop_distance_points,
                       p.initial_reward_risk, p.volatility_regime,
                       p.data_quality, p.agent_version
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
        if reason not in {"TP", "SL", "MANUAL"}:
            raise ValueError("Paper close reason must be TP, SL, or MANUAL")
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
            connection.execute(
                """
                INSERT INTO lifecycle_events(
                  event_id, proposal_id, state, payload_json, created_at_utc
                ) VALUES (?, ?, 'CLOSED', ?, ?)
                """,
                (
                    str(uuid4()), record.proposal_id,
                    json.dumps(
                        {"reason": reason, "trade_id": record.trade_id},
                        sort_keys=True, separators=(",", ":"),
                    ),
                    record.closed_at.astimezone(UTC).isoformat(),
                ),
            )
            connection.commit()

    def strategy_metrics(self, strategy_id: str, strategy_version: str) -> StrategyMetrics:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT pnl, r_multiple, mfe_r, mae_r, duration_seconds
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
                wins=0,
                losses=0,
                median_duration_seconds=None,
                expectancy_r_ci95_low=None,
                expectancy_r_ci95_high=None,
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
        ci_low, ci_high = self._bootstrap_mean_ci(
            r_values,
            seed_material=f"{strategy_id}|{strategy_version}|{sample}",
        )
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
            wins=sum(1 for value in pnl if value > 0),
            losses=sum(1 for value in pnl if value < 0),
            median_duration_seconds=statistics.median(
                float(row["duration_seconds"]) for row in rows
            ),
            expectancy_r_ci95_low=ci_low,
            expectancy_r_ci95_high=ci_high,
            evidence_sufficient=sample >= MIN_EVIDENCE_SAMPLE,
        )

    @staticmethod
    def _bootstrap_mean_ci(
        values: list[float], *, seed_material: str, samples: int = 2000
    ) -> tuple[float | None, float | None]:
        if not values:
            return None, None
        if len(values) == 1:
            return values[0], values[0]
        seed = int.from_bytes(
            hashlib.sha256(seed_material.encode("utf-8")).digest()[:8], "big"
        )
        rng = random.Random(seed)
        size = len(values)
        means = sorted(
            sum(values[rng.randrange(size)] for _ in range(size)) / size
            for _ in range(samples)
        )
        return means[int(samples * 0.025)], means[int(samples * 0.975) - 1]

    def all_strategy_metrics(self) -> list[StrategyMetrics]:
        with closing(self._connect()) as connection:
            groups = connection.execute(
                "SELECT DISTINCT strategy_id, strategy_version FROM trade_results ORDER BY strategy_id, strategy_version"
            ).fetchall()
        return [
            self.strategy_metrics(str(row["strategy_id"]), str(row["strategy_version"]))
            for row in groups
        ]

    def grouped_metrics(self) -> list[dict[str, Any]]:
        dimensions = {
            "setup": "setup_id",
            "session": "session",
            "hour_utc": "hour_utc",
            "weekday_utc": "weekday_utc",
            "direction": "side",
            "regime": "market_regime",
            "timeframe": "timeframe",
            "volatility_regime": "volatility_regime",
        }
        output: list[dict[str, Any]] = []
        with closing(self._connect()) as connection:
            for dimension, column in dimensions.items():
                groups = connection.execute(
                    f"SELECT DISTINCT {column} AS value FROM trade_results ORDER BY {column}"
                ).fetchall()
                for group in groups:
                    value = group["value"]
                    rows = connection.execute(
                        f"""
                        SELECT pnl, r_multiple, mfe_r, mae_r, duration_seconds
                        FROM trade_results WHERE {column} = ?
                        ORDER BY closed_at, trade_id
                        """,
                        (value,),
                    ).fetchall()
                    pnl = [float(row["pnl"]) for row in rows]
                    r_values = [float(row["r_multiple"]) for row in rows]
                    if not rows:
                        continue
                    gross_profit = sum(item for item in pnl if item > 0)
                    gross_loss = abs(sum(item for item in pnl if item < 0))
                    cumulative = 0.0
                    peak = 0.0
                    max_drawdown = 0.0
                    for item in pnl:
                        cumulative += item
                        peak = max(peak, cumulative)
                        max_drawdown = max(max_drawdown, peak - cumulative)
                    ci_low, ci_high = self._bootstrap_mean_ci(
                        r_values,
                        seed_material=f"{dimension}|{value}|{len(rows)}",
                    )
                    output.append({
                        "dimension": dimension,
                        "value": value,
                        "sample_size": len(rows),
                        "wins": sum(1 for item in pnl if item > 0),
                        "losses": sum(1 for item in pnl if item < 0),
                        "win_rate": sum(1 for item in pnl if item > 0) / len(rows),
                        "net_profit": sum(pnl),
                        "expectancy_r": sum(r_values) / len(rows),
                        "expectancy_r_ci95_low": ci_low,
                        "expectancy_r_ci95_high": ci_high,
                        "profit_factor": (
                            gross_profit / gross_loss if gross_loss > 0 else None
                        ),
                        "max_drawdown": max_drawdown,
                        "average_mfe_r": sum(float(row["mfe_r"]) for row in rows) / len(rows),
                        "average_mae_r": sum(float(row["mae_r"]) for row in rows) / len(rows),
                        "median_duration_seconds": statistics.median(
                            float(row["duration_seconds"]) for row in rows
                        ),
                        "evidence_sufficient": len(rows) >= MIN_EVIDENCE_SAMPLE,
                    })
        return output

    def proposal_id_for_trade(self, trade_id: str) -> str | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT proposal_id FROM trade_results WHERE trade_id = ?", (trade_id,)
            ).fetchone()
        return str(row["proposal_id"]) if row else None

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

    def update_daily_risk_state(
        self,
        *,
        currency: str,
        equity: float,
        balance: float,
        at: datetime | None = None,
    ) -> dict[str, Any]:
        self._validate_finite({"equity": equity, "balance": balance})
        if not currency or equity <= 0 or balance <= 0:
            raise ValueError("Daily risk state requires positive account economics")
        now = (at or datetime.now(UTC)).astimezone(UTC)
        day = now.date().isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM daily_risk_state WHERE date_utc = ?", (day,)
            ).fetchone()
            if row is None:
                start_equity = equity
                peak_equity = equity
                connection.execute(
                    """
                    INSERT INTO daily_risk_state(
                      date_utc, currency, start_equity, peak_equity,
                      last_equity, balance, updated_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (day, currency, equity, equity, equity, balance, now.isoformat()),
                )
            else:
                if str(row["currency"]) != currency:
                    raise RuntimeError("Account currency changed during the UTC risk day")
                start_equity = float(row["start_equity"])
                peak_equity = max(float(row["peak_equity"]), equity)
                connection.execute(
                    """
                    UPDATE daily_risk_state
                    SET peak_equity = ?, last_equity = ?, balance = ?, updated_at_utc = ?
                    WHERE date_utc = ?
                    """,
                    (peak_equity, equity, balance, now.isoformat(), day),
                )
            connection.commit()
        return {
            "date_utc": day,
            "currency": currency,
            "start_equity": start_equity,
            "peak_equity": peak_equity,
            "last_equity": equity,
            "drawdown": peak_equity - equity,
        }

    def health(self) -> bool:
        try:
            with closing(self._connect()) as connection:
                version = connection.execute(
                    "SELECT MAX(version) FROM research_schema"
                ).fetchone()[0]
            return version == 10
        except sqlite3.Error:
            return False
